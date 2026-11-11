package vault

import (
	"errors"
	"fmt"

	"github.com/tacenva/tacenva-services/app"
	"github.com/tacenva/tacenva-services/app/sourceoftruth"

	tacenvaentity "github.com/tacenva/tacenva-core/entity"
	"github.com/tacenva/tacenva-core/genericerror"
	"github.com/tacenva/tacenva-core/util/keyring"
	operationsEntity "github.com/tacenva/tacenva-services/entity"
	"github.com/tacenva/tacpass-core/contract"
	tacpassentity "github.com/tacenva/tacpass-core/entity"
	vaultCore "github.com/tacenva/tacpass-core/vault"
	vaultrecordCore "github.com/tacenva/tacpass-core/vaultrecord"
)

var (
	ErrForbidden = errors.New("Forbidden")
)

type Service struct {
	appDeps *app.Deps
	context *app.Context

	vaultService       *vaultCore.Service
	vaultrecordService *vaultrecordCore.Service
}

func NewService(
	appDeps *app.Deps,
	context *app.Context,
	vaultService *vaultCore.Service,
	vaultrecordService *vaultrecordCore.Service,
	sotService *sourceoftruth.Service,
) *Service {
	return &Service{
		appDeps:            appDeps,
		context:            context,
		vaultService:       vaultService,
		vaultrecordService: vaultrecordService,
	}
}

func (s *Service) List() ([]tacpassentity.Vault, bool, error) {
	var (
		vaultList []tacpassentity.Vault
		err       error
	)

	if !s.context.IsRemote {
		vaultList, err = s.vaultService.Sot.List(
			s.context.AuthorizedUser,
		)
		if err != nil {
			return nil, false, err
		}

		return vaultList, false, nil
	}

	// debug.LogJSON("selected sot", s.context.SelectedSot)

	vaultList, err = s.vaultService.Replica.List(
		s.context.SelectedSot.AccessGroup.ID,
	)
	if err != nil {
		return nil, false, err
	}

	if !s.appDeps.Client.IsReachable(
		s.context.SelectedSot.Address,
	) {
		return vaultList, false, nil
	}

	switch s.context.SelectedSot.SyncMode {
	case operationsEntity.SyncModeAuto:
		err = s.SyncVault()

		return vaultList, err != nil, err

	case operationsEntity.SyncModeManual:
		lastChangeID, err := s.vaultService.GetSyncLatestChangeID(
			s.context.SelectedSot.ID,
		)
		if err != nil {
			return vaultList, false, err
		}

		replicaTotalChanges, err := s.vaultService.Replica.GetChangeCount(
			s.context.SelectedSot.ID,
			lastChangeID,
		)
		if err != nil {
			return vaultList, false, err
		}

		if replicaTotalChanges == nil {
			return vaultList, false, fmt.Errorf(
				"replica change count is nil",
			)
		}

		sotChangeCount, err := s.appDeps.Client.GetVaultChangesCount(
			s.context.SelectedSot.Address,
			lastChangeID,
		)
		if err != nil {
			return vaultList, false, err
		}

		needSync := (replicaTotalChanges.Count + sotChangeCount.Count) > 0

		return vaultList, needSync, nil

	default:
		return nil, false, nil
	}
}

func collectUniqueGroupIDs(changeDataList map[string]contract.VaultChangeData) []string {
	groupIDSet := make(map[string]struct{})

	for vaultID := range changeDataList {
		groupIDs := changeDataList[vaultID].Vault.GroupIDs
		for _, groupID := range groupIDs {
			groupIDSet[groupID] = struct{}{}

		}
	}

	groupIDs := make([]string, 0, len(groupIDSet))
	for groupID := range groupIDSet {
		groupIDs = append(groupIDs, groupID)
	}

	return groupIDs
}

func (s *Service) getReplicaVaultChanges(
	lastChangeID string,
) (*contract.PendingVaultChange, error) {
	pendingCount, err := s.vaultService.Replica.GetChangeCount(
		s.context.SelectedSot.ID,
		lastChangeID,
	)
	if err != nil {
		return nil, err
	}

	if pendingCount.Count == 0 {
		return nil, nil
	}

	return s.vaultService.Replica.GetChangesAfter(
		s.context.SelectedSot.ID,
		lastChangeID,
		pendingCount.Count,
	)
}

func (s *Service) getSotVaultChanges(
	lastChangeID string,
) (*contract.PendingVaultChange, *contract.PendingTotalChanges, error) {
	changeCount, err := s.appDeps.Client.GetVaultChangesCount(
		s.context.SelectedSot.Address,
		lastChangeID,
	)
	if err != nil {
		return nil, nil, err
	}

	if changeCount.Count == 0 {
		return nil, changeCount, nil
	}

	pendingChanges, err := s.appDeps.Client.GetVaultChanges(
		s.context.SelectedSot.Address,
		lastChangeID,
		int(changeCount.Count),
	)
	if err != nil {
		return nil, nil, err
	}

	return pendingChanges, changeCount, nil
}

func (s *Service) SyncVault() error {
	if !s.context.IsRemote {
		return nil
	}

	lastChangeID, err := s.vaultService.GetSyncLatestChangeID(s.context.SelectedSot.ID)
	if err != nil {
		return err
	}

	replicaChanges, err := s.getReplicaVaultChanges(lastChangeID)
	if err != nil {
		return err
	}

	sotChanges, sotChangeTotal, err := s.getSotVaultChanges(lastChangeID)
	if err != nil {
		return err
	}

	var appliedOnSot *contract.PendingVaultChange
	if replicaChanges != nil {
		groupIDs := collectUniqueGroupIDs(replicaChanges.VaultChangeDataList)
		publicKeyOfGroups, err := s.appDeps.Client.PublicKeyOfGroups(
			s.context.SelectedSot.Address,
			groupIDs,
		)
		if err != nil {
			return err
		}
		writerGroupKeyPair := s.context.SelectedSot.AccessGroup.KeyPair
		for vaultID := range replicaChanges.VaultChangeDataList {
			vaultChangeData := replicaChanges.VaultChangeDataList[vaultID]
			vault := vaultChangeData.Vault
			if len(vault.GroupIDs) == 0 {
				continue
			}

			unwrappedVaultKey, err := writerGroupKeyPair.Open(vault.WrappedKey)
			if err != nil {
				return err
			}

			for _, groupID := range vault.GroupIDs {
				publicKey := publicKeyOfGroups[groupID]
				keyPairOfAccessGroup := keyring.FromPublicKey(publicKey)

				wrappedVaultKey, err := keyPairOfAccessGroup.Seal(unwrappedVaultKey)
				if err != nil {
					return err
				}
				access := tacpassentity.VaultAccess{
					VaultID:         vaultID,
					AccessGroupID:   groupID,
					WrappedVaultKey: wrappedVaultKey,
				}
				vaultChangeData.VaultAccessList = append(vaultChangeData.VaultAccessList, access)
			}

			vaultChangeData.Vault.WrappedKey = ""
			replicaChanges.VaultChangeDataList[vaultID] = vaultChangeData
		}

		appliedOnSot, err = s.appDeps.Client.SyncVault(
			s.context.SelectedSot.Address,
			lastChangeID,
			int(sotChangeTotal.Count),
			replicaChanges,
		)
		if err != nil {
			return err
		}

		// debug.LogJSON("applied on sot", appliedOnSot)

		for _, change := range appliedOnSot.SyncChanges {
			if change.Operation != tacenvaentity.OperationCreate {
				continue
			}

			vaultID := change.EntityID
			recordBlob, err := s.vaultService.Replica.GetRecordBlob(vaultID)
			if err != nil {
				return err
			}

			if err := s.appDeps.Client.StoreRecordBlob(
				s.context.SelectedSot.Address,
				vaultID,
				recordBlob,
			); err != nil {
				return err
			}
		}
	}

	if err := s.vaultService.Replica.Sync(
		s.context.SelectedSot.ID,
		s.context.SelectedSot.AccessGroup.ID,
		replicaChanges,
		sotChanges,
	); err != nil {
		return err
	}

	return s.vaultService.SetSyncStateToBeLatest(s.context.SelectedSot.ID)
}

func (s *Service) CreateVault(
	vaultName string,
	groupIDs []string,
) error {
	if err := genericerror.ValidateRequired(map[string]any{
		"context":                  s.context,
		"selected source of truth": s.context.SelectedSot,
	}); err != nil {
		return err
	}

	var (
		syncChangeID string
	)

	if !s.context.IsRemote {
		err := s.vaultService.Sot.Create(
			s.context.AuthorizedUser,
			&tacpassentity.Vault{
				Name:     vaultName,
				GroupIDs: groupIDs,
			},
			&syncChangeID,
		)
		if err != nil {
			return err
		}

		return err
	}

	err := s.vaultService.Replica.Create(
		&tacpassentity.Vault{
			Name:     vaultName,
			GroupIDs: groupIDs,
		},
		s.context.SelectedSot.ID,
		&syncChangeID,
		s.context.SelectedSot.AccessGroup.KeyPair,
	)
	if err != nil {
		return err
	}

	if s.context.SelectedSot.SyncMode == operationsEntity.SyncModeAuto {
		err = s.SyncVault()
	}

	return err
}

func (s *Service) UpdateVault(
	vault *tacpassentity.Vault,
) error {
	if err := genericerror.ValidateRequired(map[string]any{
		"vault":                    vault,
		"vault id":                 vault.ID,
		"vault name":               vault.Name,
		"context":                  s.context,
		"selected source of truth": s.context.SelectedSot,
	}); err != nil {
		return err
	}

	var (
		syncChangeID string
	)

	if !s.context.IsRemote {
		wrappedVaultKey, err := s.GetWrappedVaultKey(vault.ID)
		if err != nil {
			return err
		}

		unwrappedVaultKey, err := s.context.SelectedSot.AccessGroup.KeyPair.Open(wrappedVaultKey)

		err = s.vaultService.Sot.Update(
			s.context.AuthorizedUser,
			vault,
			unwrappedVaultKey,
			&syncChangeID,
		)

		return err
	}

	err := s.vaultService.Replica.Update(
		vault,
		s.context.SelectedSot.ID,
		&syncChangeID,
	)
	if err != nil {
		return err
	}

	if s.context.SelectedSot.SyncMode == operationsEntity.SyncModeAuto {
		if err = s.SyncVault(); err != nil {
			return err
		}
	}

	return nil
}

func (s *Service) DeleteVault(
	vault *tacpassentity.Vault,
) error {
	if err := genericerror.ValidateRequired(map[string]any{
		"vault":                    vault,
		"vault id":                 vault.ID,
		"vault name":               vault.Name,
		"context":                  s.context,
		"selected source of truth": s.context.SelectedSot,
	}); err != nil {
		return err
	}

	var (
		syncChangeID string
	)

	if !s.context.IsRemote {
		err := s.vaultService.Sot.Delete(
			s.context.AuthorizedUser,
			vault.ID,
			s.context.SelectedSot.ID,
			&syncChangeID,
		)

		return err
	}

	err := s.vaultService.Replica.Delete(
		vault.ID,
		s.context.SelectedSot.ID,
		&syncChangeID,
	)
	if err != nil {
		return err
	}

	if s.context.SelectedSot.SyncMode == operationsEntity.SyncModeAuto {
		err = s.SyncVault()
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Service) GetWrappedVaultKey(
	vaultID string,
) (string, error) {
	if !s.context.IsRemote {
		return s.vaultService.Sot.GetWrappedKey(
			s.context.AuthorizedUser,
			vaultID,
		)
	}

	return s.vaultService.Replica.GetWrappedKey(vaultID)
}

func (s *Service) AllAccessGroup(refresh bool) ([]tacenvaentity.AccessGroup, error) {
	currentGroup, err := s.vaultService.AllAccessGroup(
		s.context.SelectedSot.ID,
	)
	if err != nil {
		return nil, err
	}

	if refresh && s.context.IsRemote {
		groups, err := s.appDeps.Client.GetAllAccessGroup(
			s.context.SelectedSot.Address,
		)
		if err != nil {
			return currentGroup, err
		}

		// debug.LogJSON("updated group", groups)

		err = s.vaultService.SyncGroups(
			s.context.SelectedSot.ID,
			groups,
			nil,
		)
		if err != nil {
			return currentGroup, err
		}

		currentGroup = groups
	}

	return currentGroup, nil
}
