package vault

import (
	"errors"
	"fmt"

	"github.com/tacenva/tacenva-services/app"
	"github.com/tacenva/tacenva-services/app/sourceoftruth"

	tacenvaentity "github.com/tacenva/tacenva-core/entity"
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

func (s *Service) getLocalVaultChanges(
	lastChangeID string,
) (*contract.PendingVaultChange, error) {
	pendingCount, err := s.vaultService.GetChangeCount(
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
		int(pendingCount.Count),
	)
}

func (s *Service) getClientVaultChanges(
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

func (s *Service) List() ([]tacpassentity.Vault, bool, error) {
	// start := time.Now()

	// log.Printf(
	// 	"[VaultService.List] started: is_remote=%t",
	// 	s.context.IsRemote,
	// )

	var (
		vaultList []tacpassentity.Vault
		err       error
	)

	if !s.context.IsRemote {
		// log.Printf("[VaultService.List] listing local SOT vaults")

		vaultList, err = s.vaultService.Sot.List(
			s.context.AuthorizedUser,
		)
		if err != nil {
			// log.Printf(
			// 	"[VaultService.List] local SOT list failed: error=%v",
			// 	err,
			// )
			return nil, false, err
		}

		// log.Printf(
		// 	"[VaultService.List] local SOT list completed: vaults=%d, duration=%s",
		// 	len(vaultList),
		// 	time.Since(start),
		// )

		return vaultList, false, nil
	}

	// log.Printf(
	// 	"[VaultService.List] listing replica vaults: access_group_id=%s",
	// 	s.context.SelectedSot.AccessGroup.ID,
	// )

	vaultList, err = s.vaultService.Replica.List(
		s.context.SelectedSot.AccessGroup.ID,
	)
	if err != nil {
		// log.Printf(
		// 	"[VaultService.List] replica list failed: error=%v",
		// 	err,
		// )
		return nil, false, err
	}

	// log.Printf(
	// 	"[VaultService.List] replica list completed: vaults=%d",
	// 	len(vaultList),
	// )

	// for i, vault := range vaultList {
	// 	log.Printf(
	// 		"[VaultService.List] vault[%d]: id=%s, name=%s",
	// 		i,
	// 		vault.ID,
	// 		vault.Name,
	// 	)
	// }

	if !s.appDeps.Client.IsReachable() {
		// log.Printf(
		// 	"[VaultService.List] offline: returning replica data, duration=%s",
		// 	time.Since(start),
		// )
		return vaultList, false, nil
	}

	switch s.context.SelectedSot.SyncMode {
	case operationsEntity.SyncModeAuto:
		// log.Printf("[VaultService.List] auto sync started")

		err = s.SyncVault()

		// log.Printf(
		// 	"[VaultService.List] auto sync completed: success=%t, error=%v, duration=%s",
		// 	err == nil,
		// 	err,
		// 	time.Since(start),
		// )

		return vaultList, err != nil, err

	case operationsEntity.SyncModeManual:
		// log.Printf("[VaultService.List] manual sync check started")

		lastChangeID, err := s.vaultService.GetSyncLatestChangeID(
			s.context.SelectedSot.ID,
		)
		if err != nil {
			// log.Printf(
			// 	"[VaultService.List] get latest change ID failed: error=%v",
			// 	err,
			// )
			return vaultList, false, err
		}

		// log.Printf(
		// 	"[VaultService.List] latest change ID: %s",
		// 	lastChangeID,
		// )

		totalChanges, err := s.vaultService.GetChangeCount(
			s.context.SelectedSot.ID,
			lastChangeID,
		)
		if err != nil {
			// log.Printf(
			// 	"[VaultService.List] get local change count failed: error=%v",
			// 	err,
			// )
			return vaultList, false, err
		}

		if totalChanges == nil {
			// log.Printf(
			// 	"[VaultService.List] local change count is nil",
			// )
			return vaultList, false, fmt.Errorf(
				"local change count is nil",
			)
		}

		// log.Printf(
		// 	"[VaultService.List] local changes: %d",
		// 	totalChanges.Count,
		// )

		clientChangeCount, err := s.appDeps.Client.GetVaultChangesCount(
			s.context.SelectedSot.Address,
			lastChangeID,
		)
		if err != nil {
			// log.Printf(
			// 	"[VaultService.List] get remote change count failed: error=%v",
			// 	err,
			// )
			return vaultList, false, err
		}

		// log.Printf(
		// 	"[VaultService.List] remote changes: %d",
		// 	clientChangeCount.Count,
		// )

		totalChanges.Count += clientChangeCount.Count

		needSync := totalChanges.Count > 0

		// log.Printf(
		// 	"[VaultService.List] manual sync check completed: total_changes=%d, need_sync=%t, duration=%s",
		// 	totalChanges.Count,
		// 	needSync,
		// 	time.Since(start),
		// )

		return vaultList, needSync, nil

	default:
		// log.Printf(
		// 	"[VaultService.List] unsupported sync mode: %v",
		// 	s.context.SelectedSot.SyncMode,
		// )
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

func (s *Service) SyncVault() error {
	if !s.context.IsRemote {
		return nil
	}

	lastChangeID, err := s.vaultService.GetSyncLatestChangeID(s.context.SelectedSot.ID)
	if err != nil {
		return err
	}

	localChanges, err := s.getLocalVaultChanges(lastChangeID)
	if err != nil {
		return err
	}

	clientChanges, clientChangeTotal, err := s.getClientVaultChanges(lastChangeID)
	if err != nil {
		return err
	}

	// debug.LogJSON("local changes", localChanges)
	// debug.LogJSON("client changes", clientChanges)

	var appliedOnSot *contract.PendingVaultChange
	if localChanges != nil {
		groupIDs := collectUniqueGroupIDs(localChanges.VaultChangeDataList)
		publicKeyOfGroups, err := s.appDeps.Client.PublicKeyOfGroups(
			s.context.SelectedSot.Address,
			groupIDs,
		)
		if err != nil {
			return err
		}
		// debug.LogJSON("public keys", publicKeyOfGroups)

		writerGroupKeyPair := s.context.SelectedSot.AccessGroup.KeyPair
		// debug.LogJSON("keypair access group", writerGroupKeyPair)

		// debug.LogJSON("local changes 1", localChanges)
		for vaultID := range localChanges.VaultChangeDataList {
			vaultChangeData := localChanges.VaultChangeDataList[vaultID]
			vault := vaultChangeData.Vault
			if len(vault.GroupIDs) == 0 {
				continue
			}

			unwrappedVaultKey, err := writerGroupKeyPair.Open(vault.WrappedKey)
			if err != nil {
				// debug.LogJSON("vault sync", vault)
				return err
			}

			for _, groupID := range vault.GroupIDs {
				publicKey := publicKeyOfGroups[groupID]
				// log.Printf("public key: %s\ngroupID: %s", publicKey, groupID)
				keyPairOfAccessGroup := keyring.FromPublicKey(publicKey)
				// debug.LogJSON("key pair of access group", keyPairOfAccessGroup)

				wrappedVaultKey, err := keyPairOfAccessGroup.Seal(unwrappedVaultKey)
				if err != nil {
					// log.Printf("Wrapped vault key: %s", wrappedVaultKey)
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
			localChanges.VaultChangeDataList[vaultID] = vaultChangeData
		}
		// debug.LogJSON("local changes 2", localChanges)

		appliedOnSot, err = s.appDeps.Client.SyncVault(
			s.context.SelectedSot.Address,
			lastChangeID,
			int(clientChangeTotal.Count),
			localChanges,
		)
		if err != nil {
			return err
		}

		for _, change := range appliedOnSot.SyncChanges {
			if change.Operation != "create" {
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
		localChanges,
		clientChanges,
	); err != nil {
		return err
	}

	return s.vaultService.SetSyncStateToBeLatest(s.context.SelectedSot.ID)
}

func (s *Service) CreateVault(
	vaultName string,
	groupIDs []string,
) error {
	if s.context == nil {
		return errors.New("context is nil")
	}

	if s.context.SelectedSot == nil {
		return errors.New(
			"selected source of truth is nil",
		)
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
		&s.context.SelectedSot.AccessGroup.KeyPair,
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
	if vault == nil {
		return errors.New("vault cannot be nil")
	}

	if vault.ID == "" {
		return errors.New("vault id cannot be empty")
	}

	if vault.Name == "" {
		return errors.New("vault name cannot be empty")
	}

	if s.context == nil {
		return errors.New("context is nil")
	}

	if s.context.SelectedSot == nil {
		return errors.New(
			"selected source of truth is nil",
		)
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
	if vault == nil {
		return errors.New("vault cannot be nil")
	}

	if vault.ID == "" {
		return errors.New("vault id cannot be empty")
	}

	if s.context == nil {
		return errors.New("context is nil")
	}

	if s.context.SelectedSot == nil {
		return errors.New(
			"selected source of truth is nil",
		)
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
	if refresh && s.context.IsRemote {
		//
	}

	return s.vaultService.AllAccessGroup(
		s.context.SelectedSot.ID,
	)
}
