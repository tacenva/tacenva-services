package vault

import (
	"errors"

	"github.com/tacenva/database"
	"github.com/tacenva/tacenva-services/app"
	"github.com/tacenva/tacenva-services/app/sourceoftruth"

	operationsEntity "github.com/tacenva/tacenva-services/entity"
	"github.com/tacenva/tacpass-core/auth"
	"github.com/tacenva/tacpass-core/contract"
	"github.com/tacenva/tacpass-core/entity"
	coreEntity "github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/util/keyring"
	vaultCore "github.com/tacenva/tacpass-core/vault"
	vaultrecordCore "github.com/tacenva/tacpass-core/vaultrecord"
)

var (
	ErrForbidden = errors.New("Forbidden")
)

type Service struct {
	appDeps   *app.Deps
	context   *app.Context
	masterKey string

	vaultService       *vaultCore.Service
	vaultrecordService *vaultrecordCore.Service
	authService        *auth.Service
}

func NewService(
	appDeps *app.Deps,
	context *app.Context,
	masterKey string,
	vaultService *vaultCore.Service,
	vaultrecordService *vaultrecordCore.Service,
	authService *auth.Service,
	sotService *sourceoftruth.Service,
) *Service {
	return &Service{
		appDeps:   appDeps,
		context:   context,
		masterKey: masterKey,

		authService:        authService,
		vaultService:       vaultService,
		vaultrecordService: vaultrecordService,
	}
}

func (s *Service) getLocalVaultChanges(
	lastChangeID string,
	vaultFile *database.DatabaseFile,
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

	return s.vaultService.GetChangesAfterOnReplica(
		s.context.SelectedSot.ID,
		lastChangeID,
		int(pendingCount.Count),
		vaultFile,
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

func (s *Service) List() ([]coreEntity.Vault, bool, error) {
	var (
		vaultList []coreEntity.Vault
		err       error
	)

	if !s.context.IsRemote {
		authUser, err := s.authUser()
		if err != nil {
			return nil, false, err
		}
		vaultList, err = s.vaultService.VaultList(authUser)
		if err != nil {
			return nil, false, err
		}
		return vaultList, false, err
	}

	dbFile, err := s.openVaultFile()
	if err != nil {
		return nil, false, err
	}

	groupID := s.context.SelectedSot.GroupID
	err = dbFile.FindWhere(&vaultList, func(m map[string]any) bool {
		groupIDs, ok := m["group_ids"].([]any)
		if !ok {
			return false
		}

		for _, value := range groupIDs {
			id, ok := value.(string)
			if ok && id == groupID {
				return true
			}
		}

		return false
	}).Order("ID ASC").Error
	if err != nil {
		return nil, false, err
	}

	if !s.appDeps.Client.IsReachable() {
		return vaultList, false, nil
	}

	switch s.context.SelectedSot.SyncMode {
	case operationsEntity.SyncModeAuto:
		err = s.SyncVault()
		return vaultList, err != nil, err
	case operationsEntity.SyncModeManual:
		lastChangeID, err := s.vaultService.GetSyncLatestChangeID(s.context.SelectedSot.ID)
		if err != nil {
			return vaultList, false, err
		}

		totalChanges, err := s.vaultService.GetChangeCount(s.context.SelectedSot.ID, lastChangeID)
		if err != nil || totalChanges == nil {
			return vaultList, false, err
		}

		clientChangeCount, err := s.appDeps.Client.GetVaultChangesCount(
			s.context.SelectedSot.Address,
			lastChangeID,
		)
		if err != nil {
			return vaultList, false, err
		}

		totalChanges.Count += clientChangeCount.Count

		return vaultList, totalChanges.Count > 0, nil
	}
	return nil, false, nil
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

	vaultFile, err := s.openVaultFile()
	if err != nil {
		return err
	}

	localChanges, err := s.getLocalVaultChanges(lastChangeID, vaultFile)
	if err != nil {
		return err
	}

	clientChanges, clientChangeTotal, err := s.getClientVaultChanges(lastChangeID)
	if err != nil {
		return err
	}

	var appliedOnSot *contract.PendingVaultChange
	vaultDir := s.vaultDir()
	if localChanges != nil {
		groupIDs := collectUniqueGroupIDs(localChanges.VaultChangeDataList)
		permissionList, err := s.appDeps.Client.PublicKeys(
			s.context.SelectedSot.Address,
			groupIDs,
		)
		if err != nil {
			return err
		}

		nodeKeyPair := keyring.FromKeys(
			s.context.SelectedSot.KeyPair.PublicKey,
			s.context.SelectedSot.KeyPair.PrivateKey,
		)

		for vaultID := range localChanges.VaultChangeDataList {
			vaultChangeData := localChanges.VaultChangeDataList[vaultID]
			if len(vaultChangeData.VaultAccessList) == 0 {
				continue
			}

			vault := vaultChangeData.Vault

			vaultKey, err := nodeKeyPair.Open(vault.WrappedKey)
			if err != nil {
				return err
			}

			for _, groupID := range vault.GroupIDs {
				permissionByGroup := permissionList[groupID]
				for _, permissionData := range permissionByGroup {
					vaultKeyPair := keyring.FromPublicKey(permissionData.PublicKey)

					wrappedVaultKey, err := vaultKeyPair.Seal([]byte(vaultKey))
					if err != nil {
						return err
					}

					access := coreEntity.VaultAccess{
						VaultID:      vaultID,
						PermissionID: permissionData.ID,
						VaultKey:     wrappedVaultKey,
					}
					vaultChangeData.VaultAccessList = append(vaultChangeData.VaultAccessList, access)
				}
			}

			localChanges.VaultChangeDataList[vaultID] = vaultChangeData
		}

		appliedOnSot, err = s.appDeps.Client.SyncVault(
			s.context.SelectedSot.Address,
			lastChangeID,
			int(clientChangeTotal.Count),
			localChanges,
		)
		if err != nil {
			return err
		}

		db := database.New(vaultDir)
		for _, change := range appliedOnSot.SyncChanges {
			if change.Operation != "create" {
				continue
			}

			vaultID := change.EntityID

			recordBlob, err := db.Read(vaultID)
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

	if err := s.vaultService.SyncOnReplica(
		vaultDir,
		s.context.SelectedSot.ID,
		s.context.SelectedSot.GroupID,
		localChanges,
		clientChanges,
		vaultFile,
	); err != nil {
		return err
	}

	return s.vaultService.SetSyncStateToBeLastest(s.context.SelectedSot.ID)
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
		authUser, err := s.authUser()
		if err != nil {
			return err
		}

		err = s.vaultService.CreateOnSot(
			authUser,
			s.vaultDir(),
			&coreEntity.Vault{
				Name:     vaultName,
				GroupIDs: groupIDs,
			},
			s.context.SelectedSot.ID,
			&syncChangeID,
		)
		if err != nil {
			return err
		}

		return err
	}

	dbFile, err := s.openVaultFile()
	if err != nil {
		return err
	}

	err = s.vaultService.CreateOnReplica(
		s.vaultDir(),
		&coreEntity.Vault{
			Name:     vaultName,
			GroupIDs: groupIDs,
		},
		s.context.SelectedSot.ID,
		&syncChangeID,
		dbFile,
		&s.context.SelectedSot.KeyPair,
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
	vault *coreEntity.Vault,
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
		authUser, err := s.authUser()
		if err != nil {
			return err
		}

		wrappedKey, err := s.GetWrappedKey(
			vault.ID,
		)
		if err != nil {
			return err
		}

		unwrappedKey, err := s.context.SelectedSot.KeyPair.Open(wrappedKey)
		if err != nil {
			return err
		}

		err = s.vaultService.UpdateOnSot(
			authUser,
			vault,
			s.context.SelectedSot.ID,
			&syncChangeID,
			unwrappedKey,
		)

		return err
	}

	dbFile, err := s.openVaultFile()
	if err != nil {
		return err
	}

	err = s.vaultService.UpdateOnReplica(
		vault,
		s.context.SelectedSot.ID,
		&syncChangeID,
		dbFile,
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
	vault *coreEntity.Vault,
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

	vaultDir := s.vaultDir()

	if !s.context.IsRemote {
		authUser, err := s.authUser()
		if err != nil {
			return err
		}

		err = s.vaultService.DeleteOnSot(
			authUser,
			vaultDir,
			vault.ID,
			s.context.SelectedSot.ID,
			&syncChangeID,
		)

		return err
	}

	dbFile, err := s.openVaultFile()
	if err != nil {
		return err
	}

	err = s.vaultService.DeleteOnReplica(
		vaultDir,
		vault.ID,
		s.context.SelectedSot.ID,
		&syncChangeID,
		dbFile,
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

func (s *Service) authUser() (*coreEntity.User, error) {
	if s.context.SelectedSot == nil {
		return nil, errors.New(
			"selected source of truth is nil",
		)
	}

	return s.authService.GetUserData(
		s.context.SelectedSot.AuthToken,
	)
}

func (s *Service) vaultDir() string {
	vaultDir := s.appDeps.Config.Path(
		"node",
		s.context.SelectedSot.ID,
		"vault",
	)

	return vaultDir
}

func (s *Service) openVaultFile() (*database.DatabaseFile, error) {
	vaultDir := s.vaultDir()
	db := database.New(vaultDir)

	return db.File(
		"vault",
		s.masterKey,
		database.FileModeOpenOrCreate,
	)
}

func (s *Service) openRecordFile(
	vault *coreEntity.Vault,
	wrappedKey string,
) (*database.DatabaseFile, error) {
	vaultKey, err := s.context.SelectedSot.KeyPair.Open(
		wrappedKey,
	)
	if err != nil {
		return nil, err
	}

	vaultDir := s.vaultDir()
	db := database.New(vaultDir)

	return db.File(
		vault.ID,
		string(vaultKey),
		database.FileModeOpen,
	)
}

func (s *Service) ListPermissionGroup(refresh bool) ([]entity.PermissionGroup, error) {
	if refresh && s.context.IsRemote {
		_, err := s.appDeps.Client.GroupAssignment(s.context.SelectedSot.Address)
		if err != nil {
			return nil, err
		}
	}
	return s.vaultService.ListPermissionGroup(s.context.SelectedSot.ID)
}

func (s *Service) GetWrappedKey(
	vaultID string,
) (string, error) {
	authUser, err := s.authUser()
	if err != nil {
		return "", err
	}

	vaData, err := s.vaultService.VaultAccess(
		vaultID,
		authUser.PermissionID,
	)
	if err != nil {
		return "", err
	}

	return vaData.VaultKey, nil
}
