package vault

import (
	"errors"
	"slices"

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
		s.context.SelectedSoT.ID,
		lastChangeID,
	)
	if err != nil {
		return nil, err
	}

	if pendingCount.Count == 0 {
		return nil, nil
	}

	return s.vaultService.GetChangesAfterOnReplica(
		s.context.SelectedSoT.ID,
		lastChangeID,
		int(pendingCount.Count),
		vaultFile,
	)
}

func (s *Service) getClientVaultChanges(
	lastChangeID string,
) (*contract.PendingVaultChange, error) {
	var result contract.PendingTotalChanges
	err := s.appDeps.Client.GetVaultChangesCount(
		s.context.SelectedSoT.Address,
		lastChangeID,
		&result,
	)
	if err != nil {
		return nil, err
	}

	if result.Count == 0 {
		return nil, nil
	}

	var pendingChange contract.PendingVaultChange

	err = s.appDeps.Client.GetVaultChanges(
		s.context.SelectedSoT.Address,
		lastChangeID,
		int(result.Count),
		&pendingChange,
	)
	if err != nil {
		return nil, err
	}

	return &pendingChange, nil
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
	groupID := ""
	err = dbFile.FindWhere(&vaultList, func(m map[string]any) bool {
		groupIDs, ok := m["GroupIDs"].([]string)
		if !ok {
			return false
		}

		return slices.Contains(groupIDs, groupID)
	}).Order("ID ASC").Error

	switch s.context.SelectedSoT.SyncMode {
	case operationsEntity.SyncModeAuto:
		err = s.SyncVault()
		return vaultList, err != nil, err
	case operationsEntity.SyncModeManual:
		lastChangeID, err := s.vaultService.GetSyncLatestChangeID(s.context.SelectedSoT.ID)
		if err != nil {
			return vaultList, false, err
		}

		totalChanges, err := s.vaultService.GetChangeCount(s.context.SelectedSoT.ID, lastChangeID)
		if err != nil || totalChanges == nil {
			return vaultList, false, err
		}

		var result contract.PendingTotalChanges
		err = s.appDeps.Client.GetVaultChangesCount(
			s.context.SelectedSoT.Address,
			lastChangeID,
			&result,
		)
		if err != nil {
			return vaultList, false, err
		}

		totalChanges.Count += result.Count

		return vaultList, totalChanges.Count > 0, nil
	}
	return nil, false, nil
}

func (s *Service) SyncVault() error {
	if !s.context.IsRemote {
		return nil
	}

	lastChangeID, err := s.vaultService.GetSyncLatestChangeID(s.context.SelectedSoT.ID)
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

	clientChanges, err := s.getClientVaultChanges(lastChangeID)
	if err != nil {
		return err
	}

	if err := s.vaultService.SyncOnReplica(
		s.context.SelectedSoT.ID,
		localChanges,
		clientChanges,
		vaultFile,
	); err != nil {
		return err
	}

	appliedClientChanges := s.vaultService.MergePendingVaultChange(
		localChanges,
		clientChanges,
	)

	if appliedClientChanges != nil {
		var permissionList []coreEntity.Permission
		if err = s.appDeps.Client.ConnectedPublicKeys(
			s.context.SelectedSoT.Address,
			&permissionList,
		); err != nil {
			return err
		}

		nodeKeyPair := keyring.FromKeys(
			s.context.SelectedSoT.KeyPair.PublicKey,
			s.context.SelectedSoT.KeyPair.PrivateKey,
		)

		for vaultID := range appliedClientChanges.VaultChangeDataList {
			vaultChangeData := appliedClientChanges.VaultChangeDataList[vaultID]
			if len(vaultChangeData.VaultAccessList) == 0 {
				continue
			}

			firstVaultAccess := &vaultChangeData.VaultAccessList[0]

			vaultKey, err := nodeKeyPair.Open(firstVaultAccess.VaultKey)
			if err != nil {
				return err
			}

			for _, permissionData := range permissionList {
				vaultKeyPair := keyring.FromPublicKey(permissionData.PublicKey)

				wrappedVaultKey, err := vaultKeyPair.Seal([]byte(vaultKey))
				if err != nil {
					return err
				}

				if permissionData.PublicKey == s.context.SelectedSoT.KeyPair.PublicKey {
					firstVaultAccess.PermissionID = permissionData.ID
				} else {
					access := coreEntity.VaultAccess{
						VaultID:      vaultID,
						PermissionID: permissionData.ID,
						VaultKey:     wrappedVaultKey,
					}
					vaultChangeData.VaultAccessList = append(vaultChangeData.VaultAccessList, access)
				}
			}

			appliedClientChanges.VaultChangeDataList[vaultID] = vaultChangeData
		}

		if err := s.appDeps.Client.SyncVault(
			s.context.SelectedSoT.Address,
			appliedClientChanges,
		); err != nil {
			return err
		}

		vaultDir := s.vaultDir()
		db := database.New(vaultDir)
		for _, change := range appliedClientChanges.SyncChanges {
			if change.Operation != "create" {
				continue
			}

			vaultID := change.EntityID

			recordBlob, err := db.Read(vaultID)
			if err != nil {
				return err
			}

			if err := s.appDeps.Client.StoreRecordBlob(
				s.context.SelectedSoT.Address,
				vaultID,
				recordBlob,
			); err != nil {
				return err
			}
		}
	}

	return s.vaultService.SetSyncStateToBeLastest(s.context.SelectedSoT.ID)
}

func (s *Service) CreateVault(
	vaultName string,
	groupIDs []string,
) error {
	if s.context == nil {
		return errors.New("context is nil")
	}

	if s.context.SelectedSoT == nil {
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

		err = s.vaultService.CreateOnSoT(
			authUser,
			s.vaultDir(),
			&coreEntity.Vault{
				Name:     vaultName,
				GroupIDs: groupIDs,
			},
			s.context.SelectedSoT.ID,
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
			Name: vaultName,
		},
		s.context.SelectedSoT.ID,
		&syncChangeID,
		dbFile,
		&s.context.SelectedSoT.KeyPair,
	)
	if err != nil {
		return err
	}

	if s.context.SelectedSoT.SyncMode == operationsEntity.SyncModeAuto {
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

	if s.context.SelectedSoT == nil {
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

		err = s.vaultService.UpdateOnSoT(
			authUser,
			vault,
			s.context.SelectedSoT.ID,
			&syncChangeID,
		)

		return err
	}

	dbFile, err := s.openVaultFile()
	if err != nil {
		return err
	}

	err = s.vaultService.UpdateOnReplica(
		vault,
		s.context.SelectedSoT.ID,
		&syncChangeID,
		dbFile,
	)
	if err != nil {
		return err
	}

	if s.context.SelectedSoT.SyncMode == operationsEntity.SyncModeAuto {
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

	if s.context.SelectedSoT == nil {
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

		err = s.vaultService.DeleteOnSoT(
			authUser,
			vaultDir,
			vault.ID,
			s.context.SelectedSoT.ID,
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
		s.context.SelectedSoT.ID,
		&syncChangeID,
		dbFile,
	)
	if err != nil {
		return err
	}

	if s.context.SelectedSoT.SyncMode == operationsEntity.SyncModeAuto {
		err = s.SyncVault()
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Service) AppendRecord(
	vault *coreEntity.Vault,
	record *coreEntity.VaultRecord,
	wrappedKey string,
) (*coreEntity.VaultRecord, error) {
	if vault == nil {
		return nil, errors.New(
			"vault cannot be nil",
		)
	}

	if record == nil {
		return nil, errors.New(
			"record cannot be nil",
		)
	}

	if vault.ID == "" {
		return nil, errors.New(
			"vault id cannot be empty",
		)
	}

	if s.context == nil {
		return nil, errors.New("context is nil")
	}

	if s.context.SelectedSoT == nil {
		return nil, errors.New(
			"selected source of truth is nil",
		)
	}

	vaultFile, err := s.openRecordFile(vault, wrappedKey)
	if err != nil {
		return nil, err
	}

	encrypted, err := vaultFile.SimulateEncryption(record)
	if err != nil {
		return nil, err
	}

	vaultDir := s.vaultDir()

	var (
		syncChangeID string
		recordID     string
	)

	hostname := ""
	if !s.context.IsRemote {
		hostname = s.context.SelectedSoT.Hostname
	}

	err = s.vaultrecordService.Create(
		vaultDir,
		vault.ID,
		&recordID,
		[]byte(encrypted),
		s.context.SelectedSoT.ID,
		&syncChangeID,
		hostname,
	)
	if err != nil {
		return nil, err
	}

	record.ID = recordID

	if s.context.SelectedSoT.SyncMode == operationsEntity.SyncModeAuto {
		err = s.SyncRecord(vault)
		if err != nil {
			return nil, err
		}
	}
	return record, nil
}

func (s *Service) UpdateRecord(
	vault *coreEntity.Vault,
	record *coreEntity.VaultRecord,
	wrappedKey string,
) (*coreEntity.VaultRecord, error) {
	if vault == nil {
		return nil, errors.New(
			"vault cannot be nil",
		)
	}

	if record == nil {
		return nil, errors.New(
			"record cannot be nil",
		)
	}

	if vault.ID == "" {
		return nil, errors.New(
			"vault id cannot be empty",
		)
	}

	if record.ID == "" {
		return nil, errors.New(
			"record id cannot be empty",
		)
	}

	if s.context == nil {
		return nil, errors.New("context is nil")
	}

	if s.context.SelectedSoT == nil {
		return nil, errors.New(
			"selected source of truth is nil",
		)
	}

	vaultFile, err := s.openRecordFile(vault, wrappedKey)
	if err != nil {
		return nil, err
	}

	encrypted, err := vaultFile.SimulateEncryption(record)
	if err != nil {
		return nil, err
	}

	vaultDir := s.vaultDir()

	var syncChangeID string

	hostname := ""
	if !s.context.IsRemote {
		hostname = s.context.SelectedSoT.Hostname
	}

	err = s.vaultrecordService.Update(
		vaultDir,
		vault.ID,
		record.ID,
		[]byte(encrypted),
		s.context.SelectedSoT.ID,
		&syncChangeID,
		hostname,
	)
	if err != nil {
		return nil, err
	}

	if s.context.SelectedSoT.SyncMode == operationsEntity.SyncModeAuto {
		err = s.SyncRecord(vault)
		if err != nil {
			return nil, err
		}
	}

	return record, nil
}

func (s *Service) DeleteRecord(
	vault *coreEntity.Vault,
	record *coreEntity.VaultRecord,
) error {
	if vault == nil {
		return errors.New(
			"vault cannot be nil",
		)
	}

	if record == nil {
		return errors.New(
			"record cannot be nil",
		)
	}

	if vault.ID == "" {
		return errors.New(
			"vault id cannot be empty",
		)
	}

	if record.ID == "" {
		return errors.New(
			"record id cannot be empty",
		)
	}

	if s.context == nil {
		return errors.New("context is nil")
	}

	if s.context.SelectedSoT == nil {
		return errors.New(
			"selected source of truth is nil",
		)
	}

	vaultDir := s.vaultDir()

	var syncChangeID string
	hostname := ""
	if !s.context.IsRemote {
		hostname = s.context.SelectedSoT.Hostname
	}

	err := s.vaultrecordService.Delete(
		vaultDir,
		vault.ID,
		record.ID,
		s.context.SelectedSoT.ID,
		&syncChangeID,
		hostname,
	)
	if err != nil {
		return err
	}

	if s.context.SelectedSoT.SyncMode == operationsEntity.SyncModeAuto {
		err = s.SyncRecord(vault)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Service) SyncRecord(
	vault *coreEntity.Vault,
) error {
	vaultDir := s.vaultDir()

	lastChangeID, err := s.vaultrecordService.GetSyncLatestChangeId(
		s.context.SelectedSoT.ID,
		vault.ID,
	)
	if err != nil {
		return err
	}

	localChanges, err := s.getLocalRecordChanges(
		vaultDir,
		vault.ID,
		lastChangeID,
	)
	if err != nil {
		return err
	}

	clientChanges, err := s.getClientRecordChanges(
		vault.ID,
		lastChangeID,
	)
	if err != nil {
		return err
	}

	if err := s.vaultrecordService.Sync(
		vaultDir,
		s.context.SelectedSoT.ID,
		vault.ID,
		clientChanges,
		localChanges,
	); err != nil {
		return err
	}

	appliedClientChanges := s.vaultrecordService.MergePendingVaultRecordChange(
		localChanges,
		clientChanges,
	)

	if err := s.appDeps.Client.SyncRecords(
		s.context.SelectedSoT.Address,
		vault.ID,
		appliedClientChanges,
	); err != nil {
		return err
	}

	return s.vaultrecordService.SetSyncStateToBeLastest(
		s.context.SelectedSoT.ID,
		vault.ID,
	)
}

func (s *Service) getLocalRecordChanges(
	vaultDir string,
	vaultID string,
	lastChangeID string,
) (*contract.PendingVaultRecordChange, error) {
	changeCount, err := s.vaultrecordService.GetChangeCount(
		s.context.SelectedSoT.ID,
		vaultID,
		lastChangeID,
	)
	if err != nil {
		return nil, err
	}

	if changeCount == 0 {
		return nil, nil
	}

	return s.vaultrecordService.GetChangesAfter(
		vaultDir,
		vaultID,
		s.context.SelectedSoT.ID,
		lastChangeID,
		int(changeCount),
	)
}

func (s *Service) getClientRecordChanges(
	vaultID string,
	lastChangeID string,
) (*contract.PendingVaultRecordChange, error) {
	var result contract.PendingTotalChanges

	err := s.appDeps.Client.GetRecordChangesCount(
		s.context.SelectedSoT.Address,
		vaultID,
		lastChangeID,
		&result,
	)
	if err != nil {
		return nil, err
	}

	if result.Count == 0 {
		return nil, nil
	}

	var pendingChange contract.PendingVaultRecordChange

	err = s.appDeps.Client.GetRecordChanges(
		s.context.SelectedSoT.Address,
		vaultID,
		lastChangeID,
		int(result.Count),
		&pendingChange,
	)
	if err != nil {
		return nil, err
	}

	return &pendingChange, nil
}

func (s *Service) authUser() (*coreEntity.User, error) {
	if s.context.SelectedSoT == nil {
		return nil, errors.New(
			"selected source of truth is nil",
		)
	}

	return s.authService.GetUserData(
		s.context.SelectedSoT.AuthToken,
	)
}

func (s *Service) vaultDir() string {
	vaultDir := s.appDeps.Config.Path(
		"node",
		s.context.SelectedSoT.ID,
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
	vaultKey, err := s.context.SelectedSoT.KeyPair.Open(
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

func (s *Service) ListRecord(
	vault *coreEntity.Vault,
	wrappedKey string,
) ([]coreEntity.VaultRecord, bool, error) {
	if vault == nil {
		return nil, false, errors.New(
			"vault cannot be nil",
		)
	}

	if vault.ID == "" {
		return nil, false, errors.New(
			"vault id cannot be empty",
		)
	}

	if s.context == nil {
		return nil, false, errors.New(
			"context is nil",
		)
	}

	if s.context.SelectedSoT == nil {
		return nil, false, errors.New(
			"selected source of truth is nil",
		)
	}

	vaultDir := s.vaultDir()
	vaultKey, err := s.context.SelectedSoT.KeyPair.Open(wrappedKey)
	if err != nil {
		return nil, false, err
	}

	records, err := s.vaultrecordService.List(
		vaultDir,
		vault.ID,
		string(vaultKey),
	)
	if err != nil {
		if err == database.ErrFileNotFound && s.context.IsRemote {
			recordBlob, err := s.appDeps.Client.GetRecordBlob(
				s.context.SelectedSoT.Address,
				vault.ID,
			)
			if err != nil {
				return nil, false, err
			}

			db := database.New(vaultDir)
			err = db.Write(vault.ID, recordBlob)
			if err != nil {
				return nil, false, err
			}

			records, err = s.vaultrecordService.List(
				vaultDir,
				vault.ID,
				string(vaultKey),
			)
			if err != nil {
				return nil, false, err
			}
		} else {
			return nil, false, err
		}
	}

	if !s.context.IsRemote {
		return records, false, nil
	}

	switch s.context.SelectedSoT.SyncMode {
	case operationsEntity.SyncModeAuto:
		if err := s.SyncRecord(vault); err != nil {
			return records, true, err
		}

		records, err = s.vaultrecordService.List(
			vaultDir,
			vault.ID,
			string(vaultKey),
		)
		if err != nil {
			return nil, false, err
		}

		return records, false, nil

	case operationsEntity.SyncModeManual:
		lastChangeID, err := s.vaultrecordService.GetSyncLatestChangeId(
			s.context.SelectedSoT.ID,
			vault.ID,
		)
		if err != nil {
			return records, false, err
		}

		totalChanges, err := s.vaultrecordService.GetChangeCount(
			s.context.SelectedSoT.ID,
			vault.ID,
			lastChangeID,
		)
		if err != nil {
			return records, false, err
		}

		var result contract.PendingTotalChanges
		err = s.appDeps.Client.GetRecordChangesCount(
			s.context.SelectedSoT.Address,
			vault.ID,
			lastChangeID,
			&result,
		)
		if err != nil {
			return records, false, err
		}

		totalChanges += result.Count

		return records, totalChanges > 0, nil
	}

	return records, false, nil
}

func (s *Service) ListPermissionGroup() ([]entity.PermissionGroup, error) {
	return s.vaultService.ListPermissionGroup(s.context.SelectedSoT.ID)
}

func (s *Service) GetWrappedKey(
	vaultID string,
) (string, error) {
	authUser, err := s.authUser()
	if err != nil {
		return "", err
	}

	vaData, err := s.vaultService.FindByVaultAndPermission(
		vaultID,
		authUser.PermissionID,
	)
	if err != nil {
		return "", err
	}

	return vaData.VaultKey, nil
}
