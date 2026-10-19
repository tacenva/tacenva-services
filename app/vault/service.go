package vault

import (
	"errors"
	"fmt"

	"github.com/tacenva/database"
	"github.com/tacenva/tacenva-services/app"
	"github.com/tacenva/tacenva-services/app/sourceoftruth"

	operationsEntity "github.com/tacenva/tacenva-services/entity"
	"github.com/tacenva/tacpass-core/auth"
	"github.com/tacenva/tacpass-core/contract"
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
) ([]contract.PendingVaultChange, error) {
	changeCount, err := s.vaultService.GetChangeCount(
		s.context.SelectedSoT.ID,
		lastChangeID,
	)
	if err != nil {
		return nil, err
	}

	if changeCount == 0 {
		return nil, nil
	}

	return s.vaultService.GetChangesAfterOnReplica(
		s.context.SelectedSoT.ID,
		lastChangeID,
		int(changeCount),
		vaultFile,
	)
}

func (s *Service) getClientVaultChanges(
	lastChangeID string,
) ([]contract.PendingVaultChange, error) {
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

	var changes []contract.PendingVaultChange

	err = s.appDeps.Client.GetVaultChanges(
		s.context.SelectedSoT.Address,
		lastChangeID,
		int(result.Count),
		&changes,
	)
	if err != nil {
		return nil, err
	}

	return changes, nil
}

func (s *Service) List() ([]coreEntity.VaultAccess, bool, error) {
	var (
		vaList []coreEntity.VaultAccess
		err    error
	)

	if !s.context.IsRemote {
		authUser, err := s.authUser()
		if err != nil {
			return nil, false, err
		}
		vaList, err = s.vaultService.VaultAccessList(authUser)
		if err != nil {
			return nil, false, err
		}
		return vaList, false, err
	}

	dbFile, err := s.openVaultFile()
	err = dbFile.FindAll(&vaList).Order("ID ASC").Err

	switch s.context.SelectedSoT.SyncMode {
	case operationsEntity.SyncModeAuto:
		err = s.SyncVault()
		return vaList, err != nil, err
	case operationsEntity.SyncModeManual:
		lastChangeID, err := s.vaultService.GetSyncLatestChangeId(s.context.SelectedSoT.ID)
		if err != nil {
			return vaList, false, err
		}

		totalChanges, err := s.vaultService.GetChangeCount(s.context.SelectedSoT.ID, lastChangeID)
		if err != nil {
			return vaList, false, err
		}

		// fmt.Printf("total 1: %d\n", totalChanges)

		var result struct {
			Count int64 `json:"count"`
		}
		err = s.appDeps.Client.GetVaultChangesCount(
			s.context.SelectedSoT.Address,
			lastChangeID,
			&result,
		)
		if err != nil {
			return vaList, false, err
		}

		totalChanges += result.Count
		// fmt.Printf("total 2: %d\n", totalChanges)

		return vaList, totalChanges > 0, nil
	}
	return nil, false, nil
}

func (s *Service) SyncVault() error {
	if !s.context.IsRemote {
		return nil
	}

	lastChangeID, err := s.vaultService.GetSyncLatestChangeId(s.context.SelectedSoT.ID)
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

	clientChangesToSync := s.vaultService.MergePendingVaultChange(localChanges, clientChanges)

	// debug, _ := json.MarshalIndent(clientChangesToSync, "", "  ")
	// log.Printf("clientChangesToSync:\n%s", debug)

	var permissionList []coreEntity.Permission
	if err = s.appDeps.Client.ConnectedPublicKeys(
		s.context.SelectedSoT.Address,
		&permissionList,
	); err != nil {
		return err
	}

	// debug, _ = json.MarshalIndent(permissionList, "", "  ")
	// log.Printf("permissionList:\n%s", debug)
	// log.Printf("jumlah changes: %d", len(clientChangesToSync))

	for changeIndex := range clientChangesToSync {
		change := &clientChangesToSync[changeIndex]

		if change.SyncChange.Operation == "delete" {
			continue
		}

		if len(change.VaultAccessList) == 0 {
			continue
		}

		keyPair := keyring.FromKeys(
			s.context.SelectedSoT.KeyPair.PublicKey,
			s.context.SelectedSoT.KeyPair.PrivateKey,
		)

		vaultKey, err := keyPair.Open(change.VaultAccessList[0].VaultKey)
		if err != nil {
			return err
		}

		for _, permissionData := range permissionList {
			keyPair := keyring.FromPublicKey(permissionData.PublicKey)

			wrappedVaultKey, err := keyPair.Seal([]byte(vaultKey))
			if err != nil {
				return err
			}

			// log.Printf("base: %s\ncomp: %s\n", permissionData.PublicKey, s.context.SelectedSoT.KeyPair.PublicKey)
			if permissionData.PublicKey == s.context.SelectedSoT.KeyPair.PublicKey {
				change.VaultAccessList[0].PermissionID = permissionData.ID
			} else {
				access := coreEntity.VaultAccess{
					VaultID:      change.Vault.ID,
					PermissionID: permissionData.ID,
					VaultKey:     wrappedVaultKey,
				}
				change.VaultAccessList = append(change.VaultAccessList, access)
			}
		}
	}

	// debug, _ = json.MarshalIndent(clientChangesToSync, "", "  ")
	// log.Printf("clientChangesToSync:\n%s", debug)

	if err := s.appDeps.Client.SyncVault(
		s.context.SelectedSoT.Address,
		clientChangesToSync,
	); err != nil {
		return err
	}

	return s.vaultService.SetSyncStateToBeLastest(s.context.SelectedSoT.ID)
}

func (s *Service) CreateVault(
	vaultName string,
) (*coreEntity.VaultAccess, error) {
	if s.context == nil {
		return nil, errors.New("context is nil")
	}

	if s.context.SelectedSoT == nil {
		return nil, errors.New(
			"selected source of truth is nil",
		)
	}

	var (
		syncChangeID string
		vaData       *coreEntity.VaultAccess
	)

	if !s.context.IsRemote {
		authUser, err := s.authUser()
		if err != nil {
			return nil, err
		}

		vaData, err := s.vaultService.CreateOnSoT(
			authUser,
			s.vaultDir(),
			&coreEntity.Vault{
				Name: vaultName,
			},
			s.context.SelectedSoT.ID,
			&syncChangeID,
		)
		if err != nil {
			return nil, err
		}

		return vaData, err
	}

	dbFile, err := s.openVaultFile()
	if err != nil {
		return nil, err
	}

	_, err = s.vaultService.CreateOnReplica(
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
		return vaData, err
	}

	if s.context.SelectedSoT.SyncMode == operationsEntity.SyncModeAuto {
		err = s.SyncVault()
	}

	return vaData, err
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

		_, err = s.vaultService.UpdateOnSoT(
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

	_, err = s.vaultService.UpdateOnReplica(
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
	vaultAccess *coreEntity.VaultAccess,
	record *coreEntity.VaultRecord,
) (*coreEntity.VaultRecord, error) {
	if vaultAccess == nil {
		return nil, errors.New(
			"vault access cannot be nil",
		)
	}

	if record == nil {
		return nil, errors.New(
			"record cannot be nil",
		)
	}

	if vaultAccess.VaultID == "" {
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

	vaultFile, err := s.openRecordFile(vaultAccess)
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

	err = s.vaultrecordService.Create(
		vaultDir,
		vaultAccess.VaultID,
		&recordID,
		[]byte(encrypted),
		s.context.SelectedSoT.ID,
		&syncChangeID,
	)
	if err != nil {
		return nil, err
	}

	record.ID = recordID

	if s.context.SelectedSoT.SyncMode == operationsEntity.SyncModeAuto {
		err = s.SyncRecord(vaultAccess)
		if err != nil {
			return nil, err
		}
	}
	return record, nil
}

func (s *Service) UpdateRecord(
	vaultAccess *coreEntity.VaultAccess,
	record *coreEntity.VaultRecord,
) (*coreEntity.VaultRecord, error) {
	if vaultAccess == nil {
		return nil, errors.New(
			"vault access cannot be nil",
		)
	}

	if record == nil {
		return nil, errors.New(
			"record cannot be nil",
		)
	}

	if vaultAccess.VaultID == "" {
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

	vaultFile, err := s.openRecordFile(vaultAccess)
	if err != nil {
		return nil, err
	}

	encrypted, err := vaultFile.SimulateEncryption(record)
	if err != nil {
		return nil, err
	}

	vaultDir := s.vaultDir()

	var syncChangeID string

	err = s.vaultrecordService.Update(
		vaultDir,
		vaultAccess.VaultID,
		record.ID,
		[]byte(encrypted),
		s.context.SelectedSoT.ID,
		&syncChangeID,
	)
	if err != nil {
		return nil, err
	}

	if s.context.SelectedSoT.SyncMode == operationsEntity.SyncModeAuto {
		err = s.SyncRecord(vaultAccess)
		if err != nil {
			return nil, err
		}
	}

	return record, nil
}

func (s *Service) DeleteRecord(
	vaultAccess *coreEntity.VaultAccess,
	record *coreEntity.VaultRecord,
) error {
	if vaultAccess == nil {
		return errors.New(
			"vault access cannot be nil",
		)
	}

	if record == nil {
		return errors.New(
			"record cannot be nil",
		)
	}

	if vaultAccess.VaultID == "" {
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
	err := s.vaultrecordService.Delete(
		vaultDir,
		vaultAccess.VaultID,
		record.ID,
		s.context.SelectedSoT.ID,
		&syncChangeID,
	)
	if err != nil {
		return err
	}

	if s.context.SelectedSoT.SyncMode == operationsEntity.SyncModeAuto {
		err = s.SyncRecord(vaultAccess)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Service) SyncRecord(
	vaultAccess *coreEntity.VaultAccess,
) error {
	vaultDir := s.vaultDir()

	lastChangeID, err := s.vaultrecordService.GetSyncLatestChangeId(
		s.context.SelectedSoT.ID,
		vaultAccess.VaultID,
	)
	if err != nil {
		return err
	}

	localChanges, err := s.getLocalRecordChanges(
		vaultDir,
		vaultAccess.VaultID,
		lastChangeID,
	)
	if err != nil {
		return err
	}

	clientChanges, err := s.getClientRecordChanges(
		vaultAccess.VaultID,
		lastChangeID,
	)
	if err != nil {
		return err
	}

	localChangesToSync := s.vaultrecordService.MergePendingVaultRecordChange(
		clientChanges,
		localChanges,
	)

	if err := s.vaultrecordService.Sync(
		vaultDir,
		s.context.SelectedSoT.ID,
		vaultAccess.VaultID,
		localChangesToSync,
	); err != nil {
		return err
	}

	clientChangesToSync := s.vaultrecordService.MergePendingVaultRecordChange(
		localChanges,
		clientChanges,
	)

	if err := s.appDeps.Client.SyncRecords(
		s.context.SelectedSoT.Address,
		vaultAccess.VaultID,
		clientChangesToSync,
	); err != nil {
		return err
	}

	return s.vaultrecordService.SetSyncStateToBeLastest(
		s.context.SelectedSoT.ID,
		vaultAccess.VaultID,
	)
}

func (s *Service) getLocalRecordChanges(
	vaultDir string,
	vaultID string,
	lastChangeID string,
) ([]contract.PendingVaultRecordChange, error) {
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
) ([]contract.PendingVaultRecordChange, error) {
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

	var changes []contract.PendingVaultRecordChange

	err = s.appDeps.Client.GetRecordChanges(
		s.context.SelectedSoT.Address,
		vaultID,
		lastChangeID,
		int(result.Count),
		&changes,
	)
	if err != nil {
		return nil, err
	}

	return changes, nil
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
	vaultAccess *coreEntity.VaultAccess,
) (*database.DatabaseFile, error) {
	vaultKey, err := s.context.SelectedSoT.KeyPair.Open(
		vaultAccess.VaultKey,
	)
	if err != nil {
		return nil, err
	}

	vaultDir := s.vaultDir()
	db := database.New(vaultDir)

	return db.File(
		vaultAccess.VaultID,
		string(vaultKey),
		database.FileModeOpen,
	)
}

func (s *Service) ListRecord(
	vaultAccess *coreEntity.VaultAccess,
) ([]coreEntity.VaultRecord, bool, error) {
	if vaultAccess == nil {
		return nil, false, errors.New(
			"vault access cannot be nil",
		)
	}

	if vaultAccess.VaultID == "" {
		fmt.Println("Di sini?")
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
	vaultKey, err := s.context.SelectedSoT.KeyPair.Open(vaultAccess.VaultKey)
	if err != nil {
		return nil, false, err
	}

	records, err := s.vaultrecordService.List(
		vaultDir,
		vaultAccess.VaultID,
		string(vaultKey),
	)
	if err != nil {
		if err == database.ErrFileNotFound && s.context.IsRemote {
			recordBlob, err := s.appDeps.Client.RecordBlob(
				s.context.SelectedSoT.Address,
				vaultAccess.VaultID,
			)
			if err != nil {
				return nil, false, err
			}

			db := database.New(vaultDir)
			err = db.Write(vaultAccess.VaultID, recordBlob)
			if err != nil {
				return nil, false, err
			}

			records, err = s.vaultrecordService.List(
				vaultDir,
				vaultAccess.VaultID,
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
		if err := s.SyncRecord(vaultAccess); err != nil {
			return records, true, err
		}

		records, err = s.vaultrecordService.List(
			vaultDir,
			vaultAccess.VaultID,
			string(vaultKey),
		)
		if err != nil {
			return nil, false, err
		}

		return records, false, nil

	case operationsEntity.SyncModeManual:
		lastChangeID, err := s.vaultrecordService.GetSyncLatestChangeId(
			s.context.SelectedSoT.ID,
			vaultAccess.VaultID,
		)
		if err != nil {
			return records, false, err
		}

		totalChanges, err := s.vaultrecordService.GetChangeCount(
			s.context.SelectedSoT.ID,
			vaultAccess.VaultID,
			lastChangeID,
		)
		if err != nil {
			return records, false, err
		}

		var result struct {
			Count int64 `json:"count"`
		}
		err = s.appDeps.Client.GetRecordChangesCount(
			s.context.SelectedSoT.Address,
			vaultAccess.VaultID,
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
