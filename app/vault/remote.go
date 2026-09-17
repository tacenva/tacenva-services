package vault

import (
	"errors"
	"fmt"

	"github.com/tacenva/database"
	"github.com/tacenva/tacenva-services/app"
	"github.com/tacenva/tacenva-services/app/sourceoftruth"
	"github.com/tacenva/tacpass-core/config"
	coreEntity "github.com/tacenva/tacpass-core/entity"
)

type remoteService struct {
	appDeps    *app.Deps
	context    *app.Context
	masterKey  string
	sotService *sourceoftruth.Service
}

func NewRemoteService(
	appDeps *app.Deps,
	context *app.Context,
	masterKey string,
	sotService *sourceoftruth.Service,
) *remoteService {
	return &remoteService{
		appDeps:    appDeps,
		context:    context,
		masterKey:  masterKey,
		sotService: sotService,
	}
}

func (s *remoteService) FetchRecordBlob(
	vaultID string,
) error {
	blob, err := s.appDeps.Client.RecordBlob(
		s.context.SelectedSoT.Address,
		vaultID,
	)
	if err != nil {
		return err
	}

	return s.database().Write(
		vaultID,
		blob,
	)
}

func (s *remoteService) EnsureVaultFile(
	vaultID string,
	vaultKey string,
) (*database.DatabaseFile, error) {
	vaultFile, err := s.database().File(
		vaultID,
		vaultKey,
		database.FileModeOpen,
	)
	if err == nil {
		return vaultFile, nil
	}

	if !errors.Is(err, database.ErrFileNotFound) {
		return nil, err
	}

	if err := s.FetchRecordBlob(vaultID); err != nil {
		return nil, err
	}

	return s.database().File(
		vaultID,
		vaultKey,
		database.FileModeOpen,
	)
}

func (s *remoteService) ListVaults() (
	[]coreEntity.VaultAccess,
	error,
) {
	var vaultAccessList []coreEntity.VaultAccess

	if err := s.appDeps.Client.ListVault(
		s.context.SelectedSoT.Address,
		&vaultAccessList,
	); err != nil {
		return nil, err
	}

	vaultFile, err := s.database().File(
		"vault",
		s.masterKey,
		database.FileModeOpenOrCreate,
	)
	if err != nil {
		return nil, err
	}

	for i := range vaultAccessList {
		vaultAccess := vaultAccessList[i]

		if _, err := vaultFile.Insert(
			&vaultAccess,
		); err != nil {
			return nil, err
		}
	}

	return vaultAccessList, nil
}

func (s *remoteService) NeedSync() (
	[]coreEntity.VaultAccess,
	bool,
	error,
) {
	vaultFile, err := s.database().File(
		"vault",
		s.masterKey,
		database.FileModeOpen,
	)
	if err != nil {
		if errors.Is(err, database.ErrFileNotFound) {
			return nil, true, nil
		}

		return nil, false, err
	}

	var vaultAccessList []coreEntity.VaultAccess

	if err := vaultFile.FindAll(
		&vaultAccessList,
	); err != nil {
		return nil, false, err
	}

	var result struct {
		Count int64 `json:"count"`
	}

	if err := s.appDeps.Client.GetVaultChangesCount(
		s.context.SelectedSoT.Address,
		&result,
	); err != nil {
		return vaultAccessList, false, err
	}

	return vaultAccessList, result.Count > 0, nil
}

type vaultChange struct {
	SyncChange struct {
		ID        string `json:"id"`
		Sequence  uint64 `json:"sequence"`
		Entity    string `json:"entity"`
		EntityID  string `json:"entity_id"`
		Operation string `json:"operation"`
	} `json:"sync_change"`

	Vault *coreEntity.VaultAccess `json:"vault,omitempty"`
}

func (s *remoteService) Sync() (
	[]coreEntity.VaultAccess,
	error,
) {
	vaultFile, err := s.database().File(
		"vault",
		s.masterKey,
		database.FileModeOpen,
	)
	if err != nil {
		if errors.Is(err, database.ErrFileNotFound) {
			return s.ListVaults()
		}

		return nil, err
	}

	var vaultAccessList []coreEntity.VaultAccess

	if err := vaultFile.FindAll(
		&vaultAccessList,
	); err != nil {
		return nil, err
	}

	var changes []vaultChange

	if err := s.appDeps.Client.GetVaultChanges(
		s.context.SelectedSoT.Address,
		&changes,
	); err != nil {
		return vaultAccessList, err
	}

	changeIDs := make([]string, 0, len(changes))

	for _, change := range changes {
		switch change.SyncChange.Operation {
		case "create":
			if change.Vault == nil {
				return vaultAccessList, errors.New(
					"create vault change has empty vault",
				)
			}

			if _, err := vaultFile.Insert(
				change.Vault,
			); err != nil {
				return vaultAccessList, err
			}

		case "update":
			if change.Vault == nil {
				return vaultAccessList, errors.New(
					"update vault change has empty vault",
				)
			}

			if err := vaultFile.Update(
				change.Vault,
			); err != nil {
				return vaultAccessList, err
			}

		case "delete":
			if change.SyncChange.EntityID == "" {
				return vaultAccessList, errors.New(
					"delete vault change has empty entity id",
				)
			}

			if _, err := vaultFile.Delete(
				change.SyncChange.EntityID,
			); err != nil {
				return vaultAccessList, err
			}

		default:
			return vaultAccessList, fmt.Errorf(
				"unknown vault sync operation %q",
				change.SyncChange.Operation,
			)
		}

		if change.SyncChange.ID == "" {
			return vaultAccessList, errors.New(
				"vault sync change has empty id",
			)
		}

		changeIDs = append(
			changeIDs,
			change.SyncChange.ID,
		)
	}

	if len(changeIDs) > 0 {
		if err := s.appDeps.Client.MarkVaultChangesSynced(
			s.context.SelectedSoT.Address,
			changeIDs,
		); err != nil {
			return vaultAccessList, err
		}
	}

	if err := vaultFile.FindAll(
		&vaultAccessList,
	); err != nil {
		return vaultAccessList, err
	}

	return vaultAccessList, nil
}

func (s *remoteService) CreateVault(
	vaultName string,
) (*coreEntity.VaultAccess, error) {
	var vaultAccess coreEntity.VaultAccess

	body := struct {
		Name string `json:"name"`
	}{
		Name: vaultName,
	}

	if err := s.appDeps.Client.CreateVault(
		s.context.SelectedSoT.Address,
		body,
		&vaultAccess,
	); err != nil {
		return nil, err
	}

	vaultFile, err := s.database().File(
		"vault",
		s.masterKey,
		database.FileModeOpen,
	)
	if err != nil {
		return nil, err
	}

	if _, err := vaultFile.Insert(
		&vaultAccess,
	); err != nil {
		return nil, err
	}

	return &vaultAccess, nil
}

func (s *remoteService) UpdateVault(
	vault *coreEntity.Vault,
) error {
	var updated coreEntity.Vault

	if err := s.appDeps.Client.UpdateVault(
		s.context.SelectedSoT.Address,
		vault.ID,
		struct {
			Name string `json:"name"`
		}{
			Name: vault.Name,
		},
		&updated,
	); err != nil {
		return err
	}

	*vault = updated

	vaultFile, err := s.database().File(
		"vault",
		s.masterKey,
		database.FileModeOpen,
	)
	if err != nil {
		return err
	}

	var vaultAccessList []coreEntity.VaultAccess

	if err := vaultFile.FindWhere(
		&vaultAccessList,
		func(data map[string]any) bool {
			vaultID, ok := data["vault_id"]

			return ok && vaultID == vault.ID
		},
	); err != nil {
		return err
	}

	if len(vaultAccessList) == 0 {
		return errors.New("vault access not found")
	}

	vaultAccess := vaultAccessList[0]
	vaultAccess.Vault = *vault

	return vaultFile.Update(
		&vaultAccess,
	)
}

func (s *remoteService) DeleteVault(
	vault *coreEntity.Vault,
) error {
	if err := s.appDeps.Client.DeleteVault(
		s.context.SelectedSoT.Address,
		vault.ID,
	); err != nil {
		return err
	}

	vaultFile, err := s.database().File(
		"vault",
		s.masterKey,
		database.FileModeOpen,
	)
	if err != nil {
		return err
	}

	var vaultAccessList []coreEntity.VaultAccess

	if err := vaultFile.FindWhere(
		&vaultAccessList,
		func(data map[string]any) bool {
			vaultID, ok := data["vault_id"]

			return ok && vaultID == vault.ID
		},
	); err != nil {
		return err
	}

	if len(vaultAccessList) == 0 {
		return errors.New("vault access not found")
	}

	if _, err := vaultFile.Delete(
		vaultAccessList[0].ID,
	); err != nil {
		return err
	}

	return s.database().Delete(
		vault.ID,
	)
}

func (s *remoteService) NeedSyncRecords(
	vaultID string,
) (bool, error) {
	var result struct {
		Count int64 `json:"count"`
	}

	if err := s.appDeps.Client.GetRecordChangesCount(
		s.context.SelectedSoT.Address,
		vaultID,
		&result,
	); err != nil {
		return false, err
	}

	return result.Count > 0, nil
}

type recordChange struct {
	SyncChange struct {
		ID        string `json:"id"`
		Sequence  uint64 `json:"sequence"`
		Entity    string `json:"entity"`
		EntityID  string `json:"entity_id"`
		Operation string `json:"operation"`
	} `json:"sync_change"`

	Record []byte `json:"record,omitempty"`
}

func (s *remoteService) SyncRecords(
	vaultID string,
) ([]coreEntity.VaultRecord, error) {
	vaultFile, err := s.database().File(
		vaultID,
		s.masterKey,
		database.FileModeOpenOrCreate,
	)
	if err != nil {
		return nil, err
	}

	var changes []recordChange

	if err := s.appDeps.Client.GetRecordChanges(
		s.context.SelectedSoT.Address,
		vaultID,
		&changes,
	); err != nil {
		return nil, err
	}

	changeIDs := make([]string, 0, len(changes))

	for _, change := range changes {
		switch change.SyncChange.Operation {
		case "create":
			if len(change.Record) == 0 {
				return nil, errors.New(
					"create record change has empty record",
				)
			}

			if _, err := vaultFile.InsertRaw(
				change.Record,
			); err != nil {
				return nil, err
			}

		case "update":
			if len(change.Record) == 0 {
				return nil, errors.New(
					"update record change has empty record",
				)
			}

			if err := vaultFile.UpdateRaw(
				change.SyncChange.EntityID,
				change.Record,
			); err != nil {
				return nil, err
			}

		case "delete":
			if change.SyncChange.EntityID == "" {
				return nil, errors.New(
					"delete record change has empty entity id",
				)
			}

			if _, err := vaultFile.Delete(
				change.SyncChange.EntityID,
			); err != nil {
				return nil, err
			}

		default:
			return nil, fmt.Errorf(
				"unknown record sync operation %q",
				change.SyncChange.Operation,
			)
		}

		if change.SyncChange.ID == "" {
			return nil, errors.New(
				"record sync change has empty id",
			)
		}

		changeIDs = append(
			changeIDs,
			change.SyncChange.ID,
		)
	}

	if len(changeIDs) > 0 {
		if err := s.appDeps.Client.MarkRecordChangesSynced(
			s.context.SelectedSoT.Address,
			vaultID,
			changeIDs,
		); err != nil {
			return nil, err
		}
	}

	var vaultRecords []coreEntity.VaultRecord

	if err := vaultFile.FindAll(
		&vaultRecords,
	); err != nil {
		return nil, err
	}

	return vaultRecords, nil
}

func (s *remoteService) AppendRecord(
	vaultID string,
	record *coreEntity.VaultRecord,
	encrypted []byte,
) (*coreEntity.VaultRecord, error) {
	recordID, err := s.appDeps.Client.CreateRecordRaw(
		s.context.SelectedSoT.Address,
		vaultID,
		encrypted,
	)
	if err != nil {
		return nil, err
	}

	record.ID = recordID

	return record, nil
}

func (s *remoteService) UpdateRecord(
	vaultID string,
	record *coreEntity.VaultRecord,
	encrypted []byte,
) (*coreEntity.VaultRecord, error) {
	if err := s.appDeps.Client.UpdateRecordRaw(
		s.context.SelectedSoT.Address,
		vaultID,
		record.ID,
		encrypted,
	); err != nil {
		return nil, err
	}

	return record, nil
}

func (s *remoteService) DeleteRecord(
	vaultID string,
	recordID string,
) error {
	return s.appDeps.Client.DeleteRecord(
		s.context.SelectedSoT.Address,
		vaultID,
		recordID,
	)
}

func (s *remoteService) database() *database.DB {
	return database.New(
		s.appDeps.Config.Path(
			config.NodeDirName,
			s.context.SelectedSoT.ID,
			"vault",
		),
	)
}
