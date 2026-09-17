package vault

import (
	"errors"

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

func (s *remoteService) NeedSync() (
	[]coreEntity.VaultAccess,
	bool,
	error,
) {
	vaultFile, err := s.database().File(
		"vault",
		s.masterKey,
		database.FileModeOpenOrCreate,
	)
	if err != nil {
		return nil, false, err
	}

	var vaultAccessList []coreEntity.VaultAccess

	if err := vaultFile.FindAll(
		&vaultAccessList,
	); err != nil {
		return nil, false, err
	}

	var result struct {
		NeedSync bool `json:"need_sync"`
	}

	err = s.appDeps.Client.CheckVaultSync(
		s.context.SelectedSoT.Address,
		s.context.SelectedSoT.HashSync,
		&result,
	)
	if err != nil {
		return vaultAccessList, false, err
	}
	return vaultAccessList, result.NeedSync, nil
}

func (s *remoteService) Sync() (
	[]coreEntity.VaultAccess,
	error,
) {
	vaultFile, err := s.database().File(
		"vault",
		s.masterKey,
		database.FileModeOpenOrCreate,
	)
	if err != nil {
		return nil, err
	}

	var vaultAccessList []coreEntity.VaultAccess

	if err := vaultFile.FindAll(
		&vaultAccessList,
	); err != nil {
		return nil, err
	}

	var result struct {
		NeedSync        bool                     `json:"need_sync"`
		ServerVaultHash string                   `json:"server_vault_hash"`
		VaultAccessList []coreEntity.VaultAccess `json:"vault_access_list,omitempty"`
	}

	err = s.appDeps.Client.VaultSync(
		s.context.SelectedSoT.Address,
		s.context.SelectedSoT.HashSync,
		&result,
	)
	if err != nil {
		return vaultAccessList, err
	}

	if result.NeedSync {
		vaultAccessPointers := make(
			[]*coreEntity.VaultAccess,
			0,
			len(result.VaultAccessList),
		)

		for i := range result.VaultAccessList {
			vaultAccessPointers = append(
				vaultAccessPointers,
				&result.VaultAccessList[i],
			)
		}

		if err := vaultFile.Sync(
			vaultAccessPointers,
		); err != nil {
			return vaultAccessList, err
		}

		s.context.SelectedSoT.HashSync =
			result.ServerVaultHash

		if err := s.sotService.Update(
			s.context.SelectedSoT,
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

	err := s.appDeps.Client.CreateVault(
		s.context.SelectedSoT.Address,
		body,
		&vaultAccess,
	)
	if err != nil {
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

	err := s.appDeps.Client.UpdateVault(
		s.context.SelectedSoT.Address,
		vault.ID,
		struct {
			Name string `json:"name"`
		}{
			Name: vault.Name,
		},
		&updated,
	)
	if err != nil {
		return err
	}

	*vault = updated

	vaultFile, err := s.database().File(
		"vault",
		s.masterKey,
		database.FileModeOpenOrCreate,
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

	return vaultFile.Update(&vaultAccess)
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
		database.FileModeOpenOrCreate,
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

	return s.database().Delete(vault.ID)
}

func (s *remoteService) NeedSyncRecords(
	vaultID string,
) (bool, error) {
	version, err := s.database().GetVersion(vaultID)
	if err != nil {
		return false, err
	}

	var result struct {
		NeedSync bool `json:"need_sync"`
	}

	err = s.appDeps.Client.CheckRecordBlob(
		s.context.SelectedSoT.Address,
		vaultID,
		version,
		&result,
	)
	if err != nil {
		return false, err
	}

	return result.NeedSync, nil
}

func (s *remoteService) SyncRecords(
	vaultID string,
) ([]coreEntity.VaultRecord, error) {
	blob, err := s.appDeps.Client.RecordBlob(
		s.context.SelectedSoT.Address,
		vaultID,
	)
	if err != nil {
		return nil, err
	}

	if err := s.database().Write(
		vaultID,
		blob,
	); err != nil {
		return nil, err
	}

	vaultFile, err := s.database().File(
		vaultID,
		"",
		database.FileModeOpen,
	)
	if err != nil {
		return nil, err
	}

	var vaultRecords []coreEntity.VaultRecord

	if err := vaultFile.FindAll(
		&vaultRecords,
	); err != nil {
		return nil, err
	}

	return vaultRecords, nil
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
