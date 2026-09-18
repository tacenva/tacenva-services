package vault

import (
	"errors"

	"github.com/tacenva/database"
	"github.com/tacenva/tacenva-services/app"
	"github.com/tacenva/tacenva-services/app/sourceoftruth"

	operationsEntity "github.com/tacenva/tacenva-services/entity"
	"github.com/tacenva/tacpass-core/auth"
	coreEntity "github.com/tacenva/tacpass-core/entity"
	vaultCore "github.com/tacenva/tacpass-core/vault"
	vaultrecordCore "github.com/tacenva/tacpass-core/vaultrecord"
)

var (
	ErrForbidden = errors.New("Forbidden")
)

type Service struct {
	context   *app.Context
	masterKey string

	local  *localService
	remote *remoteService
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
		context:   context,
		masterKey: masterKey,

		local: NewLocalService(
			appDeps,
			context,
			vaultService,
			vaultrecordService,
			authService,
		),

		remote: NewRemoteService(
			appDeps,
			context,
			masterKey,
			sotService,
		),
	}
}

func (s *Service) List() ([]coreEntity.VaultAccess, bool, error) {
	if s.context == nil {
		return nil, false, errors.New("context is nil")
	}

	if s.context.SelectedSoT == nil {
		return nil, false, errors.New(
			"selected source of truth is nil",
		)
	}

	if !s.context.IsRemote {
		vaultAccessList, err := s.local.List()
		if err != nil {
			return nil, false, err
		}

		return vaultAccessList, false, nil
	}

	switch s.context.SelectedSoT.SyncMode {
	case operationsEntity.SyncModeManual:
		return s.remote.NeedSync()

	case operationsEntity.SyncModeAuto:
		vaultAccessList, err := s.remote.Sync()
		if err != nil {
			return vaultAccessList, false, err
		}

		return vaultAccessList, false, nil

	default:
		return nil, false, nil
	}
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

	if s.context.IsRemote {
		return s.remote.CreateVault(vaultName)
	}

	return s.local.CreateVault(vaultName)
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

	if s.context.IsRemote {
		return s.remote.UpdateVault(vault)
	}

	return s.local.UpdateVault(vault)
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

	if s.context.IsRemote {
		return s.remote.DeleteVault(vault)
	}

	return s.local.DeleteVault(vault)
}

func (s *Service) ListRecords(
	vaultAccess *coreEntity.VaultAccess,
) ([]coreEntity.VaultRecord, bool, error) {
	if vaultAccess == nil {
		return nil, false, errors.New(
			"vault access cannot be nil",
		)
	}

	if vaultAccess.VaultID == "" {
		return nil, false, errors.New(
			"vault id cannot be empty",
		)
	}

	if s.context == nil {
		return nil, false, errors.New("context is nil")
	}

	if s.context.SelectedSoT == nil {
		return nil, false, errors.New(
			"selected source of truth is nil",
		)
	}

	vaultKey, err := s.context.SelectedSoT.KeyPair.Open(
		vaultAccess.VaultKey,
	)
	if err != nil {
		return nil, false, err
	}

	var vaultFile *database.DatabaseFile

	if s.context.IsRemote {
		vaultFile, err = s.remote.EnsureVaultFile(
			vaultAccess.VaultID,
			string(vaultKey),
		)
	} else {
		vaultFile, err = s.local.OpenVaultFile(
			vaultAccess.VaultID,
			string(vaultKey),
		)
	}

	if err != nil {
		return nil, false, err
	}

	var vaultRecords []coreEntity.VaultRecord

	if err := vaultFile.FindAll(&vaultRecords); err != nil {
		return nil, false, err
	}

	if !s.context.IsRemote {
		return vaultRecords, false, nil
	}

	switch s.context.SelectedSoT.SyncMode {
	case operationsEntity.SyncModeManual:
		needSync, err := s.remote.NeedSyncRecords(
			vaultAccess.VaultID,
		)
		if err != nil {
			return vaultRecords, false, err
		}

		return vaultRecords, needSync, nil

	case operationsEntity.SyncModeAuto:
		needSync, err := s.remote.NeedSyncRecords(
			vaultAccess.VaultID,
		)
		if err != nil {
			return vaultRecords, false, err
		}

		if !needSync {
			return vaultRecords, false, nil
		}

		vaultRecords, err = s.remote.SyncRecords(
			vaultAccess.VaultID,
			string(vaultKey),
		)
		if err != nil {
			return vaultRecords, false, err
		}

		return vaultRecords, false, nil

	default:
		return vaultRecords, false, nil
	}
}

func (s *Service) SyncRecords(
	vaultAccess *coreEntity.VaultAccess,
) ([]coreEntity.VaultRecord, error) {
	vaultKey, err := s.context.SelectedSoT.KeyPair.Open(
		vaultAccess.VaultKey,
	)
	if err != nil {
		return nil, err
	}

	return s.remote.SyncRecords(
		vaultAccess.VaultID,
		string(vaultKey),
	)
}

func (s *Service) Sync() ([]coreEntity.VaultAccess, error) {
	return s.remote.Sync()
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

	vaultFile, err := s.openVaultFile(vaultAccess)
	if err != nil {
		return nil, err
	}

	encrypted, err := vaultFile.SimulateEncryption(record)
	if err != nil {
		return nil, err
	}

	if s.context.IsRemote {
		record, err = s.remote.AppendRecord(
			vaultAccess.VaultID,
			record,
			[]byte(encrypted),
		)
		if err != nil {
			return nil, err
		}

		if _, err := vaultFile.Insert(record); err != nil {
			return nil, err
		}

		return record, nil
	}

	newID, err := s.local.AppendRecord(
		vaultAccess,
		record,
	)
	if err != nil {
		return nil, err
	}

	record.ID = newID

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

	vaultFile, err := s.openVaultFile(vaultAccess)
	if err != nil {
		return nil, err
	}

	encrypted, err := vaultFile.SimulateEncryption(record)
	if err != nil {
		return nil, err
	}

	if s.context.IsRemote {
		record, err = s.remote.UpdateRecord(
			vaultAccess.VaultID,
			record,
			[]byte(encrypted),
		)
		if err != nil {
			return nil, err
		}

		if err := vaultFile.Update(record); err != nil {
			return nil, err
		}

		return record, nil
	}

	if err := s.local.UpdateRecord(
		vaultAccess,
		record,
	); err != nil {
		return nil, err
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

	if s.context.IsRemote {
		if err := s.remote.DeleteRecord(
			vaultAccess.VaultID,
			record.ID,
		); err != nil {
			return err
		}
	}

	return s.local.DeleteRecord(vaultAccess, record)
}

func (s *Service) openVaultFile(
	vaultAccess *coreEntity.VaultAccess,
) (*database.DatabaseFile, error) {
	vaultKey, err := s.context.SelectedSoT.KeyPair.Open(
		vaultAccess.VaultKey,
	)
	if err != nil {
		return nil, err
	}

	if s.context.IsRemote {
		return s.remote.EnsureVaultFile(
			vaultAccess.VaultID,
			string(vaultKey),
		)
	}

	return s.local.OpenVaultFile(
		vaultAccess.VaultID,
		string(vaultKey),
	)
}
