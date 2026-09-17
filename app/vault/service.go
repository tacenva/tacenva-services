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
)

var (
	ErrForbidden = errors.New("Forbidden")
)

type Service struct {
	context   *app.Context
	masterKey string

	local  *localService
	Remote *remoteService
}

func NewService(
	appDeps *app.Deps,
	context *app.Context,
	masterKey string,
	vaultService *vaultCore.Service,
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
			authService,
		),

		Remote: NewRemoteService(
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
		return s.Remote.NeedSync()

	case operationsEntity.SyncModeAuto:
		vaultAccessList, err := s.Remote.Sync()
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
		return s.Remote.CreateVault(vaultName)
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
		return s.Remote.UpdateVault(vault)
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
		return s.Remote.DeleteVault(vault)
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

	vaultFile, err := s.openVaultFile(vaultAccess)
	if err != nil {
		if !s.context.IsRemote ||
			!errors.Is(err, database.ErrFileNotFound) {
			return nil, false, err
		}

		if err := s.Remote.FetchRecordBlob(
			vaultAccess.VaultID,
		); err != nil {
			return nil, false, err
		}

		vaultFile, err = s.openVaultFile(vaultAccess)
		if err != nil {
			return nil, false, err
		}
	}

	vaultRecords, err := s.local.ListRecords(vaultFile)
	if err != nil {
		return nil, false, err
	}

	if !s.context.IsRemote {
		return vaultRecords, false, nil
	}

	switch s.context.SelectedSoT.SyncMode {
	case operationsEntity.SyncModeManual:
		needSync, err := s.Remote.NeedSyncRecords(
			vaultAccess.VaultID,
		)
		if err != nil {
			return vaultRecords, false, err
		}

		return vaultRecords, needSync, nil

	case operationsEntity.SyncModeAuto:
		needSync, err := s.Remote.NeedSyncRecords(
			vaultAccess.VaultID,
		)
		if err != nil {
			return vaultRecords, false, err
		}

		if !needSync {
			return vaultRecords, false, nil
		}

		vaultRecords, err = s.Remote.SyncRecords(
			vaultAccess.VaultID,
		)
		if err != nil {
			return vaultRecords, false, err
		}

		return vaultRecords, false, nil

	default:
		return vaultRecords, false, nil
	}
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
		return s.Remote.AppendRecord(
			vaultAccess.VaultID,
			record,
			[]byte(encrypted),
		)
	}

	return s.local.AppendRecord(
		vaultFile,
		record,
	)
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
		return s.Remote.UpdateRecord(
			vaultAccess.VaultID,
			record,
			[]byte(encrypted),
		)
	}

	return s.local.UpdateRecord(
		vaultFile,
		record,
	)
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
		if err := s.Remote.DeleteRecord(
			vaultAccess.VaultID,
			record.ID,
		); err != nil {
			return err
		}
	}

	vaultFile, err := s.openVaultFile(vaultAccess)
	if err != nil {
		return err
	}

	return s.local.DeleteRecord(
		vaultFile,
		record.ID,
	)
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

	return s.local.OpenVaultFile(
		vaultAccess.VaultID,
		string(vaultKey),
	)
}
