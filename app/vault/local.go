package vault

import (
	"errors"

	"github.com/tacenva/database"
	"github.com/tacenva/tacenva-services/app"
	"github.com/tacenva/tacpass-core/auth"
	"github.com/tacenva/tacpass-core/config"
	coreEntity "github.com/tacenva/tacpass-core/entity"
	vaultCore "github.com/tacenva/tacpass-core/vault"
)

type localService struct {
	appDeps      *app.Deps
	context      *app.Context
	vaultService *vaultCore.Service
	authService  *auth.Service
}

func NewLocalService(
	appDeps *app.Deps,
	context *app.Context,
	vaultService *vaultCore.Service,
	authService *auth.Service,
) *localService {
	return &localService{
		appDeps:      appDeps,
		context:      context,
		vaultService: vaultService,
		authService:  authService,
	}
}

func (s *localService) authUser() (*coreEntity.User, error) {
	if s.context.SelectedSoT == nil {
		return nil, errors.New(
			"selected source of truth is nil",
		)
	}

	return s.authService.GetUserData(
		s.context.SelectedSoT.AuthToken,
	)
}

func (s *localService) List() (
	[]coreEntity.VaultAccess,
	error,
) {
	authUser, err := s.authUser()
	if err != nil {
		return nil, err
	}

	return s.vaultService.VaultAccessList(authUser)
}

func (s *localService) CreateVault(
	vaultName string,
) (*coreEntity.VaultAccess, error) {
	authUser, err := s.authUser()
	if err != nil {
		return nil, err
	}

	vaultAccess, err := s.vaultService.Create(
		authUser,
		vaultName,
	)
	if err != nil {
		return nil, err
	}

	db := s.database()

	vaultKey, err := s.context.SelectedSoT.KeyPair.Open(
		vaultAccess.VaultKey,
	)
	if err != nil {
		return nil, err
	}

	if _, err := db.File(
		vaultAccess.VaultID,
		string(vaultKey),
		database.FileModeOpenOrCreate,
	); err != nil {
		return nil, err
	}

	return vaultAccess, nil
}

func (s *localService) UpdateVault(
	vault *coreEntity.Vault,
) error {
	authUser, err := s.authUser()
	if err != nil {
		return err
	}

	_, err = s.vaultService.Update(
		authUser,
		vault.ID,
		vault.Name,
	)

	return err
}

func (s *localService) DeleteVault(
	vault *coreEntity.Vault,
) error {
	authUser, err := s.authUser()
	if err != nil {
		return err
	}

	return s.vaultService.Delete(
		authUser,
		vault.ID,
	)
}

func (s *localService) OpenVaultFile(
	vaultID string,
	vaultKey string,
) (*database.DatabaseFile, error) {
	return s.database().File(
		vaultID,
		vaultKey,
		database.FileModeOpen,
	)
}

func (s *localService) AppendRecord(
	vaultFile *database.DatabaseFile,
	record *coreEntity.VaultRecord,
) (*coreEntity.VaultRecord, error) {
	recordID, err := vaultFile.Insert(record)
	if err != nil {
		return nil, err
	}

	record.ID = recordID

	return record, nil
}

func (s *localService) UpdateRecord(
	vaultFile *database.DatabaseFile,
	record *coreEntity.VaultRecord,
) (*coreEntity.VaultRecord, error) {
	if err := vaultFile.Update(record); err != nil {
		return nil, err
	}

	return record, nil
}

func (s *localService) DeleteRecord(
	vaultFile *database.DatabaseFile,
	recordID string,
) error {
	_, err := vaultFile.Delete(recordID)
	return err
}

func (s *localService) database() *database.DB {
	return database.New(
		s.appDeps.Config.Path(
			config.NodeDirName,
			s.context.SelectedSoT.ID,
			"vault",
		),
	)
}
