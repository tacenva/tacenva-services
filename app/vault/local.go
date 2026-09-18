package vault

import (
	"errors"

	"github.com/tacenva/database"
	"github.com/tacenva/tacenva-services/app"
	"github.com/tacenva/tacpass-core/auth"
	"github.com/tacenva/tacpass-core/config"
	coreEntity "github.com/tacenva/tacpass-core/entity"
	vaultCore "github.com/tacenva/tacpass-core/vault"
	vaultrecordCore "github.com/tacenva/tacpass-core/vaultrecord"
)

type localService struct {
	appDeps            *app.Deps
	context            *app.Context
	vaultService       *vaultCore.Service
	vaultrecordService *vaultrecordCore.Service
	authService        *auth.Service
}

func NewLocalService(
	appDeps *app.Deps,
	context *app.Context,
	vaultService *vaultCore.Service,
	vaultrecordService *vaultrecordCore.Service,
	authService *auth.Service,
) *localService {
	return &localService{
		appDeps:            appDeps,
		context:            context,
		vaultService:       vaultService,
		vaultrecordService: vaultrecordService,
		authService:        authService,
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

	vaultDir := s.appDeps.Config.Path(
		"node",
		s.context.SelectedSoT.ID,
		"vault",
	)

	vaultAccess, err := s.vaultService.Create(
		authUser,
		vaultDir,
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

	vaultDir := s.appDeps.Config.Path(
		"node",
		s.context.SelectedSoT.ID,
		"vault",
	)

	return s.vaultService.Delete(
		authUser,
		vaultDir,
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
	vaultAccess *coreEntity.VaultAccess,
	record *coreEntity.VaultRecord,
) (string, error) {
	vaultKey, err := s.unwrapVaultKey(vaultAccess)
	if err != nil {
		return "", nil
	}

	vaultDir := s.appDeps.Config.Path(
		"node",
		s.context.SelectedSoT.ID,
		"vault",
	)

	authUser, err := s.authUser()
	if err != nil {
		return "", err
	}

	return s.vaultrecordService.Create(authUser, vaultDir, vaultKey, vaultAccess.VaultID, record)
}

func (s *localService) UpdateRecord(
	vaultAccess *coreEntity.VaultAccess,
	record *coreEntity.VaultRecord,
) error {
	vaultKey, err := s.unwrapVaultKey(vaultAccess)
	if err != nil {
		return nil
	}

	vaultDir := s.appDeps.Config.Path(
		"node",
		s.context.SelectedSoT.ID,
		"vault",
	)

	authUser, err := s.authUser()
	if err != nil {
		return err
	}

	return s.vaultrecordService.Update(authUser, vaultDir, vaultKey, vaultAccess.VaultID, record)
}

func (s *localService) DeleteRecord(
	vaultAccess *coreEntity.VaultAccess,
	record *coreEntity.VaultRecord,
) error {
	vaultKey, err := s.unwrapVaultKey(vaultAccess)
	if err != nil {
		return nil
	}

	vaultDir := s.appDeps.Config.Path(
		"node",
		s.context.SelectedSoT.ID,
		"vault",
	)

	authUser, err := s.authUser()
	if err != nil {
		return err
	}

	return s.vaultrecordService.Delete(authUser, vaultDir, vaultKey, vaultAccess.VaultID, record.ID)
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

func (s *localService) unwrapVaultKey(
	vaultAccess *coreEntity.VaultAccess,
) (string, error) {
	vaultKey, err := s.context.SelectedSoT.KeyPair.Open(
		vaultAccess.VaultKey,
	)
	return string(vaultKey), err
}
