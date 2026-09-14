package accesscontrol

import (
	"fmt"

	"github.com/tacenva/tacenva-services/app"
	coreAC "github.com/tacenva/tacpass-core/accesscontrol"
	"github.com/tacenva/tacpass-core/auth"
	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/util/keyring"
)

type localService struct {
	appDeps *app.Deps
	context *app.Context

	coreACService *coreAC.Service
	authService   *auth.Service
}

func NewLocalService(
	appDeps *app.Deps,
	context *app.Context,
	coreACService *coreAC.Service,
	authService *auth.Service,
) *localService {
	return &localService{
		appDeps:       appDeps,
		context:       context,
		coreACService: coreACService,
		authService:   authService,
	}
}

func (s *localService) authUser() (*entity.User, error) {
	if s.context.SelectedSoT == nil {
		return nil, fmt.Errorf("selected source of truth is nil")
	}

	return s.authService.GetUserData(
		s.context.SelectedSoT.AuthToken,
	)
}

func (s *localService) List() ([]entity.Permission, error) {
	authUser, err := s.authUser()
	if err != nil {
		return nil, err
	}

	return s.coreACService.List(authUser)
}

func (s *localService) Get(
	id string,
) (*entity.Permission, error) {
	authUser, err := s.authUser()
	if err != nil {
		return nil, err
	}

	return s.coreACService.Get(
		authUser,
		id,
	)
}

func (s *localService) Create(
	name string,
	privilege entity.Privilege,
) ([]entity.VaultAccess, *entity.Permission, *keyring.KeyPair, error) {
	authUser, err := s.authUser()
	if err != nil {
		return nil, nil, nil, err
	}

	return s.coreACService.Create(
		authUser,
		name,
		privilege,
	)
}

func (s *localService) ChangeName(
	id string,
	name string,
) error {
	authUser, err := s.authUser()
	if err != nil {
		return err
	}

	return s.coreACService.ChangeName(
		authUser,
		id,
		name,
	)
}

func (s *localService) ChangePrivilege(
	id string,
	privilege entity.Privilege,
) error {
	authUser, err := s.authUser()
	if err != nil {
		return err
	}

	return s.coreACService.ChangePrivilege(
		authUser,
		id,
		privilege,
	)
}

func (s *localService) Revoke(
	id string,
) error {
	authUser, err := s.authUser()
	if err != nil {
		return err
	}

	return s.coreACService.Revoke(
		authUser,
		id,
	)
}

func (s *localService) UserList(
	permissionID string,
) ([]entity.User, error) {
	authUser, err := s.authUser()
	if err != nil {
		return nil, err
	}

	return s.coreACService.UserList(
		authUser,
		permissionID,
	)
}

func (s *localService) ApproveUser(
	userID string,
) (*entity.User, error) {
	authUser, err := s.authUser()
	if err != nil {
		return nil, err
	}

	return s.coreACService.ApproveUser(
		authUser,
		userID,
	)
}

func (s *localService) RevokeUser(
	userID string,
) (*entity.User, error) {
	authUser, err := s.authUser()
	if err != nil {
		return nil, err
	}

	return s.coreACService.RevokeUser(
		authUser,
		userID,
	)
}

func (s *localService) DeleteAccessControl(
	id string,
) error {
	authUser, err := s.authUser()
	if err != nil {
		return err
	}

	return s.coreACService.DeletePermission(
		authUser,
		id,
	)
}

func (s *localService) GrantPrivilege(
	vaultAccessList []entity.VaultAccess,
) error {
	authUser, err := s.authUser()
	if err != nil {
		return err
	}

	return s.coreACService.GrantPrivilege(
		authUser,
		vaultAccessList,
	)
}
