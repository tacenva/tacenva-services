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
	if s.context.SelectedSot == nil {
		return nil, fmt.Errorf("selected source of truth is nil")
	}

	return s.authService.GetUserData(
		s.context.SelectedSot.AuthToken,
	)
}

func (s *localService) List() ([]entity.Permission, error) {
	authUser, err := s.authUser()
	if err != nil {
		return nil, err
	}

	return s.coreACService.List(authUser)
}

func (s *localService) Create(
	permission *entity.Permission,
) (*entity.Permission, *keyring.KeyPair, error) {
	authUser, err := s.authUser()
	if err != nil {
		return nil, nil, err
	}

	if permission == nil {
		return nil, nil, fmt.Errorf("permission is required")
	}

	return s.coreACService.Create(
		authUser,
		permission.Name,
		permission.Privilege,
		&permission.Group,
		permission.AutoApprove,
		s.context.SelectedSot.ID,
	)
}

func (s *localService) Update(
	permission *entity.Permission,
) error {
	authUser, err := s.authUser()
	if err != nil {
		return err
	}

	return s.coreACService.Update(authUser, permission, permission.SotID)
}

func (s *localService) SetRevoked(
	id string,
	revoked bool,
	sotID string,
) error {
	authUser, err := s.authUser()
	if err != nil {
		return err
	}

	return s.coreACService.SetRevoked(
		authUser,
		id,
		sotID,
		revoked,
	)
}

func (s *localService) UserList(
	permissionID string,
	sotID string,
) ([]entity.User, error) {
	authUser, err := s.authUser()
	if err != nil {
		return nil, err
	}

	return s.coreACService.UserList(
		authUser,
		permissionID,
		sotID,
	)
}

func (s *localService) ApproveUser(
	userID string,
	sotID string,
) (*entity.User, error) {
	authUser, err := s.authUser()
	if err != nil {
		return nil, err
	}

	return s.coreACService.ApproveUser(
		authUser,
		userID,
		sotID,
	)
}

func (s *localService) RevokeUser(
	userID string,
	sotID string,
) (*entity.User, error) {
	authUser, err := s.authUser()
	if err != nil {
		return nil, err
	}

	return s.coreACService.RevokeUser(
		authUser,
		userID,
		sotID,
	)
}

func (s *localService) DeleteAccessControl(
	id string,
	sotID string,
) error {
	authUser, err := s.authUser()
	if err != nil {
		return err
	}

	return s.coreACService.DeletePermission(
		authUser,
		id,
		sotID,
	)
}

// func (s *localService) ListGroups() ([]entity.PermissionGroup, error) {
// 	authUser, err := s.authUser()
// 	if err != nil {
// 		return nil, err
// 	}

// 	return s.coreACService.GetGroupDescendants(authUser)
// }

func (s *localService) UpdateGroup(
	group *entity.PermissionGroup,
	sotID string,
) error {
	authUser, err := s.authUser()
	if err != nil {
		return err
	}

	return s.coreACService.UpdateGroup(authUser, group, sotID)
}

func (s *localService) DeleteGroup(groupID string, sotID string) error {
	authUser, err := s.authUser()
	if err != nil {
		return err
	}

	return s.coreACService.DeleteGroup(authUser, groupID, sotID)
}
