package accesscontrol

import (
	coreAC "github.com/tacenva/tacpass-core/accesscontrol"
	"github.com/tacenva/tacpass-core/auth"
	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/util/keyring"
	coreVault "github.com/tacenva/tacpass-core/vault"

	"github.com/tacenva/tacenva-services/app"
)

type Service struct {
	appDeps *app.Deps
	context *app.Context

	coreACService    *coreAC.Service
	coreVaultService *coreVault.Service
	authService      *auth.Service

	remoteService *remoteService
	localService  *localService
}

func NewService(
	appDeps *app.Deps,
	context *app.Context,
	coreACService *coreAC.Service,
	authService *auth.Service,
) *Service {
	return &Service{
		appDeps:       appDeps,
		context:       context,
		coreACService: coreACService,
		authService:   authService,

		remoteService: NewRemoteService(appDeps, context),
		localService:  NewLocalService(appDeps, context, coreACService, authService),
	}
}

func (s *Service) List() ([]entity.Permission, error) {
	if s.context.IsRemote {
		return s.remoteService.List()
	}
	return s.localService.List()
}

func (s *Service) Get(
	id string,
) (*entity.Permission, error) {
	if s.context.IsRemote {
		return s.remoteService.Get(id)
	}
	return s.localService.Get(id)
}

func (s *Service) Create(
	permission *entity.Permission,
) ([]entity.VaultAccess, *entity.Permission, *keyring.KeyPair, error) {
	if s.context.IsRemote {
		return s.remoteService.Create(permission)
	}

	return s.localService.Create(permission)
}

func (s *Service) Update(
	permission *entity.Permission,
) error {
	if s.context.IsRemote {
		return s.remoteService.Update(permission)
	}

	return s.localService.Update(permission)
}

func (s *Service) SetRevoked(
	id string,
	revoked bool,
) error {
	if s.context.IsRemote {
		return s.remoteService.SetRevoked(id, revoked)
	}

	return s.localService.SetRevoked(id, revoked)
}

func (s *Service) UserList(
	permissionID string,
) ([]entity.User, error) {
	if s.context.IsRemote {
		return s.remoteService.UserList(permissionID)
	}
	return s.localService.UserList(permissionID)
}

func (s *Service) ApproveUser(
	userID string,
) (*entity.User, error) {
	if s.context.IsRemote {
		return s.remoteService.ApproveUser(userID)
	}
	return s.localService.ApproveUser(userID)
}

func (s *Service) RevokeUser(
	userID string,
) (*entity.User, error) {
	if s.context.IsRemote {
		return s.remoteService.RevokeUser(userID)
	}
	return s.localService.RevokeUser(userID)
}

func (s *Service) DeleteAccessControl(
	id string,
) error {
	if s.context.IsRemote {
		return s.remoteService.DeleteAccessControl(id)
	}
	return s.localService.DeleteAccessControl(id)
}

func (s *Service) ListGroups() ([]entity.PermissionGroup, error) {
	if s.context.IsRemote {
		return s.remoteService.ListGroups()
	}

	return s.localService.ListGroups()
}

func (s *Service) UpdateGroup(
	group *entity.PermissionGroup,
) error {
	if s.context.IsRemote {
		return s.remoteService.UpdateGroup(group)
	}

	return s.localService.UpdateGroup(group)
}

func (s *Service) DeleteGroup(groupID string) error {
	if s.context.IsRemote {
		return s.remoteService.DeleteGroup(groupID)
	}

	return s.localService.DeleteGroup(groupID)
}
