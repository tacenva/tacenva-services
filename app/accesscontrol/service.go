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
	name string,
	privilege entity.Privilege,
) ([]entity.VaultAccess, *entity.Permission, *keyring.KeyPair, error) {
	if s.context.IsRemote {
		return s.remoteService.Create(name, privilege)
	}
	return s.localService.Create(name, privilege)
}

func (s *Service) ChangeName(
	id string,
	name string,
) error {
	if s.context.IsRemote {
		return s.remoteService.ChangeName(id, name)
	}
	return s.localService.ChangeName(id, name)
}

func (s *Service) ChangePrivilege(
	id string,
	privilege entity.Privilege,
) error {
	if s.context.IsRemote {
		return s.remoteService.ChangePrivilege(id, privilege)
	}
	return s.localService.ChangePrivilege(id, privilege)
}

func (s *Service) Revoke(
	id string,
) error {
	if s.context.IsRemote {
		return s.remoteService.Revoke(id)
	}
	return s.localService.Revoke(id)
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

func (s *Service) GrantPrivilege(
	id string,
	myVaultAccessList []entity.VaultAccess,
	keyPair *keyring.KeyPair,
) error {
	newVaultAccessList := make([]entity.VaultAccess, 0, len(myVaultAccessList))

	for _, vaultAccess := range myVaultAccessList {
		vaultKey, err := s.context.SelectedSoT.KeyPair.Open(
			vaultAccess.VaultKey,
		)
		if err != nil {
			return err
		}

		encryptedVaultKey, err := keyPair.Seal(vaultKey)
		if err != nil {
			return err
		}

		newVaultAccessList = append(
			newVaultAccessList,
			entity.VaultAccess{
				VaultID:      vaultAccess.VaultID,
				PermissionID: id,
				VaultKey:     encryptedVaultKey,
			},
		)
	}

	if s.context.IsRemote {
		return s.remoteService.GrantPrivilege(
			newVaultAccessList,
		)
	}

	return s.localService.GrantPrivilege(
		newVaultAccessList,
	)
}
