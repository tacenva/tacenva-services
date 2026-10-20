package accesscontrol

import (
	"fmt"

	"github.com/tacenva/tacenva-services/app"
	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/util/keyring"
)

type remoteService struct {
	appDeps *app.Deps
	context *app.Context
}

func NewRemoteService(
	appDeps *app.Deps,
	context *app.Context,
) *remoteService {
	return &remoteService{
		appDeps: appDeps,
		context: context,
	}
}

func (s *remoteService) List() ([]entity.Permission, error) {
	if s.context.SelectedSoT == nil {
		return nil, fmt.Errorf("selected source of truth is nil")
	}

	return s.appDeps.Client.ListAccessControls(
		s.context.SelectedSoT.Address,
	)
}

func (s *remoteService) Get(
	id string,
) (*entity.Permission, error) {
	if s.context.SelectedSoT == nil {
		return nil, fmt.Errorf("selected source of truth is nil")
	}

	return s.appDeps.Client.GetAccessControl(
		s.context.SelectedSoT.Address,
		id,
	)
}

func (s *remoteService) Create(
	permission *entity.Permission,
) ([]entity.VaultAccess, *entity.Permission, *keyring.KeyPair, error) {
	if s.context.SelectedSoT == nil {
		return nil, nil, nil, fmt.Errorf(
			"selected source of truth is nil",
		)
	}

	if permission == nil {
		return nil, nil, nil, fmt.Errorf("permission is required")
	}

	result, err := s.appDeps.Client.CreateAccessControl(
		s.context.SelectedSoT.Address,
		permission,
	)
	if err != nil {
		return nil, nil, nil, err
	}

	return result.VaultAccessList, result.Permission, result.KeyPair, nil
}

func (s *remoteService) Update(
	permission *entity.Permission,
) error {
	if s.context.SelectedSoT == nil {
		return fmt.Errorf("selected source of truth is nil")
	}

	return s.appDeps.Client.UpdateAccessControl(
		s.context.SelectedSoT.Address,
		permission,
	)
}

func (s *remoteService) SetRevoked(
	id string,
	revoked bool,
) error {
	if s.context.SelectedSoT == nil {
		return fmt.Errorf("selected source of truth is nil")
	}

	return s.appDeps.Client.SetRevokedAccessControl(
		s.context.SelectedSoT.Address,
		id,
		revoked,
	)
}

func (s *remoteService) UserList(
	permissionID string,
) ([]entity.User, error) {
	if s.context.SelectedSoT == nil {
		return nil, fmt.Errorf(
			"selected source of truth is nil",
		)
	}

	return s.appDeps.Client.ListAccessControlUsers(
		s.context.SelectedSoT.Address,
		permissionID,
	)
}

func (s *remoteService) ApproveUser(
	userID string,
) (*entity.User, error) {
	if s.context.SelectedSoT == nil {
		return nil, fmt.Errorf("selected source of truth is nil")
	}

	return s.appDeps.Client.ApproveAccessControlUser(
		s.context.SelectedSoT.Address,
		userID,
	)
}

func (s *remoteService) RevokeUser(
	userID string,
) (*entity.User, error) {
	if s.context.SelectedSoT == nil {
		return nil, fmt.Errorf("selected source of truth is nil")
	}

	return s.appDeps.Client.RevokeAccessControlUser(
		s.context.SelectedSoT.Address,
		userID,
	)
}

func (s *remoteService) DeleteAccessControl(
	id string,
) error {
	if s.context.SelectedSoT == nil {
		return fmt.Errorf("selected source of truth is nil")
	}

	return s.appDeps.Client.DeleteAccessControl(
		s.context.SelectedSoT.Address,
		id,
	)
}

func (s *remoteService) GrantPrivilege(
	vaultAccessList []entity.VaultAccess,
) error {
	if s.context.SelectedSoT == nil {
		return fmt.Errorf("selected source of truth is nil")
	}

	return s.appDeps.Client.GrantVaultAccess(
		s.context.SelectedSoT.Address,
		vaultAccessList,
	)
}

func (s *remoteService) ListGroups() ([]entity.PermissionGroup, error) {
	if s.context.SelectedSoT == nil {
		return nil, fmt.Errorf("selected source of truth is nil")
	}

	return s.appDeps.Client.ListAccessControlGroups(
		s.context.SelectedSoT.Address,
	)
}

func (s *remoteService) UpdateGroup(
	group *entity.PermissionGroup,
) error {
	if s.context.SelectedSoT == nil {
		return fmt.Errorf("selected source of truth is nil")
	}

	return s.appDeps.Client.UpdateAccessControlGroup(
		s.context.SelectedSoT.Address,
		group,
	)
}

func (s *remoteService) DeleteGroup(groupID string) error {
	if s.context.SelectedSoT == nil {
		return fmt.Errorf("selected source of truth is nil")
	}

	return s.appDeps.Client.DeleteAccessControlGroup(
		s.context.SelectedSoT.Address,
		groupID,
	)
}
