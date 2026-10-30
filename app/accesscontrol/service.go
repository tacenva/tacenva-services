package accesscontrol

import (
	"errors"

	tacenvaaccesscontrol "github.com/tacenva/tacenva-core/accesscontrol"
	tacenvacontract "github.com/tacenva/tacenva-core/contract"
	tacenvaentity "github.com/tacenva/tacenva-core/entity"
	"github.com/tacenva/tacenva-core/util/keyring"

	"github.com/tacenva/tacenva-services/app"
)

type Service struct {
	appDeps *app.Deps
	context *app.Context

	accesscontrolService *tacenvaaccesscontrol.Service

	selectedGroup          *tacenvaentity.AccessGroup
	keyPairOfSelectedGroup *keyring.KeyPair
}

func NewService(
	appDeps *app.Deps,
	context *app.Context,
	accesscontrolService *tacenvaaccesscontrol.Service,
) *Service {
	return &Service{
		appDeps:              appDeps,
		context:              context,
		accesscontrolService: accesscontrolService,
	}
}

func (s *Service) SetSelectedGroup(selectedGroup *tacenvaentity.AccessGroup) {
	s.selectedGroup = selectedGroup
	s.keyPairOfSelectedGroup = keyring.FromPublicKey(selectedGroup.PublicKey)
}

func (s *Service) CreateGroup(
	newAccessGroup *tacenvaentity.AccessGroup,
	adminUnit *tacenvaentity.AccessUnit,
	parentAccess bool,
) error {
	keyPairForAccessUnit, err := keyring.GenerateKeyPair()
	if err != nil {
		return err
	}
	adminUnit.PublicKey = keyPairForAccessUnit.PublicKey
	adminUnit.SotID = s.selectedGroup.ID

	keyPairForAccessGroup, err := keyring.GenerateKeyPair()
	if err != nil {
		return err
	}
	newAccessGroup.PublicKey = keyPairForAccessGroup.PublicKey

	wrappedGroupKey, err := keyPairForAccessUnit.Seal(
		[]byte(keyPairForAccessGroup.PrivateKey),
	)
	if err != nil {
		return err
	}

	wrappedHierarchyKey := ""
	if parentAccess {
		if s.keyPairOfSelectedGroup == nil {
			return errors.New("Parent group have not selected yet")
		}

		wrappedHierarchyKey, err = s.keyPairOfSelectedGroup.Seal(
			[]byte(keyPairForAccessGroup.PrivateKey),
		)
		if err != nil {
			return err
		}
	}

	req := tacenvacontract.AccessGroupSetupRequest{
		AccessGroup:         newAccessGroup,
		AdminUnit:           adminUnit,
		ParentGroupID:       s.selectedGroup.ID,
		WrappedGroupKey:     wrappedGroupKey,
		WrappedHierarchyKey: wrappedHierarchyKey,
	}

	if s.context.IsRemote {
		return s.appDeps.Client.CreateAccessGroup(
			s.context.SelectedSot.Address,
			&req,
		)
	}
	return s.accesscontrolService.CreateGroup(
		s.context.AuthorizedUser,
		&req,
	)
}

func (s *Service) UpdateGroup(
	toUpdateAccessGroup *tacenvaentity.AccessGroup,
) error {
	if s.context.IsRemote {
		return s.appDeps.Client.UpdateAccessGroup(
			s.context.SelectedSot.Address,
			toUpdateAccessGroup.ID,
			toUpdateAccessGroup,
		)
	}
	return s.accesscontrolService.UpdateGroup(
		s.context.AuthorizedUser,
		toUpdateAccessGroup,
	)
}

func (s *Service) DeleteGroup(
	groupID string,
) error {
	if s.context.IsRemote {
		return s.appDeps.Client.DeleteAccessGroup(
			s.context.SelectedSot.Address,
			groupID,
		)
	}
	return s.accesscontrolService.DeleteGroup(
		s.context.AuthorizedUser,
		groupID,
	)
}

func (s *Service) GroupWithChildren(
	selectedGroup *tacenvaentity.AccessGroup,
) ([]tacenvacontract.AccessGroupTree, error) {
	selectedGroupID := ""
	if selectedGroup != nil {
		selectedGroupID = selectedGroup.ID
	}
	if s.context.IsRemote {
		return s.appDeps.Client.AccessGroupWithChildren(
			s.context.SelectedSot.Address,
			selectedGroupID,
		)
	}
	return s.accesscontrolService.GroupWithChildren(s.context.AuthorizedUser, selectedGroupID)
}

func (s *Service) CreateUnit(
	accessUnit *tacenvaentity.AccessUnit,
) error {
	keyPairForAccessUnit, err := keyring.GenerateKeyPair()
	if err != nil {
		return err
	}

	accessUnit.PublicKey = keyPairForAccessUnit.PublicKey
	accessUnit.GroupID = s.selectedGroup.ID
	accessUnit.SotID = s.context.SelectedSot.ID
	unwrappedGroupKey := s.keyPairOfSelectedGroup.PrivateKey
	wrappedGroupKey, err := keyPairForAccessUnit.Seal([]byte(unwrappedGroupKey))
	if err != nil {
		return err
	}

	req := tacenvacontract.AccessUnitSetupReq{
		AccessUnit:      accessUnit,
		WrappedGroupKey: wrappedGroupKey,
	}

	if s.context.IsRemote {
		return s.appDeps.Client.CreateAccessUnit(
			s.context.SelectedSot.Address,
			&req,
		)
	}
	return s.accesscontrolService.CreateUnit(
		s.context.AuthorizedUser,
		&req,
	)
}

func (s *Service) UpdateUnit(
	accessUnit *tacenvaentity.AccessUnit,
) error {
	if s.context.IsRemote {
		return s.appDeps.Client.UpdateAccessUnit(
			s.context.SelectedSot.Address,
			accessUnit.ID,
			accessUnit,
		)
	}
	return s.accesscontrolService.UpdateUnit(
		s.context.AuthorizedUser,
		accessUnit,
	)
}

func (s *Service) DeleteUnit(
	unitID string,
) error {
	if s.context.IsRemote {
		return s.appDeps.Client.DeleteAccessUnit(
			s.context.SelectedSot.Address,
			unitID,
		)
	}
	return s.accesscontrolService.DeleteUnit(
		s.context.AuthorizedUser,
		unitID,
	)
}

func (s *Service) SetRevokeUnit(
	unitID string,
	isRevoked bool,
) error {
	if s.context.IsRemote {
		return s.appDeps.Client.SetRevokeAccessUnit(
			s.context.SelectedSot.Address,
			unitID,
			isRevoked,
		)
	}
	return s.accesscontrolService.SetRevokeUnit(
		s.context.AuthorizedUser,
		unitID,
		isRevoked,
	)
}

func (s *Service) UnitList(
	groupID string,
) ([]tacenvacontract.AccessUnitWithUserCount, error) {
	if s.context.IsRemote {
		return s.appDeps.Client.ListAccessUnits(
			s.context.SelectedSot.Address,
			groupID,
		)
	}
	return s.accesscontrolService.UnitList(
		s.context.AuthorizedUser,
		groupID,
	)
}

func (s *Service) SetApprovalUser(
	userID string,
	isRevoked bool,
) error {
	if s.context.IsRemote {
		return s.appDeps.Client.SetApprovalUser(
			s.context.SelectedSot.Address,
			userID,
			isRevoked,
		)
	}

	return s.accesscontrolService.SetApprovalUser(s.context.AuthorizedUser, userID, isRevoked)
}

func (s *Service) DeleteUser(
	userID string,
) error {
	if s.context.IsRemote {
		return s.appDeps.Client.DeleteUser(
			s.context.SelectedSot.Address,
			userID,
		)
	}

	return s.accesscontrolService.DeleteUser(s.context.AuthorizedUser, userID)
}
