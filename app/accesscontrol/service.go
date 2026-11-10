package accesscontrol

import (
	"errors"
	"fmt"

	tacenvaaccesscontrol "github.com/tacenva/tacenva-core/accesscontrol"
	tacenvacontract "github.com/tacenva/tacenva-core/contract"
	tacenvaentity "github.com/tacenva/tacenva-core/entity"
	"github.com/tacenva/tacenva-core/genericerror"
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

func (s *Service) KeyPairOfChild(
	publicKeyOfChild, wrappedPrivateKeyOfChild string,
) (*keyring.KeyPair, error) {
	if s.selectedGroup == nil || s.keyPairOfSelectedGroup == nil {
		return nil, genericerror.ErrEmptyValue
	}

	if wrappedPrivateKeyOfChild == "" {
		return nil, nil
	}

	privateKeyOfChild, err := s.keyPairOfSelectedGroup.Open(wrappedPrivateKeyOfChild)
	if err != nil {
		return nil, err
	}

	return keyring.FromKeys(publicKeyOfChild, string(privateKeyOfChild)), nil
}

func (s *Service) SetSelectedGroup(selectedGroup *tacenvaentity.AccessGroup, keyPairOfSelectedGroup *keyring.KeyPair) {
	s.selectedGroup = selectedGroup
	s.keyPairOfSelectedGroup = keyPairOfSelectedGroup
}

func (s *Service) CreateGroup(
	newAccessGroup *tacenvaentity.AccessGroup,
	adminUnit *tacenvaentity.AccessUnit,
	parentAccess bool,
) (string, error) {
	if s.keyPairOfSelectedGroup == nil {
		return "", errors.New("cannot perform this action: unaccessible group")
	}

	keyPairForAccessUnit, err := keyring.GenerateKeyPair()
	if err != nil {
		return "", err
	}

	// debug.LogJSON("keypair for access unit", keyPairForAccessUnit)

	adminUnit.PublicKey = keyPairForAccessUnit.PublicKey
	adminUnit.SotID = s.selectedGroup.ID

	keyPairForAccessGroup, err := keyring.GenerateKeyPair()
	if err != nil {
		return "", err
	}

	// debug.LogJSON("keypair for access group", keyPairForAccessGroup)
	newAccessGroup.PublicKey = keyPairForAccessGroup.PublicKey

	wrappedGroupKey, err := keyPairForAccessUnit.Seal(
		[]byte(keyPairForAccessGroup.PrivateKey),
	)
	if err != nil {
		return "", err
	}

	wrappedHierarchyKey := ""
	if parentAccess {
		if s.keyPairOfSelectedGroup == nil {
			return "", errors.New("parent group has not been selected yet")
		}

		wrappedHierarchyKey, err = s.keyPairOfSelectedGroup.Seal(
			[]byte(keyPairForAccessGroup.PrivateKey),
		)
		if err != nil {
			return "", err
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
		err = s.appDeps.Client.CreateAccessGroup(
			s.context.SelectedSot.Address,
			&req,
		)
	} else {
		err = s.accesscontrolService.CreateGroup(
			s.context.AuthorizedUser,
			&req,
		)
	}

	if err != nil {
		return "", err
	}

	encodedKey, err := keyPairForAccessUnit.EncodedKey()
	if err != nil {
		return "", fmt.Errorf("encode access unit secret key: %w", err)
	}

	return encodedKey, nil
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
	selectedGroupID string,
) ([]tacenvacontract.AccessGroupTree, error) {
	if selectedGroupID == "" {
		return nil, errors.New("cannot perform this action: group is not selected yet")
	}
	if s.context.IsRemote {
		return s.appDeps.Client.AccessGroupWithChildren(
			s.context.SelectedSot.Address,
			selectedGroupID,
		)
	}
	return s.accesscontrolService.GroupWithChildren(s.context.AuthorizedUser, selectedGroupID)
}

type CreateUnitResult struct {
	AccessUnit *tacenvaentity.AccessUnit
	EncodedKey string
}

func (s *Service) CreateUnit(
	accessUnit *tacenvaentity.AccessUnit,
) (*CreateUnitResult, error) {
	if accessUnit == nil {
		return nil, errors.New("access unit is required")
	}

	if s.keyPairOfSelectedGroup == nil {
		return nil, errors.New("cannot perform this action: unaccessible group")
	}

	if s.selectedGroup == nil {
		return nil, errors.New("access group has not been selected")
	}

	keyPairForAccessUnit, err := keyring.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	encodedKey, err := keyPairForAccessUnit.EncodedKey()
	if err != nil {
		return nil, fmt.Errorf("encode access unit secret key: %w", err)
	}

	accessUnit.PublicKey = keyPairForAccessUnit.PublicKey
	accessUnit.GroupID = s.selectedGroup.ID
	accessUnit.SotID = s.context.SelectedSot.ID

	wrappedGroupKey, err := keyPairForAccessUnit.Seal(
		[]byte(s.keyPairOfSelectedGroup.PrivateKey),
	)
	if err != nil {
		return nil, err
	}

	req := tacenvacontract.AccessUnitSetupReq{
		AccessUnit:      accessUnit,
		WrappedGroupKey: wrappedGroupKey,
	}

	var createdUnit *tacenvaentity.AccessUnit

	if s.context.IsRemote {
		createdUnit, err = s.appDeps.Client.CreateAccessUnit(
			s.context.SelectedSot.Address,
			&req,
		)
	} else {
		createdUnit, err = s.accesscontrolService.CreateUnit(
			s.context.AuthorizedUser,
			&req,
		)
	}

	if err != nil {
		return nil, err
	}

	if createdUnit == nil || createdUnit.ID == "" {
		return nil, errors.New("created access unit has no ID")
	}

	return &CreateUnitResult{
		AccessUnit: createdUnit,
		EncodedKey: encodedKey,
	}, nil
}

func (s *Service) UpdateUnit(
	accessUnit *tacenvaentity.AccessUnit,
) error {
	if s.keyPairOfSelectedGroup == nil {
		return errors.New("cannot perform this action: unaccessible group")
	}

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
	if s.keyPairOfSelectedGroup == nil {
		return errors.New("cannot perform this action: unaccessible group")
	}

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
