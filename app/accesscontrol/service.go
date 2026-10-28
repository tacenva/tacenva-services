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

	keyPairForAccessGroup, err := keyring.GenerateKeyPair()
	if err != nil {
		return err
	}

	wrappedGroupKey, err := keyPairForAccessUnit.Seal(
		[]byte(keyPairForAccessGroup.PrivateKey),
	)
	if err != nil {
		return err
	}

	wrappedHierarchyKey := ""
	if parentAccess {
		if s.keyPairOfSelectedGroup == nil {
			return errors.New("Your group have no access to parent group")
		}

		wrappedHierarchyKey, err = s.keyPairOfSelectedGroup.Seal(
			[]byte(keyPairForAccessGroup.PrivateKey),
		)
		if err != nil {
			return err
		}
	}

	return s.accesscontrolService.CreateGroup(
		s.context.AuthorizedUser,
		newAccessGroup,
		adminUnit,
		s.selectedGroup.ID,
		wrappedGroupKey,
		wrappedHierarchyKey,
	)
}

func (s *Service) UpdateGroup(
	toUpdateAccessGroup *tacenvaentity.AccessGroup,
) error {
	return s.accesscontrolService.UpdateGroup(
		s.context.AuthorizedUser,
		toUpdateAccessGroup,
	)
}

func (s *Service) DeleteGroup(
	groupID string,
) error {
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
	return s.accesscontrolService.GroupWithChildren(s.context.AuthorizedUser, selectedGroupID)
}

func (s *Service) CreateUnit(
	sotID string,
	accessUnit *tacenvaentity.AccessUnit,
	wrappedGroupKey string,
) error {
	return s.accesscontrolService.CreateUnit(
		sotID,
		accessUnit,
		wrappedGroupKey,
	)
}

func (s *Service) UpdateUnit(
	sotID string,
	accessUnit *tacenvaentity.AccessUnit,
) error {
	return s.accesscontrolService.UpdateUnit(
		sotID,
		accessUnit,
	)
}

func (s *Service) DeleteUnit(
	sotID string,
	unitID string,
) error {
	return s.accesscontrolService.DeleteUnit(
		sotID,
		unitID,
	)
}

func (s *Service) SetRevokeUnit(
	sotID string,
	unitID string,
	isRevoked bool,
) error {
	return s.accesscontrolService.SetRevokeUnit(
		sotID,
		unitID,
		isRevoked,
	)
}

func (s *Service) UnitListt(
	sotID string,
	groupID string,
) ([]tacenvacontract.AccessUnitWithUserCount, error) {
	return s.accesscontrolService.UnitList(sotID, groupID)
}
