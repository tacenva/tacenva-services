package api

import (
	"fmt"
	"net/url"
	"strings"

	tacenvacontract "github.com/tacenva/tacenva-core/contract"
	tacenvaentity "github.com/tacenva/tacenva-core/entity"
)

func (c *Client) CreateAccessGroup(
	address string,
	req *tacenvacontract.AccessGroupSetupRequest,
) error {
	if req == nil {
		return fmt.Errorf("access group request is required")
	}

	if err := c.Post(
		address,
		"/access-control/groups",
		req,
		nil,
	); err != nil {
		return fmt.Errorf("create access group: %w", err)
	}

	return nil
}

func (c *Client) UpdateAccessGroup(
	address string,
	groupID string,
	group *tacenvaentity.AccessGroup,
) error {
	groupID = strings.TrimSpace(groupID)

	if groupID == "" {
		return fmt.Errorf("access group id is required")
	}
	if group == nil {
		return fmt.Errorf("access group is required")
	}

	if err := c.Put(
		address,
		"/access-control/groups/"+url.PathEscape(groupID),
		group,
		nil,
	); err != nil {
		return fmt.Errorf("update access group: %w", err)
	}

	return nil
}

func (c *Client) DeleteAccessGroup(
	address string,
	groupID string,
) error {
	groupID = strings.TrimSpace(groupID)

	if groupID == "" {
		return fmt.Errorf("access group id is required")
	}

	if err := c.Delete(
		address,
		"/access-control/groups/"+url.PathEscape(groupID),
		nil,
	); err != nil {
		return fmt.Errorf("delete access group: %w", err)
	}

	return nil
}

func (c *Client) AccessGroupWithChildren(
	address string,
	groupID string,
) ([]tacenvacontract.AccessGroupTree, error) {
	groupID = strings.TrimSpace(groupID)

	var groups []tacenvacontract.AccessGroupTree

	if err := c.Get(
		address,
		"/access-control/groups/"+url.PathEscape(groupID)+"/tree",
		&groups,
	); err != nil {
		return nil, fmt.Errorf(
			"get access group with children: %w",
			err,
		)
	}

	return groups, nil
}

func (c *Client) CreateAccessUnit(
	address string,
	req *tacenvacontract.AccessUnitSetupReq,
) error {
	if req == nil {
		return fmt.Errorf("access unit request is required")
	}

	// Endpoint ini mengikuti router:
	// POST /access-control/groups/{id}/units
	//
	// Pastikan ID group tersedia pada request atau gunakan
	// method di bawah yang menerima groupID secara eksplisit.

	return fmt.Errorf(
		"create access unit requires groupID; use CreateAccessUnitInGroup",
	)
}

func (c *Client) CreateAccessUnitInGroup(
	address string,
	groupID string,
	req *tacenvacontract.AccessUnitSetupReq,
) error {
	groupID = strings.TrimSpace(groupID)

	if groupID == "" {
		return fmt.Errorf("access group id is required")
	}
	if req == nil {
		return fmt.Errorf("access unit request is required")
	}

	if err := c.Post(
		address,
		"/access-control/groups/"+url.PathEscape(groupID)+"/units",
		req,
		nil,
	); err != nil {
		return fmt.Errorf("create access unit: %w", err)
	}

	return nil
}

func (c *Client) UpdateAccessUnit(
	address string,
	unitID string,
	unit *tacenvaentity.AccessUnit,
) error {
	unitID = strings.TrimSpace(unitID)

	if unitID == "" {
		return fmt.Errorf("access unit id is required")
	}
	if unit == nil {
		return fmt.Errorf("access unit is required")
	}

	if err := c.Put(
		address,
		"/access-control/units/"+url.PathEscape(unitID),
		unit,
		nil,
	); err != nil {
		return fmt.Errorf("update access unit: %w", err)
	}

	return nil
}

func (c *Client) DeleteAccessUnit(
	address string,
	unitID string,
) error {
	unitID = strings.TrimSpace(unitID)

	if unitID == "" {
		return fmt.Errorf("access unit id is required")
	}

	if err := c.Delete(
		address,
		"/access-control/units/"+url.PathEscape(unitID),
		nil,
	); err != nil {
		return fmt.Errorf("delete access unit: %w", err)
	}

	return nil
}

func (c *Client) SetRevokeAccessUnit(
	address string,
	unitID string,
	revoked bool,
) error {
	unitID = strings.TrimSpace(unitID)

	if unitID == "" {
		return fmt.Errorf("access unit id is required")
	}

	req := tacenvacontract.RevokeStatusReq{
		IsRevoked: revoked,
	}

	if err := c.Patch(
		address,
		"/access-control/units/"+url.PathEscape(unitID)+"/revoke",
		&req,
		nil,
	); err != nil {
		return fmt.Errorf("set access unit revoke status: %w", err)
	}

	return nil
}

func (c *Client) ListAccessUnits(
	address string,
	groupID string,
) ([]tacenvacontract.AccessUnitWithUserCount, error) {
	groupID = strings.TrimSpace(groupID)

	if groupID == "" {
		return nil, fmt.Errorf("access group id is required")
	}

	var units []tacenvacontract.AccessUnitWithUserCount

	if err := c.Get(
		address,
		"/access-control/groups/"+url.PathEscape(groupID)+"/units",
		&units,
	); err != nil {
		return nil, fmt.Errorf("list access units: %w", err)
	}

	return units, nil
}

func (c *Client) SetApprovalUser(
	address string,
	userID string,
	isRevoked bool,
) error {
	userID = strings.TrimSpace(userID)

	if userID == "" {
		return fmt.Errorf("user id is required")
	}

	req := tacenvacontract.RevokeStatusReq{
		IsRevoked: isRevoked,
	}

	if err := c.Patch(
		address,
		"/access-control/users/"+url.PathEscape(userID)+"/approve",
		req,
		nil,
	); err != nil {
		return fmt.Errorf("update user status: %w", err)
	}

	return nil
}

func (c *Client) DeleteUser(
	address string,
	userID string,
) error {
	userID = strings.TrimSpace(userID)

	if userID == "" {
		return fmt.Errorf("user id is required")
	}

	if err := c.Delete(
		address,
		"/access-control/users/"+url.PathEscape(userID),
		nil,
	); err != nil {
		return fmt.Errorf("delete user: %w", err)
	}

	return nil
}

func (c *Client) PublicKeyOfGroups(
	address string,
	groupIDs []string,
) (map[string]string, error) {
	if len(groupIDs) == 0 {
		return nil, nil
	}

	normalizedIDs := make([]string, 0, len(groupIDs))
	seen := make(map[string]struct{}, len(groupIDs))

	for _, id := range groupIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}

		if _, exists := seen[id]; exists {
			continue
		}

		seen[id] = struct{}{}
		normalizedIDs = append(normalizedIDs, id)
	}

	if len(normalizedIDs) == 0 {
		return nil, nil
	}

	var publicKeys map[string]string

	if err := c.Query(
		address,
		"/access-groups/public-keys",
		&tacenvacontract.PublicKeyOfGroupsReq{
			GroupIDs: normalizedIDs,
		},
		&publicKeys,
	); err != nil {
		return nil, fmt.Errorf("get public keys of groups: %w", err)
	}

	return publicKeys, nil
}
