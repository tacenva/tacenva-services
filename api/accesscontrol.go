package api

import (
	"fmt"

	tacenvacontract "github.com/tacenva/tacenva-core/contract"
)

// type AccessControlCreateResponse struct {
// 	VaultAccessList []tacpassentity.VaultAccess `json:"vault_access"`
// 	Permission      *tacenvaentity.Permission   `json:"permission"`
// 	KeyPair         *keyring.KeyPair            `json:"keypair"`
// }

// func (c *Client) ListAccessControls(
// 	address string,
// ) ([]tacenvaentity.Permission, error) {
// 	var permissions []tacenvaentity.Permission

// 	if err := c.Get(
// 		address,
// 		"/access-control",
// 		&permissions,
// 	); err != nil {
// 		return nil, fmt.Errorf(
// 			"list access controls: %w",
// 			err,
// 		)
// 	}

// 	return permissions, nil
// }

// func (c *Client) CreateAccessControl(
// 	address string,
// 	permission *tacenvaentity.Permission,
// ) (*AccessControlCreateResponse, error) {
// 	if permission == nil {
// 		return nil, fmt.Errorf("permission is required")
// 	}

// 	permission.Name = strings.TrimSpace(permission.Name)
// 	permission.Group.Name = strings.TrimSpace(permission.Group.Name)

// 	if permission.Name == "" {
// 		return nil, fmt.Errorf("access control name is required")
// 	}

// 	var response AccessControlCreateResponse

// 	if err := c.Post(
// 		address,
// 		"/access-control",
// 		permission,
// 		&response,
// 	); err != nil {
// 		return nil, fmt.Errorf("create access control: %w", err)
// 	}

// 	return &response, nil
// }

// func (c *Client) UpdateAccessControl(
// 	address string,
// 	permission *tacenvaentity.Permission,
// ) error {
// 	if permission == nil {
// 		return fmt.Errorf("permission is required")
// 	}

// 	permission.ID = strings.TrimSpace(permission.ID)
// 	permission.Name = strings.TrimSpace(permission.Name)
// 	permission.Group.ID = strings.TrimSpace(permission.Group.ID)
// 	permission.Group.Name = strings.TrimSpace(permission.Group.Name)

// 	if permission.ID == "" {
// 		return fmt.Errorf("access control id is required")
// 	}

// 	if permission.Name == "" {
// 		return fmt.Errorf("access control name is required")
// 	}

// 	if err := c.Put(
// 		address,
// 		"/access-control/"+url.PathEscape(permission.ID),
// 		permission,
// 		nil,
// 	); err != nil {
// 		return fmt.Errorf("update access control: %w", err)
// 	}

// 	return nil
// }

// func (c *Client) SetRevokedAccessControl(
// 	address string,
// 	id string,
// 	revoked bool,
// ) error {
// 	id = strings.TrimSpace(id)

// 	if id == "" {
// 		return fmt.Errorf("access control id is required")
// 	}

// 	request := struct {
// 		Revoked bool `json:"revoked"`
// 	}{
// 		Revoked: revoked,
// 	}

// 	if err := c.Patch(
// 		address,
// 		"/access-control/"+url.PathEscape(id)+"/revoke",
// 		request,
// 		nil,
// 	); err != nil {
// 		return fmt.Errorf(
// 			"set access control revoked status: %w",
// 			err,
// 		)
// 	}

// 	return nil
// }

// func (c *Client) DeleteAccessControl(
// 	address string,
// 	id string,
// ) error {
// 	id = strings.TrimSpace(id)

// 	if id == "" {
// 		return fmt.Errorf(
// 			"access control id is required",
// 		)
// 	}

// 	if err := c.Delete(
// 		address,
// 		"/access-control/"+url.PathEscape(id),
// 		nil,
// 	); err != nil {
// 		return fmt.Errorf(
// 			"delete access control: %w",
// 			err,
// 		)
// 	}

// 	return nil
// }

// func (c *Client) ListAccessControlUsers(
// 	address string,
// 	permissionID string,
// ) ([]tacenvaentity.User, error) {
// 	permissionID = strings.TrimSpace(permissionID)

// 	if permissionID == "" {
// 		return nil, fmt.Errorf(
// 			"permission id is required",
// 		)
// 	}

// 	var users []tacenvaentity.User

// 	if err := c.Get(
// 		address,
// 		"/access-control/"+url.PathEscape(permissionID)+"/users",
// 		&users,
// 	); err != nil {
// 		return nil, fmt.Errorf(
// 			"list access control users: %w",
// 			err,
// 		)
// 	}

// 	return users, nil
// }

// func (c *Client) SetUserStatus(
// 	address string,
// 	userID string,
// 	status tacenvaentity.UserStatus,
// ) error {
// 	userID = strings.TrimSpace(userID)

// 	if userID == "" {
// 		return fmt.Errorf(
// 			"user id is required",
// 		)
// 	}

// 	request := struct {
// 		Status tacenvaentity.UserStatus `json:"status"`
// 	}{
// 		Status: status,
// 	}

// 	if err := c.Patch(
// 		address,
// 		"/access-control/users/"+url.PathEscape(userID)+"/approval",
// 		request,
// 		nil,
// 	); err != nil {
// 		return fmt.Errorf(
// 			"revoke access control user: %w",
// 			err,
// 		)
// 	}

// 	return nil
// }

// func (c *Client) GrantVaultAccess(
// 	address string,
// 	vaultAccessList []entity.VaultAccess,
// ) error {
// 	if len(vaultAccessList) == 0 {
// 		return fmt.Errorf(
// 			"vault access list is required",
// 		)
// 	}

// 	if err := c.Post(
// 		address,
// 		"/access-control/vault-access",
// 		vaultAccessList,
// 		nil,
// 	); err != nil {
// 		return fmt.Errorf(
// 			"grant vault access: %w",
// 			err,
// 		)
// 	}

// 	return nil
// }

// func (c *Client) ListAccessControlGroups(
// 	address string,
// ) ([]tacenvaentity.PermissionGroup, error) {
// 	var groups []tacenvaentity.PermissionGroup

// 	if err := c.Get(
// 		address,
// 		"/access-control/groups",
// 		&groups,
// 	); err != nil {
// 		return nil, fmt.Errorf(
// 			"list access control groups: %w",
// 			err,
// 		)
// 	}

// 	return groups, nil
// }

// func (c *Client) UpdateAccessControlGroup(
// 	address string,
// 	group *tacenvaentity.PermissionGroup,
// ) error {
// 	if group == nil {
// 		return fmt.Errorf("permission group is required")
// 	}

// 	group.ID = strings.TrimSpace(group.ID)
// 	group.Name = strings.TrimSpace(group.Name)

// 	if group.ID == "" {
// 		return fmt.Errorf("permission group id is required")
// 	}

// 	if group.Name == "" {
// 		return fmt.Errorf("permission group name is required")
// 	}

// 	if err := c.Put(
// 		address,
// 		"/access-control/groups/"+url.PathEscape(group.ID),
// 		group,
// 		nil,
// 	); err != nil {
// 		return fmt.Errorf(
// 			"update access control group: %w",
// 			err,
// 		)
// 	}

// 	return nil
// }

// func (c *Client) DeleteAccessControlGroup(
// 	address string,
// 	groupID string,
// ) error {
// 	groupID = strings.TrimSpace(groupID)

// 	if groupID == "" {
// 		return fmt.Errorf("permission group id is required")
// 	}

// 	if err := c.Delete(
// 		address,
// 		"/access-control/groups/"+url.PathEscape(groupID),
// 		nil,
// 	); err != nil {
// 		return fmt.Errorf(
// 			"delete access control group: %w",
// 			err,
// 		)
// 	}

// 	return nil
// }

func (c *Client) PublicKeyOfGroups(
	address string,
	groupIDs []string,
) (map[string]string, error) {
	var publicKeys map[string]string
	if err := c.do(
		"QUERY",
		address,
		"/access-control/groups/public-key",
		&tacenvacontract.PublicKeyOfGroupsReq{
			GroupIDs: groupIDs,
		},
		&publicKeys,
		true,
	); err != nil {
		return nil, fmt.Errorf(
			"vault: %w",
			err,
		)
	}

	return publicKeys, nil
}
