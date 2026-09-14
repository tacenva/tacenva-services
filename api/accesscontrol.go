package api

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/util/keyring"
)

type AccessControlCreateResponse struct {
	VaultAccessList []entity.VaultAccess `json:"vault_access"`
	Permission      *entity.Permission   `json:"permission"`
	KeyPair         *keyring.KeyPair     `json:"keypair"`
}

func (c *Client) ListAccessControls(
	address string,
) ([]entity.Permission, error) {
	var permissions []entity.Permission

	if err := c.Get(
		address,
		"/access-control",
		&permissions,
	); err != nil {
		return nil, fmt.Errorf(
			"list access controls: %w",
			err,
		)
	}

	return permissions, nil
}

func (c *Client) GetAccessControl(
	address string,
	id string,
) (*entity.Permission, error) {
	id = strings.TrimSpace(id)

	if id == "" {
		return nil, fmt.Errorf(
			"access control id is required",
		)
	}

	var permission entity.Permission

	if err := c.Get(
		address,
		"/access-control/"+url.PathEscape(id),
		&permission,
	); err != nil {
		return nil, fmt.Errorf(
			"get access control: %w",
			err,
		)
	}

	return &permission, nil
}

func (c *Client) CreateAccessControl(
	address string,
	name string,
	privilege entity.Privilege,
) (*AccessControlCreateResponse, error) {
	name = strings.TrimSpace(name)

	if name == "" {
		return nil, fmt.Errorf(
			"access control name is required",
		)
	}

	request := struct {
		Name      string           `json:"name"`
		Privilege entity.Privilege `json:"privilege"`
	}{
		Name:      name,
		Privilege: privilege,
	}

	var response AccessControlCreateResponse

	if err := c.Post(
		address,
		"/access-control",
		request,
		&response,
	); err != nil {
		return nil, fmt.Errorf(
			"create access control: %w",
			err,
		)
	}

	return &response, nil
}

func (c *Client) ChangeAccessControlName(
	address string,
	id string,
	name string,
) error {
	id = strings.TrimSpace(id)
	name = strings.TrimSpace(name)

	if id == "" {
		return fmt.Errorf("access control id is required")
	}

	if name == "" {
		return fmt.Errorf("access control name is required")
	}

	request := struct {
		Name string `json:"name"`
	}{
		Name: name,
	}

	if err := c.Patch(
		address,
		"/access-control/"+url.PathEscape(id)+"/name",
		request,
		nil,
	); err != nil {
		return fmt.Errorf("change access control name: %w", err)
	}

	return nil
}

func (c *Client) ChangeAccessControlPrivilege(
	address string,
	id string,
	privilege entity.Privilege,
) error {
	id = strings.TrimSpace(id)

	if id == "" {
		return fmt.Errorf(
			"access control id is required",
		)
	}

	request := struct {
		Privilege entity.Privilege `json:"privilege"`
	}{
		Privilege: privilege,
	}

	if err := c.Patch(
		address,
		"/access-control/"+url.PathEscape(id)+"/privilege",
		request,
		nil,
	); err != nil {
		return fmt.Errorf(
			"change access control privilege: %w",
			err,
		)
	}

	return nil
}

func (c *Client) RevokeAccessControl(
	address string,
	id string,
) error {
	id = strings.TrimSpace(id)

	if id == "" {
		return fmt.Errorf(
			"access control id is required",
		)
	}

	if err := c.Post(
		address,
		"/access-control/"+url.PathEscape(id)+"/revoke",
		nil,
		nil,
	); err != nil {
		return fmt.Errorf(
			"revoke access control: %w",
			err,
		)
	}

	return nil
}

func (c *Client) DeleteAccessControl(
	address string,
	id string,
) error {
	id = strings.TrimSpace(id)

	if id == "" {
		return fmt.Errorf(
			"access control id is required",
		)
	}

	if err := c.Delete(
		address,
		"/access-control/"+url.PathEscape(id),
		nil,
	); err != nil {
		return fmt.Errorf(
			"delete access control: %w",
			err,
		)
	}

	return nil
}

func (c *Client) ListAccessControlUsers(
	address string,
	permissionID string,
) ([]entity.User, error) {
	permissionID = strings.TrimSpace(permissionID)

	if permissionID == "" {
		return nil, fmt.Errorf(
			"permission id is required",
		)
	}

	var users []entity.User

	if err := c.Get(
		address,
		"/access-control/"+url.PathEscape(permissionID)+"/users",
		&users,
	); err != nil {
		return nil, fmt.Errorf(
			"list access control users: %w",
			err,
		)
	}

	return users, nil
}

func (c *Client) ApproveAccessControlUser(
	address string,
	userID string,
) (*entity.User, error) {
	userID = strings.TrimSpace(userID)

	if userID == "" {
		return nil, fmt.Errorf(
			"user id is required",
		)
	}

	var user entity.User

	if err := c.Post(
		address,
		"/access-control/users/"+url.PathEscape(userID)+"/approve",
		nil,
		&user,
	); err != nil {
		return nil, fmt.Errorf(
			"approve access control user: %w",
			err,
		)
	}

	return &user, nil
}

func (c *Client) RevokeAccessControlUser(
	address string,
	userID string,
) (*entity.User, error) {
	userID = strings.TrimSpace(userID)

	if userID == "" {
		return nil, fmt.Errorf(
			"user id is required",
		)
	}

	var user entity.User

	if err := c.Post(
		address,
		"/access-control/users/"+url.PathEscape(userID)+"/revoke",
		nil,
		&user,
	); err != nil {
		return nil, fmt.Errorf(
			"revoke access control user: %w",
			err,
		)
	}

	return &user, nil
}

func (c *Client) GrantVaultAccess(
	address string,
	vaultAccessList []entity.VaultAccess,
) error {
	if len(vaultAccessList) == 0 {
		return fmt.Errorf(
			"vault access list is required",
		)
	}

	if err := c.Post(
		address,
		"/access-control/vault-access",
		vaultAccessList,
		nil,
	); err != nil {
		return fmt.Errorf(
			"grant vault access: %w",
			err,
		)
	}

	return nil
}
