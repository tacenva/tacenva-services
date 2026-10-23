package api

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/tacenva/tacpass-core/contract"
	"github.com/tacenva/tacpass-core/entity"
)

func (c *Client) PublicKeys(
	address string,
	groupIDs []string,
) (map[string][]entity.Permission, error) {
	var permissions map[string][]entity.Permission
	if err := c.do(
		"QUERY",
		address,
		"/vault/public-keys",
		&contract.PermissionGroupReq{
			GroupIDs: groupIDs,
		},
		&permissions,
		true,
	); err != nil {
		return nil, fmt.Errorf(
			"[VAULT]: %w",
			err,
		)
	}

	return permissions, nil
}

func (c *Client) GetVaultChanges(
	address string,
	startChangeID string,
	limit int,
) (*contract.PendingVaultChange, error) {
	var pendingChange contract.PendingVaultChange
	path := withSyncQuery(
		"/vault/changes",
		startChangeID,
		limit,
	)

	if err := c.Get(
		address,
		path,
		&pendingChange,
	); err != nil {
		return nil, fmt.Errorf(
			"[VAULT]: %w",
			err,
		)
	}

	return &pendingChange, nil
}

func (c *Client) GetVaultChangesCount(
	address string,
	startChangeID string,
) (*contract.PendingTotalChanges, error) {
	var pendingTotalChanges contract.PendingTotalChanges
	path := withStartChangeID(
		"/vault/changes/count",
		startChangeID,
	)

	if err := c.Get(
		address,
		path,
		&pendingTotalChanges,
	); err != nil {
		return nil, fmt.Errorf(
			"[VAULT]: %w",
			err,
		)
	}

	return &pendingTotalChanges, nil
}

func (c *Client) SyncVault(
	address string,
	startChangeID string,
	limit int,
	changes any,
) (*contract.PendingVaultChange, error) {
	path := withSyncQuery(
		"/vault/sync",
		startChangeID,
		limit,
	)

	var successList contract.PendingVaultChange

	err := c.Post(
		address,
		path,
		changes,
		&successList,
	)
	if err != nil {
		return nil, err
	}

	return &successList, nil
}

func (c *Client) GetRecordBlob(
	address string,
	vaultID string,
) ([]byte, error) {
	path := fmt.Sprintf(
		"/vault/%s/record/blob",
		vaultID,
	)

	return c.doRaw(
		http.MethodGet,
		address,
		path,
		nil,
	)
}

func (c *Client) StoreRecordBlob(
	address string,
	vaultID string,
	data []byte,
) error {
	path := fmt.Sprintf(
		"/vault/%s/record/blob",
		vaultID,
	)

	_, err := c.doRaw(
		http.MethodPost,
		address,
		path,
		data,
	)

	return err
}

func (c *Client) GetRecordChanges(
	address string,
	vaultID string,
	startChangeID string,
	limit int,
) (*contract.PendingVaultRecordChange, error) {
	var pendingChange contract.PendingVaultRecordChange
	path := fmt.Sprintf(
		"/vault/%s/record/changes",
		vaultID,
	)

	path = withSyncQuery(
		path,
		startChangeID,
		limit,
	)

	if err := c.Get(
		address,
		path,
		&pendingChange,
	); err != nil {
		return nil, fmt.Errorf(
			"[VAULT]: %w",
			err,
		)
	}

	return &pendingChange, nil
}

func (c *Client) GetRecordChangesCount(
	address string,
	vaultID string,
	startChangeID string,
) (*contract.PendingTotalChanges, error) {
	var pendingTotalChanges contract.PendingTotalChanges
	path := fmt.Sprintf(
		"/vault/%s/record/changes/count",
		vaultID,
	)

	path = withStartChangeID(
		path,
		startChangeID,
	)

	if err := c.Get(
		address,
		path,
		&pendingTotalChanges,
	); err != nil {
		return nil, fmt.Errorf(
			"[VAULT]: %w",
			err,
		)
	}

	return &pendingTotalChanges, nil
}

func (c *Client) SyncRecords(
	address string,
	vaultID string,
	startChangeID string,
	limit int,
	changes any,
) (*contract.PendingVaultRecordChange, error) {
	path := fmt.Sprintf(
		"/vault/%s/record/sync",
		vaultID,
	)

	path = withSyncQuery(
		path,
		startChangeID,
		limit,
	)

	var successList contract.PendingVaultRecordChange

	err := c.Post(
		address,
		path,
		changes,
		&successList,
	)
	if err != nil {
		return nil, err
	}

	return &successList, nil
}

func withStartChangeID(
	path string,
	startChangeID string,
) string {
	return withStartQuery(
		path,
		"start_change_id",
		startChangeID,
	)
}

func withStartQuery(
	path string,
	key string,
	value string,
) string {
	query := url.Values{}

	query.Set(
		key,
		value,
	)

	return path + "?" + query.Encode()
}

func withSyncQuery(
	path string,
	startChangeID string,
	limit int,
) string {
	query := url.Values{}

	query.Set(
		"start_change_id",
		startChangeID,
	)

	query.Set(
		"limit",
		strconv.Itoa(limit),
	)

	return path + "?" + query.Encode()
}

func (c *Client) doRaw(
	method string,
	address string,
	path string,
	data []byte,
) ([]byte, error) {
	requestURL := strings.TrimRight(address, "/") +
		"/" +
		strings.TrimLeft(path, "/")

	req, err := http.NewRequest(
		method,
		requestURL,
		bytes.NewReader(data),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create request: %w",
			err,
		)
	}

	req.Header.Set(
		"Accept",
		"application/octet-stream",
	)

	req.Header.Set(
		"Content-Type",
		"application/octet-stream",
	)

	if c.Token == "" {
		return nil, fmt.Errorf(
			"authentication token is required",
		)
	}

	req.Header.Set(
		"Authorization",
		"Bearer "+c.Token,
	)

	httpClient, err := c.httpClient(
		strings.TrimRight(address, "/"),
	)
	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf(
			"request failed: %w",
			err,
		)
	}

	defer resp.Body.Close()

	if resp.StatusCode < 200 ||
		resp.StatusCode >= 300 {
		return nil, parseHTTPError(resp)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf(
			"read response: %w",
			err,
		)
	}

	return body, nil
}
