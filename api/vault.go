package api

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func (c *Client) ConnectedPublicKeys(
	address string,
	result any,
) error {
	return c.Get(
		address,
		"/vault/connected-public-keys",
		result,
	)
}

func (c *Client) ListVault(
	address string,
	result any,
) error {
	return c.Get(
		address,
		"/vault",
		result,
	)
}

func (c *Client) GetVaultChanges(
	address string,
	startChangeID string,
	limit int,
	result any,
) error {
	path := withSyncQuery(
		"/vault/changes",
		startChangeID,
		limit,
	)

	return c.Get(
		address,
		path,
		result,
	)
}

func (c *Client) GetVaultChangesCount(
	address string,
	startChangeID string,
	result any,
) error {
	path := withStartChangeID(
		"/vault/changes/count",
		startChangeID,
	)

	return c.Get(
		address,
		path,
		result,
	)
}

func (c *Client) SyncVault(
	address string,
	changes any,
) error {
	return c.Post(
		address,
		"/vault/sync",
		changes,
		nil,
	)
}

func (c *Client) RecordBlob(
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

func (c *Client) GetRecordChanges(
	address string,
	vaultID string,
	startChangeID string,
	limit int,
	result any,
) error {
	path := fmt.Sprintf(
		"/vault/%s/record/changes",
		vaultID,
	)

	path = withSyncQuery(
		path,
		startChangeID,
		limit,
	)

	return c.Get(
		address,
		path,
		result,
	)
}

func (c *Client) GetRecordChangesCount(
	address string,
	vaultID string,
	startChangeID string,
	result any,
) error {
	path := fmt.Sprintf(
		"/vault/%s/record/changes/count",
		vaultID,
	)

	path = withStartChangeID(
		path,
		startChangeID,
	)

	return c.Get(
		address,
		path,
		result,
	)
}

func (c *Client) SyncRecords(
	address string,
	vaultID string,
	changes any,
) error {
	path := fmt.Sprintf(
		"/vault/%s/record/sync",
		vaultID,
	)

	return c.Post(
		address,
		path,
		changes,
		nil,
	)
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

	if limit > 0 {
		query.Set(
			"limit",
			strconv.Itoa(limit),
		)
	}

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
