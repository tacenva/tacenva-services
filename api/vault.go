package api

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func (c *Client) CheckVaultSync(
	address string,
	replicaVaultHash string,
	result any,
) error {
	body := struct {
		ReplicaVaultHash string `json:"replica_vault_hash"`
	}{
		ReplicaVaultHash: replicaVaultHash,
	}

	return c.Post(
		address,
		"/vault/sync/check",
		body,
		result,
	)
}

func (c *Client) VaultSync(
	address string,
	replicaVaultHash string,
	result any,
) error {
	body := struct {
		ReplicaVaultHash string `json:"replica_vault_hash"`
	}{
		ReplicaVaultHash: replicaVaultHash,
	}

	return c.Post(
		address,
		"/vault/sync",
		body,
		result,
	)
}

func (c *Client) CreateVault(
	address string,
	body any,
	result any,
) error {
	return c.Post(
		address,
		"/vault",
		body,
		result,
	)
}

func (c *Client) GetRecord(
	address string,
	vaultID string,
	recordID string,
	result any,
) error {
	path := fmt.Sprintf(
		"/vault/%s/record/%s",
		vaultID,
		recordID,
	)

	return c.Get(
		address,
		path,
		result,
	)
}

func (c *Client) CheckRecordBlob(
	address string,
	vaultID string,
	replicaVersion uint64,
	result any,
) error {
	path := fmt.Sprintf(
		"/vault/%s/record/blob/check",
		vaultID,
	)

	body := struct {
		ReplicaVersion uint64 `json:"replica_version"`
	}{
		ReplicaVersion: replicaVersion,
	}

	return c.Post(
		address,
		path,
		body,
		result,
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
		http.MethodPost,
		address,
		path,
		nil,
	)
}

func (c *Client) CreateRecordRaw(
	address string,
	vaultID string,
	data []byte,
) (string, error) {
	path := fmt.Sprintf(
		"/vault/%s/record",
		vaultID,
	)

	body, err := c.doRaw(
		http.MethodPost,
		address,
		path,
		data,
	)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(body)), nil
}

func (c *Client) UpdateRecordRaw(
	address string,
	vaultID string,
	recordID string,
	data []byte,
) error {
	path := fmt.Sprintf(
		"/vault/%s/record/%s",
		vaultID,
		recordID,
	)

	_, err := c.doRaw(
		http.MethodPut,
		address,
		path,
		data,
	)

	return err
}

func (c *Client) DeleteRecord(
	address string,
	vaultID string,
	recordID string,
) error {
	path := fmt.Sprintf(
		"/vault/%s/record/%s",
		vaultID,
		recordID,
	)

	return c.Delete(
		address,
		path,
		nil,
	)
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

func (c *Client) UpdateVault(
	address string,
	vaultID string,
	body any,
	result any,
) error {
	path := fmt.Sprintf(
		"/vault/%s",
		vaultID,
	)

	return c.Put(
		address,
		path,
		body,
		result,
	)
}

func (c *Client) DeleteVault(
	address string,
	vaultID string,
) error {
	path := fmt.Sprintf(
		"/vault/%s",
		vaultID,
	)

	return c.Delete(
		address,
		path,
		nil,
	)
}
