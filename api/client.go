package api

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type TLSConfig struct {
	Fingerprint string

	// Dipanggil ketika server pertama kali dipercaya.
	// Parameter berisi fingerprint SPKI SHA-256.
	OnFirstTrust func(fingerprint string) error
}

type Client struct {
	Token string

	mu         sync.RWMutex
	tlsConfigs map[string]TLSConfig
	clients    map[string]*http.Client
}

func NewClient() *Client {
	return &Client{
		tlsConfigs: make(map[string]TLSConfig),
		clients:    make(map[string]*http.Client),
	}
}

func (c *Client) SetToken(token string) {
	c.Token = token
}

func (c *Client) ClearToken() {
	c.Token = ""
}

func (c *Client) ConfigureTLS(
	address string,
	config TLSConfig,
) {
	address = strings.TrimRight(address, "/")

	c.mu.Lock()
	defer c.mu.Unlock()

	c.tlsConfigs[address] = config

	// Buang HTTP client lama supaya transport dengan
	// konfigurasi fingerprint lama tidak dipakai lagi.
	delete(c.clients, address)
}

func (c *Client) ClearTLS(address string) {
	address = strings.TrimRight(address, "/")

	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.tlsConfigs, address)
	delete(c.clients, address)
}

func (c *Client) Get(
	address string,
	path string,
	result any,
) error {
	return c.do(
		http.MethodGet,
		address,
		path,
		nil,
		result,
		true,
	)
}

func (c *Client) GetPublic(
	address string,
	path string,
	result any,
) error {
	return c.do(
		http.MethodGet,
		address,
		path,
		nil,
		result,
		false,
	)
}

func (c *Client) Post(
	address string,
	path string,
	body any,
	result any,
) error {
	return c.do(
		http.MethodPost,
		address,
		path,
		body,
		result,
		true,
	)
}

func (c *Client) PostPublic(
	address string,
	path string,
	body any,
	result any,
) error {
	return c.do(
		http.MethodPost,
		address,
		path,
		body,
		result,
		false,
	)
}

func (c *Client) Put(
	address string,
	path string,
	body any,
	result any,
) error {
	return c.do(
		http.MethodPut,
		address,
		path,
		body,
		result,
		true,
	)
}

func (c *Client) Patch(
	address string,
	path string,
	body any,
	result any,
) error {
	return c.do(
		http.MethodPatch,
		address,
		path,
		body,
		result,
		true,
	)
}

func (c *Client) PatchPublic(
	address string,
	path string,
	body any,
	result any,
) error {
	return c.do(
		http.MethodPatch,
		address,
		path,
		body,
		result,
		false,
	)
}

func (c *Client) Delete(
	address string,
	path string,
	result any,
) error {
	return c.do(
		http.MethodDelete,
		address,
		path,
		nil,
		result,
		true,
	)
}

func (c *Client) DeletePublic(
	address string,
	path string,
	result any,
) error {
	return c.do(
		http.MethodDelete,
		address,
		path,
		nil,
		result,
		false,
	)
}

func (c *Client) do(
	method string,
	address string,
	path string,
	body any,
	result any,
	authenticated bool,
) error {
	var requestBody *bytes.Reader

	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf(
				"encode request: %w",
				err,
			)
		}

		requestBody = bytes.NewReader(data)
	} else {
		requestBody = bytes.NewReader(nil)
	}

	address = strings.TrimRight(address, "/")

	requestURL := address +
		"/" +
		strings.TrimLeft(path, "/")

	req, err := http.NewRequest(
		method,
		requestURL,
		requestBody,
	)
	if err != nil {
		return fmt.Errorf(
			"create request: %w",
			err,
		)
	}

	req.Header.Set(
		"Accept",
		"application/json",
	)

	if body != nil {
		req.Header.Set(
			"Content-Type",
			"application/json",
		)
	}

	if authenticated {
		if c.Token == "" {
			return errors.New(
				"authentication token is required",
			)
		}

		req.Header.Set(
			"Authorization",
			"Bearer "+c.Token,
		)
	}

	httpClient, err := c.httpClient(address)
	if err != nil {
		return err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf(
			"request failed: %w",
			err,
		)
	}

	defer resp.Body.Close()

	if resp.StatusCode < 200 ||
		resp.StatusCode >= 300 {
		return parseHTTPError(resp)
	}

	if result == nil {
		return nil
	}

	if err := json.NewDecoder(
		resp.Body,
	).Decode(result); err != nil {
		return fmt.Errorf(
			"decode response: %w",
			err,
		)
	}

	return nil
}

func (c *Client) httpClient(
	address string,
) (*http.Client, error) {
	c.mu.RLock()

	client, exists := c.clients[address]

	c.mu.RUnlock()

	if exists {
		return client, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Double check setelah mendapatkan write lock.
	if client, exists := c.clients[address]; exists {
		return client, nil
	}

	config, exists := c.tlsConfigs[address]
	if !exists {
		return nil, fmt.Errorf(
			"TLS configuration is not configured for %s",
			address,
		)
	}

	tlsConfig, err := newTLSConfig(
		address,
		config,
	)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client = &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}

	c.clients[address] = client

	return client, nil
}

func newTLSConfig(
	address string,
	config TLSConfig,
) (*tls.Config, error) {
	parsedURL, err := url.Parse(address)
	if err != nil {
		return nil, fmt.Errorf(
			"parse server address: %w",
			err,
		)
	}

	if parsedURL.Hostname() == "" {
		return nil, fmt.Errorf(
			"server address hostname is required",
		)
	}

	hostname := parsedURL.Hostname()

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,

		// Certificate daemon adalah self-signed.
		// Trust dilakukan secara manual melalui VerifyConnection.
		InsecureSkipVerify: true,

		ServerName: hostname,
	}

	tlsConfig.VerifyConnection = func(
		state tls.ConnectionState,
	) error {
		return verifyTLSConnection(
			state,
			hostname,
			config,
		)
	}

	return tlsConfig, nil
}

func verifyTLSConnection(
	state tls.ConnectionState,
	hostname string,
	config TLSConfig,
) error {
	if len(state.PeerCertificates) == 0 {
		return errors.New(
			"server did not provide a TLS certificate",
		)
	}

	certificate := state.PeerCertificates[0]

	now := time.Now()

	if now.Before(certificate.NotBefore) {
		return fmt.Errorf(
			"server TLS certificate is not valid yet",
		)
	}

	if now.After(certificate.NotAfter) {
		return fmt.Errorf(
			"server TLS certificate has expired",
		)
	}

	if err := certificate.VerifyHostname(hostname); err != nil {
		return fmt.Errorf(
			"server TLS certificate hostname verification failed: %w",
			err,
		)
	}

	fingerprint, err := publicKeyFingerprint(
		certificate,
	)
	if err != nil {
		return fmt.Errorf(
			"calculate server TLS fingerprint: %w",
			err,
		)
	}

	if config.Fingerprint == "" {
		if config.OnFirstTrust == nil {
			return errors.New(
				"server TLS fingerprint is not trusted",
			)
		}

		if err := config.OnFirstTrust(
			fingerprint,
		); err != nil {
			return fmt.Errorf(
				"save server TLS fingerprint: %w",
				err,
			)
		}

		return nil
	}

	if !strings.EqualFold(
		config.Fingerprint,
		fingerprint,
	) {
		return fmt.Errorf(
			"server TLS fingerprint mismatch: expected %s, got %s",
			config.Fingerprint,
			fingerprint,
		)
	}

	return nil
}

func publicKeyFingerprint(
	certificate *x509.Certificate,
) (string, error) {
	publicKeyDER, err := x509.MarshalPKIXPublicKey(
		certificate.PublicKey,
	)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(
		publicKeyDER,
	)

	return "sha256:" + hex.EncodeToString(
		sum[:],
	), nil
}

func parseHTTPError(
	resp *http.Response,
) error {
	body, err := io.ReadAll(resp.Body)
	if err == nil {
		message := strings.TrimSpace(
			string(body),
		)

		if message != "" {
			return errors.New(message)
		}
	}

	return fmt.Errorf(
		"daemon returned status %d",
		resp.StatusCode,
	)
}
