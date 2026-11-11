package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type TLSConfig struct {
	Fingerprint string

	// Called when the server is trusted for the first time.
	// The parameter contains the SHA-256 SPKI fingerprint.
	OnFirstTrust func(fingerprint string) error

	// TCP address used for the connection.
	//
	// Example:
	//   192.168.100.36:49153
	//
	// This is different from the TLS hostname.
	DialAddress string
}

type Client struct {
	Token string

	mu         sync.RWMutex
	tlsConfigs map[string]TLSConfig
	clients    map[string]*http.Client

	reachable          map[string]bool
	reachableChangedAt map[string]time.Time
	adaptiveInterval   time.Duration
}

func NewClient() *Client {
	return &Client{
		tlsConfigs:         make(map[string]TLSConfig),
		clients:            make(map[string]*http.Client),
		reachable:          make(map[string]bool),
		reachableChangedAt: make(map[string]time.Time),
		adaptiveInterval:   5 * time.Second,
	}
}

func (c *Client) SetToken(token string) {
	c.Token = token
}

func (c *Client) ClearToken() {
	c.Token = ""
}

func (c *Client) SetReachable(
	address string,
	reachable bool,
) {
	c.setReachable(address, reachable, "unknown", "")
}

func (c *Client) setReachable(
	address string,
	reachable bool,
	source string,
	reason string,
) {
	address = strings.TrimRight(address, "/")

	c.mu.Lock()

	previous := c.reachable[address]

	if previous == reachable {
		c.mu.Unlock()
		return
	}

	c.reachable[address] = reachable
	c.reachableChangedAt[address] = time.Now()

	c.mu.Unlock()

	// debug.LogJSON("reachability changed", map[string]any{
	// 	"address":   address,
	// 	"previous":  previous,
	// 	"current":   reachable,
	// 	"source":    source,
	// 	"reason":    reason,
	// 	"changedAt": time.Now().Format(time.RFC3339Nano),
	// })
}

func (c *Client) IsReachable(address string) bool {
	address = strings.TrimRight(address, "/")

	c.mu.RLock()
	defer c.mu.RUnlock()

	// debug.LogJSON("reachable per address", c.reachable)

	return c.reachable[address]
}

func (c *Client) ReachableChangedAt(address string) time.Time {
	address = strings.TrimRight(address, "/")

	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.reachableChangedAt[address]
}

func (c *Client) SetAdaptiveInterval(interval time.Duration) {
	if interval <= 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.adaptiveInterval = interval
}

func (c *Client) AdaptiveInterval() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.adaptiveInterval
}

// ConfigureDialAddress registers the actual TCP address for a logical server.
func (c *Client) ConfigureDialAddress(
	address string,
	dialAddress string,
) {
	address = strings.TrimRight(address, "/")
	dialAddress = strings.TrimSpace(dialAddress)

	c.mu.Lock()
	defer c.mu.Unlock()

	config := c.tlsConfigs[address]
	config.DialAddress = dialAddress
	c.tlsConfigs[address] = config

	delete(c.clients, address)
}

func (c *Client) ConfigureTLS(
	address string,
	config TLSConfig,
) {
	address = strings.TrimRight(address, "/")

	c.mu.Lock()
	defer c.mu.Unlock()

	if config.DialAddress == "" {
		if existing, exists := c.tlsConfigs[address]; exists {
			config.DialAddress = existing.DialAddress
		}
	}

	c.tlsConfigs[address] = config
	delete(c.clients, address)
}

func (c *Client) ClearTLS(address string) {
	address = strings.TrimRight(address, "/")

	c.mu.Lock()
	defer c.mu.Unlock()

	existing := c.tlsConfigs[address]

	// Preserve the discovered TCP address.
	dialAddress := existing.DialAddress

	delete(c.clients, address)

	if dialAddress != "" {
		c.tlsConfigs[address] = TLSConfig{
			DialAddress: dialAddress,
		}
	} else {
		delete(c.tlsConfigs, address)
	}
}

// isConnectionError identifies errors that indicate a connection failure.
// TLS verification errors and local request errors do not count as connection errors.
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		result := isConnectionError(urlErr.Err)

		// debug.LogJSON("connection error classification", map[string]any{
		// 	"type":   "url.Error",
		// 	"error":  urlErr.Err.Error(),
		// 	"result": result,
		// })

		return result
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		// debug.LogJSON("connection error classification", map[string]any{
		// 	"type":   "net.OpError",
		// 	"error":  err.Error(),
		// 	"result": true,
		// })
		return true
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		// debug.LogJSON("connection error classification", map[string]any{
		// 	"type":   "net.DNSError",
		// 	"error":  err.Error(),
		// 	"result": true,
		// })
		return true
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		// debug.LogJSON("connection error classification", map[string]any{
		// 	"type":   "net.Error",
		// 	"error":  err.Error(),
		// 	"result": true,
		// })
		return true
	}

	// debug.LogJSON("connection error classification", map[string]any{
	// 	"type":   fmt.Sprintf("%T", err),
	// 	"error":  err.Error(),
	// 	"result": false,
	// })

	return false
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

func (c *Client) Query(
	address string,
	path string,
	body any,
	result any,
) error {
	return c.do(
		"QUERY",
		address,
		path,
		body,
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
			return fmt.Errorf("encode request: %w", err)
		}

		requestBody = bytes.NewReader(data)
	} else {
		requestBody = bytes.NewReader(nil)
	}

	address = strings.TrimRight(address, "/")

	requestURL := address + "/" + strings.TrimLeft(path, "/")

	req, err := http.NewRequest(
		method,
		requestURL,
		requestBody,
	)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if authenticated {
		if c.Token == "" {
			return errors.New("authentication token is required")
		}

		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	httpClient, err := c.httpClient(address)
	if err != nil {
		// Configuration errors do not prove the server is unreachable.
		return err
	}

	// startedAt := time.Now()

	resp, err := httpClient.Do(req)
	if err != nil {
		connectionError := isConnectionError(err)

		// debug.LogJSON("API request failed", map[string]any{
		// 	"method":          method,
		// 	"address":         address,
		// 	"path":            path,
		// 	"error":           err.Error(),
		// 	"connectionError": connectionError,
		// 	"elapsed":         time.Since(startedAt).String(),
		// })

		if connectionError {
			c.setReachable(
				address,
				false,
				"api-request",
				err.Error(),
			)
		}

		return fmt.Errorf("request failed: %w", err)
	}

	defer resp.Body.Close()

	// debug.LogJSON("API request succeeded", map[string]any{
	// 	"method":     method,
	// 	"address":    address,
	// 	"path":       path,
	// 	"statusCode": resp.StatusCode,
	// 	"elapsed":    time.Since(startedAt).String(),
	// })

	c.setReachable(
		address,
		true,
		"api-request",
		fmt.Sprintf("HTTP status %d", resp.StatusCode),
	)

	// defer resp.Body.Close()

	// // Any HTTP response means the server was reached,
	// // regardless of its status code.
	// c.SetReachable(address, true)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return parseHTTPError(resp)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}

	if result == nil {
		return nil
	}

	if err := json.Unmarshal(data, result); err != nil {
		return fmt.Errorf("decode response: %w", err)
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

	// debug.LogJSON("HTTP client configuration", map[string]any{
	// 	"address":     address,
	// 	"dialAddress": config.DialAddress,
	// 	"hasDial":     config.DialAddress != "",
	// })

	tlsConfig, err := newTLSConfig(address, config)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	if config.DialAddress != "" {
		dialer := &net.Dialer{
			Timeout: 3 * time.Second,
		}

		dialAddress := config.DialAddress

		transport.DialContext = func(
			ctx context.Context,
			network string,
			_ string,
		) (net.Conn, error) {
			// debug.LogJSON("HTTP dialing", map[string]any{
			// 	"network":     network,
			// 	"dialAddress": dialAddress,
			// })
			return dialer.DialContext(
				ctx,
				network,
				dialAddress,
			)
		}
	}

	client = &http.Client{
		Timeout:   3 * time.Second,
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
		return nil, fmt.Errorf("parse server address: %w", err)
	}

	if parsedURL.Hostname() == "" {
		return nil, errors.New("server address hostname is required")
	}

	hostname := parsedURL.Hostname()

	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // Certificate verification is performed manually.
		ServerName:         hostname,
	}

	tlsConfig.VerifyConnection = func(
		state tls.ConnectionState,
	) error {
		return verifyTLSConnection(state, hostname, config)
	}

	return tlsConfig, nil
}

func verifyTLSConnection(
	state tls.ConnectionState,
	hostname string,
	config TLSConfig,
) error {
	if len(state.PeerCertificates) == 0 {
		return errors.New("server did not provide a TLS certificate")
	}

	certificate := state.PeerCertificates[0]
	now := time.Now()

	if now.Before(certificate.NotBefore) {
		return errors.New("server TLS certificate is not valid yet")
	}

	if now.After(certificate.NotAfter) {
		return errors.New("server TLS certificate has expired")
	}

	if err := certificate.VerifyHostname(hostname); err != nil {
		return fmt.Errorf(
			"server TLS certificate hostname verification failed: %w",
			err,
		)
	}

	fingerprint, err := publicKeyFingerprint(certificate)
	if err != nil {
		return fmt.Errorf(
			"calculate server TLS fingerprint: %w",
			err,
		)
	}

	if config.Fingerprint == "" {
		if config.OnFirstTrust == nil {
			return errors.New("server TLS fingerprint is not trusted")
		}

		if err := config.OnFirstTrust(fingerprint); err != nil {
			return fmt.Errorf("save server TLS fingerprint: %w", err)
		}

		return nil
	}

	if !strings.EqualFold(config.Fingerprint, fingerprint) {
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
	publicKeyDER, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(publicKeyDER)

	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func parseHTTPError(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err == nil {
		message := strings.TrimSpace(string(body))
		if message != "" {
			return errors.New(message)
		}
	}

	return fmt.Errorf("daemon returned status %d", resp.StatusCode)
}

// CheckReachability probes the server's health endpoint.
// Any HTTP response means the server is reachable.
// Connection errors set the flag to false; TLS or local errors leave it unchanged.

func (c *Client) CheckReachability(address string) {
	c.CheckReachabilityContext(
		context.Background(),
		address,
	)
}

// CheckReachabilityContext allows the caller to cancel an in-flight probe.
func (c *Client) CheckReachabilityContext(
	parent context.Context,
	address string,
) {
	address = strings.TrimRight(address, "/")

	// debug.LogJSON("reachability probe started", map[string]any{
	// 	"address": address,
	// })

	httpClient, err := c.httpClient(address)
	if err != nil {
		// debug.LogJSON("reachability client error", map[string]any{
		// 	"address": address,
		// 	"error":   err.Error(),
		// })

		if isConnectionError(err) {
			c.setReachable(
				address,
				false,
				"health-check",
				err.Error(),
			)
		}

		return
	}

	ctx, cancel := context.WithTimeout(
		parent,
		2*time.Second,
	)
	defer cancel()

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		address+"/health",
		nil,
	)
	if err != nil {
		// debug.LogJSON("reachability request creation failed", map[string]any{
		// 	"address": address,
		// 	"error":   err.Error(),
		// })
		return
	}

	// startedAt := time.Now()

	resp, err := httpClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			// debug.LogJSON("reachability probe canceled", map[string]any{
			// 	"address": address,
			// 	"error":   ctx.Err().Error(),
			// })
			return
		}

		connectionError := isConnectionError(err)

		// debug.LogJSON("reachability probe failed", map[string]any{
		// 	"address":         address,
		// 	"error":           err.Error(),
		// 	"connectionError": connectionError,
		// 	"elapsed":         time.Since(startedAt).String(),
		// })

		if connectionError {
			c.setReachable(
				address,
				false,
				"health-check",
				err.Error(),
			)
		}

		return
	}

	defer resp.Body.Close()

	if ctx.Err() != nil {
		// debug.LogJSON("reachability probe result ignored", map[string]any{
		// 	"address": address,
		// 	"error":   ctx.Err().Error(),
		// })
		return
	}

	// debug.LogJSON("reachability probe succeeded", map[string]any{
	// 	"address":    address,
	// 	"statusCode": resp.StatusCode,
	// 	"elapsed":    time.Since(startedAt).String(),
	// })

	c.setReachable(
		address,
		true,
		"health-check",
		fmt.Sprintf("HTTP status %d", resp.StatusCode),
	)
}
