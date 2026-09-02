// Package api provides a minimal OpenBao/Vault HTTP API client
// built exclusively on the Go standard library (net/http, encoding/json).
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	pathpkg "path"
	"strings"
	"time"
)

const (
	httpTimeout    = 10 * time.Second
	cleanupTimeout = 5 * time.Second
	// DefaultMaxResponseBytes is the default maximum size of a response body
	// read from Vault/OpenBao.
	DefaultMaxResponseBytes = 32 << 20
)

var reservedLegacyPathPrefixes = map[string]struct{}{
	"auth":      {},
	"cubbyhole": {},
	"identity":  {},
	"sys":       {},
}

type responseTooLargeError struct {
	limit int64
}

func (e *responseTooLargeError) Error() string {
	return fmt.Sprintf("api: response body exceeds %d-byte limit", e.limit)
}

// Client is a minimal Vault/OpenBao REST client.
type Client struct {
	addr             string
	namespace        string
	token            string
	http             *http.Client
	ctx              context.Context
	maxResponseBytes int64
}

// New creates a new Client using the default HTTP transport. namespace may be empty.
func New(addr, namespace string) *Client {
	return NewWithTransport(addr, namespace, nil)
}

// NewWithTransport creates a new Client with a custom base RoundTripper. Secret
// reads and token revocation are retried on transient failures; authentication
// requests are attempted exactly once. If base is nil, http.DefaultTransport is
// used. Use this when a custom TLS configuration (e.g. a corporate CA
// certificate) is required. The supplied transport must not independently
// retry non-idempotent requests.
func NewWithTransport(addr, namespace string, base http.RoundTripper) *Client {
	return &Client{
		addr:      strings.TrimRight(addr, "/"),
		namespace: namespace,
		http: &http.Client{
			Timeout:   httpTimeout,
			Transport: newRetryTransport(base),
			// Vault requests contain credentials in custom headers and request
			// bodies. Do not forward them to a redirect target.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		ctx:              context.Background(),
		maxResponseBytes: DefaultMaxResponseBytes,
	}
}

// SetContext sets the context used for all subsequent HTTP requests made by
// this client. Pass a context derived from signal.NotifyContext to enable
// graceful cancellation on OS signals.
func (c *Client) SetContext(ctx context.Context) {
	c.ctx = ctx
}

// SetMaxResponseBytes sets the largest Vault/OpenBao response body the client
// will read into memory. It must be called before requests are made. The limit
// must leave room for the extra byte used to detect an oversized response.
func (c *Client) SetMaxResponseBytes(limit int64) error {
	if limit <= 0 || limit == math.MaxInt64 {
		return fmt.Errorf("api: max response bytes must be between 1 and %d", int64(math.MaxInt64-1))
	}
	c.maxResponseBytes = limit
	return nil
}

// LoginJWT authenticates with the JWT auth method and stores the resulting
// client token for subsequent requests.
func (c *Client) LoginJWT(role, jwt string) error {
	return c.LoginJWTAt("jwt", role, jwt)
}

// LoginJWTAt authenticates with a JWT auth method mounted at authPath and
// stores the resulting client token for subsequent requests. authPath may be
// a mount name (for example, "gitlab") or an auth-relative path (for example,
// "auth/gitlab").
func (c *Client) LoginJWTAt(authPath, role, jwt string) error {
	body, err := json.Marshal(map[string]string{
		"role": role,
		"jwt":  jwt,
	})
	if err != nil {
		return fmt.Errorf("api: marshal login body: %w", err)
	}

	loginPath, err := authLoginPath(authPath)
	if err != nil {
		return err
	}

	resp, err := c.post(loginPath, body)
	if err != nil {
		return err
	}

	var result struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return fmt.Errorf("api: parse login response: %w", err)
	}
	if result.Auth.ClientToken == "" {
		return fmt.Errorf("api: no client_token in login response")
	}
	c.token = result.Auth.ClientToken
	return nil
}

// LoginAppRole authenticates with the AppRole auth method using a role ID and
// secret ID, and stores the resulting client token for subsequent requests.
func (c *Client) LoginAppRole(roleID, secretID string) error {
	return c.LoginAppRoleAt("approle", roleID, secretID)
}

// LoginAppRoleAt authenticates with an AppRole auth method mounted at authPath
// using a role ID and secret ID, and stores the resulting client token for
// subsequent requests. authPath accepts the same formats as LoginJWTAt.
func (c *Client) LoginAppRoleAt(authPath, roleID, secretID string) error {
	body, err := json.Marshal(map[string]string{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	if err != nil {
		return fmt.Errorf("api: marshal approle login body: %w", err)
	}

	loginPath, err := authLoginPath(authPath)
	if err != nil {
		return err
	}

	resp, err := c.post(loginPath, body)
	if err != nil {
		return err
	}

	var result struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return fmt.Errorf("api: parse approle login response: %w", err)
	}
	if result.Auth.ClientToken == "" {
		return fmt.Errorf("api: no client_token in approle login response")
	}
	c.token = result.Auth.ClientToken
	return nil
}

// authLoginPath converts an auth mount into its login API endpoint. Keeping
// the caller-provided value below /v1/auth and rejecting ambiguous URL/path
// syntax prevents a configurable mount from becoming an arbitrary API call.
func authLoginPath(authPath string) (string, error) {
	if authPath == "" || strings.HasPrefix(authPath, "/") {
		return "", fmt.Errorf("api: auth path must be a non-empty relative path")
	}
	if strings.ContainsAny(authPath, `\%?#`) || pathpkg.Clean(authPath) != authPath {
		return "", fmt.Errorf("api: auth path must be canonical")
	}
	for _, segment := range strings.Split(authPath, "/") {
		if segment == "." || segment == ".." {
			return "", fmt.Errorf("api: auth path must be canonical")
		}
	}

	authPath = strings.TrimPrefix(authPath, "auth/")
	if authPath == "" {
		return "", fmt.Errorf("api: auth path must include a mount name")
	}

	return "/v1/auth/" + authPath + "/login", nil
}

// ReadSecret fetches a secret from Vault using the KV engine.
// kvVersion must be 1 or 2. The path parameter contains the full Vault path
// including the mount point (e.g. "kv/test" or "kvv1/test").
// For KV v2, "/data/" is inserted after the first path segment (mount point).
// For KV v1, the path is used as-is after validation. OpenBao's reserved
// auth, cubbyhole, identity, and sys path prefixes are not valid KV v1 mounts
// and are rejected.
// field is the key to extract from the secret data; if empty the entire data
// map is JSON-encoded and returned.
func (c *Client) ReadSecret(path, field string, kvVersion int) (string, error) {
	if err := validateSecretPath(path, kvVersion); err != nil {
		return "", err
	}

	var apiPath string
	switch kvVersion {
	case 2:
		// Split path into mount and rest: "kv/test" → mount="kv", rest="test"
		mount, rest, _ := strings.Cut(path, "/")
		if rest != "" {
			apiPath = fmt.Sprintf("/v1/%s/data/%s", mount, rest)
		} else {
			apiPath = fmt.Sprintf("/v1/%s/data", mount)
		}
	case 1:
		apiPath = fmt.Sprintf("/v1/%s", path)
	}

	raw, err := c.get(apiPath)
	if err != nil {
		return "", err
	}

	var outer map[string]json.RawMessage
	if err := json.Unmarshal(raw, &outer); err != nil {
		return "", fmt.Errorf("api: parse secret outer: %w", err)
	}

	dataRaw, ok := outer["data"]
	if !ok {
		return "", fmt.Errorf("api: no 'data' field in secret response")
	}

	var data map[string]json.RawMessage

	if kvVersion == 2 {
		var wrapper struct {
			Data map[string]json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(dataRaw, &wrapper); err != nil {
			return "", fmt.Errorf("api: parse kv2 data wrapper: %w", err)
		}
		data = wrapper.Data
	} else {
		if err := json.Unmarshal(dataRaw, &data); err != nil {
			return "", fmt.Errorf("api: parse kv1 data: %w", err)
		}
	}

	if field == "" {
		out, err := json.Marshal(data)
		if err != nil {
			return "", fmt.Errorf("api: marshal data map: %w", err)
		}
		return string(out), nil
	}

	valRaw, ok := data[field]
	if !ok {
		return "", fmt.Errorf("api: requested field not found in secret")
	}

	var val string
	if err := json.Unmarshal(valRaw, &val); err != nil {
		// fall back to raw JSON value (e.g. number / bool)
		return strings.Trim(string(valRaw), `"`), nil
	}
	return val, nil
}

// validateSecretPath rejects paths whose interpretation could change between
// bao-wrapper's URL parser, net/http, and OpenBao's request router. Legacy KV
// v1 requests additionally cannot target OpenBao's reserved singleton mounts;
// without this restriction, legacy would act as an authenticated generic GET
// client and could expose the client token via auth/token/lookup-self.
func validateSecretPath(secretPath string, kvVersion int) error {
	if kvVersion != 1 && kvVersion != 2 {
		return fmt.Errorf("api: unsupported KV version %d", kvVersion)
	}

	if secretPath == "" || strings.HasPrefix(secretPath, "/") {
		return fmt.Errorf("api: secret path must be a non-empty relative path")
	}
	if strings.ContainsAny(secretPath, `\%?#`) || pathpkg.Clean(secretPath) != secretPath {
		return fmt.Errorf("api: secret path must be canonical")
	}

	if kvVersion == 1 {
		prefix, _, _ := strings.Cut(secretPath, "/")
		if _, reserved := reservedLegacyPathPrefixes[strings.ToLower(prefix)]; reserved {
			return fmt.Errorf("api: legacy secret path uses a reserved OpenBao prefix")
		}
	}

	return nil
}

// RevokeToken revokes the stored client token.
// If the client's main context has already been cancelled (e.g. due to an OS
// signal), a fresh timeout context is used so the cleanup call can still
// succeed.
func (c *Client) RevokeToken() error {
	ctx := c.effectiveCtx()
	if ctx.Err() != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
	}
	_, err := c.doWithTransientRetries(ctx, http.MethodPost, "/v1/auth/token/revoke-self", nil)
	return err
}

// Token returns the current client token (used only for testing; never log it).
func (c *Client) Token() string {
	return c.token
}

// SetToken sets the client token directly (useful for tests).
func (c *Client) SetToken(t string) {
	c.token = t
}

// effectiveCtx returns c.ctx if set, otherwise context.Background().
func (c *Client) effectiveCtx() context.Context {
	if c.ctx != nil {
		return c.ctx
	}
	return context.Background()
}

func (c *Client) responseSizeLimit() int64 {
	if c.maxResponseBytes <= 0 || c.maxResponseBytes == math.MaxInt64 {
		return DefaultMaxResponseBytes
	}
	return c.maxResponseBytes
}

// ---------- internal helpers ----------

func (c *Client) doWithContext(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.addr+path, bodyReader)
	if err != nil {
		// Request-construction errors can quote the raw URL, including a secret
		// path. Keep configured values out of errors returned to callers.
		return nil, fmt.Errorf("api: create request failed")
	}

	req.Header.Set("Content-Type", "application/json")
	if c.namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.namespace)
	}
	if c.token != "" {
		req.Header.Set("X-Vault-Token", c.token)
	}

	res, err := c.http.Do(req)
	if err != nil {
		var sizeErr *responseTooLargeError
		if errors.As(err, &sizeErr) {
			return nil, sizeErr
		}
		// net/http transport errors commonly embed the complete request URL.
		// Preserve cancellation semantics without exposing configured values.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("api: %s request failed: %w", method, ctxErr)
		}
		return nil, fmt.Errorf("api: %s request failed", method)
	}
	defer func() {
		_ = res.Body.Close()
	}()

	maxResponseBytes := c.responseSizeLimit()
	if res.ContentLength > maxResponseBytes {
		return nil, &responseTooLargeError{limit: maxResponseBytes}
	}

	resBody, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("api: read response body: %w", err)
	}
	if int64(len(resBody)) > maxResponseBytes {
		return nil, &responseTooLargeError{limit: maxResponseBytes}
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("api: %s returned status %d", method, res.StatusCode)
	}

	return resBody, nil
}

func (c *Client) do(method, path string, body []byte) ([]byte, error) {
	return c.doWithContext(c.effectiveCtx(), method, path, body)
}

func (c *Client) doWithTransientRetries(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	return c.doWithContext(withTransientRetries(ctx, c.responseSizeLimit()), method, path, body)
}

func (c *Client) get(path string) ([]byte, error) {
	return c.doWithTransientRetries(c.effectiveCtx(), http.MethodGet, path, nil)
}

func (c *Client) post(path string, body []byte) ([]byte, error) {
	return c.do(http.MethodPost, path, body)
}
