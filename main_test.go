package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

const successfulRunChildHelperEnv = "GO_WANT_BAO_WRAPPER_SUCCESSFUL_RUN_CHILD"

func TestSuccessfulRunChildHelper(t *testing.T) {
	if os.Getenv(successfulRunChildHelperEnv) == "" {
		return
	}
}

func TestRunVersion(t *testing.T) {
	for _, arg := range []string{"version", "-v", "--version"} {
		t.Run(arg, func(t *testing.T) {
			code := run([]string{arg})
			if code != 0 {
				t.Errorf("expected exit code 0 for %q, got %d", arg, code)
			}
		})
	}
}

func TestRunVersion_Output(t *testing.T) {
	// Temporarily override the package-level variables to verify output format.
	origVersion, origCommit := version, commit
	version = "v1.2.3"
	commit = "0123456789abcdef0123456789abcdef01234567"
	defer func() { version, commit = origVersion, origCommit }()

	// Capture stdout by redirecting os.Stdout.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origStdout := os.Stdout
	os.Stdout = w

	code := run([]string{"version"})

	closeErr := w.Close()
	os.Stdout = origStdout
	if closeErr != nil {
		t.Fatalf("close captured stdout: %v", closeErr)
	}

	outBytes, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured output: %v", err)
	}
	output := string(outBytes)

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(output, "v1.2.3") {
		t.Errorf("expected output to contain version %q, got %q", "v1.2.3", output)
	}
	if !strings.Contains(output, "0123456789abcdef0123456789abcdef01234567") {
		t.Errorf("expected output to contain full commit %q, got %q", "0123456789abcdef0123456789abcdef01234567", output)
	}
}

func TestGetEnvWithFallback(t *testing.T) {
	const primary = "BAO_ADDR"
	const fallback = "VAULT_ADDR"

	t.Run("only primary set", func(t *testing.T) {
		t.Setenv(primary, "https://bao.example.com")
		t.Setenv(fallback, "")
		got := getEnvWithFallback(primary, fallback)
		if got != "https://bao.example.com" {
			t.Errorf("expected %q, got %q", "https://bao.example.com", got)
		}
	})

	t.Run("only fallback set", func(t *testing.T) {
		t.Setenv(primary, "")
		t.Setenv(fallback, "https://vault.example.com")
		got := getEnvWithFallback(primary, fallback)
		if got != "https://vault.example.com" {
			t.Errorf("expected %q, got %q", "https://vault.example.com", got)
		}
	})

	t.Run("both set, primary wins", func(t *testing.T) {
		t.Setenv(primary, "https://bao.example.com")
		t.Setenv(fallback, "https://vault.example.com")
		got := getEnvWithFallback(primary, fallback)
		if got != "https://bao.example.com" {
			t.Errorf("expected primary %q to win, got %q", "https://bao.example.com", got)
		}
	})

	t.Run("neither set", func(t *testing.T) {
		t.Setenv(primary, "")
		t.Setenv(fallback, "")
		got := getEnvWithFallback(primary, fallback)
		if got != "" {
			t.Errorf("expected empty string, got %q", got)
		}
	})
}

func TestResponseSizeLimitFromEnv(t *testing.T) {
	const (
		primary      = "BAO_TEST_MAX_RESPONSE_BYTES"
		fallback     = "VAULT_TEST_MAX_RESPONSE_BYTES"
		defaultLimit = int64(4096)
	)

	t.Run("default", func(t *testing.T) {
		t.Setenv(primary, "")
		t.Setenv(fallback, "")

		got, err := responseSizeLimitFromEnv(primary, fallback, defaultLimit)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != defaultLimit {
			t.Fatalf("expected default %d, got %d", defaultLimit, got)
		}
	})

	t.Run("fallback", func(t *testing.T) {
		t.Setenv(primary, "")
		t.Setenv(fallback, "2048")

		got, err := responseSizeLimitFromEnv(primary, fallback, defaultLimit)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != 2048 {
			t.Fatalf("expected fallback limit 2048, got %d", got)
		}
	})

	t.Run("primary wins", func(t *testing.T) {
		t.Setenv(primary, "1024")
		t.Setenv(fallback, "2048")

		got, err := responseSizeLimitFromEnv(primary, fallback, defaultLimit)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != 1024 {
			t.Fatalf("expected primary limit 1024, got %d", got)
		}
	})

	for _, value := range []string{"not-a-number", "-1", "0", "9223372036854775807"} {
		t.Run("rejects "+value, func(t *testing.T) {
			t.Setenv(primary, value)
			t.Setenv(fallback, "")

			if _, err := responseSizeLimitFromEnv(primary, fallback, defaultLimit); err == nil {
				t.Fatalf("expected %q to be rejected", value)
			}
		})
	}
}

func TestBuildTLSTransport_NoCert(t *testing.T) {
	t.Setenv("BAO_CACERT", "")
	t.Setenv("VAULT_CACERT", "")

	transport, err := buildTLSTransport()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if transport != nil {
		t.Error("expected nil transport when no CA cert is configured")
	}
}

func TestBuildTLSTransport_FileNotFound(t *testing.T) {
	t.Setenv("BAO_CACERT", "/nonexistent/path/to/ca.pem")
	t.Setenv("VAULT_CACERT", "")

	_, err := buildTLSTransport()
	if err == nil {
		t.Fatal("expected error for non-existent CA cert file")
	}
}

func TestBuildTLSTransport_FallbackVar(t *testing.T) {
	t.Setenv("BAO_CACERT", "")
	t.Setenv("VAULT_CACERT", "/nonexistent/path/to/ca.pem")

	_, err := buildTLSTransport()
	if err == nil {
		t.Fatal("expected error: VAULT_CACERT fallback should be used when BAO_CACERT is unset")
	}
}

func TestBuildTLSTransport_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	certFile := dir + "/ca.pem"
	if err := os.WriteFile(certFile, []byte("not valid PEM content"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("BAO_CACERT", certFile)
	t.Setenv("VAULT_CACERT", "")

	_, err := buildTLSTransport()
	if err == nil {
		t.Fatal("expected error for invalid PEM content")
	}
}

func TestBuildTLSTransport_ValidCert(t *testing.T) {
	certPEM := generateSelfSignedCert(t)

	dir := t.TempDir()
	certFile := dir + "/ca.pem"
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("BAO_CACERT", certFile)
	t.Setenv("VAULT_CACERT", "")

	transport, err := buildTLSTransport()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if transport == nil {
		t.Fatal("expected non-nil transport when CA cert file is valid")
	}
}

func TestFetchGitHubActionsOIDCToken_NoEnvVars(t *testing.T) {
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")

	jwt, err := fetchGitHubActionsOIDCToken(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if jwt != "" {
		t.Errorf("expected empty string when env vars are absent, got %q", jwt)
	}
}

func TestFetchGitHubActionsOIDCToken_MissingToken(t *testing.T) {
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.com/oidc")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")

	jwt, err := fetchGitHubActionsOIDCToken(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if jwt != "" {
		t.Errorf("expected empty string when request token is absent, got %q", jwt)
	}
}

func TestFetchGitHubActionsOIDCToken_InvalidResponseSizeLimit(t *testing.T) {
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.com/oidc")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-token")
	t.Setenv("BAO_OIDC_MAX_RESPONSE_BYTES", "0")
	t.Setenv("VAULT_OIDC_MAX_RESPONSE_BYTES", "")

	_, err := fetchGitHubActionsOIDCToken(context.Background())
	if err == nil || !strings.Contains(err.Error(), "BAO_OIDC_MAX_RESPONSE_BYTES") {
		t.Fatalf("expected invalid response-size configuration error, got %v", err)
	}
}

func TestFetchGitHubActionsOIDCToken_Success(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "bearer test-request-token" {
			t.Errorf("expected Authorization header %q, got %q", "bearer test-request-token", auth)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{"value": "my-jwt-token"}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	jwt, err := requestGitHubActionsOIDCToken(context.Background(), srv.URL, "test-request-token", srv.Client().Transport)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if jwt != "my-jwt-token" {
		t.Errorf("expected %q, got %q", "my-jwt-token", jwt)
	}
}

func TestFetchGitHubActionsOIDCToken_HTTPError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := requestGitHubActionsOIDCToken(context.Background(), srv.URL, "bad-token", srv.Client().Transport)
	if err == nil {
		t.Fatal("expected error for HTTP 403 response")
	}
}

func TestFetchGitHubActionsOIDCToken_InvalidJSON(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("not-json")); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	defer srv.Close()

	_, err := requestGitHubActionsOIDCToken(context.Background(), srv.URL, "token", srv.Client().Transport)
	if err == nil {
		t.Fatal("expected error for invalid JSON response")
	}
}

func TestFetchGitHubActionsOIDCToken_EmptyValue(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{"value": ""}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	_, err := requestGitHubActionsOIDCToken(context.Background(), srv.URL, "token", srv.Client().Transport)
	if err == nil {
		t.Fatal("expected error when OIDC response value is empty")
	}
}

func TestGitHubActionsOIDCClientProtections(t *testing.T) {
	client := newGitHubActionsOIDCClient(nil)
	if client == http.DefaultClient {
		t.Fatal("expected a dedicated HTTP client")
	}
	if client.Timeout != 10*time.Second {
		t.Fatalf("expected a 10-second timeout, got %s", client.Timeout)
	}
	if client.CheckRedirect == nil {
		t.Fatal("expected redirect policy to be configured")
	}
	if err := client.CheckRedirect(&http.Request{}, nil); err != http.ErrUseLastResponse {
		t.Fatalf("expected redirects to be rejected with http.ErrUseLastResponse, got %v", err)
	}
}

func TestFetchGitHubActionsOIDCToken_RejectsRedirect(t *testing.T) {
	redirected := make(chan struct{}, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/collect", http.StatusFound)
	}))
	defer source.Close()

	_, err := requestGitHubActionsOIDCToken(context.Background(), source.URL, "must-not-leak", source.Client().Transport)
	if err == nil {
		t.Fatal("expected redirect response to be rejected")
	}
	select {
	case <-redirected:
		t.Fatal("redirect target received the OIDC request")
	default:
	}
}

func TestFetchGitHubActionsOIDCToken_ResponseSizeLimit(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"value":"`+strings.Repeat("x", githubOIDCMaxResponseBytes)+`"}`)
	}))
	defer srv.Close()

	_, err := requestGitHubActionsOIDCToken(context.Background(), srv.URL, "token", srv.Client().Transport)
	if err == nil || !strings.Contains(err.Error(), "response exceeds") {
		t.Fatalf("expected response-size error, got %v", err)
	}
}

func TestFetchGitHubActionsOIDCToken_ConfiguredResponseSizeLimit(t *testing.T) {
	responseBody := []byte(`{"value":"configured-token"}`)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Force a chunked response to exercise the streaming limit instead of
		// the Content-Length fast path.
		w.(http.Flusher).Flush()
		_, _ = w.Write(responseBody)
	}))
	defer srv.Close()

	token, err := requestGitHubActionsOIDCTokenWithLimit(
		context.Background(), srv.URL, "request-token", srv.Client().Transport, int64(len(responseBody)),
	)
	if err != nil {
		t.Fatalf("expected exact-limit response to succeed: %v", err)
	}
	if token != "configured-token" {
		t.Fatalf("expected configured-token, got %q", token)
	}

	_, err = requestGitHubActionsOIDCTokenWithLimit(
		context.Background(), srv.URL, "request-token", srv.Client().Transport, int64(len(responseBody)-1),
	)
	if err == nil || !strings.Contains(err.Error(), "response exceeds") {
		t.Fatalf("expected response-size error, got %v", err)
	}
}

func TestFetchGitHubActionsOIDCToken_RejectsInvalidExplicitLimits(t *testing.T) {
	for _, limit := range []int64{-1, 0, math.MaxInt64} {
		_, err := requestGitHubActionsOIDCTokenWithLimit(
			context.Background(), "https://example.com/oidc", "request-token", nil, limit,
		)
		if err == nil {
			t.Fatalf("expected limit %d to be rejected", limit)
		}
	}
}

func TestValidateGitHubActionsOIDCURL(t *testing.T) {
	valid := []string{
		"https://token.actions.githubusercontent.com/?api-version=2.0",
		"https://github.example.com/_services/token?api-version=2.0",
		"https://token.actions.github.example.com/oidc",
	}
	for _, endpoint := range valid {
		if err := validateGitHubActionsOIDCURL(endpoint); err != nil {
			t.Errorf("expected %q to be valid: %v", endpoint, err)
		}
	}

	invalid := []string{
		"http://token.actions.githubusercontent.com/",
		"//token.actions.githubusercontent.com/",
		"https:///oidc",
		"https://user:password@github.example.com/oidc",
		"https://github.example.com/oidc#fragment",
	}
	for _, endpoint := range invalid {
		if err := validateGitHubActionsOIDCURL(endpoint); err == nil {
			t.Errorf("expected %q to be rejected", endpoint)
		}
	}
}

func TestRunBaoToken_DirectToken(t *testing.T) {
	// A mock Vault server that serves a single KV secret and checks that the
	// client presents the token from BAO_TOKEN directly – no login endpoint
	// should be called.
	loginCalled := false
	revokeCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/jwt/login", "/v1/auth/approle/login":
			loginCalled = true
			http.Error(w, "login must not be called when BAO_TOKEN is set", http.StatusForbidden)
		case "/v1/kv/data/myapp/db":
			if got := r.Header.Get("X-Vault-Token"); got != "direct-token" {
				t.Errorf("expected X-Vault-Token %q, got %q", "direct-token", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"data": map[string]string{"password": "s3cret"},
				},
			})
		case "/v1/auth/token/revoke-self":
			revokeCalls++
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	t.Setenv("BAO_ADDR", srv.URL)
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("BAO_TOKEN", "direct-token")
	t.Setenv("VAULT_TOKEN", "")
	t.Setenv("BAO_JWT_ROLE", "")
	t.Setenv("BAO_JWT_TOKEN", "")
	t.Setenv("BAO_APP_ID", "")
	t.Setenv("BAO_APP_SECRET", "")
	t.Setenv("BAO_NAMESPACE", "")
	t.Setenv("BAO_CACERT", "")
	t.Setenv("VAULT_CACERT", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	t.Setenv("SECRET_DB_PASS", "kv://password@kv/myapp/db")

	code := run([]string{"run", "--", "env"})
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	if loginCalled {
		t.Error("login endpoint must not be called when BAO_TOKEN is set")
	}
	if revokeCalls != 1 {
		t.Errorf("expected token to be revoked exactly once, got %d calls", revokeCalls)
	}
}

func TestRun_ConfiguresVaultResponseSizeLimit(t *testing.T) {
	secretRequests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/kv/data/myapp/db":
			secretRequests++
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"data":{"data":{"password":"response-over-configured-limit"}}}`)
		case "/v1/auth/token/revoke-self":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	t.Setenv("BAO_ADDR", srv.URL)
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("BAO_TOKEN", "direct-token")
	t.Setenv("VAULT_TOKEN", "")
	t.Setenv("BAO_JWT_ROLE", "")
	t.Setenv("BAO_JWT_TOKEN", "")
	t.Setenv("BAO_APP_ID", "")
	t.Setenv("BAO_APP_SECRET", "")
	t.Setenv("BAO_NAMESPACE", "")
	t.Setenv("BAO_CACERT", "")
	t.Setenv("VAULT_CACERT", "")
	t.Setenv("BAO_MAX_RESPONSE_BYTES", "32")
	t.Setenv("VAULT_MAX_RESPONSE_BYTES", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	t.Setenv("RESPONSE_LIMIT_TEST_SECRET", "kv://password@kv/myapp/db")

	code := run([]string{"run", "--secret-prefix", "RESPONSE_LIMIT_TEST_", "--", "must-not-start"})
	if code != 1 {
		t.Fatalf("expected oversized Vault response to fail the run, got exit code %d", code)
	}
	if secretRequests != 1 {
		t.Fatalf("expected one secret request, got %d", secretRequests)
	}
}

func TestRunBaoToken_RevokeFailureReturnsNonzero(t *testing.T) {
	revokeCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/token/revoke-self" {
			http.NotFound(w, r)
			return
		}
		revokeCalls++
		http.Error(w, "cleanup failed", http.StatusInternalServerError)
	}))
	defer srv.Close()

	t.Setenv("BAO_ADDR", srv.URL)
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("BAO_TOKEN", "direct-token")
	t.Setenv("VAULT_TOKEN", "")
	t.Setenv("BAO_JWT_ROLE", "")
	t.Setenv("BAO_JWT_TOKEN", "")
	t.Setenv("BAO_APP_ID", "")
	t.Setenv("BAO_APP_SECRET", "")
	t.Setenv("BAO_NAMESPACE", "")
	t.Setenv("BAO_CACERT", "")
	t.Setenv("VAULT_CACERT", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	t.Setenv(successfulRunChildHelperEnv, "1")

	code := run([]string{
		"run", "--secret-prefix", "TEST_CLEANUP_SECRET_", "--",
		os.Args[0], "-test.run=^TestSuccessfulRunChildHelper$",
	})
	if code != 1 {
		t.Fatalf("expected exit code 1 when token revocation fails, got %d", code)
	}
	if revokeCalls != 1 {
		t.Fatalf("expected one token revocation attempt, got %d", revokeCalls)
	}
}

func TestRunBareAmbientSecretIsNotRequested(t *testing.T) {
	var unexpectedRequests []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/token/revoke-self" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		unexpectedRequests = append(unexpectedRequests, r.Method+" "+r.URL.Path)
		http.NotFound(w, r)
	}))
	defer srv.Close()

	t.Setenv("BAO_ADDR", srv.URL)
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("BAO_TOKEN", "direct-token")
	t.Setenv("VAULT_TOKEN", "")
	t.Setenv("BAO_JWT_ROLE", "")
	t.Setenv("BAO_JWT_TOKEN", "")
	t.Setenv("BAO_APP_ID", "")
	t.Setenv("BAO_APP_SECRET", "")
	t.Setenv("BAO_NAMESPACE", "")
	t.Setenv("BAO_CACERT", "")
	t.Setenv("VAULT_CACERT", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	t.Setenv("SECRET_AMBIENT", "hunter2")

	if code := run([]string{"run", "--", "true"}); code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if len(unexpectedRequests) != 0 {
		t.Fatalf("ambient secret caused Vault requests: %v", unexpectedRequests)
	}
}

func TestRunBaoToken_RevokedAfterSecretFetchFailure(t *testing.T) {
	revokeCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/kv/data/myapp/missing":
			http.NotFound(w, r)
		case "/v1/auth/token/revoke-self":
			revokeCalls++
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	t.Setenv("BAO_ADDR", srv.URL)
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("BAO_TOKEN", "direct-token")
	t.Setenv("VAULT_TOKEN", "")
	t.Setenv("BAO_JWT_ROLE", "")
	t.Setenv("BAO_JWT_TOKEN", "")
	t.Setenv("BAO_APP_ID", "")
	t.Setenv("BAO_APP_SECRET", "")
	t.Setenv("BAO_NAMESPACE", "")
	t.Setenv("BAO_CACERT", "")
	t.Setenv("VAULT_CACERT", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	t.Setenv("SECRET_NOT_FOUND", "kv://value@kv/myapp/missing")

	code := run([]string{"run", "--", "must-not-start"})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if revokeCalls != 1 {
		t.Errorf("expected token to be revoked exactly once after fetch failure, got %d calls", revokeCalls)
	}
}

func TestRunVaultToken_FallbackToken(t *testing.T) {
	// When BAO_TOKEN is unset but VAULT_TOKEN is set, it should be used as a
	// direct token (no login required).
	loginCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/jwt/login", "/v1/auth/approle/login":
			loginCalled = true
			http.Error(w, "login must not be called when VAULT_TOKEN is set", http.StatusForbidden)
		case "/v1/kv/data/myapp/db":
			if got := r.Header.Get("X-Vault-Token"); got != "vault-fallback-token" {
				t.Errorf("expected X-Vault-Token %q, got %q", "vault-fallback-token", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"data": map[string]string{"password": "s3cret"},
				},
			})
		case "/v1/auth/token/revoke-self":
			// ignore cleanup
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	t.Setenv("BAO_ADDR", srv.URL)
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("BAO_TOKEN", "")
	t.Setenv("VAULT_TOKEN", "vault-fallback-token")
	t.Setenv("BAO_JWT_ROLE", "")
	t.Setenv("BAO_JWT_TOKEN", "")
	t.Setenv("BAO_APP_ID", "")
	t.Setenv("BAO_APP_SECRET", "")
	t.Setenv("BAO_NAMESPACE", "")
	t.Setenv("BAO_CACERT", "")
	t.Setenv("VAULT_CACERT", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	t.Setenv("SECRET_DB_PASS", "kv://password@kv/myapp/db")

	code := run([]string{"run", "--", "env"})
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	if loginCalled {
		t.Error("login endpoint must not be called when VAULT_TOKEN is set")
	}
}

func TestRunBaoToken_PriorityOverJWT(t *testing.T) {
	// When both BAO_TOKEN and BAO_JWT_ROLE/BAO_JWT_TOKEN are set, BAO_TOKEN
	// must take priority and no JWT login should occur.
	loginCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/jwt/login":
			loginCalled = true
			http.Error(w, "jwt login must not be called when BAO_TOKEN is set", http.StatusForbidden)
		case "/v1/kv/data/myapp/db":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"data": map[string]string{"password": "s3cret"},
				},
			})
		case "/v1/auth/token/revoke-self":
			// ignore cleanup
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	t.Setenv("BAO_ADDR", srv.URL)
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("BAO_TOKEN", "direct-token")
	t.Setenv("VAULT_TOKEN", "")
	t.Setenv("BAO_JWT_ROLE", "my-jwt-role")
	t.Setenv("BAO_JWT_TOKEN", "some-jwt")
	t.Setenv("BAO_APP_ID", "")
	t.Setenv("BAO_APP_SECRET", "")
	t.Setenv("BAO_NAMESPACE", "")
	t.Setenv("BAO_CACERT", "")
	t.Setenv("VAULT_CACERT", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	t.Setenv("SECRET_DB_PASS", "kv://password@kv/myapp/db")

	code := run([]string{"run", "--", "env"})
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	if loginCalled {
		t.Error("JWT login endpoint must not be called when BAO_TOKEN is set")
	}
}

func TestRunBaoToken_PriorityOverAppRole(t *testing.T) {
	// When both BAO_TOKEN and BAO_APP_ID/BAO_APP_SECRET are set, BAO_TOKEN
	// must take priority and no AppRole login should occur.
	loginCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/approle/login":
			loginCalled = true
			http.Error(w, "approle login must not be called when BAO_TOKEN is set", http.StatusForbidden)
		case "/v1/kv/data/myapp/db":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"data": map[string]string{"password": "s3cret"},
				},
			})
		case "/v1/auth/token/revoke-self":
			// ignore cleanup
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	t.Setenv("BAO_ADDR", srv.URL)
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("BAO_TOKEN", "direct-token")
	t.Setenv("VAULT_TOKEN", "")
	t.Setenv("BAO_JWT_ROLE", "")
	t.Setenv("BAO_JWT_TOKEN", "")
	t.Setenv("BAO_APP_ID", "my-role-id")
	t.Setenv("BAO_APP_SECRET", "my-secret-id")
	t.Setenv("BAO_NAMESPACE", "")
	t.Setenv("BAO_CACERT", "")
	t.Setenv("VAULT_CACERT", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	t.Setenv("SECRET_DB_PASS", "kv://password@kv/myapp/db")

	code := run([]string{"run", "--", "env"})
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	if loginCalled {
		t.Error("AppRole login endpoint must not be called when BAO_TOKEN is set")
	}
}

func TestRun_CustomAuthPath(t *testing.T) {
	tests := []struct {
		name          string
		authMethod    string
		baoAuthPath   string
		vaultAuthPath string
		cliAuthPath   string
		wantPath      string
	}{
		{
			name:          "BAO_AUTH_PATH wins for JWT",
			authMethod:    "jwt",
			baoAuthPath:   "auth/gitlab",
			vaultAuthPath: "wrong-mount",
			wantPath:      "/v1/auth/gitlab/login",
		},
		{
			name:          "JWT from VAULT_AUTH_PATH fallback",
			authMethod:    "jwt",
			vaultAuthPath: "jwt_v2",
			wantPath:      "/v1/auth/jwt_v2/login",
		},
		{
			name:          "CLI overrides environment for AppRole",
			authMethod:    "approle",
			baoAuthPath:   "wrong-mount",
			vaultAuthPath: "also-wrong",
			cliAuthPath:   "auth/ci-approle",
			wantPath:      "/v1/auth/ci-approle/login",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loginCalls := 0
			revokeCalls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case tt.wantPath:
					loginCalls++
					if r.Method != http.MethodPost {
						t.Errorf("expected login method POST, got %s", r.Method)
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"auth":{"client_token":"custom-auth-token"}}`))
				case "/v1/auth/token/revoke-self":
					revokeCalls++
					w.WriteHeader(http.StatusNoContent)
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()

			t.Setenv("BAO_ADDR", srv.URL)
			t.Setenv("VAULT_ADDR", "")
			t.Setenv("BAO_TOKEN", "")
			t.Setenv("VAULT_TOKEN", "")
			t.Setenv("BAO_AUTH_PATH", tt.baoAuthPath)
			t.Setenv("VAULT_AUTH_PATH", tt.vaultAuthPath)
			t.Setenv("BAO_JWT_ROLE", "")
			t.Setenv("VAULT_JWT_ROLE", "")
			t.Setenv("BAO_JWT_TOKEN", "")
			t.Setenv("VAULT_JWT_TOKEN", "")
			t.Setenv("BAO_APP_ID", "")
			t.Setenv("VAULT_APP_ID", "")
			t.Setenv("BAO_APP_SECRET", "")
			t.Setenv("VAULT_APP_SECRET", "")
			t.Setenv("BAO_NAMESPACE", "")
			t.Setenv("VAULT_NAMESPACE", "")
			t.Setenv("BAO_CACERT", "")
			t.Setenv("VAULT_CACERT", "")
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
			t.Setenv(successfulRunChildHelperEnv, "1")

			switch tt.authMethod {
			case "jwt":
				t.Setenv("BAO_JWT_ROLE", "test-role")
				t.Setenv("BAO_JWT_TOKEN", "test-jwt")
			case "approle":
				t.Setenv("BAO_APP_ID", "test-role-id")
				t.Setenv("BAO_APP_SECRET", "test-secret-id")
			default:
				t.Fatalf("unknown test auth method %q", tt.authMethod)
			}

			args := []string{"run", "--secret-prefix", "AUTH_PATH_TEST_SECRET_"}
			if tt.cliAuthPath != "" {
				args = append(args, "--auth-path", tt.cliAuthPath)
			}
			args = append(args, "--", os.Args[0], "-test.run=^TestSuccessfulRunChildHelper$")

			if code := run(args); code != 0 {
				t.Fatalf("expected exit code 0, got %d", code)
			}
			if loginCalls != 1 {
				t.Errorf("expected one login request, got %d", loginCalls)
			}
			if revokeCalls != 1 {
				t.Errorf("expected one token revocation request, got %d", revokeCalls)
			}
		})
	}
}

func TestRun_AuthPathMissingArg(t *testing.T) {
	if code := run([]string{"run", "--auth-path", "--", "true"}); code == 0 {
		t.Error("expected non-zero exit code when --auth-path has no argument")
	}
}

func TestRun_AuthPathEmpty(t *testing.T) {
	if code := run([]string{"run", "--auth-path", "", "--", "true"}); code == 0 {
		t.Error("expected non-zero exit code when --auth-path is empty")
	}
}

func TestRun_CustomSecretPrefix(t *testing.T) {
	// Verify that --secret-prefix changes which env vars are treated as secrets.
	secretRead := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/kv/data/myapp/db":
			secretRead = true
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"data": map[string]string{"password": "s3cret"},
				},
			})
		case "/v1/auth/token/revoke-self":
			// ignore cleanup
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	t.Setenv("BAO_ADDR", srv.URL)
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("BAO_TOKEN", "direct-token")
	t.Setenv("VAULT_TOKEN", "")
	t.Setenv("BAO_JWT_ROLE", "")
	t.Setenv("BAO_JWT_TOKEN", "")
	t.Setenv("BAO_APP_ID", "")
	t.Setenv("BAO_APP_SECRET", "")
	t.Setenv("BAO_NAMESPACE", "")
	t.Setenv("BAO_CACERT", "")
	t.Setenv("VAULT_CACERT", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	// Use a custom prefix MYSECRET_ instead of the default SECRET_
	t.Setenv("MYSECRET_DB_PASS", "kv://password@kv/myapp/db")
	t.Setenv("SECRET_DB_PASS", "") // ensure the default prefix is not matched

	code := run([]string{"run", "--secret-prefix", "MYSECRET_", "--", "env"})
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	if !secretRead {
		t.Error("custom-prefix secret was not retrieved")
	}
}

func TestRun_SecretPrefixMissingArg(t *testing.T) {
	t.Setenv("BAO_ADDR", "https://vault.example.com")

	// --secret-prefix with no following value before --: the flag parser
	// consumes "--" as the prefix value, leaving no separator, so run returns an error.
	code := run([]string{"run", "--secret-prefix", "--", "env"})
	if code == 0 {
		t.Error("expected non-zero exit code when --secret-prefix has no argument before --")
	}
}

func TestRun_SecretPrefixFromEnv(t *testing.T) {
	// BAO_SECRET_PREFIX should be used when no --secret-prefix CLI flag is given.
	secretRead := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/kv/data/myapp/db":
			secretRead = true
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"data": map[string]string{"password": "s3cret"},
				},
			})
		case "/v1/auth/token/revoke-self":
			// ignore cleanup
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	t.Setenv("BAO_ADDR", srv.URL)
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("BAO_TOKEN", "direct-token")
	t.Setenv("VAULT_TOKEN", "")
	t.Setenv("BAO_JWT_ROLE", "")
	t.Setenv("BAO_JWT_TOKEN", "")
	t.Setenv("BAO_APP_ID", "")
	t.Setenv("BAO_APP_SECRET", "")
	t.Setenv("BAO_NAMESPACE", "")
	t.Setenv("BAO_CACERT", "")
	t.Setenv("VAULT_CACERT", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	t.Setenv("BAO_SECRET_PREFIX", "ENVSECRET_")
	t.Setenv("ENVSECRET_DB_PASS", "kv://password@kv/myapp/db")
	t.Setenv("SECRET_DB_PASS", "") // default prefix must not match

	code := run([]string{"run", "--", "env"})
	if code != 0 {
		t.Errorf("expected exit code 0 when prefix is set via BAO_SECRET_PREFIX, got %d", code)
	}
	if !secretRead {
		t.Error("environment-prefix secret was not retrieved")
	}
}

func TestRun_SecretPrefixCLIOverridesEnv(t *testing.T) {
	// --secret-prefix CLI flag must take priority over BAO_SECRET_PREFIX.
	secretRead := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/kv/data/myapp/db":
			secretRead = true
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"data": map[string]string{"password": "s3cret"},
				},
			})
		case "/v1/auth/token/revoke-self":
			// ignore cleanup
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	t.Setenv("BAO_ADDR", srv.URL)
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("BAO_TOKEN", "direct-token")
	t.Setenv("VAULT_TOKEN", "")
	t.Setenv("BAO_JWT_ROLE", "")
	t.Setenv("BAO_JWT_TOKEN", "")
	t.Setenv("BAO_APP_ID", "")
	t.Setenv("BAO_APP_SECRET", "")
	t.Setenv("BAO_NAMESPACE", "")
	t.Setenv("BAO_CACERT", "")
	t.Setenv("VAULT_CACERT", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	// BAO_SECRET_PREFIX says "WRONG_"; CLI flag says "CLISECRET_" — CLI wins
	t.Setenv("BAO_SECRET_PREFIX", "WRONG_")
	t.Setenv("CLISECRET_DB_PASS", "kv://password@kv/myapp/db")
	t.Setenv("WRONG_DB_PASS", "")
	t.Setenv("SECRET_DB_PASS", "")

	code := run([]string{"run", "--secret-prefix", "CLISECRET_", "--", "env"})
	if code != 0 {
		t.Errorf("expected exit code 0 when CLI --secret-prefix overrides BAO_SECRET_PREFIX, got %d", code)
	}
	if !secretRead {
		t.Error("CLI-prefix secret was not retrieved")
	}
}

// generateSelfSignedCert creates a minimal self-signed CA certificate and
// returns it as a PEM-encoded byte slice.
func generateSelfSignedCert(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ca"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
