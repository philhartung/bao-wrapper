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
	"math/big"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

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
	commit = "abc1234"
	defer func() { version, commit = origVersion, origCommit }()

	// Capture stdout by redirecting os.Stdout.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origStdout := os.Stdout
	os.Stdout = w

	code := run([]string{"version"})

	w.Close()
	os.Stdout = origStdout

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
	if !strings.Contains(output, "abc1234") {
		t.Errorf("expected output to contain commit %q, got %q", "abc1234", output)
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

func TestFetchGitHubActionsOIDCToken_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "bearer test-request-token" {
			t.Errorf("expected Authorization header %q, got %q", "bearer test-request-token", auth)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{"value": "my-jwt-token"}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-request-token")

	jwt, err := fetchGitHubActionsOIDCToken(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if jwt != "my-jwt-token" {
		t.Errorf("expected %q, got %q", "my-jwt-token", jwt)
	}
}

func TestFetchGitHubActionsOIDCToken_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bad-token")

	_, err := fetchGitHubActionsOIDCToken(context.Background())
	if err == nil {
		t.Fatal("expected error for HTTP 403 response")
	}
}

func TestFetchGitHubActionsOIDCToken_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("not-json")); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	defer srv.Close()

	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "token")

	_, err := fetchGitHubActionsOIDCToken(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid JSON response")
	}
}

func TestFetchGitHubActionsOIDCToken_EmptyValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{"value": ""}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "token")

	_, err := fetchGitHubActionsOIDCToken(context.Background())
	if err == nil {
		t.Fatal("expected error when OIDC response value is empty")
	}
}

func TestRunBaoToken_DirectToken(t *testing.T) {
	// A mock Vault server that serves a single KV secret and checks that the
	// client presents the token from BAO_TOKEN directly – no login endpoint
	// should be called.
	loginCalled := false
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
	t.Setenv("SECRET_DB_PASS", "password@kv/myapp/db")

	code := run([]string{"run", "--", "env"})
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	if loginCalled {
		t.Error("login endpoint must not be called when BAO_TOKEN is set")
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
	t.Setenv("SECRET_DB_PASS", "password@kv/myapp/db")

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
	t.Setenv("SECRET_DB_PASS", "password@kv/myapp/db")

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
	t.Setenv("SECRET_DB_PASS", "password@kv/myapp/db")

	code := run([]string{"run", "--", "env"})
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	if loginCalled {
		t.Error("AppRole login endpoint must not be called when BAO_TOKEN is set")
	}
}

func TestRun_CustomSecretPrefix(t *testing.T) {
	// Verify that --secret-prefix changes which env vars are treated as secrets.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
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
	t.Setenv("BAO_APP_ID", "")
	t.Setenv("BAO_APP_SECRET", "")
	t.Setenv("BAO_NAMESPACE", "")
	t.Setenv("BAO_CACERT", "")
	t.Setenv("VAULT_CACERT", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	// Use a custom prefix MYSECRET_ instead of the default SECRET_
	t.Setenv("MYSECRET_DB_PASS", "password@kv/myapp/db")
	t.Setenv("SECRET_DB_PASS", "") // ensure the default prefix is not matched

	code := run([]string{"run", "--secret-prefix", "MYSECRET_", "--", "env"})
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
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
	t.Setenv("BAO_APP_ID", "")
	t.Setenv("BAO_APP_SECRET", "")
	t.Setenv("BAO_NAMESPACE", "")
	t.Setenv("BAO_CACERT", "")
	t.Setenv("VAULT_CACERT", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	t.Setenv("BAO_SECRET_PREFIX", "ENVSECRET_")
	t.Setenv("ENVSECRET_DB_PASS", "password@kv/myapp/db")
	t.Setenv("SECRET_DB_PASS", "") // default prefix must not match

	code := run([]string{"run", "--", "env"})
	if code != 0 {
		t.Errorf("expected exit code 0 when prefix is set via BAO_SECRET_PREFIX, got %d", code)
	}
}

func TestRun_SecretPrefixCLIOverridesEnv(t *testing.T) {
	// --secret-prefix CLI flag must take priority over BAO_SECRET_PREFIX.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
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
	t.Setenv("BAO_APP_ID", "")
	t.Setenv("BAO_APP_SECRET", "")
	t.Setenv("BAO_NAMESPACE", "")
	t.Setenv("BAO_CACERT", "")
	t.Setenv("VAULT_CACERT", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	// BAO_SECRET_PREFIX says "WRONG_"; CLI flag says "CLISECRET_" — CLI wins
	t.Setenv("BAO_SECRET_PREFIX", "WRONG_")
	t.Setenv("CLISECRET_DB_PASS", "password@kv/myapp/db")
	t.Setenv("WRONG_DB_PASS", "")
	t.Setenv("SECRET_DB_PASS", "")

	code := run([]string{"run", "--secret-prefix", "CLISECRET_", "--", "env"})
	if code != 0 {
		t.Errorf("expected exit code 0 when CLI --secret-prefix overrides BAO_SECRET_PREFIX, got %d", code)
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
