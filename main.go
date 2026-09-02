package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/philhartung/bao-wrapper/api"
	"github.com/philhartung/bao-wrapper/parser"
	"github.com/philhartung/bao-wrapper/runner"
	tmpl "github.com/philhartung/bao-wrapper/template"
)

// version and commit are set at build time via -ldflags:
//
//	go build -ldflags "-X main.version=$(git describe --tags --always) \
//	                   -X main.commit=$(git rev-parse HEAD)" .
var version = "dev"
var commit = "none"

const (
	githubOIDCHTTPTimeout      = 10 * time.Second
	githubOIDCMaxResponseBytes = 64 << 10
)

type onceRevoker struct {
	once   sync.Once
	revoke func() error
	err    error
}

func (revoker *onceRevoker) RevokeToken() error {
	revoker.once.Do(func() { revoker.err = revoker.revoke() })
	return revoker.err
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		printUsage()
		return 0
	}

	if args[0] == "version" || args[0] == "-v" || args[0] == "--version" {
		fmt.Printf("bao-wrapper %s (commit: %s)\n", version, commit)
		return 0
	}

	if args[0] != "run" {
		fmt.Fprintln(os.Stderr, "error: unknown command", args[0])
		printUsage()
		return 1
	}

	// Find "--" separator.
	cmdStart := -1
	for i, a := range args {
		if a == "--" {
			cmdStart = i + 1
			break
		}
	}
	if cmdStart < 0 || cmdStart >= len(args) {
		fmt.Fprintln(os.Stderr, "error: missing -- <command>")
		printUsage()
		return 1
	}
	cmdArgs := args[cmdStart:]

	// Parse options between "run" and "--". CLI flags take priority over their
	// corresponding environment variables.
	secretPrefix := "SECRET_"
	if envPrefix := os.Getenv("BAO_SECRET_PREFIX"); envPrefix != "" {
		secretPrefix = envPrefix
	}
	authPath := getEnvWithFallback("BAO_AUTH_PATH", "VAULT_AUTH_PATH")
	runOpts := args[1 : cmdStart-1]
	for i := 0; i < len(runOpts); i++ {
		switch runOpts[i] {
		case "--auth-path":
			if i+1 >= len(runOpts) {
				fmt.Fprintln(os.Stderr, "error: --auth-path requires a value")
				printUsage()
				return 1
			}
			authPath = runOpts[i+1]
			if authPath == "" {
				fmt.Fprintln(os.Stderr, "error: auth path (--auth-path) must not be empty")
				return 1
			}
			i++
		case "--secret-prefix":
			if i+1 >= len(runOpts) {
				fmt.Fprintln(os.Stderr, "error: --secret-prefix requires a value")
				printUsage()
				return 1
			}
			secretPrefix = runOpts[i+1]
			i++
		default:
			fmt.Fprintln(os.Stderr, "error: unknown option:", runOpts[i])
			printUsage()
			return 1
		}
	}
	if secretPrefix == "" {
		fmt.Fprintln(os.Stderr, "error: secret prefix (--secret-prefix or BAO_SECRET_PREFIX) must not be empty")
		return 1
	}

	// Set up a main context that is cancelled on SIGINT/SIGTERM so that
	// in-flight HTTP requests are aborted promptly on shutdown.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Read configuration from environment.
	vaultAddr := getEnvWithFallback("BAO_ADDR", "VAULT_ADDR")
	if vaultAddr == "" {
		fmt.Fprintln(os.Stderr, "error: BAO_ADDR (or VAULT_ADDR) is not set")
		return 1
	}
	vaultNamespace := getEnvWithFallback("BAO_NAMESPACE", "VAULT_NAMESPACE")
	vaultToken := getEnvWithFallback("BAO_TOKEN", "VAULT_TOKEN")
	vaultRole := getEnvWithFallback("BAO_JWT_ROLE", "VAULT_JWT_ROLE")
	vaultJWT := getEnvWithFallback("BAO_JWT_TOKEN", "VAULT_JWT_TOKEN")
	vaultRoleID := getEnvWithFallback("BAO_APP_ID", "VAULT_APP_ID")
	vaultSecretID := getEnvWithFallback("BAO_APP_SECRET", "VAULT_APP_SECRET")
	vaultMaxResponseBytes, err := responseSizeLimitFromEnv(
		"BAO_MAX_RESPONSE_BYTES",
		"VAULT_MAX_RESPONSE_BYTES",
		api.DefaultMaxResponseBytes,
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	// Apply custom CA certificate when configured.
	transport, err := buildTLSTransport()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	client := api.NewWithTransport(vaultAddr, vaultNamespace, transport)
	if err := client.SetMaxResponseBytes(vaultMaxResponseBytes); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	client.SetContext(ctx)

	// Authenticate using the first available method in priority order:
	//   1. BAO_TOKEN / VAULT_TOKEN  – direct token, no login required
	//   2. BAO_JWT_ROLE + JWT       – JWT/OIDC login (GitHub Actions OIDC auto-detected)
	//   3. BAO_APP_ID + BAO_APP_SECRET – AppRole login
	tokenAcquired := false
	switch {
	case vaultToken != "":
		client.SetToken(vaultToken)
		tokenAcquired = true
	case vaultRole != "":
		if vaultJWT == "" {
			jwt, err := fetchGitHubActionsOIDCToken(ctx)
			if err != nil {
				fmt.Fprintln(os.Stderr, "error: fetch GitHub Actions OIDC token:", err)
				return 1
			}
			vaultJWT = jwt
		}
		if vaultJWT != "" {
			jwtAuthPath := authPath
			if jwtAuthPath == "" {
				jwtAuthPath = "jwt"
			}
			if err := client.LoginJWTAt(jwtAuthPath, vaultRole, vaultJWT); err != nil {
				fmt.Fprintln(os.Stderr, "error: vault login failed:", err)
				return 1
			}
			tokenAcquired = true
		}
	case vaultRoleID != "" && vaultSecretID != "":
		appRoleAuthPath := authPath
		if appRoleAuthPath == "" {
			appRoleAuthPath = "approle"
		}
		if err := client.LoginAppRoleAt(appRoleAuthPath, vaultRoleID, vaultSecretID); err != nil {
			fmt.Fprintln(os.Stderr, "error: vault approle login failed:", err)
			return 1
		}
		tokenAcquired = true
	}

	// The CLI owns the authenticated token lifecycle. Register cleanup before
	// parsing or fetching secrets so failures before child startup revoke the
	// token too. RevokeToken supplies a fresh timeout context after signals.
	var tokenRevoker runner.Revoker
	if tokenAcquired {
		revoker := &onceRevoker{revoke: client.RevokeToken}
		tokenRevoker = revoker
		defer func() { _ = revoker.RevokeToken() }()
	}

	// Parse secret variables using the configured prefix.
	refs, err := parser.ParseEnv(secretPrefix)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: parse secrets:", err)
		return 1
	}

	// Fetch each secret.
	var secretValues []runner.SecretValue
	for _, ref := range refs {
		if ref.Engine == "template" {
			// Template engine: render the template and collect inner secrets.
			result, err := tmpl.Render(ref, client)
			if err != nil {
				fmt.Fprintln(os.Stderr, "error: render template", ref.EnvName+":", err)
				return 1
			}
			secretValues = append(secretValues, runner.SecretValue{Ref: ref, Value: result.Output})
			// Register inner secrets for masking (the template itself is NOT masked).
			for _, inner := range result.InnerSecrets {
				secretValues = append(secretValues, runner.SecretValue{
					Ref:   parser.SecretRef{Type: parser.TypeEnv, EnvName: ""},
					Value: inner,
				})
			}
			continue
		}
		val, err := client.ReadSecret(ref.Path, ref.Field, parser.KVVersionForEngine(ref.Engine))
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: fetch secret", ref.EnvName+":", err)
			return 1
		}
		secretValues = append(secretValues, runner.SecretValue{Ref: ref, Value: val})
	}

	// The shared idempotent revoker lets runner revoke immediately on a signal,
	// while this function's defer still covers failures before child startup.
	exitCode, err := runner.Run(cmdArgs, secretValues, tokenRevoker, secretPrefix)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
	}
	return exitCode
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `bao-wrapper - CI-agnostic process wrapper for OpenBao/Vault secrets

Usage:
  bao-wrapper version            Print version and commit hash
  bao-wrapper run [options] -- <command> [args...]

Options (bao-wrapper run):
  --auth-path <path>         Authentication mount, e.g. gitlab or auth/gitlab
                             (env: BAO_AUTH_PATH; fallback: VAULT_AUTH_PATH)
  --secret-prefix <prefix>   Prefix used to identify secret variables (default: SECRET_; env: BAO_SECRET_PREFIX)

Environment variables:
  BAO_ADDR           OpenBao/Vault server address (required; fallback: VAULT_ADDR)
  BAO_NAMESPACE      Vault namespace (optional; fallback: VAULT_NAMESPACE)
  BAO_TOKEN          Direct client token (optional; takes priority over all login methods; fallback: VAULT_TOKEN)
  BAO_AUTH_PATH      JWT or AppRole auth mount (optional; fallback: VAULT_AUTH_PATH;
                     defaults to jwt for JWT and approle for AppRole; overridden by --auth-path)
  BAO_JWT_ROLE       JWT auth role (optional; used when BAO_TOKEN is not set; fallback: VAULT_JWT_ROLE)
  BAO_JWT_TOKEN      JWT token for authentication (optional; fallback: VAULT_JWT_TOKEN;
                     auto-detected from GitHub Actions OIDC when unset)
  BAO_APP_ID         AppRole role ID (optional; used when BAO_TOKEN and BAO_JWT_ROLE are not set; fallback: VAULT_APP_ID)
  BAO_APP_SECRET     AppRole secret ID (optional; used together with BAO_APP_ID; fallback: VAULT_APP_SECRET)
  BAO_CACERT         Path to a PEM-encoded CA certificate file (optional; fallback: VAULT_CACERT)
  BAO_MAX_RESPONSE_BYTES
                     Maximum Vault response body size in bytes (optional; default: 33554432;
                     fallback: VAULT_MAX_RESPONSE_BYTES)
  BAO_OIDC_MAX_RESPONSE_BYTES
                     Maximum GitHub OIDC response body size in bytes (optional; default: 65536;
                     fallback: VAULT_OIDC_MAX_RESPONSE_BYTES)
  BAO_SECRET_PREFIX  Prefix for secret variables (optional; default: SECRET_; overridden by --secret-prefix)

Secret variables (<PREFIX><NAME>=<spec>):
  Spec format:  <engine>://[[field][:type]@]path[?key=value&...]
  Engines:      kv (KV v2), legacy (KV v1), template
  Defaults:     type=env, field="" (full JSON)
  Note:         An explicit supported engine scheme is required; other values are ignored
  Path:         Full path including mount (e.g. kv/test, kvv1/my/secret)
  Examples:
    SECRET_DB_PASS=kv://password:env@kv/myapp/db
    SECRET_KEY=kv://kv/myapp/db
    SECRET_TLS_CERT=kv://cert:file@kv/myapp/tls
    SECRET_TOKEN=legacy://token:env@kvv1/my/path`)
}

// getEnvWithFallback returns the value of the primary environment variable, or
// the value of the fallback environment variable if the primary is empty/unset.
func getEnvWithFallback(primary, fallback string) string {
	if v := os.Getenv(primary); v != "" {
		return v
	}
	return os.Getenv(fallback)
}

// responseSizeLimitFromEnv reads a positive base-10 byte limit. MaxInt64 is
// excluded because bounded reads consume one extra byte to detect overflow.
func responseSizeLimitFromEnv(primary, fallback string, defaultLimit int64) (int64, error) {
	raw := getEnvWithFallback(primary, fallback)
	if raw == "" {
		return defaultLimit, nil
	}

	limit, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || limit <= 0 || limit == math.MaxInt64 {
		return 0, fmt.Errorf("%s (or %s) must be an integer between 1 and %d bytes", primary, fallback, int64(math.MaxInt64-1))
	}
	return limit, nil
}

// fetchGitHubActionsOIDCToken checks whether the process is running inside a
// GitHub Actions workflow that has OIDC token permissions configured. When
// both ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN are
// set, it requests a JWT from the GitHub OIDC endpoint and returns it.
// Returns an empty string (without error) when the environment variables are
// absent so that other auth methods can still be used.
func fetchGitHubActionsOIDCToken(ctx context.Context) (string, error) {
	requestURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	requestToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if requestURL == "" || requestToken == "" {
		return "", nil
	}
	maxResponseBytes, err := responseSizeLimitFromEnv(
		"BAO_OIDC_MAX_RESPONSE_BYTES",
		"VAULT_OIDC_MAX_RESPONSE_BYTES",
		githubOIDCMaxResponseBytes,
	)
	if err != nil {
		return "", err
	}
	return requestGitHubActionsOIDCTokenWithLimit(ctx, requestURL, requestToken, nil, maxResponseBytes)
}

// requestGitHubActionsOIDCToken requests a token from a validated GitHub OIDC
// endpoint. transport is nil in production and is injectable only so tests can
// trust an httptest TLS certificate without weakening endpoint validation.
func requestGitHubActionsOIDCToken(ctx context.Context, requestURL, requestToken string, transport http.RoundTripper) (string, error) {
	return requestGitHubActionsOIDCTokenWithLimit(ctx, requestURL, requestToken, transport, githubOIDCMaxResponseBytes)
}

func requestGitHubActionsOIDCTokenWithLimit(ctx context.Context, requestURL, requestToken string, transport http.RoundTripper, maxResponseBytes int64) (string, error) {
	if maxResponseBytes <= 0 || maxResponseBytes == math.MaxInt64 {
		return "", fmt.Errorf("OIDC max response bytes must be between 1 and %d", int64(math.MaxInt64-1))
	}
	if err := validateGitHubActionsOIDCURL(requestURL); err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil) // #nosec G704 -- validated as an absolute HTTPS URL; arbitrary hosts are required for GHES
	if err != nil {
		return "", fmt.Errorf("build OIDC request")
	}
	req.Header.Set("Authorization", "bearer "+requestToken)

	client := newGitHubActionsOIDCClient(transport)
	resp, err := client.Do(req) // #nosec G704 -- validated as an absolute HTTPS URL; arbitrary hosts are required for GHES
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", fmt.Errorf("OIDC request: %w", ctxErr)
		}
		return "", fmt.Errorf("OIDC request failed")
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OIDC endpoint returned HTTP %d", resp.StatusCode)
	}

	if resp.ContentLength > maxResponseBytes {
		return "", fmt.Errorf("OIDC response exceeds %d-byte limit", maxResponseBytes)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return "", fmt.Errorf("read OIDC response: %w", err)
	}
	if int64(len(body)) > maxResponseBytes {
		return "", fmt.Errorf("OIDC response exceeds %d-byte limit", maxResponseBytes)
	}

	var payload struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("parse OIDC response: %w", err)
	}
	if payload.Value == "" {
		return "", fmt.Errorf("OIDC response contained empty token value")
	}
	return payload.Value, nil
}

func newGitHubActionsOIDCClient(transport http.RoundTripper) *http.Client {
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &http.Client{
		Timeout:   githubOIDCHTTPTimeout,
		Transport: transport,
		// The bearer token must never be forwarded to another endpoint.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func validateGitHubActionsOIDCURL(rawURL string) error {
	endpoint, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("GitHub Actions OIDC request URL is invalid")
	}

	// GitHub.com uses token.actions.githubusercontent.com, while GHES uses an
	// installation-specific hostname. Requiring HTTPS and a well-formed
	// authority protects both without imposing a public-GitHub-only allowlist.
	if !strings.EqualFold(endpoint.Scheme, "https") || endpoint.Hostname() == "" || endpoint.Opaque != "" {
		return fmt.Errorf("GitHub Actions OIDC request URL must be an absolute HTTPS URL")
	}
	if endpoint.User != nil {
		return fmt.Errorf("GitHub Actions OIDC request URL must not contain user information")
	}
	if endpoint.Fragment != "" {
		return fmt.Errorf("GitHub Actions OIDC request URL must not contain a fragment")
	}
	return nil
}

// buildTLSTransport reads the CA certificate file referenced by BAO_CACERT
// (with fallback to VAULT_CACERT) and returns a custom http.RoundTripper whose
// TLS configuration trusts that certificate in addition to the system roots.
// Returns nil, nil when no CA certificate is configured.
func buildTLSTransport() (http.RoundTripper, error) {
	cacertPath := getEnvWithFallback("BAO_CACERT", "VAULT_CACERT")
	if cacertPath == "" {
		return nil, nil
	}

	pemData, err := os.ReadFile(cacertPath) // #nosec G304 -- path is operator-controlled via BAO_CACERT/VAULT_CACERT
	if err != nil {
		return nil, fmt.Errorf("read CA cert %s: %w", cacertPath, err)
	}

	certPool, err := x509.SystemCertPool()
	if err != nil {
		certPool = x509.NewCertPool()
	}
	if !certPool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("CA cert %s: no valid PEM certificates found", cacertPath)
	}

	tlsConfig := &tls.Config{RootCAs: certPool}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	return transport, nil
}
