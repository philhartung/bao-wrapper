package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/philhartung/bao-wrapper/api"
	"github.com/philhartung/bao-wrapper/parser"
	"github.com/philhartung/bao-wrapper/runner"
	tmpl "github.com/philhartung/bao-wrapper/template"
)

// version and commit are set at build time via -ldflags:
//
//	go build -ldflags "-X main.version=$(git describe --tags --always) \
//	                   -X main.commit=$(git rev-parse --short HEAD)" .
var version = "dev"
var commit = "none"

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

	// Parse options between "run" and "--".
	// The default prefix can be overridden by BAO_SECRET_PREFIX; the CLI flag
	// --secret-prefix takes priority over the environment variable.
	secretPrefix := "SECRET_"
	if envPrefix := os.Getenv("BAO_SECRET_PREFIX"); envPrefix != "" {
		secretPrefix = envPrefix
	}
	runOpts := args[1 : cmdStart-1]
	for i := 0; i < len(runOpts); i++ {
		switch runOpts[i] {
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

	// Apply custom CA certificate when configured.
	transport, err := buildTLSTransport()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	client := api.NewWithTransport(vaultAddr, vaultNamespace, transport)
	client.SetContext(ctx)

	// Authenticate using the first available method in priority order:
	//   1. BAO_TOKEN / VAULT_TOKEN  – direct token, no login required
	//   2. BAO_JWT_ROLE + JWT       – JWT/OIDC login (GitHub Actions OIDC auto-detected)
	//   3. BAO_APP_ID + BAO_APP_SECRET – AppRole login
	switch {
	case vaultToken != "":
		client.SetToken(vaultToken)
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
			if err := client.LoginJWT(vaultRole, vaultJWT); err != nil {
				fmt.Fprintln(os.Stderr, "error: vault login failed:", err)
				return 1
			}
		}
	case vaultRoleID != "" && vaultSecretID != "":
		if err := client.LoginAppRole(vaultRoleID, vaultSecretID); err != nil {
			fmt.Fprintln(os.Stderr, "error: vault approle login failed:", err)
			return 1
		}
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

	exitCode, err := runner.Run(cmdArgs, secretValues, client, secretPrefix)
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
  --secret-prefix <prefix>   Prefix used to identify secret variables (default: SECRET_; env: BAO_SECRET_PREFIX)

Environment variables:
  BAO_ADDR           OpenBao/Vault server address (required; fallback: VAULT_ADDR)
  BAO_NAMESPACE      Vault namespace (optional; fallback: VAULT_NAMESPACE)
  BAO_TOKEN          Direct client token (optional; takes priority over all login methods; fallback: VAULT_TOKEN)
  BAO_JWT_ROLE       JWT auth role (optional; used when BAO_TOKEN is not set; fallback: VAULT_JWT_ROLE)
  BAO_JWT_TOKEN      JWT token for authentication (optional; fallback: VAULT_JWT_TOKEN;
                     auto-detected from GitHub Actions OIDC when unset)
  BAO_APP_ID         AppRole role ID (optional; used when BAO_TOKEN and BAO_JWT_ROLE are not set; fallback: VAULT_APP_ID)
  BAO_APP_SECRET     AppRole secret ID (optional; used together with BAO_APP_ID; fallback: VAULT_APP_SECRET)
  BAO_CACERT         Path to a PEM-encoded CA certificate file (optional; fallback: VAULT_CACERT)
  BAO_SECRET_PREFIX  Prefix for secret variables (optional; default: SECRET_; overridden by --secret-prefix)

Secret variables (<PREFIX><NAME>=<spec>):
  Spec format:  [[engine]://][[field][:type]@]path[?key=value&...]
  Engines:      kv (default, KV v2), legacy (KV v1), template
  Defaults:     engine=kv, type=env, field="" (full JSON)
  Path:         Full path including mount (e.g. kv/test, kvv1/my/secret)
  Examples:
    SECRET_DB_PASS=kv://password:env@kv/myapp/db
    SECRET_DB_PASS=password@kv/myapp/db
    SECRET_KEY=kv/myapp/db
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil) // #nosec G704 -- URL is operator-controlled via ACTIONS_ID_TOKEN_REQUEST_URL set by GitHub Actions infrastructure
	if err != nil {
		return "", fmt.Errorf("build OIDC request: %w", err)
	}
	req.Header.Set("Authorization", "bearer "+requestToken)

	resp, err := http.DefaultClient.Do(req) // #nosec G704 -- URL is operator-controlled via ACTIONS_ID_TOKEN_REQUEST_URL set by GitHub Actions infrastructure
	if err != nil {
		return "", fmt.Errorf("OIDC request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OIDC endpoint returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read OIDC response: %w", err)
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
