package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readEnvDump parses the file written by the env helper into a map.
func readEnvDump(t *testing.T, path string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("child did not write its environment: %v", err)
	}
	env := map[string]string{}
	for _, entry := range strings.Split(string(data), "\n") {
		key, value, _ := strings.Cut(entry, "=")
		env[key] = value
	}
	return env
}

func TestRun_CommandLineErrors(t *testing.T) {
	child := helperCommand("exit")
	for _, tc := range []struct {
		name   string
		args   []string
		code   int
		stderr string
	}{
		{"no arguments prints usage", nil, 0, "Usage:"},
		{"-h prints usage", []string{"-h"}, 0, "Usage:"},
		{"--help prints usage", []string{"--help"}, 0, "Usage:"},
		{"unknown command", []string{"start"}, 1, "error: unknown command start"},
		{"missing separator", []string{"run"}, 1, "error: missing -- <command>"},
		{"separator without command", []string{"run", "--"}, 1, "error: missing -- <command>"},
		{"unknown option", runArgs([]string{"--verbose"}, child), 1, "error: unknown option: --verbose"},
		{"inline auth path is not supported", runArgs([]string{"--auth-path=gitlab"}, child), 1, "error: unknown option: --auth-path=gitlab"},
		{"revoke policy without value", runArgs([]string{"--revoke-token"}, child), 1, "error: --revoke-token requires a value"},
		{"empty secret prefix", runArgs([]string{"--secret-prefix", ""}, child), 1, "must not be empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vault := newFakeVault(t)
			wrapperEnv(t, vault.URL)
			var code int
			output := captureOutput(t, func() { code = run(tc.args) })
			if code != tc.code {
				t.Errorf("exit code = %d, want %d", code, tc.code)
			}
			if !strings.Contains(output.Stderr, tc.stderr) {
				t.Errorf("stderr = %q, want it to contain %q", output.Stderr, tc.stderr)
			}
			if len(vault.requests) != 0 {
				t.Errorf("a rejected command line must not contact the server: %v", vault.requests)
			}
		})
	}
}

func TestRun_RequiresServerAddress(t *testing.T) {
	wrapperEnv(t, "")
	marker := filepath.Join(t.TempDir(), "started")
	var code int
	output := captureOutput(t, func() { code = run(runArgs(nil, helperCommand("touch", marker))) })
	if code != 1 || !strings.Contains(output.Stderr, "BAO_ADDR (or VAULT_ADDR) is not set") {
		t.Fatalf("code=%d stderr=%q", code, output.Stderr)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("child started without a server address")
	}
}

// Every paired variable must prefer its nonempty BAO_ value and fall back to
// the VAULT_ one.
func TestRun_BaoVariablesTakePrecedenceOverVaultFallbacks(t *testing.T) {
	type observation struct {
		login recordedRequest
		read  recordedRequest
	}
	observe := func(t *testing.T, env map[string]string, loginPath string) (observation, bool) {
		t.Helper()
		vault := newFakeVault(t)
		wrapperEnv(t, vault.URL)
		other := newFakeVault(t)
		vault.respond(loginPath, http.StatusOK, `{"auth":{"client_token":"issued"}}`)
		vault.kv2("kv/app", map[string]string{"password": "precedence-secret"})
		vault.revocable()
		for key, value := range env {
			t.Setenv(key, strings.ReplaceAll(strings.ReplaceAll(value, "{primary}", vault.URL), "{other}", other.URL))
		}
		t.Setenv("PRECEDENCE_DB", "kv://password@kv/app")
		var code int
		captureOutput(t, func() { code = run(runArgs([]string{"--secret-prefix", "PRECEDENCE_"}, helperCommand("exit"))) })
		if code != 0 {
			t.Fatalf("run failed with exit code %d", code)
		}
		if len(other.requests) != 0 {
			t.Errorf("the fallback address was contacted: %v", other.requests)
		}
		var seen observation
		if logins := vault.seen(loginPath); len(logins) == 1 {
			seen.login = logins[0]
		}
		reads := vault.seen("/v1/kv/data/app")
		if len(reads) != 1 {
			return seen, false
		}
		seen.read = reads[0]
		return seen, true
	}
	field := func(t *testing.T, body, key string) string {
		t.Helper()
		var decoded map[string]string
		if err := json.Unmarshal([]byte(body), &decoded); err != nil {
			t.Fatalf("login body is not JSON: %v", err)
		}
		return decoded[key]
	}

	t.Run("address and namespace", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			env  map[string]string
			want string
		}{
			{"bao wins", map[string]string{"BAO_ADDR": "{primary}", "VAULT_ADDR": "{other}", "BAO_NAMESPACE": "bao-ns", "VAULT_NAMESPACE": "vault-ns"}, "bao-ns"},
			{"vault fallback", map[string]string{"BAO_ADDR": "", "VAULT_ADDR": "{primary}", "VAULT_NAMESPACE": "vault-ns"}, "vault-ns"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				tc.env["BAO_TOKEN"] = "direct"
				seen, ok := observe(t, tc.env, "/v1/auth/unused/login")
				if !ok || seen.read.Namespace != tc.want {
					t.Fatalf("read namespace = %q (read seen: %v), want %q", seen.read.Namespace, ok, tc.want)
				}
			})
		}
	})
	t.Run("token", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			env  map[string]string
			want string
		}{
			{"bao wins", map[string]string{"BAO_TOKEN": "bao-token", "VAULT_TOKEN": "vault-token"}, "bao-token"},
			{"vault fallback", map[string]string{"VAULT_TOKEN": "vault-token"}, "vault-token"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				seen, ok := observe(t, tc.env, "/v1/auth/unused/login")
				if !ok || seen.read.Token != tc.want {
					t.Fatalf("read token = %q, want %q", seen.read.Token, tc.want)
				}
			})
		}
	})
	t.Run("jwt role, token and auth path", func(t *testing.T) {
		for _, tc := range []struct {
			name                string
			env                 map[string]string
			path, role, jwtBody string
		}{
			{"bao wins", map[string]string{
				"BAO_JWT_ROLE": "bao-role", "VAULT_JWT_ROLE": "vault-role", "BAO_JWT_TOKEN": "bao-jwt", "VAULT_JWT_TOKEN": "vault-jwt",
				"BAO_AUTH_PATH": "bao-mount", "VAULT_AUTH_PATH": "vault-mount",
			}, "/v1/auth/bao-mount/login", "bao-role", "bao-jwt"},
			{"vault fallback", map[string]string{
				"VAULT_JWT_ROLE": "vault-role", "VAULT_JWT_TOKEN": "vault-jwt", "VAULT_AUTH_PATH": "vault-mount",
			}, "/v1/auth/vault-mount/login", "vault-role", "vault-jwt"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				seen, ok := observe(t, tc.env, tc.path)
				if !ok || seen.read.Token != "issued" {
					t.Fatalf("secret was not read with the login-issued token (token %q)", seen.read.Token)
				}
				if got := field(t, seen.login.Body, "role"); got != tc.role {
					t.Errorf("login role = %q, want %q", got, tc.role)
				}
				if got := field(t, seen.login.Body, "jwt"); got != tc.jwtBody {
					t.Errorf("login jwt = %q, want %q", got, tc.jwtBody)
				}
			})
		}
	})
	t.Run("approle credentials", func(t *testing.T) {
		for _, tc := range []struct {
			name       string
			env        map[string]string
			id, secret string
		}{
			{"bao wins", map[string]string{"BAO_APP_ID": "bao-id", "VAULT_APP_ID": "vault-id", "BAO_APP_SECRET": "bao-secret", "VAULT_APP_SECRET": "vault-secret"}, "bao-id", "bao-secret"},
			{"vault fallback", map[string]string{"VAULT_APP_ID": "vault-id", "VAULT_APP_SECRET": "vault-secret"}, "vault-id", "vault-secret"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				seen, ok := observe(t, tc.env, "/v1/auth/approle/login")
				if !ok {
					t.Fatal("secret was not read")
				}
				if got := field(t, seen.login.Body, "role_id"); got != tc.id {
					t.Errorf("role_id = %q, want %q", got, tc.id)
				}
				if got := field(t, seen.login.Body, "secret_id"); got != tc.secret {
					t.Errorf("secret_id = %q, want %q", got, tc.secret)
				}
			})
		}
	})
}

// The child must receive resolved secrets and none of the wrapper's own
// configuration, and its output must be masked on both streams.
func TestRun_ChildEnvironmentAndMaskedOutput(t *testing.T) {
	vault := newFakeVault(t)
	wrapperEnv(t, vault.URL)
	vault.login("approle", "issued-client-token")
	vault.kv2("kv/app", map[string]string{"password": "s3cr3t-database-password", "cert": "certificate-material"})
	vault.revocable()
	t.Setenv("BAO_APP_ID", "role-id")
	t.Setenv("BAO_APP_SECRET", "approle-secret-id")
	t.Setenv("VAULT_UNRELATED", "vault-ambient")
	t.Setenv("CLITEST_DB_PASS", "kv://password@kv/app")
	t.Setenv("CLITEST_CERT", "kv://cert:file@kv/app")
	t.Setenv("CLITEST_AMBIENT", "not-a-reference")
	t.Setenv("UNRELATED_SETTING", "kept")

	dump := filepath.Join(t.TempDir(), "env")
	var code int
	captureOutput(t, func() { code = run(runArgs([]string{"--secret-prefix", "CLITEST_"}, helperCommand("env", dump))) })
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	env := readEnvDump(t, dump)
	if env["DB_PASS"] != "s3cr3t-database-password" || env["UNRELATED_SETTING"] != "kept" {
		t.Errorf("child environment is missing expected values: DB_PASS=%q UNRELATED_SETTING=%q", env["DB_PASS"], env["UNRELATED_SETTING"])
	}
	for key := range env {
		upper := strings.ToUpper(key)
		for _, prefix := range []string{"BAO_", "VAULT_", "ACTIONS_ID_TOKEN_REQUEST_", "CLITEST_"} {
			if strings.HasPrefix(upper, prefix) {
				t.Errorf("child inherited %s", key)
			}
		}
	}
	certPath := env["CERT"]
	if certPath == "" || filepath.Base(certPath) != "CERT" {
		t.Fatalf("CERT = %q, want a path to a file named CERT", certPath)
	}
	if _, err := os.Stat(filepath.Dir(certPath)); !os.IsNotExist(err) {
		t.Errorf("temporary secret directory still exists after the run: %v", err)
	}
	if revocations := vault.seen("/v1/auth/token/revoke-self"); len(revocations) != 1 || revocations[0].Token != "issued-client-token" {
		t.Errorf("login-issued token was not revoked exactly once: %v", revocations)
	}

	output := captureOutput(t, func() {
		code = run(runArgs([]string{"--secret-prefix", "CLITEST_"}, helperCommand("echo",
			"out: s3cr3t-database-password and certificate-material\n", "err: s3cr3t-database-password\n")))
	})
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if output.Stdout != "out: [MASKED] and [MASKED]\n" {
		t.Errorf("stdout = %q", output.Stdout)
	}
	if output.Stderr != "err: [MASKED]\n" {
		t.Errorf("stderr = %q", output.Stderr)
	}
}

func TestRun_CustomCA(t *testing.T) {
	setup := func(t *testing.T) (*fakeVault, string) {
		vault := newFakeVaultTLS(t)
		wrapperEnv(t, vault.URL)
		vault.login("approle", "issued")
		vault.kv2("kv/app", map[string]string{"password": "tls-secret-value"})
		vault.revocable()
		t.Setenv("BAO_APP_ID", "role-id")
		t.Setenv("BAO_APP_SECRET", "secret-id")
		t.Setenv("TLSTEST_DB", "kv://password@kv/app")
		return vault, filepath.Join(t.TempDir(), "started")
	}
	for _, variable := range []string{"BAO_CACERT", "VAULT_CACERT"} {
		t.Run(variable+" trusts the server", func(t *testing.T) {
			vault, marker := setup(t)
			t.Setenv(variable, vault.caFile(t))
			var code int
			output := captureOutput(t, func() {
				code = run(runArgs([]string{"--secret-prefix", "TLSTEST_"}, helperCommand("touch", marker)))
			})
			if code != 0 {
				t.Fatalf("exit code = %d, stderr %q", code, output.Stderr)
			}
			if _, err := os.Stat(marker); err != nil {
				t.Fatal("child did not start")
			}
			if len(vault.seen("/v1/kv/data/app")) != 1 || len(vault.seen("/v1/auth/token/revoke-self")) != 1 {
				t.Errorf("unexpected requests: %v", vault.requests)
			}
		})
	}
	t.Run("untrusted server fails before the child starts", func(t *testing.T) {
		vault, marker := setup(t)
		var code int
		output := captureOutput(t, func() {
			code = run(runArgs([]string{"--secret-prefix", "TLSTEST_"}, helperCommand("touch", marker)))
		})
		if code != 1 || !strings.Contains(output.Stderr, "error: vault approle login failed") {
			t.Fatalf("code=%d stderr=%q", code, output.Stderr)
		}
		if strings.Contains(output.Stderr, vault.URL) {
			t.Errorf("error exposes the server URL: %q", output.Stderr)
		}
		if _, err := os.Stat(marker); err == nil {
			t.Fatal("child started although the server was not trusted")
		}
		if len(vault.requests) != 0 {
			t.Errorf("credentials were sent to an untrusted server: %v", vault.requests)
		}
	})
}

// With a JWT role and no explicit JWT, the wrapper requests one from the
// GitHub Actions OIDC endpoint and logs in with it.
func TestRun_GitHubActionsOIDCLogin(t *testing.T) {
	type oidcRequest struct{ authorization, query string }
	newOIDC := func(t *testing.T, status int, body string) (*httptest.Server, *[]oidcRequest) {
		var requests []oidcRequest
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests = append(requests, oidcRequest{r.Header.Get("Authorization"), r.URL.RawQuery})
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}))
		t.Cleanup(server.Close)
		githubOIDCTransport = server.Client().Transport
		t.Cleanup(func() { githubOIDCTransport = nil })
		return server, &requests
	}
	setup := func(t *testing.T) *fakeVault {
		vault := newFakeVault(t)
		wrapperEnv(t, vault.URL)
		vault.login("jwt", "issued-by-jwt")
		vault.kv2("kv/app", map[string]string{"password": "oidc-secret-value"})
		vault.revocable()
		t.Setenv("BAO_JWT_ROLE", "github-actions")
		t.Setenv("OIDCTEST_DB", "kv://password@kv/app")
		return vault
	}
	args := func(child []string) []string { return runArgs([]string{"--secret-prefix", "OIDCTEST_"}, child) }

	t.Run("requests a token and logs in", func(t *testing.T) {
		vault := setup(t)
		oidc, requests := newOIDC(t, http.StatusOK, `{"value":"jwt-from-github"}`)
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", oidc.URL+"/token?api-version=2.0")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runtime-request-token")
		dump := filepath.Join(t.TempDir(), "env")
		var code int
		output := captureOutput(t, func() { code = run(args(helperCommand("env", dump))) })
		if code != 0 {
			t.Fatalf("exit code = %d, stderr %q", code, output.Stderr)
		}
		if len(*requests) != 1 || (*requests)[0].authorization != "bearer runtime-request-token" || (*requests)[0].query != "api-version=2.0" {
			t.Fatalf("unexpected OIDC requests: %+v", *requests)
		}
		logins := vault.seen("/v1/auth/jwt/login")
		if len(logins) != 1 || !strings.Contains(logins[0].Body, `"jwt":"jwt-from-github"`) || !strings.Contains(logins[0].Body, `"role":"github-actions"`) {
			t.Fatalf("unexpected logins: %+v", logins)
		}
		env := readEnvDump(t, dump)
		if env["DB"] != "oidc-secret-value" {
			t.Errorf("DB = %q", env["DB"])
		}
		for key := range env {
			if strings.HasPrefix(key, "ACTIONS_ID_TOKEN_REQUEST_") {
				t.Errorf("child inherited %s", key)
			}
		}
		if len(vault.seen("/v1/auth/token/revoke-self")) != 1 {
			t.Error("login-issued token was not revoked")
		}
	})
	t.Run("an explicit JWT takes precedence", func(t *testing.T) {
		vault := setup(t)
		oidc, requests := newOIDC(t, http.StatusOK, `{"value":"jwt-from-github"}`)
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", oidc.URL)
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runtime-request-token")
		t.Setenv("BAO_JWT_TOKEN", "explicit-jwt")
		var code int
		captureOutput(t, func() { code = run(args(helperCommand("exit"))) })
		if code != 0 {
			t.Fatalf("exit code = %d", code)
		}
		if len(*requests) != 0 {
			t.Errorf("OIDC endpoint was contacted although a JWT was supplied: %+v", *requests)
		}
		if logins := vault.seen("/v1/auth/jwt/login"); len(logins) != 1 || !strings.Contains(logins[0].Body, `"jwt":"explicit-jwt"`) {
			t.Errorf("unexpected logins: %+v", logins)
		}
	})
	t.Run("an OIDC failure stops before login and child start", func(t *testing.T) {
		vault := setup(t)
		oidc, _ := newOIDC(t, http.StatusInternalServerError, "unavailable")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", oidc.URL)
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runtime-request-token")
		marker := filepath.Join(t.TempDir(), "started")
		var code int
		output := captureOutput(t, func() { code = run(args(helperCommand("touch", marker))) })
		if code != 1 || !strings.Contains(output.Stderr, "error: fetch GitHub Actions OIDC token: OIDC endpoint returned HTTP 500") {
			t.Fatalf("code=%d stderr=%q", code, output.Stderr)
		}
		if strings.Contains(output.Stderr, "runtime-request-token") {
			t.Error("error exposes the request token")
		}
		if len(vault.requests) != 0 {
			t.Errorf("server was contacted after the OIDC failure: %v", vault.requests)
		}
		if _, err := os.Stat(marker); err == nil {
			t.Fatal("child started after the OIDC failure")
		}
	})
}

// A reference that tries to climb out of its mount is rejected before any
// request, for declarations and for lookups inside templates.
func TestRun_RejectsTraversalInSecretPaths(t *testing.T) {
	for name, reference := range map[string]string{
		"legacy declaration": "legacy://id@../v1/auth/token/lookup-self",
		"kv declaration":     "kv://password@../data/app",
		"dot path":           "legacy://token@.",
	} {
		t.Run(name, func(t *testing.T) {
			vault := newFakeVault(t)
			wrapperEnv(t, vault.URL)
			t.Setenv("BAO_TOKEN", "direct-token")
			t.Setenv("TRAVERSAL_VALUE", reference)
			marker := filepath.Join(t.TempDir(), "started")
			var code int
			output := captureOutput(t, func() {
				code = run(runArgs([]string{"--secret-prefix", "TRAVERSAL_"}, helperCommand("touch", marker)))
			})
			if code != 1 || !strings.Contains(output.Stderr, "error: fetch secret VALUE: api: secret path must be canonical") {
				t.Fatalf("code=%d stderr=%q", code, output.Stderr)
			}
			if len(vault.requests) != 0 {
				t.Errorf("a request was sent: %v", vault.requests)
			}
			if _, err := os.Stat(marker); err == nil {
				t.Fatal("child started")
			}
		})
	}
	t.Run("template lookup", func(t *testing.T) {
		vault := newFakeVault(t)
		wrapperEnv(t, vault.URL)
		vault.kv2("kv/config", map[string]string{"tpl": `token={{ secret "legacy://id@../v1/auth/token/lookup-self" }}`})
		t.Setenv("BAO_TOKEN", "direct-token")
		t.Setenv("TRAVERSAL_CONFIG", "template://tpl@kv/config")
		var code int
		output := captureOutput(t, func() {
			code = run(runArgs([]string{"--secret-prefix", "TRAVERSAL_"}, helperCommand("exit")))
		})
		if code != 1 || !strings.Contains(output.Stderr, "secret: fetch failed") {
			t.Fatalf("code=%d stderr=%q", code, output.Stderr)
		}
		if len(vault.requests) != 1 || vault.requests[0].Path != "/v1/kv/data/config" {
			t.Errorf("only the template itself may be fetched, got %v", vault.requests)
		}
	})
}
