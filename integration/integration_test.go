//go:build integration

package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/philhartung/bao-wrapper/integration/testdata/probe"
)

func TestIntegration(t *testing.T) {
	s := newSuite(t)
	t.Run("engines-and-masking", func(t *testing.T) {
		c := s.scenario(t)
		for key, value := range map[string]string{
			"SECRET_DB_PASSWORD":  "kv://password@kv/integration/app",
			"SECRET_EXTENDED":     "kv://password_extended@kv/integration/app",
			"SECRET_RETRIES":      "kv://retries@kv/integration/app",
			"SECRET_ALL":          "kv://kv/integration/app",
			"SECRET_LEGACY_TOKEN": "legacy://token@kvv1/integration/legacy",
			"SECRET_APP_CONFIG":   "template://tpl@kv/integration/template",
		} {
			c.env[key] = value
		}
		all, err := json.Marshal(map[string]any{"password": password, "password_extended": extended, "certificate": certificate, "retries": 7, "enabled": true})
		if err != nil {
			t.Fatal(err)
		}
		c.spec = probe.Spec{
			Env:    map[string]string{"DB_PASSWORD": password, "EXTENDED": extended, "RETRIES": "7", "ALL": string(all), "LEGACY_TOKEN": legacy, "APP_CONFIG": rendered},
			Stdout: "stdout-password=${DB_PASSWORD}\n${APP_CONFIG}",
			Stderr: "stderr-overlap=${EXTENDED}\n${APP_CONFIG}",
		}
		c.finish(c.start(nil), 0)
		assertContains(t, c.stdout.String(), "stdout-password=[MASKED]")
		assertContains(t, c.stderr.String(), "stderr-overlap=[MASKED]")
		for _, output := range []string{c.stdout.String(), c.stderr.String()} {
			assertContains(t, output, "database_password=[MASKED]\nlegacy_token=[MASKED]\nmode=production\n")
		}
	})
	t.Run("file-delivery-and-vault-fallbacks", func(t *testing.T) {
		c := s.scenario(t)
		for _, key := range []string{"BAO_ADDR", "BAO_AUTH_PATH", "BAO_APP_ID", "BAO_APP_SECRET"} {
			delete(c.env, key)
		}
		for key, value := range map[string]string{
			"VAULT_ADDR": s.addr, "VAULT_AUTH_PATH": "auth/ci-approle", "VAULT_APP_ID": roleID, "VAULT_APP_SECRET": secretID,
			"SECRET_CERT_FILE":  "kv://certificate:file@kv/integration/app",
			"SECRET_APP_CONFIG": "template://tpl:file@kv/integration/template",
		} {
			c.env[key] = value
		}
		c.spec.Files = map[string]string{"CERT_FILE": certificate, "APP_CONFIG": rendered}
		c.spec.Absent = []string{"VAULT_ADDR", "VAULT_AUTH_PATH", "VAULT_APP_ID", "VAULT_APP_SECRET"}
		c.finish(c.start(nil), 0)
		report := c.reportData()
		if len(report.Files) != 2 {
			t.Fatal("child did not verify both secret files")
		}
		for _, path := range report.Files {
			assertAbsent(t, path)
		}
	})
	t.Run("prefix-and-sanitization", func(t *testing.T) {
		c := s.scenario(t)
		for key, value := range map[string]string{
			"BAO_AUTH_PATH": "ignored-mount", "BAO_SECRET_PREFIX": "IGNORED_",
			"BAO_UNUSED_FIXTURE": "sensitive-bao-value", "VAULT_UNUSED_FIXTURE": "sensitive-vault-value",
			"ACTIONS_ID_TOKEN_REQUEST_URL": "https://oidc.invalid/token", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "sensitive-oidc-value",
			"WRAP_DB_PASSWORD": "kv://password@kv/integration/app", "WRAP_SCANNING_URL": "https://scanner.invalid",
			"SAFE_PASSTHROUGH": "visible",
		} {
			c.env[key] = value
		}
		c.spec = probe.Spec{
			Env:    map[string]string{"DB_PASSWORD": password, "SAFE_PASSTHROUGH": "visible"},
			Absent: []string{"SCANNING_URL", "BAO_ADDR", "BAO_AUTH_PATH", "BAO_APP_ID", "BAO_APP_SECRET", "BAO_SECRET_PREFIX", "BAO_UNUSED_FIXTURE", "VAULT_UNUSED_FIXTURE", "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "WRAP_DB_PASSWORD", "WRAP_SCANNING_URL"},
			Stdout: "custom-prefix=${DB_PASSWORD}\n",
		}
		c.finish(c.start([]string{"--auth-path", "auth/ci-approle", "--secret-prefix", "WRAP_"}), 0)
		assertContains(t, c.stdout.String(), "custom-prefix=[MASKED]")
	})
	t.Run("child-failure", func(t *testing.T) {
		c := s.scenario(t)
		token := s.token(t)
		c.env["BAO_TOKEN"] = token
		c.env["SECRET_CERT_FILE"] = "kv://certificate:file@kv/integration/app"
		c.spec = probe.Spec{Files: map[string]string{"CERT_FILE": certificate}, Stdout: "${CERT_FILE}", Stderr: "${CERT_FILE}", ExitCode: 23}
		c.finish(c.start(nil), 23)
		assertContains(t, c.stdout.String(), "[MASKED]")
		assertContains(t, c.stderr.String(), "[MASKED]")
		report := c.reportData()
		if len(report.Files) != 1 {
			t.Fatal("child did not verify the secret file")
		}
		for _, path := range report.Files {
			assertAbsent(t, path)
		}
		s.assertToken(t, token, http.StatusOK)
	})
	for _, tc := range []struct{ name, ref, status string }{
		{"fetch-failure", "kv://value@kv/integration/missing", "404"},
		{"permission-denied", "kv://value@kv/forbidden/secret", "403"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := s.scenario(t)
			token := s.token(t)
			c.env["BAO_TOKEN"] = token
			c.env["SECRET_NOT_FOUND"] = tc.ref
			c.finish(c.start(nil), 1)
			assertAbsent(t, c.report)
			assertContains(t, c.stderr.String(), "error: fetch secret NOT_FOUND:")
			assertContains(t, c.stderr.String(), "returned status "+tc.status)
			s.assertToken(t, token, http.StatusOK)
		})
	}
	t.Run("invalid-approle", func(t *testing.T) {
		c := s.scenario(t)
		c.env["BAO_APP_SECRET"] = "invalid-integration-secret-id"
		c.finish(c.start(nil), 1)
		assertAbsent(t, c.report)
		assertContains(t, c.stderr.String(), "error: vault approle login failed:")
	})
	t.Run("child-start-failure", func(t *testing.T) {
		c := s.scenario(t)
		token := s.token(t)
		c.env["BAO_TOKEN"] = token
		c.env["SECRET_CERT_FILE"] = "kv://certificate:file@kv/integration/app"
		c.finish(c.start(nil, filepath.Join(c.dir, "does-not-exist")), 1)
		assertAbsent(t, c.report)
		assertContains(t, c.stderr.String(), "runner: start process:")
		s.assertToken(t, token, http.StatusOK)
	})
	// OpenBao answers revoke-self with 403 once a token is no longer valid, as
	// happens when a job outlives its token's TTL.
	t.Run("already-invalid-token-at-cleanup", func(t *testing.T) {
		c := s.scenario(t)
		token := s.token(t)
		if status, _, err := s.request(http.MethodPost, "/v1/auth/token/revoke-self", token, nil); err != nil || status != http.StatusNoContent {
			t.Fatalf("revoke fixture token: status=%d error=%v", status, err)
		}
		s.assertToken(t, token, http.StatusForbidden)
		c.env["BAO_TOKEN"] = token
		c.finish(c.start([]string{"--revoke-token=always"}), 0)
		_ = c.reportData()
		assertContains(t, c.stderr.String(), "warning: token revocation was rejected (HTTP 403)")
	})
	t.Run("arguments-stdin-and-borrowed-token", func(t *testing.T) {
		c := s.scenario(t)
		token := s.token(t)
		c.env["BAO_TOKEN"] = token
		c.spec.Args = []string{"", "two words", "Ünicode 日本語", `quotes"and\slashes\`, "--flag=value", "$literal"}
		c.spec.Input = "first line\nsecond line\r\nUnicode ü\x00end"
		c.spec.Absent = []string{"BAO_TOKEN"}
		c.finish(c.start(nil), 0)
		_ = c.reportData()
		s.assertToken(t, token, http.StatusOK)
	})
	for _, source := range []string{"BAO_TOKEN", "VAULT_TOKEN"} {
		for _, policy := range []string{"auto", "always", "never"} {
			t.Run(source+"-"+policy, func(t *testing.T) {
				c := s.scenario(t)
				token := s.token(t)
				c.env[source] = token
				c.env["BAO_REVOKE_TOKEN"] = policy
				c.spec.Absent = []string{source, "BAO_REVOKE_TOKEN"}
				c.finish(c.start(nil), 0)
				want := http.StatusOK
				if policy == "always" {
					want = http.StatusForbidden
				}
				s.assertToken(t, token, want)
			})
		}
	}
	t.Run("namespaces", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			env  map[string]string
		}{
			{"bao-namespace", map[string]string{"BAO_NAMESPACE": namespace}},
			{"vault-namespace-fallback", map[string]string{"VAULT_NAMESPACE": namespace}},
			{"bao-namespace-precedence", map[string]string{"BAO_NAMESPACE": namespace, "VAULT_NAMESPACE": "nonexistent-namespace"}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				c := s.scenario(t)
				for key, value := range tc.env {
					c.env[key] = value
				}
				c.env["BAO_APP_ID"] = namespaceRoleID
				c.env["BAO_APP_SECRET"] = namespaceSecretID
				// Keep the root fixture's path: only the namespace selects this value.
				c.env["SECRET_DB_PASSWORD"] = "kv://password@kv/integration/app"
				c.spec = probe.Spec{
					Env:    map[string]string{"DB_PASSWORD": namespacePassword},
					Absent: []string{"BAO_NAMESPACE", "VAULT_NAMESPACE", "BAO_APP_ID", "BAO_APP_SECRET"},
					Stdout: "namespace-password=${DB_PASSWORD}\n",
					Stderr: "namespace-password=${DB_PASSWORD}\n",
				}
				c.finish(c.start(nil), 0)
				_ = c.reportData()
				assertContains(t, c.stdout.String(), "namespace-password=[MASKED]")
				assertContains(t, c.stderr.String(), "namespace-password=[MASKED]")
			})
		}
	})
	t.Run("jwt-login", func(t *testing.T) {
		jwtScenario := func(t *testing.T) *scenario {
			c := s.scenario(t)
			for _, key := range []string{"BAO_AUTH_PATH", "BAO_APP_ID", "BAO_APP_SECRET"} {
				delete(c.env, key)
			}
			c.env["SECRET_DB_PASSWORD"] = "kv://password@kv/integration/app"
			return c
		}
		for _, tc := range []struct {
			name    string
			env     map[string]string
			options []string
		}{
			{"mount-name", map[string]string{"BAO_AUTH_PATH": "ci-jwt", "BAO_JWT_ROLE": "bao-wrapper-integration", "BAO_JWT_TOKEN": s.jwt(t, nil, nil)}, nil},
			{"auth-relative-option", map[string]string{"BAO_JWT_ROLE": "bao-wrapper-integration", "BAO_JWT_TOKEN": s.jwt(t, nil, nil)}, []string{"--auth-path", "auth/ci-jwt"}},
			{"vault-fallbacks", map[string]string{"VAULT_AUTH_PATH": "ci-jwt", "VAULT_JWT_ROLE": "bao-wrapper-integration", "VAULT_JWT_TOKEN": s.jwt(t, nil, nil)}, nil},
		} {
			t.Run(tc.name, func(t *testing.T) {
				c := jwtScenario(t)
				for key, value := range tc.env {
					c.env[key] = value
				}
				c.spec = probe.Spec{
					Env:    map[string]string{"DB_PASSWORD": password},
					Absent: []string{"BAO_JWT_ROLE", "BAO_JWT_TOKEN", "BAO_AUTH_PATH", "VAULT_JWT_ROLE", "VAULT_JWT_TOKEN", "VAULT_AUTH_PATH"},
					Stdout: "jwt-password=${DB_PASSWORD}\n",
				}
				c.finish(c.start(tc.options), 0)
				_ = c.reportData()
				assertContains(t, c.stdout.String(), "jwt-password=[MASKED]")
			})
		}

		otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			name, role, token string
		}{
			{"unknown-role", "missing-role", s.jwt(t, nil, nil)},
			{"expired-token", "bao-wrapper-integration", s.jwt(t, nil, map[string]any{"exp": time.Now().Add(-time.Hour).Unix()})},
			{"wrong-audience", "bao-wrapper-integration", s.jwt(t, nil, map[string]any{"aud": "https://another-service.test"})},
			{"wrong-bound-claim", "bao-wrapper-integration", s.jwt(t, nil, map[string]any{"project_path": "someone/else"})},
			{"untrusted-signing-key", "bao-wrapper-integration", s.jwt(t, otherKey, nil)},
		} {
			t.Run(tc.name, func(t *testing.T) {
				c := jwtScenario(t)
				c.env["BAO_AUTH_PATH"] = "ci-jwt"
				c.env["BAO_JWT_ROLE"] = tc.role
				c.env["BAO_JWT_TOKEN"] = tc.token
				c.finish(c.start(nil), 1)
				assertAbsent(t, c.report)
				assertContains(t, c.stderr.String(), "error: vault login failed: api: POST returned status")
			})
		}
	})
	t.Run("tls", func(t *testing.T) {
		tlsScenario := func(t *testing.T) *scenario {
			c := s.scenario(t)
			c.env["BAO_ADDR"] = s.tlsAddr
			c.env["SECRET_DB_PASSWORD"] = "kv://password@kv/integration/app"
			return c
		}
		for _, variable := range []string{"BAO_CACERT", "VAULT_CACERT"} {
			t.Run(variable, func(t *testing.T) {
				c := tlsScenario(t)
				c.env[variable] = s.caFile
				c.spec = probe.Spec{
					Env:    map[string]string{"DB_PASSWORD": password},
					Absent: []string{variable, "BAO_ADDR"},
					Stdout: "tls-password=${DB_PASSWORD}\n",
				}
				c.finish(c.start(nil), 0)
				_ = c.reportData()
				assertContains(t, c.stdout.String(), "tls-password=[MASKED]")
			})
		}
		t.Run("untrusted-certificate", func(t *testing.T) {
			c := tlsScenario(t)
			c.finish(c.start(nil), 1)
			assertAbsent(t, c.report)
			assertContains(t, c.stderr.String(), "error: vault approle login failed: api: POST request failed")
		})
		t.Run("unrelated-ca", func(t *testing.T) {
			c := tlsScenario(t)
			unrelated, _ := newServerCertificate(t, c.dir)
			c.env["BAO_CACERT"] = unrelated
			c.finish(c.start(nil), 1)
			assertAbsent(t, c.report)
			assertContains(t, c.stderr.String(), "error: vault approle login failed: api: POST request failed")
		})
	})
	// A login-issued token that expires while the child runs is rejected by a
	// real server at cleanup; the child's success must stand.
	t.Run("token-expires-during-child", func(t *testing.T) {
		c := s.scenario(t)
		c.env["BAO_APP_ID"] = shortTTLRoleID
		c.env["BAO_APP_SECRET"] = shortTTLSecretID
		c.env["SECRET_DB_PASSWORD"] = "kv://password@kv/integration/app"
		c.spec = probe.Spec{Env: map[string]string{"DB_PASSWORD": password}, DelayMillis: 2500}
		c.finish(c.start(nil), 0)
		_ = c.reportData()
		assertContains(t, c.stderr.String(), "warning: token revocation was rejected (HTTP 403)")
	})
	runSignalTests(t, s)
}
