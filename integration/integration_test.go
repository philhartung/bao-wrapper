//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

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
		s.assertToken(t, token, http.StatusForbidden)
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
			s.assertToken(t, token, http.StatusForbidden)
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
		s.assertToken(t, token, http.StatusForbidden)
	})
	t.Run("arguments-stdin-and-successful-revocation", func(t *testing.T) {
		c := s.scenario(t)
		token := s.token(t)
		c.env["BAO_TOKEN"] = token
		c.spec.Args = []string{"", "two words", "Ünicode 日本語", `quotes"and\slashes\`, "--flag=value", "$literal"}
		c.spec.Input = "first line\nsecond line\r\nUnicode ü\x00end"
		c.spec.Absent = []string{"BAO_TOKEN"}
		c.finish(c.start(nil), 0)
		_ = c.reportData()
		s.assertToken(t, token, http.StatusForbidden)
	})
	runSignalTests(t, s)
}
