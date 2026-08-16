package runner

import (
	"strings"
	"testing"
)

func TestFilteredEnv_RemovesSensitivePrefixes(t *testing.T) {
	cases := []struct {
		name    string
		key     string
		value   string
		wantIn  bool
	}{
		{"BAO_ prefix removed", "BAO_JWT_TOKEN", "secret-token", false},
		{"BAO_APP_SECRET removed", "BAO_APP_SECRET", "my-secret-id", false},
		{"BAO_APP_ID removed", "BAO_APP_ID", "my-role-id", false},
		{"BAO_ADDR removed", "BAO_ADDR", "https://bao.example.com", false},
		{"VAULT_ prefix removed", "VAULT_JWT_TOKEN", "vault-token", false},
		{"VAULT_ADDR removed", "VAULT_ADDR", "https://vault.example.com", false},
		{"SECRET_ prefix removed", "SECRET_DB_PASS", "kv://pass@app/db", false},
		{"ACTIONS_ID_TOKEN_REQUEST_ removed", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ghtoken", false},
		{"ACTIONS_ID_TOKEN_REQUEST_URL removed", "ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.actions.example.com", false},
		{"Regular env var kept", "HOME", "/home/runner", true},
		{"PATH kept", "PATH", "/usr/bin:/bin", true},
		{"Unrelated var with BAO in value kept", "MY_VAR", "BAO_SOMETHING", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.key, tc.value)

			env := filteredEnv("SECRET_")

			found := false
			for _, e := range env {
				if strings.HasPrefix(e, tc.key+"=") {
					found = true
					break
				}
			}

			if found != tc.wantIn {
				if tc.wantIn {
					t.Errorf("expected %q to be present in filtered env, but it was removed", tc.key)
				} else {
					t.Errorf("expected %q to be removed from filtered env, but it was present", tc.key)
				}
			}
		})
	}
}

func TestFilteredEnv_DoesNotContainSensitiveDefaults(t *testing.T) {
	// Set a variety of sensitive variables and confirm none appear in the output.
	sensitive := map[string]string{
		"BAO_JWT_TOKEN":               "tok1",
		"BAO_APP_SECRET":              "sid1",
		"VAULT_TOKEN":                 "vtok",
		"SECRET_MY_APP":               "kv://pass@path",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "ghtoken",
	}
	for k, v := range sensitive {
		t.Setenv(k, v)
	}

	env := filteredEnv("SECRET_")

	for k := range sensitive {
		for _, e := range env {
			if strings.HasPrefix(e, k+"=") {
				t.Errorf("sensitive variable %q must not appear in child environment", k)
			}
		}
	}
}
