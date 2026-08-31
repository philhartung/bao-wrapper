package runner

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/philhartung/bao-wrapper/parser"
)

const successfulChildHelperEnv = "GO_WANT_BAO_WRAPPER_SUCCESSFUL_CHILD"

type failingRevoker struct {
	err error
}

func (revoker failingRevoker) RevokeToken() error {
	return revoker.err
}

func TestSuccessfulChildHelper(t *testing.T) {
	if os.Getenv(successfulChildHelperEnv) == "" {
		return
	}
}

func TestRunReturnsNonzeroWhenRevocationFailsAfterSuccessfulChild(t *testing.T) {
	t.Setenv(successfulChildHelperEnv, "1")
	revokeErr := errors.New("revocation failed")

	exitCode, err := Run(
		[]string{os.Args[0], "-test.run=^TestSuccessfulChildHelper$"},
		nil,
		failingRevoker{err: revokeErr},
		"SECRET_",
	)

	if exitCode != 1 {
		t.Fatalf("Run() exit code = %d, want 1", exitCode)
	}
	if !errors.Is(err, revokeErr) {
		t.Fatalf("Run() error = %v, want revocation error", err)
	}
}

func TestRunReturnsNonzeroWhenTempRemovalFailsAfterSuccessfulChild(t *testing.T) {
	t.Setenv(successfulChildHelperEnv, "1")
	removeErr := errors.New("temporary-file removal failed")

	exitCode, err := runWithCleanup(
		[]string{os.Args[0], "-test.run=^TestSuccessfulChildHelper$"},
		[]SecretValue{{
			Ref:   parser.SecretRef{Type: parser.TypeFile, EnvName: "TEST_SECRET_FILE"},
			Value: "temporary secret",
		}},
		nil,
		"SECRET_",
		make(chan os.Signal),
		func(path string) error {
			return errors.Join(os.RemoveAll(path), removeErr)
		},
	)

	if exitCode != 1 {
		t.Fatalf("Run() exit code = %d, want 1", exitCode)
	}
	if !errors.Is(err, removeErr) {
		t.Fatalf("Run() error = %v, want temporary-file removal error", err)
	}
}

func TestValuesForMaskingSkipsRenderedTemplate(t *testing.T) {
	secrets := []SecretValue{
		{
			Ref:   parser.SecretRef{Engine: "kv", EnvName: "PASSWORD"},
			Value: "ordinary-secret",
		},
		{
			Ref:   parser.SecretRef{Engine: "template", EnvName: "CONFIG"},
			Value: "password=inner-secret",
		},
		{
			Ref:   parser.SecretRef{EnvName: ""},
			Value: "inner-secret",
		},
	}

	got := valuesForMasking(secrets)
	want := []string{"ordinary-secret", "inner-secret"}
	if len(got) != len(want) {
		t.Fatalf("expected %d masking values, got %d: %v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("masking value %d: expected %q, got %q", i, want[i], got[i])
		}
	}
}

func TestFilteredEnv_RemovesSensitivePrefixes(t *testing.T) {
	cases := []struct {
		name   string
		key    string
		value  string
		wantIn bool
	}{
		{"BAO_ prefix removed", "BAO_JWT_TOKEN", "secret-token", false},
		{"BAO_APP_SECRET removed", "BAO_APP_SECRET", "my-secret-id", false},
		{"BAO_APP_ID removed", "BAO_APP_ID", "my-role-id", false},
		{"BAO_ADDR removed", "BAO_ADDR", "https://bao.example.com", false},
		{"VAULT_ prefix removed", "VAULT_JWT_TOKEN", "vault-token", false},
		{"VAULT_ADDR removed", "VAULT_ADDR", "https://vault.example.com", false},
		{"mixed-case VAULT_ prefix removed", "Vault_Token", "vault-token", false},
		{"lowercase BAO_ prefix removed", "bao_app_secret", "my-secret-id", false},
		{"SECRET_ prefix removed", "SECRET_DB_PASS", "kv://pass@app/db", false},
		{"mixed-case custom prefix removed", "Secret_Db_Pass", "kv://pass@app/db", false},
		{"ACTIONS_ID_TOKEN_REQUEST_ removed", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ghtoken", false},
		{"ACTIONS_ID_TOKEN_REQUEST_URL removed", "ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.actions.example.com", false},
		{"lowercase ACTIONS_ID_TOKEN_REQUEST_ removed", "actions_id_token_request_token", "ghtoken", false},
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
		"BAO_JWT_TOKEN":                  "tok1",
		"BAO_APP_SECRET":                 "sid1",
		"VAULT_TOKEN":                    "vtok",
		"SECRET_MY_APP":                  "kv://pass@path",
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
