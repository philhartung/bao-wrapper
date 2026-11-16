package parser_test

import (
	"strings"
	"testing"

	"github.com/philhartung/bao-wrapper/parser"
)

// helper: expose the internal parseEnv via a wrapper test
// Since parseEnv is unexported we test via os.Environ simulation through ParseEnv.
// For pure unit coverage of the parsing logic we use exported ParseEnv with a
// subprocess-friendly os.Setenv approach or test the public function with env.

func TestParseEnv_BasicKV2(t *testing.T) {
	t.Setenv("SECRET_DB_PASS", "kv://password:env@myapp/db")

	refs, err := parser.ParseEnv("SECRET_")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ref := findRef(refs, "DB_PASS")
	if ref == nil {
		t.Fatal("expected DB_PASS ref")
	}
	if ref.Engine != "kv" {
		t.Errorf("engine: want kv, got %s", ref.Engine)
	}
	if ref.Field != "password" {
		t.Errorf("field: want password, got %s", ref.Field)
	}
	if ref.Type != parser.TypeEnv {
		t.Errorf("type: want env, got %s", ref.Type)
	}
	if ref.Path != "myapp/db" {
		t.Errorf("path: want myapp/db, got %s", ref.Path)
	}
}

func TestParseEnv_FileType(t *testing.T) {
	t.Setenv("SECRET_TLS_CERT", "kv://cert:file@myapp/tls")

	refs, err := parser.ParseEnv("SECRET_")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ref := findRef(refs, "TLS_CERT")
	if ref == nil {
		t.Fatal("expected TLS_CERT ref")
	}
	if ref.Type != parser.TypeFile {
		t.Errorf("expected file type, got %s", ref.Type)
	}
}

func TestParseEnv_BareValueIsIgnored(t *testing.T) {
	const ambientSecret = "hunter2"
	t.Setenv("SECRET_AMBIENT", ambientSecret)

	refs, err := parser.ParseEnv("SECRET_")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ref := findRef(refs, "AMBIENT"); ref != nil {
		t.Fatalf("ambient secret was parsed as a reference: %+v", ref)
	}
}

func TestParseEnv_EmptyField(t *testing.T) {
	t.Setenv("SECRET_ALL", "kv://:env@myapp/data")

	refs, err := parser.ParseEnv("SECRET_")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ref := findRef(refs, "ALL")
	if ref == nil {
		t.Fatal("expected ALL ref")
	}
	if ref.Field != "" {
		t.Errorf("expected empty field, got %q", ref.Field)
	}
}

func TestParseEnv_NoSecretVars(t *testing.T) {
	// Deliberately do NOT set any SECRET_* vars (rely on test isolation).
	refs, err := parser.ParseEnv("SECRET_")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Filter down to what we care about: no SECRET_ vars we injected.
	for _, r := range refs {
		_ = r // just verify no parse error
	}
}

func TestParseEnv_UnknownType(t *testing.T) {
	const configuredValue = "super-secret-token"
	t.Setenv("SECRET_BAD", "kv://field:"+configuredValue+"@path/to/secret")

	_, err := parser.ParseEnv("SECRET_")
	if err == nil {
		t.Fatal("expected error for unknown secret type")
	}
	if strings.Contains(err.Error(), configuredValue) {
		t.Fatalf("parser error exposed configured value: %q", err)
	}
}

func TestParseEnv_MalformedReferenceErrorDoesNotExposeValue(t *testing.T) {
	const configuredValue = "hunter2%zz"
	t.Setenv("SECRET_BAD", "kv://"+configuredValue)

	_, err := parser.ParseEnv("SECRET_")
	if err == nil {
		t.Fatal("expected error for malformed secret reference")
	}
	if strings.Contains(err.Error(), configuredValue) {
		t.Fatalf("parser error exposed configured value: %q", err)
	}
}

func TestParseEnv_UnknownExplicitSchemeIsIgnored(t *testing.T) {
	t.Setenv("SECRET_SCANNING_URL", "https://scanner.example.test")

	refs, err := parser.ParseEnv("SECRET_")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref := findRef(refs, "SCANNING_URL"); ref != nil {
		t.Fatalf("unsupported scheme was parsed as a reference: %+v", ref)
	}
}

func TestParseValue_TableDriven(t *testing.T) {
	tests := []struct {
		input      string
		wantEngine string
		wantField  string
		wantType   parser.SecretType
		wantPath   string
	}{
		{
			input:      "kv://password:env@myapp/db",
			wantEngine: "kv",
			wantField:  "password",
			wantType:   parser.TypeEnv,
			wantPath:   "myapp/db",
		},
		{
			input:      "legacy://token:file@my/path",
			wantEngine: "legacy",
			wantField:  "token",
			wantType:   parser.TypeFile,
			wantPath:   "my/path",
		},
		{
			input:      "kv://password@myapp/db",
			wantEngine: "kv",
			wantField:  "password",
			wantType:   parser.TypeEnv,
			wantPath:   "myapp/db",
		},
		{
			input:      "kv://token:file@my/path",
			wantEngine: "kv",
			wantField:  "token",
			wantType:   parser.TypeFile,
			wantPath:   "my/path",
		},
		{
			input:      "kv://myapp/db",
			wantEngine: "kv",
			wantField:  "",
			wantType:   parser.TypeEnv,
			wantPath:   "myapp/db",
		},
		{
			input:      "template://tpl:file@kv/config",
			wantEngine: "template",
			wantField:  "tpl",
			wantType:   parser.TypeFile,
			wantPath:   "kv/config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			envKey := "SECRET_TEST"
			t.Setenv(envKey, tt.input)

			refs, err := parser.ParseEnv("SECRET_")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			ref := findRef(refs, "TEST")
			if ref == nil {
				t.Fatal("expected TEST ref")
			}
			if ref.Engine != tt.wantEngine {
				t.Errorf("engine: want %s, got %s", tt.wantEngine, ref.Engine)
			}
			if ref.Field != tt.wantField {
				t.Errorf("field: want %s, got %s", tt.wantField, ref.Field)
			}
			if ref.Type != tt.wantType {
				t.Errorf("type: want %s, got %s", tt.wantType, ref.Type)
			}
			if ref.Path != tt.wantPath {
				t.Errorf("path: want %q, got %q", tt.wantPath, ref.Path)
			}
		})
	}
}

func TestParseEnvRejectsQueryParameters(t *testing.T) {
	tests := []string{
		"kv://value:file@kv/config?outfile=config",
		"kv://value:file@kv/config?outfile=%2Fwritable%2Fsensitive%2Fconfig",
		"kv://value:file@kv/config?outfile=..%2Fconfig",
		"kv://value:file@kv/config?outfile=C%3A%5Cconfig",
		"kv://value:file@kv/config?outfile=%5C%5Cserver%5Cshare%5Cconfig",
		"kv://value@kv/config?foo=bar",
		"kv://value@kv/config?",
	}
	for _, value := range tests {
		t.Run(value, func(t *testing.T) {
			t.Setenv("QUERY_PARAMETER_TEST", value)
			_, err := parser.ParseEnv("QUERY_PARAMETER_")
			if err == nil || !strings.Contains(err.Error(), "query parameters are not supported") {
				t.Fatalf("ParseEnv() error = %v, want unsupported-query error", err)
			}
		})
	}
}

func TestParseTemplateSecretURL_TableDriven(t *testing.T) {
	validTests := []struct {
		input      string
		wantEngine string
		wantField  string
		wantPath   string
	}{
		{
			input:      "kv://password@database/prod",
			wantEngine: "kv",
			wantField:  "password",
			wantPath:   "database/prod",
		},
		{
			input:      "legacy://token@ci/npm",
			wantEngine: "legacy",
			wantField:  "token",
			wantPath:   "ci/npm",
		},
	}

	for _, tt := range validTests {
		t.Run("valid_"+tt.input, func(t *testing.T) {
			ref, err := parser.ParseTemplateSecretURL(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ref.Engine != tt.wantEngine {
				t.Errorf("engine: want %s, got %s", tt.wantEngine, ref.Engine)
			}
			if ref.Field != tt.wantField {
				t.Errorf("field: want %s, got %s", tt.wantField, ref.Field)
			}
			if ref.Path != tt.wantPath {
				t.Errorf("path: want %q, got %q", tt.wantPath, ref.Path)
			}
		})
	}

	errorTests := []struct {
		input   string
		wantErr string
	}{
		{
			input:   "kv://password:file@database/prod",
			wantErr: "not allowed in templates",
		},
		{
			input:   "kv://password@database/prod?outfile=x",
			wantErr: "not allowed in templates",
		},
		{
			input:   "aws://key@my/path",
			wantErr: "unknown engine",
		},
	}

	for _, tt := range errorTests {
		t.Run("error_"+tt.input, func(t *testing.T) {
			_, err := parser.ParseTemplateSecretURL(tt.input)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q should contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func findRef(refs []parser.SecretRef, name string) *parser.SecretRef {
	for i := range refs {
		if refs[i].EnvName == name {
			return &refs[i]
		}
	}
	return nil
}

func TestKVVersionForEngine(t *testing.T) {
	tests := []struct {
		engine  string
		wantVer int
	}{
		{"kv", 2},
		{"template", 2},
		{"legacy", 1},
	}
	for _, tt := range tests {
		t.Run(tt.engine, func(t *testing.T) {
			got := parser.KVVersionForEngine(tt.engine)
			if got != tt.wantVer {
				t.Errorf("KVVersionForEngine(%q): want %d, got %d", tt.engine, tt.wantVer, got)
			}
		})
	}
}

func TestParseValue_AdditionalForms(t *testing.T) {
	for _, tc := range []struct {
		name, input         string
		engine, field, path string
		secretType          parser.SecretType
	}{
		{"file type without field", "kv://:file@kv/app", "kv", "", "kv/app", parser.TypeFile},
		{"empty type keeps default", "kv://password:@kv/app", "kv", "password", "kv/app", parser.TypeEnv},
		{"percent-encoded field", "kv://db%2Fpass%40word%3Ax@kv/app", "kv", "db/pass@word:x", "kv/app", parser.TypeEnv},
		{"percent-encoded path", "kv://password@kv/my%20app/db", "kv", "password", "kv/my app/db", parser.TypeEnv},
		{"unicode path", "kv://password@kv/ünïcode/日本語", "kv", "password", "kv/ünïcode/日本語", parser.TypeEnv},
		{"percent-encoded unicode field", "kv://p%C3%A4sswort@kv/app", "kv", "pässwort", "kv/app", parser.TypeEnv},
		{"mount only", "legacy://token@kvv1", "legacy", "token", "kvv1", parser.TypeEnv},
		{"deep path", "kv://kv/a/b/c/d", "kv", "", "kv/a/b/c/d", parser.TypeEnv},
		{"mixed-case mount is preserved", "kv://Password@KV/MyApp", "kv", "Password", "KV/MyApp", parser.TypeEnv},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SECRET_TEST", tc.input)
			refs, err := parser.ParseEnv("SECRET_")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			ref := findRef(refs, "TEST")
			if ref == nil {
				t.Fatal("expected TEST ref")
			}
			if ref.Engine != tc.engine || ref.Field != tc.field || ref.Path != tc.path || ref.Type != tc.secretType {
				t.Errorf("got engine=%q field=%q path=%q type=%q, want engine=%q field=%q path=%q type=%q",
					ref.Engine, ref.Field, ref.Path, ref.Type, tc.engine, tc.field, tc.path, tc.secretType)
			}
		})
	}
}

// Only an exact, lower-case supported scheme marks a value as a reference.
// Everything else is treated as an ambient value and skipped without error.
func TestParseEnv_NonReferencesAreSkipped(t *testing.T) {
	for _, value := range []string{
		"KV://password@kv/app", "Kv://kv/app", "vault://kv/app", "https://example.com/kv://x",
		" kv://password@kv/app", `"kv://password@kv/app"`, "kv:/kv/app", "kv:kv/app", "kv", "",
	} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("SECRET_TEST", value)
			refs, err := parser.ParseEnv("SECRET_")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if findRef(refs, "TEST") != nil {
				t.Fatalf("%q was treated as a secret reference", value)
			}
		})
	}
}

// The prefix match is exact and case-sensitive, and a custom prefix replaces
// the default one.
func TestParseEnv_PrefixMatching(t *testing.T) {
	t.Setenv("SECRET_DEFAULT", "kv://kv/default")
	t.Setenv("secret_lower", "kv://kv/lower")
	t.Setenv("MY_SECRET_INNER", "kv://kv/inner")
	t.Setenv("CUSTOM_VALUE", "kv://kv/custom")

	refs, err := parser.ParseEnv("SECRET_")
	if err != nil {
		t.Fatal(err)
	}
	if findRef(refs, "DEFAULT") == nil {
		t.Error("SECRET_DEFAULT was not discovered")
	}
	for _, name := range []string{"lower", "INNER", "VALUE"} {
		if findRef(refs, name) != nil {
			t.Errorf("%s must not match the SECRET_ prefix", name)
		}
	}

	refs, err = parser.ParseEnv("CUSTOM_")
	if err != nil {
		t.Fatal(err)
	}
	if findRef(refs, "VALUE") == nil || findRef(refs, "DEFAULT") != nil {
		t.Errorf("custom prefix discovery is wrong: %+v", refs)
	}
}

func TestParseTemplateSecretURL_AdditionalForms(t *testing.T) {
	for _, tc := range []struct {
		input               string
		engine, field, path string
	}{
		{"password@kv/app", "kv", "password", "kv/app"},
		{"kv/app", "kv", "", "kv/app"},
		{"legacy://kvv1/app", "legacy", "", "kvv1/app"},
		{"kv://db%20pass@kv/my%20app", "kv", "db pass", "kv/my app"},
	} {
		ref, err := parser.ParseTemplateSecretURL(tc.input)
		if err != nil {
			t.Errorf("%q: %v", tc.input, err)
			continue
		}
		if ref.Engine != tc.engine || ref.Field != tc.field || ref.Path != tc.path || ref.EnvName != "" {
			t.Errorf("%q: got %+v", tc.input, ref)
		}
	}
	for _, input := range []string{"template://tpl@kv/app", "vault://kv/app", "kv://f:env@kv/app", "kv://f:@kv/app", "kv://kv/app?version=2", "kv://kv/app?"} {
		if _, err := parser.ParseTemplateSecretURL(input); err == nil {
			t.Errorf("%q: expected an error", input)
		} else if strings.Contains(err.Error(), input) {
			t.Errorf("%q: error exposes the reference: %v", input, err)
		}
	}
}
