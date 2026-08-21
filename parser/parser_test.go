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
		wantArgs   map[string]string
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
		// --- new: query-parameter tests ---
		{
			input:      "template://tpl:file@kv/config?outfile=.env",
			wantEngine: "template",
			wantField:  "tpl",
			wantType:   parser.TypeFile,
			wantPath:   "kv/config",
			wantArgs:   map[string]string{"outfile": ".env"},
		},
		{
			input:      "kv://pass:env@db?foo=bar",
			wantEngine: "kv",
			wantField:  "pass",
			wantType:   parser.TypeEnv,
			wantPath:   "db",
			wantArgs:   map[string]string{"foo": "bar"},
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
			if tt.wantArgs != nil {
				for k, want := range tt.wantArgs {
					got, ok := ref.Args[k]
					if !ok {
						t.Errorf("args: missing key %q", k)
					} else if got != want {
						t.Errorf("args[%s]: want %q, got %q", k, want, got)
					}
				}
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
