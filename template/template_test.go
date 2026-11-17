package template_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/philhartung/bao-wrapper/masker"
	"github.com/philhartung/bao-wrapper/parser"
	tmpl "github.com/philhartung/bao-wrapper/template"
)

// fakeReader is a stub SecretReader for testing.
type fakeReader struct {
	secrets map[string]string // key = "engine/path/field"
}

func (f *fakeReader) ReadSecret(path, field string, _ int) (string, error) {
	key := path + "/" + field
	v, ok := f.secrets[key]
	if !ok {
		return "", fmt.Errorf("secret not found: %s", key)
	}
	return v, nil
}

// versionCapturingReader records the kvVersion passed to ReadSecret.
type versionCapturingReader struct {
	fakeReader
	capturedVersions map[string]int // key = "engine/path/field"
}

func newVersionCapturingReader(secrets map[string]string) *versionCapturingReader {
	return &versionCapturingReader{
		fakeReader:       fakeReader{secrets: secrets},
		capturedVersions: make(map[string]int),
	}
}

func (v *versionCapturingReader) ReadSecret(path, field string, kvVersion int) (string, error) {
	v.capturedVersions[path+"/"+field] = kvVersion
	return v.fakeReader.ReadSecret(path, field, kvVersion)
}

func TestRender_BasicTemplate(t *testing.T) {
	reader := &fakeReader{secrets: map[string]string{
		"myapp/config/template-field": `Hello {{ secret "kv://password@myapp/db" }}!`,
		"myapp/db/password":           "s3cret",
	}}

	ref := parser.SecretRef{
		Engine: "kv",
		Path:   "myapp/config",
		Field:  "template-field",
		Type:   parser.TypeFile,
	}

	result, err := tmpl.Render(context.Background(), ref, reader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Output != "Hello s3cret!" {
		t.Errorf("want %q, got %q", "Hello s3cret!", result.Output)
	}

	// Verify inner secrets are collected for masking.
	if len(result.InnerSecrets) != 1 || result.InnerSecrets[0] != "s3cret" {
		t.Errorf("inner secrets: want [s3cret], got %v", result.InnerSecrets)
	}

	// Verify the secret is actually maskable when added to a masker.
	var outBuf bytes.Buffer
	outMasker := masker.New(&outBuf, result.InnerSecrets)
	if _, err := outMasker.Write([]byte("leak: s3cret")); err != nil {
		t.Fatal(err)
	}
	_ = outMasker.Flush()
	if strings.Contains(outBuf.String(), "s3cret") {
		t.Errorf("secret leaked through masker: %q", outBuf.String())
	}
}

func TestRender_InvalidInnerEngine(t *testing.T) {
	reader := &fakeReader{secrets: map[string]string{
		"cfg/tpl": `{{ secret "aws://key@my/path" }}`,
	}}

	ref := parser.SecretRef{Engine: "kv", Path: "cfg", Field: "tpl"}

	_, err := tmpl.Render(context.Background(), ref, reader)
	if err == nil {
		t.Fatal("expected error for disallowed engine")
	}
	if !strings.Contains(err.Error(), "secret: invalid reference") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRender_InnerTypeRejected(t *testing.T) {
	reader := &fakeReader{secrets: map[string]string{
		"cfg/tpl": `{{ secret "kv://password:file@db/prod" }}`,
	}}

	ref := parser.SecretRef{Engine: "kv", Path: "cfg", Field: "tpl"}

	_, err := tmpl.Render(context.Background(), ref, reader)
	if err == nil {
		t.Fatal("expected error for type in template secret")
	}
	if !strings.Contains(err.Error(), "secret: invalid reference") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRender_InnerQueryRejected(t *testing.T) {
	reader := &fakeReader{secrets: map[string]string{
		"cfg/tpl": `{{ secret "kv://password@db/prod?outfile=x" }}`,
	}}

	ref := parser.SecretRef{Engine: "kv", Path: "cfg", Field: "tpl"}

	_, err := tmpl.Render(context.Background(), ref, reader)
	if err == nil {
		t.Fatal("expected error for query args in template secret")
	}
	if !strings.Contains(err.Error(), "secret: invalid reference") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRender_KVVersionForEngine(t *testing.T) {
	// Verify that kv inner secrets use kvVersion=2 and legacy inner
	// secrets use kvVersion=1 when fetched through the template engine.
	reader := newVersionCapturingReader(map[string]string{
		"cfg/tpl":       `{{ secret "kv://pass@app/db" }} {{ secret "legacy://token@art/npm" }}`,
		"app/db/pass":   "dbpass",
		"art/npm/token": "arttoken",
	})

	ref := parser.SecretRef{Engine: "kv", Path: "cfg", Field: "tpl"}

	result, err := tmpl.Render(context.Background(), ref, reader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Output != "dbpass arttoken" {
		t.Errorf("output: want %q, got %q", "dbpass arttoken", result.Output)
	}

	// kv inner secret must use kvVersion=2.
	if got := reader.capturedVersions["app/db/pass"]; got != 2 {
		t.Errorf("kv secret kvVersion: want 2, got %d", got)
	}
	// legacy inner secret must use kvVersion=1.
	if got := reader.capturedVersions["art/npm/token"]; got != 1 {
		t.Errorf("legacy secret kvVersion: want 1, got %d", got)
	}
}

func TestRender_FetchErrorDoesNotExposeCause(t *testing.T) {
	// The reader's error contains the path; Render must not expose it, even
	// through unwrapping or detailed formatting of the returned error.
	ref := parser.SecretRef{Engine: "template", Path: "source-credential-91ba3c"}
	result, err := tmpl.Render(context.Background(), ref, &fakeReader{})
	if err == nil {
		t.Fatal("expected template fetch to fail")
	}
	if result != nil {
		t.Fatal("expected no result on failure")
	}
	if got := fmt.Sprintf("%+v", err); got != "template: fetch template failed" {
		t.Errorf("unexpected fetch error: %q", got)
	}
	if errors.Unwrap(err) != nil {
		t.Fatal("template error must not retain an unsafe cause")
	}
}

func render(t *testing.T, template string, secrets map[string]string) (*tmpl.Result, error) {
	t.Helper()
	all := map[string]string{"kv/config/tpl": template}
	for key, value := range secrets {
		all[key] = value
	}
	return tmpl.Render(context.Background(), parser.SecretRef{Engine: "template", Path: "kv/config", Field: "tpl"}, &fakeReader{secrets: all})
}

// Control structures work, and every lookup is collected for masking,
// including repeated lookups of the same value.
func TestRender_LoopsCollectEveryLookup(t *testing.T) {
	result, err := render(t,
		`{{ range $i := 3 }}[{{ $i }}:{{ secret "kv://password@kv/db" }}]{{ end }}{{ if true }} api={{ secret "legacy://token@kvv1/api" }}{{ end }}`,
		map[string]string{"kv/db/password": "db-password-value", "kvv1/api/token": "api-token-value"})
	if err != nil {
		t.Fatal(err)
	}
	if want := "[0:db-password-value][1:db-password-value][2:db-password-value] api=api-token-value"; result.Output != want {
		t.Errorf("output = %q, want %q", result.Output, want)
	}
	want := []string{"db-password-value", "db-password-value", "db-password-value", "api-token-value"}
	if strings.Join(result.InnerSecrets, ",") != strings.Join(want, ",") {
		t.Errorf("inner secrets = %q, want %q", result.InnerSecrets, want)
	}
}

// A transformed value is rendered as the template asks, and the raw value is
// still registered. The transformed text itself has no masking guarantee,
// which the README documents.
func TestRender_TransformedValuesRegisterRawSecret(t *testing.T) {
	result, err := render(t,
		`quoted={{ secret "kv://password@kv/db" | printf "%q" }} url={{ secret "kv://password@kv/db" | urlquery }} len={{ len (secret "kv://password@kv/db") }}`,
		map[string]string{"kv/db/password": "p@ss word/1"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `quoted="p@ss word/1" url=p%40ss+word%2F1 len=11`; result.Output != want {
		t.Errorf("output = %q, want %q", result.Output, want)
	}
	if len(result.InnerSecrets) != 3 {
		t.Fatalf("inner secrets = %q", result.InnerSecrets)
	}
	for _, inner := range result.InnerSecrets {
		if inner != "p@ss word/1" {
			t.Errorf("registered %q, want the raw value", inner)
		}
	}
}

func TestRender_StaticTemplateHasNoInnerSecrets(t *testing.T) {
	result, err := render(t, "mode=production\nliteral braces: {{ `{{` }}\n", nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Output != "mode=production\nliteral braces: {{\n" || len(result.InnerSecrets) != 0 {
		t.Errorf("output = %q, inner secrets = %q", result.Output, result.InnerSecrets)
	}
}

// Errors name the stage, the numeric location and a fixed category only. They
// are printed before masking exists, so they must not carry template text,
// references or values.
func TestRender_ErrorsCarryOnlySafeDetails(t *testing.T) {
	const secretValue = "resolved-secret-value"
	for name, tc := range map[string]struct {
		template string
		want     string
	}{
		"parse error":            {"line one\n{{ secret \"kv://password@kv/db\" ", "template: parse failed at line 2"},
		"unknown function":       {`{{ lookup "kv/db" }}`, "template: parse failed at line 1"},
		"missing inner secret":   {"ok\n\n{{ secret \"kv://absent@kv/db\" }}", "template: execute failed at line 3, column 3: secret: fetch failed"},
		"invalid inner engine":   {`{{ secret "template://tpl@kv/other" }}`, "template: execute failed at line 1, column 3: secret: invalid reference"},
		"inner type selector":    {`{{ secret "kv://password:file@kv/db" }}`, "template: execute failed at line 1, column 3: secret: invalid reference"},
		"error after a lookup":   {`{{ secret "kv://password@kv/db" }}{{ index "x" 5 }}`, "template: execute failed at line 1, column 37"},
		"value used as function": {`{{ call (secret "kv://password@kv/db") }}`, "template: execute failed at line 1, column 3"},
	} {
		t.Run(name, func(t *testing.T) {
			result, err := render(t, tc.template, map[string]string{"kv/db/password": secretValue})
			if err == nil {
				t.Fatalf("expected an error, got output %q", result.Output)
			}
			if err.Error() != tc.want {
				t.Errorf("error = %q, want %q", err, tc.want)
			}
			if errors.Unwrap(err) != nil {
				t.Error("error wraps its cause, which may contain template text or values")
			}
		})
	}
}

// countingReader serves a template and counts lookups made by the helper.
type countingReader struct {
	template string
	lookups  atomic.Int32
	onLookup func()
}

func (r *countingReader) ReadSecret(path, _ string, _ int) (string, error) {
	if path == "kv/config" {
		return r.template, nil
	}
	r.lookups.Add(1)
	if r.onLookup != nil {
		r.onLookup()
	}
	return "inner-value", nil
}

var cancellableRef = parser.SecretRef{Engine: "template", Path: "kv/config", Field: "tpl"}

// A cancelled context must stop a render before it fetches anything.
func TestRender_CancelledBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reader := &countingReader{template: `{{ secret "kv://password@kv/db" }}`}
	if _, err := tmpl.Render(ctx, cancellableRef, reader); !errors.Is(err, tmpl.ErrInterrupted) {
		t.Fatalf("Render() error = %v, want ErrInterrupted", err)
	}
	if lookups := reader.lookups.Load(); lookups != 0 {
		t.Errorf("helper performed %d lookups after cancellation", lookups)
	}
}

// text/template cannot interrupt a loop that neither calls a function nor
// fails, so Render must return on cancellation without waiting for it.
func TestRender_CancelledDuringLongExecution(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	reader := &countingReader{template: `{{ range 2000000000 }}{{ end }}done`}
	time.AfterFunc(50*time.Millisecond, cancel)
	start := time.Now()
	_, err := tmpl.Render(ctx, cancellableRef, reader)
	if !errors.Is(err, tmpl.ErrInterrupted) {
		t.Fatalf("Render() error = %v, want ErrInterrupted", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Render() returned after %v, want prompt cancellation", elapsed)
	}
}

// Once the context is cancelled the helper must not read further secrets,
// and the render must not report success.
func TestRender_NoLookupsAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	reader := &countingReader{
		template: `{{ secret "kv://a@kv/db" }}{{ secret "kv://b@kv/db" }}{{ secret "kv://c@kv/db" }}`,
		onLookup: cancel,
	}
	if _, err := tmpl.Render(ctx, cancellableRef, reader); !errors.Is(err, tmpl.ErrInterrupted) {
		t.Fatalf("Render() error = %v, want ErrInterrupted", err)
	}
	// Allow an abandoned execution to reach the next helper call.
	time.Sleep(50 * time.Millisecond)
	if lookups := reader.lookups.Load(); lookups != 1 {
		t.Errorf("helper performed %d lookups, want 1", lookups)
	}
}
