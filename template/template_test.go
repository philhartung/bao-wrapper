package template_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

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

	result, err := tmpl.Render(ref, reader)
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

	_, err := tmpl.Render(ref, reader)
	if err == nil {
		t.Fatal("expected error for disallowed engine")
	}
	if !strings.Contains(err.Error(), "unknown engine") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRender_InnerTypeRejected(t *testing.T) {
	reader := &fakeReader{secrets: map[string]string{
		"cfg/tpl": `{{ secret "kv://password:file@db/prod" }}`,
	}}

	ref := parser.SecretRef{Engine: "kv", Path: "cfg", Field: "tpl"}

	_, err := tmpl.Render(ref, reader)
	if err == nil {
		t.Fatal("expected error for type in template secret")
	}
	if !strings.Contains(err.Error(), "not allowed in templates") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRender_InnerQueryRejected(t *testing.T) {
	reader := &fakeReader{secrets: map[string]string{
		"cfg/tpl": `{{ secret "kv://password@db/prod?outfile=x" }}`,
	}}

	ref := parser.SecretRef{Engine: "kv", Path: "cfg", Field: "tpl"}

	_, err := tmpl.Render(ref, reader)
	if err == nil {
		t.Fatal("expected error for query args in template secret")
	}
	if !strings.Contains(err.Error(), "not allowed in templates") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRender_KVVersionForEngine(t *testing.T) {
	// Verify that kv inner secrets use kvVersion=2 and legacy inner
	// secrets use kvVersion=1 when fetched through the template engine.
	reader := newVersionCapturingReader(map[string]string{
		"cfg/tpl":           `{{ secret "kv://pass@app/db" }} {{ secret "legacy://token@art/npm" }}`,
		"app/db/pass":       "dbpass",
		"art/npm/token":     "arttoken",
	})

	ref := parser.SecretRef{Engine: "kv", Path: "cfg", Field: "tpl"}

	result, err := tmpl.Render(ref, reader)
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
