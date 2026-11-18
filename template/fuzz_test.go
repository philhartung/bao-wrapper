package template_test

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/philhartung/bao-wrapper/parser"
	tmpl "github.com/philhartung/bao-wrapper/template"
)

// safeRenderError is the complete set of messages Render may return. They are
// printed before any masking exists.
var safeRenderError = regexp.MustCompile(`^template: (fetch template failed|(parse|execute) failed( at line [0-9]+(, column [0-9]+)?)?(: secret: (invalid reference|fetch failed))?)$`)

// sentinelReader serves the fuzzed template at one path and a recognisable
// secret everywhere else.
type sentinelReader struct{ template string }

const fuzzSentinel = "FUZZ-SENTINEL-SECRET-VALUE"

func (r sentinelReader) ReadSecret(path, _ string, _ int) (string, error) {
	if path == "kv/fuzz-template" {
		return r.template, nil
	}
	return fuzzSentinel, nil
}

// FuzzRender renders arbitrary template text. Templates are stored in the
// secret store and edited separately from the pipeline, so rendering must
// never panic and a failure must never disclose template text or a resolved
// value. Looping and recursive templates are skipped: template resource use
// is unbounded by design today, which would only stall the fuzzer.
func FuzzRender(f *testing.F) {
	for _, seed := range []string{
		`Hello {{ secret "kv://password@kv/db" }}!`, `{{ secret "legacy://token@kvv1/api" | printf "%q" }}`,
		`{{ secret "template://x@kv/y" }}`, `{{ secret "kv://f:file@kv/db" }}`, `{{ secret "kv://kv/db?x" }}`,
		`{{ secret }}`, `{{ secret 1 }}`, `{{ secret "kv://a@kv/b" "extra" }}`, `{{ .Missing.Field }}`, `{{ index "x" 9 }}`,
		`{{ if secret "kv://a@kv/b" }}yes{{ else }}no{{ end }}`, `{{ with $x := secret "kv://a@kv/b" }}{{ $x }}{{ end }}`,
		`{{ slice (secret "kv://a@kv/b") 0 4 }}`, `{{ call (secret "kv://a@kv/b") }}`, "{{", "}}", `{{ "unterminated }}`, `{{/* c */}}`,
		"line\n{{ nope }}", `{{ printf "%[9]d" }}`, `{{ html (secret "kv://a@kv/b") }}`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, template string) {
		for _, action := range []string{"range", "template", "block", "define"} {
			if strings.Contains(template, action) {
				t.Skip("looping and recursive templates are out of scope")
			}
		}
		result, err := tmpl.Render(context.Background(), parser.SecretRef{Engine: "template", Path: "kv/fuzz-template", Field: "tpl"}, sentinelReader{template})
		if err != nil {
			if result != nil {
				t.Fatalf("result returned together with an error")
			}
			if !safeRenderError.MatchString(err.Error()) {
				t.Fatalf("error is outside the safe set: %q", err)
			}
			return
		}
		for _, inner := range result.InnerSecrets {
			if inner != fuzzSentinel {
				t.Fatalf("registered an unexpected inner value %q", inner)
			}
		}
		// A value can only reach the output through a lookup, and every lookup
		// registers it for masking.
		if strings.Contains(result.Output, fuzzSentinel) && !strings.Contains(template, fuzzSentinel) && len(result.InnerSecrets) == 0 {
			t.Fatalf("output contains a resolved value that was not registered: %q", result.Output)
		}
	})
}
