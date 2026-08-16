// Package template implements the "template" engine. It fetches a raw
// Go text/template from an OpenBao/Vault KV secret, renders it while
// providing a {{ secret "kv://field@path" }} helper for in-template
// secret lookups, and returns the final output. Secrets resolved inside
// the template are collected for masking; the template string itself is
// intentionally excluded from masking.
package template

import (
	"bytes"
	"fmt"
	"text/template"

	"github.com/philhartung/bao-wrapper/parser"
)

// SecretReader abstracts fetching a secret value (implemented by api.Client).
type SecretReader interface {
	ReadSecret(path, field string, kvVersion int) (string, error)
}

// Result holds the rendered template output and the list of inner secret
// values that must be registered with the masker.
type Result struct {
	// Output is the fully rendered template string.
	Output string
	// InnerSecrets contains every value resolved via {{ secret "..." }}.
	// These must be added to the masking writer.
	InnerSecrets []string
}

// Render fetches the template from the KV path described by ref, executes it
// with a {{ secret "url" }} function, and returns the rendered output plus the
// list of inner secret values for masking.
//
// The template string itself is NOT added to the masking list (to avoid
// over-masking and performance issues). Each value resolved via the
// {{ secret }} function IS included in Result.InnerSecrets.
func Render(ref parser.SecretRef, reader SecretReader) (*Result, error) {
	// Fetch the raw template content from the KV path.
	tplContent, err := reader.ReadSecret(ref.Path, ref.Field, parser.KVVersionForEngine(ref.Engine))
	if err != nil {
		return nil, fmt.Errorf("template: fetch template: %w", err)
	}

	var innerSecrets []string

	// Build the secret helper function.
	funcMap := template.FuncMap{
		"secret": func(raw string) (string, error) {
			inner, err := parser.ParseTemplateSecretURL(raw)
			if err != nil {
				return "", fmt.Errorf("template: secret %q: %w", raw, err)
			}
			val, err := reader.ReadSecret(inner.Path, inner.Field, parser.KVVersionForEngine(inner.Engine))
			if err != nil {
				return "", fmt.Errorf("template: secret %q: %w", raw, err)
			}
			innerSecrets = append(innerSecrets, val)
			return val, nil
		},
	}

	tmpl, err := template.New("secret-template").Funcs(funcMap).Parse(tplContent)
	if err != nil {
		return nil, fmt.Errorf("template: parse: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, nil); err != nil {
		return nil, fmt.Errorf("template: execute: %w", err)
	}

	return &Result{
		Output:       buf.String(),
		InnerSecrets: innerSecrets,
	}, nil
}
