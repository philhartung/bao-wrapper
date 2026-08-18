package masker_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/philhartung/bao-wrapper/masker"
)

// --- basic masking ---

func TestWriter_MasksSecret(t *testing.T) {
	var buf bytes.Buffer
	w := masker.New(&buf, []string{"super-secret"})

	if _, err := w.Write([]byte("password is super-secret ok")); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}

	got := buf.String()
	if strings.Contains(got, "super-secret") {
		t.Errorf("secret leaked in output: %q", got)
	}
	if !strings.Contains(got, "[MASKED]") {
		t.Errorf("expected [MASKED] in output: %q", got)
	}
}

func TestWriter_MultipleSecrets(t *testing.T) {
	var buf bytes.Buffer
	w := masker.New(&buf, []string{"alpha", "beta", "gamma"})

	input := "alpha and beta and gamma are here"
	if _, err := w.Write([]byte(input)); err != nil {
		t.Fatal(err)
	}
	_ = w.Flush()

	got := buf.String()
	for _, s := range []string{"alpha", "beta", "gamma"} {
		if strings.Contains(got, s) {
			t.Errorf("secret %q leaked in output: %q", s, got)
		}
	}
}

func TestWriter_OverlappingSecrets(t *testing.T) {
	tests := []struct {
		name    string
		secrets []string
		input   string
		want    string
	}{
		{
			name:    "short prefix registered first",
			secrets: []string{"admin", "admin_password"},
			input:   "admin_password",
			want:    "[MASKED]",
		},
		{
			name:    "long prefix registered first",
			secrets: []string{"admin_password", "admin"},
			input:   "admin_password",
			want:    "[MASKED]",
		},
		{
			name:    "interior substring",
			secrets: []string{"password", "admin_password"},
			input:   "admin_password",
			want:    "[MASKED]",
		},
		{
			name:    "crossing matches",
			secrets: []string{"abab", "babab"},
			input:   "ababab",
			want:    "[MASKED]",
		},
		{
			name:    "self overlap",
			secrets: []string{"aaaa"},
			input:   "aaaaa",
			want:    "[MASKED]",
		},
		{
			name:    "adjacent matches remain distinct",
			secrets: []string{"admin"},
			input:   "adminadmin",
			want:    "[MASKED][MASKED]",
		},
		{
			name:    "mask marker is not reprocessed",
			secrets: []string{"MASK", "admin_password"},
			input:   "admin_password",
			want:    "[MASKED]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := masker.New(&buf, tt.secrets)
			if _, err := w.Write([]byte(tt.input)); err != nil {
				t.Fatal(err)
			}
			if err := w.Flush(); err != nil {
				t.Fatal(err)
			}
			if got := buf.String(); got != tt.want {
				t.Errorf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestWriter_NoSecrets_PassThrough(t *testing.T) {
	var buf bytes.Buffer
	w := masker.New(&buf, nil)

	data := "hello world"
	if _, err := w.Write([]byte(data)); err != nil {
		t.Fatal(err)
	}
	_ = w.Flush()

	if buf.String() != data {
		t.Errorf("expected %q, got %q", data, buf.String())
	}
}

// --- short secret anti-masking ---

func TestWriter_ShortSecretNotMasked(t *testing.T) {
	var buf bytes.Buffer
	// Secrets of <= 3 chars must NOT be masked.
	w := masker.New(&buf, []string{"ab", "xyz"})

	input := "ab xyz hello"
	if _, err := w.Write([]byte(input)); err != nil {
		t.Fatal(err)
	}
	_ = w.Flush()

	if buf.String() != input {
		t.Errorf("short secrets should not be masked; got %q", buf.String())
	}
}

// --- chunk boundary masking ---

func TestWriter_ChunkBoundary(t *testing.T) {
	var buf bytes.Buffer
	secret := "Password123"
	w := masker.New(&buf, []string{secret})

	// Split the secret across two writes: "Pass" + "word123"
	part1 := "The password is Pass"
	part2 := "word123 done"

	if _, err := w.Write([]byte(part1)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(part2)); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}

	got := buf.String()
	if strings.Contains(got, secret) {
		t.Errorf("secret leaked across chunk boundary: %q", got)
	}
	if !strings.Contains(got, "[MASKED]") {
		t.Errorf("expected [MASKED] in output: %q", got)
	}
}

func TestWriter_ChunkBoundary_MultipleChunks(t *testing.T) {
	var buf bytes.Buffer
	secret := "SuperLongSecretValue"
	w := masker.New(&buf, []string{secret})

	// Write one byte at a time
	for i := 0; i < len(secret); i++ {
		if _, err := w.Write([]byte{secret[i]}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}

	got := buf.String()
	if strings.Contains(got, secret) {
		t.Errorf("secret leaked byte-by-byte: %q", got)
	}
}

func TestWriter_OverlappingSecrets_EveryChunkBoundary(t *testing.T) {
	const secret = "admin_password"
	for split := 0; split <= len(secret); split++ {
		t.Run(fmt.Sprintf("split_%d", split), func(t *testing.T) {
			var buf bytes.Buffer
			w := masker.New(&buf, []string{"admin", secret})
			if _, err := w.Write([]byte(secret[:split])); err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write([]byte(secret[split:])); err != nil {
				t.Fatal(err)
			}
			if err := w.Flush(); err != nil {
				t.Fatal(err)
			}
			if got := buf.String(); got != "[MASKED]" {
				t.Errorf("expected fully masked secret, got %q", got)
			}
		})
	}
}

func TestWriter_OverlappingSecrets_ByteAtATime(t *testing.T) {
	const secret = "admin_password"
	var buf bytes.Buffer
	w := masker.New(&buf, []string{"admin", secret})
	for i := range len(secret) {
		if _, err := w.Write([]byte{secret[i]}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != "[MASKED]" {
		t.Errorf("expected fully masked secret, got %q", got)
	}
}

func TestWriter_AddSecretPreservesOverlapOrdering(t *testing.T) {
	var buf bytes.Buffer
	w := masker.New(&buf, []string{"admin"})
	if _, err := w.Write([]byte("adm")); err != nil {
		t.Fatal(err)
	}
	w.AddSecret("admin_password")
	if _, err := w.Write([]byte("in_password")); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != "[MASKED]" {
		t.Errorf("expected fully masked secret, got %q", got)
	}
}

// --- flush behavior ---

func TestWriter_FlushEmptyBuffer(t *testing.T) {
	var buf bytes.Buffer
	w := masker.New(&buf, []string{"secret"})
	// Flush before any writes should not panic or error.
	if err := w.Flush(); err != nil {
		t.Errorf("unexpected error from empty flush: %v", err)
	}
}

func TestWriter_ContextWithoutSecret(t *testing.T) {
	var buf bytes.Buffer
	w := masker.New(&buf, []string{"mysecret"})

	input := "nothing sensitive here"
	if _, err := w.Write([]byte(input)); err != nil {
		t.Fatal(err)
	}
	_ = w.Flush()

	if !strings.Contains(buf.String(), "nothing sensitive here") {
		t.Errorf("non-secret text was altered: %q", buf.String())
	}
}
