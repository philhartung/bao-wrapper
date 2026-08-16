package masker_test

import (
	"bytes"
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
