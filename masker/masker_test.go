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

// Output that cannot be part of a secret must reach the destination during
// Write, however long the registered secrets are. A wrapper killed before
// Flush would otherwise lose the last lines of a hung job.
func TestWriter_ForwardsUndecidableFreeOutputImmediately(t *testing.T) {
	var buf bytes.Buffer
	w := masker.New(&buf, []string{strings.Repeat("s3cr3t-", 2000)})

	for _, line := range []string{"step 41 ok\n", "about to hang: step 42\n"} {
		before := buf.Len()
		if _, err := w.Write([]byte(line)); err != nil {
			t.Fatalf("Write error: %v", err)
		}
		if got := buf.String()[before:]; got != line {
			t.Fatalf("Write forwarded %q, want %q before any further input", got, line)
		}
	}
}

// Only the trailing bytes that still match the beginning of a secret are
// withheld, and they are released as soon as the input diverges.
func TestWriter_WithholdsOnlyPossibleSecretPrefix(t *testing.T) {
	var buf bytes.Buffer
	w := masker.New(&buf, []string{"hunter2-password"})

	_, _ = w.Write([]byte("login: hunt"))
	if got := buf.String(); got != "login: " {
		t.Fatalf("after possible prefix: forwarded %q, want %q", got, "login: ")
	}
	_, _ = w.Write([]byte("ing season\n"))
	if got := buf.String(); got != "login: hunting season\n" {
		t.Fatalf("after divergence: forwarded %q", got)
	}

	_, _ = w.Write([]byte("pw=hunter2-pass"))
	_, _ = w.Write([]byte("word\n"))
	if got := buf.String(); got != "login: hunting season\npw=[MASKED]\n" {
		t.Fatalf("split secret: forwarded %q", got)
	}
}

// A shorter secret that already matches must stay withheld while a longer
// secret starting at the same position is still undecided.
func TestWriter_ShorterMatchWaitsForLongerCandidate(t *testing.T) {
	for _, tc := range []struct{ tail, want string }{
		{"efgh!", "[MASKED]!"},
		{"efXX!", "[MASKED]efXX!"},
	} {
		var buf bytes.Buffer
		w := masker.New(&buf, []string{"abcd", "abcdefgh"})
		_, _ = w.Write([]byte("abcd"))
		if buf.Len() != 0 {
			t.Fatalf("forwarded %q while the longer secret was undecided", buf.String())
		}
		_, _ = w.Write([]byte(tc.tail))
		_ = w.Flush()
		if got := buf.String(); got != tc.want {
			t.Fatalf("tail %q: got %q, want %q", tc.tail, got, tc.want)
		}
	}
}

// reference masks data in one pass with unlimited lookahead.
func reference(data []byte, secrets []string) []byte {
	var out []byte
	maskedUntil := 0
	for pos := range data {
		wasCovered := pos < maskedUntil
		for _, secret := range secrets {
			if len(secret) >= 4 && bytes.HasPrefix(data[pos:], []byte(secret)) {
				maskedUntil = max(maskedUntil, pos+len(secret))
			}
		}
		switch {
		case pos >= maskedUntil:
			out = append(out, data[pos])
		case !wasCovered:
			out = append(out, "[MASKED]"...)
		}
	}
	return out
}

// FuzzWriter checks that output does not depend on how the input is split
// into writes, that it matches a single-pass reference, and that forwarded
// output is never retracted. The alphabet shares no
// byte with the mask marker, so a marker cannot fabricate a secret.
func FuzzWriter(f *testing.F) {
	f.Add([]byte("abcabcabcaabbcc"), []byte("abca\x00bcab\x00aabb"), uint64(1))
	f.Add([]byte("aaaaaaaaaaaaaaaa"), []byte("aaaa\x00aaaaaaa"), uint64(7))
	f.Add([]byte("xyzzyxyzzy"), []byte("xyzz\x00zzyx\x00yxyzzy"), uint64(3))
	f.Fuzz(func(t *testing.T, data, rawSecrets []byte, seed uint64) {
		normalize := func(in []byte) []byte {
			out := make([]byte, len(in))
			for i, c := range in {
				out[i] = "abc\xc3\xa9"[c%5]
			}
			return out
		}
		var secrets []string
		for _, s := range bytes.Split(rawSecrets, []byte{0}) {
			if len(s) > 0 && len(s) <= 12 {
				secrets = append(secrets, string(normalize(s)))
			}
		}
		data = normalize(data)
		want := reference(data, secrets)

		var got bytes.Buffer
		w := masker.New(&got, secrets)
		state := seed
		for rest := data; len(rest) > 0; {
			state = state*6364136223846793005 + 1442695040888963407
			n := 1 + int((state>>33)%uint64(len(rest)))
			if state&1 == 0 && n > 3 {
				n = 1 + int((state>>40)%3)
			}
			if _, err := w.Write(rest[:n]); err != nil {
				t.Fatal(err)
			}
			rest = rest[n:]
			// Decisions are final: forwarded output never has to be retracted.
			if !bytes.HasPrefix(want, got.Bytes()) {
				t.Fatalf("forwarded output %q is not a prefix of the expected result %q", got.Bytes(), want)
			}
		}
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Bytes(), want) {
			t.Fatalf("data=%q secrets=%q\n got=%q\nwant=%q", data, secrets, got.Bytes(), want)
		}
		for _, secret := range secrets {
			if len(secret) >= 4 && bytes.Contains(got.Bytes(), []byte(secret)) {
				t.Fatalf("secret %q leaked in %q", secret, got.Bytes())
			}
		}
	})
}
