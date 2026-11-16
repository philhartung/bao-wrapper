// Package masker provides an io.Writer that replaces secret strings with
// "[MASKED]" in real-time while handling chunk-boundary splits safely.
// Output is forwarded as soon as it is known not to be part of a secret; only
// a trailing run of bytes that could still be the beginning of a registered
// secret is withheld until more input arrives.
package masker

import (
	"bytes"
	"io"
	"sort"
	"sync"
)

const masked = "[MASKED]"

// minSecretLen is the minimum length a secret must have to be masked.
// Secrets of 3 characters or fewer are passed through unchanged to
// prevent over-masking of common short strings.
const minSecretLen = 4

// Writer wraps an underlying io.Writer and replaces all occurrences of
// registered secrets with "[MASKED]". It retains the undecided tail of the
// input to handle secrets that span write boundaries.
type Writer struct {
	mu      sync.Mutex
	dst     io.Writer
	secrets [][]byte
	// pending holds the raw tail of the input whose masking cannot be decided
	// until more input arrives: it starts at the first position where the
	// remaining bytes are a proper prefix of a secret, so it is empty unless
	// the output currently ends in the beginning of one. It is always shorter
	// than the longest secret.
	pending []byte
	// maskRemaining is the number of leading pending bytes already covered
	// by a mask marker emitted for an overlapping secret span.
	maskRemaining int
}

// New creates a Writer that writes masked output to dst.
// secrets is the list of plaintext secret strings to replace.
func New(dst io.Writer, secrets []string) *Writer {
	w := &Writer{dst: dst}
	for _, s := range secrets {
		if len(s) >= minSecretLen {
			w.secrets = append(w.secrets, []byte(s))
		}
	}
	w.sortSecrets()
	return w
}

// Write implements io.Writer. Everything that can be decided is written to
// the underlying writer before Write returns. Bytes are withheld only while
// the end of the input matches the beginning of a secret, so that a secret
// split across writes is still masked.
func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if len(w.secrets) == 0 {
		return w.dst.Write(p)
	}

	combined := append(w.pending, p...)
	out, consumed, maskRemaining := w.process(combined, false)
	w.pending = bytes.Clone(combined[consumed:])
	w.maskRemaining = maskRemaining

	if len(out) > 0 {
		if _, err := w.dst.Write(out); err != nil {
			return 0, err
		}
	}

	return len(p), nil
}

// Flush writes any withheld bytes to the underlying writer.
// Call this after the child process exits.
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if len(w.pending) == 0 {
		return nil
	}
	out, _, _ := w.process(w.pending, true)
	w.pending = nil
	w.maskRemaining = 0
	_, err := w.dst.Write(out)
	return err
}

// AddSecret registers a new secret to be masked in future writes.
// It is safe for concurrent use.
func (w *Writer) AddSecret(s string) {
	if len(s) < minSecretLen {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.secrets = append(w.secrets, []byte(s))
	w.sortSecrets()
}

// process masks the decidable prefix of data. A position is decidable once
// every secret either fits in the remaining input, and so matches or does not,
// or has already diverged from it. When final is false, processing stops at
// the first position where the remaining input is a proper prefix of a secret;
// the caller retains the input from there. Positions inside an existing masked
// span are still checked so that overlapping matches can extend the span
// without exposing either secret.
func (w *Writer) process(data []byte, final bool) ([]byte, int, int) {
	out := make([]byte, 0, len(data))
	pos := 0
	maskedUntil := w.maskRemaining

scan:
	for pos < len(data) {
		rest := data[pos:]
		wasCovered := pos < maskedUntil
		// Secrets are sorted longest first, so every secret that does not fit
		// in rest is examined before the first one that does.
		for _, secret := range w.secrets {
			if len(secret) > len(rest) {
				if !final && bytes.HasPrefix(secret, rest) {
					break scan
				}
				continue
			}
			if bytes.HasPrefix(rest, secret) {
				if end := pos + len(secret); end > maskedUntil {
					maskedUntil = end
				}
				break
			}
		}

		if pos < maskedUntil {
			if !wasCovered {
				out = append(out, masked...)
			}
		} else {
			out = append(out, data[pos])
		}
		pos++
	}

	remaining := maskedUntil - pos
	if remaining < 0 {
		remaining = 0
	}
	return out, pos, remaining
}

func (w *Writer) sortSecrets() {
	sort.SliceStable(w.secrets, func(i, j int) bool {
		return len(w.secrets[i]) > len(w.secrets[j])
	})
}
