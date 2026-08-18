// Package masker provides an io.Writer that replaces secret strings with
// "[MASKED]" in real-time while handling chunk-boundary splits safely.
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
// registered secrets with "[MASKED]". It maintains a rolling overlap buffer
// to handle secrets that span write boundaries.
type Writer struct {
	mu      sync.Mutex
	dst     io.Writer
	secrets [][]byte
	// pending holds up to (maxLen-1) raw bytes whose masking cannot be
	// decided until more input arrives.
	pending []byte
	// maskRemaining is the number of leading pending bytes already covered
	// by a mask marker emitted for an overlapping secret span.
	maskRemaining int
	maxLen        int
}

// New creates a Writer that writes masked output to dst.
// secrets is the list of plaintext secret strings to replace.
func New(dst io.Writer, secrets []string) *Writer {
	w := &Writer{dst: dst}
	for _, s := range secrets {
		if len(s) >= minSecretLen {
			w.secrets = append(w.secrets, []byte(s))
			if len(s) > w.maxLen {
				w.maxLen = len(s)
			}
		}
	}
	w.sortSecrets()
	return w
}

// Write implements io.Writer. It buffers up to (maxLen-1) bytes at the end
// of each write to ensure secrets are not split across chunk boundaries.
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

// Flush writes any buffered overlap bytes to the underlying writer.
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
	if len(s) > w.maxLen {
		w.maxLen = len(s)
	}
}

// process masks the decidable prefix of data. When final is false, it retains
// enough raw input to detect secrets split across future writes. It checks
// positions inside an existing masked span so that overlapping matches can
// extend the span without exposing either secret.
func (w *Writer) process(data []byte, final bool) ([]byte, int, int) {
	out := make([]byte, 0, len(data))
	pos := 0
	maskedUntil := w.maskRemaining

	for pos < len(data) {
		if !final && len(data)-pos < w.maxLen {
			break
		}

		wasCovered := pos < maskedUntil
		for _, secret := range w.secrets {
			if bytes.HasPrefix(data[pos:], secret) {
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
