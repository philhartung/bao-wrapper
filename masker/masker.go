// Package masker provides an io.Writer that replaces secret strings with
// "[MASKED]" in real-time while handling chunk-boundary splits safely.
package masker

import (
	"bytes"
	"io"
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
	// overlap holds up to (maxLen-1) bytes from the end of the previous
	// write so that secrets split across chunk boundaries are detected.
	overlap []byte
	maxLen  int
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
	return w
}

// Write implements io.Writer. It buffers up to (maxLen-1) bytes at the end
// of each write to ensure secrets are not split across chunk boundaries.
func (w *Writer) Write(p []byte) (int, error) {
	if len(w.secrets) == 0 {
		return w.dst.Write(p)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	// Combine leftover overlap with new data.
	combined := append(w.overlap, p...)

	// Replace all known secrets in combined.
	out := replaceAll(combined, w.secrets)

	// Keep up to (maxLen-1) bytes at the end as the new overlap so that
	// a secret that begins near the end of this chunk can still be detected
	// when the next chunk arrives.
	overlapLen := w.maxLen - 1
	if overlapLen > len(out) {
		overlapLen = len(out)
	}

	toWrite := out[:len(out)-overlapLen]
	w.overlap = make([]byte, overlapLen)
	copy(w.overlap, out[len(out)-overlapLen:])

	if len(toWrite) > 0 {
		if _, err := w.dst.Write(toWrite); err != nil {
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

	if len(w.overlap) == 0 {
		return nil
	}
	out := replaceAll(w.overlap, w.secrets)
	w.overlap = nil
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
	if len(s) > w.maxLen {
		w.maxLen = len(s)
	}
}

// replaceAll replaces all occurrences of each secret in data.
func replaceAll(data []byte, secrets [][]byte) []byte {
	for _, secret := range secrets {
		data = bytes.ReplaceAll(data, secret, []byte(masked))
	}
	return data
}
