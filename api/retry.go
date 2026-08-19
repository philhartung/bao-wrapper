package api

import (
	"context"
	"io"
	"math/rand/v2"
	"net/http"
	"time"
)

type transientRetriesKey struct{}

// withTransientRetries opts a single request into the retry transport. Retry
// is deliberately disabled by default so operations that can create new
// credentials, such as login, are never repeated transparently.
func withTransientRetries(ctx context.Context) context.Context {
	return context.WithValue(ctx, transientRetriesKey{}, true)
}

func transientRetriesEnabled(ctx context.Context) bool {
	enabled, _ := ctx.Value(transientRetriesKey{}).(bool)
	return enabled
}

const (
	maxRetries = 3
	baseDelay  = 1 * time.Second
	maxJitter  = 500 * time.Millisecond
)

// retryTransport is an http.RoundTripper that retries explicitly opted-in
// requests on transient network errors and on 502/503/504 responses using
// exponential backoff with jitter. All other requests are attempted once.
type retryTransport struct {
	base http.RoundTripper
	// sleepFn is used instead of time.Sleep when set; intended for tests.
	sleepFn func(time.Duration)
}

func newRetryTransport(base http.RoundTripper) *retryTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &retryTransport{base: base}
}

// isRetryableStatus reports whether the HTTP status code is a transient
// server-side error that warrants a retry.
func isRetryableStatus(code int) bool {
	return code == http.StatusBadGateway ||
		code == http.StatusServiceUnavailable ||
		code == http.StatusGatewayTimeout
}

func (t *retryTransport) doSleep(d time.Duration) {
	if t.sleepFn != nil {
		t.sleepFn(d)
	} else {
		time.Sleep(d)
	}
}

// RoundTrip executes the HTTP request, retrying up to maxRetries times on
// transient failures. The request body is reset via req.GetBody before each
// retry (http.NewRequest sets GetBody automatically for *bytes.Reader bodies).
func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !transientRetriesEnabled(req.Context()) {
		return t.base.RoundTrip(req)
	}

	var (
		resp *http.Response
		err  error
	)

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Abort retries immediately when the request context is cancelled.
			if err := req.Context().Err(); err != nil {
				return nil, err
			}

			// Reset the request body for the retry attempt.
			if req.GetBody != nil {
				req.Body, err = req.GetBody()
				if err != nil {
					return nil, err
				}
			}
			// Exponential backoff: 1s, 2s, 4s; plus random jitter up to 500ms.
			// math/rand/v2 jitter is not security-sensitive (used only for
			// timing purposes), so weak randomness is acceptable here.
			delay := baseDelay * (1 << (attempt - 1))
			jitter := rand.N(maxJitter) // #nosec G404
			t.doSleep(delay + jitter)
		}

		resp, err = t.base.RoundTrip(req)

		// On the last attempt return whatever we got unconditionally.
		if attempt == maxRetries {
			break
		}

		if err != nil {
			// Network-level error – retry.
			continue
		}

		if isRetryableStatus(resp.StatusCode) {
			// Drain and close the body to free the connection, then retry.
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			resp = nil
			continue
		}

		// Non-retryable response (success or permanent error such as 4xx).
		return resp, nil
	}

	return resp, err
}
