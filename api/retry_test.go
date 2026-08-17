package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// noopSleep is a sleep function that returns immediately, used in tests to
// avoid real delays while still exercising the retry/backoff code paths.
func noopSleep(time.Duration) {}

// newTestRetryClient builds a Client that uses a retryTransport with a no-op
// sleep function so tests complete quickly.
func newTestRetryClient(addr string) *Client {
	t := &retryTransport{
		base:    http.DefaultTransport,
		sleepFn: noopSleep,
	}
	return &Client{
		addr: addr,
		http: &http.Client{Transport: t},
		ctx:  context.Background(),
	}
}

// TestRetry_SuccessAfterTransient503 verifies that the client retries on 503
// and eventually succeeds once the server returns 200.
func TestRetry_SuccessAfterTransient503(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestRetryClient(srv.URL)
	c.SetToken("tok")

	if err := c.RevokeToken(); err != nil {
		t.Fatalf("expected success after retries, got: %v", err)
	}
	if calls != 3 {
		t.Errorf("expected 3 calls, got %d", calls)
	}
}

// TestRetry_SuccessAfterTransient502 verifies retry behaviour for 502.
func TestRetry_SuccessAfterTransient502(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestRetryClient(srv.URL)
	c.SetToken("tok")

	if err := c.RevokeToken(); err != nil {
		t.Fatalf("expected success after one 502 retry, got: %v", err)
	}
	if calls != 2 {
		t.Errorf("expected 2 calls, got %d", calls)
	}
}

// TestRetry_SuccessAfterTransient504 verifies retry behaviour for 504.
func TestRetry_SuccessAfterTransient504(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			w.WriteHeader(http.StatusGatewayTimeout)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestRetryClient(srv.URL)
	c.SetToken("tok")

	if err := c.RevokeToken(); err != nil {
		t.Fatalf("expected success after one 504 retry, got: %v", err)
	}
	if calls != 2 {
		t.Errorf("expected 2 calls, got %d", calls)
	}
}

// TestRetry_ExhaustedReturnsError verifies that after all retries are
// exhausted the last error is propagated.
func TestRetry_ExhaustedReturnsError(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := newTestRetryClient(srv.URL)
	c.SetToken("tok")

	err := c.RevokeToken()
	if err == nil {
		t.Fatal("expected error after all retries exhausted")
	}
	// 1 initial attempt + maxRetries retries
	expected := int32(1 + maxRetries)
	if calls != expected {
		t.Errorf("expected %d calls, got %d", expected, calls)
	}
}

// TestRetry_NoRetryOn401 verifies that 401 Unauthorized is not retried.
func TestRetry_NoRetryOn401(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := newTestRetryClient(srv.URL)
	c.SetToken("tok")

	if err := c.RevokeToken(); err == nil {
		t.Fatal("expected error for 401")
	}
	if calls != 1 {
		t.Errorf("expected exactly 1 call (no retry on 401), got %d", calls)
	}
}

// TestRetry_NoRetryOn403 verifies that 403 Forbidden is not retried.
func TestRetry_NoRetryOn403(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c := newTestRetryClient(srv.URL)
	c.SetToken("tok")

	if err := c.RevokeToken(); err == nil {
		t.Fatal("expected error for 403")
	}
	if calls != 1 {
		t.Errorf("expected exactly 1 call (no retry on 403), got %d", calls)
	}
}

// TestRetry_NoRetryOn404 verifies that 404 Not Found is not retried.
func TestRetry_NoRetryOn404(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := newTestRetryClient(srv.URL)
	c.SetToken("tok")

	if err := c.RevokeToken(); err == nil {
		t.Fatal("expected error for 404")
	}
	if calls != 1 {
		t.Errorf("expected exactly 1 call (no retry on 404), got %d", calls)
	}
}

// TestRetry_NetworkErrorRetried verifies that a network-level error causes
// the request to be retried.
func TestRetry_NetworkErrorRetried(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n < 3 {
			// Abort the connection to simulate a network error.
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Error("ResponseWriter does not support Hijacker")
				return
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				t.Errorf("hijack connection: %v", err)
				return
			}
			if err := conn.Close(); err != nil {
				t.Errorf("close hijacked connection: %v", err)
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestRetryClient(srv.URL)
	c.SetToken("tok")

	if err := c.RevokeToken(); err != nil {
		t.Fatalf("expected success after network error retries, got: %v", err)
	}
	if calls != 3 {
		t.Errorf("expected 3 calls, got %d", calls)
	}
}

// TestRetry_BackoffDelayIncreases verifies that each retry delay is longer
// than the previous one (exponential backoff).
func TestRetry_BackoffDelayIncreases(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	var delays []time.Duration
	rt := &retryTransport{
		base: http.DefaultTransport,
		sleepFn: func(d time.Duration) {
			delays = append(delays, d)
		},
	}
	c := &Client{
		addr: srv.URL,
		http: &http.Client{Transport: rt},
	}
	c.SetToken("tok")

	_ = c.RevokeToken()

	if len(delays) != maxRetries {
		t.Fatalf("expected %d delay calls, got %d", maxRetries, len(delays))
	}
	for i := 1; i < len(delays); i++ {
		// Strip the jitter upper bound (maxJitter) before comparing, because
		// jitter is random and we only check the deterministic component.
		prevBase := baseDelay * (1 << (i - 1))
		if delays[i] < prevBase || delays[i-1] < (prevBase-maxJitter) {
			t.Errorf("delay[%d]=%v, delay[%d]=%v: expected increasing backoff", i-1, delays[i-1], i, delays[i])
		}
	}
}

// TestIsRetryableStatus confirms the set of retryable status codes.
func TestIsRetryableStatus(t *testing.T) {
	retryable := []int{502, 503, 504}
	for _, code := range retryable {
		if !isRetryableStatus(code) {
			t.Errorf("expected %d to be retryable", code)
		}
	}

	notRetryable := []int{200, 201, 204, 400, 401, 403, 404, 500}
	for _, code := range notRetryable {
		if isRetryableStatus(code) {
			t.Errorf("expected %d to NOT be retryable", code)
		}
	}
}

// TestContext_CancelledRequestAborted verifies that a cancelled context
// causes an in-flight HTTP request to fail immediately.
func TestContext_CancelledRequestAborted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"data":{"field":"val"}}}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	c := New(srv.URL, "")
	c.SetContext(ctx)

	_, err := c.ReadSecret("kv/test", "field", 2)
	if err == nil {
		t.Fatal("expected error when context is already cancelled")
	}
}

// TestContext_RevokeTokenSucceedsAfterCancel verifies that RevokeToken uses a
// fresh timeout context when the main context has been cancelled, allowing the
// cleanup HTTP call to succeed.
func TestContext_RevokeTokenSucceedsAfterCancel(t *testing.T) {
	var called int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&called, 1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // simulate signal-triggered cancellation

	c := New(srv.URL, "")
	c.SetToken("tok")
	c.SetContext(ctx)

	if err := c.RevokeToken(); err != nil {
		t.Fatalf("RevokeToken should succeed with cleanup context, got: %v", err)
	}
	if atomic.LoadInt32(&called) != 1 {
		t.Errorf("expected exactly 1 call to revoke endpoint, got %d", called)
	}
}

// TestContext_RetryAbortsOnCancellation verifies that the retry transport
// stops retrying once the request context is cancelled.
func TestContext_RetryAbortsOnCancellation(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"data":{"field":"val"}}}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())

	rt := &retryTransport{
		base: http.DefaultTransport,
		sleepFn: func(d time.Duration) {
			// Cancel the context during the retry backoff sleep.
			cancel()
		},
	}
	c := &Client{
		addr: srv.URL,
		http: &http.Client{Transport: rt},
		ctx:  ctx,
	}
	c.SetToken("tok")

	_, err := c.ReadSecret("kv/test", "field", 2)
	if err == nil {
		t.Fatal("expected error when context is cancelled during retry")
	}
	if calls != 1 {
		t.Errorf("expected exactly 1 server call before cancellation aborted retries, got %d", calls)
	}
}
