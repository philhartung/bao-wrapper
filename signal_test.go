package main

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestShutdownRecordsFirstSignalAndForwardsAll(t *testing.T) {
	raw := make(chan os.Signal, 2)
	interrupt := newShutdown(raw)
	defer interrupt.stop()
	if _, interrupted := interrupt.signal(); interrupted || interrupt.ctx.Err() != nil {
		t.Fatal("shutdown reported a signal before any arrived")
	}

	raw <- syscall.SIGHUP
	raw <- syscall.SIGTERM
	select {
	case <-interrupt.ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("context was not cancelled by the signal")
	}
	// The signal is recorded before the context is cancelled.
	if sig, interrupted := interrupt.signal(); !interrupted || sig != syscall.SIGHUP {
		t.Fatalf("signal() = %v, %v; want the first signal", sig, interrupted)
	}
	for _, want := range []os.Signal{syscall.SIGHUP, syscall.SIGTERM} {
		select {
		case got := <-interrupt.signals:
			if got != want {
				t.Fatalf("forwarded %v, want %v", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%v was not forwarded to the runner", want)
		}
	}
}

func TestShutdownStopLeavesNoSignal(t *testing.T) {
	interrupt := newShutdown(make(chan os.Signal))
	interrupt.stop()
	interrupt.stop()
	if _, interrupted := interrupt.signal(); interrupted {
		t.Fatal("stop must not be reported as a signal")
	}
	if interrupt.ctx.Err() == nil {
		t.Fatal("stop must release the context")
	}
}

// interruptedRun runs the wrapper in-process with an injectable signal source
// and a child that would create a marker file if it were ever started.
func interruptedRun(t *testing.T, raw chan os.Signal) (code int, childStarted bool, output captured, elapsed time.Duration) {
	t.Helper()
	marker := filepath.Join(t.TempDir(), "child-started")
	start := time.Now()
	output = captureOutput(t, func() {
		code = runWithSignals(runArgs(nil, helperCommand("touch", marker)), raw)
	})
	elapsed = time.Since(start)
	_, err := os.Stat(marker)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return code, err == nil, output, elapsed
}

// A signal that arrives while a secret is being fetched must abort the run:
// the child is not started, the login-issued token is revoked and the exit
// code names the signal.
func TestRun_SignalDuringSecretFetchPreventsChildStart(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP} {
		t.Run(sig.String(), func(t *testing.T) {
			vault := newFakeVault(t)
			wrapperEnv(t, vault.URL)
			vault.login("approle", "issued-token")
			vault.revocable()
			raw := make(chan os.Signal, 1)
			vault.handle("/v1/kv/data/app", func(w http.ResponseWriter, r *http.Request) {
				raw <- sig
				select {
				case <-r.Context().Done():
				case <-time.After(5 * time.Second):
				}
				_, _ = io.WriteString(w, `{"data":{"data":{"password":"fetched-password"}}}`)
			})
			t.Setenv("BAO_APP_ID", "role-id")
			t.Setenv("BAO_APP_SECRET", "secret-id")
			t.Setenv("SECRET_DB_PASSWORD", "kv://password@kv/app")

			code, childStarted, output, _ := interruptedRun(t, raw)

			if want := 128 + int(sig); code != want {
				t.Errorf("exit code = %d, want %d\nstderr: %s", code, want, output.Stderr)
			}
			if childStarted {
				t.Error("child was started after the signal")
			}
			if revocations := vault.seen("/v1/auth/token/revoke-self"); len(revocations) != 1 || revocations[0].Token != "issued-token" {
				t.Errorf("revocations = %v, want one for the issued token", revocations)
			}
			if strings.Contains(output.Stdout+output.Stderr, "fetched-password") {
				t.Error("output exposes the secret value")
			}
		})
	}
}

// A signal during a template that never finishes on its own must end the
// run promptly instead of waiting for the render and then starting the child.
func TestRun_SignalDuringTemplateRenderPreventsChildStart(t *testing.T) {
	vault := newFakeVault(t)
	wrapperEnv(t, vault.URL)
	raw := make(chan os.Signal, 1)
	vault.handle("/v1/kv/data/config", func(w http.ResponseWriter, _ *http.Request) {
		time.AfterFunc(100*time.Millisecond, func() { raw <- syscall.SIGTERM })
		_, _ = io.WriteString(w, `{"data":{"data":{"tpl":"{{ range 2000000000 }}{{ end }}rendered"}}}`)
	})
	t.Setenv("BAO_TOKEN", "borrowed-token")
	t.Setenv("SECRET_CONFIG", "template://tpl@kv/config")

	code, childStarted, output, elapsed := interruptedRun(t, raw)

	if want := 128 + int(syscall.SIGTERM); code != want {
		t.Errorf("exit code = %d, want %d\nstderr: %s", code, want, output.Stderr)
	}
	if childStarted {
		t.Error("child was started after the signal")
	}
	if elapsed > 3*time.Second {
		t.Errorf("run returned after %v, want prompt cancellation", elapsed)
	}
	if !strings.Contains(output.Stderr, "template: interrupted") {
		t.Errorf("stderr = %q, want the interruption to be reported", output.Stderr)
	}
}

// Without a signal the exit code of a failed run stays 1.
func TestRun_FailureWithoutSignalStillExitsOne(t *testing.T) {
	vault := newFakeVault(t)
	wrapperEnv(t, vault.URL)
	t.Setenv("BAO_TOKEN", "borrowed-token")
	t.Setenv("SECRET_MISSING", "kv://password@kv/missing")

	code, childStarted, _, _ := interruptedRun(t, make(chan os.Signal))

	if code != 1 || childStarted {
		t.Errorf("exit code = %d, child started = %v; want 1 and no child", code, childStarted)
	}
}
