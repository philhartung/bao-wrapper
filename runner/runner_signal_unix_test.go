//go:build !windows

package runner

import (
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/philhartung/bao-wrapper/parser"
)

type countingRevoker struct {
	calls   atomic.Int32
	started chan struct{}
	release chan struct{}
}

func (revoker *countingRevoker) RevokeToken() error {
	revoker.calls.Add(1)
	if revoker.started != nil {
		close(revoker.started)
	}
	if revoker.release != nil {
		<-revoker.release
	}
	return nil
}

func init() {
	helpers["signal"] = helperSignal
	helpers["kill-self"] = func([]string) int {
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		select {}
	}
}

// helperSignal reports readiness, waits for a shutdown signal, records it and
// then stays alive until the test releases it.
func helperSignal([]string) int {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer signal.Stop(sigCh)
	if err := os.WriteFile(os.Getenv("HELPER_SECRET_PATH_MARKER"), []byte(os.Getenv("HELPER_SECRET_FILE")), 0600); err != nil {
		return 2
	}
	if err := os.WriteFile(os.Getenv("HELPER_READY"), []byte("ready"), 0600); err != nil {
		return 2
	}
	sig := <-sigCh
	if err := os.WriteFile(os.Getenv("HELPER_INTERRUPTED"), []byte(sig.String()), 0600); err != nil {
		return 2
	}
	for {
		if _, err := os.Stat(os.Getenv("HELPER_RELEASE")); err == nil {
			return 0
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSignalRevokesAndUnlinksBeforeChildExit(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP} {
		t.Run(sig.String(), func(t *testing.T) { testSignalRevokesAndUnlinksBeforeChildExit(t, sig) })
	}
}

func testSignalRevokesAndUnlinksBeforeChildExit(t *testing.T, sig syscall.Signal) {
	tempDir := t.TempDir()
	readyPath := filepath.Join(tempDir, "ready")
	interruptedPath := filepath.Join(tempDir, "interrupted")
	releasePath := filepath.Join(tempDir, "release")
	secretPathMarker := filepath.Join(tempDir, "secret-path")
	t.Setenv("HELPER_READY", readyPath)
	t.Setenv("HELPER_INTERRUPTED", interruptedPath)
	t.Setenv("HELPER_RELEASE", releasePath)
	t.Setenv("HELPER_SECRET_PATH_MARKER", secretPathMarker)

	revokeStarted := make(chan struct{})
	revokeRelease := make(chan struct{})
	revoker := &countingRevoker{started: revokeStarted, release: revokeRelease}
	defer func() {
		select {
		case <-revokeRelease:
		default:
			close(revokeRelease)
		}
	}()
	sigCh := make(chan os.Signal, 1)
	type runResult struct {
		code int
		err  error
	}
	resultCh := make(chan runResult, 1)
	go func() {
		code, err := Run(
			helperCommand("signal"),
			[]SecretValue{{Ref: parser.SecretRef{Type: parser.TypeFile, EnvName: "HELPER_SECRET_FILE"}, Value: "secret"}},
			revoker,
			"SECRET_",
			sigCh,
		)
		resultCh <- runResult{code: code, err: err}
	}()
	defer func() { _ = os.WriteFile(releasePath, []byte("release"), 0600) }()

	waitForTestFile(t, readyPath)
	sigCh <- sig
	select {
	case <-revokeStarted:
	case <-time.After(time.Second):
		t.Fatal("token revocation did not start promptly")
	}
	// Signal forwarding must not wait for the deliberately blocked revoker.
	waitForTestFile(t, interruptedPath)
	// The marker can exist before the child has written the signal name.
	var forwarded []byte
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if forwarded, _ = os.ReadFile(interruptedPath); string(forwarded) == sig.String() {
			break
		}
	}
	if string(forwarded) != sig.String() {
		t.Fatalf("child received %q, want %q", forwarded, sig)
	}
	if calls := revoker.calls.Load(); calls != 1 {
		t.Fatalf("expected immediate single revocation, got %d calls", calls)
	}
	secretPath, err := os.ReadFile(secretPathMarker)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(string(secretPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary secret still exists before child exit: %v", err)
	}
	close(revokeRelease)
	if err := os.WriteFile(releasePath, []byte("release"), 0600); err != nil {
		t.Fatal(err)
	}
	result := <-resultCh
	if result.code != 0 || result.err != nil {
		t.Fatalf("run returned code %d, error %v", result.code, result.err)
	}
	if calls := revoker.calls.Load(); calls != 1 {
		t.Fatalf("revocation was not idempotent: %d calls", calls)
	}
}

// A signal that is already pending when Run is called must prevent the child
// from starting, while secret files are still removed and the token revoked.
func TestPendingSignalPreventsChildStart(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP} {
		t.Run(sig.String(), func(t *testing.T) {
			temp := isolateTemp(t)
			started := filepath.Join(t.TempDir(), "started")
			revoker := &recordingRevoker{}
			sigCh := make(chan os.Signal, 1)
			sigCh <- sig

			code, err := Run(helperCommand("env", started), []SecretValue{
				{Ref: parser.SecretRef{Type: parser.TypeFile, EnvName: "PENDING_FILE"}, Value: "value"},
			}, revoker, "SECRET_", sigCh)

			if want := 128 + int(sig); code != want {
				t.Errorf("Run() exit code = %d, want %d", code, want)
			}
			if err == nil || !strings.Contains(err.Error(), "before the command started") {
				t.Errorf("Run() error = %v, want an interruption error", err)
			}
			if _, statErr := os.Stat(started); !errors.Is(statErr, os.ErrNotExist) {
				t.Errorf("child was started despite the pending signal: %v", statErr)
			}
			assertEmptyDir(t, temp)
			if revoker.calls != 1 {
				t.Errorf("revoker called %d times, want 1", revoker.calls)
			}
		})
	}
}

func TestShutdownSignalsIncludeHangup(t *testing.T) {
	if signal.Ignored(syscall.SIGHUP) {
		t.Skip("SIGHUP is ignored in this environment")
	}
	signals := ShutdownSignals()
	for _, want := range []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP} {
		if !slices.Contains(signals, want) {
			t.Errorf("ShutdownSignals() = %v, missing %v", signals, want)
		}
	}
}

func waitForTestFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}

// A child terminated by a signal reports 128 plus the signal number, as a
// shell does, and the runner still cleans up.
func TestRunReportsSignalExitCodeWhenChildIsKilled(t *testing.T) {
	temp := isolateTemp(t)
	revoker := &recordingRevoker{}
	code, err := Run(helperCommand("kill-self"), []SecretValue{
		{Ref: parser.SecretRef{Type: parser.TypeFile, EnvName: "KILLED_FILE"}, Value: "value"},
	}, revoker, "SECRET_", nil)
	if want := 128 + int(syscall.SIGKILL); code != want || err != nil {
		t.Fatalf("Run() = %d, %v; want %d, nil", code, err, want)
	}
	assertEmptyDir(t, temp)
	if revoker.calls != 1 {
		t.Errorf("revoker called %d times, want 1", revoker.calls)
	}
}

// A file that exists but cannot be executed reports 126, as a shell does.
func TestRunReportsCannotExecute(t *testing.T) {
	temp := isolateTemp(t)
	script := filepath.Join(t.TempDir(), "not-executable")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0600); err != nil {
		t.Fatal(err)
	}
	revoker := &recordingRevoker{}
	code, err := Run([]string{script}, nil, revoker, "SECRET_", nil)
	if code != 126 || err == nil || !strings.Contains(err.Error(), "start process") {
		t.Fatalf("Run() = %d, %v; want 126 and a start failure", code, err)
	}
	assertEmptyDir(t, temp)
	if revoker.calls != 1 {
		t.Errorf("revoker called %d times, want 1", revoker.calls)
	}
}
