//go:build !windows

package runner

import (
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/philhartung/bao-wrapper/parser"
)

const signalChildHelperEnv = "GO_WANT_BAO_WRAPPER_SIGNAL_CHILD"

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

func TestSignalChildHelper(t *testing.T) {
	if os.Getenv(signalChildHelperEnv) != "1" {
		return
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigCh)
	if err := os.WriteFile(os.Getenv("HELPER_SECRET_PATH_MARKER"), []byte(os.Getenv("HELPER_SECRET_FILE")), 0600); err != nil {
		os.Exit(2)
	}
	if err := os.WriteFile(os.Getenv("HELPER_READY"), []byte("ready"), 0600); err != nil {
		os.Exit(2)
	}
	<-sigCh
	if err := os.WriteFile(os.Getenv("HELPER_INTERRUPTED"), []byte("interrupted"), 0600); err != nil {
		os.Exit(2)
	}
	for {
		if _, err := os.Stat(os.Getenv("HELPER_RELEASE")); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSignalRevokesAndUnlinksBeforeChildExit(t *testing.T) {
	tempDir := t.TempDir()
	readyPath := filepath.Join(tempDir, "ready")
	interruptedPath := filepath.Join(tempDir, "interrupted")
	releasePath := filepath.Join(tempDir, "release")
	secretPathMarker := filepath.Join(tempDir, "secret-path")
	t.Setenv(signalChildHelperEnv, "1")
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
		code, err := runWithSignalChannel(
			[]string{os.Args[0], "-test.run=^TestSignalChildHelper$"},
			[]SecretValue{{Ref: parser.SecretRef{Type: parser.TypeFile, EnvName: "HELPER_SECRET_FILE"}, Value: "secret"}},
			revoker,
			"SECRET_",
			sigCh,
		)
		resultCh <- runResult{code: code, err: err}
	}()
	defer func() { _ = os.WriteFile(releasePath, []byte("release"), 0600) }()

	waitForTestFile(t, readyPath)
	sigCh <- syscall.SIGTERM
	select {
	case <-revokeStarted:
	case <-time.After(time.Second):
		t.Fatal("token revocation did not start promptly")
	}
	// Signal forwarding must not wait for the deliberately blocked revoker.
	waitForTestFile(t, interruptedPath)
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
