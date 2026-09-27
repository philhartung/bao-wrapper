package runner

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/philhartung/bao-wrapper/parser"
)

const drainHelperEnv = "GO_WANT_BAO_WRAPPER_DRAIN_HELPER"

// TestDrainHelper runs either the direct child or its pipe-holding descendant.
// The descendant stays alive until the test explicitly releases it.
func TestDrainHelper(t *testing.T) {
	mode := os.Getenv(drainHelperEnv)
	if mode == "" {
		return
	}
	dir := os.Getenv("DRAIN_TEST_DIR")
	writeMarker := func(name, value string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if mode == "descendant" {
		writeMarker("ready", "ready")
		waitForDrainMarker(t, filepath.Join(dir, "release"), 30*time.Second)
		writeMarker("finished", "finished")
		os.Exit(0)
	}

	writeMarker("secret-path", os.Getenv("DRAIN_SECRET_FILE"))
	stream := os.Getenv("DRAIN_STREAM")
	if stream != "none" {
		if err := os.Setenv(drainHelperEnv, "descendant"); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestDrainHelper$")
		if stream == "stdout" || stream == "both" {
			cmd.Stdout = os.Stdout
		}
		if stream == "stderr" || stream == "both" {
			cmd.Stderr = os.Stderr
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		waitForDrainMarker(t, filepath.Join(dir, "ready"), 5*time.Second)
		if err := cmd.Process.Release(); err != nil {
			t.Fatal(err)
		}
	}
	// The final bytes remain in the masker's overlap buffer until Flush.
	fmt.Fprint(os.Stdout, "stdout: drain-secret tail")
	fmt.Fprint(os.Stderr, "stderr: drain-secret tail")
	exitCode, err := strconv.Atoi(os.Getenv("DRAIN_EXIT_CODE"))
	if err != nil {
		t.Fatal(err)
	}
	os.Exit(exitCode)
}

func waitForDrainMarker(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}

type drainRevoker struct {
	calls atomic.Int32
	err   error
}

func (r *drainRevoker) RevokeToken() error {
	r.calls.Add(1)
	return r.err
}

func TestRunBoundsInheritedOutputDrain(t *testing.T) {
	for _, tc := range []struct {
		name        string
		stream      string
		childCode   int
		cleanupFail bool
	}{
		{name: "stdout", stream: "stdout"},
		{name: "stderr", stream: "stderr"},
		{name: "both", stream: "both"},
		{name: "nonzero child", stream: "both", childCode: 7},
		{name: "cleanup failure", stream: "both", cleanupFail: true},
		{name: "ordinary output", stream: "none"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv(drainHelperEnv, "child")
			t.Setenv("DRAIN_TEST_DIR", dir)
			t.Setenv("DRAIN_STREAM", tc.stream)
			t.Setenv("DRAIN_EXIT_CODE", strconv.Itoa(tc.childCode))
			// Avoid the race runtime's exit sleep obscuring process timing.
			t.Setenv("GORACE", "atexit_sleep_ms=0")

			// Regular files capture output without introducing additional pipes.
			stdout, err := os.CreateTemp(dir, "stdout-")
			if err != nil {
				t.Fatal(err)
			}
			defer stdout.Close()
			stderr, err := os.CreateTemp(dir, "stderr-")
			if err != nil {
				t.Fatal(err)
			}
			defer stderr.Close()
			oldOut, oldErr := os.Stdout, os.Stderr
			os.Stdout, os.Stderr = stdout, stderr
			defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()

			revoker := &drainRevoker{}
			var removeErr error
			if tc.cleanupFail {
				revoker.err = errors.New("revocation failed")
				removeErr = errors.New("removal failed")
			}
			type result struct {
				code int
				err  error
			}
			done := make(chan result, 1)
			go func() {
				code, err := runWithCleanup(
					[]string{os.Args[0], "-test.run=^TestDrainHelper$"},
					[]SecretValue{{Ref: parser.SecretRef{Type: parser.TypeFile, EnvName: "DRAIN_SECRET_FILE"}, Value: "drain-secret"}},
					revoker, "SECRET_", make(chan os.Signal),
					func(path string) error { return errors.Join(os.RemoveAll(path), removeErr) },
				)
				done <- result{code, err}
			}()
			returned := false
			defer func() {
				// Also release the descendant on assertion failures, including if
				// the runner regresses to waiting indefinitely for inherited pipes.
				if err := os.WriteFile(filepath.Join(dir, "release"), nil, 0600); err != nil {
					t.Error(err)
				}
				if !returned {
					select {
					case <-done:
					case <-time.After(10 * time.Second):
						t.Error("runner did not return after releasing descendant")
					}
				}
				if tc.stream != "none" {
					waitForDrainMarker(t, filepath.Join(dir, "finished"), 5*time.Second)
				}
			}()

			var got result
			select {
			case got = <-done:
				returned = true
			case <-time.After(8 * time.Second):
				t.Fatal("inherited output pipes delayed runner cleanup")
			}
			wantCode := tc.childCode
			wantTimeout := tc.stream != "none" && tc.childCode == 0
			if wantTimeout {
				wantCode = 1
			}
			if got.code != wantCode || errors.Is(got.err, exec.ErrWaitDelay) != wantTimeout {
				t.Fatalf("Run() = (%d, %v), want code %d, drain timeout %t", got.code, got.err, wantCode, wantTimeout)
			}
			if !wantTimeout && got.err != nil {
				t.Fatalf("unexpected runner error: %v", got.err)
			}
			if tc.cleanupFail && (!errors.Is(got.err, revoker.err) || !errors.Is(got.err, removeErr)) {
				t.Fatalf("cleanup errors missing from %v", got.err)
			}
			if revoker.calls.Load() != 1 {
				t.Fatalf("revocation calls = %d, want 1", revoker.calls.Load())
			}
			secretPath, err := os.ReadFile(filepath.Join(dir, "secret-path"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Dir(string(secretPath))); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("temporary secret directory still exists: %v", err)
			}
			if tc.stream != "none" {
				if _, err := os.Stat(filepath.Join(dir, "ready")); err != nil {
					t.Fatalf("descendant did not start: %v", err)
				}
				if _, err := os.Stat(filepath.Join(dir, "finished")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("descendant exited before cleanup: %v", err)
				}
			}
			for _, output := range []struct {
				file *os.File
				want string
			}{{stdout, "stdout: [MASKED] tail"}, {stderr, "stderr: [MASKED] tail"}} {
				data, err := os.ReadFile(output.file.Name())
				if err != nil {
					t.Fatal(err)
				}
				if string(data) != output.want {
					t.Errorf("output = %q, want %q", data, output.want)
				}
			}
		})
	}
}
