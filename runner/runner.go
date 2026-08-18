// Package runner executes a child process with injected secrets, masked
// log output, and graceful cleanup on exit or OS signals.
package runner

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/philhartung/bao-wrapper/masker"
	"github.com/philhartung/bao-wrapper/parser"
)

// Revoker is implemented by api.Client so the runner can revoke the token
// without importing the api package directly.
type Revoker interface {
	RevokeToken() error
}

// SecretValue pairs a SecretRef with its resolved plaintext value.
type SecretValue struct {
	Ref   parser.SecretRef
	Value string
}

// Run executes args[0] with args[1:] as arguments. It:
//   - injects resolved secrets into the child environment (env or file)
//   - masks all secret values in stdout/stderr in real-time
//   - revokes the Vault token and removes temp files on exit or signal
//   - returns the child's exit code
//
// secretPrefix is the env-var prefix used to identify secret variables (e.g.
// "SECRET_"). It is stripped from the child environment to prevent leakage.
func Run(args []string, secrets []SecretValue, revoker Revoker, secretPrefix string) (int, error) {
	if len(args) == 0 {
		return 1, fmt.Errorf("runner: no command specified")
	}

	// Create an isolated temp directory for file secrets.
	tmpDir, err := os.MkdirTemp("", "bao-wrapper-*")
	if err != nil {
		return 1, fmt.Errorf("runner: create temp dir: %w", err)
	}
	tmpRoot, err := os.OpenRoot(tmpDir)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return 1, fmt.Errorf("runner: open temp dir: %w", err)
	}

	cleanup := func() {
		if revoker != nil {
			_ = revoker.RevokeToken()
		}
		_ = tmpRoot.Close()
		_ = os.RemoveAll(tmpDir)
	}

	// Build the extra environment entries and collect plaintext values for masking.
	var extraEnv []string
	var secretValues []string

	for _, sv := range secrets {
		secretValues = append(secretValues, sv.Value)

		// Entries with empty EnvName are masking-only (e.g. inner template secrets).
		if sv.Ref.EnvName == "" {
			continue
		}

		switch sv.Ref.Type {
		case parser.TypeFile:
			// If outfile is set, atomically replace it instead of writing directly
			// through a potentially attacker-controlled path.
			var path string
			if outfile := sv.Ref.Args["outfile"]; outfile != "" {
				path = outfile
				if err := writeSecretFile(path, sv.Value); err != nil {
					cleanup()
					return 1, fmt.Errorf("runner: create secret file: %w", err)
				}
			} else {
				path = filepath.Join(tmpDir, sv.Ref.EnvName)
				f, err := tmpRoot.OpenFile(sv.Ref.EnvName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if err != nil {
					cleanup()
					return 1, fmt.Errorf("runner: create secret file: %w", err)
				}
				if _, err := f.WriteString(sv.Value); err != nil {
					_ = f.Close()
					cleanup()
					return 1, fmt.Errorf("runner: write secret file: %w", err)
				}
				if err := f.Close(); err != nil {
					cleanup()
					return 1, fmt.Errorf("runner: close secret file: %w", err)
				}
			}
			extraEnv = append(extraEnv, sv.Ref.EnvName+"="+path)

		default: // TypeEnv
			extraEnv = append(extraEnv, sv.Ref.EnvName+"="+sv.Value)
		}
	}

	// Build masked writers for stdout and stderr.
	outWriter := masker.New(os.Stdout, secretValues)
	errWriter := masker.New(os.Stderr, secretValues)

	// #nosec G204 -- args come from the CLI sub-command, intentionally variable
	cmd := exec.Command(args[0], args[1:]...) //nolint:gosec // args validated by caller
	cmd.Env = append(filteredEnv(secretPrefix), extraEnv...)
	cmd.Stdout = outWriter
	cmd.Stderr = errWriter
	cmd.Stdin = os.Stdin

	// Handle OS signals: forward SIGINT/SIGTERM to the child, then clean up.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	if err := cmd.Start(); err != nil {
		cleanup()
		return 1, fmt.Errorf("runner: start process: %w", err)
	}

	doneCh := make(chan error, 1)
	go func() { doneCh <- cmd.Wait() }()

	select {
	case sig := <-sigCh:
		// Forward signal to child, then wait for it to finish.
		if cmd.Process != nil {
			_ = cmd.Process.Signal(sig)
		}
		<-doneCh
	case <-doneCh:
		// Child finished on its own.
	}

	signal.Stop(sigCh)

	// Flush masked writer buffers.
	_ = outWriter.Flush()
	_ = errWriter.Flush()

	cleanup()

	exitCode := cmd.ProcessState.ExitCode()
	if exitCode < 0 {
		// Process killed by signal; use 1 as a safe default.
		exitCode = 1
	}
	return exitCode, nil
}

// SecretValuesToStrings extracts just the value strings from a slice.
func SecretValuesToStrings(svs []SecretValue) []string {
	out := make([]string, len(svs))
	for i, sv := range svs {
		out[i] = sv.Value
	}
	return out
}

// IOWriter is a helper so callers can supply a custom writer (used in tests).
type IOWriter = io.Writer

// fixedSensitiveEnvPrefixes lists the environment variable prefixes that must
// never be forwarded to the child process regardless of the secret prefix.
var fixedSensitiveEnvPrefixes = []string{
	"BAO_",
	"VAULT_",
	"ACTIONS_ID_TOKEN_REQUEST_",
}

// filteredEnv returns a copy of os.Environ() with all entries whose key starts
// with one of the sensitive prefixes removed. secretPrefix (e.g. "SECRET_") is
// included in the filtered set. This prevents credentials such as
// BAO_JWT_TOKEN, BAO_APP_SECRET, VAULT_* tokens, raw secret spec strings, and
// ACTIONS_ID_TOKEN_REQUEST_* values from being inherited by the child.
func filteredEnv(secretPrefix string) []string {
	sensitiveEnvPrefixes := make([]string, len(fixedSensitiveEnvPrefixes)+1)
	for i, prefix := range fixedSensitiveEnvPrefixes {
		sensitiveEnvPrefixes[i] = strings.ToUpper(prefix)
	}
	sensitiveEnvPrefixes[len(fixedSensitiveEnvPrefixes)] = strings.ToUpper(secretPrefix)
	parent := os.Environ()
	out := make([]string, 0, len(parent))
	for _, e := range parent {
		key, _, _ := strings.Cut(e, "=")
		key = strings.ToUpper(key)
		skip := false
		for _, prefix := range sensitiveEnvPrefixes {
			if strings.HasPrefix(key, prefix) {
				skip = true
				break
			}
		}
		if !skip {
			out = append(out, e)
		}
	}
	return out
}
