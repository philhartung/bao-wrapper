// Package runner executes a child process with injected secrets, masked
// log output, and graceful cleanup on exit or OS signals.
package runner

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
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
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	return runWithSignalChannel(args, secrets, revoker, secretPrefix, sigCh)
}

func runWithSignalChannel(args []string, secrets []SecretValue, revoker Revoker, secretPrefix string, sigCh <-chan os.Signal) (int, error) {
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

	var cleanupOnce sync.Once
	cleanupDone := make(chan struct{})
	var closeRootErr, revokeErr error
	startCleanup := func() {
		cleanupOnce.Do(func() {
			go func() {
				closeRootErr = tmpRoot.Close()
				_ = os.RemoveAll(tmpDir)
				if revoker != nil {
					revokeErr = revoker.RevokeToken()
				}
				close(cleanupDone)
			}()
		})
	}
	finishCleanup := func() error {
		startCleanup()
		<-cleanupDone
		// Retry after the child exits because Windows may reject signal-time
		// removal while the child has a file open.
		return errors.Join(closeRootErr, os.RemoveAll(tmpDir), revokeErr)
	}

	// Build the extra environment entries and collect plaintext values for masking.
	// A rendered template's outer value is injected but deliberately excluded:
	// its separately registered inner secrets are masked while its static
	// skeleton remains visible in logs.
	var extraEnv []string
	secretValues := valuesForMasking(secrets)

	for _, sv := range secrets {
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
					_ = finishCleanup()
					return 1, fmt.Errorf("runner: create secret file: %w", err)
				}
			} else {
				path = filepath.Join(tmpDir, sv.Ref.EnvName)
				f, err := tmpRoot.OpenFile(sv.Ref.EnvName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if err != nil {
					_ = finishCleanup()
					return 1, fmt.Errorf("runner: create secret file: %w", err)
				}
				if _, err := f.WriteString(sv.Value); err != nil {
					_ = f.Close()
					_ = finishCleanup()
					return 1, fmt.Errorf("runner: write secret file: %w", err)
				}
				if err := f.Close(); err != nil {
					_ = finishCleanup()
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

	// Revoke the token and unlink temporary secrets as soon as a shutdown signal
	// arrives. Process-tree enforcement is deliberately left to the CI/container
	// runtime; the runner forwards signals only to its direct child.
	if err := cmd.Start(); err != nil {
		_ = finishCleanup()
		return 1, fmt.Errorf("runner: start process: %w", err)
	}
	doneCh := make(chan error, 1)
	go func() { doneCh <- cmd.Wait() }()

	var waitErr, signalErr error
waitLoop:
	for {
		select {
		case waitErr = <-doneCh:
			break waitLoop
		case sig := <-sigCh:
			startCleanup()
			if err := cmd.Process.Signal(sig); err != nil {
				signalErr = errors.Join(signalErr, fmt.Errorf("forward signal to child: %w", err))
			}
		}
	}

	// Flush masked writer buffers.
	_ = outWriter.Flush()
	_ = errWriter.Flush()

	cleanupErr := finishCleanup()

	exitCode := cmd.ProcessState.ExitCode()
	if exitCode < 0 {
		exitCode = 1
	}
	var exitErr *exec.ExitError
	if waitErr != nil && !errors.As(waitErr, &exitErr) {
		return 1, errors.Join(fmt.Errorf("runner: wait for process: %w", waitErr), signalErr, cleanupErr)
	}
	return exitCode, errors.Join(signalErr, cleanupErr)
}

// valuesForMasking selects plaintext values that should be registered with
// the output masker. Rendered template output is excluded so only the inner
// secrets registered as masking-only entries hide parts of the template.
func valuesForMasking(secrets []SecretValue) []string {
	values := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		if secret.Ref.Engine != "template" {
			values = append(values, secret.Value)
		}
	}
	return values
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
