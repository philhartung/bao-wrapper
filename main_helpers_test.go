package main

import (
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// helperFlag selects a child-process helper when it is the first argument of
// the test binary. Tests wrap the binary itself, so they need no external
// program such as env or true on any platform.
const helperFlag = "-bao-wrapper-test-helper="

// TestMain runs a helper instead of the tests when the binary was started as
// a wrapped child. Exiting here keeps the test framework from printing PASS
// and coverage lines into the wrapper's stdout, which otherwise replaces the
// package's real coverage figure in `go test -cover`.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && strings.HasPrefix(os.Args[1], helperFlag) {
		os.Exit(runHelper(strings.TrimPrefix(os.Args[1], helperFlag), os.Args[2:]))
	}
	os.Exit(m.Run())
}

// helperCommand returns the argv that runs the named helper:
//
//	exit [code]            exit with code (default 0)
//	touch <path>           create path, proving the child started
//	env <path>             write the child's environment to path
//	echo <stdout> <stderr> write the arguments to the two streams
func helperCommand(name string, args ...string) []string {
	return append([]string{os.Args[0], helperFlag + name}, args...)
}

// runArgs builds the arguments for run(): options, the separator and a helper
// child command.
func runArgs(options []string, child []string) []string {
	args := append([]string{"run"}, options...)
	args = append(args, "--")
	return append(args, child...)
}

func runHelper(name string, args []string) int {
	switch name {
	case "exit":
		if len(args) == 0 {
			return 0
		}
		code, err := strconv.Atoi(args[0])
		if err != nil {
			return 99
		}
		return code
	case "touch":
		if len(args) != 1 || os.WriteFile(args[0], []byte("started"), 0o600) != nil {
			return 99
		}
		return 0
	case "env":
		if len(args) != 1 || os.WriteFile(args[0], []byte(strings.Join(os.Environ(), "\n")), 0o600) != nil {
			return 99
		}
		return 0
	case "echo":
		if len(args) > 0 {
			_, _ = fmt.Fprint(os.Stdout, args[0])
		}
		if len(args) > 1 {
			_, _ = fmt.Fprint(os.Stderr, args[1])
		}
		return 0
	default:
		fmt.Fprintln(os.Stderr, "unknown test helper:", name)
		return 99
	}
}

// wrapperInputs lists every paired BAO_/VAULT_ configuration variable.
var wrapperInputs = []string{
	"ADDR", "NAMESPACE", "TOKEN", "JWT_ROLE", "JWT_TOKEN", "APP_ID", "APP_SECRET",
	"AUTH_PATH", "CACERT", "MAX_RESPONSE_BYTES", "OIDC_MAX_RESPONSE_BYTES",
}

// wrapperEnv blanks every configuration input the wrapper reads so a test
// starts from a known state regardless of the developer's or CI's
// environment, then points BAO_ADDR at addr.
func wrapperEnv(t *testing.T, addr string) {
	t.Helper()
	for _, prefix := range []string{"BAO_", "VAULT_"} {
		for _, key := range wrapperInputs {
			t.Setenv(prefix+key, "")
		}
	}
	for _, key := range []string{"BAO_REVOKE_TOKEN", "BAO_SECRET_PREFIX", "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"} {
		t.Setenv(key, "")
	}
	t.Setenv("BAO_ADDR", addr)
}

// recordedRequest is one request received by a fakeVault.
type recordedRequest struct {
	Method, Path, Token, Namespace, Body string
}

// fakeVault is an httptest OpenBao/Vault stand-in with a concurrency-safe
// request log. Unregistered paths return 404.
type fakeVault struct {
	*httptest.Server
	mu       sync.Mutex
	requests []recordedRequest
	handlers map[string]http.HandlerFunc
}

// newFakeVault starts a plain-HTTP fake; newFakeVaultTLS a TLS one.
func newFakeVault(t *testing.T) *fakeVault    { return startFakeVault(t, false) }
func newFakeVaultTLS(t *testing.T) *fakeVault { return startFakeVault(t, true) }

func startFakeVault(t *testing.T, useTLS bool) *fakeVault {
	t.Helper()
	v := &fakeVault{handlers: map[string]http.HandlerFunc{}}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		v.mu.Lock()
		v.requests = append(v.requests, recordedRequest{
			Method: r.Method, Path: r.URL.Path, Token: r.Header.Get("X-Vault-Token"),
			Namespace: r.Header.Get("X-Vault-Namespace"), Body: string(body),
		})
		handle := v.handlers[r.URL.Path]
		v.mu.Unlock()
		if handle == nil {
			http.NotFound(w, r)
			return
		}
		handle(w, r)
	})
	if useTLS {
		v.Server = httptest.NewTLSServer(handler)
	} else {
		v.Server = httptest.NewServer(handler)
	}
	t.Cleanup(v.Close)
	return v
}

// handle registers a handler for an exact request path.
func (v *fakeVault) handle(path string, handler http.HandlerFunc) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.handlers[path] = handler
}

// respond registers a fixed status and body for path.
func (v *fakeVault) respond(path string, status int, body string) {
	v.handle(path, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})
}

// kv2 serves a KV v2 secret at <mount>/data/<path> with string fields.
func (v *fakeVault) kv2(mountAndPath string, fields map[string]string) {
	mount, rest, _ := strings.Cut(mountAndPath, "/")
	pairs := make([]string, 0, len(fields))
	for key, value := range fields {
		pairs = append(pairs, strconv.Quote(key)+":"+strconv.Quote(value))
	}
	v.respond("/v1/"+mount+"/data/"+rest, http.StatusOK, `{"data":{"data":{`+strings.Join(pairs, ",")+`}}}`)
}

// login makes the auth mount issue token; revocable makes revoke-self succeed.
func (v *fakeVault) login(mount, token string) {
	v.respond("/v1/auth/"+mount+"/login", http.StatusOK, `{"auth":{"client_token":`+strconv.Quote(token)+`}}`)
}

func (v *fakeVault) revocable() {
	v.respond("/v1/auth/token/revoke-self", http.StatusNoContent, "")
}

// seen returns the recorded requests for path.
func (v *fakeVault) seen(path string) []recordedRequest {
	v.mu.Lock()
	defer v.mu.Unlock()
	var matches []recordedRequest
	for _, request := range v.requests {
		if request.Path == path {
			matches = append(matches, request)
		}
	}
	return matches
}

// caFile writes the TLS fake's certificate as a PEM file and returns its path.
func (v *fakeVault) caFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: v.Certificate().Raw})
	if err := os.WriteFile(path, block, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// captured holds what a function wrote to the process's stdout and stderr.
type captured struct {
	Stdout, Stderr string
}

// captureOutput runs fn with os.Stdout and os.Stderr redirected to files and
// returns what was written, including output of wrapped child processes.
func captureOutput(t *testing.T, fn func()) captured {
	t.Helper()
	dir := t.TempDir()
	open := func(name string) *os.File {
		file, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return file
	}
	stdout, stderr := open("stdout"), open("stderr")
	originalStdout, originalStderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = stdout, stderr
	func() {
		defer func() { os.Stdout, os.Stderr = originalStdout, originalStderr }()
		fn()
	}()
	read := func(file *os.File) string {
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(file.Name())
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	return captured{Stdout: read(stdout), Stderr: read(stderr)}
}
