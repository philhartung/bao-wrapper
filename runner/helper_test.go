package runner

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

// helperFlag selects a child-process helper when it is the first argument of
// the test binary. Tests use the binary itself as the wrapped command, so no
// external program is required on any platform.
const helperFlag = "-runner-test-helper="

// helpers maps a helper name to its implementation. The returned value is the
// process exit code. Platform-specific helpers register themselves in init.
var helpers = map[string]func(args []string) int{
	"exit": helperExit,
	"echo": helperEcho,
	"env":  helperEnv,
}

// TestMain runs a helper instead of the tests when the binary was started as
// a wrapped child. Exiting here keeps the test framework from printing PASS
// and coverage lines into the output the parent test captures, which
// otherwise replaces the package's real coverage figure in `go test -cover`.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && strings.HasPrefix(os.Args[1], helperFlag) {
		name := strings.TrimPrefix(os.Args[1], helperFlag)
		helper, ok := helpers[name]
		if !ok {
			fmt.Fprintln(os.Stderr, "unknown test helper:", name)
			os.Exit(99)
		}
		os.Exit(helper(os.Args[2:]))
	}
	os.Exit(m.Run())
}

// helperCommand returns the argv that runs the named helper.
func helperCommand(name string, args ...string) []string {
	return append([]string{os.Args[0], helperFlag + name}, args...)
}

// helperExit exits with the code given as its first argument (default 0).
func helperExit(args []string) int {
	if len(args) == 0 {
		return 0
	}
	code, err := strconv.Atoi(args[0])
	if err != nil {
		return 99
	}
	return code
}

// helperEcho writes its first argument to stdout and its second to stderr.
func helperEcho(args []string) int {
	if len(args) > 0 {
		_, _ = fmt.Fprint(os.Stdout, args[0])
	}
	if len(args) > 1 {
		_, _ = fmt.Fprint(os.Stderr, args[1])
	}
	return 0
}

// helperEnv writes the child's environment, one entry per line, to the file
// named by its first argument.
func helperEnv(args []string) int {
	if len(args) != 1 {
		return 99
	}
	if err := os.WriteFile(args[0], []byte(strings.Join(os.Environ(), "\n")), 0o600); err != nil {
		return 99
	}
	return 0
}

// recordingRevoker counts revocations.
type recordingRevoker struct{ calls int }

func (r *recordingRevoker) RevokeToken() error {
	r.calls++
	return nil
}

// isolateTemp points the process temporary directory at an empty directory so
// a test can assert that the runner left nothing behind.
func isolateTemp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, key := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(key, dir)
	}
	return dir
}

func assertEmptyDir(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		t.Errorf("temporary directory still contains %s", entry.Name())
	}
}

// captureStreams runs fn with os.Stdout and os.Stderr redirected to regular
// files and returns what the runner and its child wrote.
func captureStreams(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()
	dir := t.TempDir()
	files := make([]*os.File, 2)
	for i, name := range []string{"stdout", "stderr"} {
		file, err := os.Create(dir + string(os.PathSeparator) + name)
		if err != nil {
			t.Fatal(err)
		}
		files[i] = file
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = files[0], files[1]
	func() {
		defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()
		fn()
	}()
	contents := make([]string, 2)
	for i, file := range files {
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(file.Name())
		if err != nil {
			t.Fatal(err)
		}
		contents[i] = string(data)
	}
	return contents[0], contents[1]
}
