package runner

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/philhartung/bao-wrapper/parser"
)

func envSecret(name, value string) SecretValue {
	return SecretValue{Ref: parser.SecretRef{Type: parser.TypeEnv, EnvName: name, Engine: "kv"}, Value: value}
}

func fileSecret(name, value string) SecretValue {
	return SecretValue{Ref: parser.SecretRef{Type: parser.TypeFile, EnvName: name, Engine: "kv"}, Value: value}
}

func childEnv(t *testing.T, path string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("child did not write its environment: %v", err)
	}
	env := map[string]string{}
	for _, entry := range strings.Split(string(data), "\n") {
		key, value, _ := strings.Cut(entry, "=")
		if _, duplicate := env[key]; duplicate {
			t.Errorf("child environment contains %s more than once", key)
		}
		env[key] = value
	}
	return env
}

func TestRunRequiresCommand(t *testing.T) {
	temp := isolateTemp(t)
	revoker := &recordingRevoker{}
	code, err := Run(nil, []SecretValue{fileSecret("UNUSED", "value")}, revoker, "SECRET_")
	if code != 1 || err == nil || !strings.Contains(err.Error(), "no command specified") {
		t.Fatalf("Run() = %d, %v", code, err)
	}
	assertEmptyDir(t, temp)
}

// Secrets reach the child as environment variables or 0600 files, override
// inherited variables of the same name, and leave nothing behind afterwards.
func TestRunDeliversSecretsAndCleansUp(t *testing.T) {
	temp := isolateTemp(t)
	t.Setenv("RUNNER_TEST_OVERRIDDEN", "inherited-value")
	t.Setenv("RUNNER_TEST_KEPT", "kept-value")
	t.Setenv("SECRET_RAW_REFERENCE", "kv://password@kv/app")
	t.Setenv("BAO_TOKEN", "wrapper-token")
	dump := filepath.Join(t.TempDir(), "env")
	revoker := &recordingRevoker{}

	code, err := Run(helperCommand("env", dump), []SecretValue{
		envSecret("RUNNER_TEST_OVERRIDDEN", "secret-value"),
		envSecret("RUNNER_TEST_EMPTY", ""),
		fileSecret("RUNNER_TEST_FILE", "file-contents"),
		envSecret("", "masking-only-value"),
	}, revoker, "SECRET_")
	if code != 0 || err != nil {
		t.Fatalf("Run() = %d, %v", code, err)
	}

	env := childEnv(t, dump)
	for key, want := range map[string]string{
		"RUNNER_TEST_OVERRIDDEN": "secret-value",
		"RUNNER_TEST_KEPT":       "kept-value",
		"RUNNER_TEST_EMPTY":      "",
	} {
		if got, ok := env[key]; !ok || got != want {
			t.Errorf("%s = %q (present: %v), want %q", key, got, ok, want)
		}
	}
	for _, key := range []string{"SECRET_RAW_REFERENCE", "BAO_TOKEN", ""} {
		if _, ok := env[key]; ok {
			t.Errorf("child received %q", key)
		}
	}
	for key, value := range env {
		if value == "masking-only-value" {
			t.Errorf("masking-only value was injected as %s", key)
		}
	}
	path := env["RUNNER_TEST_FILE"]
	if filepath.Base(path) != "RUNNER_TEST_FILE" || filepath.Dir(filepath.Dir(path)) != temp {
		t.Errorf("secret file path %q is not inside a private directory under %q", path, temp)
	}
	assertEmptyDir(t, temp)
	if revoker.calls != 1 {
		t.Errorf("revoker called %d times, want 1", revoker.calls)
	}
}

// Failures while preparing secret files or starting the child must still
// revoke the token and remove every file already written.
func TestRunCleansUpAfterStartupFailures(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	for _, tc := range []struct {
		name    string
		args    []string
		secrets []SecretValue
		want    string
	}{
		{"duplicate file name", helperCommand("exit"), []SecretValue{fileSecret("DUPLICATE", "first"), fileSecret("DUPLICATE", "second")}, "create secret file"},
		{"name with separator", helperCommand("exit"), []SecretValue{fileSecret("FIRST", "first"), fileSecret("nested/NAME", "second")}, "create secret file"},
		{"name escaping the directory", helperCommand("exit"), []SecretValue{fileSecret("../ESCAPED", "value")}, "create secret file"},
		{"command not found", []string{missing}, []SecretValue{fileSecret("WRITTEN", "value")}, "start process"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			temp := isolateTemp(t)
			revoker := &recordingRevoker{}
			code, err := Run(tc.args, tc.secrets, revoker, "SECRET_")
			if code != 1 || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Run() = %d, %v; want exit 1 and %q", code, err, tc.want)
			}
			for _, secret := range tc.secrets {
				if strings.Contains(err.Error(), secret.Value) {
					t.Errorf("error exposes a secret value: %v", err)
				}
			}
			assertEmptyDir(t, temp)
			if revoker.calls != 1 {
				t.Errorf("revoker called %d times, want 1", revoker.calls)
			}
		})
	}
}

func TestRunPreservesChildExitCode(t *testing.T) {
	isolateTemp(t)
	for _, want := range []int{0, 1, 3, 42, 125} {
		revoker := &recordingRevoker{}
		code, err := Run(helperCommand("exit", strconv.Itoa(want)), nil, revoker, "SECRET_")
		if code != want || err != nil {
			t.Errorf("Run() = %d, %v; want %d", code, err, want)
		}
		if revoker.calls != 1 {
			t.Errorf("exit %d: revoker called %d times", want, revoker.calls)
		}
	}
}

// Registered values are masked on both streams; a rendered template is not
// masked as a whole, only the inner values registered alongside it; values
// shorter than four bytes pass through.
func TestRunMasksChildOutput(t *testing.T) {
	isolateTemp(t)
	template := SecretValue{Ref: parser.SecretRef{Type: parser.TypeEnv, EnvName: "CONFIG", Engine: "template"}, Value: "user=app password=inner-secret-value"}
	secrets := []SecretValue{
		envSecret("TOKEN", "registered-token-value"),
		fileSecret("CERT", "certificate-material"),
		envSecret("PIN", "123"),
		template,
		envSecret("", "inner-secret-value"),
	}
	var code int
	var err error
	stdout, stderr := captureStreams(t, func() {
		code, err = Run(helperCommand("echo",
			"token=registered-token-value pin=123 config: user=app password=inner-secret-value\n",
			"cert=certificate-material\n"), secrets, nil, "SECRET_")
	})
	if code != 0 || err != nil {
		t.Fatalf("Run() = %d, %v", code, err)
	}
	if want := "token=[MASKED] pin=123 config: user=app password=[MASKED]\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if want := "cert=[MASKED]\n"; stderr != want {
		t.Errorf("stderr = %q, want %q", stderr, want)
	}
}
