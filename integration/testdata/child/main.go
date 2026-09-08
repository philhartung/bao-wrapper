package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/philhartung/bao-wrapper/integration/testdata/probe"
)

func main() {
	// A broken wrapper must not leave a blocked child behind in CI.
	time.AfterFunc(20*time.Second, func() { os.Exit(124) })
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(90)
	}
}

func run() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("expected spec and report paths")
	}
	data, err := os.ReadFile(os.Args[1]) // #nosec G703 -- integration harness supplies the spec path in its temporary directory
	if err != nil {
		return err
	}
	var spec probe.Spec
	if err := json.Unmarshal(data, &spec); err != nil {
		return err
	}
	report := probe.Report{PID: os.Getpid(), Files: map[string]string{}}
	// Record entry before validation, so failures cannot be mistaken for a
	// wrapper that correctly refused to launch its child.
	if err := writeReport(os.Args[2], report); err != nil {
		return err
	}
	for key, want := range spec.Env {
		if got, ok := os.LookupEnv(key); !ok || got != want {
			return fmt.Errorf("unexpected environment value for %s", key)
		}
	}
	for _, key := range spec.Absent {
		if _, ok := os.LookupEnv(key); ok {
			return fmt.Errorf("forbidden environment variable %s", key)
		}
	}
	values := map[string]string{}
	for key, want := range spec.Files {
		path := os.Getenv(key)
		data, err := os.ReadFile(path) // #nosec G304 G703 -- test child intentionally reads wrapper-generated secret paths from the environment
		if err != nil {
			return err
		}
		if string(data) != want {
			return fmt.Errorf("unexpected file contents for %s", key)
		}
		for _, previous := range report.Files {
			if previous == path {
				return fmt.Errorf("file secrets share a path")
			}
		}
		if runtime.GOOS != "windows" {
			for name, mode := range map[string]os.FileMode{path: 0600, filepath.Dir(path): 0700} {
				info, err := os.Stat(name)
				if err != nil {
					return err
				}
				if info.Mode().Perm() != mode {
					return fmt.Errorf("unexpected permissions: %s", name)
				}
			}
		}
		values[key] = string(data)
		report.Files[key] = path
	}
	if !slices.Equal(os.Args[3:], spec.Args) {
		return fmt.Errorf("arguments changed in transit")
	}
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	if string(input) != spec.Input {
		return fmt.Errorf("stdin changed in transit")
	}
	expand := func(s string) string {
		return os.Expand(s, func(key string) string {
			if value, ok := values[key]; ok {
				return value
			}
			return os.Getenv(key)
		})
	}
	if _, err := io.Copy(os.Stdout, strings.NewReader(expand(spec.Stdout))); err != nil {
		return err
	}
	if _, err := io.Copy(os.Stderr, strings.NewReader(expand(spec.Stderr))); err != nil {
		return err
	}
	if err := writeReport(os.Args[2], report); err != nil {
		return err
	}
	if spec.Signal {
		return waitForSignal(os.Args[2])
	}
	os.Exit(spec.ExitCode)
	return nil
}

func writeReport(path string, report probe.Report) error {
	data, err := json.Marshal(report)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600) // #nosec G703 -- integration harness supplies the report path in its temporary directory
}
