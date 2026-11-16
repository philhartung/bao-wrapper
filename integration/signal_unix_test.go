//go:build integration && !windows

package integration

import (
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/philhartung/bao-wrapper/integration/testdata/probe"
)

func runSignalTests(t *testing.T, s *suite) {
	for _, policy := range []string{"auto", "always", "never"} {
		for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
			t.Run("signal-"+sig.String()+"-"+policy, func(t *testing.T) {
				c := s.scenario(t)
				token := s.token(t)
				c.env["BAO_TOKEN"] = token
				c.env["BAO_REVOKE_TOKEN"] = policy
				c.env["SECRET_CERT_FILE"] = "kv://certificate:file@kv/integration/app"
				c.spec.Files = map[string]string{"CERT_FILE": certificate}
				c.spec.Signal = true
				p := c.start(nil)
				waitFor(t, "child readiness", func() bool { _, err := os.Stat(c.report + ".ready"); return err == nil })
				report := c.reportData()
				if len(report.Files) != 1 {
					t.Fatal("child did not verify the secret file")
				}
				if err := p.cmd.Process.Signal(sig); err != nil {
					t.Fatal(err)
				}
				waitFor(t, "signal forwarding", func() bool {
					data, err := os.ReadFile(c.report + ".signal")
					return err == nil && string(data) == sig.String()
				})
				if policy == "always" {
					waitFor(t, "token revocation", func() bool {
						status, _, err := s.request(http.MethodGet, "/v1/auth/token/lookup-self", token, nil)
						if err != nil {
							t.Fatalf("token lookup failed: %v", err)
						}
						if status != http.StatusOK && status != http.StatusForbidden {
							t.Fatalf("unexpected lookup status: %d", status)
						}
						return status == http.StatusForbidden
					})
				}
				want := http.StatusOK
				if policy == "always" {
					want = http.StatusForbidden
				}
				s.assertToken(t, token, want)
				for _, path := range report.Files {
					waitFor(t, "file cleanup", func() bool { _, err := os.Stat(path); return os.IsNotExist(err) })
				}
				select {
				case <-p.done:
					t.Fatal("wrapper exited before child was released")
				default:
				}
				mustWrite(t, c.report+".release", []byte("release"))
				c.finish(p, 0)
				s.assertToken(t, token, want)
			})
		}
	}
	// Output written before the child blocks must be visible while it is still
	// running, even though a longer secret is registered for masking.
	t.Run("output-is-forwarded-while-child-runs", func(t *testing.T) {
		c := s.scenario(t)
		c.env["SECRET_CERT_FILE"] = "kv://certificate:file@kv/integration/app"
		c.env["SECRET_DB_PASSWORD"] = "kv://password@kv/integration/app"
		c.spec = probe.Spec{
			Files:  map[string]string{"CERT_FILE": certificate},
			Stdout: "step 42\npw=${DB_PASSWORD}\n", Stderr: "warn\n", Signal: true,
		}
		p := c.start(nil)
		waitFor(t, "child readiness", func() bool { _, err := os.Stat(c.report + ".ready"); return err == nil })
		waitFor(t, "stdout before child exit", func() bool { return c.stdout.String() == "step 42\npw=[MASKED]\n" })
		waitFor(t, "stderr before child exit", func() bool { return c.stderr.String() == "warn\n" })
		select {
		case <-p.done:
			t.Fatal("wrapper exited before the child was released")
		default:
		}
		if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "signal forwarding", func() bool { _, err := os.Stat(c.report + ".signal"); return err == nil })
		mustWrite(t, c.report+".release", []byte("release"))
		c.finish(p, 0)
	})
	// A repeated signal during shutdown must not change the outcome.
	t.Run("second-signal-during-shutdown", func(t *testing.T) {
		c := s.scenario(t)
		token := s.token(t)
		c.env["BAO_TOKEN"] = token
		c.env["BAO_REVOKE_TOKEN"] = "always"
		c.env["SECRET_CERT_FILE"] = "kv://certificate:file@kv/integration/app"
		c.spec = probe.Spec{Files: map[string]string{"CERT_FILE": certificate}, Signal: true}
		p := c.start(nil)
		waitFor(t, "child readiness", func() bool { _, err := os.Stat(c.report + ".ready"); return err == nil })
		report := c.reportData()
		for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT, syscall.SIGTERM} {
			if err := p.cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			waitFor(t, "signal forwarding", func() bool { _, err := os.Stat(c.report + ".signal"); return err == nil })
		}
		waitFor(t, "token revocation", func() bool {
			status, _, err := s.request(http.MethodGet, "/v1/auth/token/lookup-self", token, nil)
			return err == nil && status == http.StatusForbidden
		})
		for _, path := range report.Files {
			waitFor(t, "file cleanup", func() bool { _, err := os.Stat(path); return os.IsNotExist(err) })
		}
		select {
		case <-p.done:
			t.Fatal("wrapper exited before the child was released")
		default:
		}
		mustWrite(t, c.report+".release", []byte("release"))
		c.finish(p, 0)
		if strings.Contains(c.stderr.String(), "error:") {
			t.Errorf("repeated signals produced an error:\n%s", c.stderr.String())
		}
	})
}

func waitFor(t *testing.T, description string, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}
