//go:build integration && !windows

package integration

import (
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"
)

func runSignalTests(t *testing.T, s *suite) {
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
		t.Run("signal-"+sig.String(), func(t *testing.T) {
			c := s.scenario(t)
			token := s.token(t)
			c.env["BAO_TOKEN"] = token
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
			s.assertToken(t, token, http.StatusForbidden)
			for _, path := range report.Files {
				assertAbsent(t, path)
			}
			select {
			case <-p.done:
				t.Fatal("wrapper exited before child was released")
			default:
			}
			mustWrite(t, c.report+".release", []byte("release"))
			c.finish(p, 0)
		})
	}
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
