package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func tokenPolicyEnv(t *testing.T, addr string) {
	t.Helper()
	for _, prefix := range []string{"BAO_", "VAULT_"} {
		for _, key := range []string{"TOKEN", "JWT_ROLE", "JWT_TOKEN", "APP_ID", "APP_SECRET", "AUTH_PATH", "NAMESPACE", "CACERT", "MAX_RESPONSE_BYTES", "REVOKE_TOKEN"} {
			t.Setenv(prefix+key, "")
		}
	}
	t.Setenv("BAO_ADDR", addr)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	t.Setenv(successfulRunChildHelperEnv, "1")
}

func TestTokenPolicyFailedChild(t *testing.T) {
	if os.Getenv("GO_WANT_POLICY_FAILED_CHILD") == "1" {
		os.Exit(23)
	}
}

func TestTokenPolicyLifecycle(t *testing.T) {
	for _, source := range []string{"BAO_TOKEN", "VAULT_TOKEN", "jwt", "approle", "none", "failed-login"} {
		for _, policy := range []string{"", "auto", "always", "never"} {
			for _, outcome := range []string{"success", "child-failure", "start-failure", "parse-failure", "fetch-failure", "render-failure"} {
				t.Run(source+"/"+policy+"/"+outcome, func(t *testing.T) {
					revocations, logins := 0, 0
					srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						switch r.URL.Path {
						case "/v1/auth/jwt/login", "/v1/auth/approle/login":
							logins++
							if source == "failed-login" {
								http.Error(w, "denied", http.StatusForbidden)
								return
							}
							_, _ = fmt.Fprint(w, `{"auth":{"client_token":"issued-token"}}`)
						case "/v1/auth/token/revoke-self":
							revocations++
							want := "issued-token"
							if source == "BAO_TOKEN" || source == "VAULT_TOKEN" {
								want = "borrowed-token"
							}
							if got := r.Header.Get("X-Vault-Token"); got != want {
								t.Errorf("revoked token %q, want %q", got, want)
							}
							w.WriteHeader(http.StatusNoContent)
						default:
							http.NotFound(w, r)
						}
					}))
					defer srv.Close()
					tokenPolicyEnv(t, srv.URL)
					t.Setenv("BAO_REVOKE_TOKEN", policy)
					switch source {
					case "BAO_TOKEN", "VAULT_TOKEN":
						t.Setenv(source, "borrowed-token")
					case "jwt", "failed-login":
						t.Setenv("BAO_JWT_ROLE", "role")
						t.Setenv("BAO_JWT_TOKEN", "jwt")
					case "approle":
						t.Setenv("BAO_APP_ID", "id")
						t.Setenv("BAO_APP_SECRET", "secret")
					}
					t.Setenv("POLICY_TEST_SECRET", "")
					child := []string{os.Args[0], "-test.run=^TestSuccessfulRunChildHelper$"}
					switch outcome {
					case "child-failure":
						t.Setenv("GO_WANT_POLICY_FAILED_CHILD", "1")
						child = []string{os.Args[0], "-test.run=^TestTokenPolicyFailedChild$"}
					case "start-failure":
						child = []string{"/nonexistent-bao-policy-child"}
					case "parse-failure":
						t.Setenv("POLICY_TEST_SECRET", "kv://field:invalid@kv/missing")
					case "fetch-failure":
						t.Setenv("POLICY_TEST_SECRET", "kv://field@kv/missing")
					case "render-failure":
						t.Setenv("POLICY_TEST_SECRET", "template://tpl@kv/missing")
					}
					args := append([]string{"run", "--secret-prefix", "POLICY_TEST_", "--"}, child...)
					wantCode := 0
					if outcome != "success" || source == "failed-login" {
						wantCode = 1
					}
					if outcome == "child-failure" && source != "failed-login" {
						wantCode = 23
					}
					if got := run(args); got != wantCode {
						t.Errorf("exit=%d, want %d", got, wantCode)
					}
					owned := source == "jwt" || source == "approle"
					present := owned || source == "BAO_TOKEN" || source == "VAULT_TOKEN"
					wantRevocations := 0
					if present && (policy == "always" || (policy != "never" && owned)) {
						wantRevocations = 1
					}
					if revocations != wantRevocations {
						t.Errorf("revocations=%d, want %d", revocations, wantRevocations)
					}
					wantLogins := 0
					if owned || source == "failed-login" {
						wantLogins = 1
					}
					if logins != wantLogins {
						t.Errorf("logins=%d, want %d", logins, wantLogins)
					}
				})
			}
		}
	}
}

func TestTokenPolicyOptions(t *testing.T) {
	for _, tc := range []struct {
		name, env       string
		opts            []string
		invalid, revoke bool
	}{
		{name: "default"},
		{name: "env-always", env: "always", revoke: true},
		{name: "equals", opts: []string{"--revoke-token=always"}, revoke: true},
		{name: "separate", opts: []string{"--revoke-token", "always"}, revoke: true},
		{name: "override", env: "always", opts: []string{"--revoke-token=auto"}},
		{name: "override-invalid-env", env: "bad", opts: []string{"--revoke-token=never"}},
		{name: "last-wins", opts: []string{"--revoke-token=always", "--revoke-token", "never"}},
		{name: "missing", opts: []string{"--revoke-token"}, invalid: true},
		{name: "empty", opts: []string{"--revoke-token="}, invalid: true},
		{name: "empty-separate", opts: []string{"--revoke-token", ""}, invalid: true},
		{name: "invalid-env", env: "bad", invalid: true},
		{name: "uppercase", opts: []string{"--revoke-token=ALWAYS"}, invalid: true},
		{name: "whitespace", env: " auto", invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; w.WriteHeader(http.StatusNoContent) }))
			defer srv.Close()
			tokenPolicyEnv(t, srv.URL)
			t.Setenv("BAO_TOKEN", "borrowed")
			t.Setenv("BAO_REVOKE_TOKEN", tc.env)
			args := append([]string{"run", "--secret-prefix", "POLICY_OPTIONS_"}, tc.opts...)
			args = append(args, "--", os.Args[0], "-test.run=^TestSuccessfulRunChildHelper$")
			want := 0
			if tc.invalid {
				want = 1
			}
			if code := run(args); code != want {
				t.Errorf("exit=%d, want %d", code, want)
			}
			wantRequests := 0
			if tc.revoke {
				wantRequests = 1
			}
			if requests != wantRequests {
				t.Errorf("requests=%d, want %d", requests, wantRequests)
			}
		})
	}
}
