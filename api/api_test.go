package api_test

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/philhartung/bao-wrapper/api"
)

// --- LoginJWT ---

func TestLoginJWT_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/auth/jwt/login" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}

		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["role"] != "myrole" || body["jwt"] != "myjwt" {
			t.Errorf("unexpected body: %v", body)
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"auth": map[string]interface{}{
				"client_token": "s.testtoken",
			},
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	defer srv.Close()

	c := api.New(srv.URL, "")
	if err := c.LoginJWT("myrole", "myjwt"); err != nil {
		t.Fatalf("LoginJWT error: %v", err)
	}
	if c.Token() != "s.testtoken" {
		t.Errorf("expected token s.testtoken, got %s", c.Token())
	}
}

func TestLoginJWTAt_CustomAuthPath(t *testing.T) {
	tests := []struct {
		name     string
		authPath string
		wantPath string
	}{
		{name: "mount name", authPath: "gitlab", wantPath: "/v1/auth/gitlab/login"},
		{name: "auth-relative path", authPath: "auth/jwt_v2", wantPath: "/v1/auth/jwt_v2/login"},
		{name: "nested mount", authPath: "team/jwt", wantPath: "/v1/auth/team/jwt/login"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tt.wantPath {
					t.Errorf("expected path %q, got %q", tt.wantPath, r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"auth":{"client_token":"s.custom"}}`))
			}))
			defer srv.Close()

			c := api.New(srv.URL, "")
			if err := c.LoginJWTAt(tt.authPath, "myrole", "myjwt"); err != nil {
				t.Fatalf("LoginJWTAt error: %v", err)
			}
			if c.Token() != "s.custom" {
				t.Errorf("expected token s.custom, got %s", c.Token())
			}
		})
	}
}

func TestLoginAt_RejectsInvalidAuthPath(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	invalid := []string{
		"",
		"/auth/jwt",
		"auth/",
		"auth//jwt",
		"auth/../jwt",
		"../jwt",
		".",
		"..",
		"jwt/",
		`jwt\login`,
		"jwt%2flogin",
		"jwt?redirect=evil",
		"jwt#fragment",
	}

	for _, authPath := range invalid {
		t.Run(authPath, func(t *testing.T) {
			c := api.New(srv.URL, "")
			if err := c.LoginJWTAt(authPath, "role", "jwt"); err == nil {
				t.Fatal("expected invalid auth path to be rejected")
			}
			if c.Token() != "" {
				t.Error("invalid auth path must not store a token")
			}
		})
	}

	if requests != 0 {
		t.Fatalf("invalid auth paths caused %d HTTP requests", requests)
	}
}

func TestLoginJWT_MissingToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"auth": map[string]interface{}{},
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	defer srv.Close()

	c := api.New(srv.URL, "")
	if err := c.LoginJWT("role", "jwt"); err == nil {
		t.Fatal("expected error for missing client_token")
	}
}

func TestLoginJWT_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	c := api.New(srv.URL, "")
	if err := c.LoginJWT("role", "jwt"); err == nil {
		t.Fatal("expected error for HTTP 403")
	}
}

// --- LoginAppRole ---

func TestLoginAppRole_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/auth/approle/login" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}

		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["role_id"] != "myroleid" || body["secret_id"] != "mysecretid" {
			t.Errorf("unexpected body: %v", body)
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"auth": map[string]interface{}{
				"client_token": "s.approletoken",
			},
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	defer srv.Close()

	c := api.New(srv.URL, "")
	if err := c.LoginAppRole("myroleid", "mysecretid"); err != nil {
		t.Fatalf("LoginAppRole error: %v", err)
	}
	if c.Token() != "s.approletoken" {
		t.Errorf("expected token s.approletoken, got %s", c.Token())
	}
}

func TestLoginAppRoleAt_CustomAuthPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/ci-approle/login" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"auth":{"client_token":"s.custom-approle"}}`))
	}))
	defer srv.Close()

	c := api.New(srv.URL, "")
	if err := c.LoginAppRoleAt("auth/ci-approle", "myroleid", "mysecretid"); err != nil {
		t.Fatalf("LoginAppRoleAt error: %v", err)
	}
	if c.Token() != "s.custom-approle" {
		t.Errorf("expected token s.custom-approle, got %s", c.Token())
	}
}

func TestLoginAppRole_MissingToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"auth": map[string]interface{}{},
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	defer srv.Close()

	c := api.New(srv.URL, "")
	if err := c.LoginAppRole("roleid", "secretid"); err == nil {
		t.Fatal("expected error for missing client_token")
	}
}

func TestLoginAppRole_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	c := api.New(srv.URL, "")
	if err := c.LoginAppRole("roleid", "secretid"); err == nil {
		t.Fatal("expected error for HTTP 403")
	}
}

func TestClientRejectsRedirects(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		request    func(*api.Client) error
	}{
		{
			name:       "token header on 302",
			statusCode: http.StatusFound,
			request: func(c *api.Client) error {
				c.SetToken("hvs.test-token")
				_, err := c.ReadSecret("kv/test", "value", 2)
				return err
			},
		},
		{
			name:       "JWT body on 307",
			statusCode: http.StatusTemporaryRedirect,
			request: func(c *api.Client) error {
				return c.LoginJWT("test-role", "test-jwt")
			},
		},
		{
			name:       "AppRole body on 308",
			statusCode: http.StatusPermanentRedirect,
			request: func(c *api.Client) error {
				return c.LoginAppRole("test-role-id", "test-secret-id")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			redirected := make(chan struct{}, 1)
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				redirected <- struct{}{}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer target.Close()

			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target.URL+"/collect", tt.statusCode)
			}))
			defer source.Close()

			if err := tt.request(api.New(source.URL, "")); err == nil {
				t.Fatalf("expected redirect status %d to be rejected", tt.statusCode)
			}

			select {
			case <-redirected:
				t.Fatal("redirect target received a request containing credentials")
			default:
			}
		})
	}
}

func TestClientResponseSizeLimit(t *testing.T) {
	responseBody := []byte(`{"data":{"data":{"field":"value"}}}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Force a chunked response so the client cannot rely on Content-Length
		// and must enforce the limit while reading the body.
		w.(http.Flusher).Flush()
		_, _ = w.Write(responseBody)
	}))
	defer srv.Close()

	t.Run("accepts body exactly at configured limit", func(t *testing.T) {
		c := api.New(srv.URL, "")
		if err := c.SetMaxResponseBytes(int64(len(responseBody))); err != nil {
			t.Fatalf("SetMaxResponseBytes error: %v", err)
		}

		value, err := c.ReadSecret("kv/test", "field", 2)
		if err != nil {
			t.Fatalf("ReadSecret error: %v", err)
		}
		if value != "value" {
			t.Fatalf("expected value, got %q", value)
		}
	})

	t.Run("rejects body over configured limit", func(t *testing.T) {
		limit := int64(len(responseBody) - 1)
		c := api.New(srv.URL, "")
		if err := c.SetMaxResponseBytes(limit); err != nil {
			t.Fatalf("SetMaxResponseBytes error: %v", err)
		}

		_, err := c.ReadSecret("kv/test", "field", 2)
		if err == nil || !strings.Contains(err.Error(), "response body exceeds") {
			t.Fatalf("expected response-size error, got %v", err)
		}
	})
}

func TestSetMaxResponseBytesRejectsInvalidLimits(t *testing.T) {
	for _, limit := range []int64{-1, 0, math.MaxInt64} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			if err := api.New("http://127.0.0.1", "").SetMaxResponseBytes(limit); err == nil {
				t.Fatalf("SetMaxResponseBytes(%d) succeeded", limit)
			}
		})
	}
}

// --- Namespace header ---

func TestNamespaceHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ns := r.Header.Get("X-Vault-Namespace")
		if ns != "mynamespace" {
			t.Errorf("expected namespace header mynamespace, got %q", ns)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"auth": map[string]interface{}{
				"client_token": "tok",
			},
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	defer srv.Close()

	c := api.New(srv.URL, "mynamespace")
	_ = c.LoginJWT("role", "jwt")
}

// --- ReadSecret KV v2 ---

func TestReadSecret_KV2_Field(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/kv/data/myapp/db" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"data": map[string]interface{}{
					"password": "super-secret",
				},
			},
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	defer srv.Close()

	c := api.New(srv.URL, "")
	c.SetToken("tok")

	val, err := c.ReadSecret("kv/myapp/db", "password", 2)
	if err != nil {
		t.Fatalf("ReadSecret error: %v", err)
	}
	if val != "super-secret" {
		t.Errorf("expected super-secret, got %s", val)
	}
}

func TestReadSecret_KV2_EmptyField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"data": map[string]interface{}{
					"foo": "bar",
					"baz": "qux",
				},
			},
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	defer srv.Close()

	c := api.New(srv.URL, "")
	c.SetToken("tok")

	val, err := c.ReadSecret("kv/myapp/db", "", 2)
	if err != nil {
		t.Fatalf("ReadSecret error: %v", err)
	}
	// Should be a JSON object string
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(val), &m); err != nil {
		t.Errorf("expected JSON map, got: %s", val)
	}
}

func TestReadSecret_KV1_Field(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/secret/myapp/db" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"password": "kv1-secret",
			},
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	defer srv.Close()

	c := api.New(srv.URL, "")
	c.SetToken("tok")

	val, err := c.ReadSecret("secret/myapp/db", "password", 1)
	if err != nil {
		t.Fatalf("ReadSecret KV1 error: %v", err)
	}
	if val != "kv1-secret" {
		t.Errorf("expected kv1-secret, got %s", val)
	}
}

func TestReadSecret_KV1_RejectsReservedAndNonCanonicalPaths(t *testing.T) {
	requestReceived := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestReceived = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	tests := []string{
		"",
		"auth/token/lookup-self",
		"AUTH/token/lookup-self",
		"sys/internal/ui/resultant-acl",
		"identity/entity/id/example",
		"cubbyhole/response",
		"/auth/token/lookup-self",
		"auth//token/lookup-self",
		"auth/./token/lookup-self",
		"auth/token/../token/lookup-self",
		`auth\token\lookup-self`,
		"auth%2Ftoken%2Flookup-self",
		"kvv1/path/",
		"kvv1/path?query",
		"kvv1/path#fragment",
	}

	for _, secretPath := range tests {
		t.Run(secretPath, func(t *testing.T) {
			requestReceived = false
			c := api.New(srv.URL, "")
			c.SetToken("tok")

			if _, err := c.ReadSecret(secretPath, "id", 1); err == nil {
				t.Fatal("ReadSecret succeeded, want validation error")
			}
			if requestReceived {
				t.Fatal("ReadSecret sent a request for a rejected path")
			}
		})
	}
}

func TestReadSecret_KV1_AllowsNonReservedPrefix(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth-secrets/integration/token" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"token": "kv1-secret"},
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	c := api.New(srv.URL, "")
	val, err := c.ReadSecret("auth-secrets/integration/token", "token", 1)
	if err != nil {
		t.Fatalf("ReadSecret error: %v", err)
	}
	if val != "kv1-secret" {
		t.Errorf("expected kv1-secret, got %s", val)
	}
}

func TestReadSecret_RejectsUnsupportedKVVersion(t *testing.T) {
	c := api.New("http://127.0.0.1", "")
	for _, version := range []int{0, 3} {
		if _, err := c.ReadSecret("kv/path", "field", version); err == nil {
			t.Errorf("ReadSecret with KV version %d succeeded, want error", version)
		}
	}
}

func TestReadSecret_MissingField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"data": map[string]interface{}{
					"other": "value",
				},
			},
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	defer srv.Close()

	c := api.New(srv.URL, "")
	c.SetToken("tok")

	_, err := c.ReadSecret("kv/path", "notexist", 2)
	if err == nil {
		t.Fatal("expected error for missing field")
	}
}

func TestReadSecret_HTTPErrorDoesNotExposePath(t *testing.T) {
	const configuredValue = "hunter2"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := api.New(srv.URL, "")
	_, err := c.ReadSecret(configuredValue, "", 2)
	if err == nil {
		t.Fatal("expected error for HTTP 404")
	}
	if strings.Contains(err.Error(), configuredValue) {
		t.Fatalf("API error exposed configured secret path: %q", err)
	}
	if !strings.Contains(err.Error(), "status 404") {
		t.Fatalf("API error should retain useful status information: %q", err)
	}
}

// --- RevokeToken ---

func TestRevokeToken(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/token/revoke-self" && r.Method == http.MethodPost {
			called = true
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()

	c := api.New(srv.URL, "")
	c.SetToken("tok")
	if err := c.RevokeToken(); err != nil {
		t.Fatalf("RevokeToken error: %v", err)
	}
	if !called {
		t.Error("revoke-self endpoint was not called")
	}
}
