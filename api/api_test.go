package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
