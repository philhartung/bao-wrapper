package api_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/philhartung/bao-wrapper/api"
)

// serveBody returns a client for a server that answers every request with body.
func serveBody(t *testing.T, status int, body string) (*api.Client, *[]*http.Request) {
	t.Helper()
	var requests []*http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return api.New(srv.URL, ""), &requests
}

// Non-string values are returned in their JSON text form so numbers and
// structured values can be injected without a schema.
func TestReadSecret_NonStringFieldsUseJSONText(t *testing.T) {
	client, _ := serveBody(t, http.StatusOK, `{"data":{"data":{
		"count": 7, "ratio": 1.5, "object": {"a": 1, "b": "two"}, "list": [1, "x"], "text": "plain \"quoted\" text"
	}}}`)
	for field, want := range map[string]string{
		"count":  "7",
		"ratio":  "1.5",
		"object": `{"a": 1, "b": "two"}`,
		"list":   `[1, "x"]`,
		"text":   `plain "quoted" text`,
	} {
		got, err := client.ReadSecret("kv/app", field, 2)
		if err != nil {
			t.Errorf("field %s: %v", field, err)
		}
		if got != want {
			t.Errorf("field %s = %q, want %q", field, got, want)
		}
	}
}

func TestReadSecret_FullJSONIsCompactAndSorted(t *testing.T) {
	for version, body := range map[int]string{
		2: `{"data":{"data":{"zeta": "last", "alpha": 1}}}`,
		1: `{"data":{"zeta": "last", "alpha": 1}}`,
	} {
		client, _ := serveBody(t, http.StatusOK, body)
		got, err := client.ReadSecret("kv/app", "", version)
		if err != nil {
			t.Fatalf("KV v%d: %v", version, err)
		}
		if want := `{"alpha":1,"zeta":"last"}`; got != want {
			t.Errorf("KV v%d full JSON = %q, want %q", version, got, want)
		}
	}
}

func TestReadSecret_RequestPaths(t *testing.T) {
	for _, tc := range []struct {
		path    string
		version int
		want    string
	}{
		{"kv/app", 2, "/v1/kv/data/app"},
		{"kv/team/app/db", 2, "/v1/kv/data/team/app/db"},
		{"kv", 2, "/v1/kv/data"},
		{"kvv1/team/app", 1, "/v1/kvv1/team/app"},
		{"kv/path with spaces/ünïcode", 2, "/v1/kv/data/path with spaces/ünïcode"},
	} {
		client, requests := serveBody(t, http.StatusOK, `{"data":{"data":{"k":"v"},"k":"v"}}`)
		client.SetToken("request-token")
		if _, err := client.ReadSecret(tc.path, "k", tc.version); err != nil {
			t.Errorf("%s: %v", tc.path, err)
			continue
		}
		if len(*requests) != 1 {
			t.Errorf("%s: %d requests", tc.path, len(*requests))
			continue
		}
		request := (*requests)[0]
		if request.Method != http.MethodGet || request.URL.Path != tc.want || request.URL.RawQuery != "" {
			t.Errorf("%s: got %s %s?%s, want GET %s", tc.path, request.Method, request.URL.Path, request.URL.RawQuery, tc.want)
		}
		if got := request.Header.Get("X-Vault-Token"); got != "request-token" {
			t.Errorf("%s: token header = %q", tc.path, got)
		}
	}
}

// Malformed or incomplete responses must fail without echoing the body, which
// may contain secret material.
func TestReadSecret_MalformedResponses(t *testing.T) {
	const marker = "response-secret-marker"
	for name, tc := range map[string]struct {
		body    string
		field   string
		version int
		want    string
	}{
		"not JSON":             {`<html>` + marker, "k", 2, "parse secret outer"},
		"no data":              {`{"warnings":["` + marker + `"]}`, "k", 2, "no 'data' field"},
		"kv2 null inner data":  {`{"data":{"data":null,"metadata":{"x":"` + marker + `"}}}`, "k", 2, "requested field not found"},
		"kv2 inner not object": {`{"data":{"data":"` + marker + `"}}`, "k", 2, "parse kv2 data wrapper"},
		"kv1 data not object":  {`{"data":"` + marker + `"}`, "k", 1, "parse kv1 data"},
		"missing field":        {`{"data":{"data":{"other":"` + marker + `"}}}`, "k", 2, "requested field not found"},
	} {
		t.Run(name, func(t *testing.T) {
			client, _ := serveBody(t, http.StatusOK, tc.body)
			value, err := client.ReadSecret("kv/app", tc.field, tc.version)
			if err == nil {
				t.Fatalf("expected an error, got value %q", value)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
			if strings.Contains(err.Error(), marker) {
				t.Errorf("error exposes response content: %q", err)
			}
		})
	}
}

// Credentials and the namespace travel in headers on every kind of request,
// and a login never sends a stale token.
func TestRequests_CarryNamespaceAndToken(t *testing.T) {
	var requests []*http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		switch r.URL.Path {
		case "/v1/auth/approle/login":
			_, _ = io.WriteString(w, `{"auth":{"client_token":"issued-token"}}`)
		case "/v1/auth/token/revoke-self":
			w.WriteHeader(http.StatusNoContent)
		default:
			_, _ = io.WriteString(w, `{"data":{"data":{"k":"v"}}}`)
		}
	}))
	defer srv.Close()

	client := api.New(srv.URL+"/", "team/namespace")
	if err := client.LoginAppRole("role", "secret"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ReadSecret("kv/app", "k", 2); err != nil {
		t.Fatal(err)
	}
	if err := client.RevokeToken(); err != nil {
		t.Fatal(err)
	}
	wantTokens := []string{"", "issued-token", "issued-token"}
	if len(requests) != len(wantTokens) {
		t.Fatalf("got %d requests, want %d", len(requests), len(wantTokens))
	}
	for i, request := range requests {
		if got := request.Header.Get("X-Vault-Namespace"); got != "team/namespace" {
			t.Errorf("request %d (%s): namespace = %q", i, request.URL.Path, got)
		}
		if got := request.Header.Get("X-Vault-Token"); got != wantTokens[i] {
			t.Errorf("request %d (%s): token = %q, want %q", i, request.URL.Path, got, wantTokens[i])
		}
		if strings.HasPrefix(request.URL.Path, "//") {
			t.Errorf("request %d: trailing slash in the address produced path %q", i, request.URL.Path)
		}
	}
}

// path.Clean leaves leading dot segments in place, so they need their own
// check: once a proxy or the server normalizes the URL, "../v1/sys/mounts"
// would address a system endpoint from a KV reference.
func TestReadSecret_RejectsDotSegments(t *testing.T) {
	for _, path := range []string{
		"..", ".", "../x", "../v1/sys/mounts", "../v1/auth/token/lookup-self", "../../etc", "./kv/app", "kv/..", "kv/.",
	} {
		for _, version := range []int{1, 2} {
			client, requests := serveBody(t, http.StatusOK, `{"data":{"data":{"k":"v"},"k":"v"}}`)
			value, err := client.ReadSecret(path, "k", version)
			if err == nil || !strings.Contains(err.Error(), "secret path must be canonical") {
				t.Errorf("KV v%d path %q: got value %q, error %v", version, path, value, err)
			}
			if len(*requests) != 0 {
				t.Errorf("KV v%d path %q: a request was sent to %s", version, path, (*requests)[0].URL.Path)
			}
		}
	}
}
