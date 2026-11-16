package api

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

// FuzzRequestPath checks that path validation and net/http agree. For any
// secret path or auth mount the validators accept, the request that leaves
// the client must target exactly the intended API path on the configured
// host: no query, no fragment, no dot segments and no way to leave /v1/auth
// for a login. A path the validators reject must not produce a request.
func FuzzRequestPath(f *testing.F) {
	for _, seed := range []string{
		"kv/app", "kv", "kvv1/team/app", "kv/path with spaces/ünïcode", "auth/gitlab", "gitlab", "team/jwt",
		"kv/../sys/seal", "kv/./app", "kv//app", "/kv/app", "kv/app/", "kv/app?list=true", "kv/app#frag",
		"kv/%2e%2e/sys", `kv\app`, "sys/seal", "auth/token/lookup-self", "kv/a;b=c/d", "kv/a:b@c", "kv/\x00", "kv/\n",
		"..", ".", "", "auth/", "auth", "kv/...", "a/b/c/d/e/f",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, path string) {
		var sent []*http.Request
		client := &Client{
			addr: "http://vault.invalid:8200",
			ctx:  context.Background(),
			http: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				sent = append(sent, req)
				body := `{"auth":{"client_token":"t"},"data":{"data":{"k":"v"},"k":"v"}}`
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
			})},
		}
		check := func(operation, want string, accepted bool) {
			t.Helper()
			requests := sent
			sent = nil
			if !accepted {
				if len(requests) != 0 {
					t.Fatalf("%s: rejected path %q still sent %s", operation, path, requests[0].URL)
				}
				return
			}
			// Request construction may still refuse a path, which fails closed.
			if len(requests) == 0 {
				return
			}
			if len(requests) != 1 {
				t.Fatalf("%s: path %q sent %d requests", operation, path, len(requests))
			}
			got := requests[0].URL
			if got.Host != "vault.invalid:8200" || got.Scheme != "http" || got.User != nil {
				t.Fatalf("%s: path %q changed the target to %s", operation, path, got)
			}
			if got.Path != want || got.RawQuery != "" || got.ForceQuery || got.Fragment != "" {
				t.Fatalf("%s: path %q requested %q (query %q, fragment %q), want %q", operation, path, got.Path, got.RawQuery, got.Fragment, want)
			}
			for _, segment := range strings.Split(got.Path, "/")[1:] {
				if segment == "" || segment == "." || segment == ".." {
					t.Fatalf("%s: path %q produced non-canonical request path %q", operation, path, got.Path)
				}
			}
			// The path on the wire must decode back to the same path.
			if decoded, err := got.Parse(got.RequestURI()); err != nil || decoded.Path != want {
				t.Fatalf("%s: path %q is sent as %q, which decodes to %v (%v)", operation, path, got.RequestURI(), decoded, err)
			}
		}

		mount, rest, _ := strings.Cut(path, "/")
		wantKV2 := "/v1/" + mount + "/data"
		if rest != "" {
			wantKV2 += "/" + rest
		}
		_, _ = client.ReadSecret(path, "k", 2)
		check("kv2 read", wantKV2, validateSecretPath(path, 2) == nil)

		_, _ = client.ReadSecret(path, "k", 1)
		check("kv1 read", "/v1/"+path, validateSecretPath(path, 1) == nil)
		if validateSecretPath(path, 1) == nil {
			if _, reserved := reservedLegacyPathPrefixes[strings.ToLower(mount)]; reserved {
				t.Fatalf("legacy read accepted reserved path %q", path)
			}
		}

		loginPath, err := authLoginPath(path)
		_ = client.LoginJWTAt(path, "role", "jwt")
		check("jwt login", "/v1/auth/"+strings.TrimPrefix(path, "auth/")+"/login", err == nil)
		_ = client.LoginAppRoleAt(path, "id", "secret")
		check("approle login", "/v1/auth/"+strings.TrimPrefix(path, "auth/")+"/login", err == nil)
		if err == nil && (!strings.HasPrefix(loginPath, "/v1/auth/") || !strings.HasSuffix(loginPath, "/login")) {
			t.Fatalf("auth path %q became %q", path, loginPath)
		}
	})
}
