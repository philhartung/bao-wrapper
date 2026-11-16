//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/philhartung/bao-wrapper/integration/testdata/probe"
)

//go:embed bootstrap.hcl
var bootstrap string

const (
	roleID            = "11111111-2222-3333-4444-555555555555"
	secretID          = "bao-wrapper-integration-secret-id"
	password          = "integration-db-password-7c21"
	extended          = "integration-db-password-7c21-extended-f84a"
	certificate       = "integration-certificate-material-4e98"
	legacy            = "integration-legacy-token-a913"
	namespace         = "bao-wrapper-test"
	namespaceRoleID   = "66666666-7777-8888-9999-000000000000"
	namespaceSecretID = "bao-wrapper-namespace-secret-id"
	namespacePassword = "integration-namespace-password-b629"
	shortTTLRoleID    = "22222222-3333-4444-5555-666666666666"
	shortTTLSecretID  = "bao-wrapper-short-ttl-secret-id"
	jwtIssuer         = "https://ci.bao-wrapper.test"
	jwtAudience       = "https://openbao.bao-wrapper.test"
	jwtProject        = "bao-wrapper/integration"
	rendered          = "database_password=" + password + "\nlegacy_token=" + legacy + "\nmode=production\n"
)

type suite struct {
	addr, wrapper, child string
	client               *http.Client
	// tlsAddr is a second, TLS-only listener of the same server; caFile is
	// the certificate that verifies it.
	tlsAddr, caFile string
	// jwtKey signs login tokens for the ci-jwt mount, which is configured with
	// its public half.
	jwtKey *ecdsa.PrivateKey
}

// lockedBuffer collects process output that tests read while the process is
// still running.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// freeAddr returns a loopback address that was free a moment ago.
func freeAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// newServerCertificate writes a self-signed certificate for 127.0.0.1 and its
// key into dir and returns their paths.
func newServerCertificate(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "bao-wrapper integration"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile = filepath.Join(dir, "server-cert.pem"), filepath.Join(dir, "server-key.pem")
	mustWrite(t, certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	mustWrite(t, keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certFile, keyFile
}

// jwt returns an ES256 token for the ci-jwt mount. Entries in overrides
// replace the default claims; a nil value removes a claim. A nil key selects
// the key the server trusts.
func (s *suite) jwt(t *testing.T, key *ecdsa.PrivateKey, overrides map[string]any) string {
	t.Helper()
	if key == nil {
		key = s.jwtKey
	}
	now := time.Now()
	claims := map[string]any{
		"iss": jwtIssuer, "aud": jwtAudience, "sub": "project_path:" + jwtProject,
		"project_path": jwtProject, "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
	for name, value := range overrides {
		if value == nil {
			delete(claims, name)
		} else {
			claims[name] = value
		}
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	encode := base64.RawURLEncoding.EncodeToString
	signingInput := encode([]byte(`{"alg":"ES256","typ":"JWT"}`)) + "." + encode(payload)
	digest := sha256.Sum256([]byte(signingInput))
	r, sig, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	sig.FillBytes(signature[32:])
	return signingInput + "." + encode(signature)
}

type process struct {
	cmd  *exec.Cmd
	done chan struct{}
	err  error
}

func startProcess(t *testing.T, cmd *exec.Cmd) *process {
	t.Helper()
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", filepath.Base(cmd.Path), err)
	}
	p := &process{cmd: cmd, done: make(chan struct{})}
	go func() { p.err = cmd.Wait(); close(p.done) }()
	t.Cleanup(func() { p.stop(t) })
	return p
}

func (p *process) stop(t *testing.T) {
	t.Helper()
	select {
	case <-p.done:
		return
	default:
		_ = p.cmd.Process.Kill()
	}
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		t.Errorf("process %d was not reaped", p.cmd.Process.Pid)
	}
}

func newSuite(t *testing.T) *suite {
	t.Helper()
	bao := os.Getenv("BAO_TEST_BINARY")
	if bao == "" {
		bao = "bao"
	}
	bao, err := exec.LookPath(bao)
	if err != nil {
		t.Fatal("integration tests require OpenBao: install the version in integration/openbao.json on PATH or set BAO_TEST_BINARY")
	}
	bao, err = filepath.Abs(bao)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	// Exercise executable paths with spaces and Unicode on every platform.
	binDir := filepath.Join(root, "native tools ü")
	mustMkdir(t, binDir)
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	jwtKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwtPublicDER, err := x509.MarshalPKIXPublicKey(&jwtKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	jwtPublicKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: jwtPublicDER}))
	s := &suite{
		wrapper: filepath.Join(binDir, "bao-wrapper"+ext),
		child:   filepath.Join(binDir, "child"+ext),
		jwtKey:  jwtKey,
		client: &http.Client{
			Timeout:       2 * time.Second,
			Transport:     &http.Transport{Proxy: nil},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	t.Cleanup(s.client.CloseIdleConnections)
	for _, build := range []struct{ output, source string }{{s.wrapper, ".."}, {s.child, "./testdata/child"}} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		cmd := exec.CommandContext(ctx, "go", "build", "-o", build.output, build.source)
		cmd.WaitDelay = 2 * time.Second
		output, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("build %s: %v\n%s", build.source, err, output)
		}
	}
	for attempt := 0; attempt < 3; attempt++ {
		dir := filepath.Join(root, fmt.Sprintf("server-%d", attempt))
		mustMkdir(t, dir)
		addr, tlsAddr := freeAddr(t), freeAddr(t)
		s.addr, s.tlsAddr = "http://"+addr, "https://"+tlsAddr
		certFile, keyFile := newServerCertificate(t, dir)
		s.caFile = certFile
		config := fmt.Sprintf(`disable_clustering = true
api_addr = %q
listener "tcp" {
  address = %q
  tls_disable = true
}
listener "tcp" {
  address = %q
  tls_cert_file = %q
  tls_key_file = %q
}
storage "pebbledb" {
  path = %q
}
seal "static" {
  current_key_id = "bao-wrapper-integration-v1"
  current_key = "env://OPENBAO_STATIC_SEAL_KEY"
}
`, s.addr, addr, tlsAddr, filepath.ToSlash(certFile), filepath.ToSlash(keyFile), filepath.ToSlash(filepath.Join(dir, "data")))
		configPath := filepath.Join(dir, "server.hcl")
		mustWrite(t, configPath, []byte(config+bootstrap))
		logPath := filepath.Join(dir, "server.log")
		log, err := os.Create(logPath)
		if err != nil {
			t.Fatal(err)
		}
		// Registered before the process cleanup: the process is stopped before
		// closing/reading its log, including on Windows.
		t.Cleanup(func() {
			if err := log.Close(); err != nil {
				t.Error(err)
			}
			if t.Failed() {
				data, err := os.ReadFile(logPath)
				if err != nil {
					t.Error(err)
					return
				}
				t.Logf("OpenBao attempt %d:\n%s", attempt+1, data)
			}
		})
		ctx, cancel := context.WithTimeout(t.Context(), 6*time.Minute)
		t.Cleanup(cancel)
		cmd := exec.CommandContext(ctx, bao, "server", "-config="+configPath)
		cmd.Env = cleanEnv(map[string]string{
			"OPENBAO_STATIC_SEAL_KEY": "0123456789abcdef0123456789abcdef",
			"INTEGRATION_ROLE_ID":     roleID, "INTEGRATION_SECRET_ID": secretID,
			"INTEGRATION_JWT_PUBLIC_KEY": jwtPublicKey,
		})
		cmd.Stdout, cmd.Stderr = log, log
		p := startProcess(t, cmd)
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case <-p.done:
				deadline = time.Time{}
			default:
			}
			if deadline.IsZero() {
				break
			}
			status, _, err := s.request(http.MethodGet, "/v1/sys/health", "", nil)
			if err == nil && status == http.StatusOK {
				return s
			}
			time.Sleep(100 * time.Millisecond)
		}
		p.stop(t)
	}
	t.Fatal("OpenBao did not become ready after three isolated startup attempts")
	return nil
}

func cleanEnv(extra map[string]string) []string {
	values := map[string]string{}
	for _, key := range []string{"PATH", "HOME", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "USERPROFILE", "TEMP", "TMP", "TMPDIR"} {
		if value, ok := os.LookupEnv(key); ok {
			values[key] = value
		}
	}
	for key, value := range extra {
		values[key] = value
	}
	env := make([]string, 0, len(values))
	for key, value := range values {
		env = append(env, key+"="+value)
	}
	return env
}

func (s *suite) request(method, path, token string, data any) (int, []byte, error) {
	var body io.Reader
	if data != nil {
		encoded, err := json.Marshal(data)
		if err != nil {
			return 0, nil, err
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(method, s.addr+path, body)
	if err != nil {
		return 0, nil, err
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if data != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	result, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, result, err
}

func (s *suite) token(t *testing.T) string {
	t.Helper()
	status, body, err := s.request(http.MethodPost, "/v1/auth/ci-approle/login", "", map[string]string{"role_id": roleID, "secret_id": secretID})
	if err != nil || status != http.StatusOK {
		t.Fatalf("issue token: status=%d error=%v", status, err)
	}
	var result struct {
		Auth struct {
			Token string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if result.Auth.Token == "" {
		t.Fatal("login returned an empty token")
	}
	s.assertToken(t, result.Auth.Token, http.StatusOK)
	return result.Auth.Token
}

func (s *suite) assertToken(t *testing.T, token string, want int) {
	t.Helper()
	status, body, err := s.request(http.MethodGet, "/v1/auth/token/lookup-self", token, nil)
	if err != nil {
		t.Fatalf("token lookup failed: %v", err)
	}
	if status != want {
		t.Fatalf("token lookup status=%d, want %d", status, want)
	}
	if want == http.StatusForbidden {
		var result struct {
			Errors []string `json:"errors"`
		}
		if err := json.Unmarshal(body, &result); err != nil || len(result.Errors) == 0 {
			t.Fatal("token rejection did not contain an OpenBao error response")
		}
	}
}

type scenario struct {
	t                 *testing.T
	s                 *suite
	dir, temp, report string
	env               map[string]string
	spec              probe.Spec
	stdout, stderr    lockedBuffer
}

func (s *suite) scenario(t *testing.T) *scenario {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "case ü with spaces")
	clearTemp := filepath.Join(dir, "temporary files ü")
	mustMkdir(t, clearTemp)
	c := &scenario{t: t, s: s, dir: dir, temp: clearTemp, report: filepath.Join(dir, "report.json"), env: map[string]string{
		"BAO_ADDR": s.addr, "BAO_AUTH_PATH": "ci-approle", "BAO_APP_ID": roleID, "BAO_APP_SECRET": secretID,
		"TMPDIR": clearTemp, "TMP": clearTemp, "TEMP": clearTemp,
	}}
	return c
}

func (c *scenario) start(options []string, child ...string) *process {
	c.t.Helper()
	data, err := json.Marshal(c.spec)
	if err != nil {
		c.t.Fatal(err)
	}
	specPath := filepath.Join(c.dir, "spec.json")
	mustWrite(c.t, specPath, data)
	if child == nil {
		child = append([]string{c.s.child, specPath, c.report}, c.spec.Args...)
	}
	args := append([]string{"run"}, options...)
	args = append(args, "--")
	args = append(args, child...)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	c.t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, c.s.wrapper, args...)
	cmd.Dir = c.dir
	cmd.Env = cleanEnv(c.env)
	cmd.Stdin = strings.NewReader(c.spec.Input)
	cmd.Stdout, cmd.Stderr = &c.stdout, &c.stderr
	p := startProcess(c.t, cmd)
	// This cleanup runs before stopping the wrapper, allowing it to reap a
	// stuck child. The child also has its own deadline as a final backstop.
	c.t.Cleanup(func() {
		select {
		case <-p.done:
			return
		default:
		}
		data, err := os.ReadFile(c.report)
		if err != nil {
			return
		}
		var report probe.Report
		if json.Unmarshal(data, &report) == nil && report.PID > 0 {
			if child, err := os.FindProcess(report.PID); err == nil {
				_ = child.Kill()
				_ = child.Release()
				select {
				case <-p.done:
				case <-time.After(2 * time.Second):
				}
			}
		}
	})
	return p
}

func (c *scenario) finish(p *process, want int) {
	c.t.Helper()
	select {
	case <-p.done:
	case <-time.After(35 * time.Second):
		c.t.Fatal("wrapper did not exit before its deadline")
	}
	var exitErr *exec.ExitError
	if p.err != nil && !errors.As(p.err, &exitErr) {
		c.t.Fatalf("wrapper execution: %v", p.err)
	}
	if got := p.cmd.ProcessState.ExitCode(); got != want {
		c.t.Fatalf("wrapper exit=%d, want %d\nstdout:\n%s\nstderr:\n%s", got, want, &c.stdout, &c.stderr)
	}
	for _, secret := range []string{
		password, extended, certificate, legacy, secretID, namespacePassword, namespaceSecretID, shortTTLSecretID,
		c.env["BAO_TOKEN"], c.env["BAO_APP_SECRET"], c.env["BAO_JWT_TOKEN"], c.env["VAULT_JWT_TOKEN"],
		c.env["BAO_UNUSED_FIXTURE"], c.env["VAULT_UNUSED_FIXTURE"], c.env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"],
	} {
		if secret != "" && (strings.Contains(c.stdout.String(), secret) || strings.Contains(c.stderr.String(), secret)) {
			c.t.Error("raw fixture credential appeared in wrapper output")
		}
	}
	entries, err := os.ReadDir(c.temp)
	if err != nil {
		c.t.Fatal(err)
	}
	if len(entries) != 0 {
		c.t.Error("wrapper left temporary secret directories behind")
	}
}

func (c *scenario) reportData() probe.Report {
	c.t.Helper()
	data, err := os.ReadFile(c.report)
	if err != nil {
		c.t.Fatal(err)
	}
	var report probe.Report
	if err := json.Unmarshal(data, &report); err != nil {
		c.t.Fatal(err)
	}
	return report
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func assertAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected absent path %s, got %v", path, err)
	}
}

func assertContains(t *testing.T, text, want string) {
	t.Helper()
	if !strings.Contains(text, want) {
		t.Errorf("missing %q in output:\n%s", want, text)
	}
}
