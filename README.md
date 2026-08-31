# bao-wrapper

**bao-wrapper** is a CI-agnostic process wrapper for [OpenBao](https://openbao.org/) / [HashiCorp Vault](https://developer.hashicorp.com/vault).  
It fetches secrets at runtime, injects them into the child process's environment (or as temporary files), and masks them in real-time log output — all without touching the CI runner's own environment.

## Table of Contents

- [Key features](#key-features)
- [Installation](#installation)
  - [Verify release provenance](#verify-release-provenance)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Environment variables](#environment-variables)
  - [Secret variables](#secret-variables)
  - [Query parameters](#query-parameters)
- [Template engine](#template-engine)
- [Examples](#examples)
  - [GitLab CI](#example-gitlab-ci-pipeline)
  - [GitHub Actions](#example-github-actions-pipeline)
  - [AppRole Authentication](#example-approle-authentication)
- [Architecture](#architecture)
- [Security notes](#security-notes)
- [Development](#development)

## Key features

| Feature | Details |
|---|---|
| **Zero external dependencies** | Uses only the Go standard library (`net/http`, `encoding/json`, …) |
| **Secure token lifecycle** | Authenticates via direct token, JWT, or AppRole login and revokes the client token on exit |
| **Real-time log masking** | Chunk-boundary-safe masked writer replaces secrets with `[MASKED]` |
| **`env` and `file` injection** | Secrets are exposed as env vars or temp files (`0600` on Unix; inherited ACLs on Windows); sensitive config vars are stripped from the child process |
| **Template engine** | Go `text/template` rendering with in-template `{{ secret "..." }}` lookups and selective masking |
| **Outfile routing** | Write `type=file` secrets directly to a custom path via `?outfile=` query parameter |
| **Automatic retry** | Up to 3 retries with exponential backoff on transient server errors (502/503/504) |
| **No command injection** | Child process launched via `exec.Command`, never via a shell |
| **Cross-platform** | Linux, macOS (arm64/amd64), Windows (amd64) |

---

## Installation

### Download from GitHub Releases

```bash
# Linux amd64; update both values deliberately when upgrading.
BAO_WRAPPER_VERSION=v0.2.1
BAO_WRAPPER_SHA256=7268dac9d76b24c712217993b83755bcea1945f296a0ab306da78a0eb1949c56
curl -fsSLO "https://github.com/philhartung/bao-wrapper/releases/download/${BAO_WRAPPER_VERSION}/bao-wrapper-linux-amd64"
printf '%s  %s\n' "$BAO_WRAPPER_SHA256" bao-wrapper-linux-amd64 | sha256sum --check --strict
install -m 0755 bao-wrapper-linux-amd64 bao-wrapper
```

Available release assets:

| Platform | File |
|---|---|
| Linux amd64 | `bao-wrapper-linux-amd64` |
| Linux arm64 | `bao-wrapper-linux-arm64` |
| macOS amd64 | `bao-wrapper-darwin-amd64` |
| macOS arm64 (M-series) | `bao-wrapper-darwin-arm64` |
| Windows amd64 | `bao-wrapper-windows-amd64.exe` |

New releases also contain `SHA256SUMS`. The manifest and every binary have a GitHub build-provenance attestation tied to this repository's release workflow.

### Verify release provenance

For releases containing `SHA256SUMS`, download the manifest and selected binary from an explicit version, authenticate both with the [GitHub CLI](https://cli.github.com/), and only then install the binary:

```bash
BAO_WRAPPER_VERSION=vX.Y.Z # replace with the exact release being installed
curl -fsSLO "https://github.com/philhartung/bao-wrapper/releases/download/${BAO_WRAPPER_VERSION}/SHA256SUMS"
curl -fsSLO "https://github.com/philhartung/bao-wrapper/releases/download/${BAO_WRAPPER_VERSION}/bao-wrapper-linux-amd64"

gh attestation verify SHA256SUMS --repo philhartung/bao-wrapper
gh attestation verify bao-wrapper-linux-amd64 --repo philhartung/bao-wrapper
sha256sum --check --ignore-missing --strict SHA256SUMS
install -m 0755 bao-wrapper-linux-amd64 bao-wrapper
```

The attestation verifies the artifact's signed provenance; `SHA256SUMS` makes the release's complete digest set easy to inspect and use in systems that require a pinned checksum.

### Build from source

```bash
git clone https://github.com/philhartung/bao-wrapper.git
cd bao-wrapper
CGO_ENABLED=0 go build -o bao-wrapper .
```

---

## Quick Start

1. Download the binary (see [Installation](#installation)).
2. Set your Vault address and authentication variables.
3. Prefix every secret you need with `SECRET_` (or a custom prefix via `--secret-prefix`) and describe where to fetch it.
4. Wrap your command with `bao-wrapper run --`:

```bash
export BAO_ADDR="https://vault.example.com"
export BAO_JWT_ROLE="my-role"
export BAO_JWT_TOKEN="<jwt>"          # or use AppRole / GitHub Actions OIDC
export SECRET_DB_PASS="kv://password@kv/myapp/db"

bao-wrapper run -- ./my-app
```

The child process receives `DB_PASS=<actual value>` in its environment. The raw secret never appears in logs — it is replaced with `[MASKED]`. For full CI pipeline examples, see [GitLab CI](#gitlab-ci-pipeline) and [GitHub Actions](#github-actions-pipeline).

> **Note:** Variables with the secret prefix that use an unrecognised engine scheme (e.g. `SECRET_SCANNING_URL` set by CI platforms) are silently skipped.

---

## Usage

```
bao-wrapper run [options] -- <command> [args...]
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--secret-prefix <prefix>` | `SECRET_` | Prefix used to identify secret environment variables. Variables whose name starts with this prefix are parsed as secret references; the prefix is stripped before injecting the value into the child process. Can also be set via the `BAO_SECRET_PREFIX` environment variable; the CLI flag takes priority. |

### Environment variables

| Variable | Fallback | Required | Description |
|---|---|---|---|
| `BAO_ADDR` | `VAULT_ADDR` | **yes** | OpenBao/Vault server URL (e.g. `https://openbao.example.com`) |
| `BAO_NAMESPACE` | `VAULT_NAMESPACE` | no | Namespace |
| `BAO_TOKEN` | `VAULT_TOKEN` | no | Direct client token; takes priority over all login methods. Use when a token is already available (e.g. local dev, pre-issued tokens). **The token is revoked on exit** (normal exit, error, or SIGINT/SIGTERM) and cannot be reused afterwards, so do not supply a long-lived or shared static token that must survive multiple runs or jobs. |
| `BAO_JWT_ROLE` | `VAULT_JWT_ROLE` | no | JWT auth role (used when `BAO_TOKEN` is not set; skips JWT login when omitted) |
| `BAO_JWT_TOKEN` | `VAULT_JWT_TOKEN` | no | JWT token for authentication (auto-detected from GitHub Actions OIDC when unset) |
| `BAO_APP_ID` | `VAULT_APP_ID` | no | AppRole role ID (used when `BAO_TOKEN` and `BAO_JWT_ROLE` are not set) |
| `BAO_APP_SECRET` | `VAULT_APP_SECRET` | no | AppRole secret ID (used together with `BAO_APP_ID`) |
| `BAO_CACERT` | `VAULT_CACERT` | no | Path to a PEM-encoded CA certificate file (for self-signed or corporate CA) |
| `BAO_SECRET_PREFIX` | – | no | Prefix for secret variables (default: `SECRET_`); overridden by `--secret-prefix` |

> **Note:** `BAO_*` variables take priority. If a `BAO_*` variable is not set, the corresponding `VAULT_*` variable is used as a fallback for backwards compatibility with existing CI configurations. Authentication methods are tried in this order: `BAO_TOKEN` (direct token) → `BAO_JWT_ROLE`/`BAO_JWT_TOKEN` (JWT/OIDC) → `BAO_APP_ID`/`BAO_APP_SECRET` (AppRole).

### Secret variables

Define secrets with the configured prefix (default `SECRET_`) using this format:

```
<PREFIX><NAME>=<engine>://[[field][:type]@]path[?key=value&...]
```

An explicit supported engine scheme is required. Prefixed variables without one are ignored, preventing ambient `SECRET_*` passwords, tokens, or keys from being interpreted as Vault paths. The `field`, `type`, and query parameters remain optional.

| Component | Default | Description |
|---|---|---|
| `engine` | *(required)* | Secret engine type. Only `kv`, `legacy`, and `template` are supported. `kv` uses the KV v2 API path; `legacy` uses the KV v1 API path; `template` renders a Go template stored in KV. |
| `field` | *(empty)* | Key in the secret data; empty = full JSON. Requires `@` separator. |
| `type` | `env` | `env` = env var, `file` = temp file path. Specified as `field:type` before `@`. |
| `path` | *(required)* | Full path to the secret, including the mount point (e.g. `kv/test`, `kvv1/my/secret`) |
| `?key=value` | *(none)* | Optional query parameters after the path (e.g. `?outfile=./config.json`) |

| Engine | API path used | Description |
|---|---|---|
| `kv` | `GET /v1/<mount>/data/<secret_path>` (KV v2) | KV v2 secrets. The path includes the mount point; `/data/` is inserted automatically. Example: path `kv/test` → `/v1/kv/data/test` |
| `legacy` | `GET /v1/<path>` (KV v1) | KV v1 path style. The path is used as-is after validation. Example: path `kvv1/test` → `/v1/kvv1/test` |
| `template` | *(fetches template from KV v2, then renders)* | Fetches a Go `text/template` from a KV v2 path, renders it with `{{ secret "..." }}` support (see [Template engine](#template-engine)) |

> **Legacy path restrictions:** `legacy` accepts only canonical relative paths. Paths below OpenBao's reserved `auth/`, `sys/`, `identity/`, and `cubbyhole/` prefixes are rejected because these are system endpoints, not KV v1 mounts. This restriction also applies to `legacy://` references used inside templates.

The child process receives the bare name without the prefix.

#### Examples

```bash
# Full format: engine, field, type, and path (path includes mount point)
SECRET_DB_PASS=kv://password:env@kv/myapp/db

# Write TLS cert to a temp file; TLS_CERT contains the file path
SECRET_TLS_CERT=kv://cert:file@kv/myapp/tls

# Path only (no field or type — reads full JSON from kv)
SECRET_KEY=kv://kv/myapp/db

# Write a file secret to a custom path using outfile
SECRET_DOCKER_CFG=kv://config:file@kv/myapp/docker?outfile=.docker/config.json

# Use the template engine to render a config from a KV-stored template
SECRET_APP_CFG=template://tpl:file@kv/myapp/config?outfile=app.conf

# Legacy KV v1 engine
SECRET_TOKEN=legacy://token:env@kvv1/my/path
```

#### Query parameters

Query parameters can be appended to the path portion of a secret URL using standard `?key=value&...` syntax.

**`outfile`** — supported on `type=file` secrets. When set, the secret content is written directly to the specified path instead of a temporary file in the isolated temp directory.

- Parent directories are created automatically (`0750` on Unix; inherited ACLs on Windows).
- The file is atomically installed from an exclusively created, same-directory temporary file. Its permissions are `0600` on Unix; see the Windows ACL note under [Security notes](#security-notes).
- Temp-directory files (without `outfile`) still use `O_EXCL` for safety.

```bash
# Write the rendered output to .docker/config.json
SECRET_DOCKER_CFG=kv://config:file@kv/myapp/docker?outfile=.docker/config.json
```

---

## Template engine

The `template` engine fetches a Go [`text/template`](https://pkg.go.dev/text/template) from an OpenBao/Vault KV secret, renders it, and returns the result. This is useful for generating configuration files that embed multiple secrets.

### How it works

1. The raw template content is read from the KV v2 path specified in the `SecretRef` (mount, path, field).
2. The template is parsed and executed with a custom `{{ secret "url" }}` function.
3. Each `{{ secret "..." }}` call fetches the referenced secret value inline.
4. The fully rendered output replaces the secret value in the pipeline.

### Declaration syntax (full)

Use the `template` engine in the `SECRET_*` variable:

```bash
# Render template stored at KV path "kv/myapp/config", field "tpl",
# write result to app.conf
SECRET_APP_CFG=template://tpl:file@kv/myapp/config?outfile=app.conf

# Render template and inject as an env var
SECRET_APP_CFG=template://tpl@kv/myapp/config
```

### In-template syntax (reduced)

Inside the template, use `{{ secret "url" }}` to reference individual secrets. The in-template URL uses a reduced syntax compared to the main `SECRET_*` declaration:

```
{{ secret "[engine]://[field]@[path]" }}
```

**Restrictions for in-template URLs:**
- Only `kv` and `legacy` engines are allowed (no `template` recursion).
- Type selectors (`:env`, `:file`) are not allowed.
- Query parameters (`?key=value`) are not allowed.

### Template example

Suppose the KV path `kv/myapp/config` field `tpl` contains this Go template:

```
[database]
host = db.example.com
password = {{ secret "kv://password@kv/myapp/db" }}

[api]
token = {{ secret "kv://token@kv/myapp/api" }}
```

With the declaration:

```bash
SECRET_APP_CFG=template://tpl:file@kv/myapp/config?outfile=app.conf
```

bao-wrapper will:

1. Fetch the template from `kv/myapp/config` field `tpl`.
2. Resolve `{{ secret "kv://password@kv/myapp/db" }}` and `{{ secret "kv://token@kv/myapp/api" }}` by fetching each from OpenBao/Vault.
3. Write the rendered output to `app.conf`.
4. Expose `APP_CFG=app.conf` in the child process environment.

### Selective masking

The template engine applies selective masking to avoid over-masking while still protecting secret values:

- **Template skeleton** (the static text around `{{ secret }}` calls) is **not** masked. This prevents large rendered configs from triggering false-positive masking in log output.
- **Inner secret values** (each value resolved via `{{ secret "..." }}`) **are** registered with the masking writer. Any log output containing these values will show `[MASKED]`.

---

## Examples

### GitLab CI Pipeline

This example downloads `bao-wrapper` from a GitHub release, uses the GitLab CI JWT token for Vault authentication, and wraps the build command.

```yaml
# .gitlab-ci.yml
stages:
  - build

build:
  stage: build
  image: ubuntu:22.04
  id_tokens:
    BAO_JWT_TOKEN:
      aud: https://vault.example.com
  variables:
    BAO_ADDR: "https://vault.example.com"
    BAO_NAMESPACE: "mynamespace"
    BAO_JWT_ROLE: "gitlab-ci"
    # Inject the NPM token as an env var
    SECRET_NPM_TOKEN: "kv://npmToken:env@kv/frontend/ci"
    # Render a Docker config from a KV-stored template and write it to disk
    SECRET_DOCKER_CFG: "template://tpl:file@kv/ci/docker-config?outfile=.docker/config.json"
  before_script:
    - |
      BAO_WRAPPER_VERSION=v0.2.1
      BAO_WRAPPER_SHA256=7268dac9d76b24c712217993b83755bcea1945f296a0ab306da78a0eb1949c56
      curl -fsSL \
        "https://github.com/philhartung/bao-wrapper/releases/download/${BAO_WRAPPER_VERSION}/bao-wrapper-linux-amd64" \
        -o /usr/local/bin/bao-wrapper
      printf '%s  %s\n' "$BAO_WRAPPER_SHA256" /usr/local/bin/bao-wrapper | sha256sum --check --strict
      chmod +x /usr/local/bin/bao-wrapper
  script:
    - bao-wrapper run -- npm run build
```

The child process receives the resolved secret values as environment variables (e.g. `NPM_TOKEN=<actual value>`) while all sensitive configuration variables (`BAO_*`, `VAULT_*`, `SECRET_*` (or the custom prefix), `ACTIONS_ID_TOKEN_REQUEST_*`) are stripped from its environment. Any accidental `console.log` printing of `NPM_TOKEN` will appear as `[MASKED]` in the job log. The rendered Docker config file at `.docker/config.json` is written with `0600` permissions and the inner secrets it contains are masked in logs.

---

## Example: GitHub Actions Pipeline

When running inside a GitHub Actions workflow with `id-token: write` permissions, `bao-wrapper` **automatically fetches the OIDC JWT token** — no manual token-passing step required. It detects the `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN` environment variables that GitHub injects, requests a JWT, and uses it for Vault authentication.

```yaml
# .github/workflows/build.yml
name: Build

on: [push]

permissions:
  id-token: write   # required for OIDC token generation
  contents: read

jobs:
  build:
    runs-on: ubuntu-24.04
    env:
      BAO_ADDR: "https://vault.example.com"
      BAO_NAMESPACE: "mynamespace"
      BAO_JWT_ROLE: "github-actions"
      # Inject the NPM token as an env var
      SECRET_NPM_TOKEN: "kv://npmToken:env@kv/frontend/ci"
    steps:
      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6.1.0

      - name: Install bao-wrapper
        run: |
          BAO_WRAPPER_VERSION=v0.2.1
          BAO_WRAPPER_SHA256=7268dac9d76b24c712217993b83755bcea1945f296a0ab306da78a0eb1949c56
          curl -fsSL \
            "https://github.com/philhartung/bao-wrapper/releases/download/${BAO_WRAPPER_VERSION}/bao-wrapper-linux-amd64" \
            -o bao-wrapper
          printf '%s  %s\n' "$BAO_WRAPPER_SHA256" bao-wrapper | sha256sum --check --strict
          sudo install -m 0755 bao-wrapper /usr/local/bin/bao-wrapper

      - name: Build
        run: bao-wrapper run -- npm run build
```

> **Note:** `BAO_JWT_TOKEN` is intentionally omitted. `bao-wrapper` detects the GitHub Actions OIDC environment and requests the JWT automatically. Explicitly setting `BAO_JWT_TOKEN` (or its fallback `VAULT_JWT_TOKEN`) always takes precedence over auto-detection.

---

## Example: AppRole Authentication

For non-interactive environments where JWT/OIDC is not available, you can use AppRole authentication by providing a `RoleID` and `SecretID`.

```bash
export BAO_ADDR="https://vault.example.com"
export BAO_APP_ID="my-role-id"
export BAO_APP_SECRET="my-secret-id"

# Inject secrets from KV
export SECRET_API_KEY="kv://apiKey@kv/services/api"

bao-wrapper run -- ./start-service.sh
```

`bao-wrapper` will perform an AppRole login, fetch the secrets, and automatically revoke the client token upon exit.

---

## Architecture

```mermaid
flowchart TD
    CLI["bao-wrapper run -- &lt;command&gt;"]

    subgraph bao-wrapper
        PARSER["parser\nParses secret env vars (default SECRET_*)\ninto SecretRef structs"]
        API["api\nHTTP client for OpenBao/Vault\nJWT · AppRole login\nSecret fetch · Token revoke\nRetry with exponential backoff"]
        TMPL["template\nFetches Go text/template from KV v2\nRenders {{ secret }} calls inline"]
        RUNNER["runner\nFilters sensitive env vars\nInjects secrets as env vars or files\nForwards OS signals"]
        MASKER["masker\nio.Writer wrapper for stdout/stderr\nReplaces secrets with [MASKED]\nChunk-boundary-safe"]
    end

    VAULT[("OpenBao / Vault")]
    CHILD["Child process\n(e.g. npm run build)"]
    LOGS["Log output\n(masked)"]

    CLI --> PARSER
    PARSER --> API
    API -->|"JWT / AppRole login\nFetch secrets"| VAULT
    VAULT -->|"Secret values"| API
    API --> TMPL
    TMPL -->|"{{ secret }} lookups"| VAULT
    API --> RUNNER
    TMPL --> RUNNER
    RUNNER -->|"Inject env vars / write files"| CHILD
    CHILD -->|"stdout / stderr"| MASKER
    MASKER --> LOGS
```

---

## Security notes

- TLS certificate validation is always enabled (`InsecureSkipVerify` is never set).
- Vault and GitHub OIDC HTTP clients have an explicit 10-second timeout and reject redirects. GitHub OIDC endpoints must use HTTPS, and their response bodies are limited to 64 KiB.
- Secret reads and token revocation are retried up to 3 times on network errors or HTTP 502/503/504, using exponential backoff and jitter. JWT and AppRole login requests are attempted exactly once because retrying an ambiguously completed login could issue an untracked token.
- Authentication roles should enforce short token TTLs and maximum TTLs: a lost login response can leave the outcome unknowable even without an automatic retry.
- `BAO_*`, `VAULT_*`, the secret prefix variables (default `SECRET_*`), and `ACTIONS_ID_TOKEN_REQUEST_*` environment variables are stripped from the child process environment to prevent credential leakage.
- On Unix, file secrets use permission `0600`; outfile directories created by the wrapper use `0750`.
- Windows does not implement Unix `0600` as an owner-only ACL. File secrets inherit the containing directory's Windows ACL. In particular, a persistent custom outfile is safe only when its parent directory already has an appropriately restrictive ACL; the atomic replacement inherits that parent ACL rather than preserving the replaced file's ACL.
- Temp-directory files and same-directory outfile staging files use exclusive creation. Outfiles are installed with an atomic rename.
- Custom outfile parent components are resolved from the filesystem or volume root using directory handles. Symbolic links in the parent path are rejected, as are components changed to a different filesystem object while they are being opened.
- Secret values are never written to logs, error messages, or panic output.
- Template engine uses selective masking: inner secret values are masked, the template skeleton is not.
- All secrets (including values resolved via `{{ secret "..." }}` inside templates) are pre-registered with the masker before the child process is started.
- The Vault token is revoked via `POST /v1/auth/token/revoke-self` on normal
  exit and immediately when the wrapper receives SIGINT or SIGTERM. Temporary
  secret paths are unlinked at the same time.
- Signals are forwarded to the direct child. Process-tree termination and hard
  shutdown deadlines are delegated to the CI, container, or job runtime.
- Short strings (≤ 3 chars) are not masked to prevent over-masking.
- In-template URLs forbid the `template` engine to prevent recursive template rendering.
- Legacy KV v1 lookups cannot access OpenBao's reserved `auth/`, `sys/`, `identity/`, or `cubbyhole/` endpoint prefixes.
- Secret prefix variables (default `SECRET_*`) with unrecognised engine schemes are silently skipped.

---

## Development

### Prerequisites

- [Go](https://go.dev/dl/) 1.26.6 (the version pinned by `go.mod` and the release workflow)
- Access to an OpenBao or HashiCorp Vault instance (for integration testing)

### Running tests

To run the unit tests:

```bash
go test ./...
```

To run tests with coverage:

```bash
go test -cover ./...
```

### Running integration tests

The integration fixture uses Docker Compose and OpenBao 2.6. OpenBao starts
with a static test-only auto-unseal key and uses declarative self-initialization
to mount KV v1/v2, seed secrets, and create a read-only AppRole. No root token
or manual bootstrap commands are required.

```bash
./integration/test.sh
```

The script starts one disposable OpenBao instance, builds the wrapper once, and
runs isolated scenarios covering AppRole and direct-token authentication,
`BAO_*`/`VAULT_*` fallback behavior, KV v1/v2 and full-JSON reads, environment
and file injection, custom outfiles, selective template masking, custom secret
prefixes, credential stripping, child failures, temporary-file cleanup, and
token revocation. It then removes the container, storage volume, and test
artifacts. Set `OPENBAO_PORT` if port 8200 is already in use:

```bash
OPENBAO_PORT=18200 ./integration/test.sh
```

The credentials in `compose.yaml` are public fixtures for local and CI testing
only. They must never be used in a persistent or production environment.

TLS/custom-CA handling, JWT/OIDC, namespace headers, retry fault injection,
signal forwarding, symlink attacks, and deterministic masker chunk boundaries
remain in the focused Go test suites, where those failure modes can be exercised
without adding fragile infrastructure to the OpenBao fixture.

### Building for all platforms

The project uses GitHub Actions to build binaries for multiple platforms. You can build them locally using:

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o bao-wrapper-linux-amd64 .
GOOS=linux GOARCH=arm64 go build -o bao-wrapper-linux-arm64 .

# macOS
GOOS=darwin GOARCH=amd64 go build -o bao-wrapper-darwin-amd64 .
GOOS=darwin GOARCH=arm64 go build -o bao-wrapper-darwin-arm64 .

# Windows
GOOS=windows GOARCH=amd64 go build -o bao-wrapper-windows-amd64.exe .
```

### Reproducing a release build

Release builds use the Go version declared in `go.mod`, disable CGO and automatic VCS stamping, remove local paths, and embed the exact tag and full 40-character source commit. To reproduce one asset, start from a clean checkout of its tag and use the same target and flags:

```bash
VERSION=vX.Y.Z
git clone https://github.com/philhartung/bao-wrapper.git
cd bao-wrapper
git checkout --detach "$VERSION"
COMMIT=$(git rev-parse HEAD)
test "$(git describe --tags --exact-match)" = "$VERSION"

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -buildvcs=false -mod=readonly \
  -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
  -o bao-wrapper-linux-amd64 .
sha256sum bao-wrapper-linux-amd64
```

Compare the result with the attested `SHA256SUMS` entry. Reproduction requires the exact Go toolchain version and target architecture used by the workflow. Repository administrators should also enable GitHub's immutable-releases setting so a published tag and its assets cannot be altered; that repository-level policy cannot be enabled from this workflow file.
