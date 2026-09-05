# bao-wrapper

**bao-wrapper** is a CI-agnostic process wrapper for [OpenBao](https://openbao.org/) / [HashiCorp Vault](https://developer.hashicorp.com/vault).  
It fetches secrets at runtime, injects them into the child process's environment (or as temporary files), and masks registered values in captured stdout and stderr — all without touching the CI runner's own environment.

## Table of Contents

- [Key features](#key-features)
- [Installation](#installation)
  - [Verify release provenance](#verify-release-provenance)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Environment variables](#environment-variables)
  - [Secret variables](#secret-variables)
- [Template engine](#template-engine)
- [Examples](#examples)
  - [GitLab CI](#gitlab-ci-pipeline)
  - [GitHub Actions](#github-actions-pipeline)
  - [AppRole Authentication](#approle-authentication)
- [Architecture](#architecture)
- [Security notes](#security-notes)
- [Development](#development)

## Key features

| Feature | Details |
|---|---|
| **Zero external dependencies** | Uses only the Go standard library (`net/http`, `encoding/json`, …) |
| **Authentication** | Direct token, JWT/OIDC, or AppRole, with token revocation attempted during cleanup |
| **Streaming log masking** | Replaces registered plaintext values of at least four bytes with `[MASKED]`, including matches split across writes |
| **`env` and `file` injection** | Secrets are exposed as env vars or temp files (`0600` on Unix; inherited ACLs on Windows); sensitive config vars are stripped from the child process |
| **Template engine** | Go `text/template` rendering with in-template `{{ secret "..." }}` lookups and selective masking |
| **Automatic retry** | Secret reads and revocation: up to 3 retries on network errors or HTTP 502/503/504, with exponential backoff and jitter; logins are not retried |
| **Direct execution** | Launches the supplied command without implicit shell expansion |
| **Cross-platform** | Linux, macOS (amd64/arm64), Windows (amd64) |

---

## Installation

This README describes the current source. Published releases may differ; build from source if a documented feature is not yet released. In the download examples, replace the version and checksum placeholders with values for your chosen release.

### Download from GitHub Releases

```bash
# Linux amd64; pin the release version and its verified checksum.
BAO_WRAPPER_VERSION=vX.Y.Z
BAO_WRAPPER_SHA256='<verified SHA-256 for the Linux amd64 binary>'
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

The current release workflow publishes `SHA256SUMS` and GitHub build-provenance attestations for the manifest and binaries. Older releases may not include them.

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

The child process receives `DB_PASS=<actual value>`. Exact plaintext matches of registered values at least four bytes long are masked in captured stdout and stderr. See [Security notes](#security-notes) for the limits of masking and cleanup.

---

## Usage

```
bao-wrapper run [options] -- <command> [args...]
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--auth-path <path>` | `jwt` for JWT; `approle` for AppRole | Authentication mount used by the selected login method. Accepts a mount name such as `gitlab` or an auth-relative path such as `auth/gitlab`; `/login` is appended automatically. Can also be set via `BAO_AUTH_PATH` (fallback: `VAULT_AUTH_PATH`); the CLI flag takes priority. |
| `--secret-prefix <prefix>` | `SECRET_` | Prefix used to identify secret environment variables. Variables whose name starts with this prefix are parsed as secret references; the prefix is stripped before injecting the value into the child process. Can also be set via the `BAO_SECRET_PREFIX` environment variable; the CLI flag takes priority. |

### Environment variables

| Variable | Fallback | Required | Description |
|---|---|---|---|
| `BAO_ADDR` | `VAULT_ADDR` | **yes** | OpenBao/Vault server URL (e.g. `https://openbao.example.com`) |
| `BAO_NAMESPACE` | `VAULT_NAMESPACE` | no | Namespace |
| `BAO_TOKEN` | `VAULT_TOKEN` | no | Direct client token; takes priority over all login methods. Use when a token is already available (e.g. local dev, pre-issued tokens). **Cleanup attempts to revoke this token**, including after secret-fetch failures. Supply a disposable token that is not needed by other runs or jobs. |
| `BAO_AUTH_PATH` | `VAULT_AUTH_PATH` | no | Authentication mount used for JWT or AppRole login. Accepts `gitlab` and `auth/gitlab` forms. Defaults to `jwt` for JWT and `approle` for AppRole; overridden by `--auth-path`. |
| `BAO_JWT_ROLE` | `VAULT_JWT_ROLE` | no | JWT auth role (used when `BAO_TOKEN` is not set; skips JWT login when omitted) |
| `BAO_JWT_TOKEN` | `VAULT_JWT_TOKEN` | no | JWT token for authentication (auto-detected from GitHub Actions OIDC when unset) |
| `BAO_APP_ID` | `VAULT_APP_ID` | no | AppRole role ID (used when `BAO_TOKEN` and `BAO_JWT_ROLE` are not set) |
| `BAO_APP_SECRET` | `VAULT_APP_SECRET` | no | AppRole secret ID (used together with `BAO_APP_ID`) |
| `BAO_CACERT` | `VAULT_CACERT` | no | Path to a PEM-encoded CA certificate file (for self-signed or corporate CA) |
| `BAO_MAX_RESPONSE_BYTES` | `VAULT_MAX_RESPONSE_BYTES` | no | Maximum OpenBao/Vault response body size in bytes (default: 33554432 / 32 MiB) |
| `BAO_OIDC_MAX_RESPONSE_BYTES` | `VAULT_OIDC_MAX_RESPONSE_BYTES` | no | Maximum GitHub Actions OIDC response body size in bytes (default: 65536 / 64 KiB) |
| `BAO_SECRET_PREFIX` | – | no | Prefix for secret variables (default: `SECRET_`); overridden by `--secret-prefix` |

Nonempty `BAO_*` values take priority over their `VAULT_*` fallbacks. Authentication selects the first applicable method: direct token → JWT role (with an explicit JWT or GitHub OIDC) → AppRole credentials. A selected method does not fall back to another method if credentials are missing or login fails. `BAO_AUTH_PATH` is ignored for direct tokens.

OpenBao/Vault and GitHub OIDC requests have a 10-second HTTP client timeout and do not follow redirects. Secret reads and token revocation retry network errors and HTTP 502/503/504 up to three times, subject to request deadlines; login and OIDC requests are not automatically retried.

### Secret variables

Define secrets with the configured prefix (default `SECRET_`) using this format:

```
<PREFIX><NAME>=<engine>://[[field][:type]@]path
```

An explicit supported engine scheme is required. Prefixed variables without one are skipped during secret discovery and stripped from the child environment. The `field` and `type` are optional. Query parameters are not supported. `file` delivery uses an isolated temporary directory; the destination cannot be configured.

| Component | Default | Description |
|---|---|---|
| `engine` | *(required)* | Secret engine type. Only `kv`, `legacy`, and `template` are supported. `kv` uses the KV v2 API path; `legacy` uses the KV v1 API path; `template` renders a Go template stored in KV. |
| `field` | *(empty)* | Key in the secret data; empty = full JSON. Requires `@` separator. |
| `type` | `env` | `env` = env var, `file` = temp file path. Specified as `field:type` before `@`. |
| `path` | *(required)* | Full path to the secret, including the mount point (e.g. `kv/test`, `kvv1/my/secret`) |

| Engine | API path used | Description |
|---|---|---|
| `kv` | `GET /v1/<mount>/data/<secret_path>` (KV v2) | KV v2 secrets. The path includes the mount point; `/data/` is inserted automatically. Example: path `kv/test` → `/v1/kv/data/test` |
| `legacy` | `GET /v1/<path>` (KV v1) | KV v1 path style. The path is used as-is after validation. Example: path `kvv1/test` → `/v1/kvv1/test` |
| `template` | *(fetches template from KV v2, then renders)* | Fetches a Go `text/template` from a KV v2 path, renders it with `{{ secret "..." }}` support (see [Template engine](#template-engine)) |

> **Path restrictions:** Secret paths must be canonical and relative, without traversal or redundant separators. `legacy` also rejects OpenBao's reserved `auth/`, `sys/`, `identity/`, and `cubbyhole/` prefixes because these are system endpoints, not KV v1 mounts. This restriction also applies to `legacy://` references used inside templates.

The child process receives the bare name without the prefix.

#### Examples

```bash
# Full format: engine, field, type, and path (path includes mount point)
SECRET_DB_PASS=kv://password:env@kv/myapp/db

# Write TLS cert to a temp file; TLS_CERT contains the file path
SECRET_TLS_CERT=kv://cert:file@kv/myapp/tls

# Path only (no field or type — reads full JSON from kv)
SECRET_KEY=kv://kv/myapp/db

# Render a config from a KV-stored template into a temporary file;
# APP_CFG contains its path
SECRET_APP_CFG=template://tpl:file@kv/myapp/config

# Legacy KV v1 engine
SECRET_TOKEN=legacy://token:env@kvv1/my/path
```

---

## Template engine

The `template` engine fetches a Go [`text/template`](https://pkg.go.dev/text/template) from an OpenBao/Vault KV secret, renders it, and returns the result. This is useful for generating configuration files that embed multiple secrets.

### Declaration syntax

Use the `template` engine in the `SECRET_*` variable:

```bash
# Render template stored at KV path "kv/myapp/config", field "tpl",
# write the result to a temporary file, and expose its path as APP_CFG
SECRET_APP_CFG=template://tpl:file@kv/myapp/config

# Render template and inject as an env var
SECRET_APP_CFG=template://tpl@kv/myapp/config
```

### In-template lookups

Inside the template, use `{{ secret "url" }}` to reference individual secrets. The in-template URL uses a reduced syntax compared to the main `SECRET_*` declaration:

```
{{ secret "[engine://][field@]path" }}
```

The engine defaults to `kv` when omitted. The field is optional; omitting it returns the full JSON data.

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
SECRET_APP_CFG=template://tpl:file@kv/myapp/config
```

The wrapper fetches and renders the template, writes it to a temporary file, and exposes the path as `APP_CFG`. Cleanup attempts to remove the file after use; see [Security notes](#security-notes).

### Selective masking

Only values fetched through `{{ secret "..." }}` are registered for template masking. The template source and complete rendered output are not registered. Literal credentials in a template and transformed values therefore have no automatic masking guarantee. The usual minimum length of four bytes applies.

---

## Examples

### GitLab CI Pipeline

This example uses a JWT auth method mounted at `auth/gitlab` and requires a release supporting `BAO_AUTH_PATH`. It assumes your project provides an npm build script and installs its dependencies before the build.

```yaml
# .gitlab-ci.yml
stages:
  - build

build:
  stage: build
  image: node:22-bookworm
  id_tokens:
    BAO_JWT_TOKEN:
      aud: https://vault.example.com
  variables:
    BAO_ADDR: "https://vault.example.com"
    BAO_NAMESPACE: "mynamespace"
    BAO_AUTH_PATH: "gitlab" # JWT method mounted at auth/gitlab
    BAO_JWT_ROLE: "gitlab-ci"
    # Inject the NPM token as an env var
    SECRET_NPM_TOKEN: "kv://npmToken:env@kv/frontend/ci"
    # Render a Docker config into a temporary file; DOCKER_CFG contains its path
    SECRET_DOCKER_CFG: "template://tpl:file@kv/ci/docker-config"
  before_script:
    - |
      BAO_WRAPPER_VERSION=vX.Y.Z
      BAO_WRAPPER_SHA256='<verified SHA-256 for the Linux amd64 binary>'
      curl -fsSL \
        "https://github.com/philhartung/bao-wrapper/releases/download/${BAO_WRAPPER_VERSION}/bao-wrapper-linux-amd64" \
        -o /usr/local/bin/bao-wrapper
      printf '%s  %s\n' "$BAO_WRAPPER_SHA256" /usr/local/bin/bao-wrapper | sha256sum --check --strict
      chmod +x /usr/local/bin/bao-wrapper
  script:
    - bao-wrapper run -- npm run build
```

The build receives `NPM_TOKEN` and the temporary config path in `DOCKER_CFG`. The token and secrets fetched inside the template are registered for log masking.

---

### GitHub Actions Pipeline

With `id-token: write` permission and `BAO_JWT_ROLE` set, the wrapper can request a JWT using GitHub's `ACTIONS_ID_TOKEN_REQUEST_*` variables. Configure the Vault role to accept GitHub's issuer, audience, and repository claims. This example assumes your project provides an npm build script and installs its dependencies before the build.

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
          BAO_WRAPPER_VERSION=vX.Y.Z
          BAO_WRAPPER_SHA256='<verified SHA-256 for the Linux amd64 binary>'
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

### AppRole Authentication

For non-interactive environments where JWT/OIDC is not available, you can use AppRole authentication by providing a `RoleID` and `SecretID`.

```bash
export BAO_ADDR="https://vault.example.com"
export BAO_APP_ID="my-role-id"
export BAO_APP_SECRET="my-secret-id"
# export BAO_AUTH_PATH="ci-approle" # if AppRole is mounted at auth/ci-approle

# Inject secrets from KV
export SECRET_API_KEY="kv://apiKey@kv/services/api"

bao-wrapper run -- ./start-service.sh
```

`bao-wrapper` logs in with AppRole, fetches the secrets, runs the command, and attempts to revoke the client token during cleanup.

---

## Architecture

| Package | Responsibility |
|---|---|
| `main` | CLI options, authentication selection, secret resolution, token lifecycle |
| `parser` | Secret declarations and template lookup syntax |
| `api` | OpenBao/Vault HTTP requests, path validation, retries, token revocation |
| `template` | Go template rendering and collection of inner secrets for masking |
| `runner` | Child environment, temporary files, process execution, signals, cleanup |
| `masker` | Streaming plaintext replacement in stdout and stderr |

---

## Security notes

- **Transport:** Use an HTTPS `BAO_ADDR` outside local testing; plain HTTP is accepted. HTTPS certificate verification is enabled, with optional custom roots via `BAO_CACERT`. GitHub OIDC requires HTTPS and uses system trust; its request URL comes from the CI environment and has no hostname allowlist.
- **Child environment:** Inherited variables starting with `BAO_`, `VAULT_`, `ACTIONS_ID_TOKEN_REQUEST_`, or the configured secret prefix are removed case-insensitively before resolved secrets are added. Other environment variables are inherited.
- **Masking:** Only exact matches of registered values at least four bytes long are masked in captured stdout and stderr. Full-JSON reads register the JSON string, not its individual fields; templates register only inner lookups. Encoding, escaping, splitting a value between streams, or writing elsewhere can bypass masking. Run trusted child code: masking is not a security boundary. Output may be buffered by up to the longest registered value minus one byte to handle matches split across writes.
- **Temporary files:** File secrets use an isolated temporary directory (`0700`) and exclusive file creation (`0600`) on Unix. Windows uses inherited ACLs, so protect the account and temporary directory. Cleanup attempts removal on child exit and on SIGINT/SIGTERM, retrying removal after exit if necessary.
- **Token cleanup:** Once a client token is accepted or acquired, cleanup attempts `POST /v1/auth/token/revoke-self`, including after failures before child startup. SIGINT/SIGTERM starts cleanup while the child is running. Revocation can fail, and forced termination such as SIGKILL prevents cleanup. Use disposable tokens with short TTLs; a lost login response can also leave an issued token unavailable for revocation. Tokens are not renewed.
- **Signals and exit status:** The wrapper attempts to forward SIGINT/SIGTERM to its direct child. Process-tree termination and shutdown deadlines are the CI or container runtime's responsibility; Unix-style signal forwarding is not supported on Windows. Normal child exit codes are preserved, but a cleanup failure turns a successful exit into failure; signal termination is reported as exit code 1.

---

## Development

### Prerequisites

- [Go](https://go.dev/dl/) 1.26.6 (the version pinned by `go.mod` and the release workflow)
- Docker with Docker Compose and Bash (for the disposable integration fixture)

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

The script builds the wrapper and tests authentication, KV v1/v2 reads, environment and file delivery, template masking, credential stripping, failure handling, cleanup, and revocation against a disposable OpenBao instance. It removes the fixture containers, storage volume, and test artifacts afterwards. Set `OPENBAO_PORT` if port 8200 is already in use:

```bash
OPENBAO_PORT=18200 ./integration/test.sh
```

The credentials in `compose.yaml` are public fixtures for local and CI testing
only. They must never be used in a persistent or production environment.

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

The current release workflow pins the same Go version as `go.mod`, disables CGO and automatic VCS stamping, removes local paths, and embeds the version from `git describe --tags --always` and full source commit. To reproduce one asset, start from a clean checkout of its tag and use the same target and flags:

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

Compare the result with the attested `SHA256SUMS` entry. Reproduction requires the exact Go toolchain version and target architecture used by the workflow.
