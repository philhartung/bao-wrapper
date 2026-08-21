#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_dir"

openbao_port="${OPENBAO_PORT:-8200}"
bao_addr="http://127.0.0.1:${openbao_port}"
approle_id="11111111-2222-3333-4444-555555555555"
approle_secret="bao-wrapper-integration-secret-id"
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/bao-wrapper-integration.XXXXXX")
binary="$work_dir/bao-wrapper"
passed=0

fixture_secrets=(
  "integration-db-password-7c21"
  "integration-db-password-7c21-extended-f84a"
  "integration-certificate-material-4e98"
  "integration-legacy-token-a913"
)

cleanup() {
  status=$?
  if [[ $status -ne 0 ]]; then
    docker compose logs --no-color openbao || true
  fi
  docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -rf -- "$work_dir"
}
trap cleanup EXIT

fail() {
  printf 'integration test failed: %s\n' "$*" >&2
  exit 1
}

assert_eq() {
  local got=$1 want=$2 message=$3
  [[ "$got" == "$want" ]] || fail "$message (expected '$want', got '$got')"
}

assert_file_contains() {
  local file=$1 expected=$2 message=$3
  grep -F -- "$expected" "$file" >/dev/null || {
    printf '%s\n' "--- $file ---" >&2
    sed -n '1,160p' "$file" >&2
    fail "$message"
  }
}

assert_file_not_contains() {
  local file=$1 forbidden=$2 message=$3
  if grep -F -- "$forbidden" "$file" >/dev/null; then
    printf '%s\n' "--- $file ---" >&2
    sed -n '1,160p' "$file" >&2
    fail "$message"
  fi
}

assert_no_fixture_leaks() {
  local file secret
  for file in "$@"; do
    for secret in "${fixture_secrets[@]}"; do
      assert_file_not_contains "$file" "$secret" "raw fixture secret appeared in child output"
    done
  done
}

file_mode() {
  local path=$1
  if stat -c '%a' "$path" >/dev/null 2>&1; then
    stat -c '%a' "$path"
  else
    stat -f '%Lp' "$path"
  fi
}

new_case_dir() {
  local name=$1
  local dir="$work_dir/$name"
  mkdir -p "$dir/tmp"
  printf '%s\n' "$dir"
}

# run_wrapper CASE_DIR [ENV=VALUE ...] -- <bao-wrapper arguments...>
# Results are exposed through RUN_STATUS, RUN_STDOUT, and RUN_STDERR.
run_wrapper() {
  local case_dir=$1
  shift
  local -a env_args=()
  while [[ $# -gt 0 && $1 != "--" ]]; do
    env_args+=("$1")
    shift
  done
  [[ $# -gt 0 ]] || fail "run_wrapper is missing its -- separator"
  shift

  RUN_STDOUT="$case_dir/stdout"
  RUN_STDERR="$case_dir/stderr"
  set +e
  env -i \
    "PATH=$PATH" \
    "HOME=${HOME:-$case_dir}" \
    "TMPDIR=$case_dir/tmp" \
    "CASE_DIR=$case_dir" \
    "${env_args[@]}" \
    "$binary" "$@" >"$RUN_STDOUT" 2>"$RUN_STDERR"
  RUN_STATUS=$?
  set -e
}

pass_case() {
  passed=$((passed + 1))
  printf 'ok %d - %s\n' "$passed" "$1"
}

issue_token() {
  docker compose exec -T \
    -e BAO_ADDR=http://127.0.0.1:8200 \
    openbao bao write -field=token auth/approle/login \
    "role_id=$approle_id" "secret_id=$approle_secret"
}

assert_token_valid() {
  local token=$1
  docker compose exec -T \
    -e BAO_ADDR=http://127.0.0.1:8200 \
    -e "BAO_TOKEN=$token" \
    openbao bao token lookup >/dev/null 2>&1 || fail "newly issued token was not valid"
}

assert_token_revoked() {
  local token=$1
  if docker compose exec -T \
    -e BAO_ADDR=http://127.0.0.1:8200 \
    -e "BAO_TOKEN=$token" \
    openbao bao token lookup >/dev/null 2>&1; then
    fail "wrapper token remained valid after exit"
  fi
}

# Self-initialization runs only against empty storage. Reset this fixture's
# isolated volume so every run starts from the declared state.
docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true
docker compose up --detach --wait openbao
go build -o "$binary" .

case_dir=$(new_case_dir engines-and-masking)
run_wrapper "$case_dir" \
  "BAO_ADDR=$bao_addr" \
  "BAO_APP_ID=$approle_id" \
  "BAO_APP_SECRET=$approle_secret" \
  "SECRET_DB_PASSWORD=kv://password@kv/integration/app" \
  "SECRET_EXTENDED=kv://password_extended@kv/integration/app" \
  "SECRET_RETRIES=kv://retries@kv/integration/app" \
  "SECRET_ALL=kv://kv/integration/app" \
  "SECRET_LEGACY_TOKEN=legacy://token@kvv1/integration/legacy" \
  "SECRET_APP_CONFIG=template://tpl@kv/integration/template" \
  -- run -- sh -euc '
    test "$DB_PASSWORD" = "integration-db-password-7c21"
    test "$EXTENDED" = "integration-db-password-7c21-extended-f84a"
    test "$RETRIES" = "7"
    case "$ALL" in
      *"\"enabled\":true"*"\"retries\":7"*) ;;
      *) exit 91 ;;
    esac
    test "$LEGACY_TOKEN" = "integration-legacy-token-a913"
    printf "stdout-password=%s\n" "$DB_PASSWORD"
    printf "stderr-overlap=%s\n" "$EXTENDED" >&2
    printf "%s" "$APP_CONFIG"
    printf "%s" "$APP_CONFIG" >&2
  '
assert_eq "$RUN_STATUS" "0" "engine and masking scenario returned a nonzero status"
assert_no_fixture_leaks "$RUN_STDOUT" "$RUN_STDERR"
assert_file_contains "$RUN_STDOUT" "stdout-password=[MASKED]" "stdout secret was not masked"
assert_file_contains "$RUN_STDERR" "stderr-overlap=[MASKED]" "overlapping stderr secret was not masked"
assert_file_contains "$RUN_STDOUT" "database_password=[MASKED]" "template KV v2 secret was not selectively masked"
assert_file_contains "$RUN_STDOUT" "legacy_token=[MASKED]" "template KV v1 secret was not selectively masked"
assert_file_contains "$RUN_STDOUT" "mode=production" "template skeleton was unexpectedly masked"
assert_file_contains "$RUN_STDERR" "mode=production" "stderr template skeleton was unexpectedly masked"
pass_case "AppRole, KV engines, JSON/scalars, and selective masking"

case_dir=$(new_case_dir file-delivery)
outfile="$case_dir/generated/config/app.conf"
run_wrapper "$case_dir" \
  "VAULT_ADDR=$bao_addr" \
  "VAULT_APP_ID=$approle_id" \
  "VAULT_APP_SECRET=$approle_secret" \
  "SECRET_CERT_FILE=kv://certificate:file@kv/integration/app" \
  "SECRET_APP_CONFIG=template://tpl:file@kv/integration/template?outfile=$outfile" \
  -- run -- sh -euc '
    test "$(cat "$CERT_FILE")" = "integration-certificate-material-4e98"
    if stat -c "%a" "$CERT_FILE" >/dev/null 2>&1; then
      mode=$(stat -c "%a" "$CERT_FILE")
    else
      mode=$(stat -f "%Lp" "$CERT_FILE")
    fi
    test "$mode" = "600"
    printf "%s" "$CERT_FILE" > "$CASE_DIR/temp-secret-path"
    test "$APP_CONFIG" = "$CASE_DIR/generated/config/app.conf"
    expected="database_password=integration-db-password-7c21
legacy_token=integration-legacy-token-a913
mode=production"
    test "$(cat "$APP_CONFIG")" = "$expected"
  '
assert_eq "$RUN_STATUS" "0" "file delivery scenario returned a nonzero status"
temp_secret_path=$(<"$case_dir/temp-secret-path")
[[ ! -e "$temp_secret_path" ]] || fail "temporary secret file was not removed"
[[ -f "$outfile" ]] || fail "custom outfile did not persist"
assert_eq "$(file_mode "$outfile")" "600" "custom outfile permissions were not private"
assert_eq "$(file_mode "$(dirname "$outfile")")" "750" "custom outfile directory permissions were incorrect"
assert_no_fixture_leaks "$RUN_STDOUT" "$RUN_STDERR"
pass_case "VAULT fallbacks, temporary files, and persistent outfile routing"

case_dir=$(new_case_dir prefix-and-sanitization)
run_wrapper "$case_dir" \
  "BAO_ADDR=$bao_addr" \
  "BAO_APP_ID=$approle_id" \
  "BAO_APP_SECRET=$approle_secret" \
  "BAO_SECRET_PREFIX=IGNORED_" \
  "BAO_UNUSED_FIXTURE=sensitive-bao-value" \
  "VAULT_UNUSED_FIXTURE=sensitive-vault-value" \
  "ACTIONS_ID_TOKEN_REQUEST_URL=https://oidc.invalid/token" \
  "ACTIONS_ID_TOKEN_REQUEST_TOKEN=sensitive-oidc-value" \
  "WRAP_DB_PASSWORD=kv://password@kv/integration/app" \
  "WRAP_SCANNING_URL=https://scanner.invalid" \
  "SAFE_PASSTHROUGH=visible" \
  -- run --secret-prefix WRAP_ -- sh -euc '
    test "$DB_PASSWORD" = "integration-db-password-7c21"
    test "$SAFE_PASSTHROUGH" = "visible"
    test -z "${SCANNING_URL+x}"
    test -z "${BAO_ADDR+x}"
    test -z "${BAO_APP_ID+x}"
    test -z "${BAO_APP_SECRET+x}"
    test -z "${BAO_SECRET_PREFIX+x}"
    test -z "${BAO_UNUSED_FIXTURE+x}"
    test -z "${VAULT_UNUSED_FIXTURE+x}"
    test -z "${ACTIONS_ID_TOKEN_REQUEST_URL+x}"
    test -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN+x}"
    test -z "${WRAP_DB_PASSWORD+x}"
    test -z "${WRAP_SCANNING_URL+x}"
    printf "custom-prefix=%s\n" "$DB_PASSWORD"
  '
assert_eq "$RUN_STATUS" "0" "custom prefix scenario returned a nonzero status"
assert_no_fixture_leaks "$RUN_STDOUT" "$RUN_STDERR"
assert_file_contains "$RUN_STDOUT" "custom-prefix=[MASKED]" "custom-prefix secret was not masked"
pass_case "custom prefix precedence, scheme skipping, and environment sanitization"

case_dir=$(new_case_dir child-failure)
direct_token=$(issue_token)
[[ -n "$direct_token" ]] || fail "OpenBao CLI returned an empty token"
assert_token_valid "$direct_token"
run_wrapper "$case_dir" \
  "BAO_ADDR=$bao_addr" \
  "BAO_TOKEN=$direct_token" \
  "SECRET_CERT_FILE=kv://certificate:file@kv/integration/app" \
  -- run -- sh -euc '
    test "$(cat "$CERT_FILE")" = "integration-certificate-material-4e98"
    printf "%s" "$CERT_FILE" > "$CASE_DIR/temp-secret-path"
    cat "$CERT_FILE"
    cat "$CERT_FILE" >&2
    exit 23
  '
assert_eq "$RUN_STATUS" "23" "child exit code was not propagated"
assert_no_fixture_leaks "$RUN_STDOUT" "$RUN_STDERR"
assert_file_not_contains "$RUN_STDOUT" "$direct_token" "direct token appeared in stdout"
assert_file_not_contains "$RUN_STDERR" "$direct_token" "direct token appeared in stderr"
temp_secret_path=$(<"$case_dir/temp-secret-path")
[[ ! -e "$temp_secret_path" ]] || fail "temporary file survived a nonzero child exit"
assert_token_revoked "$direct_token"
pass_case "nonzero child exit, masking, cleanup, and direct-token revocation"

case_dir=$(new_case_dir fetch-failure)
direct_token=$(issue_token)
[[ -n "$direct_token" ]] || fail "OpenBao CLI returned an empty token"
assert_token_valid "$direct_token"
run_wrapper "$case_dir" \
  "BAO_ADDR=$bao_addr" \
  "BAO_TOKEN=$direct_token" \
  "SECRET_NOT_FOUND=kv://value@kv/integration/missing" \
  -- run -- sh -euc 'touch "$CASE_DIR/child-started"'
assert_eq "$RUN_STATUS" "1" "missing-secret failure returned the wrong status"
[[ ! -e "$case_dir/child-started" ]] || fail "child started after secret fetching failed"
assert_file_contains "$RUN_STDERR" "error: fetch secret NOT_FOUND:" "missing-secret diagnostic was absent"
assert_file_contains "$RUN_STDERR" "returned status 404" "missing-secret diagnostic lacked the OpenBao status"
assert_file_not_contains "$RUN_STDOUT" "$direct_token" "direct token appeared in failure stdout"
assert_file_not_contains "$RUN_STDERR" "$direct_token" "direct token appeared in failure stderr"
assert_no_fixture_leaks "$RUN_STDOUT" "$RUN_STDERR"
assert_token_revoked "$direct_token"
pass_case "pre-child failure diagnostics and token revocation"

printf 'OpenBao integration suite passed (%d scenarios).\n' "$passed"
