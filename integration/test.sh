#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_dir"

export OPENBAO_PORT="${OPENBAO_PORT:-8200}"
export BAO_ADDR="http://127.0.0.1:${OPENBAO_PORT}"
export BAO_APP_ID="11111111-2222-3333-4444-555555555555"
export BAO_APP_SECRET="bao-wrapper-integration-secret-id"

cleanup() {
  status=$?
  if [[ $status -ne 0 ]]; then
    docker compose logs --no-color openbao || true
  fi
  docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Self-initialization runs only against empty storage. Reset this fixture's
# isolated volume so every test run starts from the declared state.
docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true
docker compose up --detach --wait openbao

export SECRET_DB_PASSWORD="kv://password@kv/integration/app"
export SECRET_CERT_FILE="kv://certificate:file@kv/integration/app"
export SECRET_LEGACY_TOKEN="legacy://token@kvv1/integration/legacy"
export SECRET_APP_CONFIG="template://tpl@kv/integration/template"

set +e
output=$(go run . run -- sh -euc '
  test "$DB_PASSWORD" = "integration-db-password-7c21"
  test "$(cat "$CERT_FILE")" = "integration-certificate-material-4e98"
  test "$LEGACY_TOKEN" = "integration-legacy-token-a913"
  test "$APP_CONFIG" = "database_password=integration-db-password-7c21"

  test -z "${BAO_APP_ID+x}"
  test -z "${BAO_APP_SECRET+x}"
  test -z "${SECRET_DB_PASSWORD+x}"

  printf "%s\n" "$DB_PASSWORD"
  printf "%s\n" "$LEGACY_TOKEN"
  cat "$CERT_FILE"
  printf "\n"
' 2>&1)
status=$?
set -e

if [[ $status -ne 0 ]]; then
  printf '%s\n' "$output" >&2
  exit "$status"
fi

if [[ "$output" == *"integration-db-password-7c21"* ]] ||
   [[ "$output" == *"integration-legacy-token-a913"* ]] ||
   [[ "$output" == *"integration-certificate-material-4e98"* ]]; then
  printf 'integration test failed: raw secret was present in child output\n%s\n' "$output" >&2
  exit 1
fi

masked_count=$({ grep -o '\[MASKED\]' <<<"$output" || true; } | wc -l | tr -d ' ')
if [[ "$masked_count" -lt 3 ]]; then
  printf 'integration test failed: expected at least 3 masked values, got %s\n%s\n' "$masked_count" "$output" >&2
  exit 1
fi

printf 'OpenBao integration test passed (%s secret values masked).\n' "$masked_count"
