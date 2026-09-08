#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_dir"
exec go test -tags=integration -count=1 -timeout=8m -v ./integration "$@"
