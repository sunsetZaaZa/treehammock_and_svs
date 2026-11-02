#!/usr/bin/env bash
# Source-only: caller owns the process environment and Compose lifecycle.
set -euo pipefail
treehammock_initialize_fixture() {
  local mode="${1:-container}" project file key value
  project="${COMPOSE_PROJECT_NAME:-$(basename "$repo_root" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-')}"
  export COMPOSE_PROJECT_NAME="$project"
  file="$repo_root/.docker/fixtures/$project/compose.env"
  python3 "$repo_root/eng/fixture-isolation.py" --mode "$mode" >/dev/null
  while IFS='=' read -r key value; do
    case "$key" in TREEHAMMOCK_FIXTURE_DB_PASSWORD|TREEHAMMOCK_FIXTURE_CACHE_PASSWORD|TREEHAMMOCK_FIXTURE_TEST_KEY|TREEHAMMOCK_FIXTURE_OUTBOX_KEY|TREEHAMMOCK_FIXTURE_OPERATION_KEY) export "$key=$value" ;; *) return 2 ;; esac
  done < "$file"
}
