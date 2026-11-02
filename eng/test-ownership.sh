#!/usr/bin/env bash
# Source-only: an outer coordinator owns the lifetime; nested lanes verify it.
set -euo pipefail
treehammock_owned_test() {
  local lane="$1"; shift
  if [[ "${TREEHAMMOCK_TEST_RUN_ACTIVE:-}" != "true" ]]; then
    exec python3 "$repo_root/eng/test-ownership.py" run --lane "$lane" --entry "$repo_root/eng/$lane.sh" --shell "${BASH:-bash}" -- "$@"
  fi
  python3 "$repo_root/eng/test-ownership.py" verify --lane "$lane" -- "$@"
}
