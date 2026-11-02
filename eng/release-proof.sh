#!/usr/bin/env bash
set -euo pipefail

configuration="Release"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --configuration)
      configuration="${2:?Missing value for --configuration}"
      shift 2
      ;;
    -h|--help)
      cat <<'USAGE'
Usage: ./eng/release-proof.sh [--configuration Release|Debug|Sandbox]

Runs the local source/SQL release gate:
  1. requires committed packages.lock.json files
  2. restores in locked mode
  3. runs normal build/test validation
  4. runs deferred PostgreSQL SQL contract tests

Candidate/archive/image identity and digest promotion are separate:
  python3 eng/release_artifacts.py build
  python3 eng/test-release-artifacts.py

Requires:
  TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS=true
  TREEHAMMOCK_DB_CONTRACT_CONNECTION="Host=...;Database=...;Username=...;Password=..."
USAGE
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS:-}" != "true" && "${TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS:-}" != "1" ]]; then
  echo "TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS must be true or 1 for the final release gate." >&2
  exit 2
fi

if [[ -z "${TREEHAMMOCK_DB_CONTRACT_CONNECTION:-}" ]]; then
  echo "TREEHAMMOCK_DB_CONTRACT_CONNECTION must point to a disposable PostgreSQL database for the final release gate." >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

./eng/build-proof.sh --configuration "$configuration" --locked-restore --run-sql-contracts
