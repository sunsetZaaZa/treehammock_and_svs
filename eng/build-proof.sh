#!/usr/bin/env bash
set -euo pipefail

configuration="Release"
locked_restore="false"
run_sql_contracts="false"
collect_coverage="false"
require_locks="false"
refresh_locks="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --configuration)
      configuration="${2:?Missing value for --configuration}"
      shift 2
      ;;
    --locked-restore)
      locked_restore="true"
      require_locks="true"
      shift
      ;;
    --require-locks)
      require_locks="true"
      shift
      ;;
    --refresh-locks)
      refresh_locks="true"
      shift
      ;;
    --run-sql-contracts)
      run_sql_contracts="true"
      shift
      ;;
    --collect-coverage)
      collect_coverage="true"
      shift
      ;;
    -h|--help)
      cat <<'USAGE'
Usage: ./eng/build-proof.sh [--configuration Release|Debug|Sandbox] [--refresh-locks] [--require-locks] [--locked-restore] [--run-sql-contracts] [--collect-coverage]

Runs the full build-proof lane for a local PR checkout:
  1. verifies the .NET SDK is available
  2. optionally refreshes packages.lock.json files
  3. optionally requires lock files before restore
  4. runs the normal validation harness
  5. optionally runs the dedicated SQL contract suite when their environment variables are set
USAGE
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if ! command -v dotnet >/dev/null 2>&1; then
  echo "The .NET SDK is required to prove this build. Install .NET 8 and rerun ./eng/build-proof.sh." >&2
  exit 127
fi

dotnet --info

if [[ "$refresh_locks" == "true" ]]; then
  ./eng/restore-locks.sh
fi

if [[ "$require_locks" == "true" ]]; then
  ./eng/check-locks.sh
fi

validate_args=(--configuration "$configuration")
if [[ "$locked_restore" == "true" ]]; then
  validate_args+=(--locked-restore)
fi
if [[ "$collect_coverage" == "true" ]]; then
  validate_args+=(--collect-coverage)
fi

./eng/validate.sh "${validate_args[@]}"

if [[ "$run_sql_contracts" == "true" ]]; then
  sql_args=(--configuration "$configuration")
  if [[ "$locked_restore" == "true" ]]; then
    sql_args+=(--locked-restore)
  fi
  ./eng/sql-contracts.sh "${sql_args[@]}"
fi
