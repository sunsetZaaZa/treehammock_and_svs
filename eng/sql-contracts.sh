#!/usr/bin/env bash
set -euo pipefail

baseline_output=""
configuration="Release"
locked_restore="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --baseline-output)
      baseline_output="${2:?Missing baseline output directory}"
      shift 2
      ;;
    --configuration)
      configuration="${2:?Missing value for --configuration}"
      shift 2
      ;;
    --locked-restore)
      locked_restore="true"
      shift
      ;;
    -h|--help)
      cat <<'USAGE'
Usage: ./eng/sql-contracts.sh [--configuration Release|Debug|Sandbox] [--locked-restore] [--baseline-output .correction-results]

Runs the dedicated PostgreSQL SQL contract test suite. Requires:
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

if [[ -n "$baseline_output" ]]; then
  exec bash "$script_dir/correction-baseline.sh" --lane sql --output "$baseline_output" --configuration "$configuration"
fi

if [[ "${TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS:-}" != "true" && "${TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS:-}" != "1" ]]; then
  echo "TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS must be true or 1 to run SQL contract tests." >&2
  exit 2
fi

if [[ -z "${TREEHAMMOCK_DB_CONTRACT_CONNECTION:-}" ]]; then
  echo "TREEHAMMOCK_DB_CONTRACT_CONNECTION must point to a disposable PostgreSQL database." >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

source "$repo_root/eng/build-identity.sh"
treehammock_begin_build "$configuration"

export DOTNET_NOLOGO=true
export DOTNET_CLI_TELEMETRY_OPTOUT=true
export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=true

dotnet --info

restore_args=(restore eng/treehammock.SqlContracts.sln --use-lock-file "-p:Configuration=$configuration")
if [[ "$locked_restore" == "true" ]]; then
  ./eng/check-locks.sh
  restore_args+=(--locked-mode)
fi

dotnet "${restore_args[@]}"
dotnet build eng/treehammock.SqlContracts.sln --configuration "$configuration" --no-restore -p:ContinuousIntegrationBuild=true
sql_result_args=()
if [[ -n "${TREEHAMMOCK_TEST_RESULTS_DIRECTORY:-}" ]]; then sql_result_args=(--results-directory "$TREEHAMMOCK_TEST_RESULTS_DIRECTORY"); fi
dotnet test treehammock.Tests.SqlContracts/treehammock.Tests.SqlContracts.csproj --configuration "$configuration" --no-build --no-restore "${sql_result_args[@]}" --logger "trx;LogFileName=treehammock-sql-contracts.trx"
