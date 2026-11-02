#!/usr/bin/env bash
set -euo pipefail

baseline_output=""
configuration="Release"
locked_restore="false"
collect_coverage="false"

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
    --collect-coverage)
      collect_coverage="true"
      shift
      ;;
    -h|--help)
      cat <<'USAGE'
Usage: ./eng/validate.sh [--configuration Release|Debug|Sandbox] [--locked-restore] [--collect-coverage] [--baseline-output .correction-results]

Runs the reproducible local/CI fast validation lane:
  1. dotnet restore treehammock.sln --use-lock-file
  2. dotnet build treehammock.sln --no-restore
  3. dotnet test treehammock.Tests for the Unit namespace
  4. dotnet test treehammock.Tests for the in-process Integration namespace

Real PostgreSQL SQL contracts are a separate suite: ./eng/sql-contracts.sh.
Use --locked-restore only after packages.lock.json files have been generated and committed.
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

if [[ -n "$baseline_output" ]]; then
  baseline_args=(--lane fast --output "$baseline_output" --configuration "$configuration")
  if [[ "$collect_coverage" == "true" ]]; then baseline_args+=(--collect-coverage); fi
  exec bash "$repo_root/eng/correction-baseline.sh" "${baseline_args[@]}"
fi

source "$repo_root/eng/build-identity.sh"
treehammock_begin_build "$configuration"

export DOTNET_NOLOGO=true
export DOTNET_CLI_TELEMETRY_OPTOUT=true
export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=true

dotnet --info

restore_args=(restore treehammock.sln --use-lock-file "-p:Configuration=$configuration")
if [[ "$locked_restore" == "true" ]]; then
  ./eng/check-locks.sh
  restore_args+=(--locked-mode)
fi

dotnet "${restore_args[@]}"
dotnet build treehammock.sln --configuration "$configuration" --no-restore -p:ContinuousIntegrationBuild=true

unit_args=(test treehammock.Tests/treehammock.Tests.csproj --configuration "$configuration" --no-build --no-restore --filter "FullyQualifiedName~treehammock.Tests.Unit" --logger "trx;LogFileName=treehammock-unit-tests.trx")
integration_args=(test treehammock.Tests/treehammock.Tests.csproj --configuration "$configuration" --no-build --no-restore --filter "FullyQualifiedName~treehammock.Tests.Integration" --logger "trx;LogFileName=treehammock-integration-tests.trx")
if [[ "$collect_coverage" == "true" ]]; then
  python3 "$repo_root/eng/coverage-contract.py" --lane unit --configuration "$configuration"
  python3 "$repo_root/eng/coverage-contract.py" --lane integration --configuration "$configuration"
else
  dotnet "${unit_args[@]}"
  dotnet "${integration_args[@]}"
fi
