#!/usr/bin/env bash
set -euo pipefail

configuration="Release"
locked_restore="false"
collect_coverage="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
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
Usage: ./eng/dotnet-unit-tests.sh [--configuration Release|Debug|Sandbox] [--locked-restore] [--collect-coverage]

Runs the .NET unit-test lane. This lane restores, builds, and runs only the
treehammock.Tests Unit namespace. In-process integration tests run through
./eng/dotnet-integration-tests.sh, and real PostgreSQL SQL contracts live in
treehammock.Tests.SqlContracts.
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
  echo "The .NET SDK is required to run the unit-test lane." >&2
  exit 127
fi

source "$repo_root/eng/build-identity.sh"
treehammock_begin_build "$configuration"

export DOTNET_NOLOGO=true
export DOTNET_CLI_TELEMETRY_OPTOUT=true
export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=true

restore_args=(restore treehammock.sln --use-lock-file "-p:Configuration=$configuration")
if [[ "$locked_restore" == "true" ]]; then
  ./eng/check-locks.sh
  restore_args+=(--locked-mode)
fi

dotnet "${restore_args[@]}"
dotnet build treehammock.sln --configuration "$configuration" --no-restore -p:ContinuousIntegrationBuild=true

test_args=(test treehammock.Tests/treehammock.Tests.csproj --configuration "$configuration" --no-build --no-restore --filter "FullyQualifiedName~treehammock.Tests.Unit" --logger "trx;LogFileName=treehammock-unit-tests.trx")
if [[ "$collect_coverage" == "true" ]]; then
  python3 "$repo_root/eng/coverage-contract.py" --lane unit --configuration "$configuration"
else
  dotnet "${test_args[@]}"
fi
