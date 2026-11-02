#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
source ./eng/build-identity.sh
treehammock_begin_build Release
reports="${TREEHAMMOCK_COMPOSE_REPORT_ROOT:-/reports}"
mkdir -p "$reports"
lane_run="$reports/system-$TREEHAMMOCK_BUILD_RUN_ID"
mkdir "$lane_run"
stage="tool-compile"
tool_tmp=""
finish() {
  primary=$?
  if [[ "$primary" -ne 0 ]]; then
    printf '{"status":"Failed","stage":"%s","exit_code":%d,"run_id":"%s"}\n' "$stage" "$primary" "$TREEHAMMOCK_BUILD_RUN_ID" > "$lane_run/run.json" || true
    echo "Compose system proof failed at $stage (exit $primary)." >&2
  fi
  if [[ -n "$tool_tmp" ]]; then rm -rf -- "$tool_tmp" || true; fi
  exit "$primary"
}
trap finish EXIT
printf '{"status":"Running","run_id":"%s"}\n' "$TREEHAMMOCK_BUILD_RUN_ID" > "$lane_run/run.json"
# Compile the package-free HTTP/TRX tool outside application/shared MSBuild scope.
tool_tmp="$(mktemp -d)"
cp eng/ComposeProofProbe/* "$tool_tmp/"
printf '<configuration><packageSources><clear /></packageSources></configuration>\n' > "$tool_tmp/NuGet.Config"
dotnet publish "$tool_tmp/ComposeProofProbe.csproj" --configuration Release --output "$tool_tmp/probe" -p:NuGetAudit=false
stage="readiness"
dotnet "$tool_tmp/probe/ComposeProofProbe.dll" --ready "${TREEHAMMOCK_SYSTEM_BASE_URL:?Missing system URL}"
stage="restore"
dotnet restore treehammock.Tests.System/treehammock.Tests.System.csproj --locked-mode -p:Configuration=Release
stage="build"
dotnet build treehammock.Tests.System/treehammock.Tests.System.csproj --configuration Release --no-restore
stage="tests"
mkdir "$lane_run/results"
dotnet test treehammock.Tests.System/treehammock.Tests.System.csproj --configuration Release --no-build --no-restore --results-directory "$lane_run/results" --logger "trx;LogFileName=treehammock-system-tests.trx"
stage="result-validation"
dotnet "$tool_tmp/probe/ComposeProofProbe.dll" --trx "$lane_run/results/treehammock-system-tests.trx" docs/corrections/APPLICATION_SURFACE_INDEX.json "$TREEHAMMOCK_BUILD_RUN_ID" > "$lane_run/proof.json"
printf '{"status":"Passed","run_id":"%s","exit_code":0}\n' "$TREEHAMMOCK_BUILD_RUN_ID" > "$lane_run/run.json"
