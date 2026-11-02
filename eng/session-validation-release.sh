#!/usr/bin/env bash
# Managed SVS build/test and portable net10 service publishing.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

usage() {
  echo "Usage: $0 test [results-directory] | publish [publish-directory]" >&2
  exit 2
}
[[ $# -ge 1 && $# -le 2 ]] || usage
command="$1"
output="${2:-artifacts/session-validation/${command}}"
command -v dotnet >/dev/null || { echo 'A .NET 10 SDK is required' >&2; exit 127; }
[[ "$(dotnet --version)" == 10.* ]] || { echo 'The repository requires .NET SDK 10' >&2; exit 2; }

# Keep an explicit, auditable managed lane. Native Yugabyte/Dragonfly,
# physical-host/failover/security qualification must be evaluated separately.
managed=(UnitTests ContractTests StorageTests CacheTests ClientTests HostTests)
project_path() {
  local name="$1"
  printf 'tests/Treehammock.SessionValidation.%s/Treehammock.SessionValidation.%s.csproj' "$name" "$name"
}

case "$command" in
  test)
    mkdir -p "$output"
    output="$(cd "$output" && pwd)"
    for name in "${managed[@]}"; do
      project="$(project_path "$name")"
      [[ -f "$project" ]] || { echo "Missing required SVS test project: $project" >&2; exit 2; }
      targets=(net8.0 net10.0)
      [[ "$name" == HostTests ]] && targets=(net10.0)
      dotnet restore "$project" --locked-mode -p:Configuration=Release
      for framework in "${targets[@]}"; do
        dotnet build "$project" --configuration Release --framework "$framework" --no-restore -p:ContinuousIntegrationBuild=true
        # These projects use the xUnit v3 executable runner. Run the built test DLL,
        # never rely on a dotnet test invocation that might discover zero tests.
        binary="tests/Treehammock.SessionValidation.${name}/bin/Release/${framework}/Treehammock.SessionValidation.${name}.dll"
        [[ -f "$binary" ]] || { echo "Missing built test runner: $binary" >&2; exit 2; }
        report="$output/session-validation-${name}-${framework}.xml"
        dotnet "$binary" -maxThreads 2 -xml "$report"
        python3 eng/session_validation_test_results.py "$report"
      done
    done
    ;;
  publish)
    [[ -n "${RELEASE_TAG:-}" && -n "${RELEASE_SOURCE_SHA:-}" ]] || { echo 'RELEASE_TAG/RELEASE_SOURCE_SHA required' >&2; exit 2; }
    [[ "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ ]] || { echo 'Invalid release tag' >&2; exit 2; }
    [[ "$RELEASE_SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo 'Invalid release SHA' >&2; exit 2; }
    [[ "$(git rev-parse HEAD)" == "$RELEASE_SOURCE_SHA" ]] || { echo 'Release checkout does not match preflight SHA' >&2; exit 2; }
    [[ ! -e "$output" ]] || { echo 'Refusing to overwrite an existing publish directory' >&2; exit 2; }
    mkdir -p "$output/service" "$output/client/net8.0" "$output/client/net10.0"
    project='src/Treehammock.SessionValidation.Api/Treehammock.SessionValidation.Api.csproj'
    sdk='src/Treehammock.SessionValidation.Client/Treehammock.SessionValidation.Client.csproj'
    version="${RELEASE_TAG#v}"
    base="${version%%-*}"
    props=("-p:TreehammockReleaseTag=$RELEASE_TAG" "-p:TreehammockReleaseVersion=$version" "-p:TreehammockReleaseBaseVersion=$base" "-p:TreehammockReleaseSourceSha=$RELEASE_SOURCE_SHA" "-p:ContinuousIntegrationBuild=true")
    dotnet restore "$project" --locked-mode "${props[@]}" -p:Configuration=Release
    dotnet publish "$project" --configuration Release --framework net10.0 --no-restore \
      --self-contained false -o "$output/service" "${props[@]}"
    for framework in net8.0 net10.0; do
      dotnet restore "$sdk" --locked-mode "${props[@]}" -p:Configuration=Release
      dotnet build "$sdk" --configuration Release --framework "$framework" --no-restore "${props[@]}"
      for name in Treehammock.SessionValidation.Client.dll Treehammock.SessionValidation.Contracts.dll; do
        src="src/Treehammock.SessionValidation.Client/bin/Release/$framework/$name"
        if [[ "$name" == Treehammock.SessionValidation.Contracts.dll && ! -f "$src" ]]; then
          src="src/Treehammock.SessionValidation.Contracts/bin/Release/$framework/$name"
        fi
        [[ -f "$src" ]] || { echo "Missing built SDK assembly: $src" >&2; exit 2; }
        cp "$src" "$output/client/$framework/$name"
      done
    done
    ;;
  *) usage ;;
esac
