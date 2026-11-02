#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

export DOTNET_NOLOGO=true
export DOTNET_CLI_TELEMETRY_OPTOUT=true
export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=true

if ! command -v dotnet >/dev/null 2>&1; then
  echo "The .NET SDK is required to refresh package lock files. Install .NET 8 and rerun ./eng/restore-locks.sh." >&2
  exit 127
fi

dotnet restore treehammock.sln --use-lock-file --force-evaluate
dotnet restore eng/treehammock.SqlContracts.sln --use-lock-file --force-evaluate
dotnet restore treehammock.Tests.System/treehammock.Tests.System.csproj --use-lock-file --force-evaluate
./eng/check-locks.sh

echo
if command -v git >/dev/null 2>&1; then
  echo "Review and commit generated lock files:"
  git status --short -- '**/packages.lock.json' Directory.Packages.props '**/*.csproj'
else
  echo "dotnet restore completed. Review generated packages.lock.json files before committing."
fi
