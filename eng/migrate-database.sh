#!/usr/bin/env bash
set -euo pipefail
if [[ $# -lt 1 ]]; then
  echo 'Usage: eng/migrate-database.sh /absolute/published/treehammock.dll --maintenance-confirmed [--schema public] [--adopt-baseline]' >&2
  exit 2
fi
migration_assembly="$1"
shift
exec dotnet "$migration_assembly" migrate "$@"
