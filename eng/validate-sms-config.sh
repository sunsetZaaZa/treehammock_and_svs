#!/usr/bin/env bash
# Run from the published application directory with deployment environment/secret injection.
# Deliberately never enable shell tracing or print environment variables.
set -euo pipefail
if [[ $# -ne 1 || ! -f "$1" ]]; then
  echo 'Usage: validate-sms-config.sh /path/to/published/treehammock.dll' >&2
  exit 1
fi
assembly=$(realpath "$1")
cd "$(dirname "$assembly")"
exec dotnet "$assembly" validate-sms-config
