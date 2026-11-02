#!/usr/bin/env bash
set -euo pipefail
# No shell tracing: private NuGet/CI variables must never be printed.
svs14_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
exec python3 "$svs14_root/eng/session-validation/ci/run.py" "$@"
