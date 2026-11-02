#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
source ./eng/test-ownership.sh

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  cat <<'USAGE'
Usage: ./eng/docker-all-tests.sh

Runs all Docker-backed validation lanes in sequence:
  1. Unit tests in the Docker unit-test image
  2. SQL contract suite tests against Compose PostgreSQL
  3. Bruno HTTP checks against the API service directly
  4. Bruno HTTP checks against the HAProxy service
  5. Full Compose system tests through HAProxy

Generate package lock files first:
  ./eng/restore-locks.sh
USAGE
  exit 0
fi

if [[ $# -gt 0 ]]; then
  echo "Unknown argument: $1" >&2
  exit 2
fi

treehammock_owned_test docker-all-tests "$@"

./eng/docker-unit-tests.sh
./eng/docker-sql-contracts.sh
./eng/docker-http-contracts-direct.sh
./eng/docker-http-contracts-proxy.sh

./eng/docker-system-stack-tests.sh
