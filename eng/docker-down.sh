#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# shellcheck source=eng/docker-cli.sh
source ./eng/docker-cli.sh
source ./eng/fixture-isolation.sh
treehammock_initialize_fixture container

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required to stop the Compose stack." >&2
  exit 127
fi

docker compose \
  -f docker-compose.integration.yml \
  -f docker-compose.api-direct.yml \
  -f docker-compose.api-proxy.yml \
  -f docker-compose.ci-system.yml \
  -f docker-compose.local-system.yml \
  --profile proxy \
  --profile sql \
  --profile http \
  --profile http-proxy \
  --profile system \
  --profile host-system \
  down "$@"
