#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# shellcheck source=eng/docker-cli.sh
source ./eng/docker-cli.sh
source ./eng/fixture-isolation.sh
treehammock_initialize_fixture published

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required to run the scaled HAProxy Compose stack." >&2
  exit 127
fi

./eng/check-locks.sh

treehammock_pull_dotnet_dockerfile_images
compose_image_override="$(treehammock_write_compose_image_override)"

api_replicas="${TREEHAMMOCK_API_REPLICAS:-2}"
if [[ "${1:-}" =~ ^[0-9]+$ ]]; then
  api_replicas="$1"
  shift
fi

docker compose \
  -f docker-compose.integration.yml -f docker-compose.host-access.yml \
  -f docker-compose.api-proxy.yml -f docker-compose.proxy-access.yml \
  -f "$compose_image_override" \
  --profile proxy \
  up --build --scale "api=${api_replicas}" "$@" postgres dragonfly api haproxy
