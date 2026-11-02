#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
source ./eng/test-ownership.sh
treehammock_owned_test docker-http-contracts-proxy "$@"

# shellcheck source=eng/docker-cli.sh
source ./eng/docker-cli.sh
source ./eng/fixture-isolation.sh
treehammock_initialize_fixture container

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required to run the HAProxy HTTP contract test Compose lane." >&2
  exit 127
fi

./eng/check-locks.sh

treehammock_pull_dotnet_dockerfile_images
compose_image_override="$(treehammock_write_compose_image_override)"

docker compose -p "$COMPOSE_PROJECT_NAME" \
  -f docker-compose.integration.yml \
  -f docker-compose.api-proxy.yml \
  -f docker-compose.testing.yml \
  -f "$compose_image_override" \
  --profile proxy \
  -f docker-compose.ci-system.yml \
  -f "$TREEHAMMOCK_TEST_OWNERSHIP_OVERRIDE" \
  --profile http-proxy \
  run --rm --build "$@" http-contract-tests-proxy
