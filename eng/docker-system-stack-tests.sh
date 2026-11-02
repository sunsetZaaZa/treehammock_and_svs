#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
source ./eng/test-ownership.sh
treehammock_owned_test docker-system-stack-tests "$@"

# shellcheck source=eng/docker-cli.sh
source ./eng/docker-cli.sh
source ./eng/fixture-isolation.sh
treehammock_initialize_fixture container


if ! command -v docker >/dev/null 2>&1; then
  echo "Docker CLI is required to run the full system stack test lane. Install Docker Desktop or Docker Engine, then retry." >&2
  exit 127
fi

if ! docker info >/dev/null 2>&1; then
  echo "Docker is installed, but the Docker daemon is not reachable. Start Docker Desktop or the Docker service, wait until Docker is running, then retry ./eng/docker-system-stack-tests.sh." >&2
  exit 1
fi

./eng/check-locks.sh

treehammock_pull_dotnet_dockerfile_images
compose_image_override="$(treehammock_write_compose_image_override)"

for image in   "postgres:16"   "docker.dragonflydb.io/dragonflydb/dragonfly:latest"   "haproxy:latest"; do
  treehammock_pull_with_retry "$image"
done

docker compose -p "$COMPOSE_PROJECT_NAME" \
  -f docker-compose.integration.yml \
  -f docker-compose.api-proxy.yml \
  -f docker-compose.testing.yml \
  -f docker-compose.ci-system.yml \
  -f "$compose_image_override" \
  --profile proxy \
  -f "$TREEHAMMOCK_TEST_OWNERSHIP_OVERRIDE" \
  --profile system \
  up --build --abort-on-container-exit --exit-code-from system-tests "$@" system-tests
