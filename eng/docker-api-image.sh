#!/usr/bin/env bash
set -euo pipefail

configuration="Release"
image_name="treehammock:api"
no_cache="false"
progress="auto"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --configuration)
      configuration="${2:?Missing value for --configuration}"
      shift 2
      ;;
    --image)
      image_name="${2:?Missing value for --image}"
      shift 2
      ;;
    --no-cache)
      no_cache="true"
      shift
      ;;
    --progress)
      progress="${2:?Missing value for --progress}"
      shift 2
      ;;
    -h|--help)
      cat <<'USAGE'
Usage: ./eng/docker-api-image.sh [--configuration Release|Debug|Sandbox] [--image name:tag] [--no-cache] [--progress auto|plain|tty]

Builds the Docker api target. The final image uses the ASP.NET runtime image,
not the .NET SDK image, and hosts the published treehammock API on port 5001.

Before running this command for the first time, generate and commit package
lock files:
  ./eng/restore-locks.sh

The image only contains the API runtime. PostgreSQL, DragonflyDB, HAProxy, and
HTTP collection runners are added by later Docker PRs through Compose.
USAGE
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# shellcheck source=eng/docker-cli.sh
source ./eng/docker-cli.sh

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required to build the API runtime image." >&2
  exit 127
fi

./eng/check-locks.sh

treehammock_pull_dotnet_dockerfile_images

source "$repo_root/eng/build-identity.sh"
treehammock_begin_build "$configuration"

build_args=(
  build
  --target api
  --build-arg "DOTNET_SDK_IMAGE=${TREEHAMMOCK_DOTNET_SDK_IMAGE}"
  --build-arg "DOTNET_RUNTIME_IMAGE=${TREEHAMMOCK_DOTNET_RUNTIME_IMAGE}"
  --build-arg "BUILD_CONFIGURATION=$configuration"
  --build-arg "TREEHAMMOCK_BUILD_RUN_ID=$TREEHAMMOCK_BUILD_RUN_ID"
  --progress "$progress"
  -t "$image_name"
)

if [[ "$no_cache" == "true" ]]; then
  build_args+=(--no-cache)
fi

build_args+=(.)

docker "${build_args[@]}"
