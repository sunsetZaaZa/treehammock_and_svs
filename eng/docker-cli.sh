#!/usr/bin/env bash
set -euo pipefail

TREEHAMMOCK_DOTNET_SDK_IMAGE="${TREEHAMMOCK_DOTNET_SDK_IMAGE:-mcr.microsoft.com/dotnet/sdk:8.0}"
TREEHAMMOCK_DOTNET_RUNTIME_IMAGE="${TREEHAMMOCK_DOTNET_RUNTIME_IMAGE:-mcr.microsoft.com/dotnet/aspnet:8.0}"
export TREEHAMMOCK_DOTNET_SDK_IMAGE
export TREEHAMMOCK_DOTNET_RUNTIME_IMAGE

# Select the Docker CLI used by local Bash/WSL helper scripts.
#
# GitLab Linux runners use the normal `docker` binary. Local Windows shells can
# accidentally resolve `docker` to a Docker-compatible Podman shim instead. When
# running from Git Bash/Cygwin/MSYS, prefer Docker Desktop's `docker.exe` if it
# is available and healthy. WSL keeps the normal Linux `docker` preference, but
# can still fall back to docker.exe when Docker Desktop WSL integration is not
# exposing a Linux docker client.

if declare -F docker >/dev/null 2>&1 && [ -n "${TREEHAMMOCK_DOCKER_SELECTED:-}" ]; then
  return 0
fi

treehammock_is_windows_bash() {
  case "$(uname -s 2>/dev/null || true)" in
    MINGW*|MSYS*|CYGWIN*) return 0 ;;
    *) return 1 ;;
  esac
}

treehammock_candidate_is_podman() {
  local candidate="$1"
  local version_output
  version_output="$(command "$candidate" version 2>&1 || true)"
  printf '%s' "$version_output" | grep -Eiq 'podman|Emulate Docker CLI using podman'
}

treehammock_candidate_has_docker() {
  local candidate="$1"

  if ! command -v "$candidate" >/dev/null 2>&1; then
    return 1
  fi

  if [ "${TREEHAMMOCK_ALLOW_PODMAN:-false}" != "true" ] && treehammock_candidate_is_podman "$candidate"; then
    return 2
  fi

  if ! command "$candidate" info >/dev/null 2>&1; then
    return 3
  fi

  if ! command "$candidate" compose version >/dev/null 2>&1; then
    return 4
  fi

  return 0
}

treehammock_select_docker_cli() {
  local candidates=()
  local candidate
  local seen=" "
  local status
  local saw_podman="false"

  if [ -n "${TREEHAMMOCK_DOCKER_CLI:-}" ]; then
    candidates+=("$TREEHAMMOCK_DOCKER_CLI")
  fi

  if treehammock_is_windows_bash; then
    candidates+=("docker.exe" "docker")
  else
    candidates+=("docker" "docker.exe")
  fi

  for candidate in "${candidates[@]}"; do
    if [[ "$seen" == *" $candidate "* ]]; then
      continue
    fi
    seen+="$candidate "

    status=0
    treehammock_candidate_has_docker "$candidate" || status=$?
    if [ "$status" -eq 0 ]; then
      printf '%s\n' "$candidate"
      return 0
    fi

    case "$status" in
      2)
        saw_podman="true"
        ;;
    esac
  done

  if [ "$saw_podman" = "true" ]; then
    cat >&2 <<'MESSAGE'
Docker CLI with Compose is required, but the available `docker` command appears to be Podman emulation.
Use Docker Desktop's docker.exe from Git Bash/WSL, enable Docker Desktop WSL integration, or set TREEHAMMOCK_DOCKER_CLI to a real Docker CLI.
If Podman was recently uninstalled, close and reopen the terminal so PATH and shell command caches are refreshed.
MESSAGE
  else
    cat >&2 <<'MESSAGE'
Docker CLI with Compose is required, but no reachable Docker CLI was found.
Install/start Docker Desktop or Docker Engine, then retry this script.
On Windows, the host-backed lane can also be run with: .\eng\docker-host-system-stack-tests.cmd
MESSAGE
  fi

  return 1
}

TREEHAMMOCK_DOCKER_SELECTED="$(treehammock_select_docker_cli)"
export TREEHAMMOCK_DOCKER_SELECTED

case "$TREEHAMMOCK_DOCKER_SELECTED" in
  docker.exe|*/docker.exe)
    echo "Using Docker CLI: ${TREEHAMMOCK_DOCKER_SELECTED}" >&2
    ;;
esac

docker() {
  command "$TREEHAMMOCK_DOCKER_SELECTED" "$@"
}



treehammock_pull_dotnet_dockerfile_images() {
  treehammock_pull_with_retry "$TREEHAMMOCK_DOTNET_SDK_IMAGE"

  if treehammock_pull_with_retry "$TREEHAMMOCK_DOTNET_RUNTIME_IMAGE"; then
    return 0
  fi

  if [ "${TREEHAMMOCK_DISABLE_SDK_RUNTIME_FALLBACK:-false}" = "true" ]; then
    return 1
  fi

  if [ "${CI:-false}" = "true" ] && [ "${TREEHAMMOCK_ALLOW_SDK_RUNTIME_FALLBACK:-false}" != "true" ]; then
    cat >&2 <<MESSAGE
The .NET runtime image '${TREEHAMMOCK_DOTNET_RUNTIME_IMAGE}' is not available and SDK-runtime fallback is disabled in CI.
Fix registry access or set TREEHAMMOCK_ALLOW_SDK_RUNTIME_FALLBACK=true explicitly for a non-release diagnostic run.
MESSAGE
    return 1
  fi

  if treehammock_image_exists_locally "$TREEHAMMOCK_DOTNET_SDK_IMAGE"; then
    cat >&2 <<MESSAGE
The .NET runtime image '${TREEHAMMOCK_DOTNET_RUNTIME_IMAGE}' is not available, but the SDK image '${TREEHAMMOCK_DOTNET_SDK_IMAGE}' is cached locally.
Using the SDK image as the final API base for this local Docker test run. This is a developer fallback only; CI still requires the ASP.NET runtime image unless TREEHAMMOCK_ALLOW_SDK_RUNTIME_FALLBACK=true is set.
MESSAGE
    TREEHAMMOCK_DOTNET_RUNTIME_IMAGE="$TREEHAMMOCK_DOTNET_SDK_IMAGE"
    export TREEHAMMOCK_DOTNET_RUNTIME_IMAGE
    return 0
  fi

  return 1
}


treehammock_write_compose_image_override() {
  local file="${TREEHAMMOCK_DOCKER_COMPOSE_IMAGE_OVERRIDE_FILE:-.docker/treehammock-compose-images.override.yml}"

  mkdir -p "$(dirname "$file")"

  cat > "$file" <<MESSAGE
services:
  api:
    build:
      args:
        DOTNET_SDK_IMAGE: "${TREEHAMMOCK_DOTNET_SDK_IMAGE}"
        DOTNET_RUNTIME_IMAGE: "${TREEHAMMOCK_DOTNET_RUNTIME_IMAGE}"
  sql-contract-tests:
    build:
      args:
        DOTNET_SDK_IMAGE: "${TREEHAMMOCK_DOTNET_SDK_IMAGE}"
        DOTNET_RUNTIME_IMAGE: "${TREEHAMMOCK_DOTNET_RUNTIME_IMAGE}"
  system-tests:
    image: "${TREEHAMMOCK_DOTNET_SDK_IMAGE}"
MESSAGE

  printf '%s\n' "$file"
}

treehammock_dockerfile_build_args() {
  printf '%s\0' \
    --build-arg "DOTNET_SDK_IMAGE=${TREEHAMMOCK_DOTNET_SDK_IMAGE}" \
    --build-arg "DOTNET_RUNTIME_IMAGE=${TREEHAMMOCK_DOTNET_RUNTIME_IMAGE}"
}

treehammock_image_exists_locally() {
  local image="$1"
  docker image inspect "$image" >/dev/null 2>&1
}

treehammock_pull_with_retry() {
  local image="$1"
  local attempts="${2:-${TREEHAMMOCK_DOCKER_PULL_ATTEMPTS:-3}}"
  local attempt=1

  if [ "${TREEHAMMOCK_SKIP_DOCKER_PULLS:-false}" = "true" ]; then
    if treehammock_image_exists_locally "$image"; then
      echo "Skipping Docker pull for ${image}; using local cached image because TREEHAMMOCK_SKIP_DOCKER_PULLS=true."
      return 0
    fi

    echo "TREEHAMMOCK_SKIP_DOCKER_PULLS=true was set, but Docker image '${image}' is not available locally." >&2
    return 1
  fi

  while [ "$attempt" -le "$attempts" ]; do
    echo "Pulling Docker image ${image} (attempt ${attempt} of ${attempts})..."
    if docker pull "$image"; then
      return 0
    fi

    if treehammock_image_exists_locally "$image"; then
      echo "Docker pull failed for ${image}, but a local cached image is available. Continuing with the cached image."
      return 0
    fi

    if [ "$attempt" -lt "$attempts" ]; then
      sleep $(( attempt * 5 > 30 ? 30 : attempt * 5 ))
    fi

    attempt=$(( attempt + 1 ))
  done

  cat >&2 <<MESSAGE
Unable to pull Docker image '${image}' after ${attempts} attempts, and no local cached copy is available.
Docker is reachable, but the registry request failed. Check Docker Desktop network access, VPN/proxy/firewall settings, DNS, and registry availability.
For Microsoft Container Registry failures, try: docker pull "$TREEHAMMOCK_DOTNET_SDK_IMAGE" and docker pull "$TREEHAMMOCK_DOTNET_RUNTIME_IMAGE"
If the image is already cached and you want offline/local use, set TREEHAMMOCK_SKIP_DOCKER_PULLS=true.
MESSAGE
  return 1
}

