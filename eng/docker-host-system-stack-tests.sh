#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
if ! type -P python3 >/dev/null 2>&1; then
  echo 'Host prerequisites require Python 3.10 or newer.' >&2
  exit 127
fi
source ./eng/test-ownership.sh
treehammock_owned_test docker-host-system-stack-tests "$@"

# shellcheck source=eng/docker-cli.sh
source ./eng/docker-cli.sh
source ./eng/fixture-isolation.sh
treehammock_initialize_fixture host

cleanup() {
  local primary=$? cleanup_code=0
  trap - EXIT
  python3 eng/test-ownership.py api-stop >/dev/null || cleanup_code=$?
  if [ "$primary" -eq 0 ] && [ "$cleanup_code" -ne 0 ]; then primary=$cleanup_code; fi
  exit "$primary"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_for_system_readiness() {
  python3 eng/test-ownership.py api-ready
}

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker CLI is required to run the host-backed system stack test lane. Install Docker Desktop or Docker Engine, then retry." >&2
  exit 127
fi

if ! command -v dotnet >/dev/null 2>&1; then
  echo ".NET SDK is required to run the backend and system tests on the host." >&2
  exit 127
fi

if ! docker info >/dev/null 2>&1; then
  echo "Docker is installed, but the Docker daemon is not reachable. Start Docker Desktop or the Docker service, wait until Docker is running, then retry ./eng/docker-host-system-stack-tests.sh." >&2
  exit 1
fi

./eng/check-locks.sh

for image in \
  "postgres:16" \
  "docker.dragonflydb.io/dragonflydb/dragonfly:latest" \
  "haproxy:latest"; do
  treehammock_pull_with_retry "$image"
done

mkdir -p "$TREEHAMMOCK_TEST_HOST_LOG_ROOT"
compose=(docker compose -p "$COMPOSE_PROJECT_NAME" -f docker-compose.local-system.yml -f "$TREEHAMMOCK_TEST_OWNERSHIP_OVERRIDE" --profile host-system)
"${compose[@]}" up -d "$@" postgres dragonfly haproxy-host

export ASPNETCORE_ENVIRONMENT=Testing
export DOTNET_ENVIRONMENT=Testing
export SecurityOperationSettings__ActiveKeyVersion=1
export SecurityOperationSettings__HmacKeys__1="$TREEHAMMOCK_FIXTURE_OPERATION_KEY"
export DeliveryOutboxSettings__ActiveKeyVersion=1
export DeliveryOutboxSettings__EncryptionKeys__1="$TREEHAMMOCK_FIXTURE_OUTBOX_KEY"
export ASPNETCORE_URLS=http://127.0.0.1:5001

export DatabaseSettings__servers=127.0.0.1
export DatabaseSettings__database=treehammock
export DatabaseSettings__userId=treehammock
export DatabaseSettings__password="$TREEHAMMOCK_FIXTURE_DB_PASSWORD"
export DatabaseSettings__lc_collation=en_US.UTF-8

export ActiveUserBundleSettings__servers=127.0.0.1
export ActiveUserBundleSettings__port=6379
export ActiveUserBundleSettings__database=0
export ActiveUserBundleSettings__clientName=treehammock-api-host
export ActiveUserBundleSettings__allowAdmin=false
export ActiveUserBundleSettings__reconnectRetryPolicy=5000
export ActiveUserBundleSettings__abortOnConnectFail=false
export ActiveUserBundleSettings__password="$TREEHAMMOCK_FIXTURE_CACHE_PASSWORD"

export TwoFactorSessionBundleSettings__servers=127.0.0.1
export TwoFactorSessionBundleSettings__port=6379
export TwoFactorSessionBundleSettings__database=1
export TwoFactorSessionBundleSettings__clientName=treehammock-api-host-2fa
export TwoFactorSessionBundleSettings__allowAdmin=false
export TwoFactorSessionBundleSettings__reconnectRetryPolicy=5000
export TwoFactorSessionBundleSettings__abortOnConnectFail=false
export TwoFactorSessionBundleSettings__password="$TREEHAMMOCK_FIXTURE_CACHE_PASSWORD"

export AbuseCounterBundleSettings__servers=127.0.0.1
export AbuseCounterBundleSettings__port=6379
export AbuseCounterBundleSettings__database=2
export AbuseCounterBundleSettings__clientName=treehammock-api-host-abuse-counters
export AbuseCounterBundleSettings__allowAdmin=false
export AbuseCounterBundleSettings__reconnectRetryPolicy=5000
export AbuseCounterBundleSettings__abortOnConnectFail=false
export AbuseCounterBundleSettings__password="$TREEHAMMOCK_FIXTURE_CACHE_PASSWORD"

# The host-backed system lane exercises many happy-path flows from one loopback IP.
# Keep production abuse controls enabled, but raise shared-IP test ceilings so
# unrelated end-to-end scenarios do not trip each other's delivery throttles.
export AbuseControlSettings__Delivery__MaxEmailDeliveriesPerAccountPerHour=100
export AbuseControlSettings__Delivery__MaxSmsDeliveriesPerAccountPerHour=100
export AbuseControlSettings__Delivery__MaxEmailDeliveriesPerIpPerHour=100
export AbuseControlSettings__Delivery__MaxSmsDeliveriesPerIpPerHour=100
export AbuseControlSettings__PasswordReset__MaxRequestsPerAccountPerHour=100
export AbuseControlSettings__PasswordReset__MaxRequestsPerIdentifierPerHour=100
export AbuseControlSettings__PasswordReset__MaxRequestsPerIpPerHour=100
export PasswordResetSettings__RequestCooldownSeconds=0
export PasswordResetSettings__DailyRequestLimitPerAccount=100
export PasswordResetSettings__DailyRequestLimitPerDestination=100
export PasswordResetSettings__DailyRequestLimitPerIp=100

export HostingSettings__ConfigureKestrel=true
export HostingSettings__Port=5001
export HostingSettings__BindAddress=127.0.0.1
export HostingSettings__UseHttps=false
export HostingSettings__Protocols=Http1AndHttp2
export HostingSettings__UseHttpsRedirection=false
export HostingSettings__UseForwardedHeaders=true
export HostingSettings__ForwardLimit=1
export HostingSettings__RequireHeaderSymmetry=true
export HostingSettings__TrustAllForwardedHeaderProxies=true
export SystemTestSettings__Enabled=true
export SystemTestSettings__EnableTestInspectionEndpoints=true
export SystemTestSettings__TestKey="$TREEHAMMOCK_FIXTURE_TEST_KEY"
export RegistrationSettings__PublicOrigin=http://localhost:8080
export TREEHAMMOCK_SYSTEM_BASE_URL=http://127.0.0.1:8080
export TREEHAMMOCK_SYSTEM_TEST_KEY="$TREEHAMMOCK_FIXTURE_TEST_KEY"

source "$repo_root/eng/build-identity.sh"
treehammock_begin_build Release

dotnet restore treehammock.Tests.System/treehammock.Tests.System.csproj --locked-mode -p:Configuration=Release
dotnet build treehammock.csproj --configuration Release --no-restore
dotnet build treehammock.Tests.System/treehammock.Tests.System.csproj --configuration Release --no-restore

python3 eng/test-ownership.py api-start >/dev/null

wait_for_system_readiness

if dotnet test treehammock.Tests.System/treehammock.Tests.System.csproj --configuration Release --no-build --no-restore --results-directory "$TREEHAMMOCK_TEST_HOST_LOG_ROOT" --logger "trx;LogFileName=treehammock-system-host-tests.trx"; then
  :
else
  test_code=$?
  echo
  echo "System host API stdout ("$TREEHAMMOCK_TEST_HOST_LOG_ROOT/api.out.log"):"
  tail -200 "$TREEHAMMOCK_TEST_HOST_LOG_ROOT/api.out.log" 2>/dev/null || true
  echo
  echo "System host API stderr ("$TREEHAMMOCK_TEST_HOST_LOG_ROOT/api.err.log"):"
  tail -200 "$TREEHAMMOCK_TEST_HOST_LOG_ROOT/api.err.log" 2>/dev/null || true
  exit "$test_code"
fi

python3 eng/test-ownership.py api-proof
