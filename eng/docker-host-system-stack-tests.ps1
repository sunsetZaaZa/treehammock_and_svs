[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ComposeArgs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'native-command.ps1')
. (Join-Path $PSScriptRoot 'test-ownership.ps1')
. (Join-Path $PSScriptRoot 'fixture-isolation.ps1')

Invoke-TreehammockRunner -Stage 'docker-host-system-stack-tests' -Body {
# When this script is launched by the companion .cmd runner, the entrypoint runs
# under a process-local execution-policy bypass. Set the same process-local policy
# again here so nested PowerShell scripts, such as ./eng/check-locks.ps1, do not
# prompt for "Run once" when the checkout was downloaded from the internet.
if (-not $PSVersionTable.ContainsKey('Platform') -or $PSVersionTable.Platform -eq 'Win32NT') {
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
}


function Wait-ForSystemReadiness {
    param(
        [string]$Url = 'http://localhost:8080/health/ready',
        [int]$TimeoutSeconds = 120,
        [string]$ApiPython
    )

    Invoke-TreehammockNative -Stage 'host-api' -FilePath $ApiPython -Arguments @('eng/test-ownership.py', 'api-ready')
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot
if (Enter-TreehammockOwnedTest -Lane 'docker-host-system-stack-tests' -Arguments $ComposeArgs) { return }
Initialize-TreehammockFixture -Mode 'host' -Owner 'docker-host-system-stack-tests'

$dockerHostCli = $env:TREEHAMMOCK_DOCKER_SELECTED
if ([string]::IsNullOrWhiteSpace($dockerHostCli)) { $dockerHostCli = 'docker' }
if (-not (Get-Command $dockerHostCli -CommandType Application -ErrorAction SilentlyContinue)) {
    throw 'Docker CLI is required to run the host-backed system stack test lane. Install Docker Desktop or Docker Engine, then retry.'
}

if (-not (Get-Command dotnet -CommandType Application -ErrorAction SilentlyContinue)) {
    throw '.NET SDK is required to run the backend and system tests on the host.'
}

try {
    Invoke-TreehammockNative -Stage 'docker-info' -FilePath $dockerHostCli -Arguments @('info') *> $null
}
catch { throw }

$selectedHost = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
$lockArguments = @('-NoLogo', '-NoProfile', '-NonInteractive')
if (-not $PSVersionTable.ContainsKey('Platform') -or $PSVersionTable.Platform -eq 'Win32NT') { $lockArguments += @('-ExecutionPolicy', 'Bypass') }
$lockArguments += @('-File', (Join-Path $repoRoot 'eng/check-locks.ps1'))
Invoke-TreehammockNative -Stage 'host-lock-audit' -FilePath $selectedHost -Arguments $lockArguments

$requiredImages = @(
    'postgres:16',
    'docker.dragonflydb.io/dragonflydb/dragonfly:latest',
    'haproxy:latest'
)

foreach ($image in $requiredImages) {
    Invoke-TreehammockNative -Stage 'docker-pull' -FilePath $dockerHostCli -Arguments @('pull', $image)
}

New-Item -ItemType Directory -Path $env:TREEHAMMOCK_TEST_HOST_LOG_ROOT -Force | Out-Null

$composeFiles = @('-p', $env:COMPOSE_PROJECT_NAME, '-f', 'docker-compose.local-system.yml', '-f', $env:TREEHAMMOCK_TEST_OWNERSHIP_OVERRIDE, '--profile', 'host-system')

$previousEnvironment = @{}
$environmentKeys = @(
    'DeliveryOutboxSettings__ActiveKeyVersion',
    'DeliveryOutboxSettings__EncryptionKeys__1',
    'ASPNETCORE_ENVIRONMENT',
    'DOTNET_ENVIRONMENT',
    'SecurityOperationSettings__ActiveKeyVersion',
    'SecurityOperationSettings__HmacKeys__1',
    'ASPNETCORE_URLS',
    'DatabaseSettings__servers',
    'DatabaseSettings__database',
    'DatabaseSettings__userId',
    'DatabaseSettings__password',
    'DatabaseSettings__lc_collation',
    'ActiveUserBundleSettings__servers',
    'ActiveUserBundleSettings__port',
    'ActiveUserBundleSettings__database',
    'ActiveUserBundleSettings__clientName',
    'ActiveUserBundleSettings__allowAdmin',
    'ActiveUserBundleSettings__reconnectRetryPolicy',
    'ActiveUserBundleSettings__abortOnConnectFail',
    'ActiveUserBundleSettings__password',
    'TwoFactorSessionBundleSettings__servers',
    'TwoFactorSessionBundleSettings__port',
    'TwoFactorSessionBundleSettings__database',
    'TwoFactorSessionBundleSettings__clientName',
    'TwoFactorSessionBundleSettings__allowAdmin',
    'TwoFactorSessionBundleSettings__reconnectRetryPolicy',
    'TwoFactorSessionBundleSettings__abortOnConnectFail',
    'TwoFactorSessionBundleSettings__password',
    'AbuseCounterBundleSettings__servers',
    'AbuseCounterBundleSettings__port',
    'AbuseCounterBundleSettings__database',
    'AbuseCounterBundleSettings__clientName',
    'AbuseCounterBundleSettings__allowAdmin',
    'AbuseCounterBundleSettings__reconnectRetryPolicy',
    'AbuseCounterBundleSettings__abortOnConnectFail',
    'AbuseCounterBundleSettings__password',
    'AbuseControlSettings__Delivery__MaxEmailDeliveriesPerAccountPerHour',
    'AbuseControlSettings__Delivery__MaxSmsDeliveriesPerAccountPerHour',
    'AbuseControlSettings__Delivery__MaxEmailDeliveriesPerIpPerHour',
    'AbuseControlSettings__Delivery__MaxSmsDeliveriesPerIpPerHour',
    'AbuseControlSettings__PasswordReset__MaxRequestsPerAccountPerHour',
    'AbuseControlSettings__PasswordReset__MaxRequestsPerIdentifierPerHour',
    'AbuseControlSettings__PasswordReset__MaxRequestsPerIpPerHour',
    'PasswordResetSettings__RequestCooldownSeconds',
    'PasswordResetSettings__DailyRequestLimitPerAccount',
    'PasswordResetSettings__DailyRequestLimitPerDestination',
    'PasswordResetSettings__DailyRequestLimitPerIp',
    'HostingSettings__ConfigureKestrel',
    'HostingSettings__Port',
    'HostingSettings__BindAddress',
    'HostingSettings__UseHttps',
    'HostingSettings__Protocols',
    'HostingSettings__UseHttpsRedirection',
    'HostingSettings__UseForwardedHeaders',
    'HostingSettings__ForwardLimit',
    'HostingSettings__RequireHeaderSymmetry',
    'HostingSettings__TrustAllForwardedHeaderProxies',
    'SystemTestSettings__Enabled',
    'SystemTestSettings__EnableTestInspectionEndpoints',
    'SystemTestSettings__TestKey',
    'RegistrationSettings__PublicOrigin',
    'TREEHAMMOCK_SYSTEM_BASE_URL',
    'TREEHAMMOCK_SYSTEM_TEST_KEY'
)

foreach ($key in $environmentKeys) {
    $previousEnvironment[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
}

$apiTool = Get-Command python3 -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $apiTool) { $apiTool = Get-Command python -CommandType Application -ErrorAction Stop | Select-Object -First 1 }
$apiPython = $apiTool.Source
$primaryFailure = $null
try {
    Invoke-TreehammockNative -Stage 'docker-compose-2' -FilePath $dockerHostCli -Arguments (@('compose') + $composeFiles + @('up', '-d') + $ComposeArgs + @('postgres', 'dragonfly', 'haproxy-host'))
    $env:ASPNETCORE_ENVIRONMENT = 'Testing'
    $env:DOTNET_ENVIRONMENT = 'Testing'
    $env:SecurityOperationSettings__ActiveKeyVersion = '1'
    $env:SecurityOperationSettings__HmacKeys__1 = $env:TREEHAMMOCK_FIXTURE_OPERATION_KEY
    $env:DeliveryOutboxSettings__ActiveKeyVersion = '1'
    $env:DeliveryOutboxSettings__EncryptionKeys__1 = $env:TREEHAMMOCK_FIXTURE_OUTBOX_KEY
    $env:ASPNETCORE_URLS = 'http://127.0.0.1:5001'

    $env:DatabaseSettings__servers = '127.0.0.1'
    $env:DatabaseSettings__database = 'treehammock'
    $env:DatabaseSettings__userId = 'treehammock'
    $env:DatabaseSettings__password = $env:TREEHAMMOCK_FIXTURE_DB_PASSWORD
    $env:DatabaseSettings__lc_collation = 'en_US.UTF-8'

    $env:ActiveUserBundleSettings__servers = '127.0.0.1'
    $env:ActiveUserBundleSettings__port = '6379'
    $env:ActiveUserBundleSettings__database = '0'
    $env:ActiveUserBundleSettings__clientName = 'treehammock-api-host'
    $env:ActiveUserBundleSettings__allowAdmin = 'false'
    $env:ActiveUserBundleSettings__reconnectRetryPolicy = '5000'
    $env:ActiveUserBundleSettings__abortOnConnectFail = 'false'
    $env:ActiveUserBundleSettings__password = $env:TREEHAMMOCK_FIXTURE_CACHE_PASSWORD

    $env:TwoFactorSessionBundleSettings__servers = '127.0.0.1'
    $env:TwoFactorSessionBundleSettings__port = '6379'
    $env:TwoFactorSessionBundleSettings__database = '1'
    $env:TwoFactorSessionBundleSettings__clientName = 'treehammock-api-host-2fa'
    $env:TwoFactorSessionBundleSettings__allowAdmin = 'false'
    $env:TwoFactorSessionBundleSettings__reconnectRetryPolicy = '5000'
    $env:TwoFactorSessionBundleSettings__abortOnConnectFail = 'false'
    $env:TwoFactorSessionBundleSettings__password = $env:TREEHAMMOCK_FIXTURE_CACHE_PASSWORD

    $env:AbuseCounterBundleSettings__servers = '127.0.0.1'
    $env:AbuseCounterBundleSettings__port = '6379'
    $env:AbuseCounterBundleSettings__database = '2'
    $env:AbuseCounterBundleSettings__clientName = 'treehammock-api-host-abuse-counters'
    $env:AbuseCounterBundleSettings__allowAdmin = 'false'
    $env:AbuseCounterBundleSettings__reconnectRetryPolicy = '5000'
    $env:AbuseCounterBundleSettings__abortOnConnectFail = 'false'
    $env:AbuseCounterBundleSettings__password = $env:TREEHAMMOCK_FIXTURE_CACHE_PASSWORD

    # The host-backed system lane exercises many happy-path flows from one loopback IP.
    # Keep production abuse controls enabled, but raise shared-IP test ceilings so
    # unrelated end-to-end scenarios do not trip each other's delivery throttles.
    $env:AbuseControlSettings__Delivery__MaxEmailDeliveriesPerAccountPerHour = '100'
    $env:AbuseControlSettings__Delivery__MaxSmsDeliveriesPerAccountPerHour = '100'
    $env:AbuseControlSettings__Delivery__MaxEmailDeliveriesPerIpPerHour = '100'
    $env:AbuseControlSettings__Delivery__MaxSmsDeliveriesPerIpPerHour = '100'
    $env:AbuseControlSettings__PasswordReset__MaxRequestsPerAccountPerHour = '100'
    $env:AbuseControlSettings__PasswordReset__MaxRequestsPerIdentifierPerHour = '100'
    $env:AbuseControlSettings__PasswordReset__MaxRequestsPerIpPerHour = '100'
    $env:PasswordResetSettings__RequestCooldownSeconds = '0'
    $env:PasswordResetSettings__DailyRequestLimitPerAccount = '100'
    $env:PasswordResetSettings__DailyRequestLimitPerDestination = '100'
    $env:PasswordResetSettings__DailyRequestLimitPerIp = '100'

    $env:HostingSettings__ConfigureKestrel = 'true'
    $env:HostingSettings__Port = '5001'
    $env:HostingSettings__BindAddress = '127.0.0.1'
    $env:HostingSettings__UseHttps = 'false'
    $env:HostingSettings__Protocols = 'Http1AndHttp2'
    $env:HostingSettings__UseHttpsRedirection = 'false'
    $env:HostingSettings__UseForwardedHeaders = 'true'
    $env:HostingSettings__ForwardLimit = '1'
    $env:HostingSettings__RequireHeaderSymmetry = 'true'
    $env:HostingSettings__TrustAllForwardedHeaderProxies = 'true'
    $env:SystemTestSettings__Enabled = 'true'
    $env:SystemTestSettings__EnableTestInspectionEndpoints = 'true'
    $env:SystemTestSettings__TestKey = $env:TREEHAMMOCK_FIXTURE_TEST_KEY
    $env:RegistrationSettings__PublicOrigin = 'http://localhost:8080'
    $env:TREEHAMMOCK_SYSTEM_BASE_URL = 'http://127.0.0.1:8080'
    $env:TREEHAMMOCK_SYSTEM_TEST_KEY = $env:TREEHAMMOCK_FIXTURE_TEST_KEY

    Start-TreehammockBuildIdentity -Configuration 'Release'
    Invoke-TreehammockNative -Stage 'dotnet-restore' -FilePath 'dotnet' -Arguments @('restore', 'treehammock.Tests.System/treehammock.Tests.System.csproj', '--locked-mode', '-p:Configuration=Release')

    Invoke-TreehammockNative -Stage 'dotnet-app-build' -FilePath 'dotnet' -Arguments @('build', 'treehammock.csproj', '--configuration', 'Release', '--no-restore')
    Invoke-TreehammockNative -Stage 'dotnet-build' -FilePath 'dotnet' -Arguments @('build', 'treehammock.Tests.System/treehammock.Tests.System.csproj', '--configuration', 'Release', '--no-restore')

    Invoke-TreehammockNative -Stage 'host-api-start' -FilePath $apiPython -Arguments @('eng/test-ownership.py', 'api-start')
    Wait-ForSystemReadiness -ApiPython $apiPython

    Invoke-TreehammockNative -Stage 'dotnet-test' -FilePath 'dotnet' -Arguments @('test', 'treehammock.Tests.System/treehammock.Tests.System.csproj', '--configuration', 'Release', '--no-build', '--no-restore', '--results-directory', $env:TREEHAMMOCK_TEST_HOST_LOG_ROOT, '--logger', 'trx;LogFileName=treehammock-system-host-tests.trx')
    Invoke-TreehammockNative -Stage 'host-api-proof' -FilePath $apiPython -Arguments @('eng/test-ownership.py', 'api-proof')

}
catch {
    $primaryFailure = $_.Exception
    # Diagnostics do not replace the captured native failure.
    foreach ($log in @((Join-Path $env:TREEHAMMOCK_TEST_HOST_LOG_ROOT 'api.out.log'), (Join-Path $env:TREEHAMMOCK_TEST_HOST_LOG_ROOT 'api.err.log'))) {
        if (Test-Path $log) { Get-Content $log -Tail 200 -ErrorAction SilentlyContinue }
    }
}
finally {
    try {
        Invoke-TreehammockNative -Stage 'host-api-stop' -FilePath $apiPython -Arguments @('eng/test-ownership.py', 'api-stop')
    }
    catch { if ($null -eq $primaryFailure) { $primaryFailure = $_.Exception } }
    foreach ($key in $environmentKeys) {
        try { [Environment]::SetEnvironmentVariable($key, $previousEnvironment[$key], 'Process') }
        catch { if ($null -eq $primaryFailure) { $primaryFailure = $_.Exception } }
    }
}
if ($null -ne $primaryFailure) { throw $primaryFailure }
}
