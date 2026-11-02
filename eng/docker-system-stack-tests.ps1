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

Invoke-TreehammockRunner -Stage 'docker-system-stack-tests' -Body {
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot
if (Enter-TreehammockOwnedTest -Lane 'docker-system-stack-tests' -Arguments $ComposeArgs) { return }
Initialize-TreehammockFixture -Mode 'container' -Owner 'docker-system-stack-tests'

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker CLI is required to run the full system stack test lane. Install Docker Desktop or Docker Engine, then retry.'
}

try {
    Invoke-TreehammockNative -Stage 'docker-info' -FilePath 'docker' -Arguments @('info') *> $null
}
catch { throw }

Invoke-TreehammockScript -Stage 'check-locks' -Path './eng/check-locks.ps1'

$requiredImages = @(
    'mcr.microsoft.com/dotnet/sdk:8.0',
    'mcr.microsoft.com/dotnet/aspnet:8.0',
    'postgres:16',
    'docker.dragonflydb.io/dragonflydb/dragonfly:latest',
    'haproxy:latest'
)

foreach ($image in $requiredImages) {
    Invoke-TreehammockNative -Stage 'docker-pull' -FilePath 'docker' -Arguments @('pull', $image)
}


Invoke-TreehammockNative -Stage 'docker-compose-2' -FilePath 'docker' -Arguments (@('compose', '-p', $env:COMPOSE_PROJECT_NAME, '-f', 'docker-compose.integration.yml', '-f', 'docker-compose.api-proxy.yml', '-f', 'docker-compose.testing.yml', '-f', 'docker-compose.ci-system.yml', '--profile', 'proxy', '-f', $env:TREEHAMMOCK_TEST_OWNERSHIP_OVERRIDE, '--profile', 'system', 'up', '--build', '--abort-on-container-exit', '--exit-code-from', 'system-tests') + $ComposeArgs + @('system-tests'))
}
