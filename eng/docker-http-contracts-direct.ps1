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

Invoke-TreehammockRunner -Stage 'docker-http-contracts-direct' -Body {
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot
if (Enter-TreehammockOwnedTest -Lane 'docker-http-contracts-direct' -Arguments $ComposeArgs) { return }
Initialize-TreehammockFixture -Mode 'container' -Owner 'docker-http-contracts-direct'

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker is required to run the direct HTTP contract test Compose lane.'
}

Invoke-TreehammockScript -Stage 'check-locks' -Path './eng/check-locks.ps1'

Invoke-TreehammockNative -Stage 'docker-compose' -FilePath 'docker' -Arguments (@('compose', '-p', $env:COMPOSE_PROJECT_NAME, '-f', 'docker-compose.integration.yml', '-f', 'docker-compose.testing.yml', '-f', 'docker-compose.ci-system.yml', '-f', $env:TREEHAMMOCK_TEST_OWNERSHIP_OVERRIDE, '--profile', 'http', 'run', '--rm', '--build') + $ComposeArgs + @('http-contract-tests-direct'))
}
