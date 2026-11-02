[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ComposeArgs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'native-command.ps1')
. (Join-Path $PSScriptRoot 'fixture-isolation.ps1')

Invoke-TreehammockRunner -Stage 'docker-down' -Body {
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot
Initialize-TreehammockFixture -Mode 'container' -Owner 'docker-down'

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker is required to stop the Compose stack.'
}

Invoke-TreehammockNative -Stage 'docker-compose' -FilePath 'docker' -Arguments (@('compose', '-f', 'docker-compose.integration.yml', '-f', 'docker-compose.api-direct.yml', '-f', 'docker-compose.api-proxy.yml', '-f', 'docker-compose.ci-system.yml', '-f', 'docker-compose.local-system.yml', '--profile', 'proxy', '--profile', 'sql', '--profile', 'http', '--profile', 'http-proxy', '--profile', 'system', '--profile', 'host-system', 'down') + $ComposeArgs)
}
