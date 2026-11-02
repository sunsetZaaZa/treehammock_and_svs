[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ComposeArgs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'native-command.ps1')
. (Join-Path $PSScriptRoot 'fixture-isolation.ps1')

Invoke-TreehammockRunner -Stage 'docker-api-direct-up' -Body {
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot
Initialize-TreehammockFixture -Mode 'published' -Owner 'docker-api-direct-up'

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker is required to run the API Compose stack.'
}

Invoke-TreehammockScript -Stage 'check-locks' -Path './eng/check-locks.ps1'

Invoke-TreehammockNative -Stage 'docker-compose' -FilePath 'docker' -Arguments (@('compose', '-f', 'docker-compose.integration.yml', '-f', 'docker-compose.host-access.yml', '-f', 'docker-compose.api-direct.yml', 'up', '--build') + $ComposeArgs + @('postgres', 'dragonfly', 'api'))
}
