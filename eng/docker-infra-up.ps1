[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ComposeArgs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'native-command.ps1')
. (Join-Path $PSScriptRoot 'fixture-isolation.ps1')

Invoke-TreehammockRunner -Stage 'docker-infra-up' -Body {
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot
Initialize-TreehammockFixture -Mode 'published' -Owner 'docker-infra-up'

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker is required to run the Compose infrastructure stack.'
}

Invoke-TreehammockNative -Stage 'docker-compose' -FilePath 'docker' -Arguments (@('compose', '-f', 'docker-compose.integration.yml', '-f', 'docker-compose.host-access.yml', 'up') + $ComposeArgs + @('postgres', 'dragonfly'))
}
