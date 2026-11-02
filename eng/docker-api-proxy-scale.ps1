[CmdletBinding()]
param(
    [int]$ApiReplicas = 2,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ComposeArgs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'native-command.ps1')
. (Join-Path $PSScriptRoot 'fixture-isolation.ps1')

Invoke-TreehammockRunner -Stage 'docker-api-proxy-scale' -Body {
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot
Initialize-TreehammockFixture -Mode 'published' -Owner 'docker-api-proxy-scale'

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker is required to run the scaled HAProxy Compose stack.'
}

Invoke-TreehammockScript -Stage 'check-locks' -Path './eng/check-locks.ps1'

Invoke-TreehammockNative -Stage 'docker-compose' -FilePath 'docker' -Arguments (@('compose', '-f', 'docker-compose.integration.yml', '-f', 'docker-compose.host-access.yml', '-f', 'docker-compose.api-proxy.yml', '-f', 'docker-compose.proxy-access.yml', '--profile', 'proxy', 'up', '--build', '--scale', "api=$ApiReplicas") + $ComposeArgs + @('postgres', 'dragonfly', 'api', 'haproxy'))
}
