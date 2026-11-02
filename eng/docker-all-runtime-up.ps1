[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ComposeArgs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'native-command.ps1')
. (Join-Path $PSScriptRoot 'fixture-isolation.ps1')

Invoke-TreehammockRunner -Stage 'docker-all-runtime-up' -Body {
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot
Initialize-TreehammockFixture -Mode 'published' -Owner 'docker-all-runtime-up'

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker is required to run the full Docker runtime stack.'
}

Invoke-TreehammockScript -Stage 'check-locks' -Path './eng/check-locks.ps1'

# Full runtime mode means every long-running service used by local integration:
# PostgreSQL + DragonflyDB + API + HAProxy. Test runners remain explicit one-shot lanes.
Invoke-TreehammockNative -Stage 'docker-compose' -FilePath 'docker' -Arguments (@('compose', '-f', 'docker-compose.integration.yml', '-f', 'docker-compose.host-access.yml', '-f', 'docker-compose.api-proxy.yml', '-f', 'docker-compose.proxy-access.yml', '--profile', 'proxy', 'up', '--build') + $ComposeArgs + @('postgres', 'dragonfly', 'api', 'haproxy'))
}
