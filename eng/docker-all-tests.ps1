[CmdletBinding()]
param(
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'native-command.ps1')
. (Join-Path $PSScriptRoot 'test-ownership.ps1')

Invoke-TreehammockRunner -Stage 'docker-all-tests' -Body {
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot

if ($Help) {
    @'
Usage: ./eng/docker-all-tests.ps1

Runs all Docker-backed validation lanes in sequence:
  1. Unit tests in the Docker unit-test image
  2. SQL contract suite tests against Compose PostgreSQL
  3. Bruno HTTP checks against the API service directly
  4. Bruno HTTP checks against the HAProxy service
  5. Full Compose system tests through HAProxy

Generate package lock files first:
  ./eng/restore-locks.ps1
'@ | Write-Output
    exit 0
}

if (Enter-TreehammockOwnedTest -Lane 'docker-all-tests') { return }

Invoke-TreehammockScript -Stage 'docker-unit-tests' -Path './eng/docker-unit-tests.ps1'
Invoke-TreehammockScript -Stage 'docker-sql-contracts' -Path './eng/docker-sql-contracts.ps1'
Invoke-TreehammockScript -Stage 'docker-http-contracts-direct' -Path './eng/docker-http-contracts-direct.ps1'
Invoke-TreehammockScript -Stage 'docker-http-contracts-proxy' -Path './eng/docker-http-contracts-proxy.ps1'

Invoke-TreehammockScript -Stage 'docker-system-stack-tests' -Path './eng/docker-system-stack-tests.ps1'
}
