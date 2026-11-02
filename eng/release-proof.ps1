# Local source/SQL gate. Immutable candidate proof: eng/release_artifacts.py
# Native archive/image/registry qualification: eng/test-release-artifacts.py
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release', 'Sandbox')]
    [string] $Configuration = 'Release'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'native-command.ps1')

Invoke-TreehammockRunner -Stage 'release-proof' -Body {
$treehammockRunDeferredSqlContracts = [Environment]::GetEnvironmentVariable('TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS', 'Process')
$treehammockDbContractConnection = [Environment]::GetEnvironmentVariable('TREEHAMMOCK_DB_CONTRACT_CONNECTION', 'Process')

if ($treehammockRunDeferredSqlContracts -ne 'true' -and $treehammockRunDeferredSqlContracts -ne '1') {
    throw 'TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS must be true or 1 for the final release gate.'
}

if ([string]::IsNullOrWhiteSpace($treehammockDbContractConnection)) {
    throw 'TREEHAMMOCK_DB_CONTRACT_CONNECTION must point to a disposable PostgreSQL database for the final release gate.'
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot

Invoke-TreehammockScript -Stage 'build-proof' -Path './eng/build-proof.ps1' -Parameters @{ Configuration = $Configuration; LockedRestore = $true; RunSqlContracts = $true }
}
