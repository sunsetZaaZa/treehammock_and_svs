[CmdletBinding()]
param(
    [string] $BaselineOutput = '',

    [ValidateSet('Debug', 'Release', 'Sandbox')]
    [string] $Configuration = 'Release',

    [switch] $LockedRestore
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'native-command.ps1')

Invoke-TreehammockRunner -Stage 'sql-contracts' -Body {
if (-not [string]::IsNullOrWhiteSpace($BaselineOutput)) {
    if ($Configuration -ne 'Release') { throw 'Correction evidence currently qualifies only Release.' }
    Invoke-TreehammockScript -Stage 'correction-baseline' -Path (Join-Path $PSScriptRoot 'correction-baseline.ps1') -Parameters @{ Lane = 'sql'; Output = $BaselineOutput }
    return
}

$treehammockRunDeferredSqlContracts = [Environment]::GetEnvironmentVariable('TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS', 'Process')
$treehammockDbContractConnection = [Environment]::GetEnvironmentVariable('TREEHAMMOCK_DB_CONTRACT_CONNECTION', 'Process')

if ($treehammockRunDeferredSqlContracts -ne 'true' -and $treehammockRunDeferredSqlContracts -ne '1') {
    throw 'TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS must be true or 1 to run SQL contract tests.'
}

if ([string]::IsNullOrWhiteSpace($treehammockDbContractConnection)) {
    throw 'TREEHAMMOCK_DB_CONTRACT_CONNECTION must point to a disposable PostgreSQL database.'
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot

Start-TreehammockBuildIdentity -Configuration $Configuration

$env:DOTNET_NOLOGO = 'true'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = 'true'
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = 'true'

Invoke-TreehammockNative -Stage 'dotnet-info' -FilePath 'dotnet' -Arguments @('--info')

$restoreArgs = @('restore', 'eng/treehammock.SqlContracts.sln', '--use-lock-file', "-p:Configuration=$Configuration")
if ($LockedRestore) {
    Invoke-TreehammockScript -Stage 'check-locks' -Path './eng/check-locks.ps1'
    $restoreArgs += '--locked-mode'
}

Invoke-TreehammockNative -Stage 'dotnet-restore' -FilePath 'dotnet' -Arguments $restoreArgs
Invoke-TreehammockNative -Stage 'dotnet-build' -FilePath 'dotnet' -Arguments @('build', 'eng/treehammock.SqlContracts.sln', '--configuration', $Configuration, '--no-restore', '-p:ContinuousIntegrationBuild=true')
Invoke-TreehammockNative -Stage 'dotnet-test' -FilePath 'dotnet' -Arguments @('test', 'treehammock.Tests.SqlContracts/treehammock.Tests.SqlContracts.csproj', '--configuration', $Configuration, '--no-build', '--no-restore', '--logger', 'trx;LogFileName=treehammock-sql-contracts.trx')
}
