[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release', 'Sandbox')]
    [string] $Configuration = 'Release',

    [switch] $RefreshLocks,
    [switch] $RequireLocks,
    [switch] $LockedRestore,
    [switch] $RunSqlContracts,
    [switch] $CollectCoverage
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'native-command.ps1')

Invoke-TreehammockRunner -Stage 'build-proof' -Body {
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw 'The .NET SDK is required to prove this build. Install .NET 8 and rerun ./eng/build-proof.ps1.'
}

Invoke-TreehammockNative -Stage 'dotnet-info' -FilePath 'dotnet' -Arguments @('--info')

if ($RefreshLocks) {
    Invoke-TreehammockScript -Stage 'restore-locks' -Path './eng/restore-locks.ps1'
}

if ($RequireLocks -or $LockedRestore) {
    Invoke-TreehammockScript -Stage 'check-locks' -Path './eng/check-locks.ps1'
}

Invoke-TreehammockScript -Stage 'validate' -Path './eng/validate.ps1' -Parameters @{ Configuration = $Configuration; LockedRestore = $LockedRestore; CollectCoverage = $CollectCoverage }

if ($RunSqlContracts) {
    Invoke-TreehammockScript -Stage 'sql-contracts' -Path './eng/sql-contracts.ps1' -Parameters @{ Configuration = $Configuration; LockedRestore = $LockedRestore }
}
}
