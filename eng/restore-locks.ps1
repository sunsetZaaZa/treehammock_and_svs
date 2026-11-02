[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'native-command.ps1')

Invoke-TreehammockRunner -Stage 'restore-locks' -Body {
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot

$env:DOTNET_NOLOGO = 'true'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = 'true'
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = 'true'

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw 'The .NET SDK is required to refresh package lock files. Install .NET 8 and rerun ./eng/restore-locks.ps1.'
}

Invoke-TreehammockNative -Stage 'dotnet-restore' -FilePath 'dotnet' -Arguments @('restore', 'treehammock.sln', '--use-lock-file', '--force-evaluate')
Invoke-TreehammockNative -Stage 'dotnet-restore-2' -FilePath 'dotnet' -Arguments @('restore', 'eng/treehammock.SqlContracts.sln', '--use-lock-file', '--force-evaluate')
Invoke-TreehammockNative -Stage 'dotnet-restore-3' -FilePath 'dotnet' -Arguments @('restore', 'treehammock.Tests.System/treehammock.Tests.System.csproj', '--use-lock-file', '--force-evaluate')
Invoke-TreehammockScript -Stage 'check-locks' -Path './eng/check-locks.ps1'

Write-Host ''
if (Get-Command git -ErrorAction SilentlyContinue) {
    Write-Host 'Review and commit generated lock files:'
    Invoke-TreehammockNative -Stage 'git-status' -FilePath 'git' -Arguments @('status', '--short', '--', '**/packages.lock.json', 'Directory.Packages.props', '**/*.csproj')
} else {
    Write-Host 'dotnet restore completed. Review generated packages.lock.json files before committing.'
}
}
