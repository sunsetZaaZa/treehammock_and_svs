[CmdletBinding()]
param(
    [string] $BaselineOutput = '',

    [ValidateSet('Debug', 'Release', 'Sandbox')]
    [string] $Configuration = 'Release',

    [switch] $LockedRestore,

    [switch] $CollectCoverage
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'native-command.ps1')

Invoke-TreehammockRunner -Stage 'validate' -Body {
if (-not [string]::IsNullOrWhiteSpace($BaselineOutput)) {
    if ($Configuration -ne 'Release') { throw 'Correction evidence currently qualifies only Release.' }
    Invoke-TreehammockScript -Stage 'correction-baseline' -Path (Join-Path $PSScriptRoot 'correction-baseline.ps1') -Parameters @{ Lane = 'fast'; Output = $BaselineOutput; CollectCoverage = $CollectCoverage }
    return
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot

Start-TreehammockBuildIdentity -Configuration $Configuration

$env:DOTNET_NOLOGO = 'true'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = 'true'
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = 'true'

Invoke-TreehammockNative -Stage 'dotnet-info' -FilePath 'dotnet' -Arguments @('--info')

$restoreArgs = @('restore', 'treehammock.sln', '--use-lock-file', "-p:Configuration=$Configuration")
if ($LockedRestore) {
    Invoke-TreehammockScript -Stage 'check-locks' -Path './eng/check-locks.ps1'
    $restoreArgs += '--locked-mode'
}

Invoke-TreehammockNative -Stage 'dotnet-restore' -FilePath 'dotnet' -Arguments $restoreArgs
Invoke-TreehammockNative -Stage 'dotnet-build' -FilePath 'dotnet' -Arguments @('build', 'treehammock.sln', '--configuration', $Configuration, '--no-restore', '-p:ContinuousIntegrationBuild=true')

$unitArgs = @(
    'test',
    'treehammock.Tests/treehammock.Tests.csproj',
    '--configuration', $Configuration,
    '--no-build',
    '--no-restore',
    '--filter', 'FullyQualifiedName~treehammock.Tests.Unit',
    '--logger', 'trx;LogFileName=treehammock-unit-tests.trx'
)

$integrationArgs = @(
    'test',
    'treehammock.Tests/treehammock.Tests.csproj',
    '--configuration', $Configuration,
    '--no-build',
    '--no-restore',
    '--filter', 'FullyQualifiedName~treehammock.Tests.Integration',
    '--logger', 'trx;LogFileName=treehammock-integration-tests.trx'
)

if ($CollectCoverage) {
    Invoke-TreehammockCoverage -Lane 'unit' -Configuration $Configuration
    Invoke-TreehammockCoverage -Lane 'integration' -Configuration $Configuration
} else {
    Invoke-TreehammockNative -Stage 'dotnet-unit-test' -FilePath 'dotnet' -Arguments $unitArgs
    Invoke-TreehammockNative -Stage 'dotnet-integration-test' -FilePath 'dotnet' -Arguments $integrationArgs
}
}
