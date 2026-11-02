[CmdletBinding()]
param(
    [string]$Configuration = "Release",
    [switch]$LockedRestore,
    [switch]$CollectCoverage
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'native-command.ps1')

Invoke-TreehammockRunner -Stage 'dotnet-integration-tests' -Body {
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $RepoRoot

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw "The .NET SDK is required to run the integration-test lane."
}

Start-TreehammockBuildIdentity -Configuration $Configuration

$env:DOTNET_NOLOGO = 'true'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = 'true'
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = 'true'

$restoreArgs = @('restore', 'treehammock.sln', '--use-lock-file', "-p:Configuration=$Configuration")
if ($LockedRestore) {
    Invoke-TreehammockScript -Stage 'check-locks' -Path './eng/check-locks.ps1'
    $restoreArgs += '--locked-mode'
}

Invoke-TreehammockNative -Stage 'dotnet-restore' -FilePath 'dotnet' -Arguments $restoreArgs
Invoke-TreehammockNative -Stage 'dotnet-build' -FilePath 'dotnet' -Arguments @('build', 'treehammock.sln', '--configuration', $Configuration, '--no-restore', '-p:ContinuousIntegrationBuild=true')

$testArgs = @(
    'test',
    'treehammock.Tests/treehammock.Tests.csproj',
    '--configuration', $Configuration,
    '--no-build',
    '--no-restore',
    '--filter', 'FullyQualifiedName~treehammock.Tests.Integration',
    '--logger', 'trx;LogFileName=treehammock-integration-tests.trx'
)

if ($CollectCoverage) {
    Invoke-TreehammockCoverage -Lane 'integration' -Configuration $Configuration
} else {
    Invoke-TreehammockNative -Stage 'dotnet-test' -FilePath 'dotnet' -Arguments $testArgs
}
}
