[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release', 'Sandbox')]
    [string]$Configuration = 'Release',

    [ValidateNotNullOrEmpty()]
    [string]$Image = 'treehammock:api',

    [switch]$NoCache,

    [ValidateSet('auto', 'plain', 'tty')]
    [string]$Progress = 'auto'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'native-command.ps1')

Invoke-TreehammockRunner -Stage 'docker-api-image' -Body {
# PowerShell names are case-insensitive. Keep the caller's tag immutable and
# separate from every base-image reference used during prerequisite checks.
Set-Variable -Name outputImage -Value $Image -Option ReadOnly
$sdkImage = [Environment]::GetEnvironmentVariable('TREEHAMMOCK_DOTNET_SDK_IMAGE', 'Process')
$runtimeImage = [Environment]::GetEnvironmentVariable('TREEHAMMOCK_DOTNET_RUNTIME_IMAGE', 'Process')
if ([string]::IsNullOrEmpty($sdkImage)) { $sdkImage = 'mcr.microsoft.com/dotnet/sdk:8.0' }
if ([string]::IsNullOrEmpty($runtimeImage)) { $runtimeImage = 'mcr.microsoft.com/dotnet/aspnet:8.0' }
if ([string]::IsNullOrWhiteSpace($outputImage) -or $outputImage -eq $sdkImage -or $outputImage -eq $runtimeImage) {
    throw 'API output tag must be nonblank and distinct from the selected base references.'
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker is required to build the API runtime image.'
}

Invoke-TreehammockScript -Stage 'check-locks' -Path './eng/check-locks.ps1'

$requiredImages = @($sdkImage, $runtimeImage)

foreach ($baseImage in $requiredImages) {
    Invoke-TreehammockNative -Stage 'docker-pull' -FilePath 'docker' -Arguments @('pull', $baseImage)
}

Start-TreehammockBuildIdentity -Configuration $Configuration

$buildArgs = @(
    'build',
    '--target', 'api',
    '--build-arg', "DOTNET_SDK_IMAGE=$sdkImage",
    '--build-arg', "DOTNET_RUNTIME_IMAGE=$runtimeImage",
    '--build-arg', "BUILD_CONFIGURATION=$Configuration",
    '--build-arg', "TREEHAMMOCK_BUILD_RUN_ID=$env:TREEHAMMOCK_BUILD_RUN_ID",
    '--progress', $Progress,
    '-t', $outputImage
)

if ($NoCache) {
    $buildArgs += '--no-cache'
}

$buildArgs += '.'

Invoke-TreehammockNative -Stage 'docker-build' -FilePath 'docker' -Arguments $buildArgs
}
