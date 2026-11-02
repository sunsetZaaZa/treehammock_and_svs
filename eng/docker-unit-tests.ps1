[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release', 'Sandbox')]
    [string]$Configuration = 'Release',

    [string]$Image,

    [switch]$NoCache,

    [ValidateSet('auto', 'plain', 'tty')]
    [string]$Progress = 'auto'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'native-command.ps1')
. (Join-Path $PSScriptRoot 'test-ownership.ps1')

Invoke-TreehammockRunner -Stage 'docker-unit-tests' -Body {
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot
$ownedArgs = @('-Configuration',$Configuration,'-Progress',$Progress)
if ($NoCache) { $ownedArgs += '-NoCache' }
if ($Image) { throw 'Disposable unit image names are assigned by the owned run.' }
if (Enter-TreehammockOwnedTest -Lane 'docker-unit-tests' -Arguments $ownedArgs) { return }
$Image = $env:TREEHAMMOCK_TEST_UNIT_IMAGE

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker is required to run the containerized unit-test lane.'
}

Invoke-TreehammockScript -Stage 'check-locks' -Path './eng/check-locks.ps1'

Start-TreehammockBuildIdentity -Configuration $Configuration

$buildArgs = @(
    'build',
    '--label', "io.treehammock.fixture.owner=$env:TREEHAMMOCK_TEST_RUN_ID",
    '--label', "io.treehammock.fixture.project=$env:COMPOSE_PROJECT_NAME",
    '--label', 'io.treehammock.fixture.role=disposable-test',
    '--target', 'unit-test',
    '--build-arg', "BUILD_CONFIGURATION=$Configuration",
    '--build-arg', "TREEHAMMOCK_BUILD_RUN_ID=$env:TREEHAMMOCK_BUILD_RUN_ID",
    '--progress', $Progress,
    '-t', $Image
)

if ($NoCache) {
    $buildArgs += '--no-cache'
}

$buildArgs += '.'

Invoke-TreehammockNative -Stage 'docker-build' -FilePath 'docker' -Arguments $buildArgs
}
