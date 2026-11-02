# Source-only fixture environment, restored by the owning COR23Q runner.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Initialize-TreehammockFixture {
    param([ValidateSet('container','published','host')][string]$Mode, [string]$Owner)
    $python = Get-Command python3 -CommandType Application -ErrorAction SilentlyContinue
    if ($null -eq $python) { $python = Get-Command python -CommandType Application -ErrorAction SilentlyContinue }
    if ($null -eq $python) { throw (New-TreehammockStageFailure 'fixture-python' 127) }
    Invoke-TreehammockNative -Stage 'fixture-settings' -FilePath $python.Source -Arguments @('eng/fixture-isolation.py','--mode',$Mode) *> $null
    $project = $env:COMPOSE_PROJECT_NAME
    if ([string]::IsNullOrEmpty($project)) { $project = (Split-Path -Leaf $repoRoot).ToLowerInvariant() -replace '[^a-z0-9_-]', '' }
    $file = Join-Path $repoRoot ('.docker/fixtures/' + $project + '/compose.env')
    $script:treehammockFixtureOwner = $Owner
    $script:treehammockFixturePrior = @{ COMPOSE_PROJECT_NAME = [Environment]::GetEnvironmentVariable('COMPOSE_PROJECT_NAME','Process') }
    $env:COMPOSE_PROJECT_NAME = $project
    foreach ($line in [IO.File]::ReadAllLines($file)) {
        $parts = $line.Split(@('='),2)
        if ($parts.Count -ne 2 -or $parts[0] -notin @('TREEHAMMOCK_FIXTURE_DB_PASSWORD','TREEHAMMOCK_FIXTURE_CACHE_PASSWORD','TREEHAMMOCK_FIXTURE_TEST_KEY','TREEHAMMOCK_FIXTURE_OUTBOX_KEY','TREEHAMMOCK_FIXTURE_OPERATION_KEY')) { throw 'Invalid fixture settings.' }
        $script:treehammockFixturePrior[$parts[0]] = [Environment]::GetEnvironmentVariable($parts[0],'Process')
        [Environment]::SetEnvironmentVariable($parts[0],$parts[1],'Process')
    }
}
function Restore-TreehammockFixtureEnvironment {
    param([string]$Owner)
    if ((Get-Variable treehammockFixtureOwner -Scope Script -ErrorAction SilentlyContinue) -and $script:treehammockFixtureOwner -eq $Owner) {
        foreach ($key in $script:treehammockFixturePrior.Keys) { [Environment]::SetEnvironmentVariable($key,$script:treehammockFixturePrior[$key],'Process') }
        $script:treehammockFixtureOwner = ''
    }
}
