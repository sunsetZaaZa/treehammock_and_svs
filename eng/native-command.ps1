# Shared COR23Q command boundary. Dot-source only; this file does not run a lane.
Set-StrictMode -Version Latest

function New-TreehammockStageFailure {
    param([string]$Stage, [int]$ExitCode)
    $failure = New-Object System.Exception -ArgumentList "Stage '$Stage' failed (exit $ExitCode)."
    $failure.Data['TreehammockExitCode'] = $ExitCode
    $failure.Data['TreehammockStage'] = $Stage
    return $failure
}

function Get-TreehammockFailureCode {
    param([System.Exception]$Failure)
    $current = $Failure
    while ($null -ne $current) {
        if ($current.Data.Contains('TreehammockExitCode')) { return [int]$current.Data['TreehammockExitCode'] }
        $current = $current.InnerException
    }
    return 1
}

function Get-TreehammockFailureStage {
    param([System.Exception]$Failure, [string]$Fallback)
    $current = $Failure
    while ($null -ne $current) {
        if ($current.Data.Contains('TreehammockStage')) { return [string]$current.Data['TreehammockStage'] }
        $current = $current.InnerException
    }
    return $Fallback
}

function Invoke-TreehammockNative {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][ValidatePattern('^[a-z0-9_.-]{1,80}$')][string]$Stage,
        [Parameter(Mandatory=$true)][string]$FilePath,
        [string[]]$Arguments = @()
    )
    # Resolve an executable, never a profile alias/function. Native stderr is output,
    # not the exit-code oracle. PS 7.3+ preference is scoped to this function.
    $tool = Get-Command -Name $FilePath -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $tool) { throw (New-TreehammockStageFailure $Stage 127) }
    $PSNativeCommandUseErrorActionPreference = $false
    $ErrorActionPreference = 'Continue'
    $global:LASTEXITCODE = $null
    try {
        & $tool.Source @Arguments
        $nativeExitCode = $LASTEXITCODE # Capture immediately, before output/cmdlets/cleanup.
    }
    catch { throw (New-TreehammockStageFailure $Stage 126) }
    if ($null -eq $nativeExitCode) { throw (New-TreehammockStageFailure $Stage 126) }
    if ($nativeExitCode -ne 0) { throw (New-TreehammockStageFailure $Stage $nativeExitCode) }
}

function Invoke-TreehammockScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][ValidatePattern('^[a-z0-9_.-]{1,80}$')][string]$Stage,
        [Parameter(Mandatory=$true)][string]$Path,
        [hashtable]$Parameters = @{}
    )
    $global:LASTEXITCODE = 0
    & $Path @Parameters
    $scriptExitCode = $LASTEXITCODE # Child exit must be checked even when it did not throw.
    if ($scriptExitCode -ne 0) { throw (New-TreehammockStageFailure $Stage $scriptExitCode) }
}

function Invoke-TreehammockRunner {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][ValidatePattern('^[a-z0-9_.-]{1,80}$')][string]$Stage,
        [Parameter(Mandatory=$true)][scriptblock]$Body
    )
    $priorBuildId = [Environment]::GetEnvironmentVariable('TREEHAMMOCK_BUILD_RUN_ID', 'Process')
    $priorBuildConfiguration = [Environment]::GetEnvironmentVariable('TREEHAMMOCK_BUILD_CONFIGURATION', 'Process')
    try {
        & $Body
        $runnerExitCode = 0
    }
    catch {
        $runnerExitCode = Get-TreehammockFailureCode $_.Exception
        # Do not print command argv, endpoints, credentials or raw exception messages.
        $failureStage = Get-TreehammockFailureStage $_.Exception $Stage
        Write-Error "Runner '$Stage' failed at '$failureStage' (exit $runnerExitCode)." -ErrorAction Continue
    }
    finally {
        if (Get-Command Restore-TreehammockFixtureEnvironment -CommandType Function -ErrorAction SilentlyContinue) {
            try { Restore-TreehammockFixtureEnvironment -Owner $Stage }
            catch { if ($runnerExitCode -eq 0) { $runnerExitCode = 1 } }
        }
        [Environment]::SetEnvironmentVariable('TREEHAMMOCK_BUILD_RUN_ID', $priorBuildId, 'Process')
        [Environment]::SetEnvironmentVariable('TREEHAMMOCK_BUILD_CONFIGURATION', $priorBuildConfiguration, 'Process')
    }
    $global:LASTEXITCODE = $runnerExitCode
    exit $runnerExitCode
}

function Invoke-TreehammockCoverage {
    param([string] $Lane, [string] $Configuration)
    $python = Get-Command python3 -CommandType Application -ErrorAction SilentlyContinue
    if ($null -eq $python) { $python = Get-Command python -CommandType Application -ErrorAction SilentlyContinue }
    if ($null -eq $python) { throw (New-TreehammockStageFailure 'coverage-python' 127) }
    Invoke-TreehammockNative -Stage ('coverage-' + $Lane) -FilePath $python.Source -Arguments @(
        (Join-Path $PSScriptRoot 'coverage-contract.py'), '--lane', $Lane, '--configuration', $Configuration
    )
}

function Start-TreehammockBuildIdentity {
    param([ValidateSet('Debug', 'Release', 'Sandbox')][string] $Configuration)
    $env:TREEHAMMOCK_BUILD_RUN_ID = [Guid]::NewGuid().ToString('D')
    $env:TREEHAMMOCK_BUILD_CONFIGURATION = $Configuration
}
