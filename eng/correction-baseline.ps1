[CmdletBinding()]
param(
    [ValidateSet('all', 'fast', 'sql-harness', 'sql', 'system')]
    [string] $Lane = 'all',
    [string] $Output = '.correction-results',
    [switch] $CollectCoverage,
    [ValidateRange(1, 3600)] [int] $StageTimeout = 600
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'native-command.ps1')

Invoke-TreehammockRunner -Stage 'correction-baseline' -Body {
$python = Get-Command python3 -ErrorAction SilentlyContinue
if ($null -eq $python) { $python = Get-Command python -ErrorAction SilentlyContinue }
if ($null -eq $python) {
    Write-Error 'Correction baseline is blocked: Python 3 is required.' -ErrorAction Continue
    exit 2
}
$root = Split-Path $PSScriptRoot -Parent
if (-not [IO.Path]::IsPathRooted($Output)) { $Output = Join-Path $root $Output }
$collectorArgs = @((Join-Path $PSScriptRoot 'correction-baseline.py'), '--lane', $Lane, '--output', $Output, '--stage-timeout', $StageTimeout)
if ($CollectCoverage) { $collectorArgs += '--collect-coverage' }
Invoke-TreehammockNative -Stage 'python-collector' -FilePath $python.Source -Arguments $collectorArgs
}
