[CmdletBinding()]
param([ValidateSet('redis', 'dragonfly')][string]$CacheProduct = 'redis')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'native-command.ps1')

Invoke-TreehammockRunner -Stage 'correction-sql-fixture' -Body {
$python = Get-Command python3 -ErrorAction SilentlyContinue
if ($null -eq $python) { $python = Get-Command python -ErrorAction SilentlyContinue }
if ($null -eq $python) { Write-Error 'Python 3 is required.' -ErrorAction Continue; exit 2 }
Invoke-TreehammockNative -Stage 'python-collector' -FilePath $python.Source -Arguments @((Join-Path $PSScriptRoot 'correction-sql-fixture.py'), '--cache-product', $CacheProduct)
}
