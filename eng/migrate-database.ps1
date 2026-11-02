param([Parameter(Mandatory=$true)][string]$Assembly, [Parameter(ValueFromRemainingArguments=$true)][string[]]$MigrationArguments)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'native-command.ps1')

Invoke-TreehammockRunner -Stage 'migrate-database' -Body {
Invoke-TreehammockNative -Stage 'database-command' -FilePath 'dotnet' -Arguments (@($Assembly, 'migrate') + $MigrationArguments)
}
