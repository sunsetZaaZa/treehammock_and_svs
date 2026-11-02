[CmdletBinding()]
param(
    [switch] $WarnOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'native-command.ps1')

Invoke-TreehammockRunner -Stage 'check-locks' -Body {
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot

$missing = New-Object System.Collections.Generic.List[string]
Get-ChildItem -Path . -Filter '*.csproj' -Recurse |
    Where-Object { $_.FullName -notmatch "[\\/]bin[\\/]" -and $_.FullName -notmatch "[\\/]obj[\\/]" } |
    Sort-Object FullName |
    ForEach-Object {
        $projectContent = Get-Content -LiteralPath $_.FullName -Raw
        if ($projectContent -match '<PackageReference\s') {
            $lockFile = Join-Path $_.DirectoryName 'packages.lock.json'
            if (-not (Test-Path -LiteralPath $lockFile -PathType Leaf)) {
                $relativeDirectory = Resolve-Path -LiteralPath $_.DirectoryName -Relative
                $missing.Add((Join-Path $relativeDirectory 'packages.lock.json'))
            }
        }
    }

if ($missing.Count -eq 0) {
    Write-Host 'All package lock files are present.'
    exit 0
}

$messageLines = @('Missing package lock file(s):') + ($missing | ForEach-Object { "  - $_" }) + @('Run ./eng/restore-locks.ps1 on a machine with the .NET SDK, review the generated locks, then commit them.')
$message = $messageLines -join [Environment]::NewLine

if ($WarnOnly) {
    Write-Warning $message
    exit 0
}

Write-Error $message
}
