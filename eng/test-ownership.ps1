# Source-only: the same selected host executes private run inputs.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Enter-TreehammockOwnedTest {
    param([string]$Lane, [string[]]$Arguments = @())
    if ($null -eq $Arguments) { $Arguments = @() }
    $python = Get-Command python3 -CommandType Application -ErrorAction SilentlyContinue
    if ($null -eq $python) { $python = Get-Command python -CommandType Application -ErrorAction SilentlyContinue }
    if ($null -eq $python) { throw (New-TreehammockStageFailure 'ownership-python' 127) }
    if ($env:TREEHAMMOCK_TEST_RUN_ACTIVE -eq 'true') {
        Invoke-TreehammockNative -Stage 'ownership-verify' -FilePath $python.Source -Arguments (@('eng/test-ownership.py','verify','--lane',$Lane,'--') + $Arguments) *> $null
        return $false
    }
    $hostPath = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $entry = Join-Path $repoRoot ('eng/' + $Lane + '.ps1')
    Invoke-TreehammockNative -Stage 'ownership-run' -FilePath $python.Source -Arguments (@('eng/test-ownership.py','run','--lane',$Lane,'--entry',$entry,'--shell',$hostPath,'--') + $Arguments) | Out-Host
    return $true
}
