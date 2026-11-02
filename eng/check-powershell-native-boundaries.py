#!/usr/bin/env python3
"""COR23Q source guard; actual PowerShell execution is a separate mandatory fixture."""
import argparse,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
HELPER='eng/native-command.ps1'
HOST='eng/docker-host-system-stack-tests.ps1'
RUNNERS=['validate','build-proof','release-proof','restore-locks','check-locks','dotnet-unit-tests','dotnet-integration-tests','sql-contracts','correction-baseline','correction-sql-fixture','migrate-database','docker-api-image','docker-unit-tests','docker-sql-contracts','docker-http-contracts-direct','docker-http-contracts-proxy','docker-system-stack-tests','docker-host-system-stack-tests','docker-all-tests','docker-infra-up','docker-postgres-up','docker-dragonfly-up','docker-api-direct-up','docker-api-proxy-up','docker-api-proxy-scale','docker-all-runtime-up','docker-down','docker-help']
def require(v,m):
 if not v:raise ValueError(m)
def validate(root):
 helper=(root/HELPER).read_text()
 for token in ["-CommandType Application", "$PSNativeCommandUseErrorActionPreference = $false", "$ErrorActionPreference = 'Continue'", '$global:LASTEXITCODE = $null', '& $tool.Source @Arguments\n        $nativeExitCode = $LASTEXITCODE', 'if ($null -eq $nativeExitCode)', 'if ($nativeExitCode -ne 0)', 'New-TreehammockStageFailure $Stage $nativeExitCode', '& $Path @Parameters\n    $scriptExitCode = $LASTEXITCODE', 'if ($scriptExitCode -ne 0)', "Data['TreehammockExitCode']", '$current = $current.InnerException', '$runnerExitCode = Get-TreehammockFailureCode $_.Exception', '    exit $runnerExitCode\n']:
  require(token in helper,'Native failure boundary missing: '+token)
 require('$current = $current.InnerException' in helper[helper.index('function Get-TreehammockFailureCode'):helper.index('function Get-TreehammockFailureStage')], 'Native code traversal must not be replaced by stage traversal')
 require('-CommandType Application' in helper[helper.index('function Invoke-TreehammockNative'):helper.index('function Invoke-TreehammockScript')], 'Native invocation must resolve an Application independently of coverage interpreter lookup')
 require('$_.Exception.Message' not in helper and '$Arguments -join' not in helper,'Diagnostics cannot expose exception messages or argv')
 for name in RUNNERS:
  source=(root/'eng'/f'{name}.ps1').read_text()
  require(". (Join-Path $PSScriptRoot 'native-command.ps1')" in source and f"Invoke-TreehammockRunner -Stage '{name}' -Body {{" in source,'Unprotected entrypoint: '+name)
  require(not re.search(r'^\s*(?:& )?(?:dotnet|docker|git|powershell\.exe)\s+',source,re.M),'Unchecked native command: '+name)
  require(not re.search(r'& (?:\./eng/|\$python.Source)',source),'Unchecked child script/interpreter: '+name)
  require('Invoke-DockerPullWithRetry' not in source and 'exit $LASTEXITCODE' not in source,'Retry/stale-exit path can hide first failure: '+name)
 require(set(p.stem for p in (root/'eng').glob('*.ps1'))==set(RUNNERS)|{'native-command','fixture-isolation','test-ownership'},'PowerShell inventory is incomplete')
 for name in ['build-proof','release-proof','docker-all-tests']:
  require('Invoke-TreehammockScript' in (root/'eng'/f'{name}.ps1').read_text(),'Nested proof must propagate child status: '+name)
 host=(root/HOST).read_text()
 require(host.count('if ($null -eq $primaryFailure)') == 2, 'Every cleanup branch must preserve the primary failure')
 for token in ['$primaryFailure = $null','$primaryFailure = $_.Exception','if ($null -eq $primaryFailure)',"Enter-TreehammockOwnedTest -Lane 'docker-host-system-stack-tests'",'if ($null -ne $primaryFailure) { throw $primaryFailure }','Wait-ForSystemReadiness -ApiPython $apiPython',"-Stage 'host-api' -FilePath $ApiPython"]:
  require(token in host,'Primary/cleanup/API failure retention missing: '+token)
 fixture=(root/'eng/test-powershell-runners.py').read_text()
 for name in RUNNERS:require("'"+name+'.ps1' +"'" in fixture,'Behavioral matrix omits runner: '+name)
 for token in ["for mode in ['File','Command']:\n   for name,args in CASES.items():","failed.returncode!=47","prefix!=baseline[:number]","primary-versus-cleanup","real-missing-lock","profile-preference-and-alias-independent","spaces-in-native-argv","Language.Parser]::ParseFile"]:
  require(token in fixture,'Executable failure matrix boundary absent: '+token)
 ci=(root/'.github/workflows/treehammock-ci.yml').read_text()
 for token in ['python3 eng/check-powershell-native-boundaries.py','powershell-native-boundaries:','host: powershell.exe','host: pwsh','python eng/test-powershell-runners.py --host ${{ matrix.host }}']:
  require(token in ci,'Real supported host matrix must be mandatory: '+token)
 return dict(status='SourceContractsConsistent',qualification='NotRun',entrypoints=len(RUNNERS),native='immediate explicit exit capture',nested='explicit script status propagation',runtime='PowerShell and compiled process fixture required')
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=ROOT);a=p.parse_args()
 try:print(json.dumps(validate(a.root),indent=2));return 0
 except(ValueError,OSError) as e:print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
