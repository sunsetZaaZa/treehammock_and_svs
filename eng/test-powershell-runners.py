#!/usr/bin/env python3
"""Run actual PowerShell scripts against compiled controlled native processes. No shell emulator."""
import argparse,json,os,shutil,subprocess,sys,tempfile,time,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
IGNORE=shutil.ignore_patterns('.git','.docker','bin','obj','.correction-results','.artifacts','TestResults','__pycache__')
# Every executable wrapper is included. Host API process is a private test HTTP listener,
# not the real application/Docker topology. Resource ownership remains COR23Y/Z.
CASES={
 'validate.ps1':[], 'build-proof.ps1':['-LockedRestore','-RunSqlContracts'],
 'release-proof.ps1':[], 'restore-locks.ps1':[], 'check-locks.ps1':[],
 'dotnet-unit-tests.ps1':['-LockedRestore'], 'dotnet-integration-tests.ps1':['-LockedRestore'],
 'sql-contracts.ps1':['-LockedRestore'], 'correction-baseline.ps1':[], 'correction-sql-fixture.ps1':[],
 'migrate-database.ps1':['-Assembly','fixture assembly.dll'], 'docker-api-image.ps1':[],
 'docker-unit-tests.ps1':[], 'docker-sql-contracts.ps1':[], 'docker-http-contracts-direct.ps1':[],
 'docker-http-contracts-proxy.ps1':[], 'docker-system-stack-tests.ps1':[], 'docker-host-system-stack-tests.ps1':[],
 'docker-all-tests.ps1':[], 'docker-infra-up.ps1':[], 'docker-postgres-up.ps1':[],
 'docker-dragonfly-up.ps1':[], 'docker-api-direct-up.ps1':[], 'docker-api-proxy-up.ps1':[],
 'docker-api-proxy-scale.ps1':[], 'docker-all-runtime-up.ps1':[], 'docker-down.ps1':[], 'docker-help.ps1':[]}
def quote(value):return "'"+str(value).replace("'","''")+"'"
def invoke(host,script,args,mode,env,root,preferences=False):
 if mode=='File':command=[host,'-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',str(script),*args]
 else:
  parameters=[]
  for arg in args:parameters.append(arg if arg.startswith('-') else quote(arg))
  prefix="$PSNativeCommandUseErrorActionPreference = $true; function global:dotnet { throw 'Profile function must not run' }; " if preferences else ''
  command=[host,'-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-Command',prefix+'& '+quote(script)+' '+ ' '.join(parameters)+'; exit $LASTEXITCODE']
 return subprocess.run(command,cwd=root,env=env,text=True,capture_output=True,timeout=45)
def entries(trace):
 result=[json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else []
 for entry in result:
  for index,arg in enumerate(entry['args']):
   if arg.startswith('TREEHAMMOCK_BUILD_RUN_ID='):
    uuid.UUID(arg.split('=',1)[1]);entry['args'][index]='TREEHAMMOCK_BUILD_RUN_ID=<fresh-valid-uuid>'
 return result
def prepare_probe(sdk,folder):
 project=folder/'probe';project.mkdir();(project/'Program.cs').write_text((ROOT/'eng/tests/fixtures/native-command/NativeCommandProbe.cs.txt').read_text())
 (project/'NativeCommandProbe.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework><ImplicitUsings>enable</ImplicitUsings><Nullable>enable</Nullable><UseAppHost>true</UseAppHost></PropertyGroup></Project>')
 # No packages/feeds. All build artifacts are private to this disposable fixture.
 (project/'NuGet.Config').write_text('<configuration><packageSources><clear /></packageSources></configuration>')
 built=subprocess.run([sdk,'build',str(project/'NativeCommandProbe.csproj'),'-c','Release','--nologo'],text=True,capture_output=True,timeout=90)
 if built.returncode:raise RuntimeError('Native command probe compilation failed')
 binary=project/'bin/Release/net8.0';target=folder/'bin with spaces';shutil.copytree(binary,target)
 suffix='.exe' if os.name=='nt' else '';app=target/('NativeCommandProbe'+suffix)
 for name in ['dotnet','docker','git','python3','python'] + (['powershell.exe'] if os.name=='nt' else []):
  destination=target/(name if name.endswith('.exe') else name+suffix);shutil.copy2(app,destination);destination.chmod(0o755)
 return target
def run(host,sdk):
 results=[]
 with tempfile.TemporaryDirectory(prefix='cor23q real host ') as temporary:
  folder=Path(temporary);root=folder/'checkout with spaces';shutil.copytree(ROOT,root,ignore=IGNORE);binary=prepare_probe(sdk,folder)
  env=dict(os.environ);env.update(PATH=str(binary)+os.pathsep+env['PATH'],COR23Q_API_PID=str(folder/'api.pid'),COR23Q_TRACE=str(folder/'trace.jsonl'),COR23Q_FAIL_AT='0',COR23Q_SECOND_FAIL_AT='0',TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS='true',TREEHAMMOCK_DB_CONTRACT_CONNECTION='owned fixture connection')
  import importlib.util
  credential_spec=importlib.util.spec_from_file_location('fixture_credentials',root/'eng/fixture-isolation.py')
  credential_module=importlib.util.module_from_spec(credential_spec);credential_spec.loader.exec_module(credential_module)
  credential_module.ensure(root,{},'container')
  ownership_spec=importlib.util.spec_from_file_location('fixture_ownership',root/'eng/test-ownership.py');ownership_module=importlib.util.module_from_spec(ownership_spec);ownership_spec.loader.exec_module(ownership_module)
  controlled_run=ownership_module.create_run(root,'docker-all-tests',env);controlled_run['status']='Running';ownership_module.write(ownership_module.manifest(controlled_run),controlled_run)
  root=Path(controlled_run['checkout']);env=ownership_module.run_environment(controlled_run,env)
  # Compiled Python verify commands remain controlled processes in this Q matrix.
  # Actual ownership/copy/resource/cancellation behavior is qualified by COR23Y's
  # separate tools; this matrix retains actual PowerShell scope/exit behavior.
  trace=Path(env['COR23Q_TRACE'])
  # Parse all scripts through the selected real host before invoking any runner.
  parser="$failed=$false; Get-ChildItem -LiteralPath "+quote(root/'eng')+" -Filter '*.ps1' | ForEach-Object { $tokens=$null; $errors=$null; [System.Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$tokens,[ref]$errors) > $null; if ($errors.Count -gt 0) { $failed=$true } }; if ($failed) { exit 1 }"
  parsed=subprocess.run([host,'-NoProfile','-Command',parser],cwd=root,env=env,capture_output=True,text=True,timeout=30)
  if parsed.returncode:raise AssertionError('PowerShell parser rejected source')
  results.append(dict(case='real-host-parser',status='Passed'))
  # COR23X: run the real owning scope, then inspect the calling session.
  # Compiled native commands are controlled; PowerShell function/environment
  # scopes and finally blocks are the actual selected host implementation.
  prior_keys=sorted(credential_module.KEYS)
  prefix="$env:COMPOSE_PROJECT_NAME="+quote(controlled_run['project'])+"; "+''.join("[Environment]::SetEnvironmentVariable("+quote(key)+",'caller-sentinel','Process'); " for key in prior_keys)
  checks="if ([Environment]::GetEnvironmentVariable('COMPOSE_PROJECT_NAME','Process') -ne "+quote(controlled_run['project'])+") { exit 91 }; "+''.join("if ([Environment]::GetEnvironmentVariable("+quote(key)+",'Process') -ne 'caller-sentinel') { exit 92 }; " for key in prior_keys)
  def restore_probe(fail_at):
   env['COR23Q_FAIL_AT']=str(fail_at);trace.unlink(missing_ok=True)
   script=prefix+'& '+quote(root/'eng/docker-sql-contracts.ps1')+"; $code=$LASTEXITCODE; "+checks+"exit $code"
   return subprocess.run([host,'-NoProfile','-ExecutionPolicy','Bypass','-Command',script],cwd=root,env=env,capture_output=True,text=True,timeout=45)
  restored=restore_probe(0);assert restored.returncode==0
  baseline=entries(trace);failed_stage=next(i for i,e in enumerate(baseline,1) if e['tool']=='docker')
  restored=restore_probe(failed_stage);assert restored.returncode==47
  results.append(dict(case='fixture-owning-scope-restores-parent-environment-on-success-and-failure',status='Passed'))
  env['COR23Q_FAIL_AT']='0'
  for mode in ['File','Command']:
   for name,args in CASES.items():
    script=root/'eng'/name
    # Windows-specific policy/child host is intentionally retained until COR23AB.
    trace.unlink(missing_ok=True);env['COR23Q_FAIL_AT']='0';env['COR23Q_SECOND_FAIL_AT']='0'
    success=invoke(host,script,args,mode,env,root)
    if success.returncode!=0:raise AssertionError(f'{name} {mode}: success path returned {success.returncode}')
    baseline=entries(trace);results.append(dict(case=name,mode=mode,stage='success',status='Passed',native_calls=len(baseline)))
    for number,entry in enumerate(baseline,1):
     trace.unlink(missing_ok=True);env['COR23Q_FAIL_AT']=str(number)
     failed=invoke(host,script,args,mode,env,root)
     observed=entries(trace)
     if failed.returncode!=47:raise AssertionError(f'{name} {mode} stage {number}: failure exit was {failed.returncode}')
     # Teardown is allowed after failure; normal build/test/later proof work is forbidden.
     prefix=observed[:number]
     if prefix!=baseline[:number]:raise AssertionError(f'{name} {mode}: failed-stage argv/order differs')
     for later in observed[number:]:
      if not (later['tool']=='docker' and 'down' in later['args'] or later['tool'] in ['python','python3'] and 'api-stop' in later['args']):raise AssertionError(f'{name} {mode}: later work ran after failure')
     results.append(dict(case=name,mode=mode,stage=number,status='Passed',exit_code=failed.returncode))
     if Path(env['COR23Q_API_PID']).exists():
      subprocess.run([str(binary/('python3.exe' if os.name=='nt' else 'python3')),'eng/test-ownership.py','api-stop'],env=dict(env,COR23Q_FAIL_AT='0',COR23Q_SECOND_FAIL_AT='0'),cwd=root,capture_output=True,timeout=10)
   # Deliberately missing lock must stop a nested release proof before restore/build/test.
   env['COR23Q_FAIL_AT']='0';env['COR23Q_SECOND_FAIL_AT']='0';trace.unlink(missing_ok=True)
   lock=root/'treehammock.Tests/packages.lock.json';saved=lock.read_bytes();lock.unlink()
   try:
    failed=invoke(host,root/'eng/release-proof.ps1',[],mode,env,root);assert failed.returncode!=0
    assert all(e['args'][0]=='--info' for e in entries(trace));results.append(dict(case='real-missing-lock',mode=mode,status='Passed'))
   finally:lock.write_bytes(saved)
  retained=root/'eng/cor23q-retained-failure.ps1'
  retained.write_text(". (Join-Path $PSScriptRoot 'native-command.ps1')\nInvoke-TreehammockRunner -Stage 'retained-fixture' -Body { $primaryFailure=$null; try { Invoke-TreehammockNative -Stage 'primary' -FilePath 'docker' -Arguments @('info') } catch { $primaryFailure=$_.Exception }; try { Invoke-TreehammockNative -Stage 'secondary' -FilePath 'docker' -Arguments @('info') } catch { if ($null -eq $primaryFailure) { $primaryFailure=$_.Exception } }; if ($null -ne $primaryFailure) { throw $primaryFailure } }\n")
  for mode in ['File','Command']:
   trace.unlink(missing_ok=True);env['COR23Q_FAIL_AT']='1';env['COR23Q_SECOND_FAIL_AT']='2'
   failed=invoke(host,retained,[],mode,env,root);assert failed.returncode==47;assert len(entries(trace))==2
   results.append(dict(case='primary-versus-cleanup',mode=mode,status='Passed'))
  # A profile function/native error preference must not replace Application or its exit oracle.
  trace.unlink(missing_ok=True);env['COR23Q_FAIL_AT']='0';env['COR23Q_SECOND_FAIL_AT']='0'
  success=invoke(host,root/'eng/dotnet-unit-tests.ps1',[],'Command',env,root,preferences=True);assert success.returncode==0;assert len(entries(trace))==3
  results.append(dict(case='profile-preference-and-alias-independent',status='Passed'))
  # A genuine SDK compile error must propagate through the same boundary.
  bad=folder/'real failing build';bad.mkdir();(bad/'Broken.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>')
  (bad/'NuGet.Config').write_text('<configuration><packageSources><clear /></packageSources></configuration>');(bad/'Broken.cs').write_text('this is deliberately invalid C#;')
  real_failure=root/'eng/cor23q-real-build-failure.ps1'
  real_failure.write_text(". (Join-Path $PSScriptRoot 'native-command.ps1')\nInvoke-TreehammockRunner -Stage 'real-build-fixture' -Body { Invoke-TreehammockNative -Stage 'real-invalid-build' -FilePath "+quote(sdk)+" -Arguments @('build', "+quote(bad/'Broken.csproj')+", '--nologo'); Invoke-TreehammockNative -Stage 'later' -FilePath 'docker' -Arguments @('info') }\n")
  for mode in ['File','Command']:
   trace.unlink(missing_ok=True);failed=invoke(host,real_failure,[],mode,env,root);assert failed.returncode==1;assert not entries(trace)
   results.append(dict(case='real-dotnet-compile-failure',mode=mode,status='Passed'))
  # Missing executable is a real helper failure, not an alias/script stand-in.
  missing=root/'eng/cor23q-missing-tool.ps1'
  missing.write_text(". (Join-Path $PSScriptRoot 'native-command.ps1')\nInvoke-TreehammockRunner -Stage 'missing-fixture' -Body { Invoke-TreehammockNative -Stage 'missing-tool' -FilePath 'cor23q-no-such-application'; Invoke-TreehammockNative -Stage 'later' -FilePath 'docker' -Arguments @('info') }\n")
  trace.unlink(missing_ok=True);failed=invoke(host,missing,[],'File',env,root);assert failed.returncode==127;assert not entries(trace)
  results.append(dict(case='missing-application-stops-later-work',status='Passed'))
  # Caller argv preserves a path with spaces through the actual native executable.
  trace.unlink(missing_ok=True);result=invoke(host,root/'eng/migrate-database.ps1',['-Assembly','fixture assembly.dll'],'File',env,root);assert result.returncode==0
  assert entries(trace)[0]['args']==['fixture assembly.dll','migrate'];results.append(dict(case='spaces-in-native-argv',status='Passed'))
 return results
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--host',default='pwsh');parser.add_argument('--output',type=Path,default=ROOT/'.correction-results/cor23q-powershell.json');args=parser.parse_args()
 host=shutil.which(args.host);sdk=shutil.which('dotnet');report=dict(kind='actual-powershell-command-fixture',host=args.host,qualification='NotRun',cases=[])
 if not host or not sdk:report.update(status='Blocked',reason='Selected PowerShell host and .NET 8 SDK are required; no emulation or success substitute');code=2
 else:
  try:report['cases']=run(host,sdk);report.update(status='Passed',qualification='ControlledNativeRunnerMatrix',tests=len(report['cases']));code=0
  except Exception as error:report.update(status='Failed',reason=str(error));code=1
 args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(dict(status=report['status'],tests=len(report['cases']),qualification=report['qualification'])));return code
if __name__=='__main__':raise SystemExit(main())
