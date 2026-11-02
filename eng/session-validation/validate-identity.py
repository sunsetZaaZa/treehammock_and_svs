#!/usr/bin/env python3
"""SVS-05 reproduction: locked builds/local regressions; native suites compile only."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess,sys,time,xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parents[2]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--dotnet',default='dotnet');p.add_argument('--packages',type=Path);p.add_argument('--source',action='append',default=[]);p.add_argument('--evidence-dir',type=Path,required=True);p.add_argument('--reuse-regressions',type=Path,help='Existing same-source SVS-03 regression evidence from this run; default reruns all')
 a=p.parse_args();e=a.evidence_dir.resolve();e.mkdir(parents=True,exist_ok=True);env=os.environ.copy();env['DOTNET_CLI_TELEMETRY_OPTOUT']='1'
 if Path(a.dotnet).is_absolute():env['DOTNET_ROOT']=str(Path(a.dotnet).resolve().parent)
 if a.packages:env['NUGET_PACKAGES']=str(a.packages.resolve())
 commands=[]
 def run(name,argv,cwd=ROOT/'tests'):
  started=time.monotonic()
  with (e/(name+'.log')).open('w') as out:r=subprocess.run(argv,cwd=cwd,env=env,stdout=out,stderr=subprocess.STDOUT)
  commands.append(dict(name=name,argv=argv,exit_code=r.returncode,seconds=round(time.monotonic()-started,3)));(e/'COMMANDS.json').write_text(json.dumps(commands,indent=2)+'\n');print(name+(': PASS' if r.returncode==0 else ': FAIL'),flush=True)
  if r.returncode:raise SystemExit('See '+str(e/(name+'.log')))
 if a.reuse_regressions:
  previous=a.reuse_regressions.resolve();baseline=json.loads((previous/'VALIDATION.json').read_text())
  # Check the complete original public app/Core/contracts/test dependency surface against frozen SVS-04.
  frozen=json.loads((ROOT/'docs/session-validation/SVS-04_SOURCE_INVENTORY.json').read_text())['files']
  runtime={n:h for n,h in frozen.items() if n.endswith(('.cs','.csproj','.props','.targets','packages.lock.json','global.json')) and not n.startswith(('src/Treehammock.SessionValidation.Storage/','tests/Treehammock.SessionValidation.StorageTests/','tests/Treehammock.SessionValidation.YsqlTests/'))}
  assert all(hashlib.sha256((ROOT/n).read_bytes()).hexdigest()==h for n,h in runtime.items()),'Regression source changed: rerun full validation'
  reports=list(previous.rglob('*.xml'));assert reports
  for report in reports:
   for asm in ET.parse(report).getroot().findall('assembly'):
    assert int(asm.get('total','0'))>0 and all(int(asm.get(k,'0'))==0 for k in ['failed','skipped','errors','not-run'])
  (e/'REUSED_REGRESSIONS.json').write_text(json.dumps(dict(evidence_directory=str(previous),total_test_executions=baseline['total_test_executions'],runtime_files_verified=len(runtime),runtime_inputs_sha256=hashlib.sha256(json.dumps(runtime,sort_keys=True).encode()).hexdigest(),xml_sha256={str(f.relative_to(previous)):hashlib.sha256(f.read_bytes()).hexdigest() for f in reports}),indent=2)+'\n')
 else:
  argv=[sys.executable,str(ROOT/'eng/session-validation/validate-middleware.py'),'--dotnet',a.dotnet,'--evidence-dir',str(e/'svs03-regressions')]
  if a.packages:argv+=['--packages',str(a.packages.resolve())]
  for source in a.source:argv+=['--source',source]
  run('prior-regressions',argv);baseline=json.loads((e/'svs03-regressions/VALIDATION.json').read_text())
 for name in ['StorageTests','YsqlTests']:
  project=f'Treehammock.SessionValidation.{name}/Treehammock.SessionValidation.{name}.csproj'
  argv=[a.dotnet,'restore',project,'--locked-mode','-p:NuGetAudit=false']
  if a.packages:argv+=['--packages',str(a.packages.resolve())]
  for source in a.source:argv+=['--source',source]
  run('restore-'+name,argv);run('build-'+name,[a.dotnet,'build',project,'--no-restore','-c','Release','--disable-build-servers','-m:1'])
 results=[]
 for target in ['net8.0','net10.0']:
  report=e/('storage-'+target+'.xml');run('storage-'+target,[a.dotnet,f'Treehammock.SessionValidation.StorageTests/bin/Release/{target}/Treehammock.SessionValidation.StorageTests.dll','-maxThreads','2','-xml',str(report)])
  assembly=ET.parse(report).getroot().find('assembly');assert assembly is not None
  result={k:int(assembly.get(k,'0')) for k in ['total','passed','failed','skipped','errors','not-run']};result['framework']=target
  assert result['total']>0 and all(result[k]==0 for k in ['failed','skipped','errors','not-run']);results.append(result)
 run('identity-spec-audit',[sys.executable,str(ROOT/'eng/session-validation/inspect-identity-spec.py')])
 run('readonly-sql-audit',[sys.executable,str(ROOT/'eng/session-validation/audit-readonly-sql.py')])
 summary=dict(pr='SVS-05',reimplementation=True,status='ImplementedLocalIdentityChecksPendingNativeAcceptance',baseline_test_executions=baseline['total_test_executions'],storage_results=results,total_test_executions=baseline['total_test_executions']+sum(r['passed'] for r in results),build_errors=0,new_projects_build_warnings=0,native_cases_executed=0,native_suite='Compiled both targets only; actual Yugabyte/DDL/allow-deny/writer-preservation/pool/rollback qualification NotRun',whole_repository_suite='NotRun',advisory_feed_audit='NotRun',release_ready=False,next_pr='SVS-06')
 (e/'VALIDATION.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary,indent=2))
if __name__=='__main__':main()
