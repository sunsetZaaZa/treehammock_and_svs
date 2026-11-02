#!/usr/bin/env python3
"""SVS-06 locked builds/local regressions; native Dragonfly and YSQL suites compile/discover only."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess,sys,time,xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parents[2]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--dotnet',default='dotnet');p.add_argument('--packages',type=Path);p.add_argument('--source',action='append',default=[]);p.add_argument('--evidence-dir',type=Path,required=True);p.add_argument('--reuse-identity-evidence',type=Path)
 a=p.parse_args();e=a.evidence_dir.resolve();e.mkdir(parents=True,exist_ok=True);env=os.environ.copy();env['DOTNET_CLI_TELEMETRY_OPTOUT']='1';env['SVS06_EVIDENCE_DIRECTORY']=str(e)
 if Path(a.dotnet).is_absolute():env['DOTNET_ROOT']=str(Path(a.dotnet).resolve().parent)
 if a.packages:env['NUGET_PACKAGES']=str(a.packages.resolve())
 commands=[]
 def run(name,argv):
  started=time.monotonic()
  with (e/(name+'.log')).open('w') as out:r=subprocess.run(argv,cwd=ROOT/'tests',env=env,stdout=out,stderr=subprocess.STDOUT)
  commands.append(dict(name=name,argv=argv,exit_code=r.returncode,seconds=round(time.monotonic()-started,3)));(e/'COMMANDS.json').write_text(json.dumps(commands,indent=2)+'\n');print(name+(': PASS' if r.returncode==0 else ': FAIL'),flush=True)
  if r.returncode:raise SystemExit('See '+str(e/(name+'.log')))
 if a.reuse_identity_evidence:
  previous=a.reuse_identity_evidence.resolve();prior=json.loads((previous/'VALIDATION.json').read_text())
  before=json.loads((ROOT/'docs/session-validation/SVS-05_SOURCE_INVENTORY.json').read_text())['files']
  changed_builds={'src/Treehammock.SessionValidation.Storage/Treehammock.SessionValidation.Storage.csproj','src/Treehammock.SessionValidation.Storage/packages.lock.json','tests/Treehammock.SessionValidation.StorageTests/packages.lock.json','tests/Treehammock.SessionValidation.YsqlTests/packages.lock.json'}
  frozen={n:h for n,h in before.items() if not n.startswith('docs/') and n not in changed_builds}
  assert all(hashlib.sha256((ROOT/n).read_bytes()).hexdigest()==h for n,h in frozen.items()),'Existing implementation/regression inputs changed; run full validation'
  reports=list(previous.rglob('*.xml'));assert reports
  for report in reports:
   for asm in ET.parse(report).getroot().findall('assembly'):assert int(asm.get('total','0'))>0 and all(int(asm.get(k,'0'))==0 for k in ['failed','skipped','errors','not-run'])
  (e/'REUSED_REGRESSIONS.json').write_text(json.dumps(dict(evidence_directory=str(previous),total_test_executions=prior['total_test_executions'],unchanged_prior_source_files=len(frozen),source_fingerprint=hashlib.sha256(json.dumps(frozen,sort_keys=True).encode()).hexdigest(),xml_sha256={str(f.relative_to(previous)):hashlib.sha256(f.read_bytes()).hexdigest() for f in reports}),indent=2)+'\n')
 else:
  argv=[sys.executable,str(ROOT/'eng/session-validation/validate-identity.py'),'--dotnet',a.dotnet,'--evidence-dir',str(e/'svs05-regressions')]
  if a.packages:argv+=['--packages',str(a.packages.resolve())]
  for source in a.source:argv+=['--source',source]
  run('prior-identity-regressions',argv);prior=json.loads((e/'svs05-regressions/VALIDATION.json').read_text())
 for name in ['CacheTests','DragonflyTests']:
  project=f'Treehammock.SessionValidation.{name}/Treehammock.SessionValidation.{name}.csproj';argv=[a.dotnet,'restore',project,'--locked-mode','-p:NuGetAudit=false']
  if a.packages:argv+=['--packages',str(a.packages.resolve())]
  for source in a.source:argv+=['--source',source]
  run('restore-'+name,argv);run('build-'+name,[a.dotnet,'build',project,'--no-restore','-c','Release','--disable-build-servers','-m:1'])
 results=[]
 for framework in ['net8.0','net10.0']:
  report=e/('cache-'+framework+'.xml');run('cache-'+framework,[a.dotnet,f'Treehammock.SessionValidation.CacheTests/bin/Release/{framework}/Treehammock.SessionValidation.CacheTests.dll','-maxThreads','2','-xml',str(report)])
  asm=ET.parse(report).getroot().find('assembly');assert asm is not None
  result={k:int(asm.get(k,'0')) for k in ['total','passed','failed','skipped','errors','not-run']};result['framework']=framework
  assert result['total']>0 and all(result[k]==0 for k in ['failed','skipped','errors','not-run']);results.append(result)
 native={}
 for name in ['YsqlTests','DragonflyTests']:
  run('native-discovery-'+name,[a.dotnet,f'Treehammock.SessionValidation.{name}/bin/Release/net10.0/Treehammock.SessionValidation.{name}.dll','-preEnumerateTheories','-list','tests/json'])
  native[name]=len(json.loads((e/('native-discovery-'+name+'.log')).read_text()))
 run('cache-contract-audit',[sys.executable,str(ROOT/'eng/session-validation/inspect-cache-contract.py')])
 out=dict(pr='SVS-06',status='ImplementedLocalCoherentCacheTestsPendingNativeAcceptance',baseline_test_executions=prior['total_test_executions'],cache_results=results,total_test_executions=prior['total_test_executions']+sum(x['passed'] for x in results),build_errors=0,new_projects_build_warnings=0,native_cases_discovered=native,native_cases_executed=0,native_qualification='NotRun: actual Dragonfly/YSQL/ACL/CAS/writer/fault/mTLS/physical-host/COR gates',production_cache_only='Structurally disabled: no public enable factory/property',whole_repository_suite='NotRun',advisory_feed_audit='NotRun',release_ready=False,next_pr='SVS-07')
 (e/'VALIDATION.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out,indent=2))
if __name__=='__main__':main()
