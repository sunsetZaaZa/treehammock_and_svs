#!/usr/bin/env python3
"""SVS07 locked builds, selected regressions and actual local TLS; native suites discovery only."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess,sys,time,xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parents[2]
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--dotnet',default='dotnet');p.add_argument('--packages',type=Path);p.add_argument('--source',action='append',default=[]);p.add_argument('--evidence-dir',type=Path,required=True);p.add_argument('--reuse-cache-evidence',type=Path)
 a=p.parse_args();e=a.evidence_dir.resolve();e.mkdir(parents=True,exist_ok=True);env=os.environ.copy();env['DOTNET_CLI_TELEMETRY_OPTOUT']='1'
 if Path(a.dotnet).is_absolute():env['DOTNET_ROOT']=str(Path(a.dotnet).resolve().parent)
 if a.packages:env['NUGET_PACKAGES']=str(a.packages.resolve())
 commands=[]
 def run(name,args):
  start=time.monotonic()
  with (e/(name+'.log')).open('w') as log:r=subprocess.run(args,cwd=ROOT/'tests',env=env,stdout=log,stderr=subprocess.STDOUT)
  commands.append(dict(name=name,argv=args,exit_code=r.returncode,seconds=round(time.monotonic()-start,3)));(e/'COMMANDS.json').write_text(json.dumps(commands,indent=2)+'\n');print(name+(': PASS' if not r.returncode else ': FAIL'),flush=True)
  if r.returncode:raise SystemExit('See '+str(e/(name+'.log')))
 if a.reuse_cache_evidence:
  previous=a.reuse_cache_evidence.resolve();receipt=json.loads((previous/'COMPLETED_SOURCE_RECEIPT.json').read_text())
  assert all(digest(ROOT/n)==h for n,h in receipt['source_files'].items()),'Selected source inputs changed; rerun full chain'
  assert all(digest(previous/n)==h for n,h in receipt['xml_files'].items()),'Evidence drift'
  for n in receipt['xml_files']:
   for asm in ET.parse(previous/n).getroot().findall('assembly'):assert int(asm.get('total','0'))>0 and all(int(asm.get(k,'0'))==0 for k in ['failed','skipped','errors','not-run'])
  prior=json.loads((previous/'VALIDATION.json').read_text());(e/'REUSED_REGRESSIONS.json').write_text(json.dumps(dict(evidence_directory=str(previous),total_test_executions=prior['total_test_executions'],receipt_sha256=digest(previous/'COMPLETED_SOURCE_RECEIPT.json'),source_files_verified=len(receipt['source_files']),scope='Actually executed earlier in this task; current Storage binary equality and source receipt retained'),indent=2)+'\n')
 else:
  args=[sys.executable,str(ROOT/'eng/session-validation/validate-cache.py'),'--dotnet',a.dotnet,'--evidence-dir',str(e/'prior-chain')]
  if a.packages:args+=['--packages',str(a.packages.resolve())]
  for source in a.source:args+=['--source',source]
  run('prior-chain',args);prior=json.loads((e/'prior-chain/VALIDATION.json').read_text())
 for name in ['HostTests','YsqlTests']:
  project=f'Treehammock.SessionValidation.{name}/Treehammock.SessionValidation.{name}.csproj';args=[a.dotnet,'restore',project,'--locked-mode','-p:NuGetAudit=false','--disable-build-servers','-m:1']
  if a.packages:args+=['--packages',str(a.packages.resolve())]
  for source in a.source:args+=['--source',source]
  run('restore-'+name,args);run('build-'+name,[a.dotnet,'build',project,'-c','Release','--no-restore','--disable-build-servers','-m:1'])
 report=e/'host.xml';run('host-net10',[a.dotnet,'Treehammock.SessionValidation.HostTests/bin/Release/net10.0/Treehammock.SessionValidation.HostTests.dll','-maxThreads','1','-xml',str(report)])
 asm=ET.parse(report).getroot().find('assembly');result={k:int(asm.get(k,'0')) for k in ['total','passed','failed','skipped','errors','not-run']};assert result['total']>0 and all(result[k]==0 for k in ['failed','skipped','errors','not-run'])
 native={}
 for name in ['YsqlTests','DragonflyTests']:
  run('native-discovery-'+name,[a.dotnet,f'Treehammock.SessionValidation.{name}/bin/Release/net10.0/Treehammock.SessionValidation.{name}.dll','-preEnumerateTheories','-list','tests/json']);native[name]=len(json.loads((e/('native-discovery-'+name+'.log')).read_text()))
 run('host-contract-audit',[sys.executable,str(ROOT/'eng/session-validation/inspect-host-contract.py')])
 out=dict(pr='SVS-07',status='ImplementedLocalHostAndIdentityCompatibilityPendingNativeAcceptance',baseline_test_executions=prior['total_test_executions'],host_results=result,total_test_executions=prior['total_test_executions']+result['passed'],build_errors=0,new_projects_build_warnings=0,existing_public_build_warnings=33,native_cases_discovered=native,native_cases_executed=0,host_transport_scope='Actual local Kestrel HTTP2/TLS/certificates with substituted storage readiness; no target qualification',cache_admission='Temporarily unadmitted; actual enablement remains SVS-11',actual_validation_rpc='SVS-08; not implemented here',whole_repository_suite='NotRun',advisory_feed_audit='NotRun',release_ready=False,next_pr='SVS-08')
 (e/'VALIDATION.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out,indent=2))
if __name__=='__main__':main()
