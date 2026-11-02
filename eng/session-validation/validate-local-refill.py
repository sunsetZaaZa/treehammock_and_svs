#!/usr/bin/env python3
"""SVS-11 locked local regressions; native targets compile/discover only."""
import argparse,json,os,subprocess,sys,time,hashlib,zipfile,tempfile,xml.etree.ElementTree as ET
from pathlib import Path
R=Path(__file__).resolve().parents[2]
def main():
 p=argparse.ArgumentParser();p.add_argument('--dotnet',required=True);p.add_argument('--packages',required=True,type=Path);p.add_argument('--source',action='append',default=[]);p.add_argument('--evidence-dir',required=True,type=Path);p.add_argument('--peer-archive',required=True,type=Path);a=p.parse_args();e=a.evidence_dir.resolve();e.mkdir(parents=True,exist_ok=True);env=os.environ.copy();env.update(DOTNET_ROOT=str(Path(a.dotnet).resolve().parent),NUGET_PACKAGES=str(a.packages.resolve()),MSBUILDDISABLENODEREUSE='1',SVS02_EVIDENCE_DIRECTORY=str(e),SVS03_EVIDENCE_DIRECTORY=str(e))
 commands=[];reports=[];native={}
 def run(name,args,cwd=R/'tests'):
  start=time.monotonic();log=e/(name+'.log');log.parent.mkdir(parents=True,exist_ok=True)
  with log.open('w') as f:r=subprocess.run(args,cwd=cwd,env=env,stdout=f,stderr=subprocess.STDOUT,timeout=1800)
  commands.append(dict(name=name,argv=args,exit_code=r.returncode,seconds=round(time.monotonic()-start,3)));(e/'COMMANDS.json').write_text(json.dumps(commands,indent=2)+'\n');print(name,r.returncode,flush=True)
  if r.returncode:raise SystemExit('Failed: '+str(log))
 def build(label,project,cwd=R/'tests'):
  args=[a.dotnet,'restore',str(project),'--locked-mode','--disable-parallel','-m:1','-nr:false','-p:NuGetAudit=false']
  for s in a.source:args+=['--source',s]
  run(label+'-restore',args,cwd);run(label+'-build',[a.dotnet,'build',str(project),'--no-restore','-c','Release','-m:1','-nr:false','-p:UseSharedCompilation=false'],cwd)
 for suffix in ['UnitTests','ContractTests','StorageTests','CacheTests','ClientTests','HostTests','YsqlTests','DragonflyTests']:
  name='Treehammock.SessionValidation.'+suffix;build(name,R/'tests'/name/(name+'.csproj'))
  for target in (['net10.0'] if suffix=='HostTests' else ['net8.0','net10.0']):
   binary=R/'tests'/name/'bin/Release'/target/(name+'.dll');label=name+'-'+target
   if suffix in ['YsqlTests','DragonflyTests']:
    if target=='net10.0':
     run('native-'+suffix,[a.dotnet,str(binary),'-preEnumerateTheories','-list','tests/json']);native[suffix]=len(json.loads((e/('native-'+suffix+'.log')).read_text()))
   else:
    report=e/(label+'.xml');run(label,[a.dotnet,str(binary),'-maxThreads','1','-xml',str(report)]);reports.append(report)
 build('application',R/'treehammock.Tests/treehammock.Tests.csproj')
 from importlib.machinery import SourceFileLoader
 old=SourceFileLoader('old_core',str(R/'eng/session-validation/validate-core.py')).load_module()
 classes=['treehammock.Tests.Unit.'+x for x in old.CLASSES]+['treehammock.Tests.Integration.Cor23HSmtpTransportTests','treehammock.Tests.Integration.Svs03HttpParityTests','treehammock.Tests.Integration.Svs03MiddlewareParityTests','treehammock.Tests.Unit.AuthenticateAttributeTests','treehammock.Tests.Unit.CacheJsonSettingsTests']
 report=e/'application-selected.xml';args=[a.dotnet,str(R/'treehammock.Tests/bin/Release/net8.0/treehammock.Tests.dll'),'-maxThreads','2','-xml',str(report)]
 for c in classes:args+=['-class',c]
 run('application-selected',args);reports.append(report)
 assert hashlib.sha256(a.peer_archive.read_bytes()).hexdigest()=='364de19c8a5c65d82e79bbb22f745effeb59281d97a2dd10ae4b8e1d3a5d41b0','Wrong THS12C source'
 with tempfile.TemporaryDirectory(prefix='svs11-peer-') as temp:
  with zipfile.ZipFile(a.peer_archive) as z:assert z.testzip() is None;z.extractall(temp)
  peer=Path(temp)/'source/treehammock-main';scope=json.loads((peer/'eng/session-validation/THS12C_VALIDATION_SCOPE.json').read_text())
  build('peer-application',peer/'treehammock.Tests/treehammock.Tests.csproj',peer/'tests')
  report=e/'peer-selected.xml';args=[a.dotnet,str(peer/'treehammock.Tests/bin/Release/net8.0/treehammock.Tests.dll'),'-maxThreads','2','-xml',str(report)]
  for c in scope['application_classes']:args+=['-class',c]
  run('peer-selected',args,peer);reports.append(report)
  build('peer-native',peer/'treehammock.Tests.SqlContracts/treehammock.Tests.SqlContracts.csproj',peer/'tests')
  run('peer-native-discovery',[a.dotnet,str(peer/'treehammock.Tests.SqlContracts/bin/Release/net8.0/treehammock.Tests.SqlContracts.dll'),'-class','*Ths*','-preEnumerateTheories','-list','tests/json'],peer);native['THS12C']=len(json.loads((e/'peer-native-discovery.log').read_text()))
  run('cache-authorization-audit',[sys.executable,str(R/'eng/session-validation/audit-cache-authorization.py'),'--peer-root',str(peer),'--output',str(e/'code-audit')],peer/'tests')
  run('peer-refill-audit',[sys.executable,str(peer/'eng/session-validation/audit-ths12c-refill.py')],peer/'tests')
 run('foreground-readonly-audit',[sys.executable,str(R/'eng/session-validation/audit-readonly-sql.py')])
 results=[]
 for report in reports:
  asm=ET.parse(report).getroot().find('assembly');row={k:int(asm.get(k,'0')) for k in ['total','passed','failed','errors','skipped','not-run']};assert row['total'] and not any(row[k] for k in ['failed','errors','skipped','not-run']);results.append(dict(report=report.name,sha256=hashlib.sha256(report.read_bytes()).hexdigest(),**row))
 warnings={f.stem:int(__import__('re').findall(r'(\d+) Warning\(s\)',f.read_text())[-1]) for f in e.glob('*-build.log')}
 summary=dict(build_warning_counts=warnings,new_svs_project_warnings=sum(v for k,v in warnings.items() if k.startswith("Treehammock.SessionValidation.")),pr='SVS-11',status='LocalValidationPassedPendingNativeAcceptance',reports=results,total_test_executions=sum(x['passed'] for x in results),native_cases_discovered=native,native_cases_executed=0,build_errors=0,grant_rights=False,release_ready=False,next_pr='SVS-12',scope='Actual loopback TLS/gRPC with infrastructure doubles; exact peer local tests; native compile/discover only; no target provisioning or native execution')
 (e/'VALIDATION.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary,indent=2))
if __name__=='__main__':main()
