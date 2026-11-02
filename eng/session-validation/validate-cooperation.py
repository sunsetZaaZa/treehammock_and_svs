#!/usr/bin/env python3
"""SVS10 fresh regressions and exact THS12B local conformance; native fixtures discover only."""
from pathlib import Path
import argparse,json,os,subprocess,sys,tempfile,time,zipfile,xml.etree.ElementTree as ET
R=Path(__file__).resolve().parents[2]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--dotnet',default='dotnet');p.add_argument('--packages',type=Path);p.add_argument('--source',action='append',default=[]);p.add_argument('--evidence-dir',type=Path,required=True);p.add_argument('--peer-archive',type=Path,required=True);a=p.parse_args();E=a.evidence_dir.resolve();E.mkdir(parents=True,exist_ok=True);env=os.environ.copy();env['DOTNET_CLI_TELEMETRY_OPTOUT']='1'
 if Path(a.dotnet).is_absolute():env['DOTNET_ROOT']=str(Path(a.dotnet).resolve().parent)
 if a.packages:env['NUGET_PACKAGES']=str(a.packages.resolve())
 commands=[]
 def run(name,args,cwd=R/'tests'):
  start=time.monotonic();target=E/(name+'.log');target.parent.mkdir(parents=True,exist_ok=True)
  with target.open('w') as f:r=subprocess.run(args,cwd=cwd,env=env,stdout=f,stderr=subprocess.STDOUT)
  commands.append(dict(name=name,argv=args,cwd=str(cwd),exit_code=r.returncode,seconds=round(time.monotonic()-start,3)));(E/'COMMANDS.json').write_text(json.dumps(commands,indent=2)+'\n');print(name,r.returncode,flush=True)
  if r.returncode:raise SystemExit('See '+str(target))
 run('joint-source-audit',[sys.executable,str(R/'eng/session-validation/inspect-joint-contract.py'),'--peer-archive',str(a.peer_archive.resolve())])
 args=[sys.executable,str(R/'eng/session-validation/validate-client.py'),'--dotnet',a.dotnet,'--evidence-dir',str(E/'svs-regressions')]
 if a.packages:args+=['--packages',str(a.packages.resolve())]
 for source in a.source:args+=['--source',source]
 run('svs-regressions',args)
 with tempfile.TemporaryDirectory(prefix='svs10-peer-') as directory:
  with zipfile.ZipFile(a.peer_archive) as z:z.extractall(directory)
  peer=Path(directory)/'source/treehammock-main';cwd=peer/'tests'
  for name in ['treehammock.Tests','treehammock.Tests.SqlContracts']:
   project='../'+name+'/'+name+'.csproj';args=[a.dotnet,'restore',project,'--locked-mode','--disable-build-servers','-m:1','-p:NuGetAudit=false']
   if a.packages:args+=['--packages',str(a.packages.resolve())]
   for source in a.source:args+=['--source',source]
   run('peer/restore-'+name,args,cwd);run('peer/build-'+name,[a.dotnet,'build',project,'-c','Release','--no-restore','--disable-build-servers','-m:1'],cwd)
  run('peer/conformance',[a.dotnet,'../treehammock.Tests/bin/Release/net8.0/treehammock.Tests.dll','-maxThreads','1','-class','*Ths08*','-class','*Ths11*','-class','*Ths12*','-xml',str(E/'peer/conformance.xml')],cwd)
  run('peer/native-discovery',[a.dotnet,'../treehammock.Tests.SqlContracts/bin/Release/net8.0/treehammock.Tests.SqlContracts.dll','-class','*Ths*','-preEnumerateTheories','-list','tests/json'],cwd)
 reports={}
 for f in E.rglob('*.xml'):
  for asm in ET.parse(f).getroot().findall('assembly'):
   x={k:int(asm.get(k,'0')) for k in ['total','passed','failed','skipped','errors','not-run']};assert x['total'] and all(x[k]==0 for k in ['failed','skipped','errors','not-run']);reports[f.relative_to(E).as_posix()]=x
 native={n:len(json.loads((E/'svs-regressions/regressions'/('native-discovery-'+n+'.log')).read_text())) for n in ['YsqlTests','DragonflyTests']};native['THS12B_ThsNative']=len(json.loads((E/'peer/native-discovery.log').read_text()))
 out=dict(pr='SVS-10',status='ImplementedLocalJointConformancePendingNativeAcceptance',total_test_executions=sum(x['passed'] for x in reports.values()),results=reports,build_errors=0,native_cases_discovered=native,native_cases_executed=0,release_ready=False,next_pr='SVS-11',scope='Real loopback TLS and exact peer sources with substituted SQL/cache/lease providers; no target or cross-host qualification')
 (E/'VALIDATION.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out,indent=2))
if __name__=='__main__':main()
