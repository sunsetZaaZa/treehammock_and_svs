#!/usr/bin/env python3
"""SVS09 locked builds, actual net8/net10 SDK and host tests, selected regressions; native discovery only."""
from pathlib import Path
import argparse,json,os,subprocess,sys,time,xml.etree.ElementTree as ET
R=Path(__file__).resolve().parents[2]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--dotnet',default='dotnet');p.add_argument('--packages',type=Path);p.add_argument('--source',action='append',default=[]);p.add_argument('--evidence-dir',type=Path,required=True);a=p.parse_args();E=a.evidence_dir.resolve();E.mkdir(parents=True,exist_ok=True);env=os.environ.copy();env['DOTNET_CLI_TELEMETRY_OPTOUT']='1'
 if Path(a.dotnet).is_absolute():env['DOTNET_ROOT']=str(Path(a.dotnet).resolve().parent)
 if a.packages:env['NUGET_PACKAGES']=str(a.packages.resolve())
 commands=[]
 def run(name,args):
  start=time.monotonic()
  with (E/(name+'.log')).open('w') as f:r=subprocess.run(args,cwd=R/'tests',env=env,stdout=f,stderr=subprocess.STDOUT)
  commands.append(dict(name=name,argv=args,exit_code=r.returncode,seconds=round(time.monotonic()-start,3)));(E/'COMMANDS.json').write_text(json.dumps(commands,indent=2)+'\n');print(name,r.returncode,flush=True)
  if r.returncode:raise SystemExit('See '+str(E/(name+'.log')))
 for name in ['ClientTests','HostTests']:
  project=f'Treehammock.SessionValidation.{name}/Treehammock.SessionValidation.{name}.csproj';args=[a.dotnet,'restore',project,'--locked-mode','--disable-build-servers','-m:1','-p:NuGetAudit=false']
  if a.packages:args+=['--packages',str(a.packages.resolve())]
  for source in a.source:args+=['--source',source]
  run('restore-'+name,args);run('build-'+name,[a.dotnet,'build',project,'-c','Release','--no-restore','--disable-build-servers','-m:1'])
 for name,targets in [('ClientTests',['net8.0','net10.0']),('HostTests',['net10.0'])]:
  for target in targets:run(name+'-'+target,[a.dotnet,f'Treehammock.SessionValidation.{name}/bin/Release/{target}/Treehammock.SessionValidation.{name}.dll','-maxThreads','1','-xml',str(E/(name+'-'+target+'.xml'))])
 args=[sys.executable,str(R/'eng/session-validation/validate-cache.py'),'--dotnet',a.dotnet,'--evidence-dir',str(E/'regressions')]
 if a.packages:args+=['--packages',str(a.packages.resolve())]
 for source in a.source:args+=['--source',source]
 run('regressions',args)
 reports={}
 for f in E.rglob('*.xml'):
  for asm in ET.parse(f).getroot().findall('assembly'):
   x={k:int(asm.get(k,'0')) for k in ['total','passed','failed','skipped','errors','not-run']};assert x['total'] and all(x[k]==0 for k in ['failed','skipped','errors','not-run']);reports[f.relative_to(E).as_posix()]=x
 out=dict(pr='SVS-09',status='ImplementedLocalTypedClientPendingNativeAcceptance',total_test_executions=sum(x['passed'] for x in reports.values()),results=reports,build_errors=0,native_cases_discovered={n:len(json.loads((E/'regressions'/('native-discovery-'+n+'.log')).read_text())) for n in ['YsqlTests','DragonflyTests']},native_cases_executed=0,release_ready=False,next_pr='SVS-10')
 (E/'VALIDATION.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out))
if __name__=='__main__':main()
