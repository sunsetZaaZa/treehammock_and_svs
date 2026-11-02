#!/usr/bin/env python3
"""SVS-04 locked builds and local tests. Native tests compile but require explicit separate invocation."""
import argparse,json,os,subprocess,sys,time,xml.etree.ElementTree as ET
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--dotnet',default='dotnet');p.add_argument('--packages',type=Path);p.add_argument('--source',action='append',default=[]);p.add_argument('--evidence-dir',type=Path,required=True);a=p.parse_args()
    e=a.evidence_dir.resolve();e.mkdir(parents=True,exist_ok=True);env=os.environ.copy();env['DOTNET_CLI_TELEMETRY_OPTOUT']='1'
    if Path(a.dotnet).is_absolute():env['DOTNET_ROOT']=str(Path(a.dotnet).resolve().parent)
    if a.packages:env['NUGET_PACKAGES']=str(a.packages.resolve())
    argv=[sys.executable,str(ROOT/'eng/session-validation/validate-middleware.py'),'--dotnet',a.dotnet,'--evidence-dir',str(e/'svs03-regressions')]
    if a.packages:argv+=['--packages',str(a.packages.resolve())]
    for src in a.source:argv+=['--source',src]
    result=subprocess.run(argv,env=env)
    if result.returncode:raise SystemExit(result.returncode)
    commands=[]
    def run(name,args):
        started=time.monotonic()
        with (e/(name+'.log')).open('w') as f:r=subprocess.run([a.dotnet,*args],cwd=ROOT/'tests',env=env,stdout=f,stderr=subprocess.STDOUT)
        commands.append(dict(name=name,argv=['dotnet',*args],exit_code=r.returncode,seconds=round(time.monotonic()-started,3)))
        (e/'COMMANDS.json').write_text(json.dumps(commands,indent=2)+'\n');print(name+(': PASS' if not r.returncode else ': FAIL'),flush=True)
        if r.returncode:raise SystemExit('See '+str(e/(name+'.log')))
    for name in ['StorageTests','YsqlTests']:
        project=f'Treehammock.SessionValidation.{name}/Treehammock.SessionValidation.{name}.csproj'
        args=['restore',project,'--locked-mode','-p:NuGetAudit=false']
        if a.packages:args+=['--packages',str(a.packages.resolve())]
        for src in a.source:args+=['--source',src]
        run('restore-'+name,args);run('build-'+name,['build',project,'--no-restore','-c','Release','--disable-build-servers','-m:1'])
    results=[]
    for framework in ['net8.0','net10.0']:
        report=e/('storage-'+framework+'.xml')
        run('storage-'+framework,[f'Treehammock.SessionValidation.StorageTests/bin/Release/{framework}/Treehammock.SessionValidation.StorageTests.dll','-maxThreads','2','-xml',str(report)])
        assembly=ET.parse(report).getroot().find('assembly');assert assembly is not None
        item={k:int(assembly.get(k,'0')) for k in ['total','passed','failed','skipped','errors','not-run']};item['framework']=framework
        assert item['total'] and not any(item[k] for k in ['failed','skipped','errors','not-run']);results.append(item)
    with (e/'SQL_DEPENDENCY_AUDIT.json').open('w') as f:r=subprocess.run([sys.executable,str(ROOT/'eng/session-validation/audit-readonly-sql.py')],stdout=f)
    if r.returncode:raise SystemExit(r.returncode)
    baseline=json.loads((e/'svs03-regressions/VALIDATION.json').read_text())
    out=dict(pr='SVS-04',status='ImplementedLocalStorageTestsPendingNativeAcceptance',baseline_test_executions=baseline['total_test_executions'],storage_results=results,total_test_executions=baseline['total_test_executions']+sum(i['passed'] for i in results),build_errors=0,new_projects_build_warnings=0,native_cases_executed=0,native_suite='Built net8/net10, not executed; no target YSQL or credentials available',not_run='Target Yugabyte snapshot/privilege/grant/calendar/cancellation/query-plan/lock-wait parity; physical-host/load/mTLS/Dragonfly/COR; whole repository suite; advisory feed audit',release_ready=False,next_pr='SVS-05')
    (e/'VALIDATION.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out,indent=2))
if __name__=='__main__':main()
