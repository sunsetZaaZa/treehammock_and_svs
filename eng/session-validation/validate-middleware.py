#!/usr/bin/env python3
"""SVS-03 local middleware/public protocol parity; native SQL/service qualification stays open."""
from pathlib import Path
import argparse
import json
import os
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[2]

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--dotnet',default='dotnet');p.add_argument('--packages',type=Path)
    p.add_argument('--source',action='append',default=[]);p.add_argument('--evidence-dir',type=Path,required=True)
    a=p.parse_args();e=a.evidence_dir.resolve();e.mkdir(parents=True,exist_ok=True)
    env=os.environ.copy();env['SVS03_EVIDENCE_DIRECTORY']=str(e);env['DOTNET_CLI_TELEMETRY_OPTOUT']='1'
    if Path(a.dotnet).is_absolute():env['DOTNET_ROOT']=str(Path(a.dotnet).resolve().parent)
    if a.packages:env['NUGET_PACKAGES']=str(a.packages.resolve())
    argv=[sys.executable,str(ROOT/'eng/session-validation/validate-core.py'),'--dotnet',a.dotnet,'--evidence-dir',str(e/'svs02-regressions')]
    if a.packages:argv+=['--packages',str(a.packages.resolve())]
    for source in a.source:argv+=['--source',source]
    result=subprocess.run(argv,env=env)
    if result.returncode:raise SystemExit(result.returncode)
    args=['../treehammock.Tests/bin/Release/net8.0/treehammock.Tests.dll']
    classes=['treehammock.Tests.Integration.Svs03HttpParityTests','treehammock.Tests.Integration.Svs03MiddlewareParityTests',
             'treehammock.Tests.Unit.AuthenticateAttributeTests','treehammock.Tests.Unit.CacheJsonSettingsTests']
    for name in classes:args+=['-class',name]
    args+=['-maxThreads','2','-xml',str(e/'middleware-parity.xml')]
    started=time.monotonic()
    with (e/'middleware-parity.log').open('w') as f:
        result=subprocess.run([a.dotnet,*args],cwd=ROOT/'tests',env=env,stdout=f,stderr=subprocess.STDOUT)
    (e/'COMMANDS.json').write_text(json.dumps([dict(argv=['dotnet',*args],exit_code=result.returncode,seconds=round(time.monotonic()-started,3),log='middleware-parity.log')],indent=2)+'\n')
    if result.returncode:raise SystemExit('Middleware parity failed; see '+str(e/'middleware-parity.log'))
    assembly=ET.parse(e/'middleware-parity.xml').getroot().find('assembly')
    assert assembly is not None
    totals={k:int(assembly.get(k,'0')) for k in ['total','passed','failed','skipped','errors','not-run']}
    if not totals['total'] or any(totals[k] for k in ['failed','skipped','errors','not-run']):raise SystemExit('Incomplete parity evidence')
    # The subprocess reports the static finding independently from green local fixture tests.
    with (e/'F02_SOURCE_OBSERVATION.json').open('w') as f:
        result=subprocess.run([sys.executable,str(ROOT/'eng/session-validation/inspect-account-state-parity.py')],stdout=f)
    if result.returncode:raise SystemExit(result.returncode)
    baseline=json.loads((e/'svs02-regressions/VALIDATION.json').read_text())
    summary={'pr':'SVS-03','status':'LocalHttpParityPassedPendingNativeAcceptance','baseline_test_executions':baseline['total_test_executions'],
        'parity_selection':totals,'total_test_executions':baseline['total_test_executions']+totals['passed'],
        'not_run':'Native YSQL/Dragonfly/account-state/writer/revocation/failover/mTLS/physical-host/COR qualification; whole repository suite; advisory feed audit',
        'production_behavior_changed':False,'F02':'OpenNativeAdjudicationRequired','release_ready':False,'next_pr':'SVS-04'}
    (e/'VALIDATION.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary,indent=2))

if __name__=='__main__':main()
