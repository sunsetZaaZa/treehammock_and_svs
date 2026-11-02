#!/usr/bin/env python3
"""SVS-13: exact-peer production-owner schedules and existing parity regressions.

Local storage doubles only. Native multi-process cases are retained as NotRun.
"""
import argparse, hashlib, json, os, shutil, subprocess, sys, tempfile, time, zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
R=Path(__file__).resolve().parents[2]
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser()
    p.add_argument('--dotnet',required=True);p.add_argument('--packages',required=True,type=Path)
    p.add_argument('--source',action='append',default=[]);p.add_argument('--evidence-dir',required=True,type=Path)
    p.add_argument('--baseline-archive',required=True,type=Path);p.add_argument('--peer-archive',required=True,type=Path)
    # Reuse only evidence created by this runner's exact parity command, with every
    # input hash checked below; useful when the long regression stage already ran.
    p.add_argument('--reuse-regressions',action='store_true');p.add_argument('--overlay-only',action='store_true')
    a=p.parse_args();e=a.evidence_dir.resolve();e.mkdir(parents=True,exist_ok=True)
    env=os.environ.copy();env.update(DOTNET_ROOT=str(Path(a.dotnet).resolve().parent),NUGET_PACKAGES=str(a.packages.resolve()),MSBUILDDISABLENODEREUSE='1',SVS13_EVIDENCE_DIRECTORY=str(e/'schedules'))
    assert sha(a.peer_archive)=='364de19c8a5c65d82e79bbb22f745effeb59281d97a2dd10ae4b8e1d3a5d41b0'
    commands=[]
    def run(label,args,cwd=R/'tests'):
        start=time.monotonic()
        with (e/(label+'.log')).open('w') as f:r=subprocess.run(args,cwd=cwd,env=env,stdout=f,stderr=subprocess.STDOUT,timeout=1800)
        commands.append(dict(name=label,exit_code=r.returncode,seconds=round(time.monotonic()-start,3)))
        (e/'COMMANDS.json').write_text(json.dumps(commands,indent=2)+'\n');print(label,r.returncode,flush=True)
        if r.returncode:raise SystemExit('Failed '+str(e/(label+'.log')))
    scope={str(p.relative_to(R)):sha(p) for p in R.rglob('*') if p.is_file() and not {'bin','obj','__pycache__'}.intersection(p.parts)}
    identity=dict(baseline=sha(a.baseline_archive),peer=sha(a.peer_archive),source=scope)
    marker=e/'REGRESSION_INPUTS.json'
    if a.overlay_only:
        pass
    elif a.reuse_regressions:
        assert marker.exists() and json.loads(marker.read_text())==identity,'Stale/missing regression input identity; rerun regressions'
    else:
        args=[sys.executable,str(R/'eng/session-validation/validate-parity.py'),'--dotnet',a.dotnet,'--packages',str(a.packages.resolve()),'--evidence-dir',str(e/'regressions'),'--baseline-archive',str(a.baseline_archive.resolve()),'--peer-archive',str(a.peer_archive.resolve())]
        for source in a.source:args+=['--source',source]
        run('regressions',args);marker.write_text(json.dumps(identity,indent=2)+'\n')
    baseline=dict(total_test_executions=0) if a.overlay_only else json.loads((e/'regressions/VALIDATION.json').read_text())
    if not a.overlay_only:assert baseline['build_errors']==0
    with tempfile.TemporaryDirectory(prefix='svs13-peer-') as tmp:
        with zipfile.ZipFile(a.peer_archive) as z:assert z.testzip() is None;z.extractall(tmp)
        peer=Path(tmp)/'source/treehammock-main';original={p.relative_to(peer).as_posix():sha(p) for p in peer.rglob('*') if p.is_file()}
        tests=peer/'treehammock.Tests';overlays=[]
        for src,name in [
            ('tests/Treehammock.SessionValidation.ContractTests/TreehammockParityFixtures.cs','Svs12GoldenFixtures.cs'),
            ('tests/Treehammock.SessionValidation.StorageTests/ParityHarness.cs','ParityHarness.cs'),
            ('tests/Treehammock.SessionValidation.CacheTests/ReplicaRaces/RaceHarness.cs','Svs13RaceHarness.cs'),
            ('tests/Treehammock.SessionValidation.ContractTests/PeerOverlay/RevocationInterleavings.cs.txt','Svs13RevocationInterleavings.cs')]:
            dst=tests/'Unit'/name;assert not dst.exists();shutil.copyfile(R/src,dst);overlays.append(dict(source=src,destination=str(dst.relative_to(peer)),sha256=sha(dst)))
        shutil.copytree(R/'tests/Treehammock.SessionValidation.ContractTests/Fixtures/GoldenSessions',tests/'Fixtures/GoldenSessions')
        project=tests/'treehammock.Tests.csproj';project.write_text(project.read_text().replace('</Project>','<ItemGroup><Content Include="Fixtures/GoldenSessions/**" CopyToOutputDirectory="PreserveNewest"/></ItemGroup></Project>'))
        args=[a.dotnet,'restore',str(project),'--locked-mode','--disable-parallel','-m:1','-nr:false','-p:NuGetAudit=false']
        for source in a.source:args+=['--source',source]
        run('peer-restore',args,peer/'tests');run('peer-build',[a.dotnet,'build',str(project),'-c','Release','--no-restore','-m:1','-nr:false','-p:UseSharedCompilation=false'],peer/'tests')
        run('peer-races',[a.dotnet,str(tests/'bin/Release/net8.0/treehammock.Tests.dll'),'-class','*Svs13RevocationInterleavings','-maxThreads','1','-xml',str(e/'peer-races.xml')],peer/'tests')
        assert all(sha(peer/n)==h for n,h in original.items() if n!='treehammock.Tests/treehammock.Tests.csproj')
        (e/'PEER_OVERLAY.json').write_text(json.dumps(dict(peer_archive_sha256=sha(a.peer_archive),production_and_locks_unchanged=True,files=overlays),indent=2)+'\n')
    asm=ET.parse(e/'peer-races.xml').getroot().find('assembly');counts={k:int(asm.get(k,'0')) for k in ['total','passed','failed','errors','skipped','not-run']}
    assert counts['passed']==1000 and not any(counts[k] for k in ['failed','errors','skipped','not-run'])
    schedules=[json.loads((e/'schedules'/f'peer-race-{n:04d}.json').read_text()) for n in range(1000)]
    assert len({x['seed'] for x in schedules})==1000 and all(x['native'] is False for x in schedules)
    coverage={m:sorted({x['mode'] for x in schedules if x['mutation']==m}) for m in {x['mutation'] for x in schedules}}
    assert len(coverage)==13 and all(modes==list(range(6)) for modes in coverage.values())
    def percentile(values, p):
        values=sorted(values);return values[max(0,__import__('math').ceil(len(values)*p)-1)]
    readers=[v for row in schedules for v in row['readerMilliseconds']]
    waits=[row['writerLockWaitMilliseconds'] for row in schedules]
    timing=dict(scope='Local storage doubles; informational only, no approved physical-host/network SLO',reader_samples=len(readers),reader_p99_ms=percentile(readers,.99),writer_lock_wait_samples=len(waits),writer_lock_wait_p99_ms=percentile(waits,.99))
    (e/'LOCAL_TIMING.json').write_text(json.dumps(timing,indent=2)+'\n')
    run('native-matrix-check' ,[sys.executable,str(R/'eng/session-validation/test-race-manifest.py')])
    result=dict(pr='SVS-13',status='LocalOwnerSchedulesPassedPendingNativeQualification',local_paired_schedules=1000,distinct_mutation_modes=78,mutation_modes=coverage,peer_report=dict(sha256=sha(e/'peer-races.xml'),**counts),regression_executions=baseline['total_test_executions'],total_test_executions=baseline['total_test_executions']+1000,native_cases_executed=0,native_paired_schedules_executed=0,native_execution='NotRun: no explicitly owned configured disposable targets',production_runtime_changed=False,grant_rights=False,release_ready=False,next_pr='SVS-14',scope='Two local coordinator instances and alternating TreeHammock owner objects; production guard/fence/publisher; storage doubles; not separate processes or native MVCC')
    if a.overlay_only:
        (e/'OVERLAY_VALIDATION.json').write_text(json.dumps(result,indent=2)+'\n');return
    (e/'VALIDATION.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()
