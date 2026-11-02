#!/usr/bin/env python3
"""Exact THS12C peer vs current SVS, private synthetic paired capture only."""
import argparse,hashlib,json,os,resource,shutil,subprocess,tempfile,zipfile
from pathlib import Path
from rollout import collect,private_read
S=Path(__file__).resolve().parents[3]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    a=argparse.ArgumentParser();a.add_argument('--dotnet',required=True,type=Path);a.add_argument('--peer-archive',required=True,type=Path);a.add_argument('--evidence-dir',required=True,type=Path);args=a.parse_args();E=args.evidence_dir.resolve();E.mkdir(parents=True,exist_ok=True)
    need_peer='364de19c8a5c65d82e79bbb22f745effeb59281d97a2dd10ae4b8e1d3a5d41b0';assert sha(args.peer_archive)==need_peer
    with tempfile.TemporaryDirectory(prefix='svs21-private-') as directory:
        private=Path(directory);private.chmod(0o700);capture=private/'capture';capture.mkdir(mode=0o700);peerroot=private/'peer'
        with zipfile.ZipFile(args.peer_archive) as z:assert z.testzip() is None;z.extractall(peerroot)
        peer=peerroot/'source/treehammock-main';original={p.relative_to(peer).as_posix():sha(p) for p in peer.rglob('*') if p.is_file()};tests=peer/'treehammock.Tests';overlay=[]
        sources=[('tests/Treehammock.SessionValidation.ContractTests/TreehammockParityFixtures.cs','Svs12GoldenFixtures.cs'),('tests/Treehammock.SessionValidation.StorageTests/ParityHarness.cs','ParityHarness.cs'),('treehammock.Tests/Unit/CurrentIssuerTests.cs','CurrentIssuerTests.cs'),('tests/Treehammock.SessionValidation.ContractTests/PeerOverlay/MiddlewareGoldenTests.cs.txt','Svs12MiddlewareGoldenTests.cs'),('tests/Treehammock.SessionValidation.ContractTests/PeerOverlay/PrivateCaptureTests.cs.txt','PrivateCaptureTests.cs')]
        for src,name in sources:
            dst=tests/'Unit'/name;assert not dst.exists();shutil.copyfile(S/src,dst);overlay.append(dict(source=src,destination=dst.relative_to(peer).as_posix(),sha256=sha(dst)))
        shutil.copytree(S/'tests/Treehammock.SessionValidation.ContractTests/Fixtures/GoldenSessions',tests/'Fixtures/GoldenSessions')
        project=tests/'treehammock.Tests.csproj';before=sha(project);project.write_text(project.read_text().replace('</Project>','<ItemGroup><Content Include="Fixtures/GoldenSessions/**" CopyToOutputDirectory="PreserveNewest"/></ItemGroup></Project>'))
        env=dict(os.environ,DOTNET_ROOT=str(args.dotnet.resolve().parent),DOTNET_PROCESSOR_COUNT='4',MSBUILDDISABLENODEREUSE='1',SVS21_PRIVATE_CAPTURE=str(capture),SVS12_EVIDENCE_DIRECTORY=str(E/'observations'))
        # Do not inherit an issued-token override or export target from another job.
        for key in ['SVS12_EXPORT_TOKENS','SVS12_ISSUED_TOKENS_PATH']:env.pop(key,None)
        commands=[]
        def run(label,argv,cwd):
            with (E/(label+'.log')).open('w') as f:r=subprocess.run([str(args.dotnet.resolve()),*map(str,argv)],cwd=cwd,env=env,stdout=f,stderr=subprocess.STDOUT,timeout=600)
            commands.append(dict(label=label,exit_code=r.returncode));(E/'pairing-commands.json').write_text(json.dumps(commands,indent=2)+'\n');assert r.returncode==0,label;print(label,'Passed',flush=True)
        run('paired-peer-restore',['restore',project,'--locked-mode','--disable-parallel','-m:1','-p:NuGetAudit=false'],peer/'tests')
        run('paired-peer-build',['build',project,'--no-restore','-c','Release','-m:1'],peer/'tests')
        run('paired-peer-tests',[tests/'bin/Release/net8.0/treehammock.Tests.dll','-class','*Svs12MiddlewareGoldenTests','-class','*Svs12CurrentIssuerTests','-class','*Svs21PrivateCaptureTests','-maxThreads','1','-xml',E/'paired-peer-tests.xml'],peer/'tests')
        current=S/'tests/Treehammock.SessionValidation.StorageTests/Treehammock.SessionValidation.StorageTests.csproj'
        run('paired-current-restore',['restore',current,'--locked-mode','--disable-parallel','-m:1','-p:NuGetAudit=false'],S.parent.parent)
        run('paired-current-build',['build',current,'--no-restore','-m:1'],S.parent.parent)
        run('paired-current-tests',[current.parent/'bin/Debug/net10.0/Treehammock.SessionValidation.StorageTests.dll','-xml',E/'paired-current-tests.xml'],S.parent.parent)
        assert all(sha(peer/n)==h for n,h in original.items() if n!='treehammock.Tests/treehammock.Tests.csproj')
        runtime={p.relative_to(S).as_posix():sha(p) for p in S.rglob('*.cs') if p.is_file() and not {'bin','obj'}.intersection(p.parts) and (p.relative_to(S).parts[0]=='src' or p.relative_to(S).parts[0] in {'Controllers','DataLayer','Entities','Models','Repos','Rigging','RiggingSupport','Services'})}
        current_digest=hashlib.sha256(json.dumps(runtime,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        corpus=json.loads((S/'tests/Treehammock.SessionValidation.ContractTests/Fixtures/GoldenSessions/session-cases.json').read_text());pairs=[];expected=[]
        for case in corpus['cases']:
            id=case['id'];old=json.loads(private_read(capture/f'peer-{id}.json',16384));new=json.loads(private_read(capture/f'svs-{id}.json',16384));assert old['token']==new['token'],'Paired input differs'
            pairs.append(dict(token=old['token'],old={k:old[k] for k in ['decision','identity']},svs={k:new[k] for k in ['decision','identity']},replica='svs-1',cache_hit=new['cache_hit'],sql_reads=new['sql'],duration_us=new['duration_us'],writer_fence_us=0))
            if case.get('expectedTreehammock',case['expectedCoordinator'])!=case['expectedCoordinator']:expected.append(dict(case=id,old=old['decision'],svs=new['decision']))
        report=collect(b'\n'.join(json.dumps(v,separators=(',',':')).encode() for v in pairs),os.urandom(32),dict(version=1,scope='GoldenReference',old_source_sha256=need_peer,svs_source_sha256=current_digest,replicas=['svs-1']))
        (E/'paired-comparison.json').write_text(json.dumps(report,indent=2)+'\n');(E/'paired-source-provenance.json').write_text(json.dumps(dict(status='PairedSyntheticCollected',peer_archive_sha256=need_peer,current_runtime_source_sha256=current_digest,current_runtime_files=runtime,original_peer_files=len(original),original_peer_production_and_locks_unchanged=True,test_project_original_sha256=before,test_project_overlay_sha256=sha(project),test_only_overlay=overlay,paired_cases=len(pairs),known_profile_differences=expected,raw_capture_exported=False,writer_fence_measurement='NotRun',logical_replica_only=True,native_acceptance='NotRun',grant_rights=False,release_ready=False),indent=2)+'\n')
        print(json.dumps(dict(status='PairedSyntheticCollected',samples=len(pairs),mismatches=report['mismatches'],escalations=report['escalations'],native_acceptance='NotRun')))
if __name__=='__main__':main()
