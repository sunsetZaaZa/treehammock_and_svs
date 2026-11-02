#!/usr/bin/env python3
"""Pinned local/CI entry point. Private raw logs never become GitLab artifacts."""
import argparse,hashlib,json,os,re,shutil,subprocess,sys,tempfile,time
from pathlib import Path
from policy import ROOT,Refused,require,sha,check_source,check_archive,check_image,verify_packages,scan,source_fingerprint
from artifacts import bundle,encode
BASELINE='f80eb2feea073a1c6dba9049cce4b28c913b0021c71890cc859a29b62d582aa2'
PEER='364de19c8a5c65d82e79bbb22f745effeb59281d97a2dd10ae4b8e1d3a5d41b0'
SDK={'root':'8.0.415','tests':'10.0.100'}
def execute(args,cwd,env,log,timeout):
    with log.open('wb') as f:
        r=subprocess.run(args,cwd=cwd,env=env,stdout=f,stderr=subprocess.STDOUT,timeout=timeout)
    if r.returncode and os.environ.get('GITLAB_CI')!='true' and os.environ.get('SVS14_LOCAL_DEBUG_DIRECTORY'):
        debug=Path(os.environ['SVS14_LOCAL_DEBUG_DIRECTORY']);debug.mkdir(mode=0o700,parents=True,exist_ok=True);shutil.copyfile(log,debug/log.name)
        if (log.parent/'evidence').exists():shutil.copytree(log.parent/'evidence',debug/'failed-evidence',dirs_exist_ok=True)
    require(r.returncode==0,'CHILD_COMMAND_FAILED')
def main():
    p=argparse.ArgumentParser();p.add_argument('--dotnet',default=os.environ.get('SVS14_DOTNET','dotnet'))
    p.add_argument('--baseline-archive',default=os.environ.get('SVS14_BASELINE_ARCHIVE'),type=Path);p.add_argument('--peer-archive',default=os.environ.get('SVS14_PEER_ARCHIVE'),type=Path)
    p.add_argument('--output',type=Path,default=ROOT/'artifacts/session-validation');p.add_argument('--local-evidence',type=Path)
    a=p.parse_args();require(a.baseline_archive is not None and a.peer_archive is not None,'PINNED_INPUTS_REQUIRED')
    check_source();check_archive(a.baseline_archive,BASELINE);check_archive(a.peer_archive,PEER)
    in_ci=os.environ.get('GITLAB_CI')=='true'
    if in_ci:check_image(os.environ.get('SVS14_CI_IMAGE'))
    dotnet=shutil.which(a.dotnet);require(dotnet is not None,'DOTNET_REQUIRED')
    a.output=a.output.resolve();require(not a.output.exists(),'FRESH_OUTPUT_REQUIRED')
    if a.local_evidence is not None:require(not in_ci and not a.local_evidence.exists(),'LOCAL_EVIDENCE_NOT_FOR_CI')
    initial_source=source_fingerprint()
    commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    if in_ci:
        require(commit==os.environ.get('CI_COMMIT_SHA'),'CHECKOUT_COMMIT_MISMATCH')
        require(not subprocess.check_output(['git','status','--porcelain'],cwd=ROOT),'DIRTY_CI_CHECKOUT')
    secrets=[v for k,v in os.environ.items() if any(x in k.upper() for x in ['PASSWORD','TOKEN','SECRET','CREDENTIAL']) and len(v)>=4]
    # A private per-run package store prevents shared expanded-package poisoning.
    with tempfile.TemporaryDirectory(prefix='svs14-private-') as temp:
        private=Path(temp);private.chmod(0o700);packages=private/'packages';evidence=private/'evidence'
        env=os.environ.copy();env.update(DOTNET_ROOT=str(Path(dotnet).resolve().parent),NUGET_PACKAGES=str(packages),DOTNET_PROCESSOR_COUNT='4',MSBUILDDISABLENODEREUSE='1',ContinuousIntegrationBuild='true',Deterministic='true',DOTNET_CLI_TELEMETRY_OPTOUT='true',DOTNET_NOLOGO='true')
        for name,cwd in [('root',ROOT),('tests',ROOT/'tests')]:
            version=subprocess.check_output([dotnet,'--version'],cwd=cwd,env=env,text=True).strip();require(version==SDK[name],'SDK_SELECTION_DRIFT')
        start=time.monotonic()
        args=[sys.executable,str(ROOT/'eng/session-validation/validate-races.py'),'--dotnet',dotnet,'--packages',str(packages),'--baseline-archive',str(a.baseline_archive.resolve()),'--peer-archive',str(a.peer_archive.resolve()),'--evidence-dir',str(evidence)]
        execute(args,ROOT/'tests',env,private/'validation.log',2100)
        helper=ROOT/'tests/Treehammock.SessionValidation.PackageHash/PackageHash.csproj'
        execute([dotnet,'restore',str(helper),'--locked-mode','--configfile',str(helper.parent/'NuGet.Offline.Config'),'-p:NuGetAudit=false'],ROOT/'tests',env,private/'hash-helper-restore.log',60)
        execute([dotnet,'build',str(helper),'-c','Release','--no-restore','-m:1','-nr:false','-p:UseSharedCompilation=false'],ROOT/'tests',env,private/'hash-helper-build.log',120)
        request=private/'package-request.json';response=private/'package-response.json'
        request.write_text(json.dumps([str(x) for x in sorted(packages.rglob('*.nupkg'))]))
        execute([dotnet,str(helper.parent/'bin/Release/net10.0/PackageHash.dll'),str(request),str(response)],ROOT/'tests',env,private/'package-hash.log',120)
        package_count=verify_packages(ROOT,packages,json.loads(response.read_text()))
        if a.local_evidence is not None:shutil.copytree(evidence,a.local_evidence)
        # Explicit second builds verify deterministic output for the real .NET 8
        # app and .NET 10 validator. No lock regeneration or configuration changes.
        deterministic={}
        for name,project,framework,cwd in [('treehammock',ROOT/'treehammock.csproj','net8.0',ROOT),('Treehammock.SessionValidation.Api',ROOT/'src/Treehammock.SessionValidation.Api/Treehammock.SessionValidation.Api.csproj','net10.0',ROOT/'tests')]:
            path=project.parent/'bin/Release'/framework/(name+'.dll');digests=[]
            for n in range(2):
                command=[dotnet,'build',str(project),'-c','Release','--no-restore','-t:Rebuild','-m:1','-nr:false','-p:UseSharedCompilation=false','-p:ContinuousIntegrationBuild=true','-p:Deterministic=true',f'-p:PathMap={ROOT}=/_/treehammock']
                execute(command,cwd,env,private/f'{name}-{n}.log',240);digests.append(sha(path))
            require(digests[0]==digests[1],'NONDETERMINISTIC_ASSEMBLY');deterministic[name]=digests[0]
        check_source();source_hash=source_fingerprint();require(source_hash==initial_source,'SOURCE_CHANGED_DURING_RUN')
        raw=json.loads((evidence/'VALIDATION.json').read_text())
        summary=dict(pr='SVS-14',status='LocalValidationPassedGitLabDockerNotRun',total_test_executions=raw['total_test_executions'],local_paired_schedule_executions=raw['local_paired_schedules'],cross_target_observation_pairs=280,verified_packages=package_count,deterministic_assemblies=deterministic,seconds=round(time.monotonic()-start,3),native_cases_executed=0,gitlab_docker_execution='NotRun' if not in_ci else 'RequiresExternalJobEvidence',grant_rights=False,release_ready=False)
        provenance=dict(schema='svs-build-provenance.v1',commit=commit,source_sha256=source_hash,sdk=SDK,input_archives=dict(baseline=BASELINE,peer=PEER),execution='Local' if not in_ci else 'GitLabJob',pipeline_id=os.environ.get('CI_PIPELINE_ID') if in_ci else None,job_id=os.environ.get('CI_JOB_ID') if in_ci else None,source_pin_sha256=sha(ROOT/'eng/session-validation/ci/source-pins.json'))
        a.output.mkdir(parents=True);bundle(ROOT,a.output/'public',summary,provenance,secrets)
        # Scan every raw command/build log too, before deleting private scratch.
        for log in private.rglob('*.log'):scan(log.read_bytes(),secrets)
        print(json.dumps(summary,indent=2))
if __name__=='__main__':
    try:main()
    except Exception as e:
        # No exception text from subprocesses, configs, environment or targets.
        code=str(e) if isinstance(e,Refused) else 'VALIDATION_FAILED'
        print(code,file=sys.stderr);sys.exit(1)
