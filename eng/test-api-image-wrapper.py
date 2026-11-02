#!/usr/bin/env python3
"""Real PowerShell argv/failure matrix; optional owned real Docker build."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('cor23q_fixture',ROOT/'eng/test-powershell-runners.py')
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
IGNORE=shutil.ignore_patterns('.git','bin','obj','artifacts','.artifacts','.correction-results','TestResults','__pycache__')

def check(condition,message):
    if not condition:raise AssertionError(message)
def matrix(host,sdk,report):
    with tempfile.TemporaryDirectory(prefix='cor23v real PowerShell ') as temporary:
        folder=Path(temporary);root=folder/'checkout with spaces';shutil.copytree(ROOT,root,ignore=IGNORE)
        binary=fixture.prepare_probe(sdk,folder);trace=folder/'trace.jsonl'
        env=dict(os.environ,PATH=str(binary)+os.pathsep+os.environ['PATH'],COR23Q_TRACE=str(trace),COR23Q_FAIL_AT='0',COR23Q_SECOND_FAIL_AT='0')
        env.pop('TREEHAMMOCK_DOTNET_SDK_IMAGE',None);env.pop('TREEHAMMOCK_DOTNET_RUNTIME_IMAGE',None)
        parser="$tokens=$null;$errors=$null;[System.Management.Automation.Language.Parser]::ParseFile("+fixture.quote(root/'eng/docker-api-image.ps1')+",[ref]$tokens,[ref]$errors)>$null;if($errors.Count){exit 1}"
        check(subprocess.run([host,'-NoProfile','-Command',parser],capture_output=True,timeout=30).returncode==0,'Real PowerShell parser rejected wrapper')
        report['cases'].append(dict(case='actual-powershell-parser',status='Passed'))
        for mode in ['File','Command']:
            for configuration in ['Debug','Release','Sandbox']:
                for custom in [False,True]:
                    output='fixture.example.test/team/custom:requested' if custom else 'treehammock:api'
                    args=['-Configuration',configuration,'-Progress','plain']+(['-Image',output,'-NoCache'] if custom else [])
                    for fail_at in [0,1,2,3]:
                        trace.unlink(missing_ok=True);env['COR23Q_FAIL_AT']=str(fail_at)
                        result=fixture.invoke(host,root/'eng/docker-api-image.ps1',args,mode,env,root)
                        calls=fixture.entries(trace)
                        check(result.returncode==(47 if fail_at else 0),'Pull/build exit did not propagate')
                        check(len(calls)==(fail_at or 3),'Work continued after a failed native stage')
                        check(calls[0]['args']==['pull','mcr.microsoft.com/dotnet/sdk:8.0'],'SDK prerequisite differs')
                        if len(calls)>1:check(calls[1]['args']==['pull','mcr.microsoft.com/dotnet/aspnet:8.0'],'Runtime prerequisite differs')
                        if len(calls)>2:
                            build=calls[2]['args'];check(calls[2]['tool']=='docker' and build[0]=='build' and build[-1]=='.','Native build/context differs')
                            check(build[build.index('-t')+1]==output,'Requested output tag was replaced by a base reference')
                            check(build[build.index('--target')+1]=='api' and build[build.index('--progress')+1]=='plain','Target/progress forwarding differs')
                            check('BUILD_CONFIGURATION='+configuration in build and 'TREEHAMMOCK_BUILD_RUN_ID=<fresh-valid-uuid>' in build,'Configuration/build identity differs')
                            check(('--no-cache' in build)==custom,'NoCache forwarding differs')
                        report['cases'].append(dict(case='requested-tag-and-native-result',mode=mode,configuration=configuration,custom=custom,failed_native_stage=fail_at,status='Passed',exit_code=result.returncode))
            env['COR23Q_FAIL_AT']='0'
            for sdk_ref,runtime_ref in [('fixture/sdk:custom','fixture/runtime:custom'),('fixture/sdk@sha256:'+'a'*64,'fixture/runtime@sha256:'+'b'*64)]:
                env.update(TREEHAMMOCK_DOTNET_SDK_IMAGE=sdk_ref,TREEHAMMOCK_DOTNET_RUNTIME_IMAGE=runtime_ref);trace.unlink(missing_ok=True)
                result=fixture.invoke(host,root/'eng/docker-api-image.ps1',['-Image','fixture:override-output','-Progress','tty'],mode,env,root);calls=fixture.entries(trace)
                check(result.returncode==0 and len(calls)==3,'Override case failed')
                check(calls[0]['args']==['pull',sdk_ref] and calls[1]['args']==['pull',runtime_ref],'Override pulls differ')
                check('DOTNET_SDK_IMAGE='+sdk_ref in calls[2]['args'] and 'DOTNET_RUNTIME_IMAGE='+runtime_ref in calls[2]['args'],'Override build inputs differ')
                check(calls[2]['args'][calls[2]['args'].index('-t')+1]=='fixture:override-output','Override changed output tag')
                report['cases'].append(dict(case='tag-or-digest-base-overrides',mode=mode,status='Passed'))
            for output in [sdk_ref,runtime_ref,'   ']:
                trace.unlink(missing_ok=True)
                result=fixture.invoke(host,root/'eng/docker-api-image.ps1',['-Image',output],mode,env,root)
                check(result.returncode!=0 and not fixture.entries(trace),'Known base collision/blank output reached Docker')
                report['cases'].append(dict(case='reject-known-base-collision-or-blank-output',mode=mode,status='Passed'))
            env.pop('TREEHAMMOCK_DOTNET_SDK_IMAGE',None);env.pop('TREEHAMMOCK_DOTNET_RUNTIME_IMAGE',None)
            lock=root/'treehammock.Tests/packages.lock.json';saved=lock.read_bytes();lock.unlink();trace.unlink(missing_ok=True)
            try:
                result=fixture.invoke(host,root/'eng/docker-api-image.ps1',[],mode,env,root)
                check(result.returncode!=0 and not fixture.entries(trace),'Missing lock reached Docker');report['cases'].append(dict(case='missing-lock-before-pulls',mode=mode,status='Passed'))
            finally:lock.write_bytes(saved)

def actual_docker(host,report):
    """Uses only unique output tags; shared base tags are observed, never removed."""
    docker=shutil.which('docker');check(docker,'Actual Docker is required')
    def command(args,optional=False):
        result=subprocess.run([docker,*args],capture_output=True,text=True,timeout=1800)
        check(optional or result.returncode==0,'Actual Docker command failed');return result
    check(json.loads(command(['info','--format','{{json .}}']).stdout)['OSType']=='linux','Actual wrapper build requires Linux Docker containers')
    with tempfile.TemporaryDirectory(prefix='cor23v actual Docker ') as temporary:
        root=Path(temporary)/'source';shutil.copytree(ROOT,root,ignore=IGNORE)
        for script in (root/'eng').glob('*.sh'):script.chmod(script.stat().st_mode | 0o111)
        tags=['mcr.microsoft.com/dotnet/sdk:8.0','mcr.microsoft.com/dotnet/aspnet:8.0']
        for tag in tags:command(['pull',tag])
        before={tag:json.loads(command(['image','inspect',tag]).stdout)[0]['Id'] for tag in tags}
        pins={tag:json.loads(command(['image','inspect',tag]).stdout)[0]['RepoDigests'][0] for tag in tags}
        env=dict(os.environ,TREEHAMMOCK_DOTNET_SDK_IMAGE=pins[tags[0]],TREEHAMMOCK_DOTNET_RUNTIME_IMAGE=pins[tags[1]])
        output='treehammock-cor23v-'+str(uuid.uuid4())+':requested';failed_output='treehammock-cor23v-'+str(uuid.uuid4())+':failed'
        report['docker_resources']=[output,failed_output]
        for tag in [output,failed_output]:check(command(['image','inspect',tag],optional=True).returncode!=0,'Unique output tag unexpectedly exists')
        def invoke_actual(arguments):
            return subprocess.run([host,'-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',str(root/'eng/docker-api-image.ps1'),*arguments],cwd=root,env=env,text=True,capture_output=True,timeout=1800)
        try:
            result=invoke_actual(['-Image',output,'-Configuration','Release','-Progress','plain'])
            check(result.returncode==0,'Actual API wrapper build failed')
            value=json.loads(command(['image','inspect',output]).stdout)[0]
            check(value['Id'] not in before.values() and value['Config']['Entrypoint']==['dotnet','treehammock.dll'],'Output is not the API image')
            check(all(json.loads(command(['image','inspect',tag]).stdout)[0]['Id']==before[tag] for tag in tags),'Shared upstream base tag was overwritten')
            report['docker_cases'].append(dict(case='actual-requested-output-and-upstream-base-preservation',status='Passed',output=output,image_id=value['Id'],base_ids=before,pinned_inputs=pins))
            (root/'Dockerfile').write_text('FROM scratch AS api\nRUN ["cor23v-deliberate-missing-process"]\n')
            result=invoke_actual(['-Image',failed_output,'-Progress','plain'])
            check(result.returncode!=0 and command(['image','inspect',failed_output],optional=True).returncode!=0,'Actual failed build tagged an image')
            check(all(json.loads(command(['image','inspect',tag]).stdout)[0]['Id']==before[tag] for tag in tags),'Failed build overwrote shared base tags')
            report['docker_cases'].append(dict(case='actual-build-failure-with-no-output-tag',status='Passed',exit_code=result.returncode))
        finally:
            # Never delete caller images/base tags or prune global build caches.
            cleanup_failures=[]
            for tag in [failed_output,output]:
                try:
                    if command(['image','inspect',tag],optional=True).returncode==0 and command(['image','rm',tag],optional=True).returncode!=0:cleanup_failures.append(tag)
                except (AssertionError,OSError,subprocess.SubprocessError):cleanup_failures.append(tag)
            report['docker_cleanup']=dict(status='Failed' if cleanup_failures else 'Passed',failures=cleanup_failures)
            check(not cleanup_failures,'Owned output cleanup failed')

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--host',default='pwsh');parser.add_argument('--docker',action='store_true');parser.add_argument('--output',type=Path,default=ROOT/'.correction-results/cor23v-wrapper.json');args=parser.parse_args()
    report=dict(schema_version=1,host=args.host,status='Blocked',qualification='NotRun',cases=[],docker_cases=[],docker_qualification='NotRun')
    host=shutil.which(args.host);sdk=shutil.which('dotnet')
    if not host or not sdk:report['reason']='Selected real PowerShell host and .NET 8 SDK required; no emulation';code=2
    else:
        try:
            matrix(host,sdk,report);report.update(status='Passed',qualification='ActualPowerShellControlledNativeArgv')
            if args.docker:
                actual_docker(host,report);report['docker_qualification']='Passed'
            code=0
        except (AssertionError,OSError,RuntimeError,ValueError,KeyError,subprocess.SubprocessError):report.update(status='Failed',reason='Wrapper native argv or owned Docker qualification failed');code=1
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(dict(status=report['status'],cases=len(report['cases']),docker_cases=len(report['docker_cases']))));return code
if __name__=='__main__':raise SystemExit(main())
