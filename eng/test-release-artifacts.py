#!/usr/bin/env python3
"""Actual SDK/OCI/runtime/registry qualification in an owned disposable fixture."""
import argparse
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid
from release_identity import ReleaseError, require, run
import release_artifacts as artifacts

ROOT=Path(__file__).resolve().parents[1]
IGNORED={'.git','bin','obj','artifacts','.artifacts','.correction-results','TestResults','__pycache__','node_modules'}

def execute(report_path,fixture_output):
    report=dict(schema_version=1,qualification='NotRun',executed_cases=[],failures=[],cleanup=dict(status='Pending',failures=[]),
                scope='Actual disposable Linux/amd64 candidate and registry proof; hosted permissions/full COR24 flows are separate',
                hosted_qualification='NotRun',required_cases=['stable-native-archive-image-runtime','prerelease-native-archive-image-runtime',
                  'checkout-sha-not-trigger-sha','two-registry-digest-preservation','stable-only-latest','partial-progress-and-retry',
                  'mismatched-version-source-digest-blocked'])
    report_path.parent.mkdir(parents=True,exist_ok=True)
    missing=[name for name in ['docker','skopeo','git'] if not shutil.which(name)]
    if missing:
        report.update(reason='Missing tools: '+', '.join(missing),cleanup=dict(status='NotRequired',failures=[]));artifacts.write(report_path,report);return 2
    containers=[]
    try:
        server=json.loads(run(['docker','info','--format','{{json .}}']).stdout)
        require(server['OSType']=='linux' and server['Architecture'] in ('x86_64','amd64'),'Native fixture requires a Linux/amd64 daemon')
        run(['docker','buildx','version']);require(not fixture_output.exists(),'Native fixture output must be fresh')
        fixture_output.mkdir(parents=True)
        report['qualification']='Running';artifacts.write(report_path,report)
        registry_image=artifacts.resolve_image(os.environ.get('TREEHAMMOCK_RELEASE_REGISTRY_IMAGE','docker.io/library/registry:2'))
        report['registry_input']=registry_image
        with tempfile.TemporaryDirectory(prefix='treehammock-native-release-') as temporary:
            source=Path(temporary)/'source';source.mkdir()
            for path in ROOT.rglob('*'):
                relative=path.relative_to(ROOT)
                if path.is_file() and not IGNORED.intersection(relative.parts):
                    require(not path.is_symlink(),'Linked fixture source');target=source/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,target)
            run(['git','init','-q'],cwd=source);run(['git','add','.'],cwd=source)
            run(['git','-c','user.name=Disposable release fixture','-c','user.email=release@example.invalid','commit','-qm','COR23U qualification source'],cwd=source)
            source_sha=run(['git','rev-parse','HEAD'],cwd=source).stdout.strip()
            report['source_sha']=source_sha;report['trigger_sha_fixture']='0'*40
            manifests={}
            for tag,name in [('v1.1.0','stable'),('v1.1.0-rc.1','prerelease')]:
                folder=fixture_output/name
                manifests[name]=artifacts.build(source,folder,tag,source_sha)
                report['executed_cases'].append(name+'-native-archive-image-runtime')
                require(manifests[name]['identity']['source_sha']==source_sha and source_sha!=report['trigger_sha_fixture'],'Trigger identity leaked into build')
            report['executed_cases'].append('checkout-sha-not-trigger-sha')
            manifest=manifests['stable'];folder=fixture_output/'stable'
            def start_registry(suffix):
                name='treehammock-release-registry-'+str(uuid.uuid4())+'-'+suffix;containers.append(name)
                run(['docker','run','--detach','--name',name,'--publish','127.0.0.1::5000',registry_image])
                port=json.loads(run(['docker','inspect',name]).stdout)[0]['NetworkSettings']['Ports']['5000/tcp'][0]['HostPort']
                return name,'127.0.0.1:'+port
            def environment(host,repository,identity):
                return dict(RELEASE_TAG=identity['tag'],RELEASE_SOURCE_SHA=source_sha,PUSH_LATEST_FOR_STABLE='true',TREEHAMMOCK_RELEASE_ALLOW_LOOPBACK_HTTP='true',
                            SELF_HOSTED_REGISTRY=host,SELF_HOSTED_REGISTRY_IMAGE=host+'/'+repository,SELF_HOSTED_REGISTRY_USERNAME='fixture',SELF_HOSTED_REGISTRY_PASSWORD='fixture',
                            CI_REGISTRY=host,CI_REGISTRY_IMAGE=host+'/'+repository,CI_REGISTRY_USER='fixture',CI_REGISTRY_PASSWORD='fixture')
            def wait_registry(host):
                deadline=time.monotonic()+60
                while time.monotonic()<deadline:
                    response=run(['skopeo','login','--tls-verify=false','--username','fixture','--password-stdin',host],input='fixture\n',optional=True,timeout=5,
                                 env=dict(os.environ,REGISTRY_AUTH_FILE=str(Path(temporary)/'fixture-auth.json')))
                    if response.returncode==0:return
                    time.sleep(1)
                raise ReleaseError('Owned loopback registry did not become ready')
            first,host1=start_registry('one');second,host2=start_registry('two');wait_registry(host1);wait_registry(host2)
            env1=environment(host1,'stable',manifest['identity']);env2=environment(host2,'stable',manifest['identity'])
            one=artifacts.promote(folder,manifest,'generic',folder/'generic-publication.json',env1)
            run(['docker','stop',second])
            try:artifacts.promote(folder,manifest,'gitlab',folder/'gitlab-publication.json',env2)
            except (ReleaseError,OSError,subprocess.SubprocessError):pass
            else:raise ReleaseError('Stopped registry unexpectedly succeeded')
            failed=json.loads((folder/'gitlab-publication.json').read_text())
            summary=artifacts.aggregate(folder,manifest,[one,failed],['generic','gitlab']);require(summary['status']=='Incomplete','Partial publication not preserved')
            artifacts.write(folder/'partial-summary.json',summary)
            run(['docker','start',second]);wait_registry(host2)
            before=artifacts.sha(folder/'candidate.oci.tar')
            two=artifacts.promote(folder,manifest,'gitlab',folder/'gitlab-publication.json',env2)
            retried=artifacts.promote(folder,manifest,'generic',folder/'generic-publication.json',env1)
            require(artifacts.sha(folder/'candidate.oci.tar')==before,'Retry changed candidate bytes')
            summary=artifacts.aggregate(folder,manifest,[retried,two],['generic','gitlab']);require(summary['status']=='Complete','Retry incomplete');artifacts.write(folder/'release-summary.json',summary)
            report['executed_cases']+=['partial-progress-and-retry','two-registry-digest-preservation']
            pre=manifests['prerelease'];pre_folder=fixture_output/'prerelease'
            pre_result=artifacts.promote(pre_folder,pre,'generic',pre_folder/'generic-publication.json',environment(host1,'prerelease',pre['identity']))
            require('latest' in [t['tag'] for t in one['tags']] and 'latest' not in [t['tag'] for t in pre_result['tags']],'Latest policy failed')
            with tempfile.TemporaryDirectory(prefix='treehammock-no-latest-') as auth_folder:
                auth=Path(auth_folder)/'auth.json';auth.write_text('{"auths":{}}');auth.chmod(0o600)
                absent=artifacts.remote_manifest(host1+'/prerelease:latest',auth,optional=True,insecure=True)
                require(absent.returncode!=0 and b'manifest unknown' in absent.stderr.lower(),'Prerelease latest absence not established')
            report['executed_cases'].append('stable-only-latest')
            for variant in ['version','source','digest']:
                changed=copy.deepcopy(manifest);env=dict(env1)
                if variant=='version':env['RELEASE_TAG']='v1.2.0'
                elif variant=='source':env['RELEASE_SOURCE_SHA']='f'*40
                else:changed['tested_digest']='sha256:'+'f'*64
                try:artifacts.promote(folder,changed,'generic',folder/('rejected-'+variant+'.json'),env)
                except ReleaseError:pass
                else:raise ReleaseError('Mismatched candidate unexpectedly promoted')
            report['executed_cases'].append('mismatched-version-source-digest-blocked')
        report['qualification']='Passed'
    except (ReleaseError,OSError,KeyError,ValueError,subprocess.SubprocessError):
        report['qualification']='Failed';report['failures'].append('Native candidate/registry qualification failed; inspect owned fixture evidence')
    finally:
        failures=[]
        for name in reversed(containers):
            try:
                if run(['docker','rm','--force','--volumes',name],optional=True,timeout=60).returncode:failures.append(name)
            except (OSError,subprocess.SubprocessError):failures.append(name)
        report['cleanup']=dict(status='Failed' if failures else 'Passed',failures=failures)
        if failures:report['qualification']='Failed'
        artifacts.write(report_path,report)
    return 0 if report['qualification']=='Passed' else 2

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report',type=Path,default=ROOT/'artifacts/native-release/qualification.json')
    parser.add_argument('--output',type=Path,default=ROOT/'artifacts/native-release/candidates')
    args=parser.parse_args();raise SystemExit(execute(args.report.resolve(),args.output.resolve()))
