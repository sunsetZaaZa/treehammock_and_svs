#!/usr/bin/env python3
"""Build/test one OCI candidate and promote its exact digest without rebuilding."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from release_identity import canonical, require, run, source_check, ReleaseError

ROOT=Path(__file__).resolve().parents[1]
SHA256=re.compile(r'sha256:[0-9a-f]{64}')

def hash_stream(stream):
    value=hashlib.sha256()
    while chunk:=stream.read(1024*1024):value.update(chunk)
    return value.hexdigest()
def sha(path):
    with path.open('rb') as stream:return hash_stream(stream)
def write(path,value):
    temporary=path.with_name(path.name+'.tmp');temporary.write_text(json.dumps(value,indent=2)+'\n');temporary.replace(path)
def json_result(arguments,**kwargs):return json.loads(run(arguments,**kwargs).stdout)
def safe_file(folder,name):
    require(isinstance(name,str) and PurePosixPath(name).name==name and name not in ('','.','..'), 'Unsafe artifact path')
    path=folder/name;require(path.is_file() and not path.is_symlink(), 'Missing or linked artifact');return path
def digest(value):require(isinstance(value,str) and SHA256.fullmatch(value),'Invalid digest');return value

def oci(path):
    # Validate the actual OCI manifest/config/layer bytes, not a supplied digest.
    with tarfile.open(path,'r:*') as archive:
        members={}
        for member in archive.getmembers():
            name=member.name.removeprefix('./');parts=PurePosixPath(name)
            require(not parts.is_absolute() and '..' not in parts.parts and name not in members,'Unsafe or duplicate OCI member')
            require(member.isdir() or member.isfile(),'Linked/special OCI member');members[name]=member
        def read(name):
            require(name in members and members[name].isfile(),'Missing OCI blob')
            return archive.extractfile(members[name]).read()
        def blob(descriptor):
            value=digest(descriptor['digest']);data=read('blobs/sha256/'+value[7:])
            require(len(data)==descriptor['size'] and hashlib.sha256(data).hexdigest()==value[7:],'OCI blob hash/size mismatch');return data
        require(json.loads(read('oci-layout'))['imageLayoutVersion']=='1.0.0','Unsupported OCI layout')
        index=json.loads(read('index.json'));require(len(index['manifests'])==1,'Release candidate must be one linux/amd64 image')
        descriptor=index['manifests'][0];manifest=json.loads(blob(descriptor))
        require(manifest.get('mediaType')=='application/vnd.oci.image.manifest.v1+json','Candidate must be a single OCI image manifest')
        config=json.loads(blob(manifest['config']))
        require(config['os']=='linux' and config['architecture']=='amd64','Unsupported candidate platform')
        for layer in manifest['layers']:
            value=digest(layer['digest']);member=members.get('blobs/sha256/'+value[7:])
            require(member is not None and member.isfile() and member.size==layer['size'],'OCI layer size mismatch')
            require(hash_stream(archive.extractfile(member))==value[7:],'OCI layer hash mismatch')
        return dict(digest=descriptor['digest'],config_digest=manifest['config']['digest'],config=config)

def inspection(value,identity,run_id,assembly_hash):
    expected=dict(tag=identity['tag'],version=identity['version'],source_sha=identity['source_sha'],build_run_id=run_id,
                  assembly_version=identity['assembly_version'],file_version=identity['assembly_version'],
                  informational_version=identity['informational_version'],configuration='Release',sha256=assembly_hash)
    require(all(value.get(k)==v for k,v in expected.items()),'Actual assembly identity mismatch')
    require(str(uuid.UUID(value['mvid']))==value['mvid'] and uuid.UUID(value['mvid']).int!=0,'Invalid actual module identity')

def check_archive(path,assembly_hash):
    with tarfile.open(path,'r:gz') as archive:
        names=set();app=None
        for member in archive.getmembers():
            name=member.name;parts=PurePosixPath(name)
            require(parts.parts and parts.parts[0]=='treehammock-api' and not parts.is_absolute() and '..' not in parts.parts and name not in names,'Unsafe release archive member')
            require(member.isdir() or member.isfile(),'Linked/special release archive member');names.add(name)
            if name=='treehammock-api/treehammock.dll':app=hashlib.sha256(archive.extractfile(member).read()).hexdigest()
        require(app==assembly_hash and 'treehammock-api/LICENSE' in names,'Archive assembly/license mismatch')

def verify(folder,manifest,expected_tag=None,expected_sha=None):
    require(manifest.get('schema_version')==1 and manifest.get('status')=='Tested','Candidate has not passed actual inspection/runtime probes')
    identity=canonical(manifest['identity']['tag'],manifest['identity']['source_sha'])
    require(manifest['identity']==identity,'Manifest contains inconsistent canonical values')
    if expected_tag is not None:require(identity['tag']==expected_tag,'Expected release tag differs')
    if expected_sha is not None:require(identity['source_sha']==expected_sha,'Expected release source differs')
    run_id=manifest['build_run_id'];require(str(uuid.UUID(run_id))==run_id,'Invalid build invocation')
    candidate=safe_file(folder,manifest['candidate']['file'])
    require(sha(candidate)==manifest['candidate']['sha256'],'OCI archive hash changed')
    info=oci(candidate);require(info['digest']==manifest['candidate']['digest'] and info['config_digest']==manifest['candidate']['config_digest'],'Candidate digest mismatch')
    labels=info['config']['config']['Labels']
    require(labels.get('org.opencontainers.image.version')==identity['version'] and labels.get('org.opencontainers.image.revision')==identity['source_sha'] and labels.get('io.treehammock.build.run-id')==run_id,'OCI labels mismatch')
    archive=safe_file(folder,manifest['archive']['file']);require(sha(archive)==manifest['archive']['sha256'],'Publish archive hash changed')
    package=manifest.get('package_name');require(isinstance(package,str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}',package),'Invalid package identity')
    require(archive.name==package+'-'+identity['tag']+'.tar.gz' and manifest['archive']['checksum_file']==package+'-'+identity['tag']+'.sha256','Release archive filename identity mismatch')
    assembly_hash=manifest['archive']['assembly_sha256'];check_archive(archive,assembly_hash)
    checksum=safe_file(folder,manifest['archive']['checksum_file'])
    require(checksum.read_text()==manifest['archive']['sha256']+'  '+archive.name+'\n','Archive checksum mismatch')
    for name in ['archive-inspection','image-inspection','runtime']:
        record=manifest['tests'][name];path=safe_file(folder,record['file'])
        require(sha(path)==record['sha256'],'Candidate test evidence changed');value=json.loads(path.read_text())
        if name=='runtime':require(value==dict(live=200,ready=200),'Candidate runtime health failed')
        else:inspection(value,identity,run_id,assembly_hash)
    require(manifest['tested_digest']==info['digest'],'Tested/promotion digest mismatch')
    require(set(manifest['resolved_inputs'])=={'sdk','runtime','buildkit','frontend','postgres','cache'},'Resolved input inventory incomplete')
    for value in manifest['resolved_inputs'].values():require('@'+digest(value.rsplit('@',1)[-1]) in value,'Unpinned build/test input')
    require(manifest['cleanup']['status']=='Passed','Owned candidate cleanup failed')
    return identity,info,candidate

def resolve_image(reference):
    require(isinstance(reference,str) and re.fullmatch(r'[a-z0-9][a-z0-9./:_@-]+',reference),'Invalid base image name')
    value=json_result(['skopeo','--override-os','linux','--override-arch','amd64','inspect','docker://'+reference])
    require(value['Os']=='linux' and value['Architecture']=='amd64','Input image platform mismatch')
    resolved=digest(value['Digest']);require('@' not in reference or reference.rsplit('@',1)[-1]==resolved,'Requested base digest mismatch')
    return reference.split('@',1)[0]+'@'+resolved

def wait_dependency(arguments):
    deadline=time.monotonic()+120
    while time.monotonic()<deadline:
        if run(arguments,optional=True,timeout=5).returncode==0:return
        time.sleep(1)
    raise ReleaseError('Owned candidate dependency did not become ready')

def build(root,folder,tag,source_sha):
    identity=canonical(tag,source_sha);source_check(root,source_sha)
    # Source ZIP imports may lose executable bits; content identity remains exact.
    for script in (root/'eng').glob('*.sh'):script.chmod(script.stat().st_mode | 0o111)
    package=os.environ.get('RELEASE_PACKAGE_NAME','treehammock-api');require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}',package),'Invalid package name')
    require(not folder.exists(),'Release output must be fresh; use promotion to retry a tested candidate')
    folder.mkdir(parents=True)
    run_id=str(uuid.uuid4());owner='treehammock-release-'+run_id
    builder=owner;image=owner+':candidate';network=owner;containers=[];volumes=[];network_created=False;builder_created=False;image_loaded=False
    manifest=dict(schema_version=1,status='Building',identity=identity,package_name=package,build_run_id=run_id,configuration='Release',platform='linux/amd64',resolved_inputs={},tests={},cleanup=dict(status='Pending',failures=[]))
    path=folder/'release-manifest.json';write(path,manifest)
    stage='resolve-inputs'
    try:
        names=dict(sdk=('TREEHAMMOCK_DOTNET_SDK_IMAGE','mcr.microsoft.com/dotnet/sdk:8.0'),runtime=('TREEHAMMOCK_DOTNET_RUNTIME_IMAGE','mcr.microsoft.com/dotnet/aspnet:8.0'),
                   buildkit=('TREEHAMMOCK_BUILDKIT_IMAGE','docker.io/moby/buildkit:buildx-stable-1'),frontend=('TREEHAMMOCK_DOCKERFILE_FRONTEND','docker.io/docker/dockerfile:1.7'),
                   postgres=('TREEHAMMOCK_RELEASE_POSTGRES_IMAGE','docker.io/library/postgres:16'),cache=('TREEHAMMOCK_RELEASE_CACHE_IMAGE','docker.dragonflydb.io/dragonflydb/dragonfly:v1.36.0'))
        manifest['resolved_inputs']={key:resolve_image(os.environ.get(env,default)) for key,(env,default) in names.items()};pins=manifest['resolved_inputs'];write(path,manifest)
        manifest['tools']={tool:run(args).stdout.strip() for tool,args in dict(docker=['docker','version','--format','{{.Client.Version}}'],buildx=['docker','buildx','version'],skopeo=['skopeo','--version']).items()}
        stage='candidate-build'
        builder_created=True
        run(['docker','buildx','create','--name',builder,'--driver','docker-container','--driver-opt','image='+pins['buildkit']])
        candidate=folder/'candidate.oci.tar'
        args=['docker','buildx','build','--builder',builder,'--platform','linux/amd64','--provenance=false','--sbom=false','--target','api','--output','type=oci,dest='+str(candidate)]
        for key,value in dict(DOTNET_SDK_IMAGE=pins['sdk'],DOTNET_RUNTIME_IMAGE=pins['runtime'],BUILDKIT_SYNTAX=pins['frontend'],BUILD_CONFIGURATION='Release',TREEHAMMOCK_BUILD_RUN_ID=run_id,
                              TREEHAMMOCK_RELEASE_TAG=tag,TREEHAMMOCK_RELEASE_VERSION=identity['version'],TREEHAMMOCK_RELEASE_BASE_VERSION=identity['base_version'],TREEHAMMOCK_RELEASE_SOURCE_SHA=source_sha).items():args+=['--build-arg',key+'='+value]
        run(args+[str(root)],timeout=1800)
        info=oci(candidate)
        manifest['candidate']=dict(file=candidate.name,sha256=sha(candidate),digest=info['digest'],config_digest=info['config_digest']);write(path,manifest)
        stage='load-candidate'
        # Docker may rewrite the transport manifest. The immutable config/diffIDs
        # are checked; promotion always uses the original OCI manifest bytes.
        image_loaded=True
        run(['skopeo','copy','oci-archive:'+str(candidate),'docker-daemon:'+image])
        loaded=json_result(['docker','image','inspect',image])[0]
        require(loaded['Id']==info['config_digest'] and loaded['RootFS']['Layers']==info['config']['rootfs']['diff_ids'],'Loaded candidate content differs from OCI image')
        require(loaded['Config']['Labels']==info['config']['config']['Labels'],'Loaded labels differ')
        stage='extract-exact-publish'
        extract=owner+'-extract';containers.append(extract);run(['docker','create','--name',extract,info['config_digest']])
        publish=folder/'treehammock-api';publish.mkdir();run(['docker','cp',extract+':/app/.',str(publish)])
        require(all(p.is_file() or p.is_dir() for p in publish.rglob('*')) and not any(p.is_symlink() for p in publish.rglob('*')),'Linked/special publish payload')
        assembly=publish/'treehammock.dll';require(assembly.is_file(),'Missing application assembly');assembly_hash=sha(assembly)
        archive=folder/(package+'-'+tag+'.tar.gz')
        with tarfile.open(archive,'w:gz',dereference=False) as output:output.add(publish,arcname='treehammock-api')
        check_archive(archive,assembly_hash);checksum=folder/(package+'-'+tag+'.sha256');checksum.write_text(sha(archive)+'  '+archive.name+'\n')
        manifest['archive']=dict(file=archive.name,sha256=sha(archive),assembly_sha256=assembly_hash,checksum_file=checksum.name)
        stage='compile-inspector'
        sdk=owner+'-inspector';containers.append(sdk)
        run(['docker','create','--name',sdk,'--network','none',pins['sdk'],'sleep','infinity']);run(['docker','start',sdk])
        run(['docker','cp',str(root/'eng/ReleaseArtifactProbe')+'/.',sdk+':/src'])
        run(['docker','exec',sdk,'dotnet','publish','/src/ReleaseArtifactProbe.csproj','--configuration','Release','--output','/probe','-p:RestoreSources=','-p:RestoreIgnoreFailedSources=true'],timeout=300)
        probe=folder/'probe';probe.mkdir();run(['docker','cp',sdk+':/probe/.',str(probe)])
        probe_volume=owner+'-probe';volumes.append(probe_volume);run(['docker','volume','create',probe_volume])
        importer=owner+'-probe-import';containers.append(importer)
        run(['docker','create','--name',importer,'--mount','type=volume,src='+probe_volume+',dst=/probe',pins['sdk'],'true'])
        run(['docker','cp',str(probe)+'/.',importer+':/probe'])
        parameters=[tag,identity['version'],identity['assembly_version'],source_sha,run_id,identity['informational_version']]
        stage='inspect-archive-and-image'
        run(['docker','cp',str(assembly),sdk+':/input.dll'])
        archive_report=json_result(['docker','exec',sdk,'dotnet','/probe/ReleaseArtifactProbe.dll','/input.dll',*parameters])
        image_probe=owner+'-image-probe';containers.append(image_probe)
        image_report=json_result(['docker','run','--name',image_probe,'--network','none','--read-only','--mount','type=volume,src='+probe_volume+',dst=/probe,readonly','--entrypoint','dotnet',info['config_digest'],
                                  '/probe/ReleaseArtifactProbe.dll','/app/treehammock.dll',*parameters])
        for name,value in [('archive-inspection',archive_report),('image-inspection',image_report)]:
            inspection(value,identity,run_id,assembly_hash);record=folder/(name+'.json');write(record,value);manifest['tests'][name]=dict(file=record.name,sha256=sha(record))
        stage='owned-candidate-runtime'
        network_created=True;run(['docker','network','create','--internal',network])
        password=base64.urlsafe_b64encode(os.urandom(24)).decode();cache_password=os.urandom(32).hex();key=base64.b64encode(os.urandom(32)).decode()
        pg=owner+'-postgres';cache=owner+'-cache';api=owner+'-api'
        containers.append(pg)
        run(['docker','create','--name',pg,'--network',network,'--network-alias','postgres','--env','POSTGRES_DB','--env','POSTGRES_USER','--env','POSTGRES_PASSWORD',pins['postgres']],
            env=dict(os.environ,POSTGRES_DB='treehammock',POSTGRES_USER='treehammock',POSTGRES_PASSWORD=password))
        run(['docker','cp',str(root/'Rigging/Database/Baseline/000_treehammock_canonical_database.sql'),pg+':/docker-entrypoint-initdb.d/setup.sql']);run(['docker','start',pg])
        containers.append(cache);run(['docker','run','--detach','--name',cache,'--network',network,'--network-alias','dragonfly',pins['cache'],'dragonfly','--bind','0.0.0.0','--requirepass',cache_password])
        wait_dependency(['docker','exec',pg,'pg_isready','-h','127.0.0.1','-U','treehammock','-d','treehammock'])
        wait_dependency(['docker','exec','--env','REDISCLI_AUTH='+cache_password,cache,'redis-cli','ping'])
        import yaml
        environment=yaml.safe_load((root/'docker-compose.integration.yml').read_text())['services']['api']['environment']
        # Resolve fixture defaults, replace all durable proof keys/passwords, and
        # retain Container production capability policy (no test route enablement).
        environment={k:re.sub(r'\$\{[^}:]+:-([^}]+)\}',r'\1',str(value)) for k,value in environment.items()}
        environment.update(ActiveUserBundleSettings__password=cache_password,TwoFactorSessionBundleSettings__password=cache_password,AbuseCounterBundleSettings__password=cache_password,DatabaseSettings__password=password,DeliveryOutboxSettings__EncryptionKeys__1=key,SecurityOperationSettings__HmacKeys__1=key,
                           SystemTestSettings__Enabled='false',SystemTestSettings__EnableTestInspectionEndpoints='false',SystemTestSettings__TestKey='')
        # Credentials travel via process environment, never CLI argument values.
        env_args=[];child=dict(os.environ)
        for name,value in environment.items():env_args+=['--env',name];child[name]=value
        containers.append(api)
        run(['docker','run','--detach','--read-only','--tmpfs','/tmp','--name',api,'--network',network,'--mount','type=volume,src='+probe_volume+',dst=/probe,readonly',*env_args,info['config_digest']],env=child,timeout=30)
        runtime=json_result(['docker','exec',api,'dotnet','/probe/ReleaseArtifactProbe.dll','--http','http://127.0.0.1:5001'],timeout=150)
        require(runtime==dict(live=200,ready=200),'Candidate runtime readiness failed')
        record=folder/'runtime.json';write(record,runtime);manifest['tests']['runtime']=dict(file=record.name,sha256=sha(record));manifest['tested_digest']=info['digest'];manifest['status']='Tested'
    except (ReleaseError,OSError,KeyError,ValueError,subprocess.SubprocessError,tarfile.TarError):
        manifest['status']='Failed';manifest['failed_stage']=stage;raise
    finally:
        failures=[]
        def cleanup(arguments,name):
            try:
                if run(arguments,optional=True,timeout=60).returncode:failures.append(name)
            except (OSError,subprocess.SubprocessError):failures.append(name)
        for name in reversed(containers):
            cleanup(['docker','rm','--force','--volumes',name],name)
        for name in reversed(volumes):cleanup(['docker','volume','rm',name],name)
        if network_created:cleanup(['docker','network','rm',network],network)
        if image_loaded:cleanup(['docker','image','rm',image],image)
        if builder_created:cleanup(['docker','buildx','rm',builder],builder)
        manifest['cleanup']=dict(status='Failed' if failures else 'Passed',failures=failures)
        if failures and manifest['status']=='Tested':manifest['status']='Failed';manifest['failed_stage']='owned-cleanup'
        write(path,manifest)
    verify(folder,manifest,tag,source_sha)
    return manifest

def registry(kind,environment):
    def need(name):value=environment.get(name,'');require(bool(value),'Missing registry setting: '+name);return value
    if kind=='gitlab':return need('CI_REGISTRY'),need('CI_REGISTRY_IMAGE'),need('CI_REGISTRY_USER'),need('CI_REGISTRY_PASSWORD')
    if kind=='generic':return need('SELF_HOSTED_REGISTRY'),need('SELF_HOSTED_REGISTRY_IMAGE'),need('SELF_HOSTED_REGISTRY_USERNAME'),need('SELF_HOSTED_REGISTRY_PASSWORD')
    if kind=='dockerhub':return 'docker.io',need('DOCKERHUB_IMAGE'),need('DOCKERHUB_USERNAME'),need('DOCKERHUB_TOKEN')
    if kind=='github':return environment.get('GITHUB_CONTAINER_REGISTRY','ghcr.io'),need('GITHUB_CONTAINER_IMAGE'),need('GITHUB_ACTOR'),need('GITHUB_TOKEN')
    require(kind=='aws-ecr','Unsupported registry kind')
    region=need('AWS_REGION');account=need('AWS_ACCOUNT_ID');require(re.fullmatch(r'[0-9]{12}',account),'Invalid AWS account')
    host=account+'.dkr.ecr.'+region+'.amazonaws.com'
    image=environment.get('AWS_ECR_IMAGE') or host+'/'+need('AWS_ECR_REPOSITORY')
    password=run(['aws','ecr','get-login-password','--region',region]).stdout.strip();require(password,'Empty ECR password');return host,image,'AWS',password

def remote_manifest(reference,auth,optional=False,insecure=False):
    result=subprocess.run(['skopeo','inspect','--authfile',str(auth),*(['--tls-verify=false'] if insecure else []),'--raw','docker://'+reference],capture_output=True,timeout=120)
    if result.returncode and not optional:raise ReleaseError('Registry manifest lookup failed')
    return result

def promote(folder,manifest,kind,report_path,environment):
    require(environment.get('RELEASE_TAG') and environment.get('RELEASE_SOURCE_SHA'),'Promotion requires preflight identity')
    expected=canonical(environment['RELEASE_TAG'],environment['RELEASE_SOURCE_SHA'])
    report=dict(schema_version=1,registry=kind,status='Failed',source_sha=expected['source_sha'],release_tag=expected['tag'],build_run_id=manifest.get('build_run_id'),tested_digest=manifest.get('tested_digest'),tags=[])
    write(report_path,report)
    identity,info,candidate=verify(folder,manifest,expected['tag'],expected['source_sha'])
    require(environment.get('PUSH_LATEST_FOR_STABLE','true') in ('true','false'),'Invalid stable latest flag')
    report=dict(schema_version=1,registry=kind,status='Pending',source_sha=identity['source_sha'],release_tag=identity['tag'],build_run_id=manifest['build_run_id'],tested_digest=info['digest'],tags=[])
    write(report_path,report)
    try:
        host,image,user,password=registry(kind,environment)
        require(re.fullmatch(r'[a-z0-9][a-z0-9.:-]*',host) and re.fullmatch(r'[a-z0-9][a-z0-9./:_-]*',image) and '@' not in image,'Invalid registry destination')
        require(image.startswith(host+'/') or (host=='docker.io' and ':' not in image),'Registry/image mismatch')
        repository=image[len(host)+1:] if image.startswith(host+'/') else image
        require(re.fullmatch(r'[a-z0-9][a-z0-9._/-]*',repository),'Destination must be an untagged repository')
        allow=environment.get('TREEHAMMOCK_RELEASE_ALLOW_LOOPBACK_HTTP','false');require(allow in ('true','false'),'Invalid loopback registry opt-in')
        insecure=allow=='true';require(not insecure or re.fullmatch(r'127\.0\.0\.1:[0-9]+',host),'Plain HTTP is allowed only for explicit loopback fixtures')
        tags=[identity['tag'],identity['source_sha']]
        if not identity['is_prerelease'] and environment.get('PUSH_LATEST_FOR_STABLE','true')=='true':tags.append('latest')
        report['tags']=[dict(tag=tag,status='Pending') for tag in tags];report['image']=image;report['push_latest_for_stable']=environment.get('PUSH_LATEST_FOR_STABLE','true')=='true';write(report_path,report)
        with tempfile.TemporaryDirectory(prefix='treehammock-registry-auth-') as private:
            auth=Path(private)/'auth.json';auth.write_text('{"auths":{}}');auth.chmod(0o600)
            run(['skopeo','login','--authfile',str(auth),*(['--tls-verify=false'] if insecure else []),'--username',user,'--password-stdin',host],input=password+'\n')
            for record in report['tags']:
                reference=image+':'+record['tag'];record['status']='Checking';write(report_path,report)
                existing=remote_manifest(reference,auth,optional=True,insecure=insecure)
                if existing.returncode==0:
                    current='sha256:'+hashlib.sha256(existing.stdout).hexdigest()
                    if current==info['digest']:record.update(status='Verified',digest=current);write(report_path,report);continue
                    require(record['tag']=='latest','Existing immutable release/SHA tag points to other bytes')
                else:
                    require(any(code in existing.stderr.lower() for code in [b'manifest unknown',b'name unknown']),'Registry lookup failed; absence not established')
                record['status']='Copying';write(report_path,report)
                run(['skopeo','copy','--authfile',str(auth),*(['--dest-tls-verify=false'] if insecure else []),'--preserve-digests','oci-archive:'+str(candidate),'docker://'+reference],timeout=600)
                actual=remote_manifest(reference,auth,insecure=insecure).stdout
                copied='sha256:'+hashlib.sha256(actual).hexdigest();require(copied==info['digest'],'Registry changed candidate manifest digest')
                record.update(status='Verified',digest=copied);write(report_path,report)
        report['status']='Succeeded';write(report_path,report);return report
    except (ReleaseError,OSError,KeyError,ValueError,subprocess.SubprocessError):
        for record in report['tags']:
            if record['status'] in ('Checking','Copying'):record['status']='FailedOrUnknownOutcome'
        report['status']='Failed';write(report_path,report);raise

def aggregate(folder,manifest,reports,enabled):
    identity,info,_=verify(folder,manifest)
    result=dict(schema_version=1,identity=identity,build_run_id=manifest['build_run_id'],tested_digest=info['digest'],archive=manifest['archive'],registries={})
    for kind in enabled:
        values=[r for r in reports if r.get('registry')==kind]
        if len(values)!=1:result['registries'][kind]=dict(status='MissingOrAmbiguous');continue
        report=values[0]
        require(report['source_sha']==identity['source_sha'] and report['release_tag']==identity['tag'] and report['tested_digest']==info['digest'] and report['build_run_id']==manifest['build_run_id'],'Publication report belongs to another candidate')
        if report['status']=='Succeeded':require(report['tags'] and all(t['status']=='Verified' and t['digest']==info['digest'] for t in report['tags']),'Successful registry has unverified tags')
        if report['status']=='Succeeded':
            required={identity['tag'],identity['source_sha']}
            if report.get('push_latest_for_stable') is True and not identity['is_prerelease']:required.add('latest')
            require({t['tag'] for t in report['tags']}==required and len(report['tags'])==len(required),'Registry tag outcomes incomplete or noncanonical')
        result['registries'][kind]=report
    result['status']='Complete' if all(r['status']=='Succeeded' for r in result['registries'].values()) else 'Incomplete'
    return result

def ci_summary(provider):
    folder=ROOT/'artifacts/release'
    if provider=='github':
        require(os.environ.get('PUBLISH_GHCR') in ('true','false'),'Invalid GitHub image selection')
        enabled=['github'] if os.environ['PUBLISH_GHCR']=='true' else []
        paths=list((ROOT/'image-outcome').rglob('github-publication.json'))
    else:
        enabled=[]
        for kind,flag in [('gitlab','PUBLISH_GITLAB_REGISTRY'),('generic','PUBLISH_SELF_HOSTED_REGISTRY'),('dockerhub','PUBLISH_DOCKERHUB'),('aws-ecr','PUBLISH_AWS_ECR')]:
            value=os.environ.get(flag,'false');require(value in ('true','false'),'Invalid GitLab image selection')
            if value=='true':enabled.append(kind)
        paths=list(folder.glob('*-publication.json'))
    expected=canonical(os.environ.get('RELEASE_TAG',''),os.environ.get('RELEASE_SOURCE_SHA',''))
    try:
        manifest=json.loads((folder/'release-manifest.json').read_text())
        verify(folder,manifest,expected['tag'],expected['source_sha'])
    except (ReleaseError,OSError,KeyError,ValueError,tarfile.TarError):
        folder.mkdir(parents=True,exist_ok=True)
        write(folder/'release-summary.json',dict(schema_version=1,status='CandidateInvalidOrFailed',identity=expected,registries={kind:dict(status='BlockedNoTestedCandidate') for kind in enabled}))
        raise
    try:
        report=aggregate(folder,manifest,[json.loads(p.read_text()) for p in paths],enabled)
    except (ReleaseError,OSError,KeyError,ValueError):
        # A failed optional image job cannot hide evidence or veto source release.
        # Enabled GitLab targets still block publication below.
        report=dict(schema_version=1,status='Incomplete',identity=expected,build_run_id=manifest['build_run_id'],
                    tested_digest=manifest['tested_digest'],archive=manifest['archive'],
                    registries={kind:dict(status='InvalidPublicationEvidence') for kind in enabled},
                    publication_evidence=[dict(file=p.name,sha256=sha(p)) for p in paths if p.is_file()])
    if provider=='github' and enabled:
        report['hosted_image_job_result']=os.environ.get('GHCR_RESULT','unknown')
        if report['hosted_image_job_result']!='success':report['status']='Incomplete'
    write(folder/'release-summary.json',report)
    # Optional GHCR does not block GitHub source publication. Enabled GitLab
    # registry failures continue to block the release and remain visible.
    if provider=='gitlab':require(report['status']=='Complete','Enabled registry publication incomplete')

def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='operation',required=True)
    b=sub.add_parser('build');b.add_argument('--output',type=Path,default=ROOT/'artifacts/release')
    sub.add_parser('github-summary');sub.add_parser('gitlab-summary')
    for name in ['verify','promote','aggregate']:
        p=sub.add_parser(name);p.add_argument('--manifest',type=Path,default=ROOT/'artifacts/release/release-manifest.json')
        if name=='promote':p.add_argument('--registry',choices=['gitlab','generic','dockerhub','aws-ecr','github'],required=True);p.add_argument('--report',type=Path,required=True);p.add_argument('--env-file',type=Path)
        if name=='aggregate':p.add_argument('--reports',type=Path,nargs='*',default=[]);p.add_argument('--enabled',nargs='*',default=[]);p.add_argument('--report',type=Path,required=True)
    args=parser.parse_args()
    try:
        if args.operation=='build':build(ROOT,args.output.resolve(),os.environ.get('RELEASE_TAG',''),os.environ.get('RELEASE_SOURCE_SHA',''))
        elif args.operation.endswith('-summary'):ci_summary(args.operation.split('-')[0])
        else:
            manifest=json.loads(args.manifest.read_text());folder=args.manifest.resolve().parent
            if args.operation=='verify':verify(folder,manifest,os.environ.get('RELEASE_TAG'),os.environ.get('RELEASE_SOURCE_SHA'))
            if args.operation=='promote':
                report=promote(folder,manifest,args.registry,args.report,os.environ)
                if args.env_file:args.env_file.write_text('PUBLISHED_IMAGE='+report['image']+':'+report['release_tag']+'\nPUBLISHED_IMAGE_DIGEST='+report['tested_digest']+'\nPUBLISHED_IMAGE_SHA_TAG='+report['image']+':'+report['source_sha']+'\n')
            if args.operation=='aggregate':
                reports=[json.loads(p.read_text()) for p in args.reports if p.is_file()]
                report=aggregate(folder,manifest,reports,args.enabled);write(args.report,report)
                require(report['status']=='Complete','Enabled registry outcomes incomplete')
        return 0
    except (ReleaseError,OSError,KeyError,ValueError,subprocess.SubprocessError,tarfile.TarError):
        print('Release artifact identity, candidate proof or promotion failed.',file=sys.stderr);return 2

if __name__=='__main__':raise SystemExit(main())
