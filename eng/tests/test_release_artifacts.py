"""Synthetic OCI/PE reports and controlled promotion; never native qualification."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import uuid
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'eng'))
import release_artifacts as artifacts
import release_identity as identity
import test_release_input_boundary as boundary

spec=importlib.util.spec_from_file_location('release_artifact_guard',ROOT/'eng/check-release-artifact-identity.py')
guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard)

def encode(value):return json.dumps(value,separators=(',',':')).encode()
def hash_bytes(value):return hashlib.sha256(value).hexdigest()
def result(stdout='',stderr='',code=0):return subprocess.CompletedProcess([],code,stdout,stderr)

def candidate(folder,tag='v1.1.0',sha='a'*40,run_id=None):
    folder.mkdir(parents=True,exist_ok=True);run_id=run_id or str(uuid.uuid4());values=identity.canonical(tag,sha)
    layer=b'SYNTHETIC OCI LAYER - NOT A RUNTIME IMAGE'
    config=encode(dict(os='linux',architecture='amd64',config=dict(Labels={'org.opencontainers.image.version':values['version'],'org.opencontainers.image.revision':sha,'io.treehammock.build.run-id':run_id}),rootfs=dict(diff_ids=['sha256:'+hash_bytes(layer)])))
    descriptor=lambda data:dict(digest='sha256:'+hash_bytes(data),size=len(data))
    image=encode(dict(mediaType='application/vnd.oci.image.manifest.v1+json',config=descriptor(config),layers=[descriptor(layer)]))
    files={'oci-layout':encode(dict(imageLayoutVersion='1.0.0')),'index.json':encode(dict(manifests=[descriptor(image)])),
           'blobs/sha256/'+hash_bytes(image):image,'blobs/sha256/'+hash_bytes(config):config,'blobs/sha256/'+hash_bytes(layer):layer}
    oci=folder/'candidate.oci.tar'
    with tarfile.open(oci,'w') as output:
        for name,data in files.items():member=tarfile.TarInfo(name);member.size=len(data);output.addfile(member,io.BytesIO(data))
    publish=folder/'treehammock-api';publish.mkdir(exist_ok=True);(publish/'treehammock.dll').write_bytes(b'SYNTHETIC PE - NOT AN ASSEMBLY');(publish/'LICENSE').write_text('fixture')
    archive=folder/('treehammock-api-'+tag+'.tar.gz')
    with tarfile.open(archive,'w:gz') as output:output.add(publish,arcname='treehammock-api')
    checksum=folder/('treehammock-api-'+tag+'.sha256');checksum.write_text(artifacts.sha(archive)+'  '+archive.name+'\n')
    report=dict(tag=tag,version=values['version'],source_sha=sha,build_run_id=run_id,assembly_version=values['assembly_version'],file_version=values['assembly_version'],
                informational_version=values['informational_version'],configuration='Release',sha256=artifacts.sha(publish/'treehammock.dll'),mvid=str(uuid.uuid4()))
    manifest=dict(schema_version=1,status='Tested',identity=values,package_name='treehammock-api',build_run_id=run_id,
                  candidate=dict(file=oci.name,sha256=artifacts.sha(oci),digest='sha256:'+hash_bytes(image),config_digest='sha256:'+hash_bytes(config)),
                  archive=dict(file=archive.name,sha256=artifacts.sha(archive),assembly_sha256=report['sha256'],checksum_file=checksum.name),tests={},
                  tested_digest='sha256:'+hash_bytes(image),resolved_inputs={name:'example.test/'+name+'@sha256:'+'b'*64 for name in ['sdk','runtime','buildkit','frontend','postgres','cache']},cleanup=dict(status='Passed',failures=[]))
    for name,value in [('archive-inspection',report),('image-inspection',report),('runtime',dict(live=200,ready=200))]:
        file=folder/(name+'.json');artifacts.write(file,value);manifest['tests'][name]=dict(file=file.name,sha256=artifacts.sha(file))
    artifacts.write(folder/'release-manifest.json',manifest)
    return manifest,image

class ArtifactValidationTests(unittest.TestCase):
    def setUp(self):self.temp=tempfile.TemporaryDirectory();self.folder=Path(self.temp.name);self.manifest,self.raw=candidate(self.folder)
    def tearDown(self):self.temp.cleanup()
    def reject(self,mutate):
        mutate()
        with self.assertRaises((identity.ReleaseError,ValueError,KeyError,tarfile.TarError)):artifacts.verify(self.folder,self.manifest)
    def test_source_archive_image_and_tested_digest_share_version_and_commit(self):
        values,info,path=artifacts.verify(self.folder,self.manifest,'v1.1.0','a'*40)
        self.assertEqual(info['digest'],self.manifest['tested_digest']);self.assertEqual(values['informational_version'],'1.1.0+sha.'+'a'*40)
    def test_mismatched_sha_version_or_digest_blocks_release(self):
        for tag,sha in [('v1.2.0','a'*40),('v1.1.0','c'*40)]:
            with self.subTest(tag=tag,sha=sha),self.assertRaises(identity.ReleaseError):artifacts.verify(self.folder,self.manifest,tag,sha)
    def test_unexecuted_candidate_rejected(self):self.reject(lambda:self.manifest.update(status='Built'))
    def test_candidate_archive_tamper_rejected(self):self.reject(lambda:(self.folder/'candidate.oci.tar').write_bytes(b'changed'))
    def test_tested_digest_mismatch_rejected(self):self.reject(lambda:self.manifest.update(tested_digest='sha256:'+'c'*64))
    def test_config_digest_mismatch_rejected(self):self.reject(lambda:self.manifest['candidate'].update(config_digest='sha256:'+'c'*64))
    def test_assembly_hash_mismatch_rejected(self):self.reject(lambda:self.manifest['archive'].update(assembly_sha256='c'*64))
    def test_archive_hash_mismatch_rejected(self):self.reject(lambda:self.manifest['archive'].update(sha256='c'*64))
    def test_checksum_mismatch_rejected(self):self.reject(lambda:(self.folder/self.manifest['archive']['checksum_file']).write_text('fake\n'))
    def test_test_evidence_hash_mismatch_rejected(self):self.reject(lambda:(self.folder/'runtime.json').write_text('{}'))
    def test_unpinned_base_rejected(self):self.reject(lambda:self.manifest['resolved_inputs'].update(sdk='example.test/sdk:latest'))
    def test_missing_input_record_rejected(self):self.reject(lambda:self.manifest['resolved_inputs'].pop('frontend'))
    def test_owned_cleanup_failure_rejected(self):self.reject(lambda:self.manifest['cleanup'].update(status='Failed'))
    def test_path_traversal_rejected(self):self.reject(lambda:self.manifest['candidate'].update(file='../candidate.oci.tar'))
    def test_linked_proof_rejected(self):
        external=self.folder/'external';external.write_text((self.folder/'runtime.json').read_text());(self.folder/'runtime.json').unlink();(self.folder/'runtime.json').symlink_to(external)
        self.reject(lambda:None)
    def test_forged_runtime_success_missing_readiness_rejected(self):
        file=self.folder/'runtime.json';artifacts.write(file,dict(live=200,ready=503));self.manifest['tests']['runtime']['sha256']=artifacts.sha(file);self.reject(lambda:None)
    def test_wrong_actual_assembly_version_even_rehashed_report_rejected(self):
        file=self.folder/'image-inspection.json';value=json.loads(file.read_text());value['assembly_version']='1.0.0.0';artifacts.write(file,value);self.manifest['tests']['image-inspection']['sha256']=artifacts.sha(file);self.reject(lambda:None)
    def test_zero_actual_module_id_rejected(self):
        file=self.folder/'image-inspection.json';value=json.loads(file.read_text());value['mvid']=str(uuid.UUID(int=0));artifacts.write(file,value);self.manifest['tests']['image-inspection']['sha256']=artifacts.sha(file);self.reject(lambda:None)
    def test_unsafe_archive_members_rejected(self):
        for name,link in [('../escape',False),('treehammock-api/link',True)]:
            with self.subTest(name=name):
                path=self.folder/'bad.tar.gz'
                with tarfile.open(path,'w:gz') as output:
                    member=tarfile.TarInfo(name)
                    if link:member.type=tarfile.SYMTYPE;member.linkname='/etc/passwd'
                    output.addfile(member)
                with self.assertRaises(identity.ReleaseError):artifacts.check_archive(path,self.manifest['archive']['assembly_sha256'])
    def test_oci_layer_bytes_are_independently_hashed(self):
        path=self.folder/'bad.oci.tar'
        with tarfile.open(self.folder/'candidate.oci.tar') as source,tarfile.open(path,'w') as output:
            for member in source.getmembers():
                data=source.extractfile(member).read()
                if data.startswith(b'SYNTHETIC OCI'):data=b'x'*len(data)
                output.addfile(member,io.BytesIO(data))
        with self.assertRaises(identity.ReleaseError):artifacts.oci(path)

class PromotionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.folder=Path(self.temp.name);self.manifest,self.raw=candidate(self.folder);self.calls=[];self.remote={};self.fail_tag=None
        self.env=dict(RELEASE_TAG='v1.1.0',RELEASE_SOURCE_SHA='a'*40,SELF_HOSTED_REGISTRY='registry.example.test',SELF_HOSTED_REGISTRY_IMAGE='registry.example.test/team/api',SELF_HOSTED_REGISTRY_USERNAME='fixture',SELF_HOSTED_REGISTRY_PASSWORD='private-fixture-password')
    def tearDown(self):self.temp.cleanup()
    def command(self,args,**kwargs):
        self.calls.append(args)
        if 'copy' in args:
            self.assertIn('--preserve-digests',args);self.assertTrue(any(a.startswith('oci-archive:') for a in args));tag=args[-1].rsplit(':',1)[-1]
            if tag==self.fail_tag:raise identity.ReleaseError('Injected copy failure')
            self.remote[args[-1][len('docker://'):]]=self.raw
        return result()
    def inspect(self,reference,auth,optional=False,**kwargs):
        self.calls.append(['inspect',reference]);self.assertTrue(auth.exists())
        return result(self.remote[reference],b'',0) if reference in self.remote else result(b'',b'manifest unknown',1)
    def promote(self,**changes):
        with patch.object(artifacts,'run',side_effect=self.command),patch.object(artifacts,'remote_manifest',side_effect=self.inspect):
            return artifacts.promote(self.folder,self.manifest,'generic',self.folder/'generic-publication.json',dict(self.env,**changes))
    def test_exact_candidate_digest_is_copied_without_build(self):
        report=self.promote();self.assertEqual(report['status'],'Succeeded');self.assertEqual(len([c for c in self.calls if 'copy' in c]),3)
        self.assertTrue(all(t['digest']==self.manifest['tested_digest'] for t in report['tags']));self.assertFalse(any('build' in c for c in self.calls))
        self.assertFalse(any('private-fixture-password' in str(c) for c in self.calls))
    def test_prerelease_never_moves_latest(self):
        shutil.rmtree(self.folder);self.manifest,self.raw=candidate(self.folder,'v1.1.0-rc.1');self.env['RELEASE_TAG']='v1.1.0-rc.1'
        report=self.promote();self.assertEqual([t['tag'] for t in report['tags']],['v1.1.0-rc.1','a'*40])
    def test_explicit_stable_latest_false_is_preserved(self):self.assertEqual(len(self.promote(PUSH_LATEST_FOR_STABLE='false')['tags']),2)
    def test_partial_failure_records_verified_and_unknown_outcomes(self):
        self.fail_tag='a'*40
        with self.assertRaises(identity.ReleaseError):self.promote()
        report=json.loads((self.folder/'generic-publication.json').read_text());self.assertEqual(report['status'],'Failed')
        self.assertEqual([t['status'] for t in report['tags']],['Verified','FailedOrUnknownOutcome','Pending'])
    def test_retry_reuses_verified_candidate_and_skips_completed_tag(self):
        self.fail_tag='a'*40
        with self.assertRaises(identity.ReleaseError):self.promote()
        self.calls=[];self.fail_tag=None;report=self.promote()
        self.assertEqual(report['status'],'Succeeded');self.assertEqual(len([c for c in self.calls if 'copy' in c]),2)
    def test_existing_immutable_tag_with_other_bytes_blocks(self):
        self.remote[self.env['SELF_HOSTED_REGISTRY_IMAGE']+':v1.1.0']=b'other bytes'
        with self.assertRaises(identity.ReleaseError):self.promote()
        self.assertFalse(any('copy' in c for c in self.calls))
    def test_registry_digest_conversion_is_rejected(self):
        def wrong(reference,auth,optional=False,**kwargs):
            return result(b'converted',b'',0) if reference in self.remote else result(b'',b'manifest unknown',1)
        with patch.object(artifacts,'run',side_effect=self.command),patch.object(artifacts,'remote_manifest',side_effect=wrong),self.assertRaises(identity.ReleaseError):
            artifacts.promote(self.folder,self.manifest,'generic',self.folder/'generic-publication.json',self.env)
    def test_registry_permission_error_is_not_missing_tag(self):
        with patch.object(artifacts,'run',side_effect=self.command),patch.object(artifacts,'remote_manifest',return_value=result(b'',b'unauthorized',1)),self.assertRaises(identity.ReleaseError):
            artifacts.promote(self.folder,self.manifest,'generic',self.folder/'generic-publication.json',self.env)
        self.assertFalse(any('copy' in c for c in self.calls))
    def test_mismatched_preflight_blocks_before_authentication(self):
        with self.assertRaises(identity.ReleaseError):self.promote(RELEASE_SOURCE_SHA='c'*40)
        self.assertEqual(self.calls,[]);self.assertEqual(json.loads((self.folder/'generic-publication.json').read_text())['status'],'Failed')
    def test_insecure_remote_registry_opt_in_rejected(self):
        with self.assertRaises(identity.ReleaseError):self.promote(TREEHAMMOCK_RELEASE_ALLOW_LOOPBACK_HTTP='true')
        self.assertEqual(self.calls,[])
    def test_private_auth_file_removed_after_failure(self):
        paths=[]
        def fail(args,**kwargs):
            if '--authfile' in args:paths.append(Path(args[args.index('--authfile')+1]));self.assertEqual(paths[-1].stat().st_mode&0o777,0o600)
            raise identity.ReleaseError('Injected login failure')
        with patch.object(artifacts,'run',side_effect=fail),self.assertRaises(identity.ReleaseError):artifacts.promote(self.folder,self.manifest,'generic',self.folder/'generic-publication.json',self.env)
        self.assertTrue(paths);self.assertFalse(paths[0].exists())
    def test_multi_registry_summary_records_partial_progress(self):
        report=self.promote();other=dict(report,registry='dockerhub',status='Failed')
        summary=artifacts.aggregate(self.folder,self.manifest,[report,other],['generic','dockerhub']);self.assertEqual(summary['status'],'Incomplete')
        self.assertEqual(summary['registries']['generic']['status'],'Succeeded');self.assertEqual(summary['registries']['dockerhub']['status'],'Failed')
    def test_missing_or_cross_candidate_registry_reports_cannot_claim_completion(self):
        report=self.promote();self.assertEqual(artifacts.aggregate(self.folder,self.manifest,[],['generic'])['status'],'Incomplete')
        report['source_sha']='c'*40
        with self.assertRaises(identity.ReleaseError):artifacts.aggregate(self.folder,self.manifest,[report],['generic'])
    def test_successful_report_requires_all_canonical_tags(self):
        report=self.promote();report['tags'].pop()
        with self.assertRaises(identity.ReleaseError):artifacts.aggregate(self.folder,self.manifest,[report],['generic'])

class CanonicalSourceTests(unittest.TestCase):
    def test_canonical_stable_and_prerelease_versions(self):
        for tag in ['v1.1.0','v1.1.0-rc.1']:
            self.assertEqual(identity.canonical(tag,'a'*40)['assembly_version'],'1.1.0.0')
    def test_malformed_semver_source_and_assembly_range_rejected(self):
        for tag,sha in [('v01.1.0','a'*40),('v1.1.0-rc.01','a'*40),('v1.1.0+build','a'*40),('v65535.1.0','a'*40),('v1.1.0\n','a'*40),('v1.1.0','A'*40),('v1.1.0','bad')]:
            with self.subTest(tag=tag,sha=sha),self.assertRaises(identity.ReleaseError):identity.canonical(tag,sha)
    def test_source_byte_check_tolerates_chmod_but_rejects_content_and_sha_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);file=root/'source';file.write_text('source')
            for args in [['init','-q'],['add','.'],['-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-qm','source']]:subprocess.run(['git',*args],cwd=root,check=True,capture_output=True)
            sha=identity.run(['git','rev-parse','HEAD'],cwd=root).stdout.strip();file.chmod(0o755);identity.source_check(root,sha)
            file.write_text('changed')
            with self.assertRaises(identity.ReleaseError):identity.source_check(root,sha)
            file.write_text('source')
            with self.assertRaises(identity.ReleaseError):identity.source_check(root,'a'*40)
            (root/'extra.cs').write_text('extra')
            with self.assertRaises(identity.ReleaseError):identity.source_check(root,sha)

class VersionedMetadataTests(unittest.TestCase):
    setUp=boundary.ReleaseMetadataTests.setUp
    tearDown=boundary.ReleaseMetadataTests.tearDown
    run_metadata=boundary.ReleaseMetadataTests.run_metadata
    def test_later_manual_release_uses_checkout_not_trigger_sha(self):
        r,c,v=self.run_metadata(RELEASE_POLICY='versioned',INPUT_RELEASE_TAG='v1.1.0',INPUT_TARGET_REF='main',GITHUB_SHA=self.initial)
        self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(v['checkout_ref'],self.later);self.assertEqual(v['release_source_sha'],self.later)
        self.assertEqual(v['should_release'],'true');self.assertEqual(v['release_informational_version'],'1.1.0+sha.'+self.later)
    def test_versioned_tag_push_and_prerelease(self):
        for tag in ['v1.1.0','v1.1.0-rc.1']:
            r,c,v=self.run_metadata(RELEASE_POLICY='versioned',GITHUB_EVENT_NAME='push',GITHUB_REF='refs/tags/'+tag,PUBLISH_GHCR='false')
            self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(v['should_release'],'true');self.assertEqual(v['checkout_ref'],self.later)
    def test_versioned_branch_push_is_rejected(self):
        r,c,v=self.run_metadata(RELEASE_POLICY='versioned',GITHUB_EVENT_NAME='push');self.assertEqual((r.returncode,c,v),(2,[],{}))
    def test_existing_version_tag_must_target_requested_source(self):
        self.git('tag','v1.1.0',self.initial);self.git('push','origin','refs/tags/v1.1.0')
        r,c,v=self.run_metadata(RELEASE_POLICY='versioned',INPUT_RELEASE_TAG='v1.1.0',INPUT_TARGET_REF='main',GH_TAG_STATUS='200')
        self.assertEqual(r.returncode,2);self.assertEqual(v,{})
    def test_matching_existing_tag_allows_source_release_recovery(self):
        self.git('tag','v1.1.0',self.later);self.git('push','origin','refs/tags/v1.1.0')
        r,c,v=self.run_metadata(RELEASE_POLICY='versioned',INPUT_RELEASE_TAG='v1.1.0',INPUT_TARGET_REF='main',GH_TAG_STATUS='200')
        self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(v['should_release'],'true')
    def test_existing_versioned_release_skips(self):
        r,c,v=self.run_metadata(RELEASE_POLICY='versioned',INPUT_RELEASE_TAG='v1.1.0',INPUT_TARGET_REF='main',GH_RELEASE_STATUS='200')
        self.assertEqual(r.returncode,0);self.assertEqual(v['should_release'],'false')

class ArtifactWiringMutationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'source';shutil.copytree(ROOT,self.root,ignore=shutil.ignore_patterns('.git','bin','obj','.artifacts','.correction-results','artifacts','TestResults','__pycache__'))
    def tearDown(self):self.temp.cleanup()
    def reject(self,name,before,after):
        p=self.root/name;s=p.read_text();self.assertIn(before,s);p.write_text(s.replace(before,after,1))
        with self.assertRaises((ValueError,KeyError)):guard.validate(self.root)
    def test_wiring_is_not_native_qualification(self):self.assertEqual(guard.validate(self.root)['qualification'],'NotRun')
    def test_package_version_cannot_remain_development_default(self):self.reject('Directory.Build.props','<PackageVersion>$(TreehammockReleaseVersion)</PackageVersion>','<PackageVersion>1.0.0</PackageVersion>')
    def test_compile_and_no_build_publish_use_same_version(self):self.reject('Dockerfile','-p:TreehammockReleaseVersion=','-p:Unrelated=')
    def test_candidate_must_execute_unit_build_target(self):self.reject('Dockerfile','FROM unit-test AS publish','FROM build AS publish')
    def test_oci_revision_label_required(self):self.reject('Dockerfile','org.opencontainers.image.revision','unrelated')
    def test_probe_cannot_enter_application_glob(self):self.reject('treehammock.csproj','eng\\ReleaseArtifactProbe\\**','eng\\Other\\**')
    def test_github_sha_tag_cannot_use_trigger_identity(self):self.reject('.github/workflows/treehammock-release.yml','RELEASE_SOURCE_SHA: ${{ needs.release-preflight.outputs.checkout_ref }}','RELEASE_SOURCE_SHA: ${{ github.sha }}')
    def test_later_version_policy_cannot_replace_bootstrap_default(self):self.reject('.github/workflows/treehammock-release.yml','RELEASE_POLICY: bootstrap','RELEASE_POLICY: versioned')
    def test_gitlab_registry_cannot_bypass_tested_candidate(self):self.reject('.gitlab/ci/pipelines/release.yml','    - release-package-api\n  variables:\n    RELEASE_MANIFEST','    - release-preflight\n  variables:\n    RELEASE_MANIFEST')
    def test_partial_registry_outcomes_must_be_retained(self):self.reject('.gitlab/ci/pipelines/release.yml','release-publication-summary:\n  image: alpine:3.20\n  stage: publish\n  when: always','release-publication-summary:\n  image: alpine:3.20\n  stage: publish\n  when: on_success')

if __name__=='__main__':unittest.main()

class CandidateOwnershipTests(unittest.TestCase):
    """Controlled command adapter; these cases do not build native images."""
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.base=Path(self.temp.name);self.root=self.base/'source';self.root.mkdir()
        (self.root/'eng').mkdir();(self.root/'eng/fixture.sh').write_text('#!/bin/sh\n')
        (self.root/'docker-compose.integration.yml').write_text('services:\n  api:\n    environment:\n      DatabaseSettings__password: old\n')
        self.output=self.base/'output';self.calls=[];self.fixture=None
    def tearDown(self):self.temp.cleanup()
    def execute(self,fail=None,cleanup_fail=False,loaded_drift=False,health_bad=False):
        def adapter(args,**kwargs):
            self.calls.append((args,kwargs))
            if fail and fail(args):raise identity.ReleaseError('controlled command failure')
            if args[:3]==['docker','buildx','build']:
                build_id=next(a.split('=',1)[1] for a in args if a.startswith('TREEHAMMOCK_BUILD_RUN_ID='))
                self.fixture,_=candidate(self.base/'fixture','v1.1.0','a'*40,build_id)
                shutil.copy2(self.base/'fixture/candidate.oci.tar',self.output/'candidate.oci.tar')
            if args[:3]==['docker','image','inspect']:
                info=artifacts.oci(self.output/'candidate.oci.tar')
                return result(json.dumps([dict(Id='sha256:'+'c'*64 if loaded_drift else info['config_digest'],RootFS=dict(Layers=info['config']['rootfs']['diff_ids']),Config=dict(Labels=info['config']['config']['Labels']))]))
            if args[:2]==['docker','cp'] and args[2].endswith(':/app/.'):
                for p in (self.base/'fixture/treehammock-api').iterdir():shutil.copy2(p,Path(args[3])/p.name)
            if args[:2]==['docker','cp'] and args[2].endswith(':/probe/.'):(Path(args[3])/'ReleaseArtifactProbe.dll').write_bytes(b'controlled probe')
            if '/probe/ReleaseArtifactProbe.dll' in args:
                if '--http' in args:return result(json.dumps(dict(live=200,ready=503 if health_bad else 200)))
                return result((self.base/'fixture/archive-inspection.json').read_text())
            if cleanup_fail and args[:3]==['docker','buildx','rm']:return result(code=1)
            return result('controlled tool output')
        with patch.object(artifacts,'source_check'),patch.object(artifacts,'resolve_image',side_effect=lambda x:x+'@sha256:'+'b'*64),patch.object(artifacts,'run',side_effect=adapter),patch.dict(os.environ,{'RELEASE_PACKAGE_NAME':'treehammock-api'}):
            return artifacts.build(self.root,self.output,'v1.1.0','a'*40)
    def report(self):return json.loads((self.output/'release-manifest.json').read_text())
    def test_one_candidate_build_extracts_and_tests_exact_config_with_pinned_inputs(self):
        value=self.execute();self.assertEqual(value['status'],'Tested')
        builds=[a for a,k in self.calls if a[:3]==['docker','buildx','build']];self.assertEqual(len(builds),1)
        self.assertIn('TREEHAMMOCK_RELEASE_SOURCE_SHA='+'a'*40,builds[0]);self.assertIn('TREEHAMMOCK_RELEASE_VERSION=1.1.0',builds[0])
        api=next(a for a,k in self.calls if a[:2]==['docker','run'] and '--tmpfs' in a)
        self.assertEqual(api[-1],value['candidate']['config_digest']);self.assertNotIn('--publish',api)
        self.assertFalse(any(a[:3]==['docker','system','prune'] for a,k in self.calls))
    def test_build_failure_cannot_produce_tested_candidate(self):
        with self.assertRaises(identity.ReleaseError):self.execute(fail=lambda a:a[:3]==['docker','buildx','build'])
        value=self.report();self.assertEqual(value['status'],'Failed');self.assertEqual(value['failed_stage'],'candidate-build')
        self.assertTrue(any(a[:3]==['docker','buildx','rm'] for a,k in self.calls));self.assertFalse(any(a[:2]==['docker','create'] for a,k in self.calls))
    def test_loaded_config_drift_stops_before_extraction_and_removes_owned_image(self):
        with self.assertRaises(identity.ReleaseError):self.execute(loaded_drift=True)
        self.assertEqual(self.report()['failed_stage'],'load-candidate');self.assertTrue(any(a[:3]==['docker','image','rm'] for a,k in self.calls))
        self.assertFalse(any(a[:2]==['docker','cp'] for a,k in self.calls))
    def test_actual_runtime_probe_failure_preserves_failed_stage_and_cleanup(self):
        with self.assertRaises(identity.ReleaseError):self.execute(health_bad=True)
        value=self.report();self.assertEqual(value['status'],'Failed');self.assertEqual(value['failed_stage'],'owned-candidate-runtime');self.assertNotIn('tested_digest',value)
        removals=[a for a,k in self.calls if a[:2]==['docker','rm']];self.assertTrue(removals)
        self.assertTrue(all(a[-1].startswith('treehammock-release-'+value['build_run_id']) for a in removals))
    def test_cleanup_failure_cannot_claim_tested_or_promotable(self):
        with self.assertRaises(identity.ReleaseError):self.execute(cleanup_fail=True)
        value=self.report();self.assertEqual(value['failed_stage'],'owned-cleanup');self.assertEqual(value['cleanup']['status'],'Failed')
    def test_inspector_compile_failure_cleans_only_created_owned_resources(self):
        with self.assertRaises(identity.ReleaseError):self.execute(fail=lambda a:a[:2]==['docker','exec'] and 'publish' in a)
        self.assertEqual(self.report()['failed_stage'],'compile-inspector')
        self.assertFalse(any(a[:3]==['docker','network','rm'] for a,k in self.calls))
        self.assertTrue(any(a[:2]==['docker','rm'] for a,k in self.calls))
    def test_dirty_source_stops_before_output_or_container_creation(self):
        with patch.object(artifacts,'source_check',side_effect=identity.ReleaseError('dirty')),patch.object(artifacts,'run') as command:
            with self.assertRaises(identity.ReleaseError):artifacts.build(self.root,self.output,'v1.1.0','a'*40)
        self.assertFalse(self.output.exists());command.assert_not_called()

class CiOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.folder=self.root/'artifacts/release';self.manifest,self.raw=candidate(self.folder)
        self.evidence=self.root/'image-outcome';self.evidence.mkdir()
        self.environment=dict(RELEASE_TAG='v1.1.0',RELEASE_SOURCE_SHA='a'*40,PUBLISH_GHCR='true',GHCR_RESULT='failure',PUBLISH_GITLAB_REGISTRY='false',PUBLISH_SELF_HOSTED_REGISTRY='false',PUBLISH_DOCKERHUB='false',PUBLISH_AWS_ECR='false')
    def tearDown(self):self.temp.cleanup()
    def test_optional_missing_image_outcome_preserved_without_vetoing_source(self):
        with patch.object(artifacts,'ROOT',self.root),patch.dict(os.environ,self.environment):artifacts.ci_summary('github')
        report=json.loads((self.folder/'release-summary.json').read_text());self.assertEqual(report['status'],'Incomplete');self.assertEqual(report['hosted_image_job_result'],'failure');self.assertEqual(report['registries']['github']['status'],'MissingOrAmbiguous')
    def test_optional_corrupt_outcome_preserved_without_claiming_success(self):
        (self.evidence/'github-publication.json').write_text('{broken')
        with patch.object(artifacts,'ROOT',self.root),patch.dict(os.environ,self.environment):artifacts.ci_summary('github')
        report=json.loads((self.folder/'release-summary.json').read_text());self.assertEqual(report['status'],'Incomplete');self.assertEqual(report['registries']['github']['status'],'InvalidPublicationEvidence');self.assertTrue(report['publication_evidence'])
    def test_enabled_gitlab_missing_or_corrupt_outcome_blocks_assets(self):
        for corrupt in [False,True]:
            if corrupt:(self.folder/'gitlab-publication.json').write_text('{broken')
            with self.subTest(corrupt=corrupt),patch.object(artifacts,'ROOT',self.root),patch.dict(os.environ,dict(self.environment,PUBLISH_GITLAB_REGISTRY='true')):
                with self.assertRaises(identity.ReleaseError):artifacts.ci_summary('gitlab')
            report=json.loads((self.folder/'release-summary.json').read_text());self.assertEqual(report['status'],'Incomplete');self.assertIn('gitlab',report['registries'])
    def test_missing_candidate_writes_blocked_summary_and_never_publishes(self):
        (self.folder/'release-manifest.json').unlink()
        with patch.object(artifacts,'ROOT',self.root),patch.dict(os.environ,self.environment):
            with self.assertRaises(OSError):artifacts.ci_summary('github')
        report=json.loads((self.folder/'release-summary.json').read_text());self.assertEqual(report['status'],'CandidateInvalidOrFailed');self.assertEqual(report['registries']['github']['status'],'BlockedNoTestedCandidate')
