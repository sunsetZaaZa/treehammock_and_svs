import base64,copy,hashlib,json,os,shutil,subprocess,tempfile,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
import yaml
from policy import ROOT,Refused,check_source,check_image,check_archive,scan,verify_packages,source_fingerprint
from artifacts import bundle,verify,sign,signing_context
class PolicyTests(unittest.TestCase):
    def test_baseline_and_additive_child(self):self.assertGreater(check_source(),400)
    def test_consumer_project_lock_review_cannot_change_external_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=self.fixture(tmp);check_source(root);name='tests/Treehammock.SessionValidation.HostTests/packages.lock.json';path=root/name;lock=json.loads(path.read_text());lock['dependencies']['net10.0']['backup.identity']['type']='Direct';path.write_text(json.dumps(lock));p=root/'eng/session-validation/ci/source-pins.json';v=json.loads(p.read_text());v['reviewed_test_locks'][name]['sha256']=hashlib.sha256(path.read_bytes()).hexdigest();p.write_text(json.dumps(v))
            with self.assertRaises(Refused):check_source(root)
    def test_image_must_be_immutable(self):
        check_image('registry.invalid/ci@sha256:'+'a'*64)
        for image in ['', 'sdk:10.0','sdk:latest','sdk@sha256:bad']:
            with self.subTest(image=image),self.assertRaises(Refused):check_image(image)
    def fixture(self,directory):
        root=Path(directory)/'source';root.mkdir();data=json.loads((ROOT/'eng/session-validation/ci/source-pins.json').read_text())
        for name in [*data['files'],*data.get('reviewed_additions',{}),*data.get('reviewed_runtime_additions',{}),'.gitlab-ci.yml','.gitlab/ci/pipelines/session-validation.yml','eng/session-validation/ci/source-pins.json']:
            dest=root/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,dest)
        for review in data.get('reviewed_test_locks',{}).values():
            dest=root/review['baseline_path'];dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/review['baseline_path'],dest)
        return root
    def test_source_role_lock_sdk_and_baseline_ci_drift_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=self.fixture(tmp)
            for name in ['src/Treehammock.SessionValidation.Storage/SvsRefillDatabase.cs','packages.lock.json','global.json','.gitlab/ci/pipelines/release.yml']:
                with self.subTest(name=name):
                    path=root/name;old=path.read_bytes();path.write_bytes(old+b'\n')
                    with self.assertRaises(Refused):check_source(root)
                    path.write_bytes(old)
            path=root/'.gitlab-ci.yml';old=path.read_text();data=yaml.safe_load(old);data.pop('trigger-release-pipeline');path.write_text(yaml.safe_dump(data))
            with self.assertRaises(Refused):check_source(root)
    def test_policy_addition_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=self.fixture(tmp);(root/'src/unreviewed.cs').write_text('not reviewed')
            with self.assertRaises(Refused):check_source(root)
    def test_reviewed_addition_tamper_and_pin_override_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=self.fixture(tmp);check_source(root)
            path=root/'deploy/session-validation/compose.integration.yaml';original=path.read_bytes();path.write_bytes(original+b'\n')
            with self.assertRaises(Refused):check_source(root)
            path.write_bytes(original);p=root/'eng/session-validation/ci/source-pins.json';data=json.loads(p.read_text());name=next(iter(data['files']));data['reviewed_additions'][name]=data['files'][name];p.write_text(json.dumps(data))
            with self.assertRaises(Refused):check_source(root)
    def test_reviewed_API_capacity_delta_still_refuses_tamper_or_forged_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=self.fixture(tmp);check_source(root);path=root/'src/Treehammock.SessionValidation.Api/CapacitySettings.cs';old=path.read_bytes();path.write_bytes(old+b'\n')
            with self.assertRaises(Refused):check_source(root)
            path.write_bytes(old);p=root/'eng/session-validation/ci/source-pins.json';data=json.loads(p.read_text());name=next(iter(data['reviewed_runtime_changes']));data['reviewed_runtime_changes'][name]['baseline_sha256']='0'*64;p.write_text(json.dumps(data))
            with self.assertRaises(Refused):check_source(root)
    def test_signing_gate_and_artifact_access_drift_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=self.fixture(tmp);path=root/'.gitlab/ci/pipelines/session-validation.yml';original=path.read_text()
            for change in ['signing','access','allow_failure','cache']:
                d=yaml.safe_load(original)
                if change=='signing':d['svs14-signature']['rules']=[{'when':'always'}]
                elif change=='access':d['svs14-validation']['artifacts']['access']='all'
                elif change=='cache':d['default']['cache']={'paths':['packages']}
                else:d['svs14-validation']['allow_failure']=True
                path.write_text(yaml.safe_dump(d))
                with self.subTest(change=change),self.assertRaises(Refused):check_source(root)
    def test_exact_archive_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'input.zip'
            with zipfile.ZipFile(path,'w') as z:z.writestr('fixture','fixture')
            check_archive(path,hashlib.sha256(path.read_bytes()).hexdigest())
            with self.assertRaises(Refused):check_archive(path,'0'*64)
    def test_scan_refuses_token_key_canary_without_printing(self):
        for blob,secrets in [(b'fixture-private-canary',['fixture-private-canary']),(b'-----BEGIN PRIVATE KEY-----',[]),(b'password=do-not-export',[]),(b'eyJhbGciOiJIUzI1NiJ9.abcdefghijk.abcdefghijk',[])]:
            with self.assertRaises(Refused) as error:scan(blob,secrets)
            self.assertNotIn(blob.decode(),str(error.exception))
    def test_package_cache_poisoning_and_lock_hash_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);cache=root/'cache';folder=cache/'fixture'/'1.0.0';folder.mkdir(parents=True)
            archive=folder/'fixture.1.0.0.nupkg'
            with zipfile.ZipFile(archive,'w') as z:z.writestr('lib/net8.0/fixture.dll',b'fixture')
            digest=base64.b64encode(hashlib.sha512(archive.read_bytes()).digest()).decode()
            (root/'packages.lock.json').write_text(json.dumps({'dependencies':{'net8.0':{'Fixture':{'resolved':'1.0.0','type':'Direct','contentHash':digest}}}}))
            (root/'project.assets.json').write_text(json.dumps({'targets':{'net8.0':{'Fixture/1.0.0':{'type':'package','compile':{'lib/net8.0/fixture.dll':{}}}}}}))
            binary=folder/'lib/net8.0/fixture.dll';binary.parent.mkdir(parents=True);binary.write_bytes(b'fixture')
            self.assertEqual(verify_packages(root,cache),1);binary.write_bytes(b'tampered')
            with self.assertRaises(Refused):verify_packages(root,cache)
            binary.write_bytes(b'fixture');archive.write_bytes(b'tampered')
            with self.assertRaises(Refused):verify_packages(root,cache)
class ArtifactTests(unittest.TestCase):
    def fixture(self,tmp):
        root=Path(tmp)/'fixture';root.mkdir();name='treehammock';p=root/'bin/Release/net8.0';p.mkdir(parents=True);(p/(name+'.dll')).write_bytes(b'synthetic assembly fixture')
        for suffix in ['Api','Core','Storage','Client','Contracts']:
            name='Treehammock.SessionValidation.'+suffix;p=root/'src'/name/'bin/Release/net10.0';p.mkdir(parents=True);(p/(name+'.dll')).write_bytes(b'synthetic assembly fixture')
        summary=dict(total_test_executions=1,native_cases_executed=0,grant_rights=False,release_ready=False)
        commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
        provenance=dict(commit=commit,source_sha256=source_fingerprint())
        return root,summary,provenance
    def test_reproducible_bundle_and_tamper_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root,s,p=self.fixture(tmp);a=Path(tmp)/'a';b=Path(tmp)/'b';bundle(root,a,s,p);bundle(root,b,s,p)
            self.assertEqual((a/'payload.tar.gz').read_bytes(),(b/'payload.tar.gz').read_bytes());verify(a,p['commit'])
            (a/'payload.tar.gz').write_bytes(b'tampered')
            with self.assertRaises(Refused):verify(a,p['commit'])
    def test_unprotected_signing_refused(self):
        for env in [{},{'GITLAB_CI':'true'},{'GITLAB_CI':'true','CI_COMMIT_REF_PROTECTED':'false','CI_COMMIT_TAG':'v1'}]:
            with self.assertRaises(Refused):signing_context(env)
    def test_actual_openssl_detached_sign_verify_and_wrong_public_pin(self):
        with tempfile.TemporaryDirectory() as tmp:
            root,s,p=self.fixture(tmp);a=Path(tmp)/'a';bundle(root,a,s,p);private=Path(tmp)/'fixture-only.pem'
            subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(private)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);private.chmod(0o600)
            public=subprocess.check_output(['openssl','pkey','-in',str(private),'-pubout'])
            env=dict(GITLAB_CI='true',CI_COMMIT_REF_PROTECTED='true',CI_COMMIT_TAG='fixture-only',CI_COMMIT_SHA=p['commit'],SVS14_SIGN_ARTIFACTS='true',SVS14_SIGNING_KEY_FILE=str(private),SVS14_SIGNING_PUBLIC_SHA256=hashlib.sha256(public).hexdigest())
            self.assertEqual(sign(a,env),'SignedValidationArtifactOnly');self.assertEqual((a/'manifest.ed25519').stat().st_size,64)
            env['SVS14_SIGNING_PUBLIC_SHA256']='0'*64
            with self.assertRaises(Refused):sign(a,env)
            self.assertNotIn(private.read_bytes(),(a/'payload.tar.gz').read_bytes())
if __name__=='__main__':unittest.main()
