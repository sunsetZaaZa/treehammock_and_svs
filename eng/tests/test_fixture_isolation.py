"""Actual credential/file/Bash behavior; Compose merges are supplemental fixtures."""
import base64,concurrent.futures,importlib.util,json,os
from pathlib import Path
import shutil,subprocess,sys,tempfile,unittest
from unittest.mock import patch
import yaml
ROOT=Path(__file__).resolve().parents[2]
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,ROOT/'eng'/file);result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
fixture=module('fixture_isolation','fixture-isolation.py');guard=module('isolation_guard','check-fixture-isolation.py')
class CredentialTests(unittest.TestCase):
    def setUp(self):self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'owned';self.root.mkdir()
    def tearDown(self):self.temp.cleanup()
    def values(self,project='alpha'):
        file=fixture.ensure(self.root,{'COMPOSE_PROJECT_NAME':project});return file,dict(line.split('=',1) for line in file.read_text().splitlines())
    def test_generated_keys_have_correct_entropy_encoding_and_inventory(self):
        file,values=self.values();self.assertEqual(set(values),fixture.KEYS)
        for name,value in values.items():
            self.assertEqual(len(base64.b64decode(value) if name in ('TREEHAMMOCK_FIXTURE_OUTBOX_KEY','TREEHAMMOCK_FIXTURE_OPERATION_KEY') else bytes.fromhex(value)),32)
        self.assertEqual(len(set(values.values())),5)
    def test_existing_project_reuses_credentials_without_invalidating_its_state(self):
        file,values=self.values();before=file.stat().st_mtime_ns;self.assertEqual(self.values()[1],values);self.assertEqual(file.stat().st_mtime_ns,before)
    def test_distinct_projects_have_independent_credentials_and_locations(self):
        a,first=self.values('first');b,second=self.values('second');self.assertNotEqual(a,b)
        for key in fixture.KEYS:self.assertNotEqual(first[key],second[key])
    def test_parallel_initialization_retains_one_complete_project_identity(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:results=list(pool.map(lambda _:self.values(),range(16)))
        self.assertTrue(all(values==results[0][1] for _,values in results));self.assertFalse(list(results[0][0].parent.glob('*.tmp')))
    @unittest.skipIf(os.name=='nt','POSIX permissions; Windows ACL qualified natively')
    def test_file_and_directory_permissions_are_private(self):
        file,_=self.values();self.assertEqual(file.stat().st_mode&0o777,0o600);self.assertEqual(file.parent.stat().st_mode&0o777,0o700)
    def test_invalid_project_cannot_escape_owned_storage(self):
        for project in ['../other','Upper','-first','x'*64,'','a/b']:
            if not project:continue
            with self.subTest(project=project),self.assertRaises(ValueError):self.values(project)
        self.assertFalse((self.root/'.docker').exists())
    def test_duplicate_missing_unknown_or_malformed_inventory_fails_closed(self):
        file,_=self.values();original=file.read_text()
        for text in [original+original.splitlines()[0]+'\n','\n'.join(original.splitlines()[1:]),original+'OTHER=bad\n',original.replace('=',':',1)]:
            file.write_text(text)
            with self.assertRaises(ValueError):self.values()
        file.write_text(original)
    def test_invalid_crypto_material_rejected_without_secret_diagnostic(self):
        file,values=self.values();values['TREEHAMMOCK_FIXTURE_OPERATION_KEY']='not-secret-base64'
        file.write_text(''.join(k+'='+v+'\n' for k,v in values.items()))
        with self.assertRaises(ValueError) as caught:self.values()
        self.assertNotIn('not-secret-base64',str(caught.exception))
    @unittest.skipIf(os.name=='nt','Symlink permission is host-specific')
    def test_linked_project_directory_does_not_touch_unrelated_storage(self):
        outside=self.root/'outside';outside.mkdir();parent=self.root/'.docker/fixtures';parent.mkdir(parents=True);(parent/'alpha').symlink_to(outside)
        with self.assertRaises(ValueError):self.values()
        self.assertEqual(list(outside.iterdir()),[])
    @unittest.skipIf(os.name=='nt','Symlink permission is host-specific')
    def test_linked_credential_file_rejected(self):
        file,_=self.values();outside=self.root/'sentinel';outside.write_text('sentinel');file.unlink();file.symlink_to(outside)
        with self.assertRaises(ValueError):self.values()
        self.assertEqual(outside.read_text(),'sentinel')
    @unittest.skipIf(os.name=='nt','POSIX permissions')
    def test_public_existing_credential_file_rejected(self):
        file,_=self.values();file.chmod(0o644)
        with self.assertRaises(ValueError):self.values()
    def test_bash_exports_the_project_credentials_without_echoing_values(self):
        if not shutil.which('bash'):self.skipTest('Bash unavailable')
        (self.root/'eng').mkdir()
        for name in ['fixture-isolation.py','fixture-isolation.sh']:shutil.copy2(ROOT/'eng'/name,self.root/'eng'/name)
        command='repo_root="$PWD"; source ./eng/fixture-isolation.sh; treehammock_initialize_fixture container; python3 -c "import os; assert len(os.environ[\'TREEHAMMOCK_FIXTURE_TEST_KEY\'])==64; assert os.environ[\'COMPOSE_PROJECT_NAME\']==\'bash-owned\'"'
        result=subprocess.run(['bash','-c',command],cwd=self.root,env=dict(os.environ,COMPOSE_PROJECT_NAME='bash-owned'),text=True,capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout,'');self.assertEqual(result.stderr,'')
class PreflightTests(unittest.TestCase):
    def response(self,args,**kwargs):
        if args[1]=='version':out=self.version
        elif args[1]=='context':out=self.endpoint
        else:out=json.dumps(dict(OSType=self.ostype,OperatingSystem=self.system))
        return subprocess.CompletedProcess(args,self.code,stdout=out,stderr='')
    def setUp(self):self.version='28.0.0';self.endpoint='unix:///owned.sock';self.ostype='linux';self.system='Docker Engine';self.code=0;self.mock=patch.object(fixture.subprocess,'run',self.response);self.mock.start()
    def tearDown(self):self.mock.stop()
    def test_container_mode_does_not_require_host_docker_or_version(self):
        with patch.object(fixture.subprocess,'run',side_effect=AssertionError('Unexpected daemon access')):fixture.check_host('container',{})
    def test_docker_28_local_published_mode_accepted(self):fixture.check_host('published',{})
    def test_older_malformed_or_failed_engine_is_rejected(self):
        for version in ['27.5.1','1.0','garbage','']:
            self.version=version
            with self.subTest(version=version),self.assertRaises(ValueError):fixture.check_host('published',{})
        self.version='28.0.0';self.code=1
        with self.assertRaises(ValueError):fixture.check_host('published',{})
    def test_remote_daemon_and_docker_host_override_rejected(self):
        self.endpoint='tcp://remote:2376'
        with self.assertRaises(ValueError):fixture.check_host('published',{})
        self.endpoint='unix:///owned.sock'
        with self.assertRaises(ValueError):fixture.check_host('published',{'DOCKER_HOST':'ssh://remote'})
        self.endpoint='ssh://remote'
        with self.assertRaises(ValueError):fixture.check_host('published',{'DOCKER_HOST':'unix:///owned.sock','DOCKER_CONTEXT':'remote'})
    def test_desktop_host_networking_requires_explicit_confirmation(self):
        self.system='Docker Desktop'
        with self.assertRaises(ValueError):fixture.check_host('host',{})
        fixture.check_host('host',{'TREEHAMMOCK_HOST_NETWORKING_CONFIRMED':'true'})
    def test_windows_container_host_lane_rejected(self):
        self.ostype='windows'
        with self.assertRaises(ValueError):fixture.check_host('host',{'TREEHAMMOCK_HOST_NETWORKING_CONFIRMED':'true'})
    def test_remote_lab_requires_explicit_opt_in_and_still_uses_local_daemon(self):
        with self.assertRaises(ValueError):fixture.check_host('remote',{})
        fixture.check_host('remote',{'TREEHAMMOCK_REMOTE_LAB_ACCESS':'true'});self.endpoint='tcp://remote:2376'
        with self.assertRaises(ValueError):fixture.check_host('remote',{'TREEHAMMOCK_REMOTE_LAB_ACCESS':'true'})
    def test_failed_host_preflight_creates_no_settings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.version='27.0.0'
            with self.assertRaises(ValueError):fixture.ensure(root,{},'published')
            self.assertEqual(list(root.iterdir()),[])
class ConfigurationTests(unittest.TestCase):
    def compose(self,*names):
        # Supplemental Compose port-union model; native config --format json is authoritative.
        result={}
        for name in names:
            for service,value in yaml.safe_load((ROOT/name).read_text()).get('services',{}).items():
                target=result.setdefault(service,{});ports=target.get('ports',[])
                target.update(value)
                if ports or value.get('ports'):target['ports']=list(dict.fromkeys(ports+value.get('ports',[])))
        return result
    def test_default_and_privileged_container_profiles_have_no_publications(self):
        for overlays in [[],['docker-compose.testing.yml'],['docker-compose.api-proxy.yml','docker-compose.testing.yml','docker-compose.ci-system.yml']]:
            config=self.compose('docker-compose.integration.yml',*overlays);self.assertFalse(any(value.get('ports') for value in config.values()))
    def test_all_supported_access_overlay_combinations_are_loopback(self):
        import itertools
        overlays=['docker-compose.host-access.yml','docker-compose.proxy-access.yml','docker-compose.api-direct.yml']
        for count in range(4):
            for selected in itertools.combinations(overlays,count):
                config=self.compose('docker-compose.integration.yml','docker-compose.api-proxy.yml','docker-compose.testing.yml',*selected)
                self.assertTrue(all(port.startswith('127.0.0.1:') for value in config.values() for port in value.get('ports',[])))
    def test_keys_are_generated_for_producer_and_client_without_enabling_default_capture(self):
        base=self.compose('docker-compose.integration.yml')['api']['environment'];testing=self.compose('docker-compose.testing.yml')['api']['environment'];client=self.compose('docker-compose.ci-system.yml')['system-tests']['environment']
        self.assertEqual(base['SystemTestSettings__Enabled'],'false');self.assertEqual(base['SystemTestSettings__TestKey'],'')
        self.assertEqual(testing['SystemTestSettings__TestKey'],client['TREEHAMMOCK_SYSTEM_TEST_KEY']);self.assertIn(':?',testing['SystemTestSettings__TestKey'])
    def test_source_wiring_is_supplemental_only(self):self.assertEqual(guard.validate(ROOT)['qualification'],'NotRun')
    def test_wildcard_profile_mutation_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'source';shutil.copytree(ROOT,root,ignore=shutil.ignore_patterns('.docker','.git','bin','obj','__pycache__','artifacts','.artifacts','.correction-results','TestResults'))
            file=root/'docker-compose.host-access.yml';file.write_text(file.read_text().replace('127.0.0.1:5432','0.0.0.0:5432'))
            with self.assertRaises(ValueError):guard.validate(root)
            file.write_text(file.read_text().replace('0.0.0.0:5432','127.0.0.1:5432'))
            script=root/'eng/docker-sql-contracts.ps1';text=script.read_text();line=". (Join-Path $PSScriptRoot 'fixture-isolation.ps1')\n";script.write_text(text.replace(line,'').replace("Initialize-TreehammockFixture -Mode",line+"Initialize-TreehammockFixture -Mode"))
            with self.assertRaises(ValueError):guard.validate(root)
