"""Actual private binaries/process/HTTP/TRX behavior with controlled protocol actors."""
import importlib.util,json,os,signal,socket,subprocess,sys,time,unittest,uuid
from pathlib import Path
from unittest.mock import patch
import test_test_ownership as fixtures
owned=fixtures.owned;ROOT=fixtures.ROOT;proof=owned.hostproof
ADAPTER=ROOT/'eng/tests/fixtures/host-identity/host_adapter.py.txt'
def adapter():
 scope={'__name__':'controlled_host_fixture'};exec(compile(ADAPTER.read_text(),str(ADAPTER),'exec'),scope);return scope
def prepare_environment(run,environment):
 env=owned.run_environment(run,environment);env.update(TREEHAMMOCK_BUILD_RUN_ID=str(uuid.uuid4()),TREEHAMMOCK_BUILD_CONFIGURATION='Release',ASPNETCORE_ENVIRONMENT='Testing',DOTNET_ENVIRONMENT='Testing',SystemTestSettings__Enabled='true',SystemTestSettings__EnableTestInspectionEndpoints='true',TREEHAMMOCK_SYSTEM_BASE_URL=proof.PROXY)
 env['SystemTestSettings__TestKey']=dict(line.split('=',1) for line in Path(run['credential_file']).read_text().splitlines())['TREEHAMMOCK_FIXTURE_TEST_KEY'];adapter()['build'](Path(run['checkout']),env,'treehammock.Tests.System');return env

class HostArtifactTests(unittest.TestCase):
 setUp=fixtures.ControlledRuns.setUp
 tearDown=fixtures.ControlledRuns.tearDown
 def make(self):
  run=owned.create_run(self.root,'docker-host-system-stack-tests',self.env);run['status']='Running';owned.write(owned.manifest(run),run);owner=owned.Lifecycle(run);return run,owner,prepare_environment(run,self.env)
 def test_exact_artifact_hash_reference_build_and_target_bound_before_launch(self):
  run,owner,env=self.make();child,path=owner.proof.prepare(env);self.assertEqual(path,Path(run['checkout'])/'bin/Release/net8.0/treehammock.dll');self.assertEqual(child['HostSystemTestProof__RunId'],run['id']);self.assertEqual(child['HostSystemTestProof__AssemblySha256'],proof.sha(path));self.assertNotIn(run['host_artifact']['challenge'],json.dumps(run.get('host_runtime',{})))
 def test_stale_main_test_or_changed_reference_is_rejected(self):
  for kind in ['main','tests','reference']:
   run,owner,env=self.make();app=Path(run['checkout'])/'bin/Release/net8.0/treehammock.dll';tests=Path(run['checkout'])/'treehammock.Tests.System/bin/Release/net8.0/treehammock.Tests.System.dll'
   path=app.with_name(app.name+'.proof-id') if kind=='main' else tests.with_name(tests.name+'.proof-id') if kind=='tests' else tests.parent/'treehammock.dll';path.write_text('stale')
   with self.subTest(kind=kind),self.assertRaises(ValueError):owner.proof.prepare(env)
 def test_reused_result_receipts_cannot_be_accepted(self):
  run,owner,env=self.make();(Path(run['artifacts'])/'host/treehammock-system-host-tests.trx').touch()
  with self.assertRaises(ValueError):owner.proof.prepare(env)
 def test_an_unverified_system_url_or_capability_is_rejected(self):
  for key,value in [('TREEHAMMOCK_SYSTEM_BASE_URL','http://localhost:8080'),('ASPNETCORE_ENVIRONMENT','Production'),('SystemTestSettings__TestKey','wrong')]:
   run,owner,env=self.make();env[key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):owner.proof.prepare(env)
 def test_trx_rejects_missing_failed_duplicate_and_external_entities(self):
  run,owner,env=self.make();adapter()['result'](Path(run['checkout']),env);path=Path(run['artifacts'])/'host/treehammock-system-host-tests.trx';names=proof.expected_tests(Path(run['checkout']));data=path.read_text();self.assertEqual(proof.validate_trx(path,names)['executed_tests'],len(names))
  for changed in [data.replace('outcome="Passed"','outcome="Failed"',1),data.replace(next(iter(names)),'unrelated',1),'<!DOCTYPE TestRun [<!ENTITY x SYSTEM "file:///private">]>'+data]:
   path.write_text(changed)
   with self.assertRaises(ValueError):proof.validate_trx(path,names)
 def test_linked_identity_probe_is_in_the_expected_system_inventory(self):self.assertIn('Loaded_test_and_application_share_the_requested_configuration',proof.expected_tests(ROOT))
 def test_startup_budget_rejects_unbounded_values(self):
  for value in ['0','1801','NaN']:
   with self.assertRaises(ValueError):proof.startup_seconds({'TREEHAMMOCK_HOST_STARTUP_TIMEOUT_SECONDS':value})

@unittest.skipUnless(sys.platform.startswith('linux'),'Linux actual Bash/supervisor/loopback test; native Windows remains separate')
class HostTargetRuns(unittest.TestCase):
 setUp=fixtures.ControlledRuns.setUp
 tearDown=fixtures.ControlledRuns.tearDown
 invoke=fixtures.ControlledRuns.invoke
 state_value=fixtures.ControlledRuns.state_value
 def install(self):
  binary=self.binary/'dotnet';binary.write_text('#!'+sys.executable+'\n'+ADAPTER.read_text());binary.chmod(0o755)
 def host(self,**settings):self.install();return self.invoke('docker-host-system-stack-tests',dict(self.env,TREEHAMMOCK_HOST_STARTUP_TIMEOUT_SECONDS='5',**settings))
 def latest(self):return json.loads(max((self.root/'.docker/test-runs').glob('*/ownership.json'),key=lambda p:p.stat().st_mtime).read_text())
 def test_actual_wrapper_proves_direct_proxy_binary_process_and_fresh_trx(self):
  result=self.host();self.assertEqual(result.returncode,0,result.stderr);run=self.latest();value=json.loads((Path(run['artifacts'])/'host/proof.json').read_text());self.assertEqual(value['status'],'Passed');self.assertEqual(value['run_id'],run['id']);self.assertGreater(value['executed_tests'],0);self.assertNotIn(run['host_artifact']['challenge'],json.dumps(value));self.assertEqual(self.state_value()['resources'],self.sentinel)
 def test_wrong_proxy_target_or_runtime_hash_fails_and_preserves_developer_state(self):
  for settings in [dict(COR23AA_PROXY_WRONG='true'),dict(COR23AA_WRONG_HASH='true')]:
   result=self.host(**settings);self.assertEqual(result.returncode,1,result.stderr);self.assertEqual(self.state_value()['resources'],self.sentinel)
 def test_api_startup_exception_preserves_its_nonzero_exit(self):
  result=self.host(COR23Z_DOTNET_FAIL='run');self.assertEqual(result.returncode,47,result.stderr);self.assertEqual(self.state_value()['resources'],self.sentinel)
 def test_api_exit_during_tests_aborts_tests_even_when_exit_is_zero(self):
  for code in ['0','47']:
   start=time.monotonic();result=self.host(COR23AA_API_EXIT_DELAY='.8',COR23AA_API_EXIT_CODE=code,COR23AA_TEST_DELAY='10');self.assertEqual(result.returncode,1 if code=='0' else 47,result.stderr);self.assertLess(time.monotonic()-start,8);self.assertEqual(self.state_value()['resources'],self.sentinel)
 def test_api_exit_during_readiness_retains_the_api_failure(self):
  result=self.host(COR23AA_API_EXIT_DELAY='.2',COR23AA_API_EXIT_CODE='47',COR23Z_READINESS_FAIL='true');self.assertEqual(result.returncode,47,result.stderr);self.assertEqual(self.state_value()['resources'],self.sentinel)
 def test_proxy_target_changed_during_tests_aborts_the_proof(self):
  start=time.monotonic();result=self.host(COR23AA_PROXY_SWAP_DELAY='.8',COR23AA_TEST_DELAY='10');self.assertEqual(result.returncode,1,result.stderr);self.assertLess(time.monotonic()-start,8);self.assertEqual(self.state_value()['resources'],self.sentinel)
 def test_aggregate_startup_budget_cannot_be_reset_by_readiness_retries(self):
  self.install();start=time.monotonic();result=self.invoke('docker-host-system-stack-tests',dict(self.env,TREEHAMMOCK_HOST_STARTUP_TIMEOUT_SECONDS='2',COR23Z_READINESS_FAIL='true'));self.assertEqual(result.returncode,124,result.stderr);self.assertLess(time.monotonic()-start,7);self.assertEqual(self.state_value()['resources'],self.sentinel)
 def test_prelaunch_docker_context_call_consumes_the_same_startup_budget(self):
  self.install();start=time.monotonic();result=self.invoke('docker-host-system-stack-tests',dict(self.env,TREEHAMMOCK_HOST_STARTUP_TIMEOUT_SECONDS='2',COR23Z_HANG='context show'));self.assertEqual(result.returncode,124,result.stderr);self.assertLess(time.monotonic()-start,7);self.assertEqual(self.state_value()['resources'],self.sentinel)
 def test_successful_native_exit_without_complete_fresh_results_is_not_green(self):
  for settings in [dict(COR23AA_NO_RESULTS='true'),dict(COR23AA_MISSING_TEST='true')]:
   result=self.host(**settings);self.assertNotEqual(result.returncode,0,result.stderr);self.assertEqual(self.state_value()['resources'],self.sentinel)
 def test_live_old_listener_is_preserved_and_blocks_acquisition(self):
  with socket.socket() as old:
   old.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);old.bind(('127.0.0.1',8080));old.listen();result=self.host();self.assertNotEqual(result.returncode,0);self.assertEqual(old.getsockname()[1],8080);self.assertEqual(self.state_value()['resources'],self.sentinel)

class HostProofSourceGuard(unittest.TestCase):
 def load(self):
  spec=importlib.util.spec_from_file_location('host_guard',ROOT/'eng/check-host-system-proof.py');guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard);return guard
 def test_guard_is_consistency_only(self):self.assertEqual(self.load().validate(ROOT)['qualification'],'NotRun')
 def test_unprotected_identity_route_is_rejected(self):
  import tempfile,shutil
  with tempfile.TemporaryDirectory() as folder:
   root=Path(folder)/'source';owned.snapshot(ROOT,root);path=root/'Controllers/SystemTestIdentityController.cs';path.write_text(path.read_text().replace('capability.Authorizes(Request)','true'))
   with self.assertRaises(ValueError):self.load().validate(root)
 def test_missing_continuous_monitor_cannot_pass_guard(self):
  import tempfile
  with tempfile.TemporaryDirectory() as folder:
   root=Path(folder)/'source';owned.snapshot(ROOT,root);path=root/'eng/test-ownership.py';path.write_text(path.read_text().replace('lifecycle.proof.tick()','0'))
   with self.assertRaises(ValueError):self.load().validate(root)

class BoundHttpAttempts(unittest.TestCase):
 def test_redirected_identity_is_rejected_without_following_it(self):
  class Response:
   status=302
   def close(self):pass
  class Socket:
   def shutdown(self,*args):pass
  class Connection:
   sock=Socket()
   def __init__(self,*a,**k):pass
   def connect(self):pass
   def request(self,*a,**k):pass
   def close(self):pass
   def getresponse(self):return Response()
  with patch.object(proof.http.client,'HTTPConnection',Connection),self.assertRaises(ValueError):proof.fetch(proof.DIRECT,'/__system-test/identity','private',.2)
 def test_slow_dripping_headers_have_one_absolute_attempt_deadline(self):
  import threading
  # Real TCP worker drips bytes often enough to defeat per-recv timeout alone.
  server=socket.socket();server.bind(('127.0.0.1',0));server.listen();port=server.getsockname()[1]
  def drip():
   connection,_=server.accept()
   with connection:
    connection.recv(8192)
    try:
     for byte in b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}':connection.send(bytes([byte]));time.sleep(.04)
    except OSError:pass
  worker=threading.Thread(target=drip,daemon=True);worker.start();real=proof.http.client.HTTPConnection
  def redirected(host,port_argument,**kwargs):return real('127.0.0.1',port,**kwargs)
  start=time.monotonic()
  try:
   with patch.object(proof.http.client,'HTTPConnection',redirected),self.assertRaises((OSError,ValueError,proof.http.client.HTTPException)):proof.fetch(proof.DIRECT,'/__system-test/identity','private',.2)
   self.assertLess(time.monotonic()-start,1)
  finally:server.close();worker.join(timeout=1)
