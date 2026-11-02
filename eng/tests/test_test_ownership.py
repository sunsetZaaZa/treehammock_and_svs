"""Actual run/copy/lease/process/shell behavior with a controlled Docker adapter."""
import concurrent.futures,importlib.util,json,os
from pathlib import Path
import shutil,signal,socket,subprocess,sys,tempfile,time,unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('test_ownership',ROOT/'eng/test-ownership.py');owned=importlib.util.module_from_spec(spec);spec.loader.exec_module(owned)
class OwnershipFiles(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'source with spaces';self.root.mkdir();(self.root/'eng').mkdir()
  for name in ['test-ownership.py','test-ownership-compose.json','fixture-isolation.py']:shutil.copy2(ROOT/'eng'/name,self.root/'eng'/name)
  (self.root/'developer.txt').write_text('untouched');self.env=dict(os.environ)
 def tearDown(self):self.temp.cleanup()
 def make(self,lane='docker-all-tests'):return owned.create_run(self.root,lane,self.env)
 def test_fresh_project_ignores_developer_compose_identity(self):
  self.env['COMPOSE_PROJECT_NAME']='developer-sentinel';run=self.make();self.assertTrue(run['project'].startswith('treehammock-test-'));self.assertNotEqual(run['project'],'developer-sentinel')
 def test_parallel_runs_have_distinct_projects_keys_outputs_and_overrides(self):
  with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:runs=list(pool.map(lambda _:self.make(),range(4)))
  for key in ['id','project','checkout','artifacts','override','images_override']:self.assertEqual(len({run[key] for run in runs}),4)
  files=[Path(run['credential_file']).read_text() for run in runs];self.assertEqual(len(set(files)),4)
 def test_private_checkout_does_not_modify_or_copy_developer_outputs(self):
  (self.root/'obj').mkdir();(self.root/'obj/caller.dll').write_text('caller');run=self.make();checkout=Path(run['checkout']);(checkout/'developer.txt').write_text('test mutation');self.assertEqual((self.root/'developer.txt').read_text(),'untouched');self.assertFalse((checkout/'obj').exists())
 def test_owner_token_is_not_in_artifact_or_compose_output(self):
  run=self.make();self.assertNotIn(run['token'],Path(run['override']).read_text());self.assertEqual(list(Path(run['artifacts']).rglob('*.json')),[])
 def test_private_manifest_permissions(self):
  if os.name=='nt':self.skipTest('Windows ACL qualification is native')
  run=self.make();self.assertEqual(owned.manifest(run).stat().st_mode&0o777,0o600);self.assertEqual(owned.manifest(run).parent.stat().st_mode&0o777,0o700)
 def running(self):
  run=self.make();run['status']='Running';owned.write(owned.manifest(run),run);return run,owned.run_environment(run,self.env)
 def test_nested_lanes_reuse_one_verified_run(self):
  run,env=self.running()
  for lane in owned.LANES[:5]:self.assertEqual(owned.joined(Path(run['checkout']),env,lane)['id'],run['id'])
 def test_missing_or_wrong_token_cannot_join(self):
  run,env=self.running()
  for token in ['', 'wrong']:
   env['TREEHAMMOCK_TEST_RUN_TOKEN']=token
   with self.assertRaises(ValueError):owned.joined(Path(run['checkout']),env,'docker-sql-contracts')
 def test_sibling_source_project_or_daemon_cannot_join(self):
  run,env=self.running()
  with self.assertRaises(ValueError):owned.joined(self.root,env,'docker-sql-contracts')
  for name,value in [('COMPOSE_PROJECT_NAME','developer'),('DOCKER_HOST','tcp://other'),('TREEHAMMOCK_TEST_ARTIFACT_ROOT','/unowned')]:
   with self.subTest(name=name),self.assertRaises(ValueError):owned.joined(Path(run['checkout']),dict(env,**{name:value}),'docker-sql-contracts')
 def test_single_lane_cannot_borrow_another_lane_or_host_lease(self):
  run=self.make('docker-sql-contracts');run['status']='Running';owned.write(owned.manifest(run),run);env=owned.run_environment(run,self.env)
  with self.assertRaises(ValueError):owned.joined(Path(run['checkout']),env,'docker-system-stack-tests')
  run,env=self.running()
  with self.assertRaises(ValueError):owned.joined(Path(run['checkout']),env,'docker-host-system-stack-tests')
 def test_arbitrary_project_file_volume_service_and_image_arguments_rejected(self):
  for args in [['-p','developer'],['--project-name=developer'],['-f','other.yml'],['--env-file','other.env'],['--volume','/:/src'],['postgres'],['--profile','host-system']]:
   with self.subTest(args=args),self.assertRaises(ValueError):owned.arguments('docker-system-stack-tests',args)
  with self.assertRaises(ValueError):owned.arguments('docker-unit-tests',['--image','developer:test'])
  owned.arguments('docker-unit-tests',['--configuration','Release','--no-cache','--progress','plain'])
 def test_source_links_fail_before_a_writable_checkout_can_escape(self):
  if os.name=='nt':self.skipTest('Host symlink permissions differ')
  (self.root/'redirect').symlink_to(self.root/'developer.txt')
  with self.assertRaises(ValueError):self.make()
 def test_generated_override_has_only_owned_mode_services_and_output_mounts(self):
  run=self.make();value=json.loads(Path(run['override']).read_text());self.assertNotIn('haproxy-host',value['services']);self.assertEqual(value['services']['system-tests']['volumes'][0]['source'],str(Path(run['artifacts'])/'compose-proof'))
  host=self.make('docker-host-system-stack-tests');value=json.loads(Path(host['override']).read_text());self.assertEqual(set(value['services']),{'postgres','dragonfly','haproxy-host'})
 def test_ci_identity_requires_complete_exact_job(self):
  with self.assertRaises(ValueError):owned.ci_identity({'GITHUB_ACTIONS':'true','GITHUB_RUN_ID':'1'})
  first={'GITLAB_CI':'true','CI_PROJECT_ID':'1','CI_PIPELINE_ID':'2','CI_JOB_ID':'3'};second=dict(first,CI_JOB_ID='4');self.assertNotEqual(owned.ci_identity(first),owned.ci_identity(second))
 def test_lease_rejects_another_holder_and_releases_without_unlinking(self):
  with patch.object(owned,'tempfile_directory',return_value=self.temp.name):
   first=owned.HostLease();second=owned.HostLease()
   # Use the actual OS lease, while removing environment-dependent port checks.
   with patch.object(owned.socket,'socket'):
    first.acquire()
    try:
     with self.assertRaises((OSError,ValueError)):second.acquire()
    finally:first.release()
    second.acquire();second.release()
   self.assertTrue((Path(self.temp.name)/'treehammock-host-fixture.lease').exists())
 def test_lease_preserves_an_unrelated_listening_service(self):
  with socket.socket() as service:
   service.bind(('127.0.0.1',0));port=service.getsockname()[1];service.listen()
   real_socket=socket.socket
   class Probe:
    def __enter__(self):self.socket=real_socket();return self
    def __exit__(self,*_):self.socket.close()
    def setsockopt(self,*args):self.socket.setsockopt(*args)
    def bind(self,address):self.socket.bind((address[0],port))
   with patch.object(owned,'tempfile_directory',return_value=self.temp.name),patch.object(owned.socket,'socket',Probe):
    lease=owned.HostLease()
    with self.assertRaises(OSError):lease.acquire()
   self.assertEqual(service.getsockname()[1],port)
@unittest.skipIf(os.name=='nt','Controlled adapter uses POSIX file locking; real Windows harness is authored separately')
class ControlledRuns(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.folder=Path(self.temp.name);self.root=self.folder/'source';shutil.copytree(ROOT,self.root,ignore=shutil.ignore_patterns(*owned.IGNORE));self.binary=self.folder/'bin';self.binary.mkdir();docker=self.binary/'docker';docker.write_text('#!'+sys.executable+'\n'+(ROOT/'eng/tests/fixtures/docker-runtime/docker_adapter.py.txt').read_text());docker.chmod(0o755)
  for script in (self.root/'eng').glob('*.sh'):script.chmod(script.stat().st_mode|0o111)
  self.state=self.folder/'docker.json';self.started=self.folder/'started';self.started.mkdir();self.env=dict(os.environ,PATH=str(self.binary)+os.pathsep+os.environ['PATH'],COR23Y_STATE=str(self.state),COMPOSE_PROJECT_NAME='developer',COR23Y_STARTED=str(self.started))
  self.sentinel={'developer-volume':dict(kind='volume',Name='developer-volume',Labels={'com.docker.compose.project':'developer'},sentinel='preserve-me')};self.state.write_text(json.dumps({'resources':self.sentinel,'calls':[]}));self.environment_patch=patch.dict(os.environ,self.env);self.environment_patch.start()
 def tearDown(self):self.environment_patch.stop();self.temp.cleanup()
 def invoke(self,lane='docker-http-contracts-direct',env=None,args=None):return subprocess.run(['bash',str(self.root/'eng'/f'{lane}.sh'),*(args or [])],cwd=self.root,env=env or self.env,text=True,capture_output=True,timeout=30)
 def state_value(self):return json.loads(self.state.read_text())
 def reports(self):return [json.loads(path.read_text()) for path in (self.root/'artifacts/test-runs').glob('*/run.json')]
 def test_actual_wrapper_success_preserves_developer_state_and_cleans_owned_resources(self):
  result=self.invoke();self.assertEqual(result.returncode,0,result.stderr);state=self.state_value();self.assertEqual(state['resources'],self.sentinel);self.assertEqual(len(self.reports()),1)
  manifest=json.loads(next((self.root/'.docker/test-runs').glob('*/ownership.json')).read_text());self.assertEqual(manifest['docker_environment'].get('DOCKER_CONTEXT'),'controlled')
  self.assertTrue(all('down' not in call['args'] and 'prune' not in call['args'] for call in state['calls']))
  for call in state['calls']:
   if call['args'][:1]==['compose'] and any(x in call['args'] for x in ['config','run','up']):self.assertNotEqual(call['args'][call['args'].index('-p')+1],'developer')
 def test_all_test_children_share_one_identity_and_isolated_checkout(self):
  result=self.invoke('docker-all-tests');self.assertEqual(result.returncode,0,result.stderr);calls=self.state_value()['calls'];run_ids={c['run_id'] for c in calls if c['run_id']};self.assertEqual(len(run_ids),1);self.assertEqual(len(self.reports()),1);self.assertTrue(all(c['cwd']!=str(self.root) for c in calls));self.assertEqual(self.state_value()['resources'],self.sentinel)
 def test_lane_failure_preserves_its_code_after_owned_cleanup(self):
  result=self.invoke(env=dict(self.env,COR23Y_LANE_EXIT='47'));self.assertEqual(result.returncode,47);self.assertEqual(self.reports()[0]['exit_code'],47);self.assertEqual(self.state_value()['resources'],self.sentinel)
 def test_cleanup_failure_cannot_hide_primary_failure_or_turn_success_green(self):
  for primary in ['0','47']:
   result=self.invoke(env=dict(self.env,COR23Y_LANE_EXIT=primary,COR23Y_CLEANUP_FAIL='true'));self.assertEqual(result.returncode,47 if primary=='47' else 1)
 def test_failed_outcome_write_retains_primary_and_cannot_turn_success_green(self):
  for primary in ['0','47']:
   env=dict(self.env,COR23Y_LANE_EXIT=primary)
   with patch.object(owned,'report',side_effect=OSError('controlled diagnostic failure')):
    code=owned.execute(self.root,'docker-http-contracts-direct',str(self.root/'eng/docker-http-contracts-direct.sh'),'bash',[],env)
   self.assertEqual(code,47 if primary=='47' else 1)
   self.assertEqual(self.state_value()['resources'],self.sentinel)
 def test_publication_or_project_override_fails_before_any_docker_operation(self):
  result=self.invoke(args=['--project-name','developer']);self.assertEqual(result.returncode,2);self.assertEqual(self.state_value()['calls'],[])
 def test_edited_ownership_labels_are_refused_before_removal(self):
  run=owned.create_run(self.root,'docker-all-tests',self.env);name=run['project']+'_foreign';state=self.state_value();state['resources'][name]=dict(kind='volume',Name=name,Labels={owned.OWNER:run['id'],owned.PROJECT:'sibling',owned.ROLE:'disposable-test'},sentinel='wrong-project');self.state.write_text(json.dumps(state))
  result=owned.cleanup(run);self.assertEqual(result['status'],'Failed');self.assertIn(name,self.state_value()['resources'])
 def test_graph_rejects_unowned_labels_external_state_and_wildcard_ports(self):
  run=owned.create_run(self.root,'docker-all-tests',self.env);value=json.loads(owned.docker(run,owned.compose(run)+['config','--format','json']).stdout);owned.validate_graph(run,value)
  for mutate in ['labels','external','ports']:
   graph=json.loads(json.dumps(value))
   if mutate=='labels':graph['services']['api']['labels'][owned.OWNER]='sibling'
   elif mutate=='external':graph['volumes']['treehammock-postgres-data']['external']=True
   else:graph['services']['api']['ports']=[dict(host_ip='0.0.0.0',target=5001)]
   with self.assertRaises(ValueError):owned.validate_graph(run,graph)
 def test_parallel_runs_and_cancellation_preserve_the_other_run(self):
  env=dict(self.env,COR23Y_WAIT='true');processes=[subprocess.Popen(['bash',str(self.root/'eng/docker-http-contracts-direct.sh')],cwd=self.root,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE) for _ in range(2)]
  try:
   deadline=time.monotonic()+15
   while len(list(self.started.iterdir()))<2:
    if time.monotonic()>deadline:raise AssertionError('Controlled lanes did not both start')
    time.sleep(.05)
   initial=self.state_value();owners={r.get('Labels',r.get('Config',{}).get('Labels',{})).get(owned.OWNER) for r in initial['resources'].values()}-{None};self.assertEqual(len(owners),2)
   processes[0].terminate();processes[0].communicate(timeout=15)
   state=self.state_value();remaining={r.get('Labels',r.get('Config',{}).get('Labels',{})).get(owned.OWNER) for r in state['resources'].values()}-{None};self.assertEqual(len(remaining),1);self.assertEqual(processes[0].returncode,143);self.assertIsNone(processes[1].poll());self.assertEqual(state['resources']['developer-volume'],self.sentinel['developer-volume'])
  finally:
   for process in processes:
    if process.poll() is None:process.terminate()
    process.communicate(timeout=15)
  self.assertEqual(self.state_value()['resources'],self.sentinel)
 def test_run_output_redacts_generated_credentials_and_private_capability(self):
  result=self.invoke(env=dict(self.env,COR23Y_PRINT_CREDENTIALS='true'));self.assertEqual(result.returncode,0)
  run=json.loads(next((self.root/'.docker/test-runs').glob('*/ownership.json')).read_text());values=owned.redactions(run);log=(Path(run['artifacts'])/'runner.log').read_text()
  self.assertIn('[REDACTED]',result.stdout)
  for value in values:self.assertNotIn(value,result.stdout);self.assertNotIn(value,log)
 def test_failed_diagnostics_do_not_prevent_owned_removal(self):
  result=self.invoke(env=dict(self.env,COR23Y_FAIL='logs --tail'));self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(self.state_value()['resources'],self.sentinel)
 def test_undeclared_service_definition_is_not_treated_as_renderable(self):
  run=owned.create_run(self.root,'docker-all-tests',self.env)
  # Omitting CI-system would leave the shared override's system service undefined.
  args=['compose','-p',run['project'],'--env-file',run['credential_file'],'-f',str(Path(run['checkout'])/'docker-compose.integration.yml'),'-f',run['override'],'config','--format','json']
  with self.assertRaises(ValueError):owned.docker(run,args)
 def test_ci_cleanup_cannot_remove_a_different_job_run(self):
  env=dict(self.env,GITLAB_CI='true',CI_PROJECT_ID='1',CI_PIPELINE_ID='2',CI_JOB_ID='3');run=owned.create_run(self.root,'docker-all-tests',env);name=run['project']+'_sentinel';state=self.state_value();state['resources'][name]=dict(kind='volume',Name=name,Labels=owned.labels(run));self.state.write_text(json.dumps(state))
  with patch.object(owned,'alive',return_value=False):self.assertEqual(owned.cleanup_ci(self.root,dict(env,CI_JOB_ID='4')),0)
  self.assertIn(name,self.state_value()['resources'])

class SourceOwnershipGuard(unittest.TestCase):
 def test_source_guard_is_not_native_qualification(self):
  spec=importlib.util.spec_from_file_location('ownership_guard',ROOT/'eng/check-test-ownership.py');guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard);self.assertEqual(guard.validate(ROOT)['qualification'],'NotRun')
 def test_shared_project_reset_or_missing_project_is_rejected(self):
  spec=importlib.util.spec_from_file_location('ownership_guard_mutation',ROOT/'eng/check-test-ownership.py');guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard)
  with tempfile.TemporaryDirectory() as temporary:
   root=Path(temporary)/'source';shutil.copytree(ROOT,root,ignore=shutil.ignore_patterns(*owned.IGNORE));file=root/'eng/docker-system-stack-tests.sh';original=file.read_text()
   for text in [original.replace('docker compose -p "$COMPOSE_PROJECT_NAME"','docker compose'),original+'\ndocker compose down --volumes\n']:
    file.write_text(text)
    with self.assertRaises(ValueError):guard.validate(root)
 def test_default_ci_teardown_cannot_replace_owned_cleanup(self):
  spec=importlib.util.spec_from_file_location('ownership_ci_guard',ROOT/'eng/check-test-ownership.py');guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard)
  with tempfile.TemporaryDirectory() as temporary:
   root=Path(temporary)/'source';shutil.copytree(ROOT,root,ignore=shutil.ignore_patterns(*owned.IGNORE));file=root/'.gitlab/ci/pipelines/docker-system.yml';file.write_text(file.read_text().replace('python3 eng/test-ownership.py cleanup-ci','docker compose down --volumes'))
   with self.assertRaises(ValueError):guard.validate(root)
