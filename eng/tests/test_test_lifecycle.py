"""COR23Z executable lifecycle faults; controlled Docker is not native qualification."""
import importlib.util,io,json,os,signal,subprocess,sys,time,unittest
from pathlib import Path
from unittest.mock import patch
import test_test_ownership as fixtures
owned=fixtures.owned;ROOT=fixtures.ROOT

class LifecycleFiles(unittest.TestCase):
 setUp=fixtures.OwnershipFiles.setUp
 tearDown=fixtures.OwnershipFiles.tearDown
 make=fixtures.OwnershipFiles.make
 def test_manifest_and_cleanup_owner_exist_before_snapshot_failure(self):
  captured=[]
  with patch.object(owned,'snapshot',side_effect=OSError('partial copy')):
   with self.assertRaises(OSError):owned.create_run(self.root,'docker-all-tests',self.env,on_created=captured.append)
  self.assertEqual(len(captured),1);run=captured[0];saved=json.loads(owned.manifest(run).read_text());self.assertEqual(saved['status'],'PreparationFailed');owned.validate_run(saved,owned.manifest(run),inputs=False)
 def test_acquisition_failure_runs_cleanup_and_preserves_preparation_code(self):
  calls=[]
  with patch.object(owned,'snapshot',side_effect=OSError()),patch.object(owned,'cleanup',side_effect=lambda run,*a,**k:calls.append(run) or {'status':'Failed'}):
   code=owned.execute(self.root,'docker-all-tests','docker-all-tests.sh','bash',[],self.env)
  self.assertEqual(code,2);self.assertEqual(len(calls),1)
 def test_cleanup_exception_restores_signal_handlers_and_recovery_lease(self):
  old=signal.getsignal(signal.SIGTERM)
  with patch.object(owned,'snapshot',side_effect=OSError()),patch.object(owned,'cleanup',side_effect=OSError()):owned.execute(self.root,'docker-all-tests','docker-all-tests.sh','bash',[],self.env)
  self.assertIs(signal.getsignal(signal.SIGTERM),old);run=json.loads(next((self.root/'.docker/test-runs').glob('*/ownership.json')).read_text());lock=owned.RunLock(run);lock.acquire();lock.release()
 def test_budget_rejects_unbounded_and_invalid_values(self):
  for value in ['0','121','garbage','-1']:
   with self.subTest(value=value),self.assertRaises(ValueError):owned.budget({'TREEHAMMOCK_TEST_CLEANUP_TIMEOUT_SECONDS':value})
 def test_capped_stream_redacts_secret_across_flush_boundary(self):
  run=self.make();secret=run['token'];path=Path(run['artifacts'])/'capped.log'
  data=b'x'*(65536-len(secret)//2)+secret.encode()+b'y'*1100000
  owned.pump_stream(io.BytesIO(data),run,path,False)
  value=path.read_text();self.assertLessEqual(len(value),1048576);self.assertNotIn(secret,value);self.assertIn('[REDACTED]',value)
 def test_recovery_refuses_an_active_coordinator(self):
  run=self.make()
  with self.assertRaises(ValueError):owned.recover(self.root,run['id'],self.env)
 def test_recovery_refuses_a_concurrent_lease_even_with_dead_parent(self):
  run=self.make();lock=owned.RunLock(run);lock.acquire()
  try:
   with patch.object(owned,'alive',return_value=False),self.assertRaises(OSError):owned.recover(self.root,run['id'],self.env)
  finally:lock.release()
 def test_retention_is_preserved_when_process_cleanup_also_failed(self):
  run=self.make();run.update(status='Failed',retained_resources=True);owned.write(owned.manifest(run),run)
  with patch.object(owned,'alive',return_value=False),self.assertRaises(ValueError):owned.recover(self.root,run['id'],self.env)
 def test_process_identity_mismatch_never_signals_unrelated_process(self):
  run=self.make();state=owned.manifest(run).parent/'state.json';owned.write(state,{'status':'Running'})
  with patch.object(owned,'verified_signal') as send:
   self.assertFalse(owned.stop_record({'pid':os.getpid(),'identity':'other-birth','state':str(state)},owned.Deadline(1)))
   send.assert_not_called()
 def test_unsupported_manifest_cannot_recover(self):
  run=self.make();run['schema_version']=1;owned.write(owned.manifest(run),run)
  with patch.object(owned,'alive',return_value=False),self.assertRaises(ValueError):owned.recover(self.root,run['id'],self.env)

@unittest.skipUnless(sys.platform.startswith('linux'),'Linux containment exercised here; Windows job requires native host')
class LifecycleRuns(unittest.TestCase):
 setUp=fixtures.ControlledRuns.setUp
 tearDown=fixtures.ControlledRuns.tearDown
 invoke=fixtures.ControlledRuns.invoke
 state_value=fixtures.ControlledRuns.state_value
 reports=fixtures.ControlledRuns.reports
 def latest(self):return json.loads(sorted((self.root/'.docker/test-runs').glob('*/ownership.json'),key=lambda p:p.stat().st_mtime)[-1].read_text())
 def test_partial_compose_start_is_cleaned_and_original_exit_retained(self):
  result=self.invoke(env=dict(self.env,COR23Z_PARTIAL_START='true'));self.assertEqual(result.returncode,47,result.stderr);self.assertEqual(self.state_value()['resources'],self.sentinel);self.assertEqual(self.reports()[0]['cleanup'],'Passed')
 def test_hung_diagnostics_are_bounded_and_do_not_block_removal(self):
  started=time.monotonic();result=self.invoke(env=dict(self.env,COR23Z_HANG='logs --tail',TREEHAMMOCK_TEST_CLEANUP_TIMEOUT_SECONDS='15'))
  self.assertEqual(result.returncode,0,result.stderr);self.assertLess(time.monotonic()-started,20);self.assertEqual(self.state_value()['resources'],self.sentinel)
 def test_hung_inventory_exhausts_one_budget_and_cannot_turn_success_green(self):
  started=time.monotonic();result=self.invoke(env=dict(self.env,COR23Z_HANG='ps --all',TREEHAMMOCK_TEST_CLEANUP_TIMEOUT_SECONDS='1'))
  self.assertEqual(result.returncode,1);self.assertLess(time.monotonic()-started,5);run=self.latest();self.assertTrue(json.loads((Path(run['artifacts'])/'cleanup.json').read_text())['budget_exhausted'])
 def test_primary_failure_survives_budget_exhaustion(self):
  result=self.invoke(env=dict(self.env,COR23Y_LANE_EXIT='47',COR23Z_HANG='ps --all',TREEHAMMOCK_TEST_CLEANUP_TIMEOUT_SECONDS='1'));self.assertEqual(result.returncode,47)
 def test_retained_debug_is_distinct_and_recovery_requires_explicit_discard(self):
  result=self.invoke(env=dict(self.env,COR23Y_LANE_EXIT='47',TREEHAMMOCK_TEST_RETAIN_FAILED_RESOURCES='true'));self.assertEqual(result.returncode,47);run=self.latest();self.assertEqual(run['status'],'RetainedDebug');self.assertEqual(self.reports()[0]['cleanup'],'RetainedDebug')
  with self.assertRaises(ValueError):owned.recover(self.root,run['id'],self.env)
  self.assertEqual(owned.recover(self.root,run['id'],self.env,True),0);self.assertEqual(self.state_value()['resources'],self.sentinel);self.assertEqual(owned.recover(self.root,run['id'],self.env,True),0)
 def test_process_cleanup_exception_cannot_replace_lane_failure(self):
  with patch.object(owned.Lifecycle,'stop',side_effect=OSError()):
   code=owned.execute(self.root,'docker-http-contracts-direct','docker-http-contracts-direct.sh','bash',[],dict(self.env,COR23Y_LANE_EXIT='47'))
  self.assertEqual(code,47)
 def running(self,lane='docker-all-tests'):
  run=owned.create_run(self.root,lane,self.env);run['status']='Running';owned.write(owned.manifest(run),run);return run,owned.run_environment(run,self.env)
 def test_registration_failure_does_not_release_child_to_acquire_resources(self):
  run,env=self.running();manager=owned.Lifecycle(run);marker=Path(run['artifacts'])/'unauthorized'
  original=owned.write
  def write(path,value):
   if path==owned.manifest(run):raise OSError('receipt commit failed')
   return original(path,value)
  with patch.object(owned,'write',side_effect=write),self.assertRaises(OSError):manager.launch('wrapper',[sys.executable,'-c',f'open({str(marker)!r},"w").close()'],env)
  self.assertEqual(manager.stop(owned.Deadline(8)),[]);manager.children[0][0].stdout.close();self.assertFalse(marker.exists())
 def test_subreaper_stops_detached_grandchild_after_wrapper_exits(self):
  run,env=self.running();manager=owned.Lifecycle(run);marker=Path(run['artifacts'])/'descendant.pid'
  command='import subprocess,sys,time; p=subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"],start_new_session=True); open('+repr(str(marker))+',"w").write(str(p.pid))'
  process=manager.launch('wrapper',[sys.executable,'-c',command],env)
  process.communicate(timeout=10);self.assertEqual(process.returncode,0)
  pid=int(marker.read_text());self.assertIsNone(owned.processes.identity(pid));self.assertEqual(manager.stop(owned.Deadline(5)),[])
 def test_recovery_stops_recorded_api_tree_after_coordinator_loss(self):
  run,env=self.running();manager=owned.Lifecycle(run);marker=Path(run['artifacts'])/'api.pid'
  process=manager.launch('host-api',[sys.executable,'-c','import os,time,signal; signal.signal(signal.SIGTERM,signal.SIG_IGN); open('+repr(str(marker))+',"w").write(str(os.getpid())); time.sleep(60)'],env)
  try:
   until=time.monotonic()+5
   while not marker.exists() and time.monotonic()<until:time.sleep(.02)
   self.assertTrue(marker.exists());run['pid']=999999999;owned.write(owned.manifest(run),run)
   self.assertEqual(owned.recover(self.root,run['id'],dict(self.env,TREEHAMMOCK_TEST_CLEANUP_TIMEOUT_SECONDS='2')),0);process.wait(timeout=3);self.assertIsNone(owned.processes.identity(int(marker.read_text())))
   self.assertEqual(owned.recover(self.root,run['id'],self.env),0)
  finally:manager.stop(owned.Deadline(8))
 def test_host_broker_owns_api_beyond_wrapper_lifetime_and_redacts_logs(self):
  from test_host_system_proof import prepare_environment,ADAPTER
  run,env=self.running('docker-host-system-stack-tests');env=prepare_environment(run,env);env['COR23AA_PRINT_SECRET']='true';env['COR23AA_GRANDCHILD']='true';manager=owned.Lifecycle(run);port=manager.start_broker();env['TREEHAMMOCK_TEST_PROCESS_BROKER_PORT']=port
  fake=self.binary/'dotnet';fake.write_text('#!'+sys.executable+'\n'+ADAPTER.read_text());fake.chmod(0o755)
  helper=Path(run['checkout'])/'eng/test-ownership.py'
  try:
   result=subprocess.run([sys.executable,str(helper),'api-start'],env=env,cwd=run['checkout'],capture_output=True,text=True,timeout=10);self.assertEqual(result.returncode,0,result.stderr)
   time.sleep(.2);result=subprocess.run([sys.executable,str(helper),'api-stop'],env=env,cwd=run['checkout'],capture_output=True,text=True,timeout=12);self.assertEqual(result.returncode,0,result.stderr)
   self.assertEqual(manager.stop(owned.Deadline(8)),[]);log=(Path(run['artifacts'])/'host/api.out.log').read_text();self.assertNotIn(run['token'],log);self.assertIn('[REDACTED]',log)
  finally:manager.stop(owned.Deadline(8))
 def test_interrupt_during_acquisition_preserves_interrupt_code(self):
  original=owned.snapshot
  def interrupt(source,target):os.kill(os.getpid(),signal.SIGINT);original(source,target)
  with patch.object(owned,'snapshot',side_effect=interrupt):code=owned.execute(self.root,'docker-http-contracts-direct','docker-http-contracts-direct.sh','bash',[],self.env)
  self.assertEqual(code,130);self.assertEqual(self.state_value()['resources'],self.sentinel)

class LifecycleSourceGuard(unittest.TestCase):
 def test_guard_reports_source_consistency_only(self):
  spec=importlib.util.spec_from_file_location('lifecycle_guard',ROOT/'eng/check-test-lifecycle.py');guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard);self.assertEqual(guard.validate(ROOT)['qualification'],'NotRun')

@unittest.skipUnless(sys.platform.startswith('linux'),'Actual Bash Linux host coordination; native SDK/Windows qualification separate')
class HostAcquisitionFaults(unittest.TestCase):
 setUp=fixtures.ControlledRuns.setUp
 tearDown=fixtures.ControlledRuns.tearDown
 state_value=fixtures.ControlledRuns.state_value
 invoke=fixtures.ControlledRuns.invoke
 def test_host_startup_restore_build_readiness_and_test_failures_clean_up(self):
  # Use the actual host wrapper and broker, with controlled executables and a
  # shortened readiness timeout. Preserve wrapper structure and finally behavior.
  from test_host_system_proof import ADAPTER
  dotnet=self.binary/'dotnet';dotnet.write_text('#!'+sys.executable+'\n'+ADAPTER.read_text());dotnet.chmod(0o755)
  for phase in ['compose','restore','build','run','readiness','test']:
   env=dict(self.env,TREEHAMMOCK_HOST_STARTUP_TIMEOUT_SECONDS='3')
   if phase=='compose':env['COR23Z_PARTIAL_START']='true'
   elif phase=='readiness':env['COR23Z_READINESS_FAIL']='true'
   else:env['COR23Z_DOTNET_FAIL']=phase
   # AA's monitor now retains the API's 47 instead of accepting another listener.
   with self.subTest(phase=phase):
    result=self.invoke('docker-host-system-stack-tests',env=env);self.assertEqual(result.returncode,124 if phase=='readiness' else 47,result.stderr);self.assertEqual(self.state_value()['resources'],self.sentinel)
    run=json.loads(max((self.root/'.docker/test-runs').glob('*/ownership.json'),key=lambda p:p.stat().st_mtime).read_text());self.assertEqual(json.loads((Path(run['artifacts'])/'run.json').read_text())['cleanup'],'Passed')
    marker=Path(run['artifacts'])/'api.pid'
    if marker.exists():self.assertIsNone(owned.processes.identity(int(marker.read_text())))
