"""Read-only preflight behavior; controlled command replies are not native qualification."""
import importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import test_test_ownership as fixtures
owned=fixtures.owned;pre=owned.prerequisites;ROOT=fixtures.ROOT
class HostPrerequisites(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='host prerequisites ');self.root=Path(self.temp.name)/'checkout with spaces';shutil.copytree(ROOT,self.root,ignore=shutil.ignore_patterns(*owned.IGNORE));self.env=dict(os.environ);self.calls=[]
 def tearDown(self):self.temp.cleanup()
 def response(self,argv,**kwargs):
  self.calls.append(argv)
  args=argv[1:]
  value=''
  if args[:1]==['/user']:value='"test user","S-1-5-21-100"'
  elif '-Command' in args:value=json.dumps(dict(PSEdition='Core',Major=7,Minor=4))
  elif args[:1]==['-c']:value='5'
  elif args[:2]==['context','show']:value='local-test'
  elif args[:2]==['context','inspect']:value='unix:///var/run/docker.sock'
  elif args[:1]==['version']:value='28.1.0'
  elif args[:1]==['info']:value=json.dumps(dict(OSType='linux',OperatingSystem='Linux'))
  elif args[:2]==['compose','version']:value='2.32.0'
  elif args[:1]==['compose']:value=json.dumps(dict(services={name:{} for name in ('postgres','dragonfly','haproxy-host')}))
  elif args==['--list-sdks']:value='8.0.400 [SDK with spaces]'
  elif args==['--list-runtimes']:value='Microsoft.NETCore.App 8.0.10 [runtime]\nMicrosoft.AspNetCore.App 8.0.10 [runtime]'
  return subprocess.CompletedProcess(argv,0,value,'')
 def resolve(self,name,**kwargs):return '/selected host with spaces/'+Path(name).name
 def check(self,entry='docker-host-system-stack-tests.ps1'):
  return pre.check(self.root,entry,'pwsh',self.env,owned.Deadline(10))
 def test_selected_pwsh_child_is_exact_and_space_path_is_one_argument(self):
  with patch.object(pre.shutil,'which',side_effect=self.resolve),patch.object(pre.subprocess,'run',side_effect=self.response):env=self.check()
  audit=self.calls[-1];self.assertEqual(audit[0],'/selected host with spaces/pwsh');self.assertEqual(audit[-1],str(self.root/'eng/check-locks.ps1'));self.assertNotIn('-ExecutionPolicy',audit);self.assertEqual(env['TREEHAMMOCK_POWERSHELL_HOST'],audit[0]);self.assertEqual(env['DOCKER_CONTEXT'],'local-test');self.assertFalse((self.root/'.docker').exists());self.assertFalse((self.root/'artifacts').exists())
 def test_missing_tool_fails_before_owned_acquisition(self):
  for missing in ['docker','dotnet','pwsh']:
   with self.subTest(missing=missing),patch.object(pre.shutil,'which',side_effect=lambda name,**kw:None if name==missing else self.resolve(name)),patch.object(pre.subprocess,'run',side_effect=self.response),patch.object(owned,'create_run') as acquire:
    code=owned.execute(self.root,'docker-host-system-stack-tests','docker-host-system-stack-tests.ps1','pwsh',[],self.env)
    self.assertEqual(code,127);acquire.assert_not_called()
 def test_failed_prerequisite_retains_its_exit_code_and_never_acquires(self):
  for target in ['info','compose','--list-sdks','--list-runtimes','-File']:
   def fail(argv,**kw):return subprocess.CompletedProcess(argv,47,'','private diagnostic') if target in argv else self.response(argv,**kw)
   with self.subTest(target=target),patch.object(pre.shutil,'which',side_effect=self.resolve),patch.object(pre.subprocess,'run',side_effect=fail),patch.object(owned,'create_run') as acquire:
    self.assertEqual(owned.execute(self.root,'docker-host-system-stack-tests','docker-host-system-stack-tests.ps1','pwsh',[],self.env),47);acquire.assert_not_called()
 def test_unsupported_platform_and_wsl_fail_without_commands(self):
  for platform,environment in [('darwin',{}),('linux',{'WSL_INTEROP':'test'})]:
   with self.subTest(platform=platform),patch.object(pre.sys,'platform',platform),patch.object(pre.subprocess,'run') as command,self.assertRaisesRegex(pre.Failure,'native Linux or Windows'):
    pre.check(self.root,'host.ps1','pwsh',environment,owned.Deadline(10))
   command.assert_not_called()
 def test_unsupported_powershell_version_is_rejected_before_docker(self):
  def version(argv,**kw):return subprocess.CompletedProcess(argv,0,json.dumps(dict(PSEdition='Desktop',Major=5,Minor=1)),'')
  with patch.object(pre.shutil,'which',side_effect=self.resolve),patch.object(pre.subprocess,'run',side_effect=version),self.assertRaisesRegex(pre.Failure,'PowerShell 7'):
   self.check()
 def test_sdk_runtime_compose_and_remote_engine_are_required(self):
  replacements=[('--list-sdks','7.0.100 [sdk]'),('--list-runtimes','Microsoft.NETCore.App 8.0.0 [runtime]'),('compose','1.29.0'),('inspect','tcp://remote:2375'),('version','27.0.0'),('info','{"OSType":"windows"}')]
  for target,value in replacements:
   def replace(argv,**kw):return subprocess.CompletedProcess(argv,0,value,'') if target in argv else self.response(argv,**kw)
   with self.subTest(target=target),patch.object(pre.shutil,'which',side_effect=self.resolve),patch.object(pre.subprocess,'run',side_effect=replace),self.assertRaises(pre.Failure):self.check()
 def test_required_config_missing_or_invalid_before_acquisition(self):
  path=self.root/'eng/test-ownership-compose.json'
  for content in [None,'{}','invalid']:
   if content is None:path.unlink()
   else:path.write_text(content)
   with self.subTest(content=content),patch.object(pre.shutil,'which',side_effect=self.resolve),patch.object(pre.subprocess,'run',side_effect=self.response),patch.object(owned,'create_run') as acquire:
    self.assertEqual(owned.execute(self.root,'docker-host-system-stack-tests','docker-host-system-stack-tests.ps1','pwsh',[],self.env),2);acquire.assert_not_called()
 def test_preflight_timeout_is_bounded_and_preserves_124(self):
  with patch.object(pre.shutil,'which',side_effect=self.resolve),patch.object(pre.subprocess,'run',side_effect=subprocess.TimeoutExpired('selected host',1)),self.assertRaises(pre.Failure) as caught:self.check()
  self.assertEqual(caught.exception.code,124)
 def test_explicit_context_and_cli_remain_selected(self):
  self.env.update(DOCKER_CONTEXT='chosen',TREEHAMMOCK_DOCKER_CLI='custom-docker')
  with patch.object(pre.shutil,'which',side_effect=self.resolve),patch.object(pre.subprocess,'run',side_effect=self.response):env=self.check()
  self.assertEqual(env['DOCKER_CONTEXT'],'chosen');self.assertTrue(env['TREEHAMMOCK_DOCKER_SELECTED'].endswith('custom-docker'));self.assertFalse(any(argv[1:]==['context','show'] for argv in self.calls))
 def test_windows_policy_is_child_process_only_and_desktop_opt_in_required(self):
  with patch.object(pre.sys,'platform','win32'),patch.object(pre.shutil,'which',side_effect=self.resolve),patch.object(pre.subprocess,'run',side_effect=self.response):
   with self.assertRaisesRegex(pre.Failure,'host networking'):self.check()
   self.env['TREEHAMMOCK_HOST_NETWORKING_CONFIRMED']='true';self.check();self.assertIn('-ExecutionPolicy',self.calls[-1]);self.assertIn('Bypass',self.calls[-1])
 def test_windows_bash_variant_is_explicitly_disabled(self):
  with patch.object(pre.sys,'platform','win32'),patch.object(pre.shutil,'which',side_effect=self.resolve),self.assertRaisesRegex(pre.Failure,'use PowerShell on Windows'):self.check('host.sh')
 def test_acl_uses_explicit_host_and_never_falls_back(self):
  from types import SimpleNamespace
  replies=[]
  def invoke(argv,**kw):
   replies.append(argv);return subprocess.CompletedProcess(argv,0,'"user","S-1-5-21-100"','')
  env={'TREEHAMMOCK_POWERSHELL_HOST':'/chosen host/pwsh.exe','PATH':'controlled'}
  with patch.object(owned.fixture,'os',SimpleNamespace(name='nt',environ=env)),patch.object(owned.fixture.shutil,'which',side_effect=lambda name,**kw:name),patch.object(owned.fixture.subprocess,'run',side_effect=invoke):
   owned.fixture.private_windows(self.root,True,env)
  self.assertEqual(replies[-1][0],env['TREEHAMMOCK_POWERSHELL_HOST'])
  with patch.object(owned.fixture,'os',SimpleNamespace(name='nt',environ=env)),patch.object(owned.fixture.shutil,'which',return_value=None) as resolve,self.assertRaisesRegex(ValueError,'host unavailable'):
   owned.fixture.private_windows(self.root,True,env)
  self.assertEqual(resolve.call_count,1)
 def test_malformed_selected_version_and_compose_render_rejected(self):
  for target in ['-Command','config']:
   def malformed(argv,**kw):return subprocess.CompletedProcess(argv,0,'{}','') if target in argv else self.response(argv,**kw)
   with self.subTest(target=target),patch.object(pre.shutil,'which',side_effect=self.resolve),patch.object(pre.subprocess,'run',side_effect=malformed),self.assertRaises(pre.Failure):self.check()
 def test_bash_version_is_checked_without_legacy_shell_selection(self):
  def old(argv,**kw):return subprocess.CompletedProcess(argv,0,'3','') if '-c' in argv else self.response(argv,**kw)
  with patch.object(pre.shutil,'which',side_effect=self.resolve),patch.object(pre.subprocess,'run',side_effect=old),self.assertRaisesRegex(pre.Failure,'Bash 4'):self.check('host.sh')
 def test_source_guard_is_supplemental(self):
  spec=importlib.util.spec_from_file_location('prerequisite_guard',ROOT/'eng/check-host-prerequisites.py');guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard);self.assertEqual(guard.validate(ROOT)['qualification'],'NotRun')
 @unittest.skipUnless(sys.platform=='linux','actual Linux Bash lock process')
 def test_actual_bash_lock_audit_failure_precedes_any_private_creation(self):
  (self.root/'missing').mkdir()
  (self.root/'missing/project.csproj').write_text('<Project><PackageReference Include="Missing" /></Project>')
  real=subprocess.run;bash=str(Path(shutil.which('bash')).resolve())
  def actor(argv,**kwargs):return real(argv,**kwargs) if argv[0]==bash else self.response(argv,**kwargs)
  with patch.object(pre.shutil,'which',side_effect=lambda name,**kw:bash if name=='bash' else '/controlled/'+name),patch.object(pre.subprocess,'run',side_effect=actor),patch.object(owned,'create_run') as acquire:
   self.assertEqual(owned.execute(self.root,'docker-host-system-stack-tests','docker-host-system-stack-tests.sh','bash',[],self.env),1);acquire.assert_not_called()
if __name__=='__main__':unittest.main()
