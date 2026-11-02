"""Source mutation/Lua shim witnesses only; no native cache/transport results."""
import importlib.util,shutil,tempfile,unittest,json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('health',ROOT/'eng/check-provider-health.py');health=importlib.util.module_from_spec(spec);spec.loader.exec_module(health)
SERVICE='Rigging/Delivery/ProviderHealth.cs';ACQUIRE='Rigging/Abuse/Scripts/provider-health-acquire-v1.lua';COMPLETE='Rigging/Abuse/Scripts/provider-health-complete-v1.lua'
class ProviderHealthTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'source';shutil.copytree(ROOT,self.root,ignore=shutil.ignore_patterns('.git','bin','obj','.artifacts','.correction-results','TestResults','__pycache__'))
 def tearDown(self):self.temp.cleanup()
 def reject(self,path,old,new):
  p=self.root/path;s=p.read_text();self.assertIn(old,s);p.write_text(s.replace(old,new,1))
  with self.assertRaises(ValueError):health.validate(self.root)
 def test_consistent_source_is_not_native_qualification(self):self.assertEqual('NotRun',health.validate(self.root)['qualification'])
 def test_no_old_channel_cooldown(self):self.reject('Services/DeliveryAbuseThrottleService.cs','string method = NormalizeMethod(request.DeliveryMethod);','string method = NormalizeMethod(request.DeliveryMethod); // GetCooldownAsync')
 def test_account_budget_preserved(self):self.reject('Services/DeliveryAbuseThrottleService.cs','AbuseCounterDimension.Account','AbuseCounterDimension.DeliveryMethod')
 def test_versioned_route_namespace(self):self.reject(SERVICE,'"delivery:health:v1:"','"providerfailure-"')
 def test_user_specific_route_forbidden(self):self.reject(SERVICE,'private readonly string[] _keys;','private readonly string[] _keys; // Destination')
 def test_server_clock_required(self):self.reject(ACQUIRE,"redis.call('TIME')",'{100,0}')
 def test_single_probe_required(self):self.reject(ACQUIRE,'untilProbe > now','false')
 def test_capacity_bound_required(self):self.reject(ACQUIRE,'for slot=1,slots do','for slot=1,999999 do')
 def test_epoch_fence_required(self):self.reject(COMPLETE,"redis.call('HGET',key,'generation') ~= gen",'false')
 def test_exact_permit_fence_required(self):self.reject(COMPLETE,'~= permit','== false')
 def test_neutral_failures_cannot_increment(self):self.reject(COMPLETE,'elseif evidence==2 then','else')
 def test_only_healthy_probe_closes(self):self.reject(COMPLETE,'if evidence==1 then','if evidence~=2 then')
 def test_state_expires(self):self.reject(COMPLETE,"redis.call('PEXPIRE',key,window+opened+lease)",'-- no expiry')
 def test_sms_cannot_skip_health(self):self.reject('Services/SmsSender.cs','!permit.Allowed','false')
 def test_unknown_cannot_fallback(self):self.reject('Services/SmsSender.cs','if(result.Succeeded || !result.CanFallback) return result;','if(result.Succeeded) return result;')
 def test_cancelled_smtp_is_not_outage(self):self.reject('Services/SMTPService.cs','!token.IsCancellationRequested &&','true &&')
 def test_report_failure_cannot_replace_receipt(self):self.reject(SERVICE,'catch(Exception){Metric(permit.Key,"report-unavailable");}','catch{throw;}')
 def test_production_DI_requires_health(self):self.reject('Rigging/DependencyInjection/TreehammockServiceCollectionExtensions.cs','services.AddSingleton<IProviderHealthService>','services.AddSingleton<NullProviderHealthService>')
 def test_profile_cannot_enable_emergency_by_default(self):
  p=self.root/'appsettings.Testing.json';o=json.loads(p.read_text());o['ProviderHealthSettings']['EmergencySmsStop']=True;p.write_text(json.dumps(o))
  with self.assertRaises(ValueError):health.validate(self.root)
 @unittest.skipUnless(shutil.which('texlua'),'Local Lua interpreter absent')
 def test_actual_lua_with_explicit_nonserver_command_shim(self):
  r=subprocess.run(['texlua',str(ROOT/'eng/tests/provider-health-script-boundaries.lua'),str(ROOT)],capture_output=True,text=True);self.assertEqual(r.returncode,0,r.stdout+r.stderr);self.assertEqual(r.stdout.count('Passed'),11)
if __name__=='__main__':unittest.main()
