"""COR23L source mutation witnesses only; no native runtime qualification."""
import importlib.util,shutil,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('sms_configuration',ROOT/'eng/check-sms-transport-configuration.py');sms=importlib.util.module_from_spec(spec);spec.loader.exec_module(sms)
VALIDATOR='Rigging/Config/TwilioTransportConfiguration.cs'
COMMAND='Rigging/Config/SmsConfigurationCommand.cs'
class SmsTransportConfigurationTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'source';shutil.copytree(ROOT,self.root,ignore=shutil.ignore_patterns('.git','bin','obj','.artifacts','.correction-results','TestResults','__pycache__'))
 def tearDown(self):self.temp.cleanup()
 def reject(self,path,old,new):
  p=self.root/path;s=p.read_text();self.assertIn(old,s);p.write_text(s.replace(old,new,1))
  with self.assertRaises(ValueError):sms.validate(self.root)
 def test_source_consistency_never_claims_native_execution(self):self.assertEqual('NotRun',sms.validate(self.root)['qualification'])
 def test_selection_cannot_check_only_primary(self):self.reject(VALIDATOR,'SmsProviderNames.NormalizeConfiguredProviders(settings).Contains(SmsProviderNames.Twilio,StringComparer.Ordinal)','settings.SmsProviderPrimary == "twilio"')
 def test_disabled_sms_stays_optional(self):self.reject(VALIDATOR,'!settings.SmsEnabled','false')
 def test_unused_disabled_twilio_stays_optional(self):self.reject(VALIDATOR,'!settings.TwilioEnabled','false')
 def test_only_validated_capture_can_skip_unused_secrets(self):self.reject(VALIDATOR,'capability.CaptureEnabled','true')
 def test_sid_shape_required(self):self.reject(VALIDATOR,'sid.Length!=34','sid.Length<1')
 def test_token_controls_rejected(self):self.reject(VALIDATOR,"token.Any(c=>c<'!' || c>'~')",'false')
 def test_sender_maximum_enforced(self):self.reject(VALIDATOR,'sender.Length is >=3 and <=16','sender.Length>=3')
 def test_sender_ascii_digits_required(self):self.reject(VALIDATOR,"c is >= '0' and <= '9'",'char.IsDigit(c)')
 def test_error_cannot_echo_token(self):self.reject(VALIDATOR,'invalid.Select(setting=>"SidewalkSettings:"+setting+" is missing or invalid.")','invalid.Select(setting=>settings.TwilioAuthToken!)')
 def test_startup_DI_cannot_drop_validator(self):self.reject('Rigging/DependencyInjection/TreehammockServiceCollectionExtensions.cs','services.AddSingleton<IValidateOptions<SidewalkSettings>, SelectedSmsTransportValidator>();','')
 def test_runtime_guard_cannot_drop(self):self.reject('Services/SmsSender.cs','TwilioTransportConfiguration.InvalidSettings(_settings)','Array.Empty<string>()')
 def test_preflight_cannot_claim_fake_transport_readiness(self):self.reject(COMMAND,'if(capability.CaptureEnabled)','if(false)')
 def test_preflight_must_validate_routes(self):self.reject(COMMAND,'ConfigurationValidation.TryValidate(settings,out _)','true')
 def test_preflight_errors_cannot_echo_binding_exception(self):self.reject(COMMAND,'catch {output.WriteLine("SidewalkSettings/SystemTestSettings configuration is invalid or could not be bound.");return 1;}','catch(Exception exception){output.WriteLine(exception.ToString());return 1;}')
 def test_preflight_must_exit_before_host(self):self.reject('Program.cs','Environment.ExitCode = SmsConfigurationCommand.Run','Environment.ExitCode = FakeCommand.Run')
 def test_source_guard_runs_in_CI(self):self.reject('.github/workflows/treehammock-ci.yml','python3 eng/check-sms-transport-configuration.py','true')
 def test_preflight_unknown_options_must_fail_closed(self):self.reject(COMMAND,'binder=>binder.ErrorOnUnknownConfiguration=true','binder=>binder.ErrorOnUnknownConfiguration=false')
 def test_CI_exercises_actual_preflight_command(self):self.reject('.github/workflows/treehammock-ci.yml','--no-launch-profile -- validate-sms-config','--no-launch-profile -- unrelated-command')
if __name__=='__main__':unittest.main()
