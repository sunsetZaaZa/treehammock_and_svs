#!/usr/bin/env python3
"""COR23L supplemental source witnesses; executable host/preflight qualification remains required."""
import argparse,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def require(value,message):
 if not value:raise ValueError(message)
def validate(root):
 read=lambda path:(root/path).read_text()
 validator=read('Rigging/Config/TwilioTransportConfiguration.cs')
 for token in ['IValidateOptions<SidewalkSettings>','capability.CaptureEnabled','!settings.SmsEnabled','!settings.TwilioEnabled','SmsProviderNames.NormalizeConfiguredProviders(settings).Contains(SmsProviderNames.Twilio,StringComparer.Ordinal)','sid.Length!=34','sid.StartsWith("AC",StringComparison.Ordinal)','char.IsAsciiHexDigit','token.Length>512',"token.Any(c=>c<'!' || c>'~')",'sender.Length is >=3 and <=16',"sender[1] is >= '1' and <= '9'", "c is >= '0' and <= '9'",'invalid.Select(setting=>"SidewalkSettings:"+setting+" is missing or invalid.")']:
  require(token in validator,'Missing conditional local transport boundary: '+token)
 require('IConfiguration' not in validator,'Options validator must use immutable validated capture capability')
 di=read('Rigging/DependencyInjection/TreehammockServiceCollectionExtensions.cs')
 require('services.AddSingleton<IValidateOptions<SidewalkSettings>, SelectedSmsTransportValidator>();' in di and 'AddValidatedOptions<SidewalkSettings>' in di and '.ValidateOnStart()' in di,'Production startup options validation missing')
 runtime=read('Services/SmsSender.cs');start=runtime.index('public class TwilioSmsService');runtime=runtime[start:]
 require('TwilioTransportConfiguration.InvalidSettings(_settings)' in runtime and 'ProviderDeliveryResult.ConfigurationMissing(ProviderName,invalidSettings[0])' in runtime,'Runtime transport configuration guard missing')
 require(runtime.index('TwilioTransportConfiguration.InvalidSettings(_settings)')<runtime.index('_client.SendMessage('),'Runtime validation must precede provider I/O')
 command=read('Rigging/Config/SmsConfigurationCommand.cs')
 for token in ['SystemTestCapability.FromConfiguration(configuration,environment)','if(capability.CaptureEnabled)','section.Get<SidewalkSettings>(binder=>binder.ErrorOnUnknownConfiguration=true)','ConfigurationValidation.TryValidate(settings,out _)','new SelectedSmsTransportValidator(capability).Validate(null,settings)','remote readiness is not checked','catch {output.WriteLine("SidewalkSettings/SystemTestSettings configuration is invalid or could not be bound.");return 1;}']:
  require(token in command,'Missing deployment preflight boundary: '+token)
 for token in ['HttpClient','SendMessage(','BuildServiceProvider','Console.WriteLine(settings','error.ToString()','exception.ToString()']:require(token not in command,'Preflight may not perform I/O or echo inputs: '+token)
 program=read('Program.cs');start=program.index('if (validateSms)');end=program.index('// Hosting/request logging',start);branch=program[start:end]
 require('args[0] == "validate-sms-config"' in program and 'Environment.ExitCode = SmsConfigurationCommand.Run' in branch and 'return;' in branch and end<program.index('var services = builder.Services'),'Preflight must exit before service/host composition')
 routes=read('Rigging/Config/ConfigurationValidation.cs')
 require('{unsupportedProvider}' not in routes and '{disabledConfiguredProvider}' not in routes,'Route errors cannot print configured input')
 for path,token in [('treehammock.Tests/Integration/TwilioStartupTests.cs','Real_host_rejects_each_missing_selected_Twilio_prerequisite_in_primary_and_secondary_positions'),('treehammock.Tests/Unit/TwilioConfigurationTests.cs','Preflight_binding_and_route_errors_do_not_print_the_configured_input')]:require(token in read(path),'Native regression missing: '+path)
 ci=read('.github/workflows/treehammock-ci.yml');require('python3 eng/check-sms-transport-configuration.py' in ci and "test_sms_transport_configuration.py" in ci and "--no-launch-profile -- validate-sms-config" in ci,'CI source witnesses missing')
 example=read('deploy/sms-twilio.env.example');require('SidewalkSettings__SmsProviderPrimary=twilio' in example and 'SidewalkSettings__TwilioAuthToken=\n' in example,'Incomplete deployment example must require secret provisioning')
 return dict(status='SourceContractsConsistent',qualification='NotRun',selection='enabled selected primary or secondary normalized Twilio',diagnostics='setting names only',remote_readiness='not checked',native_required=['actual host ValidateOnStart matrix','command exit code and redaction','runtime guard prevents provider submission'])
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=ROOT);args=parser.parse_args()
 try:print(json.dumps(validate(args.root),indent=2));return 0
 except(ValueError,OSError) as error:print(str(error));return 1
if __name__=='__main__':raise SystemExit(main())
