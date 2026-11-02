using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using treehammock.Rigging.Hosting;
namespace treehammock.Rigging.Config;

// Deployment CI can check local selected SMS prerequisites without starting workers or contacting dependencies.
public static class SmsConfigurationCommand
{
    public static int Run(IConfiguration configuration,IHostEnvironment environment,TextWriter output)
    {
        try
        {
            var capability=SystemTestCapability.FromConfiguration(configuration,environment);
            if(capability.CaptureEnabled){output.WriteLine("SystemTestSettings:Enabled must be false for physical SMS preflight.");return 1;}
            var section=configuration.GetSection("SidewalkSettings");
            if(!section.Exists()){output.WriteLine("SidewalkSettings configuration section is required.");return 1;}
            var settings=section.Get<SidewalkSettings>(binder=>binder.ErrorOnUnknownConfiguration=true);
            if(settings is null){output.WriteLine("SidewalkSettings configuration could not be bound.");return 1;}
            bool valid=ConfigurationValidation.TryValidate(settings,out _);
            var transport=new SelectedSmsTransportValidator(capability).Validate(null,settings);
            if(!valid)output.WriteLine("SidewalkSettings route/settings validation failed.");
            if(transport.Failed)foreach(string failure in transport.Failures)output.WriteLine(failure);
            if(!valid || transport.Failed)return 1;
            output.WriteLine("Local selected SMS configuration passed; remote readiness is not checked.");return 0;
        }
        catch {output.WriteLine("SidewalkSettings/SystemTestSettings configuration is invalid or could not be bound.");return 1;}
    }
}
