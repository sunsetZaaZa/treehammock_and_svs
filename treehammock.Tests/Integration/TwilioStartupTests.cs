using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using treehammock.Rigging.Config;
using treehammock.Rigging.Sidewalk;
using treehammock.Services;
using treehammock.Services.SystemTesting;
using treehammock.Tests.Infrastructure;
namespace treehammock.Tests.Integration;
public sealed class Cor23LTwilioStartupTests
{
    private sealed class Logs : ILoggerProvider
    {
        internal readonly ConcurrentQueue<string> Values=new();
        public ILogger CreateLogger(string categoryName)=>new Recorder(Values);
        public void Dispose() { }
        private sealed class Recorder(ConcurrentQueue<string> values) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState:notnull=>null;
            public bool IsEnabled(LogLevel level)=>true;
            public void Log<TState>(LogLevel level,EventId id,TState state,Exception? error,Func<TState,Exception?,string> formatter)=>values.Enqueue(formatter(state,error)+(error?.ToString()??""));
        }
    }
    private static Dictionary<string,string?> Settings(bool secondary=false)
    {
        var settings=TestConfiguration.ValidSettings();settings["SystemTestSettings:Enabled"]="false";
        settings["SystemTestSettings:EnableTestInspectionEndpoints"]="false";settings["SystemTestSettings:TestKey"]="";
        settings["SidewalkSettings:SmsProviderPrimary"]=secondary?"aws-sns":"twilio";settings["SidewalkSettings:SmsProviderSecondary"]=secondary?"twilio":null;
        settings["SidewalkSettings:TwilioAuthToken"]="private-auth-sentinel";
        return settings;
    }
    private static TreehammockWebApplicationFactory Host(Dictionary<string,string?> settings,ITwilioMessageClient client,Logs logs,string environment="Testing")=>new(settings,environment,services=>
    {
        // Keep the real Program/ValidateOnStart composition. This fixture has no background SQL/cache/provider work.
        services.RemoveAll<IHostedService>();services.RemoveAll<ITwilioMessageClient>();services.AddSingleton(client);services.AddSingleton<ILoggerProvider>(logs);
    });
    [Theory]
    [InlineData(false,"TwilioAccountSid",null)][InlineData(false,"TwilioAuthToken",null)][InlineData(false,"TwilioFromPhoneNumber",null)]
    [InlineData(true,"TwilioAccountSid",null)][InlineData(true,"TwilioAuthToken",null)][InlineData(true,"TwilioFromPhoneNumber",null)]
    [InlineData(false,"TwilioAccountSid","")][InlineData(false,"TwilioAuthToken","")][InlineData(false,"TwilioFromPhoneNumber","")]
    [InlineData(true,"TwilioAccountSid","")][InlineData(true,"TwilioAuthToken","")][InlineData(true,"TwilioFromPhoneNumber","")]
    [InlineData(false,"TwilioAccountSid"," ")][InlineData(false,"TwilioAuthToken"," ")][InlineData(false,"TwilioFromPhoneNumber"," ")]
    [InlineData(true,"TwilioAccountSid"," ")][InlineData(true,"TwilioAuthToken"," ")][InlineData(true,"TwilioFromPhoneNumber"," ")]
    public void Real_host_rejects_each_missing_selected_Twilio_prerequisite_in_primary_and_secondary_positions(bool secondary,string field,string? value)
    {
        var settings=Settings(secondary);settings["SidewalkSettings:"+field]=value;var client=Substitute.For<ITwilioMessageClient>();var logs=new Logs();
        using var factory=Host(settings,client,logs);var error=Record.Exception(()=>factory.CreateClient());Assert.NotNull(error);
        Assert.Contains("SidewalkSettings:"+field,error.ToString());Assert.DoesNotContain("private-auth-sentinel",error.ToString());Assert.DoesNotContain("AC0123456789abcdef0123456789abcdef",error.ToString());
        Assert.DoesNotContain(logs.Values,v=>v.Contains("private-auth-sentinel")||v.Contains("AC0123456789abcdef0123456789abcdef"));Assert.Empty(client.ReceivedCalls());
    }
    [Theory][InlineData(false)][InlineData(true)]
    public void Real_host_reports_all_missing_secondary_or_primary_settings_without_values(bool secondary)
    {
        var settings=Settings(secondary);foreach(string field in new[]{"TwilioAccountSid","TwilioAuthToken","TwilioFromPhoneNumber"})settings["SidewalkSettings:"+field]=null;
        using var factory=Host(settings,Substitute.For<ITwilioMessageClient>(),new());var error=Record.Exception(()=>factory.CreateClient());Assert.NotNull(error);
        foreach(string field in new[]{"TwilioAccountSid","TwilioAuthToken","TwilioFromPhoneNumber"})Assert.Contains(field,error.ToString());
    }
    [Theory][InlineData("TwilioAccountSid","private-invalid-sid")][InlineData("TwilioAuthToken","private token")]
    [InlineData("TwilioAuthToken","private\nvalue")][InlineData("TwilioFromPhoneNumber","private-sender")]
    [InlineData("TwilioFromPhoneNumber","+15555550100\n")][InlineData("TwilioFromPhoneNumber","+0123456")]
    public void Real_host_rejects_malformed_transport_settings_with_setting_name_only(string field,string value)
    {
        var settings=Settings();settings["SidewalkSettings:"+field]=value;var logs=new Logs();using var factory=Host(settings,Substitute.For<ITwilioMessageClient>(),logs);
        var error=Record.Exception(()=>factory.CreateClient());Assert.NotNull(error);Assert.Contains(field,error.ToString());Assert.DoesNotContain(value,error.ToString());Assert.DoesNotContain(logs.Values,v=>v.Contains(value));
    }
    [Theory][InlineData(false)][InlineData(true)]
    public void Real_host_starts_with_valid_Twilio_selected_in_either_position_without_credential_readiness_or_provider_calls(bool secondary)
    {
        var settings=Settings(secondary);var client=Substitute.For<ITwilioMessageClient>();using var factory=Host(settings,client,new());using var http=factory.CreateClient();
        var options=factory.Services.GetRequiredService<IOptions<SidewalkSettings>>().Value;Assert.True(options.SmsEnabled);Assert.Empty(client.ReceivedCalls());
    }
    [Theory][InlineData(false,false)][InlineData(true,false)][InlineData(true,true)]
    public void Real_host_keeps_unselected_or_disabled_Twilio_optional(bool smsEnabled,bool twilioEnabled)
    {
        var settings=Settings();settings["SidewalkSettings:SmsEnabled"]=smsEnabled.ToString();settings["SidewalkSettings:TwilioEnabled"]=twilioEnabled.ToString();
        settings["SidewalkSettings:SmsProviderPrimary"]="aws-sns";settings["SidewalkSettings:SmsProviderSecondary"]=null;
        foreach(string field in new[]{"TwilioAccountSid","TwilioAuthToken","TwilioFromPhoneNumber"})settings["SidewalkSettings:"+field]=null;
        var client=Substitute.For<ITwilioMessageClient>();using var factory=Host(settings,client,new());using var http=factory.CreateClient();Assert.Empty(client.ReceivedCalls());
    }
    [Fact]
    public void Disabled_SMS_keeps_selected_Twilio_prerequisites_optional()
    {
        var settings=Settings(true);settings["SidewalkSettings:SmsEnabled"]="false";
        foreach(var field in new[]{"TwilioAccountSid","TwilioAuthToken","TwilioFromPhoneNumber"})settings["SidewalkSettings:"+field]=null;
        var client=Substitute.For<ITwilioMessageClient>();using var factory=Host(settings,client,new());using var http=factory.CreateClient();Assert.Empty(client.ReceivedCalls());
    }
    [Fact]
    public void Exact_Testing_capture_composition_starts_without_unused_physical_Twilio_secrets()
    {
        var settings=Settings(true);settings["SystemTestSettings:Enabled"]="true";
        foreach(string field in new[]{"TwilioAccountSid","TwilioAuthToken","TwilioFromPhoneNumber"})settings["SidewalkSettings:"+field]=null;
        var client=Substitute.For<ITwilioMessageClient>();using var factory=Host(settings,client,new());using var http=factory.CreateClient();
        Assert.IsType<SystemTestSmsSender>(factory.Services.GetRequiredService<ISmsSender>());Assert.Empty(client.ReceivedCalls());
    }
    [Theory][InlineData("Development")][InlineData("Container")][InlineData("Production")]
    public void A_non_Testing_host_cannot_use_capture_to_bypass_selected_transport_prerequisites(string environment)
    {
        var settings=Settings();settings["SystemTestSettings:Enabled"]="true";settings["SidewalkSettings:TwilioAuthToken"]=null;
        using var factory=Host(settings,Substitute.For<ITwilioMessageClient>(),new(),environment);var error=Record.Exception(()=>factory.CreateClient());Assert.NotNull(error);Assert.Contains("SystemTestSettings",error.ToString());
    }
    [Theory][InlineData("aws")][InlineData("sns")][InlineData("aws-sns")]
    public void Normalized_AWS_primary_does_not_hide_missing_Twilio_secondary_credentials(string primary)
    {
        var settings=Settings(true);settings["SidewalkSettings:SmsProviderPrimary"]=primary;settings["SidewalkSettings:TwilioAuthToken"]=null;
        using var factory=Host(settings,Substitute.For<ITwilioMessageClient>(),new());var error=Record.Exception(()=>factory.CreateClient());Assert.NotNull(error);Assert.Contains("TwilioAuthToken",error.ToString());
    }
}
