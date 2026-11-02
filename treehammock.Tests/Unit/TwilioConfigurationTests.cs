using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using treehammock.Rigging.Config;
using treehammock.Rigging.Delivery;
using treehammock.Rigging.Sidewalk;
using treehammock.Services;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Unit;

public sealed class Cor23LTwilioConfigurationTests
{
    private static SidewalkSettings Valid() => new()
    {
        SmsEnabled=true, TwilioEnabled=true, SmsProviderPrimary="twilio", SmsProviderSecondary=null,
        PaymentProcessorPrimary="disabled-test", TwilioAccountSid="AC0123456789abcdef0123456789abcdef",
        TwilioAuthToken="opaque-owned-fixture", TwilioFromPhoneNumber="+15555550100"
    };
    private static Dictionary<string,string?> Configuration()
    {
        var settings=TestConfiguration.ValidSettings();
        settings["SystemTestSettings:Enabled"]="false";
        settings["SystemTestSettings:EnableTestInspectionEndpoints"]="false";
        settings["SystemTestSettings:TestKey"]="";
        return settings;
    }
    private static (int Code,string Output) Preflight(Dictionary<string,string?> settings,string environment="Testing")
    {
        var config=new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
        var host=Substitute.For<IHostEnvironment>(); host.EnvironmentName.Returns(environment);
        using var output=new StringWriter();
        return (SmsConfigurationCommand.Run(config,host,output),output.ToString());
    }
    [Theory]
    [InlineData(null,false)][InlineData("",false)][InlineData("+1",false)][InlineData("+12",true)]
    [InlineData("+15555550100",true)][InlineData("+123456789012345",true)][InlineData("+1234567890123456",false)]
    [InlineData("+0123",false)][InlineData("15555550100",false)][InlineData("+1 5555550100",false)]
    [InlineData("+15555550100\n",false)][InlineData("+1１２",false)][InlineData("SHORTCODE",false)]
    [InlineData("whatsapp:+15555550100",false)]
    public void Sender_shape_enforces_the_app_E164_phone_setting(string? sender,bool supported)
        => Assert.Equal(supported,TwilioTransportConfiguration.IsSupportedSender(sender));

    [Theory]
    [InlineData("AC0123456789abcdef0123456789abcdef",true)]
    [InlineData("AC0123456789ABCDEF0123456789ABCDEF",true)]
    [InlineData("ac0123456789abcdef0123456789abcdef",false)]
    [InlineData("AC0123456789abcdef0123456789abcdeg",false)]
    [InlineData("AC0123456789abcdef0123456789abcde",false)]
    [InlineData("AC0123456789abcdef0123456789abcdef0",false)]
    [InlineData(null,false)]
    public void Account_SID_requires_the_local_account_resource_shape(string? sid,bool valid)
    {
        var settings=Valid(); settings.TwilioAccountSid=sid;
        Assert.Equal(!valid,TwilioTransportConfiguration.InvalidSettings(settings).Contains("TwilioAccountSid"));
    }
    [Theory][InlineData(1,true)][InlineData(512,true)][InlineData(513,false)][InlineData(0,false)]
    public void Opaque_token_has_bounded_local_length_without_a_fixed_hex_assumption(int length,bool valid)
    {
        var settings=Valid();settings.TwilioAuthToken=new string('x',length);
        Assert.Equal(!valid,TwilioTransportConfiguration.InvalidSettings(settings).Contains("TwilioAuthToken"));
    }
    [Theory][InlineData("TwilioAccountSid")][InlineData("TwilioAuthToken")][InlineData("TwilioFromPhoneNumber")]
    public async Task Direct_runtime_service_rejects_invalid_configuration_without_submission_or_outage(string field)
    {
        var settings=Valid();typeof(SidewalkSettings).GetProperty(field)!.SetValue(settings,"private invalid sentinel");
        var client=Substitute.For<ITwilioMessageClient>();
        var service=new TwilioSmsService(client,Options.Create(settings),NullLogger<TwilioSmsService>.Instance);
        var result=await service.SendMessage("+15555550101","owned-fixture-body");
        Assert.Equal(ProviderDeliveryStatus.ConfigurationMissing,result.Status);
        Assert.Equal("CONFIGURATION_MISSING:"+field,result.FailureCode);
        Assert.Equal(DeliverySendState.NotSubmitted,result.Outcome.State);
        Assert.Equal(ProviderHealthEvidence.Neutral,result.Health);Assert.Empty(client.ReceivedCalls());
    }
    [Theory][InlineData("TwilioAccountSid")][InlineData("TwilioAuthToken")][InlineData("TwilioFromPhoneNumber")]
    public void Preflight_rejects_each_missing_selected_secondary_setting_with_no_secret_values(string field)
    {
        var settings=Configuration();settings["SidewalkSettings:"+field]=null;
        var result=Preflight(settings);Assert.Equal(1,result.Code);Assert.Contains("SidewalkSettings:"+field,result.Output);
        Assert.DoesNotContain("owned-fixture-token-not-a-secret",result.Output);
        Assert.DoesNotContain("AC0123456789abcdef0123456789abcdef",result.Output);
    }
    [Fact]
    public void Preflight_lists_all_missing_selected_settings()
    {
        var settings=Configuration();foreach(var field in new[]{"TwilioAccountSid","TwilioAuthToken","TwilioFromPhoneNumber"})settings["SidewalkSettings:"+field]=null;
        var result=Preflight(settings);Assert.Equal(1,result.Code);
        foreach(var field in new[]{"TwilioAccountSid","TwilioAuthToken","TwilioFromPhoneNumber"})Assert.Contains(field,result.Output);
    }
    [Theory][InlineData(false)][InlineData(true)]
    public void Preflight_accepts_local_prerequisites_without_claiming_remote_credential_readiness(bool secondary)
    {
        var settings=Configuration();settings["SidewalkSettings:SmsProviderPrimary"]=secondary?"aws-sns":"twilio";
        settings["SidewalkSettings:SmsProviderSecondary"]=secondary?"twilio":null;
        var result=Preflight(settings);Assert.Equal(0,result.Code);Assert.Contains("remote readiness is not checked",result.Output);
    }
    [Theory][InlineData(false,false)][InlineData(true,false)][InlineData(true,true)]
    public void Preflight_keeps_unused_or_disabled_physical_Twilio_optional(bool sms,bool twilio)
    {
        var settings=Configuration();settings["SidewalkSettings:SmsEnabled"]=sms.ToString();settings["SidewalkSettings:TwilioEnabled"]=twilio.ToString();
        settings["SidewalkSettings:SmsProviderPrimary"]="aws-sns";settings["SidewalkSettings:SmsProviderSecondary"]=null;
        foreach(var field in new[]{"TwilioAccountSid","TwilioAuthToken","TwilioFromPhoneNumber"})settings["SidewalkSettings:"+field]=null;
        Assert.Equal(0,Preflight(settings).Code);
    }
    [Theory][InlineData(false)][InlineData(true)]
    public void Disabled_SMS_preflight_keeps_selected_Twilio_prerequisites_optional(bool twilio)
    {
        var settings=Configuration();settings["SidewalkSettings:SmsEnabled"]="false";settings["SidewalkSettings:TwilioEnabled"]=twilio.ToString();
        foreach(var field in new[]{"TwilioAccountSid","TwilioAuthToken","TwilioFromPhoneNumber"})settings["SidewalkSettings:"+field]=null;
        Assert.Equal(0,Preflight(settings).Code);
    }
    [Fact]
    public void Physical_preflight_rejects_fake_capture_even_in_Testing()
    {
        var settings=Configuration();settings["SystemTestSettings:Enabled"]="true";
        var result=Preflight(settings);Assert.Equal(1,result.Code);Assert.Contains("SystemTestSettings:Enabled",result.Output);
    }
    [Theory][InlineData("SidewalkSettings:SmsEnabled")][InlineData("SidewalkSettings:SmsProviderSecondary")][InlineData("SystemTestSettings:Enabled")][InlineData("SidewalkSettings:UnknownSetting")]
    public void Preflight_binding_and_route_errors_do_not_print_the_configured_input(string field)
    {
        var settings=Configuration();settings[field]="private-invalid-sentinel";
        var result=Preflight(settings);Assert.Equal(1,result.Code);Assert.DoesNotContain("private-invalid-sentinel",result.Output);
    }
    [Fact]
    public void Physical_preflight_requires_the_options_section()
        => Assert.Equal(1,Preflight(new()).Code);
}
