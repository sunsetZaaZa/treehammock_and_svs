using System.Collections.Concurrent;
using System.Net;
using Amazon.Runtime;
using Microsoft.Extensions.Options;
using NSubstitute;
using StackExchange.Redis;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Rigging.Delivery;
using treehammock.Rigging.Sidewalk;
using treehammock.Services;
namespace treehammock.Tests.Unit;
public sealed class Cor23KProviderHealthTests
{
    internal sealed class Health : IProviderHealthService
    {
        internal DeliveryRoute? Blocked;
        internal readonly List<DeliveryRoute> Routes=new();
        internal readonly List<ProviderHealthEvidence> Evidence=new();
        public Task<ProviderHealthPermit> AcquireAsync(DeliveryRoute route,CancellationToken token)
        {Routes.Add(route);return Task.FromResult(new ProviderHealthPermit(route!=Blocked,"fixture","epoch",1,"permit","fixture"));}
        public Task CompleteAsync(ProviderHealthPermit permit,ProviderHealthEvidence evidence,CancellationToken token)
        {Evidence.Add(evidence);return Task.CompletedTask;}
    }
    [Theory][InlineData("400",ProviderHealthEvidence.Neutral)][InlineData("429",ProviderHealthEvidence.Outage)]
    [InlineData("500",ProviderHealthEvidence.Outage)][InlineData("bad-json",ProviderHealthEvidence.Neutral)][InlineData("valid",ProviderHealthEvidence.Healthy)]
    public async Task Real_Twilio_adapter_classifies_health_independently_from_acceptance(string outcome,ProviderHealthEvidence expected)
    {
        using var http=new Cor23IProviderOutcomeTests.HttpFixture(outcome);var options=Options.Create(Cor23IProviderOutcomeTests.Settings());
        var result=await new TwilioSmsService(new TwilioMessageClient(http),options).SendSMS("+15555550101","code");
        Assert.Equal(expected,result.Health);
        if(outcome is "500" or "bad-json"){Assert.Equal(DeliverySendState.Unknown,result.Outcome.State);Assert.False(result.CanFallback);}
    }
    [Theory][InlineData(400,ProviderHealthEvidence.Neutral)][InlineData(401,ProviderHealthEvidence.Neutral)][InlineData(403,ProviderHealthEvidence.Neutral)]
    [InlineData(429,ProviderHealthEvidence.Outage)][InlineData(500,ProviderHealthEvidence.Outage)]
    public async Task SNS_service_responses_separate_configuration_or_recipient_failure_from_outage(int status,ProviderHealthEvidence expected)
    {
        var client=Substitute.For<IAwsSnsSmsClient>();client.PublishSms(Arg.Any<string>(),Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(Task.FromException<string?>(new AmazonServiceException("private"){StatusCode=(HttpStatusCode)status}));
        var result=await new AWSService(client,Options.Create(Cor23IProviderOutcomeTests.Settings())).SendSMS("+15555550101","code");Assert.Equal(expected,result.Health);
        if(status==500){Assert.False(result.CanFallback);Assert.False(result.Outcome.CanRetry);}
    }
    [Theory][InlineData(false)][InlineData(true)]
    public async Task An_open_primary_route_skips_physical_send_and_uses_only_a_safe_healthy_alternative(bool unknown)
    {
        var health=new Health{Blocked=unknown?null:DeliveryRoute.Twilio};var aws=Substitute.For<IAWSService>();var twilio=Substitute.For<ITwilioSmsService>();
        twilio.SendSMS(Arg.Any<string>(),Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(ProviderDeliveryResult.Unknown("twilio") with {Health=ProviderHealthEvidence.Outage});
        aws.SendSMS(Arg.Any<string>(),Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(ProviderDeliveryResult.Sent("aws-sns",Guid.NewGuid().ToString()));
        var result=await new SmsSender(aws,twilio,Options.Create(Cor23IProviderOutcomeTests.Settings()),health:health).SendDurable(Guid.NewGuid(),new("factor","sms","+15555550101","","123"),CancellationToken.None);
        Assert.Equal(unknown?DeliverySendState.Unknown:DeliverySendState.Accepted,result.Outcome.State);
        Assert.Equal(unknown?new[]{DeliveryRoute.Twilio}:new[]{DeliveryRoute.Twilio,DeliveryRoute.AwsSns},health.Routes);
        if(unknown)await aws.DidNotReceiveWithAnyArgs().SendSMS(default!,default!,default);else await twilio.DidNotReceiveWithAnyArgs().SendSMS(default!,default!,default);
    }
    [Fact]
    public async Task All_blocked_routes_are_confirmed_not_submitted_and_retryable_without_transport()
    {
        var config=Cor23IProviderOutcomeTests.Settings();config.SmsProviderSecondary=null;var health=new Health{Blocked=DeliveryRoute.Twilio};var twilio=Substitute.For<ITwilioSmsService>();
        var result=await new SmsSender(Substitute.For<IAWSService>(),twilio,Options.Create(config),health:health).SendDurable(Guid.NewGuid(),new("factor","sms","+15555550101","","123"),CancellationToken.None);
        Assert.Equal(DeliverySendState.NotSubmitted,result.Outcome.State);Assert.True(result.Outcome.CanRetry);await twilio.DidNotReceiveWithAnyArgs().SendSMS(default!,default!,default);
    }
    internal static ProviderHealthService Service(IDatabase database,ProviderHealthSettings? settings=null)=>new(Options.Create(settings??new()),Options.Create(new SMTPSettings{SMTPQualifiedDomain="relay.example.test",SMTPPort=587,SMTPUsername="fixture-account"}),Options.Create(Cor23IProviderOutcomeTests.Settings()),Options.Create(new AbuseControlSettings()),database);
    [Theory][InlineData(DeliveryRoute.Smtp)][InlineData(DeliveryRoute.Twilio)][InlineData(DeliveryRoute.AwsSns)]
    public async Task Explicit_emergency_channel_stop_works_even_when_automatic_health_is_disabled(DeliveryRoute route)
    {
        var db=Substitute.For<IDatabase>();var health=Service(db,new(){Enabled=false,EmergencyEmailStop=true,EmergencySmsStop=true});
        var permit=await health.AcquireAsync(route,CancellationToken.None);Assert.False(permit.Allowed);Assert.Equal("emergency",permit.Reason);Assert.Empty(db.ReceivedCalls());
    }
    [Fact]
    public async Task Cache_outage_denies_a_physical_start_and_cancellation_still_propagates()
    {
        var db=Substitute.For<IDatabase>();db.ScriptEvaluateAsync(Arg.Any<string>(),Arg.Any<RedisKey[]>(),Arg.Any<RedisValue[]>(),Arg.Any<CommandFlags>()).Returns(Task.FromException<RedisResult>(new RedisConnectionException(ConnectionFailureType.UnableToConnect,"fixture")));
        var health=Service(db);Assert.False((await health.AcquireAsync(DeliveryRoute.Twilio,CancellationToken.None)).Allowed);
        using var cancel=new CancellationTokenSource();cancel.Cancel();await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>health.AcquireAsync(DeliveryRoute.Twilio,cancel.Token));
    }
    [Fact]
    public async Task Failed_health_report_does_not_replace_a_known_receipt()
    {
        var db=Substitute.For<IDatabase>();db.ScriptEvaluateAsync(Arg.Any<string>(),Arg.Any<RedisKey[]>(),Arg.Any<RedisValue[]>(),Arg.Any<CommandFlags>()).Returns(Task.FromException<RedisResult>(new RedisServerException("fixture")));
        await Service(db).CompleteAsync(new(true,"delivery:health:v1:twilio:fixture","epoch",1,"permit","allowed"),ProviderHealthEvidence.Healthy,CancellationToken.None);
    }
    [Theory][InlineData(0,45,32)][InlineData(5,44,32)][InlineData(5,45,129)]
    public void Invalid_health_budgets_fail_before_cache_access(int threshold,int permit,int slots)
    {Assert.Throws<ArgumentException>(()=>Service(Substitute.For<IDatabase>(),new(){FailureThreshold=threshold,PermitSeconds=permit,MaxInFlightPerRoute=slots}));}
}
