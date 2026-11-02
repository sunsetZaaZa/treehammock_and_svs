using System.Diagnostics;
using System.Net;
using Microsoft.Extensions.Options;
using NSubstitute;
using treehammock.Rigging.Config;
using treehammock.Rigging.Delivery;
using treehammock.Rigging.Sidewalk;
using treehammock.Services;
using treehammock.Tests.Infrastructure;
using treehammock.Tests.Unit;
namespace treehammock.Tests.Integration;
public sealed class Cor23JTransportDeadlineTests
{
    [Theory]
    [InlineData("RequiredStartTls","hang-greeting",DeliverySendState.NotSubmitted)]
    [InlineData("ImplicitTls","hang-greeting",DeliverySendState.NotSubmitted)]
    [InlineData("RequiredStartTls","hang-tls",DeliverySendState.NotSubmitted)]
    [InlineData("ImplicitTls","hang-tls",DeliverySendState.NotSubmitted)]
    [InlineData("RequiredStartTls","hang-auth",DeliverySendState.NotSubmitted)]
    [InlineData("ImplicitTls","hang-auth",DeliverySendState.NotSubmitted)]
    [InlineData("RequiredStartTls","hang-data-ack",DeliverySendState.Unknown)]
    [InlineData("ImplicitTls","hang-data-ack",DeliverySendState.Unknown)]
    [InlineData("RequiredStartTls","hang-quit",DeliverySendState.Accepted)]
    [InlineData("ImplicitTls","hang-quit",DeliverySendState.Accepted)]
    public async Task Real_SMTP_blocked_phase_cancels_closes_socket_and_releases_owned_capacity(string mode,string fault,DeliverySendState expected)
    {
        await using var server=new Cor23HSmtpServer(mode,fault);var policy=Cor23JDeliveryBudgetTests.Policy(total:2,attempt:1);
        var settings=Cor23HSmtpTransportTests.Settings(server,mode);var mail=new SMTPService(Options.Create(settings),Options.Create(new EmailTemplateSettings()),new Cor23HSmtpTransportTests.Logs(),new(settings,"Testing"),server.Clients(),policy);
        var watch=Stopwatch.StartNew();var result=await mail.SendDurable(Guid.NewGuid(),new("verify","email","recipient@example.test","verify","proof-sentinel"),TestContext.Current.CancellationToken);
        Assert.Equal(expected,result.State);Assert.True(watch.Elapsed<TimeSpan.FromSeconds(4));
        await Cor23JDeliveryBudgetTests.Eventually(()=>policy.ActiveOperations==0&&server.Sessions.All(s=>s.Closed));Assert.Equal(1,policy.AvailableCapacity);
        var session=Assert.Single(server.Sessions);Assert.Equal(fault is "hang-data-ack" or "hang-quit",session.Accepted);
        if(fault is "hang-greeting" or "hang-tls")Assert.DoesNotContain(session.Commands,c=>c.Verb is "AUTH" or "MAIL" or "DATA");
    }
    [Fact]
    public async Task All_ten_legacy_SMTP_methods_propagate_precancellation_without_opening_a_socket()
    {
        await using var server=new Cor23HSmtpServer("RequiredStartTls");var mail=Cor23HSmtpTransportTests.Service(server,"RequiredStartTls");using var cancel=new CancellationTokenSource();cancel.Cancel();
        var token=cancel.Token;Task<bool?>[] sends=[mail.VerificationLetter("r@example.test","verify","proof",token),mail.ResendVerifyLetter("r@example.test","verify","proof",token),mail.EmailChangeVerifyLetter("r@example.test","verify","proof",token),mail.DeleteAccountTwoStepLetter("r@example.test","verify","proof","code",token),mail.AccountUnlockLetter("r@example.test","verify","proof",token),mail.TwoFactorSetupLetter("r@example.test","verify","proof",token),mail.TwoFactorKeyOutboundLetter("r@example.test","verify","proof",token),mail.TwoFactorDeleteLetter("r@example.test","verify","proof",token),mail.PasswordResetCodeLetter("r@example.test","verify","proof","later","masked",token),mail.Send("r@example.test","verify","proof",token)];
        Assert.All(await Task.WhenAll(sends),s=>Assert.False(s));Assert.Empty(server.Sessions);
    }
    private sealed class HungContent(Action entered,Action released) : HttpContent
    {
        protected override bool TryComputeLength(out long length){length=0;return false;}
        protected override Task SerializeToStreamAsync(Stream stream,TransportContext? context)=>throw new InvalidOperationException("A cancellable body read is required");
        protected override async Task SerializeToStreamAsync(Stream stream,TransportContext? context,CancellationToken token)
        {entered();try{await Task.Delay(Timeout.InfiniteTimeSpan,token);}finally{released();}}
    }
    private sealed class HttpFault(string phase) : HttpMessageHandler,IHttpClientFactory
    {
        public int Calls;public bool Released;public TaskCompletionSource<bool> Entered=new(TaskCreationOptions.RunContinuationsAsynchronously);
        public HttpClient CreateClient(string name)=>new(this,disposeHandler:false){Timeout=Timeout.InfiniteTimeSpan};
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)
        {
            Calls++;
            if(phase=="body")return new(HttpStatusCode.Created){Content=new HungContent(()=>Entered.TrySetResult(true),()=>Released=true)};
            Entered.TrySetResult(true);try{await Task.Delay(Timeout.InfiniteTimeSpan,token);return new(HttpStatusCode.Created);}finally{Released=true;}
        }
    }
    private static SidewalkSettings Settings()=>new(){SmsEnabled=true,TwilioEnabled=true,AwsSnsEnabled=true,SmsProviderPrimary="twilio",SmsProviderSecondary="aws-sns",TwilioAccountSid="AC0123456789abcdef0123456789abcdef",TwilioAuthToken="fixture",TwilioFromPhoneNumber="+15555550100"};
    [Theory][InlineData("headers",false)][InlineData("body",false)][InlineData("headers",true)][InlineData("body",true)]
    public async Task Real_HTTP_header_and_body_stalls_receive_deadline_or_request_cancellation_without_fallback(string phase,bool requestCancel)
    {
        var policy=Cor23JDeliveryBudgetTests.Policy();using var http=new HttpFault(phase);var aws=Substitute.For<IAWSService>();var config=Options.Create(Settings());
        var sender=new SmsSender(aws,new TwilioSmsService(new TwilioMessageClient(http),config),config,execution:policy);using var cancel=new CancellationTokenSource();
        var send=sender.SendDurable(Guid.NewGuid(),new("factor","sms","+15555550101","","123456"),cancel.Token);await http.Entered.Task.WaitAsync(TimeSpan.FromSeconds(3));if(requestCancel)cancel.Cancel();
        Assert.Equal(DeliverySendState.Unknown,(await send).Outcome.State);Assert.True(http.Released);Assert.Equal(1,http.Calls);Assert.Equal(0,policy.ActiveOperations);Assert.Equal(1,policy.AvailableCapacity);
        await aws.DidNotReceiveWithAnyArgs().SendSMS(default!,default!,default);
    }
    [Fact]
    public async Task Aggregate_budget_is_not_reset_when_definite_primary_rejection_allows_a_slow_secondary()
    {
        var policy=Cor23JDeliveryBudgetTests.Policy(total:2,attempt:2);var config=Options.Create(Settings());var aws=Substitute.For<IAWSService>();var twilio=Substitute.For<ITwilioSmsService>();int secondary=0;
        twilio.SendSMS(Arg.Any<string>(),Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(async call=>{await Task.Delay(700,call.ArgAt<CancellationToken>(2));return ProviderDeliveryResult.Rejected("twilio");});
        aws.SendSMS(Arg.Any<string>(),Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(async call=>{secondary++;await Task.Delay(Timeout.InfiniteTimeSpan,call.ArgAt<CancellationToken>(2));return ProviderDeliveryResult.Sent("aws-sns",Guid.NewGuid().ToString());});
        var watch=Stopwatch.StartNew();var result=await new SmsSender(aws,twilio,config,execution:policy).SendDurable(Guid.NewGuid(),new("factor","sms","+15555550101","","123456"),CancellationToken.None);
        Assert.Equal(DeliverySendState.Unknown,result.Outcome.State);Assert.Equal(1,secondary);Assert.InRange(watch.Elapsed.TotalSeconds,1.5,2.6);Assert.Equal(1,policy.AvailableCapacity);
    }
    [Fact]
    public async Task SNS_adapter_propagates_the_same_cancellation_budget_to_its_SDK_client()
    {
        var policy=Cor23JDeliveryBudgetTests.Policy();var client=Substitute.For<IAwsSnsSmsClient>();bool released=false;
        client.PublishSms(Arg.Any<string>(),Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(async call=>{try{await Task.Delay(Timeout.InfiniteTimeSpan,call.ArgAt<CancellationToken>(2));return Guid.NewGuid().ToString();}finally{released=true;}});
        var config=Settings();config.SmsProviderPrimary="aws-sns";config.SmsProviderSecondary="twilio";var twilio=Substitute.For<ITwilioSmsService>();var options=Options.Create(config);
        var result=await new SmsSender(new AWSService(client,options),twilio,options,execution:policy).SendDurable(Guid.NewGuid(),new("factor","sms","+15555550101","","123456"),CancellationToken.None);
        Assert.Equal(DeliverySendState.Unknown,result.Outcome.State);Assert.True(released);Assert.Equal(1,policy.AvailableCapacity);await twilio.DidNotReceiveWithAnyArgs().SendSMS(default!,default!,default);
    }
}
