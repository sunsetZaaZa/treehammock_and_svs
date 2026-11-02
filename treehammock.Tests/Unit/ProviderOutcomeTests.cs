using System.Net;
using Amazon.Runtime;
using Microsoft.Extensions.Options;
using NSubstitute;
using treehammock.Rigging.Config;
using treehammock.Rigging.Delivery;
using treehammock.Rigging.Sidewalk;
using treehammock.Services;
namespace treehammock.Tests.Unit;
public sealed class Cor23IProviderOutcomeTests
{
    internal sealed class HttpFixture(string outcome) : HttpMessageHandler,IHttpClientFactory
    {
        internal int Calls,Accepted;
        private HttpClient? _client;
        public HttpClient CreateClient(string name)=>_client??=new HttpClient(this,disposeHandler:false);
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)
        {
            Assert.Equal(HttpMethod.Post,request.Method);Calls++;
            if(outcome=="lost"){Accepted++;throw new IOException("proof-and-recipient-must-not-leak");}
            int status=outcome switch {"429"=>429,"400"=>400,"500"=>500,"408"=>408,"202"=>202,_=>201};
            string body=outcome switch {"missing"=>"{}","number"=>"{\"sid\":42}","array"=>"[]","bad-json"=>"{","bad-id"=>"{\"sid\":\"SM-short\"}","newline"=>"{\"sid\":\"SM0123456789abcdef0123456789abcdef\\n\"}",_=>"{\"sid\":\"SM0123456789abcdef0123456789abcdef\"}"};
            if(status==201&&outcome is not ("429" or "400"))Accepted++;
            return Task.FromResult(new HttpResponseMessage((HttpStatusCode)status){Content=new StringContent(body)});
        }
        protected override void Dispose(bool disposing){if(disposing)_client?.Dispose();base.Dispose(disposing);}
    }
    internal static SidewalkSettings Settings()=>new(){SmsEnabled=true,TwilioEnabled=true,AwsSnsEnabled=true,SmsProviderPrimary="twilio",SmsProviderSecondary="aws-sns",TwilioAccountSid="AC0123456789abcdef0123456789abcdef",TwilioAuthToken="fixture-secret",TwilioFromPhoneNumber="+15555550100",PaymentProcessorPrimary="disabled-test"};
    internal static SmsSender Sender(HttpFixture http,IAWSService aws)=>new(aws,new TwilioSmsService(new TwilioMessageClient(http),Options.Create(Settings())),Options.Create(Settings()));
    [Theory]
    [InlineData("lost")] [InlineData("500")] [InlineData("408")] [InlineData("202")]
    [InlineData("missing")] [InlineData("number")] [InlineData("array")] [InlineData("bad-json")]
    [InlineData("bad-id")] [InlineData("newline")]
    public async Task Twilio_unknown_or_malformed_acceptance_stops_both_durable_and_legacy_fallback(string outcome)
    {
        using var http=new HttpFixture(outcome);var aws=Substitute.For<IAWSService>();var sender=Sender(http,aws);
        var result=await sender.SendDurable(Guid.NewGuid(),new("factor","sms","+15555550101","","123456"),TestContext.Current.CancellationToken);
        Assert.Equal(DeliverySendState.Unknown,result.Outcome.State);Assert.False(result.CanFallback);Assert.False(result.Outcome.CanRetry);
        await Assert.ThrowsAsync<DeliveryAcceptanceUnknownException>(()=>sender.SendCode("+15555550101","123456"));
        Assert.Equal(2,http.Calls);await aws.DidNotReceiveWithAnyArgs().SendSMS(default!,default!, cancellationToken: Arg.Any<CancellationToken>());
    }
    [Theory]
    [InlineData("429")] [InlineData("400")]
    public async Task Only_confirmed_non_submission_or_explicit_rejection_permits_the_next_provider(string outcome)
    {
        using var http=new HttpFixture(outcome);var aws=Substitute.For<IAWSService>();aws.SendSMS(Arg.Any<string>(),Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(ProviderDeliveryResult.Sent("aws-sns","01234567-89ab-cdef-0123-456789abcdef"));
        var result=await Sender(http,aws).SendDurable(Guid.NewGuid(),new("factor","sms","+15555550101","","123456"),TestContext.Current.CancellationToken);
        Assert.Equal(DeliverySendState.Accepted,result.Outcome.State);Assert.Equal("aws-sns",result.Provider);Assert.Equal(1,http.Calls);
        await aws.Received(1).SendSMS(Arg.Any<string>(),Arg.Any<string>(),Arg.Any<CancellationToken>());
    }
    [Fact]
    public async Task Confirmed_Twilio_rate_limit_without_an_alternative_is_not_submitted_and_retryable()
    {
        using var http=new HttpFixture("429");var settings=Settings();settings.SmsProviderSecondary=null;var sender=new SmsSender(Substitute.For<IAWSService>(),new TwilioSmsService(new TwilioMessageClient(http),Options.Create(settings)),Options.Create(settings));
        var result=await sender.SendDurable(Guid.NewGuid(),new("factor","sms","+15555550101","","123456"),TestContext.Current.CancellationToken);
        Assert.Equal(DeliverySendState.NotSubmitted,result.Outcome.State);Assert.True(result.Outcome.CanRetry);Assert.Equal(1,http.Calls);
    }
    [Fact]
    public async Task Valid_Twilio_receipt_preserves_acceptance_and_never_calls_another_provider()
    {
        using var http=new HttpFixture("valid");var aws=Substitute.For<IAWSService>();var result=await Sender(http,aws).SendDurable(Guid.NewGuid(),new("factor","sms","+15555550101","","123456"),TestContext.Current.CancellationToken);
        Assert.Equal(DeliverySendState.Accepted,result.Outcome.State);Assert.Equal("SM0123456789abcdef0123456789abcdef",result.Outcome.ReceiptId);Assert.Equal(1,http.Accepted);
        await aws.DidNotReceiveWithAnyArgs().SendSMS(default!,default!, cancellationToken: Arg.Any<CancellationToken>());
    }
    [Theory]
    [InlineData("lost")] [InlineData("empty")] [InlineData("malformed")] [InlineData("500")] [InlineData("timeout")]
    public async Task SNS_missing_receipt_or_lost_response_is_unknown_and_is_not_retried_or_fallen_back(string outcome)
    {
        var client=Substitute.For<IAwsSnsSmsClient>();int calls=0;
        client.PublishSms(Arg.Any<string>(),Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(_=>{calls++;return outcome switch {
            "empty"=>Task.FromResult<string?>(null),"malformed"=>Task.FromResult<string?>("unusable-id"),"500"=>Task.FromException<string?>(new AmazonServiceException("provider-secret"){StatusCode=HttpStatusCode.InternalServerError}),"timeout"=>Task.FromException<string?>(new TaskCanceledException()),_=>Task.FromException<string?>(new IOException("accepted-then-response-lost"))};});
        var settings=Settings();settings.SmsProviderPrimary="aws-sns";settings.SmsProviderSecondary="twilio";var twilio=Substitute.For<ITwilioSmsService>();var sender=new SmsSender(new AWSService(client,Options.Create(settings)),twilio,Options.Create(settings));
        var result=await sender.SendDurable(Guid.NewGuid(),new("factor","sms","+15555550101","","123456"),TestContext.Current.CancellationToken);
        Assert.Equal(DeliverySendState.Unknown,result.Outcome.State);Assert.Equal(1,calls);await twilio.DidNotReceiveWithAnyArgs().SendSMS(default!,default!, cancellationToken: Arg.Any<CancellationToken>());
    }
    [Theory]
    [InlineData(DeliverySendState.Unknown,true,"smtp","receipt")]
    [InlineData((DeliverySendState)99,false,"smtp","receipt")]
    [InlineData(DeliverySendState.Accepted,false,"smtp","receipt\n")]
    [InlineData(DeliverySendState.Accepted,false,"bad provider","receipt")]
    public void Invalid_result_metadata_cannot_enable_retry_or_publication(DeliverySendState state,bool retry,string provider,string receipt)
    {var result=new DeliverySendResult(state,"raw provider secret",retry,provider,receipt).Normalize();Assert.Equal(DeliverySendState.Unknown,result.State);Assert.False(result.CanRetry);Assert.DoesNotContain("secret",result.Code);}
    [Theory]
    [InlineData(ProviderDeliveryStatus.Failed)] [InlineData(ProviderDeliveryStatus.ProviderUnavailable)] [InlineData(ProviderDeliveryStatus.Unknown)]
    public void Generic_provider_failures_are_conservatively_unknown_not_negative_receipts(ProviderDeliveryStatus status)
    {var result=new ProviderDeliveryResult(status,"twilio");Assert.Equal(DeliverySendState.Unknown,result.Outcome.State);Assert.False(result.CanFallback);}
}
