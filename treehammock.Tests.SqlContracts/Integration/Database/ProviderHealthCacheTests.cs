using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NSubstitute;
using StackExchange.Redis;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Rigging.Delivery;
using treehammock.Rigging.Sidewalk;
using treehammock.Services;
namespace treehammock.Tests.Integration.Database;
[Trait("Suite","SqlContracts")]
public sealed class Cor23KProviderHealthCacheTests
{
    private sealed class Fixture : IAsyncDisposable
    {
        internal IConnectionMultiplexer First=null!,Second=null!;
        internal IDatabase Database=>First.GetDatabase();
        internal readonly ProviderHealthSettings Settings=new(){FailureThreshold=3,WindowSeconds=10,OpenSeconds=1,MaxInFlightPerRoute=4};
        internal readonly SidewalkSettings Sms=new(){SmsEnabled=true,TwilioEnabled=true,AwsSnsEnabled=true,SmsProviderPrimary="twilio",SmsProviderSecondary="aws-sns",TwilioAccountSid="AC0123456789abcdef0123456789abcdef",TwilioAuthToken="fixture",TwilioFromPhoneNumber="+15555550100"};
        internal readonly HashSet<string> Keys=new();
        internal ProviderHealthService Service(bool second=false)=>new(Options.Create(Settings),Options.Create(new SMTPSettings{SMTPQualifiedDomain="relay.example.test",SMTPPort=587,SMTPUsername="fixture"}),Options.Create(Sms),Options.Create(new AbuseControlSettings{DragonflyTimeoutMilliseconds=5000}),second?Second.GetDatabase():Database);
        internal static async Task<Fixture> Open()
        {
            string? endpoint=Environment.GetEnvironmentVariable("TREEHAMMOCK_CORRECTION_CACHE_ENDPOINT"),password=Environment.GetEnvironmentVariable("TREEHAMMOCK_CORRECTION_CACHE_PASSWORD");
            if(string.IsNullOrWhiteSpace(endpoint)||string.IsNullOrWhiteSpace(password))throw new InvalidOperationException("Use the owned correction SQL/cache fixture.");
            var config=ConfigurationOptions.Parse(endpoint);config.Password=password;config.AbortOnConnectFail=true;config.AsyncTimeout=5000;
            var fixture=new Fixture();string scope="test-"+Guid.NewGuid().ToString("N");fixture.Settings.SmtpScope=scope;fixture.Settings.TwilioScope=scope;fixture.Settings.AwsSnsScope=scope;
            fixture.First=await ConnectionMultiplexer.ConnectAsync(config);try{fixture.Second=await ConnectionMultiplexer.ConnectAsync(config);return fixture;}catch{await fixture.First.DisposeAsync();throw;}
        }
        internal async Task<ProviderHealthPermit> Permit(DeliveryRoute route=DeliveryRoute.Twilio,bool second=false)
        {var p=await Service(second).AcquireAsync(route,TestContext.Current.CancellationToken);Keys.Add(p.Key);return p;}
        public async ValueTask DisposeAsync(){foreach(string key in Keys)await Database.KeyDeleteAsync(key);await Second.DisposeAsync();await First.DisposeAsync();}
    }
    [Fact]
    public async Task Real_cache_concurrent_instances_admit_exactly_bounded_permits_and_reuse_only_after_completion()
    {
        await using var f=await Fixture.Open();var a=f.Service();var b=f.Service(true);
        var permits=await Task.WhenAll(Enumerable.Range(0,64).Select(i=>(i%2==0?a:b).AcquireAsync(DeliveryRoute.Twilio,CancellationToken.None)));
        foreach(var p in permits)f.Keys.Add(p.Key);Assert.Equal(4,permits.Count(p=>p.Allowed));
        var live=permits.Where(p=>p.Allowed).ToArray();await Task.WhenAll(live.Select(p=>b.CompleteAsync(p,ProviderHealthEvidence.Neutral,CancellationToken.None)));
        Assert.True((await f.Permit()).Allowed);Assert.True((await f.Database.KeyTimeToLiveAsync(live[0].Key))>TimeSpan.Zero);
        Assert.InRange(await f.Database.HashLengthAsync(live[0].Key),4,12);
    }
    [Fact]
    public async Task Real_cache_atomic_outage_threshold_stale_receipts_and_single_recovery_probe_survive_new_instances()
    {
        await using var f=await Fixture.Open();var a=f.Service();var old=new List<ProviderHealthPermit>();for(int i=0;i<4;i++)old.Add(await f.Permit());
        await Task.WhenAll(old.Take(3).Select(p=>a.CompleteAsync(p,ProviderHealthEvidence.Outage,CancellationToken.None)));
        await a.CompleteAsync(old[0],ProviderHealthEvidence.Outage,CancellationToken.None);await a.CompleteAsync(old[3],ProviderHealthEvidence.Healthy,CancellationToken.None);
        Assert.Equal(3,(int)await f.Database.HashGetAsync(old[0].Key,"count"));Assert.False((await f.Permit(second:true)).Allowed);Assert.True((await f.Permit(DeliveryRoute.AwsSns,true)).Allowed);
        await Task.Delay(1100,TestContext.Current.CancellationToken);var restarted=f.Service(true);
        var probes=await Task.WhenAll(Enumerable.Range(0,64).Select(i=>(i%2==0?a:restarted).AcquireAsync(DeliveryRoute.Twilio,CancellationToken.None)));
        var probe=Assert.Single(probes.Where(p=>p.Allowed));Assert.Equal(0,probe.Slot);
        await restarted.CompleteAsync(probe,ProviderHealthEvidence.Healthy,CancellationToken.None);Assert.True((await f.Permit()).Allowed);
        await a.CompleteAsync(old[3],ProviderHealthEvidence.Outage,CancellationToken.None);Assert.Equal(0,(int)await f.Database.HashGetAsync(probe.Key,"count"));
    }
    [Theory][InlineData(ProviderHealthEvidence.Neutral)][InlineData(ProviderHealthEvidence.Outage)]
    public async Task Real_cache_nonhealthy_probe_reopens_and_expired_probe_cannot_close_a_later_generation(ProviderHealthEvidence evidence)
    {
        await using var f=await Fixture.Open();var service=f.Service();var first=await f.Permit();
        for(int i=0;i<3;i++){var p=i==0?first:await f.Permit();await service.CompleteAsync(p,ProviderHealthEvidence.Outage,CancellationToken.None);}
        await f.Database.HashSetAsync(first.Key,"open",1);var probe=await f.Permit();Assert.Equal(0,probe.Slot);
        await service.CompleteAsync(probe,evidence,CancellationToken.None);Assert.False((await f.Permit()).Allowed);
        await f.Database.HashSetAsync(first.Key,"open",1);probe=await f.Permit();await f.Database.HashSetAsync(first.Key,"probe_until",1);
        Assert.False((await f.Permit()).Allowed);await service.CompleteAsync(probe,ProviderHealthEvidence.Healthy,CancellationToken.None);Assert.False((await f.Permit()).Allowed);
    }
    [Fact]
    public async Task Real_cache_fixed_window_route_scope_and_user_budgets_remain_separate()
    {
        await using var f=await Fixture.Open();var service=f.Service();var p=await f.Permit();await service.CompleteAsync(p,ProviderHealthEvidence.Outage,CancellationToken.None);
        await f.Database.HashSetAsync(p.Key,"window",1);p=await f.Permit();await service.CompleteAsync(p,ProviderHealthEvidence.Outage,CancellationToken.None);Assert.Equal(1,(int)await f.Database.HashGetAsync(p.Key,"count"));
        f.Settings.TwilioScope="other-"+Guid.NewGuid().ToString("N");var other=await f.Permit();Assert.NotEqual(p.Key,other.Key);Assert.True(other.Allowed);
        var settings=new AbuseControlSettings{Delivery=new(){MaxEmailDeliveriesPerAccountPerHour=1,MaxEmailDeliveriesPerIpPerHour=1000}};
        using var counters=new DragonflyAbuseCounterStore(Options.Create(new AbuseCounterCacheSettings()),Options.Create(settings),f.First);
        var throttle=new DeliveryAbuseThrottleService(counters,Options.Create(settings),new HttpContextAccessor{HttpContext=new DefaultHttpContext()});
        var account=Guid.NewGuid();var key=new AbuseCounterKey(AbuseFeature.Delivery,AbuseCounterDimension.Account,$"email-{account:N}");f.Keys.Add(key.Value);f.Keys.Add(key.CooldownValue);
        var legacy=new AbuseCounterKey(AbuseFeature.Delivery,AbuseCounterDimension.DeliveryMethod,"providerfailure-email");
        // Never mutate a shared historical key in this fixture; only prove it is not read through provider state.
        Assert.True((await throttle.ShouldAllowDeliveryAsync(new(AbuseFeature.Activation,"email",account))).Allowed);
        Assert.False((await throttle.ShouldAllowDeliveryAsync(new(AbuseFeature.Activation,"email",account))).Allowed);
        Assert.True((await f.Permit(DeliveryRoute.Smtp)).Allowed);Assert.DoesNotContain(account.ToString("N"),p.Key);
        Assert.DoesNotContain("fixture",p.Key);Assert.DoesNotContain("providerfailure",p.Key);
    }
    private sealed class Responses(int status) : HttpMessageHandler,IHttpClientFactory
    {
        internal int Calls;
        public HttpClient CreateClient(string name)=>new(this,disposeHandler:false){Timeout=Timeout.InfiniteTimeSpan};
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token){Calls++;return Task.FromResult(new HttpResponseMessage((HttpStatusCode)status){Content=new StringContent("{}")});}
    }
    [Theory][InlineData(400)][InlineData(500)]
    public async Task Real_HTTP_adapter_and_real_cache_keep_bad_recipients_local_and_outage_unknown_without_unsafe_fallback(int status)
    {
        await using var f=await Fixture.Open();using var http=new Responses(status);var health=f.Service();var options=Options.Create(f.Sms);var aws=Substitute.For<IAWSService>();
        aws.SendSMS(Arg.Any<string>(),Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(ProviderDeliveryResult.Sent("aws-sns",Guid.NewGuid().ToString()));
        var sender=new SmsSender(aws,new TwilioSmsService(new TwilioMessageClient(http),options),options,health:health);
        for(int i=0;i<3;i++)
        {
            var result=await sender.SendDurable(Guid.NewGuid(),new("factor","sms","+1555555010"+i,"","123"),CancellationToken.None);
            Assert.Equal(status==400?DeliverySendState.Accepted:DeliverySendState.Unknown,result.Outcome.State);
        }
        var p=await f.Permit();Assert.Equal(status==400,p.Allowed);
        var final=await sender.SendDurable(Guid.NewGuid(),new("factor","sms","+15555550109","","123"),CancellationToken.None);
        Assert.Equal(DeliverySendState.Accepted,final.Outcome.State);Assert.Equal(status==400?4:3,http.Calls);
        if(status==500)await aws.Received(1).SendSMS(Arg.Any<string>(),Arg.Any<string>(),Arg.Any<CancellationToken>());
        var awsPermit=await f.Permit(DeliveryRoute.AwsSns);Assert.True(awsPermit.Allowed);
    }
    [Fact]
    public async Task Real_cache_expired_permit_replay_and_corrupt_route_state_cannot_fabricate_health()
    {
        await using var f=await Fixture.Open();var service=f.Service();var permit=await f.Permit();await f.Database.HashSetAsync(permit.Key,"until:"+permit.Slot,1);
        await service.CompleteAsync(permit,ProviderHealthEvidence.Outage,CancellationToken.None);Assert.Equal(0,(int)await f.Database.HashGetAsync(permit.Key,"count"));
        await f.Database.KeyDeleteAsync(permit.Key);await f.Database.StringSetAsync(permit.Key,"invalid",TimeSpan.FromSeconds(10));Assert.False((await f.Permit()).Allowed);
    }
}
