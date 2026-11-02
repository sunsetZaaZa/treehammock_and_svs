using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using NSubstitute;
using StackExchange.Redis;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Rigging.Dependencies;
using treehammock.Rigging.Delivery;
using treehammock.Services;
using treehammock.Tests.Infrastructure;
namespace treehammock.Tests.Unit;

public sealed class Cor23MAuthoritativeBudgetTests
{
    private static AbuseCounterKey Key(AbuseFeature feature=AbuseFeature.Login,AbuseCounterDimension dimension=AbuseCounterDimension.IpFingerprint) => new(feature,dimension,"owned-fixture");
    private static readonly AbuseCounterLimit Limit=new(5,TimeSpan.FromSeconds(10));
    private static AbuseControlSettings Settings() => new() { CounterFailureMode=AbuseCounterFailureMode.RequirePostgreSqlBudgetV1,PostgreSqlFallbackPolicies=[AbuseFeature.Login,AbuseFeature.Delivery],PostgreSqlBudgetTimeoutMilliseconds=50 };
    private static RedisResult Reply(params int[] values) => RedisResult.Create(values.Select(v=>(RedisValue)v).ToArray());
    private static DragonflyAbuseCounterStore Store(IDatabase database,IPostgreSqlAbuseBudgetStore? durable=null,AbuseControlSettings? settings=null)
    {
        var connection=Substitute.For<IConnectionMultiplexer>();connection.GetDatabase(Arg.Any<int>(),Arg.Any<object?>()).Returns(database);
        return new(Options.Create(new AbuseCounterCacheSettings {database=0}),Options.Create(settings??Settings()),connection,durable);
    }
    private static void CacheFails(IDatabase database) => database.ScriptEvaluateAsync(Arg.Any<string>(),Arg.Any<RedisKey[]>(),Arg.Any<RedisValue[]>(),Arg.Any<CommandFlags>())
        .Returns(_=>Task.FromException<RedisResult>(new RedisServerException("owned cache unavailable")));
    private static IPostgreSqlAbuseBudgetStore Allows(int count=1)
    {
        var durable=Substitute.For<IPostgreSqlAbuseBudgetStore>();durable.IncrementAsync(Arg.Any<AbuseCounterKey>(),Arg.Any<AbuseCounterLimit>(),Arg.Any<CancellationToken>())
            .Returns(c=>new CounterDecision(true,count,c.ArgAt<AbuseCounterLimit>(1).MaxAttempts,c.ArgAt<AbuseCounterLimit>(1).Window,null,null));return durable;
    }
    [Theory]
    [InlineData(AbuseFeature.Login,AbuseCounterDimension.Account)][InlineData(AbuseFeature.Login,AbuseCounterDimension.IpFingerprint)][InlineData(AbuseFeature.Login,AbuseCounterDimension.IdentifierFingerprint)]
    [InlineData(AbuseFeature.Delivery,AbuseCounterDimension.Account)][InlineData(AbuseFeature.Delivery,AbuseCounterDimension.IpFingerprint)][InlineData(AbuseFeature.Delivery,AbuseCounterDimension.IdentifierFingerprint)]
    public async Task Cache_outage_allows_only_a_completed_equivalent_selected_budget(AbuseFeature feature,AbuseCounterDimension dimension)
    {
        var cache=Substitute.For<IDatabase>();CacheFails(cache);var durable=Allows();using var store=Store(cache,durable);
        var result=await store.IncrementAsync(Key(feature,dimension),Limit);Assert.True(result.CanAdmit);Assert.False(result.Unavailable);Assert.Equal(1,result.CurrentCount);Assert.Null(result.ReasonCode);
        await durable.Received(1).IncrementAsync(Key(feature,dimension),Limit,Arg.Any<CancellationToken>());
    }
    [Theory]
    [InlineData(AbuseFeature.Signup,AbuseCounterDimension.IpFingerprint)][InlineData(AbuseFeature.Reauthentication,AbuseCounterDimension.Session)]
    [InlineData(AbuseFeature.TwoFactorChallenge,AbuseCounterDimension.Challenge)][InlineData(AbuseFeature.TwoFactorSetup,AbuseCounterDimension.Account)]
    [InlineData(AbuseFeature.PasswordResetRequest,AbuseCounterDimension.Account)][InlineData(AbuseFeature.PasswordResetFinalize,AbuseCounterDimension.Reset)]
    [InlineData(AbuseFeature.AccountUnlock,AbuseCounterDimension.TokenFingerprint)][InlineData(AbuseFeature.Activation,AbuseCounterDimension.IpFingerprint)]
    [InlineData(AbuseFeature.AccountDeleteFinalize,AbuseCounterDimension.Account)][InlineData(AbuseFeature.PublicTokenVerification,AbuseCounterDimension.TokenFingerprint)]
    [InlineData(AbuseFeature.PasswordResetTokenVerification,AbuseCounterDimension.Reset)][InlineData(AbuseFeature.PasswordResetTwoFactorProof,AbuseCounterDimension.Reset)]
    [InlineData(AbuseFeature.Login,AbuseCounterDimension.Session)][InlineData(AbuseFeature.Delivery,AbuseCounterDimension.DeliveryMethod)]
    public async Task Redis_only_or_unsupported_dimensions_deny_without_SQL_write(AbuseFeature feature,AbuseCounterDimension dimension)
    {
        var cache=Substitute.For<IDatabase>();CacheFails(cache);var durable=Allows();using var store=Store(cache,durable);
        var result=await store.IncrementAsync(Key(feature,dimension),Limit);Assert.False(result.CanAdmit);Assert.True(result.Unavailable);Assert.Empty(durable.ReceivedCalls());
    }
    [Fact]
    public async Task Healthy_cache_still_requires_SQL_first_and_returns_the_authoritative_count()
    {
        var order=new List<string>();var cache=Substitute.For<IDatabase>();var durable=Allows(3);
        durable.IncrementAsync(Arg.Any<AbuseCounterKey>(),Arg.Any<AbuseCounterLimit>(),Arg.Any<CancellationToken>()).Returns(_=>{order.Add("sql");return new CounterDecision(true,3,5,Limit.Window,null,null);});
        cache.ScriptEvaluateAsync(Arg.Any<string>(),Arg.Any<RedisKey[]>(),Arg.Any<RedisValue[]>(),Arg.Any<CommandFlags>()).Returns(_=>{order.Add("cache");return Task.FromResult(Reply(1,1,0,0,0));});
        using var store=Store(cache,durable);var result=await store.IncrementAsync(Key(),Limit);Assert.True(result.CanAdmit);Assert.Equal(3,result.CurrentCount);Assert.Equal(new[]{"sql","cache"},order);
    }
    [Theory][InlineData(false)][InlineData(true)]
    public async Task PostgreSQL_failure_or_limit_denial_never_consults_a_healthy_cache(bool failure)
    {
        var cache=Substitute.For<IDatabase>();var durable=Allows();
        durable.IncrementAsync(Arg.Any<AbuseCounterKey>(),Arg.Any<AbuseCounterLimit>(),Arg.Any<CancellationToken>()).Returns(_=>failure
            ?Task.FromException<CounterDecision>(DependencyUnavailableException.Database("budget",DependencyStage.Execute))
            :Task.FromResult(new CounterDecision(false,6,5,Limit.Window,TimeSpan.FromSeconds(10),AbuseReasonCodes.CounterLimitExceeded)));
        using var store=Store(cache,durable);var result=await store.IncrementAsync(Key(),Limit);Assert.False(result.CanAdmit);Assert.Equal(failure,result.Unavailable);Assert.Empty(cache.ReceivedCalls());
    }
    [Fact]
    public async Task Selected_mode_without_an_owner_cannot_fabricate_allow()
    {
        var cache=Substitute.For<IDatabase>();using var store=Store(cache);var result=await store.IncrementAsync(Key(),Limit);Assert.True(result.Unavailable);Assert.False(result.CanAdmit);Assert.Empty(cache.ReceivedCalls());
    }
    [Fact]
    public async Task Unselected_delivery_remains_fail_closed_without_SQL()
    {
        var cache=Substitute.For<IDatabase>();CacheFails(cache);var durable=Allows();var settings=Settings();settings.PostgreSqlFallbackPolicies=[AbuseFeature.Login];using var store=Store(cache,durable,settings);
        Assert.True((await store.IncrementAsync(Key(AbuseFeature.Delivery),Limit)).Unavailable);Assert.Empty(durable.ReceivedCalls());
    }
    [Fact]
    public async Task FailClosed_default_never_uses_durable_fallback()
    {
        var cache=Substitute.For<IDatabase>();CacheFails(cache);var durable=Allows();using var store=Store(cache,durable,new());Assert.True((await store.IncrementAsync(Key(),Limit)).Unavailable);Assert.Empty(durable.ReceivedCalls());
    }
    [Fact]
    public async Task A_late_SQL_completion_after_deadline_cannot_change_denial_or_start_cache_work()
    {
        var cache=Substitute.For<IDatabase>();var durable=Allows();var pending=new TaskCompletionSource<CounterDecision>(TaskCreationOptions.RunContinuationsAsynchronously);
        durable.IncrementAsync(Arg.Any<AbuseCounterKey>(),Arg.Any<AbuseCounterLimit>(),Arg.Any<CancellationToken>()).Returns(pending.Task);
        using var store=Store(cache,durable);var result=await store.IncrementAsync(Key(),Limit);Assert.False(result.CanAdmit);Assert.Equal(AbuseReasonCodes.CounterStoreTimeout,result.ReasonCode);
        pending.SetResult(new(true,1,5,Limit.Window,null,null));Assert.False(result.CanAdmit);Assert.Empty(cache.ReceivedCalls());
    }
    [Fact]
    public async Task Caller_cancellation_stops_admission_without_SQL_or_cache_work()
    {
        var cache=Substitute.For<IDatabase>();var durable=Allows();using var store=Store(cache,durable);using var canceled=new CancellationTokenSource();canceled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>store.IncrementAsync(Key(),Limit,canceled.Token));Assert.Empty(cache.ReceivedCalls());Assert.Empty(durable.ReceivedCalls());
    }
    [Fact]
    public async Task Mode_and_policy_selection_are_snapshotted_at_store_composition()
    {
        var settings=new AbuseControlSettings();var cache=Substitute.For<IDatabase>();CacheFails(cache);var durable=Allows();using var store=Store(cache,durable,settings);
        settings.CounterFailureMode=AbuseCounterFailureMode.RequirePostgreSqlBudgetV1;settings.PostgreSqlFallbackPolicies.Add(AbuseFeature.Login);
        Assert.True((await store.IncrementAsync(Key(),Limit)).Unavailable);Assert.Empty(durable.ReceivedCalls());
    }
    [Theory][InlineData(false)][InlineData(true)]
    public async Task Failed_SQL_reset_never_clears_cache_admission_state(bool failure)
    {
        var cache=Substitute.For<IDatabase>();var durable=Allows();durable.ResetAsync(Arg.Any<AbuseCounterKey>(),Arg.Any<CancellationToken>()).Returns(_=>failure?Task.FromException(new InvalidOperationException("owned SQL failure")):Task.CompletedTask);
        using var store=Store(cache,durable);await store.ResetAsync(Key());Assert.Equal(failure?0:1,cache.ReceivedCalls().Count());
    }
    [Theory][InlineData(false,false)][InlineData(true,false)][InlineData(false,true)]
    public async Task Cooldown_requires_equivalent_SQL_state_before_cache_outage_can_be_degraded(bool active,bool failure)
    {
        var cache=Substitute.For<IDatabase>();CacheFails(cache);var durable=Allows();durable.GetCooldownAsync(Arg.Any<AbuseCounterKey>(),Arg.Any<CancellationToken>()).Returns(_=>failure?Task.FromException<CooldownDecision>(new InvalidOperationException("owned SQL failure")):Task.FromResult(new CooldownDecision(active,active?TimeSpan.FromSeconds(1):null,active?AbuseReasonCodes.FailureCooldownActive:null)));
        using var store=Store(cache,durable);var result=await store.GetCooldownAsync(Key());Assert.Equal(active||failure,result.BlocksAdmission);Assert.Equal(failure,result.Unavailable);
    }
    [Theory][InlineData(AbuseReasonCodes.CounterStoreUnavailable)][InlineData(AbuseReasonCodes.CounterStoreTimeout)]
    public async Task An_unavailable_allow_bit_cannot_admit_real_login_lookup_or_password_work(string reason)
    {
        var harness=new AccountControllerHarness();harness.AbuseCounterStore.IncrementAsync(Arg.Any<AbuseCounterKey>(),Arg.Any<AbuseCounterLimit>(),Arg.Any<CancellationToken>()).Returns(c=>new CounterDecision(true,1,c.ArgAt<AbuseCounterLimit>(1).MaxAttempts,c.ArgAt<AbuseCounterLimit>(1).Window,null,reason,CounterStoreAvailability.Unavailable));
        var controller=harness.CreateLoginController();var result=await controller.Authenticate(harness.LoginPayload());AccountControllerHarness.ExtractEnvelope(result,StatusCodes.Status503ServiceUnavailable);
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().GetCredentials(default!,default,cancellationToken:Arg.Any<CancellationToken>());Assert.Empty(harness.Delivery.Intents);
    }
    [Fact]
    public async Task Unavailable_delivery_cannot_create_a_candidate_or_publish_to_a_provider()
    {
        var harness=new AccountControllerHarness();var controller=harness.CreateTwoFactorController();harness.SetAuthenticatedSession();
        // Satisfy the existing sensitive-action gate so this test reaches delivery admission.
        harness.HttpContext.Request.Headers[treehammock.Rigging.Security.SensitiveActionTokenConstants.HeaderName]="owned-sensitive-proof";
        var cache=Substitute.For<IDatabase>();CacheFails(cache);using var counter=Store(cache,null);var policy=new DeliveryAbuseThrottleService(counter,Options.Create(new AbuseControlSettings()),new HttpContextAccessor{HttpContext=harness.HttpContext});
        using var storage=new treehammock.Rigging.Database.StorageContext(Options.Create(new DatabaseSettings {servers="localhost",database="owned-fixture",userId="owned-fixture",password="owned-fixture"}));
        var delivery=new DurableDeliveryService(new treehammock.Repos.DeliveryOutboxRepo(storage,Options.Create(new DeliveryOutboxSettings())),CapturingDurableDelivery.Protector(),policy);
        harness.HttpContext.RequestServices=new ServiceCollection().AddSingleton<IDurableDeliveryService>(delivery).AddSingleton(harness.SensitiveActionService).AddSingleton(harness.LoginProofs).BuildServiceProvider();
        var error=await Assert.ThrowsAsync<DependencyUnavailableException>(()=>controller.SetupTwoFactorMethod(new treehammock.Models.Authentication.SetupLayeredAuthenticateMethodRequest(treehammock.RiggingSupport.Enum.TwoFactorAuthMethod.SMS_KEY,"5555550101",1,true)));
        Assert.Equal("dragonfly",error.Failure.Dependency);Assert.Equal("delivery_admission",error.Failure.Operation);
        Assert.Empty(harness.Delivery.Intents);
    }
    [Theory][InlineData(0)][InlineData(6)]
    public async Task A_malformed_SQL_allow_count_cannot_authorize_cache_work(int count)
    {
        var cache=Substitute.For<IDatabase>();using var store=Store(cache,Allows(count));Assert.True((await store.IncrementAsync(Key(),Limit)).Unavailable);Assert.Empty(cache.ReceivedCalls());
    }
}
