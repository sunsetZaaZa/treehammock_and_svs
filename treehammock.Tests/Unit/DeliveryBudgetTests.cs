using System.Diagnostics;
using System.ComponentModel.DataAnnotations;
using Microsoft.Extensions.Options;
using NSubstitute;
using treehammock.Rigging.Config;
using treehammock.Rigging.Delivery;
using treehammock.Rigging.Sidewalk;
using treehammock.Services;
namespace treehammock.Tests.Unit;
public sealed class Cor23JDeliveryBudgetTests
{
    internal static DeliveryExecutionPolicy Policy(int total=1,int attempt=1,int capacity=1)=>new(Options.Create(new DeliveryOutboxSettings {ProviderTimeoutSeconds=total,ProviderAttemptTimeoutSeconds=attempt,CancellationDrainSeconds=1,MaxConcurrentSends=capacity}));
    private static TaskCompletionSource<T> Signal<T>()=>new(TaskCreationOptions.RunContinuationsAsynchronously);
    [Theory][InlineData(false)][InlineData(true)]
    public async Task Request_cancellation_reaches_throttle_before_any_email_or_SMS_submission(bool sms)
    {
        var policy=Policy();var entered=Signal<bool>();var released=Signal<bool>();
        var throttle=Substitute.For<IDeliveryAbuseThrottleService>();
        throttle.ShouldAllowDeliveryAsync(Arg.Any<DeliveryAbuseThrottleRequest>(),Arg.Any<CancellationToken>()).Returns(async call=>
        {
            var token=call.ArgAt<CancellationToken>(1);entered.SetResult(token.CanBeCanceled);
            try {await Task.Delay(Timeout.InfiniteTimeSpan,token);return treehammock.Rigging.Abuse.AbuseDecision.Allow();}
            finally {released.TrySetResult(token.IsCancellationRequested);}
        });
        var mail=Substitute.For<ISMTPService>();var text=Substitute.For<ISmsSender>();
        var service=new TwoFactorAuthenticateService(mail,text,deliveryAbuseThrottleService:throttle,execution:policy);
        using var cancel=new CancellationTokenSource();Task<bool?> send=sms?service.SMS("+15555550101","123456",token:cancel.Token):Project(service.Email("recipient@example.test","123456",token:cancel.Token));
        Assert.True(await entered.Task.WaitAsync(TimeSpan.FromSeconds(3)));cancel.Cancel();Assert.False(await send);
        Assert.True(await released.Task);Assert.Equal(0,policy.ActiveOperations);Assert.Equal(1,policy.AvailableCapacity);
        await mail.DidNotReceiveWithAnyArgs().TwoFactorKeyOutboundLetter(default!,default!,default!,default);
        await text.DidNotReceiveWithAnyArgs().SendCode(default!,default!,default);
    }
    private static async Task<bool?> Project(Task<bool> task)=>await task;
    [Theory][InlineData(false)][InlineData(true)]
    public async Task Precancelled_root_and_expired_durable_deadline_do_not_start_or_consume_capacity(bool expired)
    {
        var policy=Policy();int calls=0;using var cancel=new CancellationTokenSource();if(!expired)cancel.Cancel();
        int result=await policy.RunAsync(cancel.Token,_=>{calls++;return Task.FromResult(1);},()=>-1,()=>-2,expired?DateTimeOffset.UtcNow.AddSeconds(-1):null);
        Assert.Equal(-1,result);Assert.Equal(0,calls);Assert.Equal(1,policy.AvailableCapacity);
    }
    [Fact]
    public async Task Eight_hung_sends_keep_two_owned_slots_after_deadline_and_release_only_after_actual_completion()
    {
        var policy=Policy(capacity:2);var release=Signal<int>();int calls=0,peak=0;
        var watch=Stopwatch.StartNew();
        Task<int>[] work=Enumerable.Range(0,8).Select(_=>policy.RunAsync(CancellationToken.None,b=>
        {
            int active=Interlocked.Increment(ref calls);peak=Math.Max(peak,active);return release.Task;
        },()=>-1,()=>-2)).ToArray();
        try
        {
            int[] results=await Task.WhenAll(work).WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(2,results.Count(r=>r==-2));Assert.Equal(6,results.Count(r=>r==-1));Assert.Equal(2,calls);Assert.Equal(2,peak);
            Assert.True(watch.Elapsed<TimeSpan.FromSeconds(4));Assert.Equal(2,policy.ActiveOperations);Assert.Equal(0,policy.AvailableCapacity);
        }
        finally {release.TrySetResult(1);}
        await Eventually(()=>policy.ActiveOperations==0);Assert.Equal(2,policy.AvailableCapacity);
    }
    [Fact]
    public async Task Cancellation_joins_cooperative_work_and_shutdown_retains_uncooperative_ownership()
    {
        var policy=Policy();var entered=Signal<bool>();using var cancel=new CancellationTokenSource();
        var send=policy.RunAsync(cancel.Token,async b=>{entered.SetResult(true);await Task.Delay(Timeout.InfiniteTimeSpan,b.Token);return 1;},()=>-1,()=>-2);
        await entered.Task;cancel.Cancel();Assert.Equal(-2,await send);Assert.Equal(0,policy.ActiveOperations);
        var held=Signal<int>();var started=Signal<bool>();var pending=policy.RunAsync(CancellationToken.None,_=>{started.SetResult(true);return held.Task;},()=>-1,()=>-2);
        await started.Task;await policy.StopAsync(CancellationToken.None);Assert.Equal(-2,await pending);Assert.Equal(1,policy.ActiveOperations);
        held.SetException(new IOException("owned late fault"));await Eventually(()=>policy.ActiveOperations==0);Assert.Equal(1,policy.AvailableCapacity);
    }
    [Fact]
    public async Task Nested_boundaries_share_one_slot_and_authority_denial_prevents_a_second_attempt()
    {
        var policy=Policy();int authority=0,starts=0;
        int result=await policy.RunAsync(CancellationToken.None,async b=>
        {
            return await policy.RunAsync(b.Token,async inherited=>
            {
                Assert.Same(b,inherited);using var first=await inherited.BeginAttemptAsync(b.Token);Assert.NotNull(first);starts++;
                using var second=await inherited.BeginAttemptAsync(b.Token);Assert.Null(second);return starts;
            },()=>-1,()=>-2);
        },()=>-1,()=>-2,canSend:_=>Task.FromResult(++authority==1));
        Assert.Equal(1,result);Assert.Equal(2,authority);Assert.Equal(1,policy.AvailableCapacity);
    }
    [Theory][InlineData(0,1,1,1,60)][InlineData(2,3,1,1,60)][InlineData(2,1,0,1,60)][InlineData(2,1,1,9,60)][InlineData(20,10,2,4,32)]
    public void Invalid_budget_and_lease_combinations_fail_validation(int total,int attempt,int drain,int capacity,int lease)
    {
        var s=new DeliveryOutboxSettings {ProviderTimeoutSeconds=total,ProviderAttemptTimeoutSeconds=attempt,CancellationDrainSeconds=drain,MaxConcurrentSends=capacity,LeaseSeconds=lease,EncryptionKeys=new(){{1,Convert.ToBase64String(new byte[32])}}};
        Assert.False(Validator.TryValidateObject(s,new ValidationContext(s),new List<ValidationResult>(),true));
    }
    [Fact]
    public async Task Execution_settings_are_snapshotted_and_cannot_expand_capacity_after_start()
    {
        var settings=new DeliveryOutboxSettings {ProviderTimeoutSeconds=1,ProviderAttemptTimeoutSeconds=1,CancellationDrainSeconds=1,MaxConcurrentSends=1};
        var policy=new DeliveryExecutionPolicy(Options.Create(settings));settings.ProviderTimeoutSeconds=30;settings.MaxConcurrentSends=8;
        var watch=Stopwatch.StartNew();Assert.Equal(-2,await policy.RunAsync(CancellationToken.None,async b=>{await Task.Delay(Timeout.InfiniteTimeSpan,b.Token);return 1;},()=>-1,()=>-2));
        Assert.True(watch.Elapsed<TimeSpan.FromSeconds(3));Assert.Equal(1,policy.AvailableCapacity);
    }
    internal static async Task Eventually(Func<bool> check)
    {
        using var timer=new CancellationTokenSource(TimeSpan.FromSeconds(5));while(!check())await Task.Delay(10,timer.Token);
    }
}
