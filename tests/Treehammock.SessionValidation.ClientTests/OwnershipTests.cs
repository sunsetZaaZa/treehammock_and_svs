using Google.Protobuf;
using Treehammock.SessionValidation.Client;
using Treehammock.SessionValidation.Contracts.V1;
using Xunit;
namespace Treehammock.SessionValidation.ClientTests;
public sealed class OwnershipTests
{
    private sealed class Transport:IValidationTransport
    {
        internal int Calls,Disposals;internal byte[]? Request,Response;internal CancellationToken Token;internal DateTimeOffset Deadline;internal Func<byte[],Task<byte[]>>? Send;
        public bool TrustCurrent{get;set;}=true;
        public Task<byte[]> CallAsync(byte[] r,DateTimeOffset d,CancellationToken t){Calls++;Request=r;Deadline=d;Token=t;return Send is null?Task.FromResult(Response=ClientFixture.Reply(ValidateRequest.Parser.ParseFrom(r)).ToByteArray()):Send(r);}
        public void Dispose()=>Disposals++;
    }
    private sealed class Clock:TimeProvider{internal DateTimeOffset Now=DateTimeOffset.UtcNow;internal long Stamp;public override DateTimeOffset GetUtcNow()=>Now;public override long GetTimestamp()=>Stamp;public override long TimestampFrequency=>1000;}
    [Fact] public async Task Timeout_or_shutdown_cannot_release_uncancellable_provider_capacity_or_resources_early()
    {
        using var f=new ClientFixture();var t=new Transport();var finish=new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);t.Send=_=>finish.Task;var client=new SessionValidatorClient(f.Options(j=>{j["maximumConcurrentCalls"]=1;j["requestTimeoutMilliseconds"]=50;j["shutdownTimeoutMilliseconds"]=100;}),t,TimeProvider.System);var result=await client.ValidateAsync("private-token","backup.read",DateTimeOffset.UtcNow.AddSeconds(1),TestContext.Current.CancellationToken);Assert.Equal(503,result.HttpStatusCode);Assert.Equal(1,client.ActiveCalls);Assert.True(t.Token.IsCancellationRequested);for(int i=0;i<10000;i++)Assert.Equal(503,(await client.ValidateAsync("private-token","backup.read",DateTimeOffset.UtcNow.AddSeconds(1),TestContext.Current.CancellationToken)).HttpStatusCode);Assert.Equal(1,t.Calls);await client.DisposeAsync();Assert.False(client.Cleanup.IsCompleted);Assert.Equal(0,t.Disposals);Assert.Contains(t.Request!,b=>b!=0);var late=ClientFixture.Reply(ValidateRequest.Parser.ParseFrom(t.Request!)).ToByteArray();finish.SetResult(late);await client.Cleanup.WaitAsync(TimeSpan.FromSeconds(2),TestContext.Current.CancellationToken);Assert.Equal(0,client.ActiveCalls);Assert.Equal(1,t.Disposals);Assert.All(late,b=>Assert.Equal(0,b));Assert.All(t.Request!,b=>Assert.Equal(0,b));await client.DisposeAsync();Assert.Equal(1,t.Disposals);
    }
    [Theory][InlineData("empty")][InlineData("oversized")][InlineData("utf8-size")][InlineData("surrogate")][InlineData("controls")][InlineData("action")][InlineData("past")][InlineData("cancelled")][InlineData("untrusted")]
    public async Task Invalid_input_never_uses_transport(string kind)
    {
        using var f=new ClientFixture();var t=new Transport{TrustCurrent=kind!="untrusted"};await using var c=new SessionValidatorClient(f.Options(),t,TimeProvider.System);string s=kind switch{"empty"=>" ","oversized"=>new string('x',8193),"utf8-size"=>new string('ü',4097),"surrogate"=>"\ud800","controls"=>"private\ncredential",_=>"credential"};using var stop=new CancellationTokenSource();if(kind=="cancelled")stop.Cancel();var r=await c.ValidateAsync(s,kind=="action"?"auth.session.revoke":"backup.read",kind=="past"?DateTimeOffset.UtcNow.AddSeconds(-1):DateTimeOffset.UtcNow.AddSeconds(1),stop.Token);Assert.Equal(503,r.HttpStatusCode);Assert.Null(r.Subject);Assert.Equal(0,t.Calls);
    }
    [Theory][InlineData("backward")][InlineData("forward")][InlineData("monotonic")][InlineData("cancel-receipt")][InlineData("trust-receipt")]
    public async Task Receipt_time_cancellation_and_trust_are_checked_after_io(string fault)
    {
        using var f=new ClientFixture();var clock=new Clock();var t=new Transport();using var stop=new CancellationTokenSource();t.Send=request=>{var b=ClientFixture.Reply(ValidateRequest.Parser.ParseFrom(request)).ToByteArray();if(fault=="backward")clock.Now=clock.Now.AddSeconds(-1);if(fault=="forward")clock.Now=clock.Now.AddSeconds(5);if(fault=="monotonic")clock.Stamp=2000;if(fault=="cancel-receipt")stop.Cancel();if(fault=="trust-receipt")t.TrustCurrent=false;return Task.FromResult(b);};await using var c=new SessionValidatorClient(f.Options(),t,clock);var r=await c.ValidateAsync("credential","backup.read",clock.Now.AddSeconds(2),stop.Token);Assert.Equal(503,r.HttpStatusCode);Assert.Null(r.Subject);Assert.Equal(1,t.Calls);
    }
    [Fact] public async Task Earliest_budget_and_unique_request_id_are_preserved_without_positive_reuse()
    {
        using var f=new ClientFixture();var t=new Transport();var ids=new List<string>();t.Send=request=>{var r=ValidateRequest.Parser.ParseFrom(request);ids.Add(r.RequestId);return Task.FromResult(ClientFixture.Reply(r).ToByteArray());};await using var c=new SessionValidatorClient(f.Options(),t,TimeProvider.System);var deadline=DateTimeOffset.UtcNow.AddMilliseconds(700);Assert.Equal(200,(await c.ValidateAsync("credential","backup.read",deadline,TestContext.Current.CancellationToken)).HttpStatusCode);Assert.Equal(deadline,t.Deadline);Assert.Equal(200,(await c.ValidateAsync("credential","backup.read",DateTimeOffset.UtcNow.AddMinutes(1),TestContext.Current.CancellationToken)).HttpStatusCode);Assert.Equal(2,t.Calls);Assert.Equal(2,ids.Distinct().Count());Assert.True(t.Deadline<DateTimeOffset.UtcNow.AddMilliseconds(1100));Assert.All(t.Request!,b=>Assert.Equal(0,b));
    }
    [Fact] public async Task Tcp_budget_retains_retired_stream_slot_until_actual_async_disposal()
    {
        var budget=new ConnectionBudget(1);var released=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var first=await budget.EnterAsync(TestContext.Current.CancellationToken);var stream=new ConnectionStream(new DelayedStream(released.Task),first);var disposal=stream.DisposeAsync().AsTask();var second=budget.EnterAsync(TestContext.Current.CancellationToken);Assert.False(disposal.IsCompleted);Assert.False(second.IsCompleted);released.SetResult();await disposal;using var lease=await second;budget.Close();await Assert.ThrowsAsync<ObjectDisposedException>(()=>budget.EnterAsync(TestContext.Current.CancellationToken));lease.Dispose();stream.Dispose();
    }
    private sealed class DelayedStream(Task release):MemoryStream{public override async ValueTask DisposeAsync(){await release;await base.DisposeAsync();}}
}
