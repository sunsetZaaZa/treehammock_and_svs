using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using NodaTime;
using Treehammock.SessionValidation.Core;
using Treehammock.SessionValidation.Storage;
using Treehammock.SessionValidation.UnitTests;
using Xunit;
namespace Treehammock.SessionValidation.StorageTests;

public sealed class AuthorityReaderTests
{
    private static readonly Instant Now = TestSessions.Now;
    private static string Hash(string token) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
    private static readonly string Binding = Hash(TestSessions.Mint());
    private static string Json() => $$"""
    {"accountId":"{{TestSessions.Identity.AccountId}}","version":4,"features":1,"capabilities":["account.manage","account.read"],"rightsEnabled":false,"evaluatedAt":"2026-10-17T01:00:00Z","nextBoundary":null,"eligibilityUntil":null,"grants":[]}
    """;
    private static CurrentSessionRow Row() => new(Binding,TestSessions.Identity,TestSessions.Identity.AccountStamp,TestSessions.Key(),
        new(Now+Duration.FromMinutes(5),Now+Duration.FromHours(1),null),1,null,Now,Json());
    private sealed class Clock : IClock { public Instant Now = TestSessions.Now; public Instant GetCurrentInstant() => Now; }
    private sealed class Executor(Func<string,TimeSpan,CancellationToken,Task<CurrentSessionRow?>> read) : IYsqlSnapshotExecutor
    {
        public int Calls; public TimeSpan Budget; public CancellationToken Token;
        public Task<CurrentSessionRow?> ReadAsync(string binding,TimeSpan budget,CancellationToken token)
        { Calls++;Budget=budget;Token=token;return read(binding,budget,token); }
    }
    private static Executor Returns(CurrentSessionRow? row) => new((_,_,_)=>Task.FromResult(row));
    private static YsqlSessionAuthority Reader(Executor executor,Clock? clock=null,TimeSpan? budget=null) => new(executor,budget??TimeSpan.FromSeconds(1),clock??new Clock());

    [Theory]
    [InlineData("valid",AuthorityReadStatus.Found)]
    [InlineData("unverified",AuthorityReadStatus.Unauthenticated)]
    [InlineData("sent",AuthorityReadStatus.Unauthenticated)]
    [InlineData("replaced",AuthorityReadStatus.Unauthenticated)]
    [InlineData("unknown-status",AuthorityReadStatus.Unavailable)]
    [InlineData("locked",AuthorityReadStatus.Unauthenticated)]
    [InlineData("unlock-equal",AuthorityReadStatus.Found)]
    [InlineData("stamp",AuthorityReadStatus.Unauthenticated)]
    [InlineData("empty-account-stamp",AuthorityReadStatus.Unavailable)]
    [InlineData("empty-family",AuthorityReadStatus.Unavailable)]
    [InlineData("generation-zero",AuthorityReadStatus.Unavailable)]
    [InlineData("generation-overflow",AuthorityReadStatus.Unavailable)]
    [InlineData("protocol",AuthorityReadStatus.Unavailable)]
    [InlineData("access-equal",AuthorityReadStatus.Unauthenticated)]
    [InlineData("hard-equal",AuthorityReadStatus.Unauthenticated)]
    [InlineData("cutoff-equal",AuthorityReadStatus.Unauthenticated)]
    [InlineData("future-read",AuthorityReadStatus.Unavailable)]
    [InlineData("wrong-binding",AuthorityReadStatus.Unavailable)]
    [InlineData("short-key",AuthorityReadStatus.Unavailable)]
    public async Task Admits_only_complete_current_evidence(string kind,AuthorityReadStatus expected)
    {
        var row=Row();
        row=kind switch {
            "unverified"=>row with { VerificationStatus=0 }, "sent"=>row with { VerificationStatus=2 },
            "replaced"=>row with { VerificationStatus=6 }, "unknown-status"=>row with { VerificationStatus=99 },
            "locked"=>row with { UnlockWhen=Now+Duration.FromSeconds(1) }, "unlock-equal"=>row with { UnlockWhen=Now },
            "stamp"=>row with { AccountStamp=Guid.NewGuid() }, "empty-account-stamp"=>row with { AccountStamp=Guid.Empty },
            "empty-family"=>row with { Identity=row.Identity with { FamilyId=Guid.Empty } },
            "generation-zero"=>row with { Identity=row.Identity with { Generation=0 } },
            "generation-overflow"=>row with { Identity=row.Identity with { Generation=SessionIdentity.MaximumGeneration+1 } },
            "protocol"=>row with { Identity=row.Identity with { ProtocolVersion=1 } },
            "access-equal"=>row with { Lifetime=row.Lifetime with { AccessExpiration=Now } },
            "hard-equal"=>row with { Lifetime=row.Lifetime with { HardExpiration=Now } },
            "cutoff-equal"=>row with { Lifetime=row.Lifetime with { Cutoff=Now } },
            "future-read"=>row with { ReadAt=Now+Duration.FromSeconds(1) },
            "wrong-binding"=>row with { Binding=new string('A',64) }, "short-key"=>row with { Key=new byte[16] }, _=>row };
        var executor=Returns(row);
        using var result=await Reader(executor).ReadAsync(Binding,Now+Duration.FromSeconds(1),TestContext.Current.CancellationToken);
        Assert.Equal(expected,result.Status);Assert.Equal(1,executor.Calls);
        Assert.All(row.Key,b=>Assert.Equal(0,b));
        Assert.Equal(expected==AuthorityReadStatus.Found,result.Projection is not null);
        Assert.DoesNotContain(Binding,result.ToString());
    }
    [Theory]
    [InlineData("missing-account")][InlineData("wrong-account")][InlineData("missing-version")][InlineData("version-zero")]
    [InlineData("version-overflow")][InlineData("tier")][InlineData("paid-disabled")][InlineData("unknown-capability")]
    [InlineData("null-capabilities")][InlineData("missing-grants")][InlineData("null-grants")]
    [InlineData("future-evaluation")][InlineData("different-snapshot")][InlineData("boundary-equal")]
    [InlineData("missing-rights")][InlineData("malformed")][InlineData("missing-boundary")]
    public async Task Malformed_or_stale_entitlements_are_unavailable(string kind)
    {
        var json=JsonNode.Parse(Json())!.AsObject();
        switch(kind) {
            case "missing-account":json.Remove("accountId");break;
            case "wrong-account":json["accountId"]=Guid.NewGuid().ToString();break;
            case "missing-version":json.Remove("version");break;
            case "version-zero":json["version"]=0;break;
            case "version-overflow":json["version"]=SessionIdentity.MaximumGeneration+1;break;
            case "tier":json["features"]=3;break;case "paid-disabled":json["features"]=2;break;
            case "unknown-capability":json["capabilities"]=new JsonArray("admin");break;
            case "null-capabilities":json["capabilities"]=null;break;
            case "missing-grants":json.Remove("grants");break;case "null-grants":json["grants"]=null;break;
            case "future-evaluation":json["evaluatedAt"]="2026-10-17T01:01:00Z";break;
            case "different-snapshot":json["evaluatedAt"]="2026-10-17T00:59:00Z";break;
            case "boundary-equal":json["nextBoundary"]="2026-10-17T01:00:00Z";break;
            case "missing-rights":json.Remove("rightsEnabled");break;case "missing-boundary":json.Remove("nextBoundary");break;
        }
        var row=Row() with { EntitlementJson=kind=="malformed"?"not-json":json.ToJsonString() };
        using var result=await Reader(Returns(row)).ReadAsync(Binding,Now+Duration.FromSeconds(1),TestContext.Current.CancellationToken);
        Assert.Equal(AuthorityReadStatus.Unavailable,result.Status);Assert.Null(result.Projection);
        Assert.All(row.Key,b=>Assert.Equal(0,b));
    }
    [Theory]
    [InlineData("")][InlineData("abcd")][InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA;")]
    public async Task Invalid_hash_never_opens_database(string hash)
    { var e=Returns(Row());using var result=await Reader(e).ReadAsync(hash,Now+Duration.FromSeconds(1),TestContext.Current.CancellationToken);Assert.Equal(AuthorityReadStatus.Unavailable,result.Status);Assert.Equal(0,e.Calls); }
    [Fact] public async Task Missing_row_is_not_found()
    { using var r=await Reader(Returns(null)).ReadAsync(Binding,Now+Duration.FromSeconds(1),TestContext.Current.CancellationToken);Assert.Equal(AuthorityReadStatus.NotFound,r.Status);Assert.Null(r.Projection); }
    [Fact] public async Task Database_failure_contains_no_private_exception()
    { var e=new Executor((_,_,_)=>throw new Exception("private-key-canary"));using var r=await Reader(e).ReadAsync(Binding,Now+Duration.FromSeconds(1),TestContext.Current.CancellationToken);Assert.Equal(AuthorityReadStatus.Unavailable,r.Status);Assert.DoesNotContain("canary",r.ToString()); }
    [Fact] public async Task Expired_deadline_never_opens_database()
    { var e=Returns(Row());using var r=await Reader(e).ReadAsync(Binding,Now,TestContext.Current.CancellationToken);Assert.Equal(AuthorityReadStatus.Unavailable,r.Status);Assert.Equal(0,e.Calls); }
    private sealed class OperationOwner(Action release):IDisposable { public void Dispose()=>release(); }
    [Fact] public async Task Fleet_operation_owner_is_released_after_late_result_key_erasure()
    {
        var completion=new TaskCompletionSource<CurrentSessionRow?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var released=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var row=Row();bool erased=false;
        var reader=new YsqlSessionAuthority(new Executor((_,_,_)=>completion.Task),TimeSpan.FromSeconds(1),new Clock(),ownOperation:()=>new OperationOwner(()=>{erased=row.Key.All(x=>x==0);released.SetResult();}));
        using var cancel=CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var work=reader.ReadAsync(Binding,Now+Duration.FromSeconds(1),cancel.Token);cancel.Cancel();await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>work);Assert.False(released.Task.IsCompleted);
        completion.SetResult(row);await released.Task.WaitAsync(TimeSpan.FromSeconds(2),TestContext.Current.CancellationToken);Assert.True(erased);
    }
    [Fact] public async Task Caller_cancellation_propagates()
    { var e=Returns(Row());using var c=CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);c.Cancel();await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>Reader(e).ReadAsync(Binding,Now+Duration.FromSeconds(1),c.Token));Assert.Equal(0,e.Calls); }
    [Fact] public async Task Timeout_bounds_uncooperative_driver_and_erases_late_key()
    {
        var completion=new TaskCompletionSource<CurrentSessionRow?>();var e=new Executor((_,_,_)=>completion.Task);
        using var r=await Reader(e,budget:TimeSpan.FromMilliseconds(20)).ReadAsync(Binding,Now+Duration.FromSeconds(1),TestContext.Current.CancellationToken);
        Assert.Equal(AuthorityReadStatus.Unavailable,r.Status);Assert.True(e.Token.IsCancellationRequested);
        var row=Row();completion.SetResult(row);Assert.All(row.Key,b=>Assert.Equal(0,b));
    }
    [Fact] public async Task Cancellation_in_flight_erases_late_result()
    {
        using var c=CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);var completion=new TaskCompletionSource<CurrentSessionRow?>();
        var task=Reader(new Executor((_,_,_)=>completion.Task)).ReadAsync(Binding,Now+Duration.FromSeconds(1),c.Token);
        c.Cancel();await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>task);
        var row=Row();completion.SetResult(row);Assert.All(row.Key,b=>Assert.Equal(0,b));
    }
    [Theory][InlineData(-1)][InlineData(1)] public async Task Clock_jump_or_deadline_passage_discards_completed_row(int direction)
    {
        var clock=new Clock();var row=Row();var e=new Executor((_,_,_)=>{clock.Now=Now+Duration.FromSeconds(direction);return Task.FromResult<CurrentSessionRow?>(row);});
        using var r=await Reader(e,clock).ReadAsync(Binding,Now+Duration.FromSeconds(1),TestContext.Current.CancellationToken);Assert.Equal(AuthorityReadStatus.Unavailable,r.Status);Assert.All(row.Key,b=>Assert.Equal(0,b));
    }
    [Fact] public async Task Deadline_limits_driver_budget()
    { var e=Returns(null);using var r=await Reader(e).ReadAsync(Binding,Now+Duration.FromMilliseconds(50),TestContext.Current.CancellationToken);Assert.Equal(TimeSpan.FromMilliseconds(50),e.Budget); }
    [Theory][InlineData(0)][InlineData(31000)] public void Invalid_budget_is_rejected(int ms) => Assert.Throws<ArgumentOutOfRangeException>(()=>Reader(Returns(null),budget:TimeSpan.FromMilliseconds(ms)));

    [Theory][InlineData("valid",SessionDecision.Active)][InlineData("wrong-key",SessionDecision.Unauthenticated)]
    [InlineData("preauth",SessionDecision.Unauthenticated)][InlineData("forbidden",SessionDecision.Forbidden)]
    [InlineData("wrong-binding",SessionDecision.Unauthenticated)]
    public async Task Real_signature_binding_and_capability_are_required(string kind,SessionDecision expected)
    {
        string token=TestSessions.Mint(kind=="forbidden"?"valid":kind=="wrong-binding"?"wrong-issuer":kind);
        string hash=kind=="wrong-binding"?Binding:Hash(token);
        var row=Row() with { Binding=hash };
        if(kind=="forbidden") { var j=JsonNode.Parse(Json())!;j["capabilities"]=new JsonArray();row=row with { EntitlementJson=j.ToJsonString() }; }
        using var r=await Reader(Returns(row)).ReadAsync(hash,Now+Duration.FromSeconds(1),TestContext.Current.CancellationToken);
        Assert.Equal(AuthorityReadStatus.Found,r.Status);
        Assert.Equal(expected,await r.Projection!.EvaluateAccessAsync(new TreehammockSessionPolicyEvaluator(),token,TestSessions.Issuer,"account.read",Now+Duration.FromSeconds(1),new Clock(),TestContext.Current.CancellationToken));
        Assert.DoesNotContain(hash,r.Projection.ToString());
    }
    [Fact] public async Task Disposed_evidence_cannot_authorize()
    { using var r=await Reader(Returns(Row())).ReadAsync(Binding,Now+Duration.FromSeconds(1),TestContext.Current.CancellationToken);r.Dispose();Assert.Equal(SessionDecision.Unavailable,await r.Projection!.EvaluateAccessAsync(new TreehammockSessionPolicyEvaluator(),TestSessions.Mint(),TestSessions.Issuer,"account.read",Now+Duration.FromSeconds(1),new Clock(),TestContext.Current.CancellationToken)); }
    [Fact] public async Task Boundary_crossed_during_signature_work_is_rechecked()
    {
        var clock=new Clock();using var r=await Reader(Returns(Row())).ReadAsync(Binding,Now+Duration.FromSeconds(1),TestContext.Current.CancellationToken);
        var verifier=new AdvancingVerifier(clock);
        Assert.Equal(SessionDecision.Unavailable,await r.Projection!.EvaluateAccessAsync(new TreehammockSessionPolicyEvaluator(verifier),TestSessions.Mint(),TestSessions.Issuer,"account.read",Now+Duration.FromSeconds(1),clock,TestContext.Current.CancellationToken));
    }
    private sealed class AdvancingVerifier(Clock clock) : ITreehammockTokenVerifier
    {
        public async Task<TokenVerificationResult> ValidateAsync(string token,byte[] key,string issuer,Instant now,Instant expires,string purpose = TreehammockTokenPurpose.Active,Duration? skew = null)
        { var result=await new TreehammockTokenVerifier().ValidateAsync(token,key,issuer,now,expires,purpose,skew);clock.Now=Now+Duration.FromSeconds(1);return result; }
    }
    [Theory][InlineData("Maximum Pool Size=100")][InlineData("Enlist=true")][InlineData("No Reset On Close=true")]
    [InlineData("Include Error Detail=true")][InlineData("Persist Security Info=true")][InlineData("Multiplexing=true")]
    [InlineData("Command Timeout=0")][InlineData("Cancellation Timeout=0")]
    public void Unsafe_pool_context_settings_are_rejected(string setting)
    { Assert.Throws<ArgumentException>(()=>YsqlAuthorityDataSource.Create("Host=localhost;Username=svs;Enlist=false;Maximum Pool Size=8;Timeout=2;Command Timeout=2;Cancellation Timeout=1000;"+setting)); }
    [Fact] public void Bounded_dedicated_pool_can_be_built_without_contacting_server()
    { using var source=YsqlAuthorityDataSource.Create("Host=localhost;Username=svs;Enlist=false;Maximum Pool Size=8;Timeout=2;Command Timeout=2;Cancellation Timeout=1000");Assert.NotNull(source); }
}
