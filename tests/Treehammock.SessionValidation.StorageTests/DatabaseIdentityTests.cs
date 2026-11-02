using System.Text.Json.Nodes;
using NodaTime;
using Treehammock.SessionValidation.Storage;
using Treehammock.SessionValidation.UnitTests;
using Xunit;
namespace Treehammock.SessionValidation.StorageTests;

public sealed class DatabaseIdentityTests
{
    private sealed class Clock : IClock { internal Instant Now=TestSessions.Now; public Instant GetCurrentInstant()=>Now; }
    private static Npgsql.NpgsqlDataSource Source()=>YsqlAuthorityDataSource.Create("Host=localhost;Username=treehammock_svs;Enlist=false;Maximum Pool Size=8;Timeout=2;Command Timeout=3;Cancellation Timeout=1000");
    private static JsonObject Valid() => JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory,"Fixtures/valid-validator-identity.json")))!.AsObject();
    [Fact] public void Exact_minimum_identity_is_accepted() => Assert.True(DatabaseIdentityPolicy.Accept(Valid().ToJsonString()));
    [Theory]
    [InlineData("session-user")][InlineData("current-user")][InlineData("missing-role")][InlineData("extra-role")]
    [InlineData("superuser")][InlineData("createDb")][InlineData("createRole")][InlineData("replication")][InlineData("bypassRls")]
    [InlineData("group-login")][InlineData("group-inherit")][InlineData("login-no-inherit")][InlineData("unbounded-connections")]
    [InlineData("membership-admin")][InlineData("membership-missing")][InlineData("membership-writer")]
    [InlineData("secret-column")][InlineData("missing-column")][InlineData("duplicate-column")]
    [InlineData("extra-function")][InlineData("missing-function")][InlineData("duplicate-function")]
    [InlineData("definer")][InlineData("volatile")][InlineData("language")][InlineData("procedure")]
    [InlineData("unsafe-path")][InlineData("missing-path")][InlineData("extra-config")][InlineData("body-changed")]
    [InlineData("no-connect")][InlineData("no-usage")][InlineData("missing-field")]
    public void Privilege_or_dependency_drift_is_rejected(string kind)
    {
        var j=Valid();var role=j["roles"]![0]!.AsObject();var f=j["functions"]![0]!.AsObject();
        switch(kind)
        {
            case "session-user":j["sessionUser"]="writer";break;case "current-user":j["currentUser"]="writer";break;
            case "missing-role":j["roles"]!.AsArray().RemoveAt(1);break;
            case "extra-role":j["roles"]!.AsArray().Add(role.DeepClone());break;
            case "superuser":case "createDb":case "createRole":case "replication":case "bypassRls":role[kind]=true;break;
            case "group-login":j["roles"]![1]!["login"]=true;break;case "group-inherit":j["roles"]![1]!["inherit"]=true;break;
            case "login-no-inherit":role["inherit"]=false;break;case "unbounded-connections":role["connectionLimit"]=-1;break;
            case "membership-admin":j["memberships"]![0]!["admin"]=true;break;
            case "membership-missing":j["memberships"]=new JsonArray();break;
            case "membership-writer":j["memberships"]!.AsArray().Add(new JsonObject{{"member","treehammock_svs"},{"role","app_writer"},{"admin",false}});break;
            case "secret-column":j["columns"]!.AsArray().Add("public.accounts.password");break;
            case "missing-column":j["columns"]!.AsArray().RemoveAt(0);break;
            case "duplicate-column":j["columns"]!.AsArray().Add(j["columns"]![0]!.DeepClone());break;
            case "extra-function":j["functions"]!.AsArray().Add(new JsonObject{{"signature","public.cor20_resolve_account(uuid)"}});break;
            case "missing-function":j["functions"]!.AsArray().RemoveAt(0);break;
            case "duplicate-function":j["functions"]![1]=f.DeepClone();break;
            case "definer":f["definer"]=true;break;case "volatile":f["volatility"]="v";break;
            case "language":f["language"]="plpythonu";break;case "procedure":f["kind"]="p";break;
            case "unsafe-path":f["config"]=new JsonArray("search_path=pg_temp, public");break;
            case "missing-path":f["config"]=new JsonArray();break;
            case "extra-config":f["config"]!.AsArray().Add("role=writer");break;
            case "body-changed":f["source"]=f["source"]!.GetValue<string>()+" -- drift";break;
            case "no-connect":j["requiredConnect"]=false;break;case "no-usage":j["requiredUsage"]=false;break;
            case "missing-field":j.Remove("unsafe");break;
        }
        Assert.False(DatabaseIdentityPolicy.Accept(j.ToJsonString()));
    }
    [Theory]
    [InlineData("Ownership")][InlineData("TableDefinition")][InlineData("SystemWrite")][InlineData("DatabasePrivilege")][InlineData("SchemaPrivilege")][InlineData("TableWrite")]
    [InlineData("ColumnWriteOrDelegation")][InlineData("SequencePrivilege")][InlineData("AuthCatalogPrivilege")]
    [InlineData("RiskyBuiltin")][InlineData("FunctionDelegation")][InlineData("FuturePrivilege")][InlineData("FuturePublicFunction")]
    public void Positive_unsafe_catalog_fact_rejects_admission(string fact)
    { var j=Valid();j["unsafe"]!.AsArray().Add(fact);Assert.False(DatabaseIdentityPolicy.Accept(j.ToJsonString())); }
    [Theory][InlineData("not-json")][InlineData("null")][InlineData("[]")][InlineData("{}")]
    public void Missing_or_malformed_inspection_fails_closed(string json) => Assert.False(DatabaseIdentityPolicy.Accept(json));
    [Fact] public void Audit_lease_expires_and_clock_rollback_disables_only_database_admission()
    {
        var admission=new DatabaseIdentityAdmission();var now=TestSessions.Now;
        Assert.Null(admission.Capture(now));admission.Verify(now);var token=admission.Capture(now)!;Assert.NotNull(token);
        Assert.True(admission.IsCurrent(token,now+Duration.FromSeconds(29)));
        Assert.Null(admission.Capture(now+Duration.FromSeconds(30)));Assert.Null(admission.Capture(now-Duration.FromSeconds(1)));
    }
    [Fact] public void Audit_unavailable_invalidates_inflight_proof_but_can_recover()
    {
        var a=new DatabaseIdentityAdmission();a.Verify(TestSessions.Now);var token=a.Capture(TestSessions.Now)!;
        a.Unavailable();Assert.False(a.IsCurrent(token,TestSessions.Now));Assert.False(a.Quarantined);
        a.Verify(TestSessions.Now);Assert.NotNull(a.Capture(TestSessions.Now));Assert.False(a.IsCurrent(token,TestSessions.Now));
    }
    [Fact] public void Positive_privilege_violation_requires_new_identity_owner()
    { var a=new DatabaseIdentityAdmission();a.Verify(TestSessions.Now);a.Reject();a.Verify(TestSessions.Now);Assert.True(a.Quarantined);Assert.Null(a.Capture(TestSessions.Now)); }
    [Theory][InlineData("Username=writer;SSL Mode=VerifyFull")][InlineData("Username=treehammock_svs;SSL Mode=Disable")]
    [InlineData("Username=treehammock_svs;SSL Mode=Require")]
    public void Writer_or_unverified_transport_cannot_construct_validator_identity(string settings)
    { Assert.Throws<ArgumentException>(()=>YsqlAuthorityDataSource.CreateValidator("Host=localhost;Database=owned;Enlist=false;Maximum Pool Size=8;Timeout=2;Command Timeout=3;Cancellation Timeout=1000;"+settings)); }
    [Fact] public async Task Correct_username_and_tls_do_not_invent_runtime_privilege_proof()
    {
        await using var identity=YsqlAuthorityDataSource.CreateValidator("Host=localhost;Database=owned;Username=treehammock_svs;SSL Mode=VerifyFull;Enlist=false;Maximum Pool Size=8;Timeout=2;Command Timeout=3;Cancellation Timeout=1000");
        Assert.False(identity.DatabaseFallbackReady);
        using var result=await new YsqlSessionAuthority(identity,TimeSpan.FromSeconds(1)).ReadAsync(new string('A',64),NodaTime.SystemClock.Instance.GetCurrentInstant()+Duration.FromSeconds(1),TestContext.Current.CancellationToken);
        Assert.Equal(AuthorityReadStatus.Unavailable,result.Status);
        Assert.DoesNotContain("localhost",identity.ToString());
    }
    [Fact] public async Task Actual_refresh_workflow_distinguishes_network_failure_from_privilege_violation()
    {
        int mode=0,calls=0;var clock=new Clock();
        await using var identity=new ValidatorDatabaseIdentity(Source(),clock,_=>{
            calls++;if(mode==1)throw new InvalidOperationException("private-connection-canary");
            return Task.FromResult(mode==2?"{}":Valid().ToJsonString());});
        Assert.Equal(DatabaseIdentityAuditStatus.Verified,(await identity.RefreshIdentityAsync(TestContext.Current.CancellationToken)).Status);Assert.True(identity.DatabaseFallbackReady);
        mode=1;Assert.Equal(DatabaseIdentityAuditStatus.Unavailable,(await identity.RefreshIdentityAsync(TestContext.Current.CancellationToken)).Status);Assert.False(identity.DatabaseFallbackReady);
        mode=0;Assert.Equal(DatabaseIdentityAuditStatus.Verified,(await identity.RefreshIdentityAsync(TestContext.Current.CancellationToken)).Status);
        mode=2;Assert.Equal(DatabaseIdentityAuditStatus.Rejected,(await identity.RefreshIdentityAsync(TestContext.Current.CancellationToken)).Status);
        mode=0;Assert.Equal(DatabaseIdentityAuditStatus.Quarantined,(await identity.RefreshIdentityAsync(TestContext.Current.CancellationToken)).Status);Assert.Equal(4,calls);
    }
    [Theory][InlineData(-1)][InlineData(4)] public async Task Clock_jump_during_audit_cannot_admit_identity(int seconds)
    {
        var clock=new Clock();await using var identity=new ValidatorDatabaseIdentity(Source(),clock,_=>{clock.Now+=Duration.FromSeconds(seconds);return Task.FromResult(Valid().ToJsonString());});
        Assert.Equal(DatabaseIdentityAuditStatus.Unavailable,(await identity.RefreshIdentityAsync(TestContext.Current.CancellationToken)).Status);Assert.False(identity.DatabaseFallbackReady);
    }
    [Fact] public async Task Cancelled_audit_cannot_enable_database_admission()
    {
        var completion=new TaskCompletionSource<string>();using var cancellation=CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        await using var identity=new ValidatorDatabaseIdentity(Source(),new Clock(),_=>completion.Task);
        var task=identity.RefreshIdentityAsync(cancellation.Token);cancellation.Cancel();await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>task);
        completion.SetResult(Valid().ToJsonString());Assert.False(identity.DatabaseFallbackReady);
    }
}
