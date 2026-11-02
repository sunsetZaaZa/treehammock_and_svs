using System.Text.Json;
using System.Text.Json.Nodes;
using NodaTime;
using Treehammock.SessionValidation.Core;
using Treehammock.SessionValidation.Storage;
using Treehammock.SessionValidation.UnitTests;
using Xunit;
namespace Treehammock.SessionValidation.StorageTests;

public sealed class TreehammockIdentityTests
{
    private static readonly TreehammockRoleMap Roles = new("app", "coordinator", "validator", "maintenance", "owner", "treehammock_svs_read");
    private static JsonObject Role(bool login) => new() { ["login"] = login, ["inherit"] = false, ["connectionLimit"] = -1, ["superuser"] = false, ["createDb"] = false, ["createRole"] = false, ["replication"] = false, ["bypassRls"] = false };
    private static JsonObject Valid() => new()
    {
        ["sessionUser"] = Roles.Validator, ["currentUser"] = Roles.Validator, ["rolesMatch"] = true, ["policyMatch"] = true, ["groupOwnsObjects"] = false,
        ["login"] = Role(true), ["readGroup"] = Role(false),
        ["membership"] = new JsonObject { ["count"] = 1, ["member"] = Roles.Validator, ["role"] = Roles.ValidatorRead, ["admin"] = false },
        ["helper"] = new JsonObject { ["source"] = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures/validator-helper-source.txt")), ["owner"] = Roles.Owner, ["definer"] = false, ["kind"] = "f", ["language"] = "plpgsql", ["volatility"] = "s", ["config"] = new JsonArray("search_path=public, pg_catalog, pg_temp") },
        ["helperSafe"] = true
    };
    [Fact] public void Fresh_THS_profile_and_adopted_SVS05_profile_accept_only_audited_effective_rights()
    {
        var j = Valid(); Assert.True(TreehammockIdentityPolicy.Accept(j.ToJsonString(), Roles));
        j["login"]!["inherit"] = true; j["login"]!["connectionLimit"] = 16; Assert.True(TreehammockIdentityPolicy.Accept(j.ToJsonString(), Roles));
        j["helperSafe"] = false; Assert.False(TreehammockIdentityPolicy.Accept(j.ToJsonString(), Roles));
    }
    [Theory]
    [InlineData("sessionUser")][InlineData("currentUser")][InlineData("rolesMatch")][InlineData("policyMatch")][InlineData("groupOwnsObjects")]
    [InlineData("superuser")][InlineData("createDb")][InlineData("createRole")][InlineData("replication")][InlineData("bypassRls")]
    [InlineData("group-login")][InlineData("group-inherit")][InlineData("membership-admin")][InlineData("membership-extra")][InlineData("membership-writer")]
    [InlineData("helper-body")][InlineData("helper-owner")][InlineData("helper-definer")][InlineData("helper-language")][InlineData("helper-kind")]
    [InlineData("helper-volatile")][InlineData("helper-path")][InlineData("helper-safe")][InlineData("missing")][InlineData("unbounded-inherit")][InlineData("unexpected-server-limit")]
    public void Rejects_role_policy_or_audit_helper_drift(string fault)
    {
        var j = Valid(); var helper = j["helper"]!;
        switch (fault)
        {
            case "sessionUser": case "currentUser": j[fault] = "writer"; break;
            case "rolesMatch": case "policyMatch": j[fault] = false; break;
            case "groupOwnsObjects": j[fault] = true; break;
            case "superuser": case "createDb": case "createRole": case "replication": case "bypassRls": j["login"]![fault] = true; break;
            case "group-login": j["readGroup"]!["login"] = true; break;
            case "group-inherit": j["readGroup"]!["inherit"] = true; break;
            case "membership-admin": j["membership"]!["admin"] = true; break;
            case "membership-extra": j["membership"]!["count"] = 2; break;
            case "membership-writer": j["membership"]!["role"] = "coordinator"; break;
            case "helper-body": helper["source"] = "begin return true; end;"; break;
            case "helper-owner": helper["owner"] = Roles.Validator; break;
            case "helper-definer": helper["definer"] = true; break;
            case "helper-language": helper["language"] = "plpythonu"; break;
            case "helper-kind": helper["kind"] = "p"; break;
            case "helper-volatile": helper["volatility"] = "v"; break;
            case "helper-path": helper["config"] = new JsonArray("search_path=pg_temp, public"); break;
            case "helper-safe": j["helperSafe"] = false; break;
            case "missing": j.Remove("login"); break;
            case "unbounded-inherit": j["login"]!["inherit"] = true; break;
            case "unexpected-server-limit": j["login"]!["connectionLimit"] = 1000; break;
        }
        Assert.False(TreehammockIdentityPolicy.Accept(j.ToJsonString(), Roles));
    }
    [Theory][InlineData("null")][InlineData("{}")][InlineData("[]")][InlineData("not-json")]
    public void Unknown_inspection_cannot_authorize(string json) => Assert.False(TreehammockIdentityPolicy.Accept(json, Roles));
    [Theory][InlineData("pg_admin")][InlineData("yb_admin")][InlineData("bad;role")][InlineData("app")]
    public void Untrusted_or_duplicate_role_map_rejects(string validator) => Assert.Throws<ArgumentException>(() => (Roles with { Validator = validator }).Validate());
    [Fact] public async Task Rotated_validator_login_is_still_typed_and_initially_unadmitted()
    {
        await using var identity = YsqlAuthorityDataSource.CreateTreehammockValidator("Host=localhost;Database=owned;Username=validator;SSL Mode=VerifyFull;Enlist=false;Maximum Pool Size=8;Timeout=2;Command Timeout=3;Cancellation Timeout=1000", Roles);
        Assert.False(identity.DatabaseFallbackReady);
        Assert.Throws<ArgumentException>(() => YsqlAuthorityDataSource.CreateTreehammockValidator("Host=localhost;Database=owned;Username=coordinator;SSL Mode=VerifyFull;Enlist=false;Maximum Pool Size=8;Timeout=2;Command Timeout=3;Cancellation Timeout=1000", Roles));
    }
    [Fact] public async Task Cancelled_provider_retains_single_audit_slot_until_actual_completion()
    {
        int calls = 0; var pending = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var identity = new ValidatorDatabaseIdentity(YsqlAuthorityDataSource.Create("Host=localhost;Enlist=false;Maximum Pool Size=8;Timeout=2;Command Timeout=3;Cancellation Timeout=1000"), SystemClock.Instance,
            _ => { Interlocked.Increment(ref calls); return pending.Task; }, s => TreehammockIdentityPolicy.Accept(s, Roles));
        using var first = new CancellationTokenSource(); var audit = identity.RefreshIdentityAsync(first.Token); first.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => audit);
        using var second = new CancellationTokenSource(); var another = identity.RefreshIdentityAsync(second.Token); second.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => another); Assert.Equal(1, calls);
        pending.SetResult(Valid().ToJsonString()); Assert.False(identity.DatabaseFallbackReady);
    }
    [Theory][InlineData("2025-01-01T00:00:00Z")][InlineData("2025-01-01T03:00:00+03:00")][InlineData("2024-12-31T18:00:00-06:00")]
    public void SQL_offset_timestamp_maps_to_the_same_instant(string timestamp)
    {
        string json = $$"""{"accountId":"{{TestSessions.Identity.AccountId}}","version":1,"features":1,"capabilities":[],"grants":[],"rightsEnabled":false,"evaluatedAt":"{{timestamp}}","nextBoundary":null,"eligibilityUntil":null}""";
        var readAt = Instant.FromUtc(2025, 1, 1, 0, 0);
        using var row = new CurrentSessionRow(new string('A', 64), TestSessions.Identity, TestSessions.Identity.AccountStamp, TestSessions.Key(), new(readAt + Duration.FromMinutes(1), readAt + Duration.FromHours(1), null), 1, null, readAt, json);
        using var result = AuthorityProjectionMapper.Map(row, row.Binding, readAt);
        Assert.Equal(AuthorityReadStatus.Found, result.Status);
        using var expired = AuthorityProjectionMapper.Map(row with { Lifetime = row.Lifetime with { AccessExpiration = readAt } }, row.Binding, readAt);
        Assert.Equal(AuthorityReadStatus.Unauthenticated, expired.Status);
    }
}
