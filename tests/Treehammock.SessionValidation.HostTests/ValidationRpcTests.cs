using Google.Protobuf;
using Microsoft.Extensions.DependencyInjection;
using NodaTime;
using Treehammock.SessionValidation.Api;
using Treehammock.SessionValidation.Contracts;
using Treehammock.SessionValidation.Contracts.V1;
using Treehammock.SessionValidation.Storage;
using Xunit;
namespace Treehammock.SessionValidation.HostTests;

public sealed class ValidationRpcTests(HostFixture fixture) : IClassFixture<HostFixture>
{
    private HostSettings Config(bool mapped = true) => fixture.Settings(j =>
    { if (mapped) j["actionPolicy"] = System.Text.Json.Nodes.JsonNode.Parse("""{"version":"test-actions.v1","requirements":{"backup.read":"account.read","backup.write":"account.manage"}}"""); });

    [Theory][InlineData("active", Decision.Active)][InlineData("signature", Decision.Unauthenticated)]
    [InlineData("refresh", Decision.Unauthenticated)][InlineData("forbidden", Decision.Forbidden)]
    [InlineData("missing", Decision.Unauthenticated)][InlineData("down", Decision.Unavailable)]
    [InlineData("unmapped", Decision.Unavailable)]
    public async Task Real_grpc_and_signature_policy_return_only_current_active_subject(string kind, Decision expected)
    {
        var resources = new RpcResources(); var settings = Config(kind != "unmapped");
        if (kind == "missing") resources.Status = AuthorityReadStatus.NotFound;
        if (kind == "down") resources.Status = AuthorityReadStatus.Unavailable;
        await using var app = SvsHost.Build(settings, _ => resources); await app.StartAsync(TestContext.Current.CancellationToken);
        using var http = fixture.Http(settings, fixture.Client); var request = RpcWire.Request(resources.Credential(kind == "signature", kind == "refresh" ? "refresh" : "active_v2"), kind == "forbidden" ? "backup.write" : "backup.read");
        var started = DateTimeOffset.UtcNow; var result = await RpcWire.Call(http, request.ToByteArray(), token: TestContext.Current.CancellationToken);
        Assert.Equal(0, result.Status); var reply = RpcWire.Reply(result.Body); Assert.Equal(expected, reply.Decision);
        Assert.Equal(ContractError.None, ContractRules.CheckReply(reply, new(request.RequestId, settings.ActionPolicy.Version, started, started.AddSeconds(2), DateTimeOffset.UtcNow)));
        Assert.Equal(kind == "unmapped" ? 0 : 1, resources.Calls);
        if (expected == Decision.Active) { Assert.Equal(resources.Identity.AccountId, UuidCodec.Decode(reply.AccountIdUuid)); Assert.Equal(7, reply.Generation); }
        else { Assert.Empty(reply.AccountIdUuid); Assert.Empty(reply.SessionFamilyUuid); Assert.Equal(0, reply.ValidUntilUnixMs); }
        Assert.DoesNotContain("private-webkey", System.Text.Encoding.UTF8.GetString(result.Body));
    }

    [Theory][InlineData("unknown", 3)][InlineData("duplicate", 3)][InlineData("wrongwire", 3)]
    [InlineData("truncated", 3)][InlineData("version", 3)][InlineData("request-id", 3)]
    [InlineData("unknown-action", 3)][InlineData("caller-action", 7)][InlineData("utf8", 3)]
    [InlineData("blank", 3)][InlineData("controls", 3)][InlineData("missing", 3)]
    [InlineData("credential-size", 8)][InlineData("message-size", 8)][InlineData("no-deadline", 3)]
    [InlineData("long-deadline", 3)]
    public async Task Strict_wire_and_admission_errors_never_read_authority(string kind, int status)
    {
        var resources = new RpcResources(); var settings = Config();
        await using var app = SvsHost.Build(settings, _ => resources); await app.StartAsync(TestContext.Current.CancellationToken);
        using var http = fixture.Http(settings, fixture.Client); var request = RpcWire.Request(resources.Credential());
        switch (kind)
        {
            case "version": request.ContractVersion = 2; break;
            case "request-id": request.RequestId = "claimed-account"; break;
            case "unknown-action": request.RequestedAction = "auth.session.revoke"; break;
            case "caller-action": request.RequestedAction = "recovery_package.read"; break;
            case "utf8": request.AccessCredential = ByteString.CopyFrom([0xff]); break;
            case "blank": request.AccessCredential = ByteString.CopyFromUtf8(" "); break;
            case "controls": request.AccessCredential = ByteString.CopyFromUtf8("private\ncredential"); break;
            case "missing": request.AccessCredential = ByteString.Empty; break;
            case "credential-size": request.AccessCredential = ByteString.CopyFromUtf8(new string('x', 8193)); break;
        }
        var bytes = request.ToByteArray();
        bytes = kind switch { "unknown" => [.. bytes, 0x28, 0x01], "duplicate" => [.. bytes, 0x08, 0x01],
            "wrongwire" => [0x0a, 0x01, 0x01], "truncated" => [0x12, 0xff], "message-size" => new byte[9217], _ => bytes };
        var result = await RpcWire.Call(http, bytes, kind == "no-deadline" ? null : kind == "long-deadline" ? "10000m" : "1500m", token: TestContext.Current.CancellationToken);
        Assert.Equal(status, result.Status); Assert.Empty(result.Body); Assert.Equal(0, resources.Calls);
    }

    [Fact] public async Task Compressed_messages_are_refused_without_decompression_or_authority()
    {
        var resources = new RpcResources(); var settings = Config(); await using var app = SvsHost.Build(settings, _ => resources); await app.StartAsync(TestContext.Current.CancellationToken);
        using var http = fixture.Http(settings, fixture.Client);
        using var output = new MemoryStream();
        using (var gzip = new System.IO.Compression.GZipStream(output, System.IO.Compression.CompressionLevel.Fastest, leaveOpen: true))
            gzip.Write(RpcWire.Request(resources.Credential()).ToByteArray());
        foreach (var encoding in new string?[] { "gzip", "br", "identity", null })
        {
            var result = await RpcWire.Call(http, output.ToArray(), flag: 1, encoding: encoding, token: TestContext.Current.CancellationToken);
            Assert.NotEqual(0, result.Status); Assert.Empty(result.Body); Assert.Equal(0, resources.Calls);
        }
    }

    [Fact] public async Task No_positive_identity_is_shared_between_rpc_calls()
    {
        var resources = new RpcResources(); var settings = Config(); await using var app = SvsHost.Build(settings, _ => resources); await app.StartAsync(TestContext.Current.CancellationToken);
        using var http = fixture.Http(settings, fixture.Client); var request = RpcWire.Request(resources.Credential()).ToByteArray();
        Assert.Equal(Decision.Active, RpcWire.Reply((await RpcWire.Call(http, request, token: TestContext.Current.CancellationToken)).Body).Decision);
        resources.Status = AuthorityReadStatus.NotFound;
        Assert.Equal(Decision.Unauthenticated, RpcWire.Reply((await RpcWire.Call(http, request, token: TestContext.Current.CancellationToken)).Body).Decision); Assert.Equal(2, resources.Calls);
    }

    [Fact] public async Task Client_deadline_cancels_read_and_late_provider_cannot_publish_subject()
    {
        var resources = new RpcResources(); var entered = new TaskCompletionSource<CancellationToken>(TaskCreationOptions.RunContinuationsAsynchronously);
        var late = new TaskCompletionSource<AuthorityReadResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        resources.Read = (_, _, ct) => { entered.TrySetResult(ct); return late.Task; };
        var settings = Config(); await using var app = SvsHost.Build(settings, _ => resources); await app.StartAsync(TestContext.Current.CancellationToken);
        using var http = fixture.Http(settings, fixture.Client);
        using var warm = await http.GetAsync("/health/live", TestContext.Current.CancellationToken); Assert.Equal(System.Net.HttpStatusCode.OK, warm.StatusCode);
        var call = RpcWire.Call(http, RpcWire.Request(resources.Credential()).ToByteArray(), "500m", token: TestContext.Current.CancellationToken);
        var cancelled = await entered.Task.WaitAsync(TimeSpan.FromSeconds(2), TestContext.Current.CancellationToken);
        var result = await call; Assert.Equal(4, result.Status); Assert.Empty(result.Body); Assert.True(cancelled.IsCancellationRequested);
        late.SetResult(new(AuthorityReadStatus.NotFound));
    }

    [Fact] public void Reply_serialization_rechecks_deadline_and_subject_boundaries()
    {
        var now = DateTimeOffset.UtcNow; var id = Guid.NewGuid().ToString("N");
        var reply = new ValidateReply { Decision = Decision.Active, ContractVersion = 1, RequestId = id, DecisionId = Guid.NewGuid().ToString("N"), PolicyVersion = "test.v1",
            CheckedAtUnixMs = now.ToUnixTimeMilliseconds(), ValidUntilUnixMs = now.AddMilliseconds(-1).ToUnixTimeMilliseconds(), AccountIdUuid = UuidCodec.Encode(Guid.NewGuid()),
            SessionFamilyUuid = UuidCodec.Encode(Guid.NewGuid()), Generation = 1, SessionProtocolVersion = 2 };
        Assert.Throws<Grpc.Core.RpcException>(() => new CheckedReply(reply, new(id, "test.v1", now, now.AddSeconds(1), now), CancellationToken.None).Serialize());
        using var stop = new CancellationTokenSource(); stop.Cancel(); Assert.Throws<OperationCanceledException>(() => new CheckedReply(reply, new(id, "test.v1", now, now.AddSeconds(1), now), stop.Token).Serialize());
    }
    [Theory][InlineData("action")][InlineData("capability")][InlineData("version")]
    public void Host_rejects_unreviewed_or_malformed_action_policy(string fault)
    {
        var settings = fixture.Settings(j => j["actionPolicy"] = System.Text.Json.Nodes.JsonNode.Parse(fault switch
        {
            "action" => """{"version":"test.v1","requirements":{"auth.session.revoke":"account.manage"}}""",
            "capability" => """{"version":"test.v1","requirements":{"backup.write":"admin"}}""",
            _ => """{"version":"client supplied policy","requirements":{}}"""
        }));
        Assert.Throws<ArgumentException>(() => SvsHost.Build(settings, _ => new RpcResources()));
    }
}
