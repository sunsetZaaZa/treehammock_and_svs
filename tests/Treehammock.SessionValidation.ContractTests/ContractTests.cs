using System.Diagnostics;
using System.Text.Json;
using Google.Protobuf;
using Treehammock.SessionValidation.Contracts;
using Treehammock.SessionValidation.Contracts.V1;
using Xunit;

namespace Treehammock.SessionValidation.ContractTests;

public class ContractTests(ITestOutputHelper output)
{
    private const long Moment = 1900000000000;
    private const string RequestId = "11111111111141118111111111111111";
    private const string DecisionId = "22222222222242228222222222222222";
    private const string Peer = "spiffe://treehammock.test/service/contact-backup-api";
    private const string PolicyVersion = "svs.policy.v1.fixture";
    private static DateTimeOffset Start => DateTimeOffset.FromUnixTimeMilliseconds(Moment);
    private static AdmissionContext Admission => new(Peer, Start, Start.AddSeconds(5), Start.AddMilliseconds(100));
    private static ReplyContext ReplyContext => new(RequestId, PolicyVersion, Start, Start.AddSeconds(5), Start.AddMilliseconds(100));
    private static CallerPolicy Policy() => new([new(Peer, ["backup.read", "backup.write"])]);
    private static ValidateRequest Request() => new()
    {
        ContractVersion = 1, AccessCredential = ByteString.CopyFromUtf8("fixture-access"),
        RequestedAction = "backup.read", RequestId = RequestId
    };
    private static ValidateReply Reply(Decision decision = Decision.Active) => new()
    {
        Decision = decision, ContractVersion = 1, RequestId = RequestId, PolicyVersion = PolicyVersion,
        DecisionId = DecisionId, CheckedAtUnixMs = Moment + 100,
        AccountIdUuid = decision == Decision.Active ? UuidCodec.Encode(Guid.Parse("11223344-5566-7788-99aa-bbccddeeff00")) : ByteString.Empty,
        SessionFamilyUuid = decision == Decision.Active ? UuidCodec.Encode(Guid.Parse("ffeeddcc-bbaa-9988-7766-554433221100")) : ByteString.Empty,
        Generation = decision == Decision.Active ? 7 : 0, SessionProtocolVersion = decision == Decision.Active ? 2u : 0u,
        ValidUntilUnixMs = decision == Decision.Active ? Moment + 1000 : 0
    };

    [Fact]
    public void Golden_binary_and_json_cover_every_field_and_decision()
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures/contract-golden.json")));
        foreach (var fixture in doc.RootElement.GetProperty("fixtures").EnumerateArray())
        {
            var bytes = Convert.FromHexString(fixture.GetProperty("binary_hex").GetString()!);
            string json = fixture.GetProperty("json").GetRawText();
            if (fixture.GetProperty("kind").GetString() == "request")
            {
                Assert.Equal(ContractError.None, ContractCodec.DecodeRequestBinary(bytes, Admission, Policy(), out var binary));
                Assert.Equal(ContractError.None, ContractCodec.DecodeRequestJson(json, Admission, Policy(), out var fromJson));
                Assert.Equal(Request(), binary);
                Assert.Equal(binary, fromJson);
                Assert.Equal(bytes, binary!.ToByteArray());
                AssertJsonEqual(json, JsonFormatter.Default.Format(binary));
            }
            else
            {
                Assert.Equal(ContractError.None, ContractCodec.DecodeReplyBinary(bytes, ReplyContext, out var binary));
                Assert.Equal(ContractError.None, ContractCodec.DecodeReplyJson(json, ReplyContext, out var fromJson));
                Assert.Equal(binary, fromJson);
                Assert.Equal(Reply(binary!.Decision), binary);
                Assert.Equal(bytes, binary.ToByteArray());
                AssertJsonEqual(json, JsonFormatter.Default.Format(binary));
            }
        }
    }

    private static void AssertJsonEqual(string expected, string actual)
    {
        static string Canonical(string json)
        {
            using var doc = JsonDocument.Parse(json);
            return JsonSerializer.Serialize(doc.RootElement.EnumerateObject().OrderBy(p => p.Name)
                .ToDictionary(p => p.Name, p => p.Value.Clone()));
        }
        Assert.Equal(Canonical(expected), Canonical(actual));
    }

    [Theory]
    [InlineData(0u)] [InlineData(2u)] [InlineData(uint.MaxValue)]
    public void Unknown_major_versions_reject(uint version)
    {
        var request = Request(); request.ContractVersion = version;
        Assert.Equal(ContractError.UnsupportedVersion, ContractRules.CheckRequest(request, Admission, Policy()));
        var reply = Reply(); reply.ContractVersion = version;
        Assert.Equal(ContractError.UnsupportedVersion, ContractRules.CheckReply(reply, ReplyContext));
    }

    [Theory]
    [InlineData(0)] [InlineData(5)] [InlineData(-1)] [InlineData(999)]
    public void Unknown_decisions_never_become_active(int value)
    {
        var reply = Reply(); reply.Decision = (Decision)value;
        Assert.Equal(ContractError.UnknownDecision, ContractRules.CheckReply(reply, ReplyContext));
        Assert.Equal(ContractError.UnknownDecision, ContractCodec.DecodeReplyJson(JsonFormatter.Default.Format(reply), ReplyContext, out _));
    }

    [Theory]
    [InlineData(null)] [InlineData("")] [InlineData("contact-backup-api")]
    [InlineData("spiffe://treehammock.test/service/other-api")]
    [InlineData("SPIFFE://treehammock.test/service/contact-backup-api")]
    public void Missing_or_unmatched_transport_identity_rejects(string? identity)
    {
        Assert.NotEqual(ContractError.None, ContractRules.CheckRequest(Request(), Admission with { AuthenticatedPeerIdentity = identity }, Policy()));
    }

    [Theory]
    [InlineData("")] [InlineData("auth.session.rotate")] [InlineData("auth.session.revoke")]
    [InlineData("password.reset")] [InlineData("BACKUP.READ")] [InlineData("*")]
    [InlineData("backup.read ")] [InlineData("recovery_package.read")]
    public void Action_must_be_supported_and_explicitly_allowed(string action)
    {
        var request = Request(); request.RequestedAction = action;
        Assert.NotEqual(ContractError.None, ContractRules.CheckRequest(request, Admission, Policy()));
    }

    [Fact]
    public void Deny_all_is_default_and_policy_copies_mutable_inputs()
    {
        Assert.False(CallerPolicy.DenyAll.Allows(Peer, "backup.read"));
        string[] actions = ["backup.read"];
        var policy = new CallerPolicy([new(Peer, actions)]);
        actions[0] = "backup.write";
        Assert.True(policy.Allows(Peer, "backup.read"));
        Assert.False(policy.Allows(Peer, "backup.write"));
        Assert.Throws<ArgumentException>(() => new CallerPolicy([new(Peer, ["*"])]));
        Assert.Throws<ArgumentException>(() => new CallerPolicy([new(Peer, ["backup.read"]), new(Peer, ["backup.write"])]));
    }

    [Theory]
    [InlineData("http://treehammock.test/service/api")]
    [InlineData("spiffe://treehammock.test/service/")]
    [InlineData("spiffe://treehammock.test/service/api?caller=other")]
    [InlineData("spiffe://treehammock.test/service/../api")]
    [InlineData("spiffe://treehammock.test/service/%61pi")]
    [InlineData("spiffe://treehammock.test:80/service/api")]
    public void Ambiguous_identity_configuration_rejects(string identity) =>
        Assert.Throws<ArgumentException>(() => new CallerPolicy([new(identity, ["backup.read"])]));

    [Fact]
    public void Deadline_is_required_future_and_bounded()
    {
        Assert.Equal(ContractError.MissingDeadline, ContractRules.CheckRequest(Request(), Admission with { Deadline = null }, Policy()));
        Assert.Equal(ContractError.DeadlineExceeded, ContractRules.CheckRequest(Request(), Admission with { Deadline = Admission.Now }, Policy()));
        Assert.Equal(ContractError.DeadlineTooLong, ContractRules.CheckRequest(Request(), Admission with { Deadline = Start.AddSeconds(6) }, Policy()));
        Assert.Equal(ContractError.DeadlineExceeded, ContractRules.CheckRequest(Request(), Admission with { Now = Start.AddMilliseconds(-1) }, Policy()));
    }

    [Theory]
    [InlineData("")] [InlineData("not-an-id")] [InlineData("00000000000000000000000000000000")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public void Correlation_id_has_no_free_text(string id)
    {
        var request = Request(); request.RequestId = id;
        Assert.Equal(ContractError.InvalidRequestId, ContractRules.CheckRequest(request, Admission, Policy()));
    }

    [Fact]
    public void Credential_limits_and_strict_utf8_are_enforced()
    {
        var request = Request(); request.AccessCredential = ByteString.Empty;
        Assert.Equal(ContractError.MissingCredential, ContractRules.CheckRequest(request, Admission, Policy()));
        request.AccessCredential = ByteString.CopyFromUtf8(new string('x', 8192));
        Assert.Equal(ContractError.None, ContractRules.CheckRequest(request, Admission, Policy()));
        request.AccessCredential = ByteString.CopyFromUtf8(new string('x', 8193));
        Assert.Equal(ContractError.TooLarge, ContractRules.CheckRequest(request, Admission, Policy()));
        request.AccessCredential = ByteString.CopyFrom([0xc0, 0x80]);
        Assert.Equal(ContractError.InvalidCredential, ContractRules.CheckRequest(request, Admission, Policy()));
        request.AccessCredential = ByteString.CopyFromUtf8("fixture-鍵");
        Assert.Equal(ContractError.None, ContractRules.CheckRequest(request, Admission, Policy()));
        request.AccessCredential = ByteString.CopyFromUtf8(" \t");
        Assert.Equal(ContractError.InvalidCredential, ContractRules.CheckRequest(request, Admission, Policy()));
    }

    [Fact]
    public void Unknown_duplicate_wrong_type_and_truncated_wire_reject()
    {
        var wire = Request().ToByteArray();
        Assert.Equal(ContractError.UnknownField, ContractCodec.DecodeRequestBinary([..wire, 0x28, 0x01], Admission, Policy(), out _));
        Assert.Equal(ContractError.DuplicateField, ContractCodec.DecodeRequestBinary([..wire, 0x08, 0x01], Admission, Policy(), out _));
        Assert.Equal(ContractError.WrongWireType, ContractCodec.DecodeRequestBinary([0x0a, 0x01, 0x01], Admission, Policy(), out _));
        Assert.Equal(ContractError.Malformed, ContractCodec.DecodeRequestBinary([0x12, 0x05, 0x01], Admission, Policy(), out _));
        Assert.Equal(ContractError.Malformed, ContractCodec.DecodeRequestBinary([], Admission, Policy(), out _));
        Assert.Equal(ContractError.TooLarge, ContractCodec.DecodeRequestBinary(new byte[9217], Admission, Policy(), out _));
        var reply = Reply().ToByteArray();
        Assert.Equal(ContractError.UnknownField, ContractCodec.DecodeReplyBinary([..reply, 0x60, 0x01], ReplyContext, out _));
        Assert.Equal(ContractError.DuplicateField, ContractCodec.DecodeReplyBinary([..reply, 0x50, 0x01], ReplyContext, out _));
    }

    [Fact]
    public void Json_rejects_unknown_alias_duplicate_and_malformed_fields()
    {
        string json = JsonFormatter.Default.Format(Request());
        Assert.Equal(ContractError.UnknownField, ContractCodec.DecodeRequestJson(json[..^1]+",\"callerId\":\"forged\"}", Admission, Policy(), out _));
        Assert.Equal(ContractError.UnknownField, ContractCodec.DecodeRequestJson(json.Replace("requestId", "request_id"), Admission, Policy(), out _));
        Assert.Equal(ContractError.DuplicateField, ContractCodec.DecodeRequestJson(json[..^1]+",\"contractVersion\":1}", Admission, Policy(), out _));
        Assert.Equal(ContractError.Malformed, ContractCodec.DecodeRequestJson("{", Admission, Policy(), out _));
        Assert.Equal(ContractError.Malformed, ContractCodec.DecodeRequestJson("[]", Admission, Policy(), out _));
        Assert.Equal(ContractError.TooLarge, ContractCodec.DecodeRequestJson(new string(' ', 16385), Admission, Policy(), out _));
        string reply = JsonFormatter.Default.Format(Reply());
        Assert.Equal(ContractError.UnknownField, ContractCodec.DecodeReplyJson(reply[..^1]+",\"refreshToken\":\"secret\"}", ReplyContext, out _));
    }

    [Theory]
    [InlineData(Decision.Unauthenticated)] [InlineData(Decision.Forbidden)] [InlineData(Decision.Unavailable)]
    public void Every_refusal_omits_all_subject_fields(Decision decision)
    {
        var reply = Reply(decision);
        Assert.Equal(ContractError.None, ContractRules.CheckReply(reply, ReplyContext));
        foreach (var change in SubjectMutations())
        {
            var changed = reply.Clone(); change(changed);
            Assert.Equal(ContractError.SubjectOnRefusal, ContractRules.CheckReply(changed, ReplyContext));
        }
    }

    private static IEnumerable<Action<ValidateReply>> SubjectMutations()
    {
        yield return r => r.AccountIdUuid = UuidCodec.Encode(Guid.NewGuid());
        yield return r => r.SessionFamilyUuid = UuidCodec.Encode(Guid.NewGuid());
        yield return r => r.Generation = 1;
        yield return r => r.SessionProtocolVersion = 2;
        yield return r => r.ValidUntilUnixMs = Moment + 1000;
    }

    [Fact]
    public void Active_requires_complete_current_subject()
    {
        Action<ValidateReply>[] changes = [r => r.AccountIdUuid = ByteString.Empty, r => r.SessionFamilyUuid = ByteString.Empty,
            r => r.AccountIdUuid = ByteString.CopyFrom(new byte[16]), r => r.SessionFamilyUuid = ByteString.CopyFrom(new byte[15]),
            r => r.Generation = 0, r => r.Generation = ContractLimits.MaximumGeneration + 1, r => r.SessionProtocolVersion = 1];
        foreach (var change in changes)
        {
            var reply = Reply(); change(reply);
            Assert.Equal(ContractError.InvalidSubject, ContractRules.CheckReply(reply, ReplyContext));
        }
        var maximum = Reply(); maximum.Generation = ContractLimits.MaximumGeneration;
        Assert.Equal(ContractError.None, ContractRules.CheckReply(maximum, ReplyContext));
    }

    [Fact]
    public void Reply_is_bound_to_request_policy_time_and_deadline()
    {
        var reply = Reply(); reply.RequestId = DecisionId;
        Assert.Equal(ContractError.WrongRequest, ContractRules.CheckReply(reply, ReplyContext));
        reply = Reply(); reply.PolicyVersion = "other.policy";
        Assert.Equal(ContractError.WrongPolicy, ContractRules.CheckReply(reply, ReplyContext));
        reply = Reply(); reply.DecisionId = "PII text";
        Assert.Equal(ContractError.InvalidMetadata, ContractRules.CheckReply(reply, ReplyContext));
        foreach (long value in new[] { Moment, Moment + 100, Moment + 5001 })
        {
            reply = Reply(); reply.ValidUntilUnixMs = value;
            Assert.Equal(ContractError.InvalidValidity, ContractRules.CheckReply(reply, ReplyContext));
        }
        reply = Reply(); reply.CheckedAtUnixMs = Moment - 1;
        Assert.Equal(ContractError.InvalidValidity, ContractRules.CheckReply(reply, ReplyContext));
        reply = Reply(); reply.CheckedAtUnixMs = Moment + 101;
        Assert.Equal(ContractError.InvalidValidity, ContractRules.CheckReply(reply, ReplyContext));
        Assert.Equal(ContractError.InvalidValidity, ContractRules.CheckReply(Reply(), ReplyContext with { Now = Start.AddSeconds(5) }));
    }

    [Fact]
    public void Uuid_byte_order_is_rfc4122_not_Guid_default_layout()
    {
        var guid = Guid.Parse("11223344-5566-7788-99aa-bbccddeeff00");
        Assert.Equal("112233445566778899AABBCCDDEEFF00", Convert.ToHexString(UuidCodec.Encode(guid).ToByteArray()));
        Assert.Equal(guid, UuidCodec.Decode(UuidCodec.Encode(guid)));
        Assert.Throws<ArgumentException>(() => UuidCodec.Encode(Guid.Empty));
    }

    [Fact]
    public void Schema_contains_no_key_refresh_or_caller_claim_field()
    {
        var requestNames = ValidateRequest.Descriptor.Fields.InFieldNumberOrder().Select(f => f.Name).ToArray();
        Assert.Equal(["contract_version", "access_credential", "requested_action", "request_id"], requestNames);
        Assert.DoesNotContain(ValidateReply.Descriptor.Fields.InFieldNumberOrder(), f =>
            f.Name.Contains("token") || f.Name.Contains("key") || f.Name.Contains("credential") || f.Name.Contains("stamp"));
    }

    [Fact]
    public void Errors_and_configuration_exceptions_do_not_echo_credentials()
    {
        const string canary = "CREDENTIAL_CANARY_DO_NOT_LOG";
        var request = Request(); request.RequestId = canary; request.AccessCredential = ByteString.CopyFromUtf8(canary);
        string diagnostic = ContractRules.CheckRequest(request, Admission, Policy()).ToString();
        Assert.DoesNotContain(canary, diagnostic);
        var exception = Assert.Throws<ArgumentException>(() => new CallerPolicy([new(canary, [canary])]));
        Assert.DoesNotContain(canary, exception.Message);
    }

    [Fact]
    public void Max_size_binary_admission_has_bounded_local_allocations()
    {
        var request = Request(); request.AccessCredential = ByteString.CopyFromUtf8(new string('x', 8192));
        var wire = request.ToByteArray(); var policy = Policy();
        for (int i = 0; i < 100; i++) ContractCodec.DecodeRequestBinary(wire, Admission, policy, out _);
        long start = GC.GetAllocatedBytesForCurrentThread(); var stopwatch = Stopwatch.StartNew();
        for (int i = 0; i < 1000; i++) Assert.Equal(ContractError.None, ContractCodec.DecodeRequestBinary(wire, Admission, policy, out _));
        stopwatch.Stop(); long perRequest = (GC.GetAllocatedBytesForCurrentThread() - start) / 1000;
        output.WriteLine($"SVS01_CONTRACT_ALLOCATION bytes_per_request={perRequest}; iterations=1000; payload_bytes={wire.Length}; elapsed_ms={stopwatch.Elapsed.TotalMilliseconds:F3}");
        Assert.InRange(perRequest, 1, 131072); // Local regression ceiling, not a production SLO.
    }
}
