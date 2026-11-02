using Google.Protobuf;
using Svs12.Golden;
using Treehammock.SessionValidation.Contracts;
using Treehammock.SessionValidation.Contracts.V1;
using Xunit;
namespace Treehammock.SessionValidation.ContractTests;
public sealed class GoldenWireParityTests
{
    [Fact] public void Shared_corpus_is_explicitly_synthetic_and_has_complete_unique_case_ids()
    {
        var corpus=TreehammockParityFixtures.Corpus;Assert.Equal("SVS12Parity.v1",corpus.Format);Assert.True(corpus.SyntheticOnly);Assert.False(corpus.NativeQualification);
        Assert.Equal(60,corpus.Cases.Length);Assert.Equal(60,corpus.Cases.Select(c=>c.Id).Distinct(StringComparer.Ordinal).Count());Assert.Equal(64,TreehammockParityFixtures.Key().Length);
        Assert.Equal(new[]{"Active","Forbidden","Unauthenticated","Unavailable"},corpus.Cases.Select(c=>c.ExpectedCoordinator).Distinct().Order(StringComparer.Ordinal));
    }
    private static readonly DateTimeOffset Now=DateTimeOffset.Parse("2026-10-20T12:00:00Z",System.Globalization.CultureInfo.InvariantCulture);
    private const string Id="11111111111141118111111111111111",Policy="svs12.v1",Peer="spiffe://svs12.test/service/consumer";
    private static AdmissionContext Admission=>new(Peer,Now,Now.AddSeconds(1),Now);
    private static ReplyContext Window=>new(Id,Policy,Now,Now.AddSeconds(1),Now);
    private static CallerPolicy Callers=>new([new(Peer,["backup.read"]) ]);
    private static ValidateRequest Request()=>new(){ContractVersion=1,RequestId=Id,RequestedAction="backup.read",AccessCredential=ByteString.CopyFromUtf8(TreehammockParityFixtures.Credential(TreehammockParityFixtures.Case("issued-no-exp")))};
    private static ValidateReply Reply()=>new(){ContractVersion=1,RequestId=Id,PolicyVersion=Policy,DecisionId="22222222222242228222222222222222",Decision=Decision.Active,CheckedAtUnixMs=Now.ToUnixTimeMilliseconds(),ValidUntilUnixMs=Now.AddMilliseconds(500).ToUnixTimeMilliseconds(),AccountIdUuid=UuidCodec.Encode(Guid.Parse("11223344-5566-7788-99aa-bbccddeeff00")),SessionFamilyUuid=UuidCodec.Encode(Guid.Parse("ffeeddcc-bbaa-9988-7766-554433221100")),Generation=9007199254740991,SessionProtocolVersion=2};
    public static IEnumerable<object[]> Cases()
    {
        foreach(string kind in new[]{"valid-request","valid-reply","request-unknown","request-duplicate","missing-credential","version","unknown-action","reply-unknown","reply-duplicate","subject-on-refusal","wrong-request","wrong-policy","generation-zero","generation-overflow","protocol","uuid-size","validity-equality","validity-after-deadline","unknown-decision","missing-decision-id"})
        foreach(bool json in new[]{false,true})yield return new object[]{kind,json};
    }
    [Theory][MemberData(nameof(Cases))]
    public void Binary_and_JSON_have_the_same_closed_golden_admission(string kind,bool json)
    {
        var request=Request();var reply=Reply();bool isRequest=kind.StartsWith("request",StringComparison.Ordinal)||kind is "valid-request" or "missing-credential" or "version" or "unknown-action";
        ContractError expected=ContractError.None;
        switch(kind)
        {
            case "request-unknown":case "reply-unknown":expected=ContractError.UnknownField;break;
            case "request-duplicate":case "reply-duplicate":expected=ContractError.DuplicateField;break;
            case "missing-credential":request.AccessCredential=ByteString.Empty;expected=ContractError.MissingCredential;break;
            case "version":request.ContractVersion=2;expected=ContractError.UnsupportedVersion;break;
            case "unknown-action":request.RequestedAction="backup.invalid";expected=ContractError.UnknownAction;break;
            case "subject-on-refusal":reply.Decision=Decision.Forbidden;expected=ContractError.SubjectOnRefusal;break;
            case "wrong-request":reply.RequestId="aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa";expected=ContractError.WrongRequest;break;
            case "wrong-policy":reply.PolicyVersion="foreign.v1";expected=ContractError.WrongPolicy;break;
            case "generation-zero":reply.Generation=0;expected=ContractError.InvalidSubject;break;
            case "generation-overflow":reply.Generation=9007199254740992;expected=ContractError.InvalidSubject;break;
            case "protocol":reply.SessionProtocolVersion=1;expected=ContractError.InvalidSubject;break;
            case "uuid-size":reply.AccountIdUuid=ByteString.CopyFrom(new byte[]{1});expected=ContractError.InvalidSubject;break;
            case "validity-equality":reply.ValidUntilUnixMs=Now.ToUnixTimeMilliseconds();expected=ContractError.InvalidValidity;break;
            case "validity-after-deadline":reply.ValidUntilUnixMs=Now.AddSeconds(2).ToUnixTimeMilliseconds();expected=ContractError.InvalidValidity;break;
            case "unknown-decision":reply.Decision=(Decision)999;expected=ContractError.UnknownDecision;break;
            case "missing-decision-id":reply.DecisionId="";expected=ContractError.InvalidMetadata;break;
        }
        ContractError actual;object? decoded;
        if(json)
        {
            string raw=JsonFormatter.Default.Format(isRequest?request:reply);
            if(kind.EndsWith("unknown",StringComparison.Ordinal))raw=raw[..^1]+",\"refreshCredential\":\"forbidden\"}";
            if(kind.EndsWith("duplicate",StringComparison.Ordinal))raw=raw[..^1]+(isRequest?",\"requestId\":\""+Id+"\"}":",\"decision\":\"ACTIVE\"}");
            if(isRequest){actual=ContractCodec.DecodeRequestJson(raw,Admission,Callers,out var value);decoded=value;}
            else{actual=ContractCodec.DecodeReplyJson(raw,Window,out var value);decoded=value;}
        }
        else
        {
            byte[] raw=isRequest?request.ToByteArray():reply.ToByteArray();
            if(kind.EndsWith("unknown",StringComparison.Ordinal))raw=[..raw,0xA0,0x06,1];
            if(kind.EndsWith("duplicate",StringComparison.Ordinal))raw=[..raw,..(isRequest?new byte[]{0x22,0x01,0x61}:new byte[]{0x08,0x01})];
            if(isRequest){actual=ContractCodec.DecodeRequestBinary(raw,Admission,Callers,out var value);decoded=value;}
            else{actual=ContractCodec.DecodeReplyBinary(raw,Window,out var value);decoded=value;}
        }
        Assert.Equal(expected,actual);Assert.Equal(expected==ContractError.None,decoded is not null);
        TreehammockParityFixtures.Report("wire-"+kind+"-"+json,new{Kind=kind,Json=json,Error=actual.ToString(),Admitted=decoded is not null});
    }
}
