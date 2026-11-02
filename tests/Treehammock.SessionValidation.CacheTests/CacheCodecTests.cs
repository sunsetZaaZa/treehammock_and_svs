using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Treehammock.SessionValidation.Storage;
using Xunit;
namespace Treehammock.SessionValidation.CacheTests;

public sealed class CacheCodecTests
{
    [Theory][InlineData("ready-v1.json",CachedAuthorityState.Ready)][InlineData("blocked-v1.json",CachedAuthorityState.Blocked)]
    public void Independent_golden_vectors_round_trip_on_both_targets(string name,CachedAuthorityState state)
    {
        byte[] input=File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory,"Fixtures",name));Assert.True(CoherentCacheCodec.TryDecode(input,out var decoded));using var r=decoded!;
        Assert.Equal(state,r.Header.State);byte[] encoded=CoherentCacheCodec.Encode(r);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(input),JsonNode.Parse(encoded)));CryptographicOperations.ZeroMemory(input);CryptographicOperations.ZeroMemory(encoded);
    }
    private static JsonObject Payload(){using var h=new CacheHarness();return JsonNode.Parse(h.Cache.Payload!)!.AsObject();}
    public static IEnumerable<object[]> Fields()
    {
        var j=Payload();foreach(var p in j)yield return new object[]{p.Key};
        foreach(string parent in new[]{"identity","lifetime","account","entitlements"})foreach(var p in j[parent]!.AsObject())yield return new object[]{parent+"."+p.Key};
    }
    [Theory][MemberData(nameof(Fields))] public void Every_required_field_must_be_present(string path)
    {
        var j=Payload();var p=path.Split('.');if(p.Length==1)j.Remove(p[0]);else j[p[0]]!.AsObject().Remove(p[1]);
        Assert.False(CoherentCacheCodec.TryDecode(Encoding.UTF8.GetBytes(j.ToJsonString()),out var result));Assert.Null(result);
    }
    [Theory][InlineData(1L)][InlineData(9007199254740993L)][InlineData(long.MaxValue)]
    public void Shared_writer_codec_preserves_exact_revision_and_disposable_key(long revision)
    {
        using var h=new CacheHarness();using var record=h.Record(revision);byte[] bytes=CoherentCacheCodec.Encode(record);
        try
        {
            Assert.True(CoherentCacheCodec.TryDecode(bytes,out var decoded));using var r=decoded!;
            Assert.Equal(revision,r.Header.Revision);Assert.Equal(record.Identity,r.Identity);Assert.Equal(record.Key,r.Key);
            Assert.DoesNotContain(h.Hash,r.ToString());Assert.DoesNotContain(Convert.ToBase64String(record.Key!),r.ToString());
            var key=r.Key!;r.Dispose();Assert.All(key,b=>Assert.Equal(0,b));
        }
        finally{CryptographicOperations.ZeroMemory(bytes);}
    }
    [Theory][InlineData("")][InlineData("identity")][InlineData("lifetime")][InlineData("account")][InlineData("entitlements")]
    public void Unknown_fields_cannot_silently_change_the_schema(string parent)
    {var j=Payload();(parent==""?j:j[parent]!.AsObject())["futureAuthority"]=true;Assert.False(CoherentCacheCodec.TryDecode(Encoding.UTF8.GetBytes(j.ToJsonString()),out _));}
    [Theory][InlineData("schema")][InlineData("verificationStatus")][InlineData("generation")][InlineData("featureTier")]
    public void Duplicate_fields_are_rejected(string name)
    {
        var j=Payload();string text=j.ToJsonString();var value=name switch{"schema"=>"1","verificationStatus"=>"1","generation"=>"\"5\"",_=>"1"};
        text=text.Replace($"\"{name}\":{value}",$"\"{name}\":{value},\"{name}\":{value}",StringComparison.Ordinal);
        Assert.False(CoherentCacheCodec.TryDecode(Encoding.UTF8.GetBytes(text),out _));
    }
    [Theory][InlineData("numeric-revision")][InlineData("leading-zero")][InlineData("overflow")][InlineData("negative")]
    [InlineData("schema")][InlineData("state")][InlineData("nonce")][InlineData("empty-epoch")][InlineData("noncanonical-uuid")]
    [InlineData("hash")][InlineData("key")][InlineData("short-key")][InlineData("long-key")][InlineData("duplicate-capabilities")]
    public void Ambiguous_or_invalid_control_fields_fail_decoding(string kind)
    {
        var j=Payload();switch(kind)
        {
            case "numeric-revision":j["revision"]=9007199254740993L;break;case "leading-zero":j["revision"]="01";break;
            case "overflow":j["revision"]="9223372036854775808";break;case "negative":j["revision"]="-1";break;
            case "schema":j["schema"]=2;break;case "state":j["state"]="Unknown";break;case "nonce":j["nonce"]=new string('a',64);break;
            case "empty-epoch":j["epoch"]=new string('0',32);break;case "noncanonical-uuid":j["accountId"]=Guid.NewGuid().ToString();break;
            case "hash":j["credentialHash"]=new string('a',64);break;case "key":j["signingKey"]="not base64";break;
            case "short-key":j["signingKey"]=Convert.ToBase64String(new byte[16]);break;case "long-key":j["signingKey"]=Convert.ToBase64String(new byte[513]);break;
            case "duplicate-capabilities":j["entitlements"]!["capabilities"]=new JsonArray("account.read","account.read");break;
        }
        Assert.False(CoherentCacheCodec.TryDecode(Encoding.UTF8.GetBytes(j.ToJsonString()),out _));
    }
    [Theory][InlineData("")][InlineData("null")][InlineData("[]")][InlineData("{}")][InlineData("{\"accountId\":\"legacy-json\"}")]
    public void Legacy_or_non_object_payload_is_ineligible(string value)=>Assert.False(CoherentCacheCodec.TryDecode(Encoding.UTF8.GetBytes(value),out _));
    [Fact] public void Oversized_payload_and_deep_objects_are_rejected()
    {Assert.False(CoherentCacheCodec.TryDecode(new byte[65537],out _));Assert.False(CoherentCacheCodec.TryDecode(Encoding.UTF8.GetBytes(new string('[',20)+"0"+new string(']',20)),out _));}
    [Fact] public void Blocked_format_has_no_session_or_key_and_cannot_be_decoded_as_ready()
    {
        using var h=new CacheHarness();using var ready=h.Record();using var r=new CachedAccountAuthority(ready.Header with{State=CachedAuthorityState.Blocked,Revision=0});
        byte[] bytes=CoherentCacheCodec.Encode(r);Assert.True(CoherentCacheCodec.TryDecode(bytes,out var decoded));using var d=decoded!;
        Assert.Equal(CachedAuthorityState.Blocked,d.Header.State);Assert.Null(d.Key);Assert.Null(d.Identity);Assert.False(Encoding.UTF8.GetString(bytes).Contains("signingKey",StringComparison.Ordinal));
    }
}
