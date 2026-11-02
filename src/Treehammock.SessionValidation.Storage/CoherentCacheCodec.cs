using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using NodaTime;
using NodaTime.Text;
using Treehammock.SessionValidation.Core;
namespace Treehammock.SessionValidation.Storage;

// Exact v1 shape: no polymorphic CLR serializer, comments, duplicate properties or legacy JSON.
public static class CoherentCacheCodec
{
    public const int SchemaVersion=1;
    public const int MaximumPayloadBytes=65536;
    private static readonly string[] Common=["schema","environment","epoch","policy","nonce","revision","state","accountId"];
    private static readonly string[] Ready=[..Common,"credentialHash","producedAt","notAfter","identity","lifetime","account","entitlements","signingKey"];
    private static void Shape(JsonElement e,params string[] names)
    {
        if(e.ValueKind!=JsonValueKind.Object)throw new FormatException();
        var actual=e.EnumerateObject().Select(p=>p.Name).ToArray();
        if(actual.Length!=names.Length || actual.Distinct(StringComparer.Ordinal).Count()!=actual.Length || !actual.ToHashSet(StringComparer.Ordinal).SetEquals(names))throw new FormatException();
    }
    private static string Text(JsonElement e,string n)=>e.GetProperty(n).GetString()??throw new FormatException();
    private static Guid Id(JsonElement e,string n)
    { var s=Text(e,n);if(!Guid.TryParseExact(s,"N",out var id)||id==Guid.Empty||s!=id.ToString("N"))throw new FormatException();return id; }
    private static Instant Time(JsonElement e)
    { var s=e.GetString()??throw new FormatException();var value=InstantPattern.ExtendedIso.Parse(s).GetValueOrThrow();if(value<Instant.FromUtc(1,1,1,0,0)||InstantPattern.ExtendedIso.Format(value)!=s)throw new FormatException();return value; }
    private static Instant? OptionalTime(JsonElement e)=>e.ValueKind==JsonValueKind.Null?null:Time(e);
    private static bool Hex(string s,int length)=>s.Length==length && s.All(c=>c is >= '0' and <= '9' or >= 'A' and <= 'F');
    public static bool TryDecode(ReadOnlyMemory<byte> bytes,out CachedAccountAuthority? record)
    {
        record=null;byte[]? key=null;
        if(bytes.Length is 0 or >MaximumPayloadBytes)return false;
        try
        {
            using var doc=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=16});var e=doc.RootElement;
            bool ready=Text(e,"state")=="Ready";Shape(e,ready?Ready:Common);
            if(e.GetProperty("schema").GetInt32()!=SchemaVersion || (!ready && Text(e,"state")!="Blocked"))return false;
            string revision=Text(e,"revision"),nonce=Text(e,"nonce");
            if(!long.TryParse(revision,NumberStyles.None,CultureInfo.InvariantCulture,out var value)||value<0||revision!=value.ToString(CultureInfo.InvariantCulture)||!Hex(nonce,64))return false;
            string environment=Text(e,"environment"),policy=Text(e,"policy");
            if(!CoherentCacheKeySpace.IsLabel(environment,32)||!CoherentCacheKeySpace.IsLabel(policy,64))return false;
            var header=new CacheAuthorityHeader(environment,Id(e,"epoch"),policy,nonce,value,ready?CachedAuthorityState.Ready:CachedAuthorityState.Blocked,Id(e,"accountId"));
            if(!ready){record=new(header);return true;}
            if(value==0)return false;
            string hash=Text(e,"credentialHash");if(!YsqlSessionAuthority.IsHash(hash))return false;
            var i=e.GetProperty("identity");Shape(i,"accountId","familyId","generation","protocol","sessionStamp","accountStamp");
            string generation=Text(i,"generation");if(!long.TryParse(generation,NumberStyles.None,CultureInfo.InvariantCulture,out var gen)||generation!=gen.ToString(CultureInfo.InvariantCulture))return false;
            var identity=new SessionIdentity(Id(i,"accountId"),Id(i,"familyId"),gen,i.GetProperty("protocol").GetInt32(),Id(i,"sessionStamp"),Id(i,"accountStamp"));
            if(!identity.IsWellFormed)return false;
            var l=e.GetProperty("lifetime");Shape(l,"accessExpiration","hardExpiration","cutoff");
            var lifetime=new SessionLifetime(Time(l.GetProperty("accessExpiration")),Time(l.GetProperty("hardExpiration")),OptionalTime(l.GetProperty("cutoff")));
            var a=e.GetProperty("account");Shape(a,"exists","verificationStatus","unlockWhen","currentStamp","sessionCurrent");
            var account=new CachedAccountState(a.GetProperty("exists").GetBoolean(),a.GetProperty("verificationStatus").GetInt16(),OptionalTime(a.GetProperty("unlockWhen")),Id(a,"currentStamp"),a.GetProperty("sessionCurrent").GetBoolean());
            var t=e.GetProperty("entitlements");Shape(t,"accountId","version","featureTier","capabilities","rightsEnabled","evaluatedAt","nextBoundary","eligibilityUntil","grantsPresent");
            string version=Text(t,"version");if(!long.TryParse(version,NumberStyles.None,CultureInfo.InvariantCulture,out var v)||v is <1 or >SessionIdentity.MaximumGeneration||version!=v.ToString(CultureInfo.InvariantCulture))return false;
            var caps=t.GetProperty("capabilities").EnumerateArray().Select(c=>c.GetString()??throw new FormatException()).ToArray();
            if(caps.Length>16||caps.Distinct(StringComparer.Ordinal).Count()!=caps.Length)return false;
            var entitlements=new EntitlementPolicyInputs(Id(t,"accountId"),v,t.GetProperty("featureTier").GetInt32(),caps,t.GetProperty("rightsEnabled").GetBoolean(),Time(t.GetProperty("evaluatedAt")),OptionalTime(t.GetProperty("nextBoundary")),OptionalTime(t.GetProperty("eligibilityUntil")),t.GetProperty("grantsPresent").GetBoolean());
            key=e.GetProperty("signingKey").GetBytesFromBase64();if(key.Length is <32 or >512||Convert.ToBase64String(key)!=Text(e,"signingKey"))return false;
            record=new(header,hash,Time(e.GetProperty("producedAt")),Time(e.GetProperty("notAfter")),identity,lifetime,account,entitlements,key);return true;
        }
        catch(Exception ex) when(ex is JsonException or FormatException or InvalidOperationException or ArgumentException or KeyNotFoundException or OverflowException){return false;}
        finally { if(key is not null)CryptographicOperations.ZeroMemory(key); }
    }
    public static byte[] Encode(CachedAccountAuthority record)
    {
        // Serialized bytes contain signing material: caller owns and erases them after the storage command.
        using var stream=new MemoryStream();
        try
        {
        using(var w=new Utf8JsonWriter(stream))
        {
            var h=record.Header;w.WriteStartObject();w.WriteNumber("schema",SchemaVersion);w.WriteString("environment",h.Environment);w.WriteString("epoch",h.Epoch.ToString("N"));
            w.WriteString("policy",h.Policy);w.WriteString("nonce",h.Nonce);w.WriteString("revision",h.Revision.ToString(CultureInfo.InvariantCulture));
            w.WriteString("state",h.State==CachedAuthorityState.Ready?"Ready":h.State==CachedAuthorityState.Blocked?"Blocked":throw new ArgumentException("Invalid state."));w.WriteString("accountId",h.AccountId.ToString("N"));
            if(h.State==CachedAuthorityState.Ready)
            {
                var i=record.Identity??throw new ArgumentException("Incomplete Ready.");var l=record.Lifetime??throw new ArgumentException("Incomplete Ready.");
                var a=record.Account??throw new ArgumentException("Incomplete Ready.");var t=record.Entitlements??throw new ArgumentException("Incomplete Ready.");
                w.WriteString("credentialHash",record.CredentialHash);WriteTime(w,"producedAt",record.ProducedAt??throw new ArgumentException("Incomplete Ready."));WriteTime(w,"notAfter",record.NotAfter??throw new ArgumentException("Incomplete Ready."));
                w.WriteStartObject("identity");w.WriteString("accountId",i.AccountId.ToString("N"));w.WriteString("familyId",i.FamilyId.ToString("N"));w.WriteString("generation",i.Generation.ToString(CultureInfo.InvariantCulture));w.WriteNumber("protocol",i.ProtocolVersion);w.WriteString("sessionStamp",i.SessionStamp.ToString("N"));w.WriteString("accountStamp",i.AccountStamp.ToString("N"));w.WriteEndObject();
                w.WriteStartObject("lifetime");WriteTime(w,"accessExpiration",l.AccessExpiration);WriteTime(w,"hardExpiration",l.HardExpiration);WriteTime(w,"cutoff",l.Cutoff);w.WriteEndObject();
                w.WriteStartObject("account");w.WriteBoolean("exists",a.Exists);w.WriteNumber("verificationStatus",a.VerificationStatus);WriteTime(w,"unlockWhen",a.UnlockWhen);w.WriteString("currentStamp",a.CurrentStamp.ToString("N"));w.WriteBoolean("sessionCurrent",a.SessionCurrent);w.WriteEndObject();
                w.WriteStartObject("entitlements");w.WriteString("accountId",t.AccountId.ToString("N"));w.WriteString("version",t.Version.ToString(CultureInfo.InvariantCulture));w.WriteNumber("featureTier",t.FeatureTier);w.WriteStartArray("capabilities");foreach(var c in t.Capabilities)w.WriteStringValue(c);w.WriteEndArray();w.WriteBoolean("rightsEnabled",t.RightsEnabled);WriteTime(w,"evaluatedAt",t.EvaluatedAt);WriteTime(w,"nextBoundary",t.NextBoundary);WriteTime(w,"eligibilityUntil",t.EligibilityUntil);w.WriteBoolean("grantsPresent",t.GrantsPresent);w.WriteEndObject();
                w.WriteBase64String("signingKey",record.Key??throw new ObjectDisposedException(nameof(record)));
            }
            w.WriteEndObject();
        }
        byte[] bytes=stream.ToArray();
        if(bytes.Length>MaximumPayloadBytes){CryptographicOperations.ZeroMemory(bytes);throw new ArgumentException("Projection too large.");}
        if(!TryDecode(bytes,out var check)){CryptographicOperations.ZeroMemory(bytes);throw new ArgumentException("Invalid projection shape.");}
        check!.Dispose();return bytes;
        }
        finally
        {
            // Includes exceptional serialization: MemoryStream.Dispose alone does not clear it.
            if(stream.TryGetBuffer(out var segment))CryptographicOperations.ZeroMemory(segment.AsSpan());
        }
    }
    private static void WriteTime(Utf8JsonWriter w,string name,Instant? value)
    { if(value is null)w.WriteNull(name);else w.WriteString(name,InstantPattern.ExtendedIso.Format(value.Value)); }
}
