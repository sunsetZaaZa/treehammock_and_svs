using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
namespace treehammock.Rigging.Fleet;
public enum FleetMode { Unadmitted, Quarantined, DBOnlyIsolated, CoherentAdmitted }
internal sealed record FleetSqlIdentities(string App,string Coordinator,string Validator,string Refiller,string Maintenance)
{
 [JsonIgnore] internal string[] Names=>[App,Coordinator,Validator,Refiller,Maintenance];
 internal void Validate(){if(Names.Any(x=>!FleetProtocol.Role(x))||Names.Distinct(StringComparer.Ordinal).Count()!=5)throw new InvalidOperationException("Five named distinct SQL identities required.");}
}
internal sealed record FleetIdentity(string Purpose,string Kind,string Name);
internal sealed record FleetParticipant(string Id,string Kind,string IdentityHash);
internal sealed record FleetBinding(Guid Realm,long Generation,Guid Barrier,string InventoryHash,FleetMode Mode,string Environment,Guid Epoch,string Policy,string PrimaryRunId,FleetSqlIdentities SqlIdentities,FleetParticipant[] Participants,string DatabasePolicyHash,string CachePolicyHash)
{
 [JsonIgnore] internal string[] SqlRoles=>SqlIdentities.Names;
 internal void Validate()
 {
  if(Realm==Guid.Empty||Generation<1||Barrier==Guid.Empty||!FleetProtocol.Hash(InventoryHash)||Mode is not (FleetMode.DBOnlyIsolated or FleetMode.CoherentAdmitted)||DatabasePolicyHash!=FleetPolicyHashes.Database||CachePolicyHash!=FleetPolicyHashes.Cache||SqlIdentities is null||Participants is null||Participants.Length is <2 or >64||Participants.Select(x=>x.Id).Distinct().Count()!=Participants.Length||Participants.Any(x=>!FleetProtocol.Name(x.Id)||x.Kind is not ("TreeHammock" or "SVS")||!FleetProtocol.Hash(x.IdentityHash)))throw new InvalidOperationException("Invalid v2 fleet binding.");
  SqlIdentities.Validate();if(!Participants.Any(x=>x.Kind=="SVS")||!Participants.Any(x=>x.Kind=="TreeHammock"))throw new InvalidOperationException("Both fleets required.");
  if(Mode==FleetMode.CoherentAdmitted&&(!FleetProtocol.Label(Environment,32)||Epoch==Guid.Empty||!FleetProtocol.Label(Policy,64)||!System.Text.RegularExpressions.Regex.IsMatch(PrimaryRunId,"^[a-f0-9]{40}$")))throw new InvalidOperationException("Invalid coherent binding.");
 }
 public override string ToString()=>nameof(FleetBinding);
}
internal sealed record FleetRequest(string Action,string Nonce,Guid BootId,long Generation,Guid Barrier,string InventoryHash,FleetBinding? Binding=null,string? Prepared=null,string Protocol=FleetProtocol.Version);
internal sealed record FleetReply(string Protocol,string Instance,string Kind,Guid BootId,string Nonce,long Generation,Guid Barrier,string InventoryHash,FleetMode Mode,int Active,string? Prepared,string PolicyHash,FleetIsolationProof? Isolation=null,string IdentityHash="",string CachePolicyHash="");
internal sealed record FleetIsolationProof(FleetIdentity[] Rejected);
internal static class FleetProtocol
{
 internal const string Version="authority-fleet.v2";
 internal const string Path="/internal/v2/authority-fleet";
 internal const int MaximumBodyBytes=32768;
 internal static readonly JsonSerializerOptions Json=new(){PropertyNamingPolicy=JsonNamingPolicy.CamelCase,UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow,Converters={new JsonStringEnumConverter(allowIntegerValues:false)}};
 internal static T Read<T>(ReadOnlySpan<byte> bytes)
 {
  if(bytes.Length>MaximumBodyBytes)throw new JsonException("Unbounded fleet message.");using var document=JsonDocument.Parse(bytes.ToArray(),new JsonDocumentOptions{MaxDepth=16});
  void Check(JsonElement e){if(e.ValueKind==JsonValueKind.Object){var names=new HashSet<string>(StringComparer.Ordinal);foreach(var p in e.EnumerateObject()){if(!names.Add(p.Name))throw new JsonException("Duplicate fleet field.");Check(p.Value);}}else if(e.ValueKind==JsonValueKind.Array)foreach(var item in e.EnumerateArray())Check(item);}
  Check(document.RootElement);if(typeof(T)==typeof(FleetRequest)||typeof(T)==typeof(FleetReply))if(!document.RootElement.TryGetProperty("protocol",out var v)||v.GetString()!=Version)throw new JsonException("Explicit v2 protocol required.");
  return JsonSerializer.Deserialize<T>(document.RootElement,Json)??throw new JsonException("Missing fleet message.");
 }
 internal static string Digest<T>(T value)=>Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(value,Json)));
 internal static FleetIdentity[] Identities(string kind,FleetIdentity[]? identities)
 {
  var purposes=kind switch{"TreeHammock"=>new[]{"app","coordinator","cache-reader","cache-writer"},"SVS"=>new[]{"validator","refiller","cache-reader","cache-refiller"},_=>throw new InvalidOperationException("Unknown fleet kind.")};
  if(identities is null||identities.Length!=purposes.Length||!identities.Select(x=>x.Purpose).ToHashSet(StringComparer.Ordinal).SetEquals(purposes)||identities.Any(x=>x.Kind!=(x.Purpose.StartsWith("cache-",StringComparison.Ordinal)?"Cache":"SQL")||!(x.Kind=="SQL"?Role(x.Name):Name(x.Name)))||identities.Select(x=>(x.Kind,x.Name)).Distinct().Count()!=identities.Length)throw new InvalidOperationException("Complete named runtime credential inventory required.");
  return identities.OrderBy(x=>x.Purpose,StringComparer.Ordinal).ToArray();
 }
 internal static string IdentityHash(string kind,FleetIdentity[]? identities)=>Digest(Identities(kind,identities));
 internal static string Nonce()=>Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
 internal static bool Hash(string? value)=>value is {Length:64}&&value.All(c=>c is >= '0' and <= '9' or >= 'A' and <= 'F');
 internal static bool Name(string? value)=>value is not null&&System.Text.RegularExpressions.Regex.IsMatch(value,"^[a-z][a-z0-9-]{0,47}$");
 internal static bool Role(string? value)=>value is not null&&System.Text.RegularExpressions.Regex.IsMatch(value,"^[a-z][a-z0-9_]{0,62}$")&&!value.StartsWith("pg_")&&!value.StartsWith("yb_");
 internal static bool Label(string? value,int max)=>value is {Length:>0}&&value.Length<=max&&value.All(c=>c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '.');
}
