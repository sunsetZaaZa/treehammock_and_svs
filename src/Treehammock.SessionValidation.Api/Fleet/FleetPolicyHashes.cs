using System.Security.Cryptography;
using System.Text;
namespace treehammock.Rigging.Fleet;
internal static class FleetPolicyHashes
{
 internal static string Database=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(treehammock.Services.DatabaseRoleBoundary.Policy)));
 internal static string Cache {get{using var stream=typeof(FleetPolicyHashes).Assembly.GetManifestResourceStream("treehammock.SvsRefillCachePolicy.json")??throw new InvalidOperationException("Missing cache policy.");using var reader=new StreamReader(stream);return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(reader.ReadToEnd())));}}
}
