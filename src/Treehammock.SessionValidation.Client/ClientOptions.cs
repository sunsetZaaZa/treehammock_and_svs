using System.Net;
using Treehammock.SessionValidation.Contracts;
namespace Treehammock.SessionValidation.Client;
public sealed class ClientOptions
{
    public string TlsName { get; init; } = "";
    public string PrivateAddress { get; init; } = "";
    public int Port { get; init; }
    public string ServerRootCertificatePath { get; init; } = "";
    public string[] ServerLeafSha256 { get; init; } = [];
    public string ClientCertificatePath { get; init; } = "";
    public string ClientCertificatePassword { get; init; } = "";
    public string ClientRootCertificatePath { get; init; } = "";
    public string ServiceIdentity { get; init; } = "";
    public string PolicyVersion { get; init; } = "";
    public int RequestTimeoutMilliseconds { get; init; } = 1000;
    public int MaximumConcurrentCalls { get; init; } = 32;
    public int MaximumConnections { get; init; } = 2;
    public int ConnectionLifetimeMilliseconds { get; init; } = 60000;
    public int ShutdownTimeoutMilliseconds { get; init; } = 3000;
    private string[]? _pins;
    internal string[] Pins => _pins ?? ServerLeafSha256;
    internal ClientOptions Snapshot() { var copy=(ClientOptions)MemberwiseClone();copy._pins=ServerLeafSha256?.ToArray()??[];copy.Validate();return copy; }
    internal void Validate()
    {
        if(Uri.CheckHostName(TlsName)!=UriHostNameType.Dns || TlsName.Length>253 || PrivateAddress is null || PrivateAddress.Length!=0&&(!IPAddress.TryParse(PrivateAddress,out var ip)||!IsPrivate(ip)) || Port is <1 or >65535 || !ContractRules.IsPolicyVersion(PolicyVersion) || Pins is not {Length:>=1 and <=4} || Pins.Any(p=>p is not {Length:64} || !p.All(c=>c is >= '0' and <= '9' or >= 'A' and <= 'F')) || Pins.Distinct(StringComparer.Ordinal).Count()!=Pins.Length || RequestTimeoutMilliseconds is <1 or >4000 || MaximumConcurrentCalls is <1 or >1024 || MaximumConnections is <1 or >16 || ConnectionLifetimeMilliseconds is <100 or >120000 || ShutdownTimeoutMilliseconds is <100 or >10000) throw new ArgumentException("Bounded private validation client options required.");
        _=new CallerPolicy([new(ServiceIdentity,["backup.read"])]);
        foreach(var path in new[]{ServerRootCertificatePath,ClientCertificatePath,ClientRootCertificatePath}) if(!Path.IsPathFullyQualified(path)||!File.Exists(path))throw new ArgumentException("Explicit client trust files required.");
    }
    internal static bool IsPrivate(IPAddress ip)
    {
        if(ip.IsIPv4MappedToIPv6)ip=ip.MapToIPv4();if(IPAddress.IsLoopback(ip))return true;
        if(ip.AddressFamily==System.Net.Sockets.AddressFamily.InterNetworkV6)return ip.IsIPv6UniqueLocal;
        var b=ip.GetAddressBytes();return b[0]==10||b[0]==172&&b[1] is >=16 and <=31||b[0]==192&&b[1]==168;
    }
    public override string ToString()=>nameof(ClientOptions);
}
