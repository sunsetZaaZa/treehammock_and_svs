using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
namespace Treehammock.SessionValidation.Api;

internal sealed class ServiceCertificates : IDisposable
{
    private readonly X509Certificate2 _clientRoot, _serverRoot;
    private readonly Dictionary<string, string> _pins;
    internal X509Certificate2 Server { get; }
    internal ServiceCertificates(HostSettings settings)
    {
        _clientRoot = X509CertificateLoader.LoadCertificateFromFile(settings.ClientRootCertificatePath);
        _serverRoot = null!; Server = null!;
        try
        {
            _serverRoot = X509CertificateLoader.LoadCertificateFromFile(settings.ServerRootCertificatePath);
            RequireRoot(_clientRoot); RequireRoot(_serverRoot);
            Server = X509CertificateLoader.LoadPkcs12FromFile(settings.ServerCertificatePath, settings.ServerCertificatePassword, X509KeyStorageFlags.EphemeralKeySet);
            if (!Server.HasPrivateKey || !ValidLeaf(Server, _serverRoot, "1.3.6.1.5.5.7.3.1")) throw new ArgumentException("Server certificate rejected.");
            _pins = settings.Callers.SelectMany(c => c.LeafSha256.Select(pin => (pin, c.Identity))).ToDictionary(x => x.pin, x => x.Identity, StringComparer.Ordinal);
            if(settings.Monitoring is {} m)foreach(var pin in m.LeafSha256)_pins.Add(pin,m.Identity);
        }
        catch { Server?.Dispose(); _clientRoot.Dispose(); _serverRoot?.Dispose(); throw; }
    }
    internal string? Authenticate(X509Certificate2? certificate)
    {
        try
        {
            if (certificate is null || !_pins.TryGetValue(Convert.ToHexString(SHA256.HashData(certificate.RawData)), out var identity) || !ValidLeaf(certificate, _clientRoot, "1.3.6.1.5.5.7.3.2")) return null;
            var san = certificate.Extensions["2.5.29.17"];
            if (san is null) return null;
            var reader = new AsnReader(san.RawData, AsnEncodingRules.DER).ReadSequence(); var uris = new List<string>();
            while (reader.HasData)
            {
                var tag = reader.PeekTag();
                if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 6))) uris.Add(reader.ReadCharacterString(UniversalTagNumber.IA5String, tag));
                else reader.ReadEncodedValue();
            }
            return uris.Count == 1 && uris[0] == identity ? identity : null;
        }
        catch (Exception) { return null; }
    }
    internal static void RequireRoot(X509Certificate2 root)
    {
        if (!Current(root) || !root.Extensions.OfType<X509BasicConstraintsExtension>().Any(x => x.CertificateAuthority)) throw new ArgumentException("Current private CA required.");
    }
    internal static bool ValidLeaf(X509Certificate2 cert, X509Certificate2 root, string eku)
    {
        if (!Current(cert) || !Current(root) || cert.Extensions.OfType<X509BasicConstraintsExtension>().Any(x => x.CertificateAuthority) ||
            !cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().Any(x => x.EnhancedKeyUsages.Cast<Oid>().Any(o => o.Value == eku))) return false;
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust; chain.ChainPolicy.CustomTrustStore.Add(root);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid(eku));
        return chain.Build(cert);
    }
    private static bool Current(X509Certificate2 cert) => DateTime.UtcNow >= cert.NotBefore.ToUniversalTime() && DateTime.UtcNow < cert.NotAfter.ToUniversalTime();
    public void Dispose() { Server.Dispose(); _clientRoot.Dispose(); _serverRoot.Dispose(); }
}
