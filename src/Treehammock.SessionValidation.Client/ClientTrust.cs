using System.Formats.Asn1;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
namespace Treehammock.SessionValidation.Client;
internal sealed class ClientTrust : IDisposable
{
    private readonly X509Certificate2 _serverRoot,_clientRoot;
    private readonly string[] _pins;
    internal X509Certificate2 Client {get;}
    private long _peerExpires=DateTime.MaxValue.Ticks;
    internal ClientTrust(ClientOptions options)
    {
        X509Certificate2? server=null,root=null,client=null;
        try
        {
            server=Load(options.ServerRootCertificatePath);root=Load(options.ClientRootCertificatePath);
            if(!IsRoot(server)||!IsRoot(root))throw new ArgumentException("Current private roots required.");
#if NET8_0
            client=new X509Certificate2(options.ClientCertificatePath,options.ClientCertificatePassword,X509KeyStorageFlags.EphemeralKeySet);
#else
            client=X509CertificateLoader.LoadPkcs12FromFile(options.ClientCertificatePath,options.ClientCertificatePassword,X509KeyStorageFlags.EphemeralKeySet);
#endif
            if(!client.HasPrivateKey||!Valid(client,root,"1.3.6.1.5.5.7.3.2")||!Identity(client,options.ServiceIdentity))throw new ArgumentException("Dedicated service client identity required.");
            _serverRoot=server;_clientRoot=root;Client=client;_pins=options.Pins.ToArray();
        }
        catch{server?.Dispose();root?.Dispose();client?.Dispose();throw;}
    }
    private static X509Certificate2 Load(string path)
    {
#if NET8_0
        return new X509Certificate2(File.ReadAllBytes(path));
#else
        return X509CertificateLoader.LoadCertificateFromFile(path);
#endif
    }
    internal bool Current=>DateTime.UtcNow.Ticks<Interlocked.Read(ref _peerExpires)&&Valid(Client,_clientRoot,"1.3.6.1.5.5.7.3.2")&&IsRoot(_serverRoot);
    internal bool Authenticate(object sender,X509Certificate? certificate,X509Chain? chain,SslPolicyErrors errors)
    {
        try
        {
            if(certificate is null||(errors&SslPolicyErrors.RemoteCertificateNameMismatch)!=0)return false;
#if NET8_0
            using var leaf=new X509Certificate2(certificate.GetRawCertData());
#else
            using var leaf=X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
#endif
            if(!_pins.Contains(Convert.ToHexString(SHA256.HashData(leaf.RawData)),StringComparer.Ordinal)||!Valid(leaf,_serverRoot,"1.3.6.1.5.5.7.3.1"))return false;
            long end=Math.Min(leaf.NotAfter.ToUniversalTime().Ticks,_serverRoot.NotAfter.ToUniversalTime().Ticks),old;
            do{old=Interlocked.Read(ref _peerExpires);if(end>=old)break;}while(Interlocked.CompareExchange(ref _peerExpires,end,old)!=old);
            return true;
        }
        catch{return false;}
    }
    private static bool CurrentCert(X509Certificate2 cert)=>DateTime.UtcNow>=cert.NotBefore.ToUniversalTime()&&DateTime.UtcNow<cert.NotAfter.ToUniversalTime();
    private static bool IsRoot(X509Certificate2 cert)=>CurrentCert(cert)&&cert.Extensions.OfType<X509BasicConstraintsExtension>().Any(e=>e.CertificateAuthority);
    private static bool Valid(X509Certificate2 leaf,X509Certificate2 root,string eku)
    {
        if(!CurrentCert(leaf)||!IsRoot(root)||leaf.Extensions.OfType<X509BasicConstraintsExtension>().Any(e=>e.CertificateAuthority)||!leaf.Extensions.OfType<X509EnhancedKeyUsageExtension>().Any(e=>e.EnhancedKeyUsages.Cast<Oid>().Any(o=>o.Value==eku)))return false;
        using var chain=new X509Chain();chain.ChainPolicy.TrustMode=X509ChainTrustMode.CustomRootTrust;chain.ChainPolicy.CustomTrustStore.Add(root);chain.ChainPolicy.RevocationMode=X509RevocationMode.NoCheck;chain.ChainPolicy.DisableCertificateDownloads=true;chain.ChainPolicy.ApplicationPolicy.Add(new Oid(eku));return chain.Build(leaf);
    }
    private static bool Identity(X509Certificate2 cert,string identity)
    {
        try
        {
            var san=cert.Extensions["2.5.29.17"];if(san is null)return false;var reader=new AsnReader(san.RawData,AsnEncodingRules.DER).ReadSequence();var uris=new List<string>();
            while(reader.HasData){var tag=reader.PeekTag();if(tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific,6)))uris.Add(reader.ReadCharacterString(UniversalTagNumber.IA5String,tag));else reader.ReadEncodedValue();}
            return uris.Count==1&&uris[0]==identity;
        }catch{return false;}
    }
    public void Dispose(){Client.Dispose();_clientRoot.Dispose();_serverRoot.Dispose();}
}
