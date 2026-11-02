using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using MailKit.Net.Smtp;
using treehammock.Rigging.Delivery;

namespace treehammock.Tests.Infrastructure;

// Owned loopback relay, no external delivery or machine trust-store edits. Transcripts retain verbs, never AUTH bytes.
internal sealed class Cor23HSmtpServer : IAsyncDisposable
{
    internal sealed class Session
    {
        internal readonly List<(string Verb,bool Encrypted)> Commands=new();
        internal bool Accepted;
        internal volatile bool Closed;
        internal string Message="";
    }
    internal readonly ConcurrentQueue<Session> Sessions=new();
    internal readonly X509Certificate2 Root,Certificate;
    private readonly TcpListener _listener=new(IPAddress.Loopback,0);
    private readonly CancellationTokenSource _stop=new(TimeSpan.FromSeconds(45));
    private readonly Task _run;
    private readonly string _mode,_fault;
    private readonly SslProtocols _protocols;
    internal int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;
    internal Cor23HSmtpServer(string mode,string fault="none",SslProtocols protocols=SslProtocols.Tls12|SslProtocols.Tls13)
    {
        _mode=mode;_fault=fault;_protocols=protocols;
        (Root,Certificate)=Certificates(fault);_listener.Start();_run=RunAsync();
    }
    private async Task RunAsync()
    {
        try
        {
            while(!_stop.IsCancellationRequested)
            {
                using var client=await _listener.AcceptTcpClientAsync(_stop.Token);
                var session=new Session();Sessions.Enqueue(session);
                try {await ServeAsync(client,session,_stop.Token);}
                catch(AuthenticationException) { /* Expected handshake abort in invalid-certificate/protocol cases. */ }
                catch(IOException) { /* Rejected clients close their owned socket. */ }
#pragma warning disable SYSLIB0039
                catch(NotSupportedException) when(_protocols == SslProtocols.Tls11) { /* OS refuses obsolete TLS 1.1; no AUTH/DATA. */ }
#pragma warning restore SYSLIB0039
            }
        }
        catch(OperationCanceledException) when(_stop.IsCancellationRequested) { }
        catch(SocketException) when(_stop.IsCancellationRequested) { }
    }
    private async Task ServeAsync(TcpClient client,Session session,CancellationToken token)
    {
        Stream stream=client.GetStream();SslStream? tls=null;bool encrypted=false;
        async Task WaitForClose()
        {
            var bytes=new byte[256];while(await stream.ReadAsync(bytes,token)!=0) { }
        }
        async Task Upgrade()
        {
            if(_fault=="hang-tls"){await WaitForClose();return;}
            tls=new SslStream(stream,leaveInnerStreamOpen:true);
            await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions {ServerCertificate=Certificate,EnabledSslProtocols=_protocols,ClientCertificateRequired=false},token);
            stream=tls;encrypted=true;
        }
        try
        {
            if(_mode=="ImplicitTls")await Upgrade();
            if(_fault=="hang-greeting"){await WaitForClose();return;}
            await WriteAsync(stream,"220 fixture ESMTP ready",token);
            while(true)
            {
                string? line=await ReadLineAsync(stream,token);if(line is null)return;
                string verb=line.Split(' ',2)[0].ToUpperInvariant();session.Commands.Add((verb,encrypted));
                switch(verb)
                {
                    case "EHLO":
                        await WriteAsync(stream,"250-fixture",token);
                        if(!encrypted&&_mode=="RequiredStartTls"&&_fault!="missing-starttls")await WriteAsync(stream,"250-STARTTLS",token);
                        // Advertise AUTH before TLS deliberately: required TLS must still precede credentials.
                        await WriteAsync(stream,"250 AUTH PLAIN",token);break;
                    case "HELO": await WriteAsync(stream,"250 fixture",token);break;
                    case "STARTTLS":
                        if(_fault=="reject-starttls"){await WriteAsync(stream,"454 TLS unavailable secret-provider-detail",token);break;}
                        await WriteAsync(stream,"220 Begin TLS",token);
                        if(_fault=="plaintext-after-upgrade"){await WriteAsync(stream,"530 plaintext downgrade refused",token);return;}
                        await Upgrade();break;
                    case "AUTH":
                        if(_fault=="hang-auth"){await WaitForClose();return;}
                        if(line.Split(' ',StringSplitOptions.RemoveEmptyEntries).Length<3)
                        {await WriteAsync(stream,"334 ",token);await ReadLineAsync(stream,token);}
                        await WriteAsync(stream,_fault=="reject-auth"?"535 secret-provider-detail authentication rejected":"235 authenticated",token);break;
                    case "RCPT":await WriteAsync(stream,_fault=="reject-recipient"&&line.Contains("bad@",StringComparison.OrdinalIgnoreCase)?"550 unknown recipient":"250 OK",token);break;
                    case "MAIL": case "RSET":await WriteAsync(stream,"250 OK",token);break;
                    case "DATA":
                        await WriteAsync(stream,"354 send content",token);var body=new StringBuilder();
                        while(true)
                        {
                            string? data=await ReadLineAsync(stream,token);if(data is null)return;if(data==".")break;
                            if(body.Length+data.Length>131072)throw new InvalidOperationException("Fixture message budget exceeded.");
                            body.AppendLine(data.StartsWith("..",StringComparison.Ordinal)?data[1..]:data);
                        }
                        session.Message=body.ToString();
                        if(_fault is "reject-data" or "temporary-data")
                        {await WriteAsync(stream,_fault=="reject-data"?"550 DATA rejected":"451 DATA temporarily rejected",token);break;}
                        session.Accepted=true;
                        if(_fault=="hang-data-ack"){await WaitForClose();return;}
                        if(_fault=="accept-drop")return;
                        await WriteAsync(stream,"250 accepted",token);
                        if(_fault=="disconnect-after-accept")return;
                        break;
                    case "QUIT":if(_fault=="hang-quit"){await WaitForClose();return;}await WriteAsync(stream,"221 bye",token);return;
                    default:await WriteAsync(stream,"500 unsupported",token);break;
                }
            }
        }
        finally {if(tls is not null)await tls.DisposeAsync();session.Closed=true;}
    }
    private static async Task<string?> ReadLineAsync(Stream stream,CancellationToken token)
    {
        var bytes=new List<byte>();var one=new byte[1];
        while(await stream.ReadAsync(one,token)!=0)
        {
            if(one[0]==10)return Encoding.ASCII.GetString(bytes.ToArray()).TrimEnd('\r');
            bytes.Add(one[0]);if(bytes.Count>8192)throw new InvalidOperationException("Fixture line budget exceeded.");
        }
        return bytes.Count==0?null:throw new IOException("Partial fixture line.");
    }
    private static async Task WriteAsync(Stream stream,string value,CancellationToken token)
    {await stream.WriteAsync(Encoding.ASCII.GetBytes(value+"\r\n"),token);await stream.FlushAsync(token);}
    private static (X509Certificate2,X509Certificate2) Certificates(string fault)
    {
        using var caKey=RSA.Create(2048);var ca=new CertificateRequest("CN=COR23H isolated fixture root",caKey,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        ca.CertificateExtensions.Add(new X509BasicConstraintsExtension(true,false,0,true));
        ca.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign|X509KeyUsageFlags.CrlSign,true));
        using var root=ca.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-10),DateTimeOffset.UtcNow.AddDays(10));
        using var key=RSA.Create(2048);var request=new CertificateRequest("CN=fixture",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        var san=new SubjectAlternativeNameBuilder();if(fault=="wrong-host")san.AddDnsName("wrong.example.test");else san.AddIpAddress(IPAddress.Loopback);request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false,false,0,true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature|X509KeyUsageFlags.KeyEncipherment,true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection {new Oid("1.3.6.1.5.5.7.3.1")},true));
        using var unsigned=request.Create(root,DateTimeOffset.UtcNow.AddDays(-2),fault=="expired"?DateTimeOffset.UtcNow.AddDays(-1):DateTimeOffset.UtcNow.AddDays(1),RandomNumberGenerator.GetBytes(16));
        using var leaf=unsigned.CopyWithPrivateKey(key);
        return (new(root.Export(X509ContentType.Cert)),new(leaf.Export(X509ContentType.Pfx)));
    }
    internal ISmtpClientFactory Clients(bool trustRoot=true) => new FixtureClients(Root,trustRoot);
    private sealed class FixtureClients(X509Certificate2 root,bool trustRoot) : ISmtpClientFactory
    {
        public SmtpClient Create()
        {
            var client=new SmtpClientFactory().Create();client.Timeout=10000;
            if(trustRoot)client.ServerCertificateValidationCallback=(_,certificate,_,errors)=>
            {
                if(certificate is null||(errors&(SslPolicyErrors.RemoteCertificateNameMismatch|SslPolicyErrors.RemoteCertificateNotAvailable))!=0)return false;
                using var leaf=new X509Certificate2(certificate);using var chain=new X509Chain();
                chain.ChainPolicy.TrustMode=X509ChainTrustMode.CustomRootTrust;chain.ChainPolicy.CustomTrustStore.Add(root);
                // Ephemeral private fixture CA has no CRL service; production retains online revocation/default validation.
                chain.ChainPolicy.RevocationMode=X509RevocationMode.NoCheck;chain.ChainPolicy.DisableCertificateDownloads=true;
                chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));return chain.Build(leaf);
            };
            return client;
        }
    }
    public async ValueTask DisposeAsync()
    {
        _stop.Cancel();_listener.Stop();
        try {await _run.WaitAsync(TimeSpan.FromSeconds(5));}
        finally {_stop.Dispose();Certificate.Dispose();Root.Dispose();}
    }
}
