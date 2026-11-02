using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Grpc.Core;
using Grpc.Net.Client;
namespace Treehammock.SessionValidation.Client;
internal interface IValidationTransport:IDisposable{bool TrustCurrent{get;}Task<byte[]> CallAsync(byte[] request,DateTimeOffset deadline,CancellationToken token);}
internal sealed class GrpcValidationTransport:IValidationTransport
{
    private int _disposed;private readonly ConnectionBudget _connections;private readonly ClientTrust _trust;private readonly GrpcChannel _channel;private readonly CallInvoker _calls;
    private static readonly Method<byte[],byte[]> Method=new(MethodType.Unary,"treehammock.sessionvalidation.v1.SessionValidator","Validate",Marshallers.Create<byte[]>(b=>b,b=>b),Marshallers.Create<byte[]>(b=>b,b=>b));
    internal GrpcValidationTransport(ClientOptions options,Func<string,CancellationToken,Task<IPAddress[]>>? resolve=null)
    {
        _trust=new(options);_connections=new(options.MaximumConnections);SocketsHttpHandler? sockets=null;GuardHandler? guard=null;
        try
        {
            int cursor=-1;
            sockets=new SocketsHttpHandler{UseProxy=false,AllowAutoRedirect=false,UseCookies=false,AutomaticDecompression=DecompressionMethods.None,EnableMultipleHttp2Connections=false,MaxConnectionsPerServer=options.MaximumConnections,MaxResponseHeadersLength=4,PooledConnectionLifetime=TimeSpan.FromMilliseconds(options.ConnectionLifetimeMilliseconds),PooledConnectionIdleTimeout=TimeSpan.FromSeconds(30),ConnectTimeout=TimeSpan.FromMilliseconds(options.RequestTimeoutMilliseconds),MaxResponseDrainSize=0,
                SslOptions=new SslClientAuthenticationOptions{EnabledSslProtocols=SslProtocols.Tls12|SslProtocols.Tls13,ClientCertificates=new X509CertificateCollection{_trust.Client},RemoteCertificateValidationCallback=_trust.Authenticate},
                ConnectCallback=async(_,token)=>{
                    var lease=await _connections.EnterAsync(token);
                    try{
                        var addresses=options.PrivateAddress.Length!=0?[IPAddress.Parse(options.PrivateAddress)]:await(resolve is null?Dns.GetHostAddressesAsync(options.TlsName,token):resolve(options.TlsName,token));
                        if(addresses.Length is <1 or >8||addresses.Any(a=>!ClientOptions.IsPrivate(a)))throw new HttpRequestException("Private validation endpoint required.");
                        var address=addresses[(int)((uint)Interlocked.Increment(ref cursor)%(uint)addresses.Length)];var socket=new Socket(address.AddressFamily,SocketType.Stream,ProtocolType.Tcp);
                        try{await socket.ConnectAsync(address,options.Port,token);return new ConnectionStream(new NetworkStream(socket,true),lease);}catch{socket.Dispose();throw;}
                    }catch{lease.Dispose();throw;}
                }};
            guard=new GuardHandler(_trust,sockets);
            _channel=GrpcChannel.ForAddress(new UriBuilder("https",options.TlsName,options.Port).Uri,new GrpcChannelOptions{HttpHandler=guard,DisposeHttpClient=true,MaxSendMessageSize=Contracts.ContractLimits.BinaryRequestBytes,MaxReceiveMessageSize=Contracts.ContractLimits.BinaryReplyBytes,CompressionProviders=[],DisableResolverServiceConfig=true,ServiceConfig=new(),MaxRetryAttempts=1,MaxRetryBufferSize=0,MaxRetryBufferPerCallSize=0});_calls=_channel.CreateCallInvoker();
        }
        catch{guard?.Dispose();if(guard is null)sockets?.Dispose();_connections.Close();_trust.Dispose();throw;}
    }
    public bool TrustCurrent=>_trust.Current;
    public async Task<byte[]> CallAsync(byte[] request,DateTimeOffset deadline,CancellationToken token)
    {
        // The original absolute ceiling prevents relative grpc-timeout reconstruction
        // after cold TLS/transit from extending evidence/reply validity.
        var headers=new Metadata{{"svs-deadline-unix-ms",deadline.ToUnixTimeMilliseconds().ToString(System.Globalization.CultureInfo.InvariantCulture)}};
        using var call=_calls.AsyncUnaryCall(Method,null,new CallOptions(headers:headers,deadline:deadline.UtcDateTime,cancellationToken:token),request);return await call.ResponseAsync;
    }
    private sealed class GuardHandler(ClientTrust trust,HttpMessageHandler inner):DelegatingHandler(inner)
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)
        {
            if(!trust.Current)throw new HttpRequestException("Validation trust expired.");var response=await base.SendAsync(request,token);
            if(response.Version!=HttpVersion.Version20||response.Headers.CacheControl?.NoStore!=true||response.Content.Headers.ContentEncoding.Count!=0||response.Headers.TryGetValues("grpc-encoding",out var encodings)&&encodings.Any(e=>e!="identity")){response.Dispose();throw new HttpRequestException("Validation response refused.");}return response;
        }
    }
    public void Dispose(){if(Interlocked.Exchange(ref _disposed,1)==0){_channel.Dispose();_connections.Close();_trust.Dispose();}}
}
