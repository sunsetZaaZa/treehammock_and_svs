using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Builder;
using Treehammock.SessionValidation.Api;
using Treehammock.SessionValidation.HostTests;
using Xunit;
namespace Treehammock.SessionValidation.SystemTests;
// Actual opaque TCP relays, not Nginx/HAProxy qualification. They verify that the
// delivered pass-through architecture can preserve original mTLS and ALPN.
public sealed class ProxyTransportTests(HostFixture fixture):IClassFixture<HostFixture>
{
    [Fact] public async Task Two_TCP_hops_preserve_original_server_pin_client_possession_and_HTTP2()
    {
        var settings=fixture.Settings();await using var app=SvsHost.Build(settings,_=>new FakeResources());await app.StartAsync(TestContext.Current.CancellationToken);
        await using var backend=new Relay(settings.Port);await using var ingress=new Relay(backend.Port);
        using var client=fixture.Http(settings,fixture.Client);client.BaseAddress=new($"https://127.0.0.1:{ingress.Port}");
        using var response=await client.GetAsync("/health/live",TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.OK,response.StatusCode);Assert.Equal(HttpVersion.Version20,response.Version);Assert.Equal("no-store",response.Headers.CacheControl!.ToString());
        Assert.Equal(1,ingress.Accepted);Assert.Equal(1,backend.Accepted);
    }
    [Fact] public async Task Two_TCP_hops_do_not_turn_forwarded_headers_into_TLS_identity()
    {
        var settings=fixture.Settings();await using var app=SvsHost.Build(settings,_=>new FakeResources());await app.StartAsync(TestContext.Current.CancellationToken);
        await using var backend=new Relay(settings.Port);await using var ingress=new Relay(backend.Port);
        using var client=fixture.Http(settings,null);client.BaseAddress=new($"https://127.0.0.1:{ingress.Port}");client.DefaultRequestHeaders.Add("X-Forwarded-Client-Cert",HostFixture.Pin(fixture.Client));
        await Assert.ThrowsAsync<HttpRequestException>(async()=>{using var response=await client.GetAsync("/health/live",TestContext.Current.CancellationToken);});
    }
    private sealed class Relay:IAsyncDisposable
    {
        private readonly TcpListener _listener=new(IPAddress.Loopback,0);private readonly CancellationTokenSource _stop=new();private readonly int _destination;private readonly Task _accept;
        private readonly object _sync=new();private readonly List<Task> _connections=[];internal int Accepted;internal int Port{get;}
        internal Relay(int destination){_destination=destination;_listener.Start(16);Port=((IPEndPoint)_listener.LocalEndpoint).Port;_accept=AcceptAsync();}
        private async Task AcceptAsync()
        {
            try
            {
                while(true)
                {
                    var client=await _listener.AcceptTcpClientAsync(_stop.Token);
                    lock(_sync)
                    {
                        _connections.RemoveAll(t=>t.IsCompleted);
                        if(_connections.Count>=16){client.Dispose();continue;}
                        Interlocked.Increment(ref Accepted);_connections.Add(TransferAsync(client));
                    }
                }
            }
            catch(OperationCanceledException)when(_stop.IsCancellationRequested){}
            catch(SocketException)when(_stop.IsCancellationRequested){}
        }
        private async Task TransferAsync(TcpClient client)
        {
            using(client)using(var server=new TcpClient())
            {
                try
                {
                    await server.ConnectAsync(IPAddress.Loopback,_destination,_stop.Token);using var incoming=client.GetStream();using var outgoing=server.GetStream();
                    var a=incoming.CopyToAsync(outgoing,16384,_stop.Token);var b=outgoing.CopyToAsync(incoming,16384,_stop.Token);await Task.WhenAny(a,b);client.Close();server.Close();
                    try{await Task.WhenAll(a,b);}catch(Exception e)when(e is IOException or OperationCanceledException or ObjectDisposedException){}
                }
                catch(Exception e)when(e is SocketException or IOException or OperationCanceledException or ObjectDisposedException){}
            }
        }
        public async ValueTask DisposeAsync()
        {
            await _stop.CancelAsync();_listener.Stop();await _accept;Task[] pending;lock(_sync)pending=_connections.ToArray();await Task.WhenAll(pending);_stop.Dispose();
        }
    }
}
