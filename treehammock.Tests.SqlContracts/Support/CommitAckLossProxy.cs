using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace treehammock.Tests.SqlContracts.Support;

// Test-only PostgreSQL wire fault. The server's CommandComplete(COMMIT)
// proves commit occurred; this packet and ReadyForQuery are never forwarded.
internal sealed class Cor04CommitAckLossProxy : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _stop = new();
    private readonly ConcurrentBag<TcpClient> _clients = new();
    private readonly ConcurrentBag<Task> _sessions = new();
    private readonly string _host;
    private readonly int _serverPort;
    private readonly Task _accept;
    private int _armed;
    private readonly TaskCompletionSource _dropped = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;
    public Task Dropped => _dropped.Task;
    public Cor04CommitAckLossProxy(string host, int port)
    { _host=host; _serverPort=port; _listener.Start(); _accept=AcceptAsync(); }
    public void Arm() => Interlocked.Exchange(ref _armed, 1);
    private async Task AcceptAsync()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                var client = await _listener.AcceptTcpClientAsync(_stop.Token);
                _clients.Add(client); _sessions.Add(RelayAsync(client));
            }
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
        catch (SocketException) when (_stop.IsCancellationRequested) { }
    }
    private async Task RelayAsync(TcpClient client)
    {
        using var server = new TcpClient(); _clients.Add(server);
        try
        {
            await server.ConnectAsync(_host, _serverPort, _stop.Token);
            using var incoming = client.GetStream(); using var outgoing = server.GetStream();
            Task upload = incoming.CopyToAsync(outgoing, _stop.Token);
            Task download = ServerMessagesAsync(incoming, outgoing);
            await Task.WhenAny(upload, download);
            client.Dispose(); server.Dispose();
            try { await Task.WhenAll(upload, download); } catch { }
        }
        catch (Exception) when (_stop.IsCancellationRequested || !client.Connected) { }
        catch { client.Dispose(); }
    }
    private async Task ServerMessagesAsync(NetworkStream incoming, NetworkStream outgoing)
    {
        byte[] header = new byte[5];
        while (!_stop.IsCancellationRequested)
        {
            await outgoing.ReadExactlyAsync(header.AsMemory(), _stop.Token);
            int length = BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(1));
            if (length < 4 || length > 16 * 1024 * 1024) throw new IOException("Invalid PostgreSQL test packet.");
            byte[] payload = new byte[length - 4];
            await outgoing.ReadExactlyAsync(payload.AsMemory(), _stop.Token);
            if (header[0] == (byte)'C' && Encoding.UTF8.GetString(payload) == "COMMIT\0" && Interlocked.Exchange(ref _armed, 0) == 1)
            { _dropped.TrySetResult(); return; }
            await incoming.WriteAsync(header.AsMemory(), _stop.Token);
            await incoming.WriteAsync(payload.AsMemory(), _stop.Token);
        }
    }
    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync(); _listener.Stop();
        foreach (var client in _clients) client.Dispose();
        try { await _accept.WaitAsync(TimeSpan.FromSeconds(5)); } catch (OperationCanceledException) { }
        await Task.WhenAll(_sessions).WaitAsync(TimeSpan.FromSeconds(5));
        _stop.Dispose();
    }
}
