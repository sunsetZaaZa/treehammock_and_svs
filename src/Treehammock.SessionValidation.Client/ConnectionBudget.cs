namespace Treehammock.SessionValidation.Client;
// Holds physical HTTP2 connection ownership through actual stream disposal.
internal sealed class ConnectionBudget(int capacity)
{
    private readonly SemaphoreSlim _slots=new(capacity,capacity);private readonly object _gate=new();private int _waiting,_leased;private bool _closed,_disposed;
    internal async Task<IDisposable> EnterAsync(CancellationToken token)
    {
        lock(_gate){ObjectDisposedException.ThrowIf(_closed,this);_waiting++;}bool counted=true;
        try{await _slots.WaitAsync(token);lock(_gate){_waiting--;counted=false;if(_closed){_slots.Release();MaybeDispose();throw new ObjectDisposedException(nameof(ConnectionBudget));}_leased++;return new Lease(this);}}
        finally{if(counted)lock(_gate){_waiting--;MaybeDispose();}}
    }
    private void Release(){lock(_gate){_leased--;_slots.Release();MaybeDispose();}}
    internal void Close(){lock(_gate){_closed=true;MaybeDispose();}}
    private void MaybeDispose(){if(_closed&&!_disposed&&_waiting==0&&_leased==0){_disposed=true;_slots.Dispose();}}
    private sealed class Lease(ConnectionBudget owner):IDisposable{private int _released;public void Dispose(){if(Interlocked.Exchange(ref _released,1)==0)owner.Release();}}
}
internal sealed class ConnectionStream(Stream inner,IDisposable lease):Stream
{
    private int _disposed;
    public override bool CanRead=>inner.CanRead;public override bool CanSeek=>inner.CanSeek;public override bool CanWrite=>inner.CanWrite;public override bool CanTimeout=>inner.CanTimeout;
    public override long Length=>inner.Length;public override long Position{get=>inner.Position;set=>inner.Position=value;}
    public override int ReadTimeout{get=>inner.ReadTimeout;set=>inner.ReadTimeout=value;}public override int WriteTimeout{get=>inner.WriteTimeout;set=>inner.WriteTimeout=value;}
    public override void Flush()=>inner.Flush();public override Task FlushAsync(CancellationToken token)=>inner.FlushAsync(token);
    public override int Read(byte[] b,int o,int c)=>inner.Read(b,o,c);public override int Read(Span<byte> b)=>inner.Read(b);
    public override ValueTask<int> ReadAsync(Memory<byte> b,CancellationToken t=default)=>inner.ReadAsync(b,t);public override Task<int> ReadAsync(byte[] b,int o,int c,CancellationToken t)=>inner.ReadAsync(b,o,c,t);
    public override void Write(byte[] b,int o,int c)=>inner.Write(b,o,c);public override void Write(ReadOnlySpan<byte> b)=>inner.Write(b);
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> b,CancellationToken t=default)=>inner.WriteAsync(b,t);public override Task WriteAsync(byte[] b,int o,int c,CancellationToken t)=>inner.WriteAsync(b,o,c,t);
    public override long Seek(long o,SeekOrigin s)=>inner.Seek(o,s);public override void SetLength(long v)=>inner.SetLength(v);
    protected override void Dispose(bool disposing){if(disposing&&Interlocked.Exchange(ref _disposed,1)==0)try{inner.Dispose();}finally{lease.Dispose();}base.Dispose(disposing);}
    public override async ValueTask DisposeAsync(){if(Interlocked.Exchange(ref _disposed,1)==0)try{await inner.DisposeAsync();}finally{lease.Dispose();}GC.SuppressFinalize(this);}
}
