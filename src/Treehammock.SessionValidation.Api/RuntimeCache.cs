using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using StackExchange.Redis;
using Treehammock.SessionValidation.Storage;
namespace Treehammock.SessionValidation.Api;
internal sealed class RuntimeCache : IRuntimeCache
{
    private readonly HostSettings _settings;
    private readonly RefillSettings _refill;
    private readonly X509Certificate2 _readerRoot,_writerRoot;
    private readonly RequestLifetime _raw;
    private readonly ServiceConcurrencyLimiter _reads;
    private readonly object _sync=new();
    private Func<IDisposable>? _ownership;
    public void OwnOperations(Func<IDisposable> ownership)=>_ownership=ownership;
    private Task? _startup;
    private IConnectionMultiplexer? _reader,_writer;
    private DragonflyAuthorityStore? _store;
    private int _invalid,_disposed;
    private long _trustUntil=DateTime.MaxValue.Ticks;
    internal RuntimeCache(HostSettings settings)
    {
        _settings=settings;_refill=settings.Refill!;_reads=new(settings.Capacity.CacheReadOperations,"cache-read");_raw=new(settings.Capacity.RawCacheOperations,"raw-cache");
        _readerRoot=X509CertificateLoader.LoadCertificateFromFile(settings.Cache.RootCertificatePath);_writerRoot=X509CertificateLoader.LoadCertificateFromFile(_refill.PublisherCache.RootCertificatePath);
        try{ServiceCertificates.RequireRoot(_readerRoot);ServiceCertificates.RequireRoot(_writerRoot);}catch{_readerRoot.Dispose();_writerRoot.Dispose();throw;}
    }
    private bool Current=>Volatile.Read(ref _invalid)==0&&Volatile.Read(ref _disposed)==0&&DateTime.UtcNow.Ticks<Interlocked.Read(ref _trustUntil);
    public bool ReaderReady=>Current&&_reader?.IsConnected==true;
    public bool PublisherReady=>Current&&_store?.Available==true;
    public IAuthorityConditionalStore Publisher=>new PublisherAdapter(this);
    public void Quarantine(){Interlocked.Exchange(ref _invalid,1);_store?.Quarantine();}
    private ConfigurationOptions Options(CacheConnectionSettings s,X509Certificate2 root)
    {
        var o=new ConfigurationOptions{Ssl=true,SslHost=s.TlsName,User=s.Username,Password=s.Password,AbortOnConnectFail=true,ConnectRetry=0,ConnectTimeout=2000,AsyncTimeout=2000,SyncTimeout=2000,ConfigurationChannel="",AllowAdmin=false,BacklogPolicy=BacklogPolicy.FailFast,IncludeDetailInExceptions=false,SslProtocols=System.Security.Authentication.SslProtocols.Tls12|System.Security.Authentication.SslProtocols.Tls13};o.EndPoints.Add(s.Address,s.Port);
        o.CertificateValidation+=(_,c,_,errors)=>
        {
            if(c is null||(errors&SslPolicyErrors.RemoteCertificateNameMismatch)!=0)return false;using var leaf=X509CertificateLoader.LoadCertificate(c.GetRawCertData());
            if(Convert.ToHexString(SHA256.HashData(leaf.RawData))!=s.LeafSha256||!ServiceCertificates.ValidLeaf(leaf,root,"1.3.6.1.5.5.7.3.1"))return false;
            long end=Math.Min(leaf.NotAfter.ToUniversalTime().Ticks,root.NotAfter.ToUniversalTime().Ticks),old;
            do{old=Interlocked.Read(ref _trustUntil);if(end>=old)break;}while(Interlocked.CompareExchange(ref _trustUntil,end,old)!=old);return true;
        };return o;
    }
    private async Task<IConnectionMultiplexer> ConnectAsync(CacheConnectionSettings s,X509Certificate2 root)
    {
        var c=await ConnectionMultiplexer.ConnectAsync(Options(s,root));
        c.ConnectionFailed+=Changed;c.ConnectionRestored+=Changed;c.ConfigurationChanged+=Changed;c.ConfigurationChangedBroadcast+=Changed;c.ErrorMessage+=Error;
        try
        {
            var expected=c.GetEndPoints(true);var actual=c.GetEndPoints(false);if(expected.Length!=1||actual.Length!=1||!expected[0].Equals(actual[0]))throw new InvalidOperationException("Primary endpoint mismatch.");
            var server=c.GetServer(expected[0]);if(!server.IsConnected||server.IsReplica||server.ServerType!=ServerType.Standalone)throw new InvalidOperationException("Single primary required.");
            var db=c.GetDatabase();string info=(await db.ExecuteAsync("INFO","server")).ToString();
            var fields=info.Split('\n').Select(l=>l.TrimEnd('\r').Split(':',2)).Where(x=>x.Length==2).ToDictionary(x=>x[0],x=>x[1],StringComparer.Ordinal);
            if(fields.GetValueOrDefault("dragonfly_version")!=_refill.DragonflyVersion||fields.GetValueOrDefault("run_id")!=_refill.PrimaryRunId)throw new InvalidOperationException("Primary process/version mismatch.");
            string who=(await db.ExecuteAsync("ACL","WHOAMI")).ToString();if(who!=s.Username&&who!="User is "+s.Username)throw new InvalidOperationException("Actual cache login mismatch.");
            if(!Current)throw new InvalidOperationException("Cache incarnation invalidated.");return c;
        }
        catch{await c.DisposeAsync();throw;}
    }
    public async Task PrepareAsync(CancellationToken token)
    {
        Task pending;lock(_sync)pending=_startup??=StartAsync();
        try{await pending.WaitAsync(token);if(!Current)throw new InvalidOperationException("Cache invalidated.");}catch{Quarantine();throw;}
    }
    private async Task StartAsync()
    {
        using var lease=_raw.TryEnter()??throw new InvalidOperationException("Cache draining.");
        try
        {
            _reader=await ConnectAsync(_settings.Cache,_readerRoot);_writer=await ConnectAsync(_refill.PublisherCache,_writerRoot);
            await CheckAclAsync(_writer.GetDatabase());if(!Current)throw new InvalidOperationException("Startup invalidated.");
            _store=new(_writer,0,new(_refill.Environment,_refill.Epoch,_refill.Policy),_refill.Workers);
        }
        catch{Quarantine();throw;}
    }
    // Exact policy semantics from THS12C; DRYRUN checks permissions without writing
    // test data. It cannot prove script-body isolation; native escape tests remain.
    private async Task CheckAclAsync(IDatabase db)
    {
        var space=new CoherentCacheKeySpace(_refill.Environment,_refill.Epoch,_refill.Policy);string account=space.AccountKey(Guid.Parse("11111111-1111-1111-1111-111111111111")),index=space.CredentialKey(new('A',64));
        var checks=new List<(string User,bool Allow,string[] Command)>();
        void Add(string u,bool allow,params string[] command)=>checks.Add((u,allow,command));
        string read=_settings.Cache.Username,write=_refill.PublisherCache.Username;
        foreach(string key in new[]{account,index}){Add(read,true,"GET",key);Add(write,true,"GET",key);Add(write,true,"SET",key,"probe");}
        Add(read,true,"ACL","WHOAMI");Add(read,false,"SET",account,"probe");Add(read,false,"EVAL","return 1","1",account);Add(read,false,"EVALSHA",new('a',40),"1",account);
        Add(write,true,"EVAL","return 1","1",account);
        foreach(string user in new[]{read,write})
        {
            Add(user,false,"GET","ths10:outside");Add(user,false,"SET","ths10:outside","probe");Add(user,false,"EVAL","return 1","1","ths10:outside");
            foreach(string cmd in new[]{"DEL","UNLINK","EXPIRE","PEXPIRE","RESTORE","RENAME","MSET"})
            {string[] args=cmd switch{"DEL" or "UNLINK"=>[cmd,account],"EXPIRE" or "PEXPIRE"=>[cmd,account,"10"],"RESTORE"=>[cmd,account,"0","payload"],"RENAME"=>[cmd,account,index],_=>[cmd,account,"payload"]};Add(user,false,args);}
            Add(user,false,"FLUSHALL");Add(user,false,"CONFIG","SET","maxmemory","0");Add(user,false,"ACL","SETUSER",user,"+@all");Add(user,false,"REPLICAOF","127.0.0.1","1");
        }
        foreach(var (user,allow,command) in checks)
        {
            string reply;try{reply=(await db.ExecuteAsync("ACL",new object[]{"DRYRUN",user}.Concat(command.Cast<object>()).ToArray())).ToString();}
            catch(RedisServerException e)when(e.Message.StartsWith("NOPERM ",StringComparison.Ordinal)){reply=e.Message;}
            bool permitted=allow?reply=="OK":reply.StartsWith("NOPERM ",StringComparison.Ordinal)||reply.StartsWith("This user has no permissions to run the '",StringComparison.Ordinal);
            if(!permitted)throw new InvalidOperationException("Actual cache ACL boundary refused.");
        }
    }
    private void Changed(object? s,ConnectionFailedEventArgs e)=>Quarantine();
    private void Changed(object? s,EndPointEventArgs e)=>Quarantine();
    private void Error(object? s,RedisErrorEventArgs e)=>Quarantine();
    private bool Key(string key)
    {
        var space=new CoherentCacheKeySpace(_refill.Environment,_refill.Epoch,_refill.Policy);string prefix=$"svs:authority:v1:{space.Environment}:{space.Epoch:N}:";
        if(!key.StartsWith(prefix,StringComparison.Ordinal))return false;string tail=key[prefix.Length..];
        if(tail.StartsWith("account:",StringComparison.Ordinal)){string id=tail[8..];return Guid.TryParseExact(id,"N",out var g)&&g!=Guid.Empty&&id==g.ToString("N");}
        return tail.StartsWith("credential:",StringComparison.Ordinal)&&HostSettings.Pin(tail[11..]);
    }
    public Task<byte[]?> GetAsync(string key,CancellationToken token)=>GetRawAsync(key,false,token);
    private async Task<byte[]?> GetRawAsync(string key,bool writer,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();if(!Current||!Key(key)||!(writer?PublisherReady:ReaderReady))throw new InvalidOperationException("Cache unavailable or busy.");
        using var read=_reads.TryEnter()??throw new InvalidOperationException("Cache capacity unavailable.");
        using var lease=_raw.TryEnter();
        try
        {
            using var operation=_ownership?.Invoke();
            if(lease is null)throw new InvalidOperationException("Cache draining.");var c=writer?_writer!:_reader!;
            var value=await c.GetDatabase().StringGetAsync(key,CommandFlags.DemandMaster|CommandFlags.NoRedirect);byte[]? bytes=value.IsNull?null:(byte[]?)value;
            if(!Current||token.IsCancellationRequested){if(bytes is not null)CryptographicOperations.ZeroMemory(bytes);throw new OperationCanceledException(token);}return bytes;
        }
        catch(RedisException){Quarantine();throw;}
    }
    private sealed class PublisherAdapter(RuntimeCache owner):IAuthorityConditionalStore
    {
        public bool Available=>owner.PublisherReady;
        public Task<byte[]?> GetAsync(string key,CancellationToken token)=>owner.GetRawAsync(key,true,token);
        public async Task<bool> ExchangeAsync(CacheTransition command,CancellationToken token)
        {using var lease=owner._raw.TryEnter()??throw new InvalidOperationException("Cache draining.");if(!owner.PublisherReady)throw new InvalidOperationException("Publisher unavailable.");return await owner._store!.ExchangeAsync(command,token);}
    }
    public async Task ProbeAsync(string purpose,CancellationToken token)
    {
        var settings=purpose=="cache-reader"?_settings.Cache:purpose=="cache-refiller"?_refill.PublisherCache:throw new ArgumentException("Cache purpose required.");var root=purpose=="cache-reader"?_readerRoot:_writerRoot;
        var pending=ConnectionMultiplexer.ConnectAsync(Options(settings,root));
        try{await using var c=await pending.WaitAsync(token);throw new InvalidOperationException("Retired cache login still authenticates.");}
        catch(RedisConnectionException e)when(e.FailureType==ConnectionFailureType.AuthenticationFailure){return;}
        finally{if(!pending.IsCompleted)_=pending.ContinueWith(async t=>{if(t.IsCompletedSuccessfully)await t.Result.DisposeAsync();else _=t.Exception;},CancellationToken.None,TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default).Unwrap();}
    }
    public async Task StopAsync(CancellationToken token)
    {
        Quarantine();_raw.Close();var closing=new List<Task>();if(_reader is not null)closing.Add(_reader.CloseAsync());if(_writer is not null)closing.Add(_writer.CloseAsync());
        await Task.WhenAll(closing).WaitAsync(token);await _raw.DrainAsync(token);
    }
    public async ValueTask DisposeAsync()
    {
        if(Interlocked.Exchange(ref _disposed,1)!=0)return;Quarantine();await StopAsync(CancellationToken.None);
        _store?.Dispose();if(_reader is not null)await _reader.DisposeAsync();if(_writer is not null)await _writer.DisposeAsync();_readerRoot.Dispose();_writerRoot.Dispose();
    }
}
