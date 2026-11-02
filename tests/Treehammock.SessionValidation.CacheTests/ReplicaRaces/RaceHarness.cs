using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using NodaTime;
using Svs12.Harness;
using Svs12.Golden;
using Treehammock.SessionValidation.Core;
using Treehammock.SessionValidation.Storage;
namespace Svs13.Harness;

// Only infrastructure is doubled. Uses the production publisher, projection mapper,
// GET reader, signature verifier and coordinator. This is not native MVCC/CAS proof.
internal sealed class RaceWorld : IDisposable
{
    internal readonly ParityHarness Golden=new("issued-no-exp",true);
    internal readonly SemaphoreSlim Guard=new(1,1);
    internal readonly Trace Events=new();
    internal readonly Store Cache;
    internal readonly Database Db;
    internal AuthorityVersion Version;
    internal CurrentSessionRow? Current;
    internal SessionCacheAdmission[] Admissions;
    internal readonly ConcurrentQueue<double> ReaderMilliseconds=new();
    internal double WriterLockWaitMilliseconds {get;set;}
    internal RaceWorld()
    {
        Version=new(Golden.Identity.AccountId,new(7),"Live");Current=Golden.Row()!;
        Cache=new(Events);Db=new(this);Cache.Seed(Golden.Space.AccountKey(Version.AccountId),Golden.Store.Payload!);
        Cache.Seed(Golden.Space.CredentialKey(Golden.Hash),Golden.Store.Index!);
        Admissions=[SessionCacheAdmission.ForQualification(Golden.Space,Cache),SessionCacheAdmission.ForQualification(Golden.Space,Cache)];
    }
    internal SessionEvidenceCoordinator Reader(int replica)=>new(new(Cache,Admissions[replica],TimeSpan.FromSeconds(1),TimeSpan.FromSeconds(30)),
        new YsqlSessionAuthority(Db,TimeSpan.FromSeconds(1),new ParityClock(Golden.Now)),TreehammockParityFixtures.Corpus.Issuer,TimeSpan.FromSeconds(2),clock:new ParityClock(Golden.Now));
    internal Task<SessionEvidenceDecision[]> ReadBoth()=>Task.WhenAll(Enumerable.Range(0,2).Select(n=>Task.Run(async()=>{
        long start=System.Diagnostics.Stopwatch.GetTimestamp();
        var result=await Reader(n).ValidateAsync(Golden.Credential,"account.read",Golden.Now+Duration.FromSeconds(2));
        ReaderMilliseconds.Enqueue(System.Diagnostics.Stopwatch.GetElapsedTime(start).TotalMilliseconds);return result;
    })));
    internal ConditionalProjectionPublisher Publisher()=>new(new(new Leases(this),Golden.Space,TimeSpan.FromSeconds(30),TimeSpan.FromSeconds(2),new ParityClock(Golden.Now)),Cache,Golden.Space,TimeSpan.FromSeconds(2),new ParityClock(Golden.Now));
    internal void Mutate(string mutation)
    {
        var row=Current!;
        Current=mutation switch {
            "lock"=>row with{UnlockWhen=Golden.Now+Duration.FromHours(1)},
            "verification"=>row with{VerificationStatus=0},
            "account-stamp"=>row with{AccountStamp=Guid.NewGuid()},
            "calendar"=>row with{Lifetime=row.Lifetime with{AccessExpiration=Golden.Now}},
            "capability"=>row with{EntitlementJson=WithoutRead(row.EntitlementJson)},
            _=>null // Old credential row removed by the simulated domain transaction.
        };
        if(Current is null)row.Dispose();
        Version=Version with{Revision=Version.Revision.Next(),Lifecycle=mutation=="deletion"?"Deleted":"Live"};
        Events.Add("commit");
    }
    private static string WithoutRead(string json)
    {
        var node=System.Text.Json.Nodes.JsonNode.Parse(json)!;
        node["capabilities"]=new System.Text.Json.Nodes.JsonArray(System.Text.Json.Nodes.JsonValue.Create("account.manage"));
        return node.ToJsonString();
    }
    internal CachedAuthorityState State()
    {using var r=CacheTransition.Decode(Cache.Copy(Golden.Space.AccountKey(Version.AccountId))!,Golden.Space,Version.AccountId);return r.Header.State;}
    public void Dispose(){Current?.Dispose();Cache.Dispose();Golden.Dispose();Guard.Dispose();}
    internal sealed class Leases(RaceWorld w):IAuthorityProjectionLeaseFactory
    {
        public async Task<IAuthorityProjectionLease> AcquireAsync(Guid account,TimeSpan budget,CancellationToken token)
        {await w.Guard.WaitAsync(token);w.Events.Add("refill-lock");return new Lease(w);}
        private sealed class Lease(RaceWorld w):IAuthorityProjectionLease
        {
            public AuthorityVersion? Authority=>w.Version;
            public Task<ProjectionCandidate> ReadCurrentAsync(string hash,CancellationToken token)
            {w.Events.Add("refill-read");return Task.FromResult(new ProjectionCandidate(w.Current is null?null:hash,w.Current is {} row?row with{Key=row.Key.ToArray()}:null));}
            public ValueTask DisposeAsync(){w.Events.Add("refill-release");w.Guard.Release();return ValueTask.CompletedTask;}
        }
    }
    internal sealed class Database(RaceWorld w):IYsqlSnapshotExecutor
    {
        internal int Calls;internal bool Down;internal Func<Task>? BeforeSnapshot {get;set;}
        public async Task<CurrentSessionRow?> ReadAsync(string hash,TimeSpan budget,CancellationToken token)
        {
            Interlocked.Increment(ref Calls);if(BeforeSnapshot is {} before)await before();w.Events.Add("snapshot");
            if(Down)throw new InvalidOperationException("Synthetic database outage");
            return w.Current is {} row?row with{Key=row.Key.ToArray()}:null;
        }
    }
    internal sealed class Store(Trace trace):IAuthorityConditionalStore,ICoherentCacheGetStore,IDisposable
    {
        private readonly Dictionary<string,byte[]> _values=[];
        internal Func<CacheTransition,Task<bool>>? Raw {get;set;}
        internal Func<Task>? BeforeAccountRead {get;set;}
        internal readonly ConcurrentQueue<byte[]> Returned=new();
        public bool Available{get;set;}=true;
        internal byte[]? Copy(string key){lock(_values)return _values.TryGetValue(key,out var b)?b.ToArray():null;}
        internal void Seed(string key,byte[] value){lock(_values){if(_values.Remove(key,out var old))CryptographicOperations.ZeroMemory(old);_values[key]=value.ToArray();}}
        internal void Remove(string key){lock(_values)if(_values.Remove(key,out var old))CryptographicOperations.ZeroMemory(old);}
        // The hook only gates validator transport; publication's private GET is
        // deliberately separate so the actual mutation owner can fence/commit.
        public async Task<byte[]?> GetAsync(string key,CancellationToken token)
        {if(key.Contains(":account:",StringComparison.Ordinal)&&BeforeAccountRead is {} before)await before();return ReadImmediate(key);}
        Task<byte[]?> IAuthorityConditionalStore.GetAsync(string key,CancellationToken token)=>Task.FromResult(ReadImmediate(key));
        private byte[]? ReadImmediate(string key)
        {var b=Copy(key);if(b is not null)Returned.Enqueue(b);trace.Add(key.Contains(":account:",StringComparison.Ordinal)?"account-get":"index-get");return b;}
        public Task<bool> ExchangeAsync(CacheTransition command,CancellationToken token)=>Raw?.Invoke(command)??Task.FromResult(Apply(command));
        internal bool Apply(CacheTransition command)
        {
            lock(_values)
            {
                _values.TryGetValue(command.AccountKey,out var before);
                if(command.Prior is null?before is not null:before is null||!before.SequenceEqual(command.Prior))return false;
                Seed(command.AccountKey,command.Next);
                if(command.CredentialKey is {} index)Seed(index,Encoding.ASCII.GetBytes(command.Header.AccountId.ToString("N")));
                trace.Add(command.Header.State==CachedAuthorityState.Ready?"ready-cas":"fence-cas");return true;
            }
        }
        public void Dispose(){lock(_values)foreach(var bytes in _values.Values)CryptographicOperations.ZeroMemory(bytes);}
    }
    internal sealed class Trace
    {
        private readonly List<string> _events=[];
        internal void Add(string name){lock(_events)_events.Add(name);}
        internal string[] Snapshot(){lock(_events)return _events.ToArray();}
    }
}

// A named rendezvous, not a delay or a counter standing in for another process.
internal sealed class Rendezvous
{
    internal readonly TaskCompletionSource Entered=new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal readonly TaskCompletionSource Release=new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal async Task Arrive(){Entered.TrySetResult();await Release.Task.WaitAsync(TimeSpan.FromSeconds(5));}
}
