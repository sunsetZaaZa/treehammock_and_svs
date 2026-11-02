using System.Security.Cryptography;
using System.Text;
using NodaTime;
using Treehammock.SessionValidation.Core;
using Treehammock.SessionValidation.Storage;
using Treehammock.SessionValidation.UnitTests;
namespace Treehammock.SessionValidation.CacheTests;

internal sealed class Clock : IClock { internal Instant Now=TestSessions.Now;public Instant GetCurrentInstant()=>Now; }
internal sealed class CacheHarness : IDisposable
{
    internal readonly Clock Clock=new();
    internal readonly CoherentCacheKeySpace Space=new("qualification",Guid.Parse("77777777-7777-4777-8777-777777777777"),"auth.v1");
    internal readonly Store Cache=new();
    internal readonly Authority Db=new();
    internal readonly Refills Refill=new();
    internal SessionCacheAdmission Gate;
    internal string Token=TestSessions.Mint();
    internal string Hash=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Token)));
    internal CacheHarness(bool admitted=true)
    { Gate=admitted?SessionCacheAdmission.ForQualification(Space,Cache):new();SetReady(); }
    internal CachedAccountAuthority Record(long revision=9007199254740993)
    { return new(new(Space.Environment,Space.Epoch,Space.Policy,CoherentCacheKeySpace.NewTransitionNonce(),revision,CachedAuthorityState.Ready,TestSessions.Identity.AccountId),Hash,Clock.Now,Clock.Now+Duration.FromSeconds(20),TestSessions.Identity,TestSessions.Inputs().Lifetime,
        new(true,1,null,TestSessions.Identity.AccountStamp,true),TestSessions.Entitlements(rights:false,evaluated:Clock.Now),TestSessions.Key()); }
    internal void SetReady()
    { using var r=Record();Cache.Index=Encoding.UTF8.GetBytes(TestSessions.Identity.AccountId.ToString("N"));Cache.Payload=CoherentCacheCodec.Encode(r); }
    internal SessionEvidenceCoordinator Coordinator(ITreehammockSessionPolicyEvaluator? policy=null,int cacheMilliseconds=200,int requestMilliseconds=1000)
    { return new(new(Cache,Gate,TimeSpan.FromMilliseconds(cacheMilliseconds),TimeSpan.FromSeconds(30)),Db,TestSessions.Issuer,TimeSpan.FromMilliseconds(requestMilliseconds),Refill,policy,Clock); }
    internal Task<SessionEvidenceDecision> Validate(string capability="account.read",CancellationToken token=default)
        =>Coordinator().ValidateAsync(Token,capability,Clock.Now+Duration.FromSeconds(1),token);
    public void Dispose(){if(Cache.Index is {} i)CryptographicOperations.ZeroMemory(i);if(Cache.Payload is {} p)CryptographicOperations.ZeroMemory(p);}
    internal sealed class Store : ICoherentCacheGetStore
    {
        internal byte[]? Index;internal byte[]? Payload;internal bool Down;
        internal Func<string,CancellationToken,Task<byte[]?>>? Read;
        internal readonly List<string> Keys=[];internal readonly List<byte[]> Returned=[];
        public Task<byte[]?> GetAsync(string key,CancellationToken token)
        {
            Keys.Add(key);if(Down)throw new InvalidOperationException("private-cache-canary");
            if(Read is not null)return Read(key,token);
            byte[]? bytes=key.Contains(":credential:",StringComparison.Ordinal)?Index:Payload;
            var owned=bytes is null?null:(byte[])bytes.Clone();if(owned is not null)Returned.Add(owned);return Task.FromResult(owned);
        }
    }
    internal sealed class Authority : IReadonlySessionAuthority
    {
        internal int Calls;internal bool Down;internal AuthorityReadStatus Status=AuthorityReadStatus.Found;
        internal Func<string,Instant,CancellationToken,Task<AuthorityReadResult>>? Read;
        public Task<AuthorityReadResult> ReadAsync(string hash,Instant deadline,CancellationToken token)
        {
            Calls++;if(Down)throw new InvalidOperationException("private-db-canary");if(Read is not null)return Read(hash,deadline,token);
            var result=Status==AuthorityReadStatus.Found?new AuthorityReadResult(Status,Projection(hash)):new(Status);
            return Task.FromResult(result);
        }
        internal static AuthSessionProjection Projection(string hash)=>new(hash,TestSessions.Key(),TestSessions.Identity,TestSessions.Inputs().Lifetime,TestSessions.Entitlements(rights:false),TestSessions.Now);
    }
    internal sealed class Refills : IGuardedSessionRefillQueue
    {
        internal readonly List<(string Hash,Guid Epoch)> Requests=[];internal Action? OnRequest;
        public bool TryRequest(string hash,Guid epoch){Requests.Add((hash,epoch));OnRequest?.Invoke();return true;}
    }
}
