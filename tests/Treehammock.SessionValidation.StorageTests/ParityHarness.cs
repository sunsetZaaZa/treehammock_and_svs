using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NodaTime;
using NodaTime.Text;
using Svs12.Golden;
using Treehammock.SessionValidation.Core;
using Treehammock.SessionValidation.Storage;
namespace Svs12.Harness;

internal sealed class ParityClock(Instant now):IClock{public Instant GetCurrentInstant()=>now;}
internal sealed class ParityHarness:IDisposable
{
    internal readonly ParityCase Case;
    internal readonly Instant Now;
    internal readonly string Credential,Hash;
    internal readonly SessionIdentity Identity;
    internal readonly CoherentCacheKeySpace Space=new("svs12",Guid.Parse("77777777-7777-4777-8777-777777777777"),"auth.v1");
    internal readonly Cache Store=new();
    internal readonly Hints Refill=new();
    internal readonly Executor Database;
    internal readonly SessionCacheAdmission Admission;
    internal SessionValidationInputs Inputs {get;}
    internal EntitlementPolicyInputs Entitlements {get;}
    internal SessionLifetime Lifetime {get;}
    internal ParityHarness(string id,bool warm,Instant? now=null)
    {
        Case=TreehammockParityFixtures.Case(id);Now=now??InstantPattern.ExtendedIso.Parse(TreehammockParityFixtures.Corpus.Now).Value;
        Credential=TreehammockParityFixtures.Credential(Case);Hash=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Credential)));
        Identity=new(Guid.Parse("11111111-1111-4111-8111-111111111111"),Case.EmptyFamily?Guid.Empty:Guid.Parse("22222222-2222-4222-8222-222222222222"),Case.Generation,Case.Protocol,Guid.Parse("33333333-3333-4333-8333-333333333333"),Guid.Parse("44444444-4444-4444-8444-444444444444"));
        Instant? At(long? ticks)=>ticks is {} t?Now+Duration.FromTicks(t):null;
        Lifetime=new(Now+Duration.FromTicks(Case.AccessTicks),Now+Duration.FromTicks(Case.HardTicks),At(Case.CutoffTicks));
        Entitlements=new(Identity.AccountId,Case.EntitlementVersion,Case.FeatureTier,Case.Capabilities,false,Now+Duration.FromTicks(Case.EvaluatedTicks),At(Case.BoundaryTicks),At(Case.EligibilityTicks),true);
        var current=Case.Authority switch{"family"=>Identity with{FamilyId=Guid.Parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")},"generation"=>Identity with{Generation=8},"session-stamp"=>Identity with{SessionStamp=Guid.Parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")},"account-stamp"=>Identity with{AccountStamp=Guid.Parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")},"current"=>Identity,_=>Identity with{SessionStamp=Guid.Empty}};
        Inputs=new(Identity,current,Lifetime,Entitlements,Enum.Parse<AccountEligibility>(Case.AccountState),Case.RequiredCapability,Now,Now+Duration.FromSeconds(2));
        Database=new(this);Admission=warm?SessionCacheAdmission.ForQualification(Space,Store):new();
        if(warm)
        {
            Store.Index=Encoding.UTF8.GetBytes(Identity.AccountId.ToString("N"));
            short status=Case.AccountState switch{"Unverified"=>0,"Disabled"=>2,"Deleted"=>3,"Unknown"=>7,_=>1};
            using var record=new CachedAccountAuthority(new(Space.Environment,Space.Epoch,Space.Policy,new('A',64),7,CachedAuthorityState.Ready,Identity.AccountId),Case.BadBinding?new('B',64):Hash,Now,Now+Duration.FromSeconds(20),Identity,Lifetime,new(true,status,At(Case.UnlockTicks??(Case.AccountState=="Locked"?1:null)),Identity.AccountStamp,Case.Authority=="current"),Entitlements,Case.ShortKey?new byte[8]:TreehammockParityFixtures.Key());
            // Invalid authoritative rows cannot be published by the shared encoder.
            // Their warm path starts from unusable cache and exercises the same fallback.
            Store.Payload=!Identity.IsWellFormed||Case.ShortKey||Case.EntitlementVersion==0?Encoding.UTF8.GetBytes("{}"):CoherentCacheCodec.Encode(record);
        }
    }
    internal SessionEvidenceCoordinator Coordinator()=>new(new(Store,Admission,TimeSpan.FromMilliseconds(100),TimeSpan.FromSeconds(30)),new YsqlSessionAuthority(Database,TimeSpan.FromSeconds(1),new ParityClock(Now)),TreehammockParityFixtures.Corpus.Issuer,TimeSpan.FromSeconds(2),Refill,clock:new ParityClock(Now));
    internal Task<SessionEvidenceDecision> Validate(CancellationToken token)=>Coordinator().ValidateAsync(Credential,Case.RequiredCapability,Now+Duration.FromSeconds(2),token);
    internal CurrentSessionRow? Row()
    {
        if(Case.Authority!="current")return null;
        string? Format(Instant? i)=>i is {} x?InstantPattern.ExtendedIso.Format(x):null;
        var e=Entitlements;string json=JsonSerializer.Serialize(new{accountId=e.AccountId,version=e.Version,features=e.FeatureTier,capabilities=Case.Capabilities,rightsEnabled=false,evaluatedAt=Format(e.EvaluatedAt),nextBoundary=Format(e.NextBoundary),eligibilityUntil=Format(e.EligibilityUntil),grants=Array.Empty<object>()});
        short status=Case.AccountState switch{"Unverified"=>0,"Disabled"=>2,"Deleted"=>3,"Unknown"=>7,_=>1};
        return new(Case.BadBinding?new('B',64):Hash,Identity,Identity.AccountStamp,Case.ShortKey?new byte[8]:TreehammockParityFixtures.Key(),Lifetime,status,Case.UnlockTicks is {} t?Now+Duration.FromTicks(t):Case.AccountState=="Locked"?Now+Duration.FromSeconds(1):null,Now+Duration.FromTicks(Case.EvaluatedTicks),json);
    }
    public void Dispose(){Admission.Quarantine();Store.Dispose();}
    internal sealed class Executor(ParityHarness owner):IYsqlSnapshotExecutor
    {
        internal int Calls;
        public Task<CurrentSessionRow?> ReadAsync(string hash,TimeSpan budget,CancellationToken token){Calls++;return Task.FromResult(owner.Row());}
    }
    internal sealed class Cache:ICoherentCacheGetStore,IDisposable
    {
        internal byte[]? Index,Payload;internal int Gets;
        public Task<byte[]?> GetAsync(string key,CancellationToken token){Gets++;return Task.FromResult((key.Contains(":credential:",StringComparison.Ordinal)?Index:Payload)?.ToArray());}
        public void Dispose(){if(Index is not null)CryptographicOperations.ZeroMemory(Index);if(Payload is not null)CryptographicOperations.ZeroMemory(Payload);}
    }
    internal sealed class Hints:IGuardedSessionRefillQueue{internal int Calls;public bool TryRequest(string hash,Guid epoch){Calls++;return true;}}
}
