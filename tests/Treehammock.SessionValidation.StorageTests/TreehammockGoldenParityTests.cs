using Svs12.Golden;
using Svs12.Harness;
using Treehammock.SessionValidation.Core;
using Xunit;
namespace Treehammock.SessionValidation.StorageTests;
public sealed class TreehammockGoldenParityTests
{
    public static IEnumerable<object[]> Cases()=>TreehammockParityFixtures.Cases();
    public static IEnumerable<object[]> Reads()=>Cases().SelectMany(x=>new[]{new object[]{x[0],false},new object[]{x[0],true}});
    [Theory][MemberData(nameof(Cases))]
    public async Task Current_JWT_and_policy_match_reviewed_golden_decisions(string id)
    {
        using var h=new ParityHarness(id,false);var key=TreehammockParityFixtures.Key();
        var token=await new TreehammockTokenVerifier().ValidateAsync(h.Credential,key,TreehammockParityFixtures.Corpus.Issuer,h.Now,h.Lifetime.AccessExpiration);
        Assert.Equal(h.Case.ExpectedToken,token.Status.ToString());
        var decision=await new TreehammockSessionPolicyEvaluator().EvaluateAccessAsync(h.Inputs,h.Credential,key,TreehammockParityFixtures.Corpus.Issuer);
        Assert.Equal(h.Case.ExpectedCore,decision.ToString());
        TreehammockParityFixtures.Report("policy-"+id,new{Id=id,Token=token.Status.ToString(),Decision=decision.ToString()});
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(key);
    }
    [Theory][MemberData(nameof(Reads))]
    public async Task Same_issued_credential_has_golden_cold_and_warm_outcomes(string id,bool warm)
    {
        using var h=new ParityHarness(id,warm);var decision=await h.Validate(TestContext.Current.CancellationToken);
        Assert.Equal(h.Case.ExpectedCoordinator,decision.Decision.ToString());
        if(decision.Decision==SessionDecision.Active){Assert.NotNull(decision.Subject);Assert.Equal(h.Identity.AccountId,decision.Subject.AccountId);Assert.Equal(h.Identity.Generation,decision.Subject.Generation);Assert.True(decision.ValidUntil>h.Now);}
        else Assert.Null(decision.Subject);
        Assert.InRange(h.Database.Calls,0,1);Assert.InRange(h.Refill.Calls,0,1);
        // A validated hit's Active/Forbidden/signature refusal is terminal. These
        // cases contain well formed, eligible and current cache evidence.
        if(warm&&(h.Case.Id is "issued-no-exp" or "forbidden-capability" or "empty-capabilities-eligible" or "bad-signature-not-forbidden" or "wrong-signing-key" or "preauth-twofactor" or "generation-max-exact"))
        {Assert.Equal(0,h.Database.Calls);Assert.Equal(0,h.Refill.Calls);Assert.Equal(2,h.Store.Gets);}
        if(!warm){Assert.Equal(id=="missing-action-policy"?0:1,h.Database.Calls);Assert.Equal(0,h.Store.Gets);Assert.Equal(0,h.Refill.Calls);}
        TreehammockParityFixtures.Report("coordinator-"+id+"-"+warm,new{Id=id,Warm=warm,Decision=decision.Decision.ToString(),Subject=decision.Subject is not null,Sql=h.Database.Calls,Get=h.Store.Gets,Hint=h.Refill.Calls});
    }
}
