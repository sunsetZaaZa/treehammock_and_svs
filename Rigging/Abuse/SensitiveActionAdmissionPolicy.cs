using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using treehammock.Rigging.Config;
namespace treehammock.Rigging.Abuse;

public interface ISensitiveActionAdmissionPolicy
{
    Task<string?> CheckAsync(Guid account, string session, string? ip, CancellationToken cancellationToken = default);
}
public sealed class SensitiveActionAdmissionPolicy(IAbuseCounterStore store,IOptions<SensitiveActionSettings> settings,IOptions<LoginSettings> login) : ISensitiveActionAdmissionPolicy
{
    public async Task<string?> CheckAsync(Guid account,string session,string? ip,CancellationToken cancellationToken=default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if(login.Value.TwoFactorChallengePepper.Length<16)return AbuseReasonCodes.CounterStoreUnavailable;
        var s=settings.Value;
        foreach(var item in new[] {(AbuseCounterDimension.Account,account.ToString("N"),s.MaxRequestsPerAccount),
            (AbuseCounterDimension.Session,session,s.MaxRequestsPerSession),(AbuseCounterDimension.IpFingerprint,ip??"unknown",s.MaxRequestsPerIp)})
        {
            byte[] secret=Encoding.UTF8.GetBytes(login.Value.TwoFactorChallengePepper);string digest;
            try{digest=Convert.ToHexString(HMACSHA256.HashData(secret,Encoding.UTF8.GetBytes("treehammock:reauth:v1:"+(int)item.Item1+":"+item.Item2)));}
            finally{CryptographicOperations.ZeroMemory(secret);}
            var decision=await store.IncrementAsync(new(AbuseFeature.Reauthentication,item.Item1,digest),new(item.Item3,TimeSpan.FromSeconds(s.AttemptWindowSeconds)),cancellationToken);
            if(decision.ReasonCode is AbuseReasonCodes.CounterStoreUnavailable or AbuseReasonCodes.CounterStoreTimeout)return decision.ReasonCode;
            if(!decision.CanAdmit)return "SENSITIVE_ACTION_RATE_LIMITED";
        }
        return null;
    }
}
