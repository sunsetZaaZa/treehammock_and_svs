using NodaTime;
using treehammock.DataLayer.Cache;
using treehammock.RiggingSupport.Enum;
namespace treehammock.Tests.Support;

// A service-unit fixture only. PostgreSQL policy and authority are qualified by the native suites.
internal sealed class Cor13ResetSessionStore
{
    private readonly Dictionary<string,PasswordResetSession> rows = new();
    private readonly HashSet<string> revoked = new();
    internal PasswordResetSession? Read(string hash) => rows.TryGetValue(hash,out var s) ? Copy(s) : null;
    // Explicit fixture authority setup; changing a Read() result must never change a stored row.
    internal void ShortenSessionDeadline(string hash, Instant deadline)
    {
        PasswordResetSession row = rows[hash];
        if (deadline <= row.createdOn || deadline >= row.expiresAt
            || row.challengeExpiration is Instant challenge && challenge > deadline)
            throw new ArgumentOutOfRangeException(nameof(deadline));
        row.expiresAt = deadline;
    }
    internal void ShortenChallengeDeadline(string hash, Instant deadline)
    {
        PasswordResetSession row = rows[hash];
        if (row.challengeExpiration is not Instant current || deadline <= row.createdOn
            || deadline >= current || deadline >= row.expiresAt)
            throw new ArgumentOutOfRangeException(nameof(deadline));
        row.challengeExpiration = deadline;
    }
    internal bool Apply(PasswordResetSession s)
    {
        if(revoked.Contains(s.resetAccessTokenHash))return false;
        rows.TryGetValue(s.resetAccessTokenHash,out var old);
        if(s.transition==PasswordResetTransition.Create)
        {if(old is not null || s.sessionVersion!=0)return false;}
        else if(old is null || old.sessionVersion!=s.sessionVersion || old.challengeVersion!=s.challengeVersion)return false;
        s.sessionVersion++;
        if(s.transition is PasswordResetTransition.Select or PasswordResetTransition.Resend or PasswordResetTransition.ValidProof)s.challengeVersion++;
        rows[s.resetAccessTokenHash]=Copy(s);return true;
    }
    internal void Revoke(string hash){rows.Remove(hash);revoked.Add(hash);}
    internal static PasswordResetSession Copy(PasswordResetSession s) => new(s.accountId,s.resetAccessTokenHash,s.bootstrapProof,
        s.availableConfigurationsSnapshot,s.createdOn,s.expiresAt,s.state,s.passwordResetRequestId)
    {
        state=s.state,selectedConfiguration=s.selectedConfiguration,requiredMethods=s.requiredMethods.ToList(),completedMethods=s.completedMethods.ToList(),
        currentExpectedMethod=s.currentExpectedMethod,challengeCodeHash=s.challengeCodeHash,challengeExpiration=s.challengeExpiration,
        challengeAttempts=s.challengeAttempts,challengeResends=s.challengeResends,nextChallengeAllowedAt=s.nextChallengeAllowedAt,
        selectedAt=s.selectedAt,twoFactorCompletedAt=s.twoFactorCompletedAt,passwordChangedAt=s.passwordChangedAt,
        sessionVersion=s.sessionVersion,challengeVersion=s.challengeVersion,factorPolicyVersion=s.factorPolicyVersion,
        accountSecurityStamp=s.accountSecurityStamp,bootstrapCodeHash=s.bootstrapCodeHash,transition=s.transition
    };
}
