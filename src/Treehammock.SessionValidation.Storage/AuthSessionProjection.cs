using System.Security.Cryptography;
using System.Text;
using NodaTime;
using Treehammock.SessionValidation.Core;
namespace Treehammock.SessionValidation.Storage;

// Ephemeral server evidence, not a cache-admission proof or a transport contract.
public sealed class AuthSessionProjection : IDisposable
{
    private byte[]? _key;
    private readonly string _binding;
    internal AuthSessionProjection(string binding, byte[] key, SessionIdentity identity, SessionLifetime lifetime,
        EntitlementPolicyInputs entitlements, Instant readAt)
    { _binding = binding; _key = (byte[])key.Clone(); Identity = identity; Lifetime = lifetime; Entitlements = entitlements; ReadAt = readAt; }
    public SessionIdentity Identity { get; }
    public SessionLifetime Lifetime { get; }
    public EntitlementPolicyInputs Entitlements { get; }
    public Instant ReadAt { get; }

    // Credential binding and post-await time checks cannot be omitted by a consumer of this evidence.
    public async Task<SessionDecision> EvaluateAccessAsync(ITreehammockSessionPolicyEvaluator evaluator,
        string credential,string issuer,string requiredCapability,Instant deadline,IClock clock,CancellationToken cancellationToken=default)
        => (await EvaluateCoreAsync(evaluator,credential,issuer,requiredCapability,deadline,clock,cancellationToken,false)).Decision;
    internal Task<VerifiedSessionAccess> EvaluateApplicationAsync(ITreehammockSessionPolicyEvaluator evaluator,
        string credential,string issuer,string requiredCapability,Instant deadline,IClock clock,CancellationToken cancellationToken)
        => EvaluateCoreAsync(evaluator,credential,issuer,requiredCapability,deadline,clock,cancellationToken,true);
    private async Task<VerifiedSessionAccess> EvaluateCoreAsync(ITreehammockSessionPolicyEvaluator evaluator,
        string credential, string issuer, string requiredCapability, Instant deadline, IClock clock,
        CancellationToken cancellationToken, bool application)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var key = _key;
        if (key is null || string.IsNullOrWhiteSpace(credential)) return new(SessionDecision.Unavailable);
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(credential)));
        if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(hash), Encoding.ASCII.GetBytes(_binding)))
            return new(SessionDecision.Unauthenticated);
        var now = clock.GetCurrentInstant();
        if (now < ReadAt) return new(SessionDecision.Unavailable);
        var inputs = new SessionValidationInputs(Identity, Identity, Lifetime, Entitlements,
            AccountEligibility.Eligible, requiredCapability, now, deadline);
        VerifiedSessionAccess decision;
        if(application)
        {
            if(evaluator is not IVerifiedSessionPolicyEvaluator verified)return new(SessionDecision.Unavailable);
            decision=await verified.EvaluateVerifiedAccessAsync(inputs,credential,key,issuer);
        }
        else decision=new(await evaluator.EvaluateAccessAsync(inputs,credential,key,issuer));
        cancellationToken.ThrowIfCancellationRequested();
        var after = clock.GetCurrentInstant();
        if (after < now || after >= deadline || _key is null) return new(SessionDecision.Unavailable);
        var state = evaluator.EvaluateState(inputs with { Now = after });
        if (state.Outcome == PolicyOutcome.Unauthenticated) return new(SessionDecision.Unauthenticated);
        if (state.Outcome is not (PolicyOutcome.Eligible or PolicyOutcome.Forbidden)) return new(SessionDecision.Unavailable);
        return application&&decision.Decision==SessionDecision.Active&&string.IsNullOrWhiteSpace(decision.WebKey)
            ? new(SessionDecision.Unavailable) : decision;
    }
    // Caller owns disposal and must not race it with verification.
    public void Dispose() { var key = Interlocked.Exchange(ref _key, null); if (key is not null) CryptographicOperations.ZeroMemory(key); }
    public override string ToString() => nameof(AuthSessionProjection);
}
