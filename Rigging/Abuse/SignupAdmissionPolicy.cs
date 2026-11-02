using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using treehammock.Rigging.Config;
using treehammock.RiggingSupport.Status;

namespace treehammock.Rigging.Abuse;

public interface ISignupAdmissionPolicy
{
    Task<HttpMessage?> CheckAsync(string email, string? username, string? ip, CancellationToken cancellationToken = default);
}
public sealed class SignupAdmissionPolicy(IAbuseCounterStore? store, IOptions<AbuseControlSettings> settings,
    IOptions<LoginSettings> login) : ISignupAdmissionPolicy
{
    public async Task<HttpMessage?> CheckAsync(string email, string? username, string? ip, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (store is null || login.Value.TwoFactorChallengePepper.Length < 16)
            return HttpMessage.ACCOUNT_CREATION_ADMISSION_UNAVAILABLE;
        var policy = settings.Value.Signup;
        var keys = new List<(AbuseCounterKey Key, int Maximum)>
        {
            (Key("ip", ip ?? "unknown", AbuseCounterDimension.IpFingerprint), policy.MaxAttemptsPerIp),
            (Key("email", email, AbuseCounterDimension.IdentifierFingerprint), policy.MaxAttemptsPerIdentifier)
        };
        if (!string.IsNullOrWhiteSpace(username)) keys.Add((Key("username", username, AbuseCounterDimension.IdentifierFingerprint), policy.MaxAttemptsPerIdentifier));
        foreach (var (key, maximum) in keys)
        {
            var decision = await store.IncrementAsync(key, new(maximum, TimeSpan.FromSeconds(policy.WindowSeconds)), cancellationToken);
            // Signup remains Redis-only in the version-1 capability catalog.
            if (decision.ReasonCode is AbuseReasonCodes.CounterStoreUnavailable or AbuseReasonCodes.CounterStoreTimeout)
                return HttpMessage.ACCOUNT_CREATION_ADMISSION_UNAVAILABLE;
            if (!decision.CanAdmit) return HttpMessage.ACCOUNT_CREATION_RATE_LIMITED;
        }
        return null;
    }
    private AbuseCounterKey Key(string kind, string value, AbuseCounterDimension dimension)
    {
        byte[] secret = Encoding.UTF8.GetBytes(login.Value.TwoFactorChallengePepper);
        try
        {
            string input = "treehammock:signup:v1:" + kind + ":" + value.Trim().ToLowerInvariant();
            string digest = Convert.ToHexString(HMACSHA256.HashData(secret, Encoding.UTF8.GetBytes(input)));
            return new(AbuseFeature.Signup, dimension, digest);
        }
        finally { CryptographicOperations.ZeroMemory(secret); }
    }
}
