using System.Net;
using System.Security.Cryptography;
using System.Text;

using treehammock.Rigging.Abuse;

namespace treehammock.Services;

public interface IAccountTokenVerificationAbuseCounterKeyFactory
{
    AbuseCounterKey ForPublicToken(string flow, string token);

    AbuseCounterKey ForPublicIpAddress(string flow, string? ipAddress);

    AbuseCounterKey ForAccountDeleteFinalizeAccount(Guid accountId);

    AbuseCounterKey ForAccountDeleteFinalizeToken(string deleteToken);
}

public sealed class AccountTokenVerificationAbuseCounterKeyFactory : IAccountTokenVerificationAbuseCounterKeyFactory
{
    public AbuseCounterKey ForPublicToken(string flow, string token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            throw new ArgumentException("A non-empty public verification token is required for abuse throttling.", nameof(token));
        }

        string normalizedFlow = NormalizeFlow(flow);
        return new AbuseCounterKey(
            AbuseFeature.PublicTokenVerification,
            AbuseCounterDimension.TokenFingerprint,
            $"{normalizedFlow}-{Fingerprint($"public-token:{normalizedFlow}:token:{token.Trim()}")}");
    }

    public AbuseCounterKey ForPublicIpAddress(string flow, string? ipAddress)
    {
        string normalizedFlow = NormalizeFlow(flow);
        string normalizedIp = NormalizeIpAddress(ipAddress);
        return new AbuseCounterKey(
            AbuseFeature.PublicTokenVerification,
            AbuseCounterDimension.IpFingerprint,
            $"{normalizedFlow}-{Fingerprint($"public-token:{normalizedFlow}:ip:{normalizedIp}")}");
    }

    public AbuseCounterKey ForAccountDeleteFinalizeAccount(Guid accountId)
    {
        if (accountId == Guid.Empty)
        {
            throw new ArgumentException("A non-empty account id is required for account-delete finalize abuse throttling.", nameof(accountId));
        }

        return new AbuseCounterKey(
            AbuseFeature.AccountDeleteFinalize,
            AbuseCounterDimension.Account,
            accountId.ToString("N"));
    }

    public AbuseCounterKey ForAccountDeleteFinalizeToken(string deleteToken)
    {
        if (string.IsNullOrWhiteSpace(deleteToken))
        {
            throw new ArgumentException("A non-empty delete token is required for account-delete finalize abuse throttling.", nameof(deleteToken));
        }

        return new AbuseCounterKey(
            AbuseFeature.AccountDeleteFinalize,
            AbuseCounterDimension.TokenFingerprint,
            Fingerprint($"account-delete:finalize:token:{deleteToken.Trim()}"));
    }

    private static string NormalizeFlow(string flow)
    {
        if (string.IsNullOrWhiteSpace(flow))
        {
            throw new ArgumentException("A non-empty public token verification flow is required.", nameof(flow));
        }

        string normalized = flow.Trim().ToLowerInvariant();
        if (normalized.Contains(':') || normalized.Contains('/') || normalized.Any(char.IsWhiteSpace))
        {
            throw new ArgumentException("Public token verification flow names cannot contain separators or whitespace.", nameof(flow));
        }

        return normalized;
    }

    private static string NormalizeIpAddress(string? ipAddress)
    {
        if (string.IsNullOrWhiteSpace(ipAddress))
        {
            return "unknown";
        }

        string trimmed = ipAddress.Trim();
        return IPAddress.TryParse(trimmed, out IPAddress? parsed)
            ? parsed.ToString()
            : trimmed.ToLowerInvariant();
    }

    private static string Fingerprint(string material)
    {
        byte[] digest = SHA256.HashData(Encoding.UTF8.GetBytes(material));
        return Convert.ToHexString(digest, 0, 16).ToLowerInvariant();
    }
}
