using System.Net;
using System.Security.Cryptography;
using System.Text;

using treehammock.Rigging.Abuse;

namespace treehammock.Services;

public interface IAccountUnlockAbuseCounterKeyFactory
{
    AbuseCounterKey ForVerifyToken(string token);

    AbuseCounterKey ForVerifyIpAddress(string? ipAddress);
}

public sealed class AccountUnlockAbuseCounterKeyFactory : IAccountUnlockAbuseCounterKeyFactory
{
    public AbuseCounterKey ForVerifyToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            throw new ArgumentException("A non-empty unlock token is required for account-unlock abuse throttling.", nameof(token));
        }

        return new AbuseCounterKey(
            AbuseFeature.AccountUnlock,
            AbuseCounterDimension.TokenFingerprint,
            Fingerprint($"account-unlock:verify:token:{token.Trim()}"));
    }

    public AbuseCounterKey ForVerifyIpAddress(string? ipAddress)
    {
        string normalizedIp = NormalizeIpAddress(ipAddress);
        return new AbuseCounterKey(
            AbuseFeature.AccountUnlock,
            AbuseCounterDimension.IpFingerprint,
            Fingerprint($"account-unlock:verify:ip:{normalizedIp}"));
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
