using System.Net;
using System.Security.Cryptography;
using System.Text;

using treehammock.Rigging.Abuse;

namespace treehammock.Services;

public interface ILoginAbuseCounterKeyFactory
{
    AbuseCounterKey ForAccount(Guid accountId);

    AbuseCounterKey ForIdentifier(string kind, string identifier);

    AbuseCounterKey ForIpAddress(string? ipAddress);
}

public sealed class LoginAbuseCounterKeyFactory : ILoginAbuseCounterKeyFactory
{
    public AbuseCounterKey ForAccount(Guid accountId)
    {
        if (accountId == Guid.Empty)
        {
            throw new ArgumentException("A non-empty account id is required for login abuse throttling.", nameof(accountId));
        }

        return new AbuseCounterKey(AbuseFeature.Login, AbuseCounterDimension.Account, accountId.ToString("N"));
    }

    public AbuseCounterKey ForIdentifier(string kind, string identifier)
    {
        if (string.IsNullOrWhiteSpace(kind))
        {
            throw new ArgumentException("A non-empty identifier kind is required for login abuse throttling.", nameof(kind));
        }

        if (string.IsNullOrWhiteSpace(identifier))
        {
            throw new ArgumentException("A non-empty identifier is required for login abuse throttling.", nameof(identifier));
        }

        string normalizedKind = NormalizeSegment(kind);
        string normalizedIdentifier = NormalizeIdentifier(normalizedKind, identifier);
        return new AbuseCounterKey(
            AbuseFeature.Login,
            AbuseCounterDimension.IdentifierFingerprint,
            $"{normalizedKind}-{Fingerprint($"login:identifier:{normalizedKind}:{normalizedIdentifier}")}");
    }

    public AbuseCounterKey ForIpAddress(string? ipAddress)
    {
        string normalizedIp = NormalizeIpAddress(ipAddress);
        return new AbuseCounterKey(
            AbuseFeature.Login,
            AbuseCounterDimension.IpFingerprint,
            Fingerprint($"login:ip:{normalizedIp}"));
    }

    private static string NormalizeIdentifier(string kind, string identifier)
    {
        string trimmed = identifier.Trim();
        return string.Equals(kind, "email", StringComparison.Ordinal)
            ? trimmed.ToLowerInvariant()
            : trimmed.ToLowerInvariant();
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

    private static string NormalizeSegment(string value)
    {
        string normalized = value.Trim().ToLowerInvariant();
        if (normalized.Contains(':') || normalized.Contains('/') || normalized.Any(char.IsWhiteSpace))
        {
            throw new ArgumentException("Login abuse counter key segments cannot contain separators or whitespace.", nameof(value));
        }

        return normalized;
    }

    private static string Fingerprint(string material)
    {
        byte[] digest = SHA256.HashData(Encoding.UTF8.GetBytes(material));
        return Convert.ToHexString(digest, 0, 16).ToLowerInvariant();
    }
}
