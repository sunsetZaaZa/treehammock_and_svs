using System.Net;
using System.Security.Cryptography;
using System.Text;

using treehammock.Rigging.Abuse;

namespace treehammock.Services;

public interface IActivationAbuseCounterKeyFactory
{
    AbuseCounterKey ForVerifyAccount(Guid accountId);

    AbuseCounterKey ForVerifyIdentifier(string emailAddress);

    AbuseCounterKey ForVerifyIpAddress(string? ipAddress);
}

public sealed class ActivationAbuseCounterKeyFactory : IActivationAbuseCounterKeyFactory
{
    public AbuseCounterKey ForVerifyAccount(Guid accountId)
    {
        if (accountId == Guid.Empty)
        {
            throw new ArgumentException("A non-empty account id is required for activation verification abuse throttling.", nameof(accountId));
        }

        return new AbuseCounterKey(AbuseFeature.Activation, AbuseCounterDimension.Account, accountId.ToString("N"));
    }

    public AbuseCounterKey ForVerifyIdentifier(string emailAddress)
    {
        if (string.IsNullOrWhiteSpace(emailAddress))
        {
            throw new ArgumentException("A non-empty activation email address is required for activation verification abuse throttling.", nameof(emailAddress));
        }

        string normalized = emailAddress.Trim().ToLowerInvariant();
        return new AbuseCounterKey(
            AbuseFeature.Activation,
            AbuseCounterDimension.IdentifierFingerprint,
            $"email-{Fingerprint($"activation:verify:email:{normalized}")}");
    }

    public AbuseCounterKey ForVerifyIpAddress(string? ipAddress)
    {
        string normalizedIp = NormalizeIpAddress(ipAddress);
        return new AbuseCounterKey(
            AbuseFeature.Activation,
            AbuseCounterDimension.IpFingerprint,
            Fingerprint($"activation:verify:ip:{normalizedIp}"));
    }

    public static string CreationIpFingerprint(string? ipAddress) => Fingerprint($"activation:create:ip:{NormalizeIpAddress(ipAddress)}");

    private static string NormalizeIpAddress(string? ipAddress)
    {
        if (string.IsNullOrWhiteSpace(ipAddress))
        {
            return "unknown";
        }

        string trimmed = ipAddress.Trim();
        return IPAddress.TryParse(trimmed, out IPAddress? parsed)
            ? (parsed.IsIPv4MappedToIPv6 ? parsed.MapToIPv4() : parsed).ToString()
            : trimmed.ToLowerInvariant();
    }

    private static string Fingerprint(string material)
    {
        byte[] digest = SHA256.HashData(Encoding.UTF8.GetBytes(material));
        return Convert.ToHexString(digest, 0, 16).ToLowerInvariant();
    }
}
