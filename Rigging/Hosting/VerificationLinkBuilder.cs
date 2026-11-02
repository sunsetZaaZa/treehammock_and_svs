using System.Net;
using System.Text.RegularExpressions;

namespace treehammock.Rigging.Hosting;

// One immutable, configuration-owned public authority for all account proofs.
// No HttpContext, Host, forwarded headers or caller-selected route is accepted.
public sealed class VerificationLinkBuilder
{
    private readonly Uri _origin;
    public string PublicOrigin => _origin.GetLeftPart(UriPartial.Authority);
    public VerificationLinkBuilder(string? publicOrigin)
    {
        if (!TryOrigin(publicOrigin, out var origin))
            throw new ArgumentException("RegistrationSettings PublicOrigin must be an absolute HTTP(S) origin without credentials, path, query or fragment.", nameof(publicOrigin));
        _origin = origin!;
    }
    public string Registration(string payload) => Build("/account/verifyaccount", payload);
    public string EmailChange(string payload) => Build("/account/adjust/email/verify", payload);
    public string Delete(string payload) => Build("/account/wipeout/verify", payload);
    private string Build(string route, string payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        return new Uri(_origin, route + "?payload=" + Uri.EscapeDataString(payload)).AbsoluteUri;
    }
    public static bool TryOrigin(string? value, out Uri? origin)
    {
        origin = null;
        if (string.IsNullOrWhiteSpace(value) || value.Length > 2048 || !Regex.IsMatch(value, @"\Ahttps?://[^/?#\\]+/?\z", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant) || value.Any(char.IsWhiteSpace) || value.Any(char.IsControl) || value.Contains('\\') ||
            !Uri.TryCreate(value, UriKind.Absolute, out var parsed) || parsed.Scheme is not ("http" or "https") ||
            string.IsNullOrEmpty(parsed.Host) || Uri.CheckHostName(parsed.IdnHost) == UriHostNameType.Unknown || parsed.Port < 1 ||
            parsed.UserInfo.Length != 0 || parsed.Query.Length != 0 || parsed.Fragment.Length != 0 || parsed.AbsolutePath != "/") return false;
        if (IPAddress.TryParse(parsed.Host.Trim('[', ']'), out var address) && (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))) return false;
        origin = new Uri(parsed.GetLeftPart(UriPartial.Authority) + "/", UriKind.Absolute);
        return true;
    }
    public static bool AllowedForEnvironment(string? value, string? environment)
    {
        if (!TryOrigin(value, out var origin)) return false;
        bool production = string.Equals(environment, "Production", StringComparison.OrdinalIgnoreCase);
        bool loopback = origin!.IsLoopback || origin.Host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase);
        if (production) return origin.Scheme == "https" && !loopback;
        if (origin.Scheme == "https" || environment is null) return true;
        return environment is "Development" or "Testing" or "Container" or "ContainerReverseProxy";
    }
}
