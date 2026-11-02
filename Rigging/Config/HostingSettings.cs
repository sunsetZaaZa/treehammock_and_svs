using System.ComponentModel.DataAnnotations;
using System.Net;
using Microsoft.AspNetCore.Server.Kestrel.Core;

namespace treehammock.Rigging.Config;

public sealed class HostingSettings : IValidatableObject
{
    public bool ConfigureKestrel { get; set; } = true;

    [Range(1, 65535)]
    public int Port { get; set; } = 5001;

    public string BindAddress { get; set; } = "0.0.0.0";

    public bool UseHttps { get; set; } = true;

    public string Protocols { get; set; } = nameof(HttpProtocols.Http1AndHttp2AndHttp3);

    public bool UseHttpsRedirection { get; set; } = true;

    public bool UseForwardedHeaders { get; set; }

    [Range(1, 32)]
    public int ForwardLimit { get; set; } = 1;

    public bool RequireHeaderSymmetry { get; set; } = true;

    public bool TrustAllForwardedHeaderProxies { get; set; }

    public string[] KnownProxies { get; set; } = Array.Empty<string>();

    public string[] KnownNetworks { get; set; } = Array.Empty<string>();

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (!string.Equals(BindAddress, "AnyIP", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(BindAddress, "*", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(BindAddress, "0.0.0.0", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(BindAddress, "::", StringComparison.OrdinalIgnoreCase) &&
            !IPAddress.TryParse(BindAddress, out _))
        {
            yield return new ValidationResult(
                "HostingSettings BindAddress must be AnyIP, *, 0.0.0.0, ::, or a valid IP address.",
                new[] { nameof(BindAddress) });
        }

        if (!TryGetProtocols(out _))
        {
            yield return new ValidationResult(
                "HostingSettings Protocols must be a nonzero combination of Http1, Http2 and Http3.",
                new[] { nameof(Protocols) });
        }

        foreach (string proxy in (KnownProxies ?? Array.Empty<string>()).Where(proxy => !string.IsNullOrWhiteSpace(proxy)))
        {
            if (!IPAddress.TryParse(proxy, out _))
            {
                yield return new ValidationResult(
                    $"HostingSettings KnownProxies contains an invalid IP address: {proxy}.",
                    new[] { nameof(KnownProxies) });
            }
        }

        foreach (string network in (KnownNetworks ?? Array.Empty<string>()).Where(network => !string.IsNullOrWhiteSpace(network)))
        {
            if (!IsValidCidr(network))
            {
                yield return new ValidationResult(
                    $"HostingSettings KnownNetworks contains an invalid CIDR network: {network}.",
                    new[] { nameof(KnownNetworks) });
            }
        }
    }

    public HttpProtocols GetProtocols()
    {
        if (!TryGetProtocols(out HttpProtocols protocols))
            throw new InvalidOperationException("HostingSettings Protocols must be a nonzero combination of Http1, Http2 and Http3.");
        return protocols;
    }

    private bool TryGetProtocols(out HttpProtocols protocols)
    {
        const HttpProtocols supported = HttpProtocols.Http1 | HttpProtocols.Http2 | HttpProtocols.Http3;
        return Enum.TryParse(Protocols, ignoreCase: true, out protocols)
            && protocols != HttpProtocols.None && (protocols & ~supported) == 0;
    }

    private static bool IsValidCidr(string value)
    {
        string[] parts = value.Split('/', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out IPAddress? address))
        {
            return false;
        }

        if (!int.TryParse(parts[1], out int prefixLength))
        {
            return false;
        }

        int maxPrefixLength = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
        return prefixLength >= 0 && prefixLength <= maxPrefixLength;
    }
}
