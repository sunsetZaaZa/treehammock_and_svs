using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using treehammock.Rigging.Config;

namespace treehammock.Rigging.Hosting;

// One immutable startup decision owns provider selection, route discovery and request access.
// Testing is an explicitly disposable harness profile; Container is a deployable profile.
public sealed class SystemTestCapability
{
    public const string EnvironmentName = "Testing";
    public const string TestKeyHeaderName = "X-System-Test-Key";
    public bool CaptureEnabled { get; }
    public bool InspectionEnabled { get; }
    private readonly byte[]? _keyHash;

    private SystemTestCapability(bool capture, bool inspection, string key)
    {
        CaptureEnabled = capture;
        InspectionEnabled = inspection;
        _keyHash = inspection ? SHA256.HashData(Encoding.UTF8.GetBytes(key)) : null;
    }

    public static SystemTestCapability FromConfiguration(IConfiguration configuration, IHostEnvironment? environment)
    {
        var section = configuration.GetSection("SystemTestSettings");
        var settings = section.Get<SystemTestSettings>() ?? new SystemTestSettings();
        void Reject(string reason) => throw new OptionsValidationException("SystemTestSettings",
            typeof(SystemTestSettings), [reason]); // Never include configured keys/connection strings.
        var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { nameof(SystemTestSettings.Enabled), nameof(SystemTestSettings.EnableTestInspectionEndpoints), nameof(SystemTestSettings.TestKey) };
        if (section.GetChildren().Any(child => !known.Contains(child.Key)))
            Reject("SystemTestSettings contains an unsupported setting.");
        if (settings.Enabled && !string.Equals(environment?.EnvironmentName, EnvironmentName, StringComparison.Ordinal))
            Reject("Test capabilities require the dedicated Testing environment.");
        if (!settings.Enabled && (settings.EnableTestInspectionEndpoints || !string.IsNullOrEmpty(settings.TestKey)))
            Reject("Disabled test capabilities require inspection disabled and an empty TestKey.");
        if (settings.Enabled && string.Equals(configuration["DatabaseSettings:profile"], "Production", StringComparison.OrdinalIgnoreCase))
            Reject("Test capabilities cannot use the Production database profile.");
        if (settings.EnableTestInspectionEndpoints)
        {
            if (settings.TestKey is null || settings.TestKey.Length < 24 || settings.TestKey.Length > 128 ||
                settings.TestKey.Any(c => c < '!' || c > '~'))
                Reject("Test inspection requires a 24 to 128 character printable ASCII key without whitespace.");
        }
        else if (!string.IsNullOrEmpty(settings.TestKey))
            Reject("A TestKey requires enabled inspection endpoints.");
        return new(settings.Enabled, settings.EnableTestInspectionEndpoints, settings.TestKey ?? string.Empty);
    }

    public void RequireCapture()
    {
        if (!CaptureEnabled) throw new InvalidOperationException("Test capture is unavailable in this host composition.");
    }

    public bool Authorizes(HttpRequest request)
    {
        if (!InspectionEnabled) return false;
        var supplied = request.Headers[TestKeyHeaderName];
        if (supplied.Count != 1 || supplied[0] is not string key || key.Length > 128) return false;
        return CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(key)), _keyHash!);
    }
}
