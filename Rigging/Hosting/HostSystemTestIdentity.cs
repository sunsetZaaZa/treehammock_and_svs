using System.Reflection;
using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace treehammock.Rigging.Hosting;

// Snapshot the loaded application at startup. No identity I/O/surface on deployable hosts.
public sealed class HostSystemTestIdentity
{
    public HostSystemTestIdentityResponse? Value { get; }
    private HostSystemTestIdentity(HostSystemTestIdentityResponse? value) => Value = value;
    public static HostSystemTestIdentity FromConfiguration(IConfiguration configuration, SystemTestCapability capability)
    {
        var section = configuration.GetSection("HostSystemTestProof");
        if (!section.GetChildren().Any()) return new(null);
        void Reject() => throw new OptionsValidationException("HostSystemTestProof", typeof(HostSystemTestIdentity),
            ["Host identity requires the owned Testing inspection capability and current Release assembly."]);
        var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "RunId", "BuildRunId", "AssemblySha256", "Challenge" };
        if (!capability.InspectionEnabled || section.GetChildren().Any(child => !known.Contains(child.Key))) Reject();
        string? runId = section["RunId"], buildId = section["BuildRunId"], hash = section["AssemblySha256"], challenge = section["Challenge"];
        bool Canonical(string? value) => Guid.TryParseExact(value, "D", out var parsed) && parsed.ToString("D") == value;
        bool Hex(string? value) => value?.Length == 64 && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
        if (!Canonical(runId) || !Canonical(buildId) || !Hex(hash) || !Hex(challenge)) Reject();
        Assembly application = typeof(HostSystemTestIdentity).Assembly;
        string? builtId = application.GetCustomAttributes<AssemblyMetadataAttribute>().SingleOrDefault(a => a.Key == "TreehammockProofRunId")?.Value;
        string? configurationName = application.GetCustomAttribute<AssemblyConfigurationAttribute>()?.Configuration;
        string actualHash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(application.Location))).ToLowerInvariant();
        if (builtId != buildId || configurationName != "Release" || actualHash != hash) Reject();
        return new(new(runId!, buildId!, configurationName!, actualHash,
            application.ManifestModule.ModuleVersionId.ToString("D"), Environment.ProcessId, challenge!));
    }
}
public sealed record HostSystemTestIdentityResponse(string run_id, string build_run_id, string configuration,
    string assembly_sha256, string mvid, int process_id, string challenge);
