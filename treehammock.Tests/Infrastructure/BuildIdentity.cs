using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json;
using Xunit;

namespace Treehammock.Testing;

// Linked by all three test projects. An owned proof checks the actual loaded
// binaries before test code executes, independently of a source/sidecar receipt.
internal static class BuildIdentity
{
    [ModuleInitializer]
    internal static void ValidateLoadedAssemblies()
    {
        string? runId = Environment.GetEnvironmentVariable("TREEHAMMOCK_BUILD_RUN_ID");
        if (string.IsNullOrEmpty(runId)) return; // Raw IDE runs do not claim owned proof identity.
        string? configuration = Environment.GetEnvironmentVariable("TREEHAMMOCK_BUILD_CONFIGURATION");
        if (!Guid.TryParseExact(runId, "D", out _) || configuration is not ("Debug" or "Release" or "Sandbox"))
            throw new InvalidOperationException("Invalid build proof identity/configuration.");
        Assembly tests = typeof(BuildIdentity).Assembly;
        Assembly application = Assembly.Load("treehammock");
        foreach (Assembly assembly in new[] { tests, application })
        {
            string? builtId = assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
                .SingleOrDefault(a => a.Key == "TreehammockProofRunId")?.Value;
            string? builtConfiguration = assembly.GetCustomAttribute<AssemblyConfigurationAttribute>()?.Configuration;
            var folder = new DirectoryInfo(Path.GetDirectoryName(assembly.Location)!);
            if (builtId != runId || builtConfiguration != configuration ||
                folder.Name != "net8.0" || folder.Parent?.Name != configuration || folder.Parent.Parent?.Name != "bin")
                throw new InvalidOperationException("Loaded assembly is not from the requested current build.");
        }
        if (Path.GetDirectoryName(tests.Location) != Path.GetDirectoryName(application.Location))
            throw new InvalidOperationException("Application reference is loaded from a different output directory.");
        var evidence = new
        {
            run_id = runId, configuration,
            assemblies = new[] { tests, application }.Select(a => new
            {
                name = a.GetName().Name, path = a.Location,
                mvid = a.ManifestModule.ModuleVersionId,
                sha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(a.Location))).ToLowerInvariant()
            }).ToArray()
        };
        File.WriteAllText(Path.Combine(AppContext.BaseDirectory, tests.GetName().Name + ".identity.json"),
            JsonSerializer.Serialize(evidence, new JsonSerializerOptions { WriteIndented = true }));
    }
}

// Allows the native qualification matrix to observe the System assembly without
// contacting a deployed endpoint. It qualifies loaded binaries, not HTTP flows.
public sealed class BuildIdentityProbe
{
    [Fact]
    public void Loaded_test_and_application_share_the_requested_configuration()
    {
        Assembly tests = typeof(BuildIdentityProbe).Assembly;
        Assembly application = Assembly.Load("treehammock");
        string configuration = tests.GetCustomAttribute<AssemblyConfigurationAttribute>()!.Configuration;
        Xunit.Assert.Contains(configuration, new[] { "Debug", "Release", "Sandbox" });
        Xunit.Assert.Equal(configuration, application.GetCustomAttribute<AssemblyConfigurationAttribute>()!.Configuration);
        Xunit.Assert.Equal(Path.GetDirectoryName(tests.Location), Path.GetDirectoryName(application.Location));
    }
}
