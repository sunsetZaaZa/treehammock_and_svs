using Microsoft.Extensions.Configuration;
using NSubstitute;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.ActionConstraints;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using treehammock.Controllers;

namespace treehammock.Tests.Unit;

public sealed class Cor23ReconciliationContractTests
{
    [Fact]
    public void Native_MVC_discovery_matches_the_current_literal_source_endpoint_index()
    {
        // Full literal catalog includes explicit Testing-only controllers; deployable hosts are tested separately.
        // Discovery only: no host, network or database.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddControllers().ConfigureApplicationPartManager(manager =>
        {
            manager.ApplicationParts.Clear();
            manager.ApplicationParts.Add(new AssemblyPart(typeof(AccountLoginController).Assembly));
            var environment = NSubstitute.Substitute.For<Microsoft.Extensions.Hosting.IHostEnvironment>();
            environment.EnvironmentName.Returns("Testing");
            var configuration = new Microsoft.Extensions.Configuration.ConfigurationBuilder().AddInMemoryCollection(
                new Dictionary<string, string?> { ["SystemTestSettings:Enabled"] = "true", ["SystemTestSettings:EnableTestInspectionEndpoints"] = "true",
                    ["SystemTestSettings:TestKey"] = "treehammock-system-test-key" }).Build();
            manager.FeatureProviders.Add(new treehammock.Rigging.Hosting.SystemTestControllerFeatureProvider(
                treehammock.Rigging.Hosting.SystemTestCapability.FromConfiguration(configuration, environment)));
        });
        using var provider = services.BuildServiceProvider();
        var descriptors = provider.GetRequiredService<IActionDescriptorCollectionProvider>()
            .ActionDescriptors.Items.OfType<ControllerActionDescriptor>().ToArray();
        Assert.NotEmpty(descriptors);
        var actual = descriptors.SelectMany(action =>
        {
            Assert.NotNull(action.AttributeRouteInfo);
            var methods = action.ActionConstraints?.OfType<HttpMethodActionConstraint>()
                .SelectMany(constraint => constraint.HttpMethods).Distinct().ToArray();
            Assert.NotNull(methods);
            Assert.NotEmpty(methods!);
            return methods!.Select(method => string.Join("|", method.ToUpperInvariant(),
                "/" + action.AttributeRouteInfo!.Template!.Trim('/'), action.ControllerTypeInfo.Name,
                action.MethodInfo.Name));
        }).OrderBy(x => x, StringComparer.Ordinal).ToArray();
        using var source = JsonDocument.Parse(File.ReadAllText(Path.Combine(ProjectRoot(),
            "docs", "corrections", "APPLICATION_SURFACE_INDEX.json")));
        var expected = source.RootElement.GetProperty("endpoints").EnumerateArray()
            .Where(endpoint => endpoint.GetProperty("controller").ValueKind != JsonValueKind.Null)
            .Select(endpoint => string.Join("|", endpoint.GetProperty("method").GetString(),
                endpoint.GetProperty("route").GetString(), endpoint.GetProperty("controller").GetString(),
                endpoint.GetProperty("action").GetString()))
            .OrderBy(x => x, StringComparer.Ordinal).ToArray();
        Assert.Equal(expected.Length, expected.Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(expected, actual);
    }

    private static string ProjectRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "treehammock.sln")))
            directory = directory.Parent;
        return directory?.FullName ?? throw new InvalidOperationException("Cannot locate current project root.");
    }
}
