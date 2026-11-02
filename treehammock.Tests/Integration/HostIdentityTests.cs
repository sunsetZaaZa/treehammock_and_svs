using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using NSubstitute;
using treehammock.Controllers;
using treehammock.Rigging.Hosting;

namespace treehammock.Tests.Integration;

public sealed class Cor23AAHostIdentityTests
{
    private const string Key = "treehammock-owned-host-proof-key";
    private static IConfiguration Config(Dictionary<string, string?> values) => new ConfigurationBuilder().AddInMemoryCollection(values).Build();
    private static Dictionary<string, string?> Settings(bool enabled, bool bound = false)
    {
        var app = typeof(HostSystemTestIdentity).Assembly;
        var values = new Dictionary<string, string?>
        {
            ["SystemTestSettings:Enabled"] = enabled.ToString(),
            ["SystemTestSettings:EnableTestInspectionEndpoints"] = enabled.ToString(),
            ["SystemTestSettings:TestKey"] = enabled ? Key : ""
        };
        if (bound)
        {
            values["HostSystemTestProof:RunId"] = Guid.NewGuid().ToString("D");
            values["HostSystemTestProof:BuildRunId"] = app.GetCustomAttributes<AssemblyMetadataAttribute>().SingleOrDefault(a => a.Key == "TreehammockProofRunId")?.Value ?? Guid.NewGuid().ToString("D");
            values["HostSystemTestProof:AssemblySha256"] = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(app.Location))).ToLowerInvariant();
            values["HostSystemTestProof:Challenge"] = new string('a', 64);
        }
        return values;
    }
    private static IHostEnvironment EnvironmentFor(string name)
    {
        var value = Substitute.For<IHostEnvironment>(); value.EnvironmentName.Returns(name); return value;
    }
    private static TestServer Host(string environment, Dictionary<string, string?> values)
        => new(new WebHostBuilder().UseEnvironment(environment).ConfigureServices(services =>
        {
            var config = Config(values);
            var capability = SystemTestCapability.FromConfiguration(config, EnvironmentFor(environment));
            services.AddSingleton(capability);
            services.AddSingleton(HostSystemTestIdentity.FromConfiguration(config, capability));
            services.AddControllers().AddApplicationPart(typeof(SystemTestIdentityController).Assembly)
                .ConfigureApplicationPartManager(manager => manager.FeatureProviders.Add(new SystemTestControllerFeatureProvider(capability)));
        }).Configure(app => { app.UseRouting(); app.UseEndpoints(endpoints => endpoints.MapControllers()); }));

    [Theory]
    [InlineData("Production")] [InlineData("Staging")] [InlineData("Development")]
    [InlineData("Container")] [InlineData("ContainerReverseProxy")] [InlineData("Testing")]
    public async Task Disabled_identity_route_is_absent_even_with_a_valid_key(string environment)
    {
        using var host = Host(environment, Settings(false)); using var client = host.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/__system-test/identity"); request.Headers.Add(SystemTestCapability.TestKeyHeaderName, Key);
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.DoesNotContain("assembly_sha256", await response.Content.ReadAsStringAsync());
    }
    [Theory]
    [InlineData("Production")] [InlineData("Testing")]
    public void Configured_proof_cannot_enable_a_disabled_inspection_capability(string environment)
    {
        var config = Config(Settings(false, true));
        var capability = SystemTestCapability.FromConfiguration(config, EnvironmentFor(environment));
        var error = Assert.Throws<OptionsValidationException>(() => HostSystemTestIdentity.FromConfiguration(config, capability));
        Assert.DoesNotContain(Key, error.ToString()); Assert.DoesNotContain(new string('a',64), error.ToString());
    }
    [Theory]
    [InlineData("RunId", "old-process")] [InlineData("BuildRunId", "00000000-0000-0000-0000-000000000000")]
    [InlineData("AssemblySha256", "wrong-hash")] [InlineData("Challenge", "short")]
    [InlineData("Unsupported", "value")]
    public void Invalid_or_stale_binding_fails_startup_without_secret_diagnostics(string key, string value)
    {
        var settings = Settings(true,true); settings["HostSystemTestProof:"+key] = value; var config=Config(settings);
        var capability=SystemTestCapability.FromConfiguration(config,EnvironmentFor("Testing"));
        var error=Assert.Throws<OptionsValidationException>(() => HostSystemTestIdentity.FromConfiguration(config,capability));
        Assert.DoesNotContain(Key,error.ToString()); Assert.DoesNotContain(new string('a',64),error.ToString());
    }
    [Fact]
    public async Task Unbound_testing_rejects_missing_wrong_and_duplicate_keys_and_has_no_identity()
    {
        using var host=Host("Testing",Settings(true)); using var client=host.CreateClient();
        foreach (string[] keys in new[] { Array.Empty<string>(), new[] { "wrong" }, new[] { Key, Key } })
        {
            using var request=new HttpRequestMessage(HttpMethod.Get,"/__system-test/identity");
            if (keys.Length>0) request.Headers.TryAddWithoutValidation(SystemTestCapability.TestKeyHeaderName,keys);
            using var response=await client.SendAsync(request); Assert.Equal(HttpStatusCode.Unauthorized,response.StatusCode);
            Assert.DoesNotContain("challenge",await response.Content.ReadAsStringAsync());
        }
        client.DefaultRequestHeaders.Add(SystemTestCapability.TestKeyHeaderName,Key);
        using var valid=await client.GetAsync("/__system-test/identity"); Assert.Equal(HttpStatusCode.NotFound,valid.StatusCode);
    }
    [Fact]
    public async Task Owned_release_loaded_metadata_hash_process_and_challenge_are_authenticated_and_not_cached()
    {
        var app=typeof(HostSystemTestIdentity).Assembly; var settings=Settings(true,true);
        // Raw IDE builds have no proof identity and must refuse binding; only an
        // owning Release build can exercise the positive current-binary branch.
        if (app.GetCustomAttributes<AssemblyMetadataAttribute>().All(a => a.Key!="TreehammockProofRunId") || app.GetCustomAttribute<AssemblyConfigurationAttribute>()?.Configuration!="Release")
        {
            var config=Config(settings); var capability=SystemTestCapability.FromConfiguration(config,EnvironmentFor("Testing"));
            Assert.Throws<OptionsValidationException>(() => HostSystemTestIdentity.FromConfiguration(config,capability)); return;
        }
        using var host=Host("Testing",settings); using var client=host.CreateClient();
        using var rejected=await client.GetAsync("/__system-test/identity"); Assert.Equal(HttpStatusCode.Unauthorized,rejected.StatusCode);
        client.DefaultRequestHeaders.Add(SystemTestCapability.TestKeyHeaderName,Key);
        using var response=await client.GetAsync("/__system-test/identity"); Assert.Equal(HttpStatusCode.OK,response.StatusCode);
        Assert.True(response.Headers.CacheControl?.NoStore);
        using var value=JsonDocument.Parse(await response.Content.ReadAsStringAsync()); var root=value.RootElement;
        Assert.Equal(settings["HostSystemTestProof:RunId"],root.GetProperty("run_id").GetString());
        Assert.Equal(settings["HostSystemTestProof:BuildRunId"],root.GetProperty("build_run_id").GetString());
        Assert.Equal(settings["HostSystemTestProof:AssemblySha256"],root.GetProperty("assembly_sha256").GetString());
        Assert.Equal(app.ManifestModule.ModuleVersionId.ToString("D"),root.GetProperty("mvid").GetString());
        Assert.Equal(Environment.ProcessId,root.GetProperty("process_id").GetInt32());
        Assert.DoesNotContain(Key,value.RootElement.GetRawText()); Assert.False(root.TryGetProperty("path",out _));
    }
}
