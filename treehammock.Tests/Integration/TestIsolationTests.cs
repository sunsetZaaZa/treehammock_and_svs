using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using NSubstitute;
using treehammock.Controllers;
using treehammock.Rigging.DependencyInjection;
using treehammock.Rigging.Hosting;
using treehammock.Services;
using treehammock.Services.SystemTesting;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Integration;

public sealed class Cor23DTestIsolationTests
{
    private const string Key = "treehammock-system-test-key";
    private const string Latest = "/__system-test/deliveries/latest?channel=email&purpose=account_verify&destination=fixture@example.test";
    private static Dictionary<string, string?> Settings(bool enabled = false, bool inspection = false, string key = "")
    {
        var settings = TestConfiguration.ValidSettings();
        settings["SystemTestSettings:Enabled"] = enabled.ToString();
        settings["SystemTestSettings:EnableTestInspectionEndpoints"] = inspection.ToString();
        settings["SystemTestSettings:TestKey"] = key;
        settings["DatabaseSettings:profile"] = "Local";
        settings["RetentionSettings:Enabled"] = "false";
        settings["SecurityOperationSettings:HmacKeys:1"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        return settings;
    }
    private static IConfiguration Config(Dictionary<string, string?> settings)
        => new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
    // Actual production service registration/MVC; no background jobs or remote provider calls.
    private static TestServer Host(string environment, Dictionary<string, string?> settings,
        ISystemTestDeliveryCapture? capture = null)
        => new(new WebHostBuilder().UseEnvironment(environment)
            .ConfigureAppConfiguration((_, builder) => { builder.Sources.Clear(); builder.AddInMemoryCollection(settings); })
            .ConfigureServices((context, services) =>
            {
                services.AddTreehammockServices(context.Configuration, context.HostingEnvironment);
                services.RemoveAll<IHostedService>();
                services.AddControllers().AddApplicationPart(typeof(AccountLoginController).Assembly);
                if (capture is not null) { services.RemoveAll<ISystemTestDeliveryCapture>(); services.AddSingleton(capture); }
            })
            .Configure(app => { app.UseRouting(); app.UseEndpoints(endpoints => endpoints.MapControllers()); }));
    private static HttpRequestMessage Request(HttpMethod method, string path, params string[] keys)
    {
        var request = new HttpRequestMessage(method, path);
        if (method == HttpMethod.Post) request.Content = JsonContent.Create(new { emailAddress = "fixture@example.test", password = "fixture password" });
        if (keys.Length != 0) request.Headers.TryAddWithoutValidation(SystemTestCapability.TestKeyHeaderName, keys);
        return request;
    }

    [Theory]
    [InlineData("Production", false)] [InlineData("Production", true)]
    [InlineData("Staging", false)] [InlineData("Staging", true)]
    [InlineData("Development", false)] [InlineData("Development", true)]
    [InlineData("Container", false)] [InlineData("Container", true)]
    [InlineData("ContainerReverseProxy", false)] [InlineData("ContainerReverseProxy", true)]
    [InlineData("Custom", false)] [InlineData("Custom", true)]
    [InlineData("testing", false)] [InlineData("testing", true)]
    public void Actual_program_start_rejects_test_activation_outside_owned_testing(string environment, bool inspection)
    {
        using var factory = new TreehammockWebApplicationFactory(Settings(true, inspection, inspection ? Key : ""), environment);
        var error = Record.Exception(() => factory.CreateClient());
        Assert.NotNull(error);
        Assert.Contains("SystemTestSettings", error.ToString());
        Assert.Contains("dedicated Testing", error.ToString());
        Assert.DoesNotContain(Key, error.ToString());
    }

    [Theory]
    [InlineData("Production")] [InlineData("Staging")] [InlineData("Development")]
    [InlineData("Container")] [InlineData("ContainerReverseProxy")] [InlineData("Custom")] [InlineData("Testing")]
    public async Task Disabled_hosts_resolve_real_providers_and_all_privileged_routes_are_absent(string environment)
    {
        using var host = Host(environment, Settings());
        Assert.IsType<SMTPService>(host.Services.GetRequiredService<ISMTPService>());
        Assert.IsType<SmsSender>(host.Services.GetRequiredService<ISmsSender>());
        Assert.Null(host.Services.GetService<ISystemTestDeliveryCapture>());
        Assert.False(host.Services.GetRequiredService<SystemTestCapability>().CaptureEnabled);
        using var client = host.CreateClient();
        foreach (var (method, path) in new[] { (HttpMethod.Get, Latest), (HttpMethod.Delete, "/__system-test/deliveries"), (HttpMethod.Post, "/__system-test/accounts/verified") })
        {
            using var request = Request(method, path, Key);
            using var response = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            Assert.DoesNotContain("fixture password", await response.Content.ReadAsStringAsync());
        }
    }

    [Theory]
    [InlineData("Production")] [InlineData("Staging")] [InlineData("Development")]
    [InlineData("Container")] [InlineData("ContainerReverseProxy")] [InlineData("Testing")]
    public async Task Actual_program_disabled_profiles_start_with_real_providers_and_absent_routes(string environment)
    {
        var settings = Settings();
        if (environment == "Production") settings["DatabaseSettings:profile"] = "Production";
        settings["HostingSettings:ConfigureKestrel"] = "false";
        settings["HostingSettings:UseHttpsRedirection"] = "false";
        using var factory = new TreehammockWebApplicationFactory(settings, environment,
            services => services.RemoveAll<IHostedService>());
        using var client = factory.CreateClient();
        Assert.IsType<SMTPService>(factory.Services.GetRequiredService<ISMTPService>());
        Assert.IsType<SmsSender>(factory.Services.GetRequiredService<ISmsSender>());
        Assert.Null(factory.Services.GetService<ISystemTestDeliveryCapture>());
        foreach (var (method, path) in new[] { (HttpMethod.Get, Latest), (HttpMethod.Delete, "/__system-test/deliveries"), (HttpMethod.Post, "/__system-test/accounts/verified") })
        {
            using var request = Request(method, path, Key); using var response = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        }
    }

    [Theory]
    [InlineData(false, true, "")] [InlineData(false, false, Key)] [InlineData(false, true, Key)]
    [InlineData(true, true, "")] [InlineData(true, true, "short")]
    [InlineData(true, true, "has whitespace inside test key")]
    [InlineData(true, false, Key)]
    public void Actual_program_start_rejects_inconsistent_flags_and_keys(bool enabled, bool inspection, string key)
    {
        using var factory = new TreehammockWebApplicationFactory(Settings(enabled, inspection, key), "Testing");
        var error = Record.Exception(() => factory.CreateClient());
        Assert.NotNull(error); Assert.Contains("SystemTestSettings", error.ToString());
        if (key.Length > 0) Assert.DoesNotContain(key, error.ToString());
    }

    [Fact]
    public void Unknown_settings_oversized_keys_and_production_database_profile_fail_closed()
    {
        var settings = Settings(true, true, new string('x', 129));
        using (var host = new TreehammockWebApplicationFactory(settings, "Testing"))
            Assert.Contains("SystemTestSettings", Assert.ThrowsAny<Exception>(() => host.CreateClient()).ToString());
        settings = Settings(); settings["SystemTestSettings:DeliveryCaptureConnection"] = "ignored-connection-secret";
        using (var host = new TreehammockWebApplicationFactory(settings, "Testing"))
        {
            var error = Assert.ThrowsAny<Exception>(() => host.CreateClient());
            Assert.Contains("unsupported setting", error.ToString()); Assert.DoesNotContain("ignored-connection-secret", error.ToString());
        }
        settings = Settings(true, true, Key); settings["DatabaseSettings:profile"] = "Production";
        using (var host = new TreehammockWebApplicationFactory(settings, "Testing"))
            Assert.Contains("Production database", Assert.ThrowsAny<Exception>(() => host.CreateClient()).ToString());
        Assert.Throws<OptionsValidationException>(() => new ServiceCollection().AddTreehammockServices(Config(Settings(true))));
    }

    [Fact]
    public async Task Explicit_capture_only_testing_resolves_fake_providers_but_exposes_no_privileged_routes()
    {
        using var host = Host("Testing", Settings(true));
        Assert.IsType<SystemTestSmtpService>(host.Services.GetRequiredService<ISMTPService>());
        Assert.IsType<SystemTestSmsSender>(host.Services.GetRequiredService<ISmsSender>());
        Assert.IsType<SystemTestDeliveryCapture>(host.Services.GetRequiredService<ISystemTestDeliveryCapture>());
        using var client = host.CreateClient();
        foreach (var (method, path) in new[] { (HttpMethod.Get, Latest), (HttpMethod.Delete, "/__system-test/deliveries"), (HttpMethod.Post, "/__system-test/accounts/verified") })
        {
            using var request = Request(method, path, Key); using var response = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        }
    }

    [Theory]
    [InlineData("missing")] [InlineData("wrong")] [InlineData("duplicate")] [InlineData("comma")]
    public async Task Inspection_and_seed_reject_invalid_keys_before_any_fixture_capture_work(string kind)
    {
        var capture = Substitute.For<ISystemTestDeliveryCapture>();
        using var host = Host("Testing", Settings(true, true, Key), capture);
        using var client = host.CreateClient();
        string[] keys = kind switch { "missing" => [], "wrong" => ["wrong-test-key"], "duplicate" => [Key, "wrong-test-key"], _ => [Key + "," + Key] };
        foreach (var (method, path) in new[] { (HttpMethod.Get, Latest), (HttpMethod.Delete, "/__system-test/deliveries"), (HttpMethod.Post, "/__system-test/accounts/verified") })
        {
            using var request = Request(method, path, keys); using var response = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }
        Assert.Empty(capture.ReceivedCalls()); // No capture read/clear; valid seed input would attempt SQL if allowed.
    }

    [Fact]
    public async Task Actual_program_allows_explicit_inspection_with_the_matching_key()
    {
        var capture = Substitute.For<ISystemTestDeliveryCapture>();
        capture.GetLatest("email", "account_verify", "fixture@example.test").Returns(
            Task.FromResult<SystemTestDeliveryRecord?>(new(Guid.NewGuid(), "fixture", "email", "account_verify", "fixture@example.test", "verify", "fixture proof", "123456", null)));
        using var factory = new TreehammockWebApplicationFactory(Settings(true, true, Key), "Testing", services =>
        { services.RemoveAll<ISystemTestDeliveryCapture>(); services.AddSingleton(capture); });
        using var client = factory.CreateClient(); using var request = Request(HttpMethod.Get, Latest, Key);
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("fixture proof", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public void Configuration_reload_cannot_enable_capabilities_or_replace_the_inspection_key()
    {
        var configuration = Config(Settings());
        var disabled = SystemTestCapability.FromConfiguration(configuration, null);
        configuration["SystemTestSettings:Enabled"] = "true";
        Assert.False(disabled.CaptureEnabled); Assert.False(disabled.InspectionEnabled);
        Assert.Throws<InvalidOperationException>(() => new SystemTestSmtpService(Substitute.For<ISystemTestDeliveryCapture>(), disabled));
        Assert.Throws<InvalidOperationException>(() => new SystemTestSmsSender(Substitute.For<ISystemTestDeliveryCapture>(), disabled));
        Assert.Throws<InvalidOperationException>(() => new SystemTestDeliveryCapture(null!, disabled));
        var env = Substitute.For<IHostEnvironment>(); env.EnvironmentName.Returns("Testing");
        configuration = Config(Settings(true, true, Key));
        var enabled = SystemTestCapability.FromConfiguration(configuration, env);
        configuration["SystemTestSettings:TestKey"] = "replacement-system-test-key";
        var context = new DefaultHttpContext(); context.Request.Headers[SystemTestCapability.TestKeyHeaderName] = Key;
        Assert.True(enabled.Authorizes(context.Request));
        context.Request.Headers[SystemTestCapability.TestKeyHeaderName] = "replacement-system-test-key";
        Assert.False(enabled.Authorizes(context.Request));
    }

    [Theory]
    [InlineData("activation-code", "activation", "047291")]
    [InlineData("email-change-notice", "email_change_notice", null)]
    public async Task Durable_capture_preserves_purpose_code_and_job_and_waits_for_publication(
        string kind, string purpose, string? code)
    {
        var capture = Substitute.For<ISystemTestDeliveryCapture>();
        var publication = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var environment = Substitute.For<IHostEnvironment>(); environment.EnvironmentName.Returns("Testing");
        var capability = SystemTestCapability.FromConfiguration(Config(Settings(true)), environment);
        var service = new SystemTestSmtpService(capture, capability);
        Guid job = Guid.NewGuid();
        string value = code ?? "Your email address changed.";
        var token = TestContext.Current.CancellationToken;
        capture.CaptureEmail(purpose, "owner@example.test", "subject", value, code, job.ToString("N"), token)
            .Returns(publication.Task);
        var send = service.SendDurable(job, new(kind, "email", "owner@example.test", "subject", value), token);
        try
        {
            Assert.False(send.IsCompleted);
            _ = capture.Received(1).CaptureEmail(purpose, "owner@example.test", "subject", value,
                code, job.ToString("N"), token);
        }
        finally
        {
            publication.TrySetResult();
            await send.WaitAsync(TimeSpan.FromSeconds(5));
        }
        var result = await send;
        Assert.Equal(treehammock.Rigging.Delivery.DeliverySendState.Accepted, result.State);
        Assert.Equal(job.ToString("N"), result.ReceiptId);
    }
}
