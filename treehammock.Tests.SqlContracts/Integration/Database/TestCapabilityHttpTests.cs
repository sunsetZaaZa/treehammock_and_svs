using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Npgsql;
using treehammock.Controllers;
using treehammock.Rigging.Config;
using treehammock.Rigging.Database;
using treehammock.Rigging.DependencyInjection;
using treehammock.Rigging.Hosting;
using treehammock.Rigging.Security;
using treehammock.Services;
using treehammock.Services.SystemTesting;
using treehammock.Tests.SqlContracts.Support;

namespace treehammock.Tests.Integration.Database;

// Production composition/controllers/providers/hash service with real owned PostgreSQL.
// Storage's search_path is the sole persistence substitute. No background jobs or external providers.
[Trait("Suite", "SqlContracts")]
public sealed class Cor23DTestCapabilityHttpTests
{
    private const string Key = "treehammock-system-test-key";
    private static string Root()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "treehammock.sln"))) directory = directory.Parent;
        return directory?.FullName ?? throw new InvalidOperationException("Cannot locate source root.");
    }
    private static TestServer Host(string environment, bool enabled, Cor09RefreshHttpTests.FixtureStorage storage)
        => new(new WebHostBuilder().UseContentRoot(Root()).UseEnvironment(environment)
            .ConfigureAppConfiguration((_, builder) =>
            {
                builder.Sources.Clear(); builder.AddJsonFile(Path.Combine(Root(), "appsettings.Example.json"));
                builder.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["SystemTestSettings:Enabled"] = enabled.ToString(),
                    ["SystemTestSettings:EnableTestInspectionEndpoints"] = enabled.ToString(),
                    ["SystemTestSettings:TestKey"] = enabled ? Key : "",
                    ["SecurityOperationSettings:HmacKeys:1"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
                });
            })
            .ConfigureServices((context, services) =>
            {
                services.AddTreehammockServices(context.Configuration, context.HostingEnvironment);
                services.RemoveAll<IHostedService>();
                services.RemoveAll<StorageContext>(); services.AddSingleton<StorageContext>(storage);
                services.AddControllers().AddApplicationPart(typeof(AccountLoginController).Assembly);
            })
            .Configure(app => { app.UseRouting(); app.UseEndpoints(endpoints => endpoints.MapControllers()); }));
    private static HttpRequestMessage Request(HttpMethod method, string path, string? key = Key)
    {
        var request = new HttpRequestMessage(method, path);
        if (key is not null) request.Headers.Add(SystemTestCapability.TestKeyHeaderName, key);
        return request;
    }
    private static string Latest(string channel, string purpose, string destination)
        => $"/__system-test/deliveries/latest?channel={Uri.EscapeDataString(channel)}&purpose={Uri.EscapeDataString(purpose)}&destination={Uri.EscapeDataString(destination)}";
    private static async Task<long> Count(NpgsqlConnection connection, string sql, CancellationToken token)
    { await using var command = new NpgsqlCommand(sql, connection); return (long)(await command.ExecuteScalarAsync(token))!; }

    [Fact]
    public Task Owned_testing_delivers_inspects_clears_and_seeds_with_real_persistence()
        => SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            await using var storage = new Cor09RefreshHttpTests.FixtureStorage(fixture,
                new SecurityOperationSettings { HmacKeys = new() { [1] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) } });
            using var host = Host("Testing", true, storage); using var client = host.CreateClient();
            Assert.IsType<SystemTestSmtpService>(host.Services.GetRequiredService<ISMTPService>());
            Assert.IsType<SystemTestSmsSender>(host.Services.GetRequiredService<ISmsSender>());
            const string proof = "owned-fixture-proof";
            Assert.True(await host.Services.GetRequiredService<ISMTPService>().VerificationLetter("fixture@example.test", "verify", "https://example.test/verify?payload=" + proof));
            Assert.True(await host.Services.GetRequiredService<ISmsSender>().SendCode("+15555550123", "123456"));
            foreach (var (channel, purpose, destination, code) in new[] {
                ("email", "account_verify", "fixture@example.test", proof), ("sms", "sms_code", "+15555550123", "123456") })
            {
                using var request = Request(HttpMethod.Get, Latest(channel, purpose, destination));
                using var response = await client.SendAsync(request, token); Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(token));
                Assert.Equal(code, body.RootElement.GetProperty("data").GetProperty("code").GetString());
            }
            var connection = await fixture.OpenConnectionAsync(token);
            Assert.Equal(2L, await Count(connection, "select count(*) from system_test_delivery_messages", token));
            // Invalid keys cannot clear captured proof or seed a valid account.
            using (var request = Request(HttpMethod.Delete, "/__system-test/deliveries", "wrong-key"))
            using (var response = await client.SendAsync(request, token)) Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            using (var request = Request(HttpMethod.Post, "/__system-test/accounts/verified", null))
            {
                request.Content = JsonContent.Create(new { emailAddress = "denied@example.test", password = "owned fixture password" });
                using var response = await client.SendAsync(request, token); Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            }
            Assert.Equal(2L, await Count(connection, "select count(*) from system_test_delivery_messages", token));
            Assert.Equal(0L, await Count(connection, "select count(*) from accounts", token));
            using (var request = Request(HttpMethod.Post, "/__system-test/accounts/verified"))
            {
                request.Content = JsonContent.Create(new { emailAddress = "owned@example.test", password = "owned fixture password" });
                using var response = await client.SendAsync(request, token); Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            }
            byte[] hash;
            await using (var command = new NpgsqlCommand("select hashed_password,verify_status,security_stamp from accounts where email_address='owned@example.test'", connection))
            await using (var reader = await command.ExecuteReaderAsync(token))
            {
                Assert.True(await reader.ReadAsync(token)); hash = reader.GetFieldValue<byte[]>(0);
                Assert.Equal((short)1, reader.GetInt16(1)); Assert.NotEqual(Guid.Empty, reader.GetGuid(2));
                Assert.False(await reader.ReadAsync(token));
            }
            Assert.True(await host.Services.GetRequiredService<IPasswordWorkService>().VerifyBytesAsync(hash, "owned fixture password", token));
            using (var request = Request(HttpMethod.Delete, "/__system-test/deliveries"))
            using (var response = await client.SendAsync(request, token)) Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(0L, await Count(connection, "select count(*) from system_test_delivery_messages", token));
        });

    [Theory]
    [InlineData("Production")] [InlineData("Container")] [InlineData("ContainerReverseProxy")]
    public Task Disabled_deployable_hosts_create_no_capture_table_or_seeded_account(string environment)
        => SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            // Complete canonical setup owns this retention relation before any host exists.
            // Disabled composition must neither replace it nor add capture/account rows.
            var connection = await fixture.OpenConnectionAsync(token);
            string relationIdentitySql = $"select to_regclass('{fixture.Schema}.system_test_delivery_messages')::oid::bigint";
            long relationBeforeHost = await Count(connection, relationIdentitySql, token);
            Assert.True(relationBeforeHost > 0);
            long deliveriesBeforeHost = await Count(connection, "select count(*) from system_test_delivery_messages", token);
            long accountsBeforeHost = await Count(connection, "select count(*) from accounts", token);
            Assert.Equal(0L, deliveriesBeforeHost);
            Assert.Equal(0L, accountsBeforeHost);
            await using var storage = new Cor09RefreshHttpTests.FixtureStorage(fixture,
                new SecurityOperationSettings { HmacKeys = new() { [1] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) } });
            using var host = Host(environment, false, storage); using var client = host.CreateClient();
            Assert.IsType<SMTPService>(host.Services.GetRequiredService<ISMTPService>());
            Assert.IsType<SmsSender>(host.Services.GetRequiredService<ISmsSender>());
            Assert.Null(host.Services.GetService<ISystemTestDeliveryCapture>());
            foreach (var (method, path) in new[] { (HttpMethod.Get, Latest("email", "account_verify", "owned@example.test")),
                (HttpMethod.Delete, "/__system-test/deliveries"), (HttpMethod.Post, "/__system-test/accounts/verified") })
            {
                using var request = Request(method, path);
                if (method == HttpMethod.Post) request.Content = JsonContent.Create(new { emailAddress = "owned@example.test", password = "production proof must not be captured" });
                using var response = await client.SendAsync(request, token); Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            }
            Assert.Equal(relationBeforeHost, await Count(connection, relationIdentitySql, token));
            Assert.Equal(deliveriesBeforeHost, await Count(connection, "select count(*) from system_test_delivery_messages", token));
            Assert.Equal(accountsBeforeHost, await Count(connection, "select count(*) from accounts", token));
        });
}
