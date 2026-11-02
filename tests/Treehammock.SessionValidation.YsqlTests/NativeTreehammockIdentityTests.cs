using System.Text.Json;
using Npgsql;
using NpgsqlTypes;
using Treehammock.SessionValidation.Storage;
using Xunit;
namespace Treehammock.SessionValidation.YsqlTests;

// Explicit disposable THS12A fixture, distinct from the historical SVS04/05 SQL fixture.
// No provisioning, grants, mutations or identity switching are performed by these cases.
public sealed class NativeTreehammockIdentityTests
{
    private static (string Connection, TreehammockRoleMap Roles) Fixture()
    {
        if (Environment.GetEnvironmentVariable("SVS07_DISPOSABLE_YSQL") != "true") throw new InvalidOperationException("Explicit disposable THS YSQL fixture required.");
        var connection = Environment.GetEnvironmentVariable("SVS07_VALIDATOR_CONNECTION") ?? throw new InvalidOperationException("Dedicated validator connection required.");
        var roles = JsonSerializer.Deserialize<TreehammockRoleMap>(Environment.GetEnvironmentVariable("SVS07_ROLE_MAP_JSON") ?? "", new JsonSerializerOptions { UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow }) ?? throw new InvalidOperationException("Exact role binding required.");
        roles.Validate(); return (connection, roles);
    }
    [Fact] public async Task Actual_THS12A_policy_admits_only_the_owned_validator_identity()
    {
        var fixture = Fixture(); await using var identity = YsqlAuthorityDataSource.CreateTreehammockValidator(fixture.Connection, fixture.Roles);
        var result = await identity.RefreshIdentityAsync(TestContext.Current.CancellationToken);
        Assert.Equal(DatabaseIdentityAuditStatus.Verified, result.Status); Assert.True(identity.DatabaseFallbackReady);
    }
    [Theory][InlineData("wrong-role")][InlineData("wrong-policy")]
    public async Task Actual_invoker_helper_refuses_foreign_role_or_policy(string fault)
    {
        var fixture = Fixture();
        // Validate ownership/transport via the public typed factory before issuing a catalog-only probe.
        await using var identity = YsqlAuthorityDataSource.CreateTreehammockValidator(fixture.Connection, fixture.Roles);
        Assert.Equal(DatabaseIdentityAuditStatus.Verified, (await identity.RefreshIdentityAsync(TestContext.Current.CancellationToken)).Status);
        await using var source = YsqlAuthorityDataSource.Create(fixture.Connection); await using var connection = await source.OpenConnectionAsync(TestContext.Current.CancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(TestContext.Current.CancellationToken);
        await using (var setup = new NpgsqlCommand("set transaction read only; set local yb_read_from_followers=off; set local statement_timeout='2s'", connection, transaction) { CommandTimeout = 3 }) await setup.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
        string policy = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "treehammock-validator-policy.json"));
        await using var command = new NpgsqlCommand("select public.ths_database_role_safe(@kind,@policy)", connection, transaction) { CommandTimeout = 3 };
        command.Parameters.AddWithValue("kind", fault == "wrong-role" ? "Coordinator" : "Validator"); command.Parameters.AddWithValue("policy", NpgsqlDbType.Jsonb, fault == "wrong-policy" ? "{}" : policy);
        Assert.Equal(false, await command.ExecuteScalarAsync(TestContext.Current.CancellationToken)); await transaction.CommitAsync(TestContext.Current.CancellationToken);
    }
}
