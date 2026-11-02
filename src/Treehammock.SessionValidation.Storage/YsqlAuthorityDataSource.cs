using Npgsql;
namespace Treehammock.SessionValidation.Storage;

public static class YsqlAuthorityDataSource
{
    public static ValidatorDatabaseIdentity CreateTreehammockValidator(string connectionString, TreehammockRoleMap roles, NodaTime.IClock? clock = null)
    {
        roles.Validate();
        var c = new NpgsqlConnectionStringBuilder(connectionString);
        if (c.Username != roles.Validator || c.SslMode != SslMode.VerifyFull || string.IsNullOrWhiteSpace(c.Host) || string.IsNullOrWhiteSpace(c.Database))
            throw new ArgumentException("Dedicated validator identity with verified TLS required.");
        var source = Create(connectionString);
        return new(source, clock ?? NodaTime.SystemClock.Instance,
            ct => TreehammockIdentityAuditor.InspectAsync(source, roles, ct), json => TreehammockIdentityPolicy.Accept(json, roles));
    }
    public static ValidatorDatabaseIdentity CreateValidator(string connectionString, NodaTime.IClock? clock = null)
    {
        var c = new NpgsqlConnectionStringBuilder(connectionString);
        if (c.Username != DatabaseIdentityPolicy.Login || c.SslMode != SslMode.VerifyFull ||
            string.IsNullOrWhiteSpace(c.Host) || string.IsNullOrWhiteSpace(c.Database))
            throw new ArgumentException("Dedicated validator identity with verified TLS required.");
        return new(Create(connectionString), clock ?? NodaTime.SystemClock.Instance);
    }
    // Dedicated lifetime owned by the future private host. Never borrow StorageContext/writer credentials.
    public static NpgsqlDataSource Create(string connectionString)
    {
        var c = new NpgsqlConnectionStringBuilder(connectionString);
        if (c.Multiplexing || c.NoResetOnClose || c.PersistSecurityInfo || c.IncludeErrorDetail || c.Enlist ||
            c.MaxPoolSize > 32 || c.MinPoolSize > c.MaxPoolSize || c.Timeout is < 1 or > 30 ||
            c.CommandTimeout is < 1 or > 30 || c.CancellationTimeout is < 1 or > 2000)
            throw new ArgumentException("Dedicated bounded authority connection settings required.");
        var builder = new NpgsqlDataSourceBuilder(c.ConnectionString);
        builder.UseNodaTime();
        return builder.Build();
    }
}
