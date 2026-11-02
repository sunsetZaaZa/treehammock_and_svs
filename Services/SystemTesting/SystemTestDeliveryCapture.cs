using treehammock.Rigging.Hosting;
using System.Data;
using System.Text.RegularExpressions;

using Npgsql;

using treehammock.Rigging.Database;

namespace treehammock.Services.SystemTesting;

public sealed record SystemTestDeliveryRecord(
    Guid DeliveryId,
    string CreatedAt,
    string Channel,
    string Purpose,
    string Destination,
    string? Subject,
    string Body,
    string? Code,
    string? CorrelationId);

public interface ISystemTestDeliveryCapture
{
    Task CaptureEmail(string purpose, string destination, string subject, string body, string? code = null, string? correlationId = null, CancellationToken token = default);
    Task CaptureSms(string purpose, string destination, string body, string? code = null, string? correlationId = null, CancellationToken token = default);
    Task<SystemTestDeliveryRecord?> GetLatest(string channel, string purpose, string destination);
    Task<int> Clear();
}

public sealed class SystemTestDeliveryCapture : ISystemTestDeliveryCapture
{
    private const string CreateTableSql = """
        create table if not exists system_test_delivery_messages (
            delivery_id uuid primary key,
            created_at timestamptz not null default now(),
            channel text not null,
            purpose text not null,
            destination text not null,
            subject text null,
            body text not null,
            code text null,
            correlation_id text null
        );

        create index if not exists ix_system_test_delivery_messages_lookup
            on system_test_delivery_messages(channel, purpose, destination, created_at desc);
        """;

    private static readonly Regex CodeRegex = new(@"(?<!\d)(\d{6,10})(?!\d)", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private readonly StorageContext _storageContext;
    private readonly SemaphoreSlim _schemaLock = new(1, 1);
    private bool _schemaEnsured;

    public SystemTestDeliveryCapture(StorageContext storageContext, SystemTestCapability capability)
    {
        capability.RequireCapture();
        _storageContext = storageContext;
    }

    public async Task CaptureEmail(string purpose, string destination, string subject, string body, string? code = null, string? correlationId = null, CancellationToken token = default)
    {
        await Capture("email", purpose, destination, subject, body, code, correlationId, token);
    }

    public async Task CaptureSms(string purpose, string destination, string body, string? code = null, string? correlationId = null, CancellationToken token = default)
    {
        await Capture("sms", purpose, destination, null, body, code, correlationId, token);
    }

    public async Task<SystemTestDeliveryRecord?> GetLatest(string channel, string purpose, string destination)
    {
        await EnsureSchema();
        await using NpgsqlConnection connection = await _storageContext.CreateConnection();
        await using var command = new NpgsqlCommand("""
            select delivery_id, created_at::text, channel, purpose, destination, subject, body, code, correlation_id
            from system_test_delivery_messages
            where lower(channel) = lower(@channel)
              and lower(purpose) = lower(@purpose)
              and lower(destination) = lower(@destination)
            order by created_at desc
            limit 1;
            """, connection);
        command.Parameters.AddWithValue("channel", channel);
        command.Parameters.AddWithValue("purpose", purpose);
        command.Parameters.AddWithValue("destination", destination);

        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(CommandBehavior.SingleRow);
        if (!await reader.ReadAsync())
        {
            return null;
        }

        return new SystemTestDeliveryRecord(
            reader.GetGuid(0),
            reader.GetString(1),
            reader.GetString(2),
            reader.GetString(3),
            reader.GetString(4),
            reader.IsDBNull(5) ? null : reader.GetString(5),
            reader.GetString(6),
            reader.IsDBNull(7) ? null : reader.GetString(7),
            reader.IsDBNull(8) ? null : reader.GetString(8));
    }

    public async Task<int> Clear()
    {
        await EnsureSchema();
        await using NpgsqlConnection connection = await _storageContext.CreateConnection();
        await using var command = new NpgsqlCommand("delete from system_test_delivery_messages;", connection);
        return await command.ExecuteNonQueryAsync();
    }

    private async Task Capture(string channel, string purpose, string destination, string? subject, string body, string? code, string? correlationId, CancellationToken token)
    {
        await EnsureSchema(token);
        string? capturedCode = string.IsNullOrWhiteSpace(code) ? ExtractCode(body) : code;
        await using NpgsqlConnection connection = await _storageContext.CreateConnection(token);
        await using var command = new NpgsqlCommand("""
            insert into system_test_delivery_messages(delivery_id, channel, purpose, destination, subject, body, code, correlation_id)
            values (@deliveryId, @channel, @purpose, @destination, @subject, @body, @code, @correlationId);
            """, connection);
        command.Parameters.AddWithValue("deliveryId", Guid.NewGuid());
        command.Parameters.AddWithValue("channel", channel);
        command.Parameters.AddWithValue("purpose", purpose);
        command.Parameters.AddWithValue("destination", destination);
        command.Parameters.AddWithValue("subject", (object?)subject ?? DBNull.Value);
        command.Parameters.AddWithValue("body", body);
        command.Parameters.AddWithValue("code", (object?)capturedCode ?? DBNull.Value);
        command.Parameters.AddWithValue("correlationId", (object?)correlationId ?? DBNull.Value);
        await command.ExecuteNonQueryAsync(token);
    }

    private async Task EnsureSchema(CancellationToken token = default)
    {
        if (_schemaEnsured)
        {
            return;
        }

        await _schemaLock.WaitAsync(token);
        try
        {
            if (_schemaEnsured)
            {
                return;
            }

            await using NpgsqlConnection connection = await _storageContext.CreateConnection(token);
            await using var command = new NpgsqlCommand(CreateTableSql, connection);
            await command.ExecuteNonQueryAsync(token);
            _schemaEnsured = true;
        }
        finally
        {
            _schemaLock.Release();
        }
    }

    private static string? ExtractCode(string body)
    {
        Match match = CodeRegex.Match(body);
        return match.Success ? match.Groups[1].Value : null;
    }
}
