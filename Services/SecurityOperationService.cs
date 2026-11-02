using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using NodaTime;
using NodaTime.Serialization.JsonNet;
using Npgsql;
using NpgsqlTypes;
using treehammock.DataLayer.Operations;
using treehammock.Repos;
using treehammock.Rigging.Config;
using treehammock.Rigging.Database;
using treehammock.Rigging.Dependencies;
using treehammock.Rigging.Operations;

namespace treehammock.Services;

public sealed class SecurityOperationService
{
    private readonly StorageContext _storage;
    private readonly SecurityOperationSettings _settings;
    private readonly SecurityOperationRepo _repo;
    private readonly CancellationToken _shutdown;
    private sealed class BindingResolver : Newtonsoft.Json.Serialization.DefaultContractResolver
    {
        protected override Newtonsoft.Json.Serialization.JsonProperty CreateProperty(System.Reflection.MemberInfo member, MemberSerialization serialization)
        {
            var property = base.CreateProperty(member, serialization);
            property.Ignored = false; return property;
        }
    }
    private static readonly JsonSerializerSettings ParameterJson = new JsonSerializerSettings { ContractResolver = new BindingResolver() }
        .ConfigureForNodaTime(DateTimeZoneProviders.Tzdb);
    public SecurityOperationService(StorageContext storage, SecurityOperationSettings settings, CancellationToken shutdown = default)
    { _storage = storage; _settings = settings; _repo = new(storage); _shutdown = shutdown; }
    internal byte[] Mac(int version, string purpose, params byte[][] parts)
    {
        if (!_settings.HmacKeys.TryGetValue(version, out string? encoded))
            throw new SecurityOperationException("SECURITY_OPERATION_KEY_VERSION_UNAVAILABLE", 503);
        byte[] key = Convert.FromBase64String(encoded);
        try
        {
            using var stream = new MemoryStream(); using var writer = new BinaryWriter(stream, Encoding.UTF8, true);
            writer.Write("treehammock:security-operation:v1:" + purpose);
            foreach (byte[] part in parts) { writer.Write(part.Length); writer.Write(part); }
            writer.Flush(); return HMACSHA256.HashData(key, stream.ToArray());
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
    internal SecurityOperationSettings Settings => _settings;
    internal SecurityOperationBinding Binding(SecurityOperationRequestContext context, SecurityOperationKey key, int version) => new(
        Mac(version, "request", Encoding.UTF8.GetBytes(context.Purpose), Encoding.UTF8.GetBytes(key.IssuedAt.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture)), context.CanonicalBody),
        Mac(version, "recovery", key.Id.ToByteArray(), context.RecoveryBytes!), version);
    public async Task<SecurityOperationScope> BeginAsync(string purpose, object parameters, Guid? accountId,
        Guid? expectedStamp, string? expectedVersion, CancellationToken caller)
    {
        var context = SecurityOperationRequestContext.Current ?? SecurityOperationRequestContext.Isolated(purpose);
        using var admissionBudget = Budget(caller, _settings.ExecutionSeconds);
        await context.Admission.WaitAsync(admissionBudget.Token);
        try
        {
            if (!context.Admitted)
            {
                if (context.ClientKey is null || context.RecoveryKey is null)
                    throw new SecurityOperationException("SECURITY_OPERATION_KEYS_REQUIRED", 428);
                var key = SecurityOperationKey.Parse(context.ClientKey, _settings.RetentionSeconds);
                context.OperationId = key.Id; context.RecoveryBytes = SecurityOperationKey.ParseRecoveryKey(context.RecoveryKey);
                var existing = await _repo.GetBindingAsync(key.Id, admissionBudget.Token);
                if (existing is not null)
                {
                    ValidateBinding(existing, Binding(context, key, existing.KeyVersion));
                    throw SecurityOperationException.Outcome(await ReconcileAsync(key.Id));
                }
                DateTimeOffset expires = key.IssuedAt.AddSeconds(_settings.RetentionSeconds);
                DateTimeOffset execute = DateTimeOffset.UtcNow.AddSeconds(_settings.ExecutionSeconds);
                if (execute >= expires) execute = expires.AddMilliseconds(-1);
                bool inserted;
                try
                {
                    inserted = await _repo.ReserveAsync(key.Id, Binding(context, key, _settings.ActiveKeyVersion),
                        "request:" + Convert.ToHexString(Mac(_settings.ActiveKeyVersion, "purpose", Encoding.UTF8.GetBytes(context.Purpose))),
                        key.IssuedAt, execute, expires, admissionBudget.Token);
                }
                catch (OperationCanceledException) { throw SecurityOperationException.Outcome(await ReconcileAsync(key.Id)); }
                catch (Exception ex) when (ex is not SecurityOperationException)
                { throw SecurityOperationException.Outcome(await ReconcileAsync(key.Id)); }
                if (!inserted)
                {
                    existing = await _repo.GetBindingAsync(key.Id, admissionBudget.Token);
                    if (existing is null) throw SecurityOperationException.Outcome(new(key.Id, SecurityOperationState.Unknown, null, []));
                    ValidateBinding(existing, Binding(context, key, existing.KeyVersion));
                    throw SecurityOperationException.Outcome(await ReconcileAsync(key.Id));
                }
                context.Admitted = true;
            }
        }
        finally { context.Admission.Release(); }
        var budget = Budget(caller, _settings.ExecutionSeconds);
        NpgsqlConnection? connection = null; NpgsqlTransaction? transaction = null;
        try
        {
            connection = await _storage.CreateConnection(budget.Token);
            transaction = await connection.BeginTransactionAsync(budget.Token);
            await using (var bounds = new NpgsqlCommand("select set_config('lock_timeout',@lock,true),set_config('statement_timeout',@statement,true)", connection, transaction))
            {
                bounds.Parameters.AddWithValue("lock", (_settings.LockSeconds * 1000).ToString(System.Globalization.CultureInfo.InvariantCulture));
                bounds.Parameters.AddWithValue("statement", (_settings.ExecutionSeconds * 1000).ToString(System.Globalization.CultureInfo.InvariantCulture));
                await bounds.ExecuteNonQueryAsync(budget.Token);
            }
            await using (var gate = new NpgsqlCommand("select lock_security_operation(@id,@account)", connection, transaction))
            {
                gate.Parameters.AddWithValue("id", context.OperationId!.Value);
                gate.Parameters.Add("account", NpgsqlDbType.Uuid).Value = accountId is Guid id && id != Guid.Empty ? id : DBNull.Value;
                await gate.ExecuteNonQueryAsync(budget.Token);
            }
            byte[] parameterBytes = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(parameters, ParameterJson));
            byte[] hmac;
            try { hmac = Mac(_settings.ActiveKeyVersion, "step:" + purpose, parameterBytes); }
            finally { CryptographicOperations.ZeroMemory(parameterBytes); }
            return new(this, context, connection, transaction, budget, context.NextStep(purpose), hmac, expectedStamp, expectedVersion);
        }
        catch (Exception ex) when (ex is not SecurityOperationException)
        {
            if (transaction is not null) { try { await transaction.DisposeAsync(); } catch { } }
            if (connection is not null) { try { await connection.DisposeAsync(); } catch { } }
            budget.Dispose();
            if (ex is PostgresException pg && pg.SqlState == "P0405") throw new SecurityOperationException("SECURITY_OPERATION_CONFLICT", 409);
            throw SecurityOperationException.Outcome(await ReconcileAsync(context.OperationId!.Value));
        }
    }
    internal static void ValidateBinding(SecurityOperationBinding stored, SecurityOperationBinding supplied)
    {
        if (!CryptographicOperations.FixedTimeEquals(stored.RequestHmac, supplied.RequestHmac)
            || !CryptographicOperations.FixedTimeEquals(stored.RecoveryHmac, supplied.RecoveryHmac))
            throw new SecurityOperationException("SECURITY_OPERATION_CONFLICT", 409);
    }
    private CancellationTokenSource Budget(CancellationToken caller, int seconds)
    {
        var budget = CancellationTokenSource.CreateLinkedTokenSource(caller, _shutdown);
        budget.CancelAfter(TimeSpan.FromSeconds(seconds)); return budget;
    }
    public async Task<SecurityOperationStatus> ReconcileAuthorizedAsync(string clientKey, string recoveryKey, CancellationToken caller)
    {
        var key = SecurityOperationKey.Parse(clientKey, _settings.RetentionSeconds);
        byte[] recovery = SecurityOperationKey.ParseRecoveryKey(recoveryKey);
        try
        {
            using var budget = Budget(caller, _settings.ReconciliationSeconds);
            var stored = await _repo.GetBindingAsync(key.Id, budget.Token);
            // An unknown ID and a wrong capability have the same denial shape.
            if (stored is null || !CryptographicOperations.FixedTimeEquals(stored.RecoveryHmac, Mac(stored.KeyVersion, "recovery", key.Id.ToByteArray(), recovery)))
                throw new SecurityOperationException("SECURITY_OPERATION_NOT_FOUND", 404);
            return await _repo.ReconcileAsync(key.Id, budget.Token);
        }
        catch (SecurityOperationException) { throw; }
        catch { return new(key.Id, SecurityOperationState.Unknown, null, []); }
        finally { CryptographicOperations.ZeroMemory(recovery); }
    }
    public async Task<SecurityOperationStatus> ReconcileAsync(Guid id)
    {
        using var budget = Budget(CancellationToken.None, _settings.ReconciliationSeconds);
        try { return await _repo.ReconcileAsync(id, budget.Token); }
        catch { return new(id, SecurityOperationState.Unknown, null, []); }
    }
    public async Task FinishAsync(SecurityOperationRequestContext context, int status, bool failed)
    {
        if (!context.Admitted || context.OperationId is not Guid id) return;
        using var budget = Budget(CancellationToken.None, _settings.ReconciliationSeconds);
        try { await _repo.CompleteRequestAsync(id, status, failed, budget.Token); }
        catch { /* A lost final envelope is reconciled from the durable child receipts. */ }
    }
    internal async Task<SecurityOperationStatus> FailAsync(SecurityOperationRequestContext context)
    {
        await FinishAsync(context, 503, true);
        return await ReconcileAsync(context.OperationId!.Value);
    }
    public async Task<int> PurgeAsync(CancellationToken caller)
    {
        using var budget = Budget(caller, _settings.ReconciliationSeconds);
        return await _repo.PurgeAsync(_settings.CleanupBatchSize, budget.Token);
    }
}

public sealed class SecurityOperationScope : IAsyncDisposable
{
    private readonly SecurityOperationService _service;
    private readonly SecurityOperationRequestContext _context;
    private readonly CancellationTokenSource _budget;
    private readonly string _step;
    private readonly byte[] _hmac;
    private readonly Guid? _stamp;
    private readonly string? _version;
    private bool _committed;
    private bool _commitAttempted;
    public NpgsqlConnection Connection { get; }
    public NpgsqlTransaction Transaction { get; }
    public CancellationToken CancellationToken => _budget.Token;
    internal SecurityOperationScope(SecurityOperationService service, SecurityOperationRequestContext context,
        NpgsqlConnection connection, NpgsqlTransaction transaction, CancellationTokenSource budget,
        string step, byte[] hmac, Guid? stamp, string? version)
    { _service=service; _context=context; Connection=connection; Transaction=transaction; _budget=budget; _step=step; _hmac=hmac; _stamp=stamp; _version=version; }
    public async Task CommitAsync(object outcome)
    {
        SecurityOperationOutcome safe = SecurityOperationOutcome.From(outcome);
        await using (var receipt = new NpgsqlCommand("""
            with receipt as (
                insert into security_operation_steps(operation_id,step_key,request_hmac,expected_account_stamp,expected_version,outcome_code,succeeded)
                values(@id,@step,@hmac,@stamp,@version,@code,@success) returning operation_id
            )
            update security_operations s set account_id=s.account_id from receipt r
            where s.operation_id=r.operation_id and s.state='Pending' and s.execute_before>clock_timestamp()
            """, Connection, Transaction))
        {
            receipt.Parameters.AddWithValue("id", _context.OperationId!.Value); receipt.Parameters.AddWithValue("step", _step);
            receipt.Parameters.AddWithValue("hmac", _hmac);
            receipt.Parameters.Add("stamp", NpgsqlDbType.Uuid).Value = (object?)_stamp ?? DBNull.Value;
            receipt.Parameters.Add("version", NpgsqlDbType.Text).Value = (object?)_version ?? DBNull.Value;
            receipt.Parameters.AddWithValue("code", safe.Code);
            receipt.Parameters.Add("success", NpgsqlDbType.Boolean).Value = (object?)safe.Succeeded ?? DBNull.Value;
            int writes = await receipt.ExecuteNonQueryAsync(CancellationToken);
            if (writes != 1) throw new SecurityOperationException("SECURITY_OPERATION_DEADLINE", 503);
        }
        _commitAttempted = true;
        try { await Transaction.CommitAsync(CancellationToken); _committed = true; }
        catch (Exception)
        {
            // DisposeAsync releases this connection and then reconciles. Do not
            // acquire a second connection while holding a saturated pool slot.
            throw new SecurityOperationException("SECURITY_OPERATION_UNKNOWN", 503,
                new(_context.OperationId!.Value, SecurityOperationState.Unknown, null, []));
        }
    }
    public async ValueTask DisposeAsync()
    {
        Exception? cleanupFault = null;
        if (!_committed && Transaction.Connection is not null)
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            try { await Transaction.RollbackAsync(cleanup.Token); } catch (Exception ex) { cleanupFault = ex; }
        }
        try { await Transaction.DisposeAsync(); } catch (Exception ex) { cleanupFault = ex; }
        try { await Connection.DisposeAsync(); } catch (Exception ex) { cleanupFault ??= ex; }
        _budget.Dispose();
        if (!_committed)
        {
            // A successful rollback before COMMIT plus the terminal operation
            // gate proves no later participant can mutate. After attempted
            // COMMIT, only durable receipts can establish the outcome.
            var status = _commitAttempted || cleanupFault is not null
                ? await _service.ReconcileAsync(_context.OperationId!.Value)
                : await _service.FailAsync(_context);
            throw SecurityOperationException.Outcome(status);
        }
        if (SecurityOperationRequestContext.Current is null)
            await _service.FinishAsync(_context, 200, false);
    }
}
