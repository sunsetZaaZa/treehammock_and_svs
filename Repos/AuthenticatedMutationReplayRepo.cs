using System.Security.Cryptography;
using Npgsql;
using NpgsqlTypes;
using treehammock.DataLayer.Operations;
using treehammock.Rigging.Config;
using treehammock.Rigging.Database;
using treehammock.Rigging.Operations;
using treehammock.Rigging.Replay;

namespace treehammock.Repos;

/// <summary>Immutable idempotency binding, joined to the COR04 mutation gate/receipts.</summary>
public sealed class AuthenticatedMutationReplayRepo(StorageContext storage, AuthenticatedMutationIdempotencySettings settings)
{
    private sealed record Row(byte[] Hmac, int Version, Guid Stamp, Guid Operation, Guid Owner,
        bool Alive, bool ReplayAlive, bool Completed, int? Status, string? Code, string? Response);
    public async Task<AuthenticatedMutationIdempotencyBeginResult> BeginAsync(
        AuthenticatedMutationIdempotencyRequest request, string key, CancellationToken caller)
    {
        var context = SecurityOperationRequestContext.Current!;
        var operations = storage.SecurityOperations;
        var operationSettings = operations.Settings;
        byte[] identity = AuthenticatedMutationCanonicalRequest.Identity(request.AccountId, request.Method, request.Route, key);
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(caller);
        budget.CancelAfter(TimeSpan.FromSeconds(operationSettings.ExecutionSeconds));
        await context.Admission.WaitAsync(budget.Token);
        try
        {
            await using var connection = await storage.CreateConnection(budget.Token);
            // Normal HTTP JWT trust has already run. Recheck the current account epoch before
            // any historical response is read; cache state alone never authorizes replay.
            if (!await CurrentAuthority(connection, request, budget.Token))
                return Result(AuthenticatedMutationIdempotencyStatus.AuthorityChanged, AuthenticatedMutationIdempotencyConstants.AuthorityChangedCode);
            var row = await Read(connection, identity, budget.Token);
            if (row is not null) return Existing(row, request, identity, operations);
            if (context.ClientKey is null || context.RecoveryKey is null)
                throw new SecurityOperationException("SECURITY_OPERATION_KEYS_REQUIRED", 428);
            var operationKey = SecurityOperationKey.Parse(context.ClientKey, operationSettings.RetentionSeconds);
            if (context.OperationId is Guid prior && prior != operationKey.Id)
                throw new SecurityOperationException("SECURITY_OPERATION_CONFLICT", 409);
            context.OperationId = operationKey.Id;
            context.RecoveryBytes ??= SecurityOperationKey.ParseRecoveryKey(context.RecoveryKey);
            int version = operationSettings.ActiveKeyVersion;
            byte[] mac = operations.Mac(version, "authenticated-replay:request", identity, request.CanonicalRequest!);
            Guid owner = Guid.NewGuid();
            DateTimeOffset expires = operationKey.IssuedAt.AddSeconds(operationSettings.RetentionSeconds);
            DateTimeOffset execute = DateTimeOffset.UtcNow.AddSeconds(operationSettings.ExecutionSeconds);
            if (execute >= expires) execute = expires.AddMilliseconds(-1);
            var binding = operations.Binding(context, operationKey, version);
            await using (var transaction = await connection.BeginTransactionAsync(budget.Token))
            {
                await Bounds(connection, transaction, operationSettings.LockSeconds, operationSettings.ExecutionSeconds, budget.Token);
                // Lock order is COR04 operation -> replay row. Competing INSERT identities
                // serialize on the unique constraint; a loser rolls back its unused new root.
                if (!context.Admitted)
                {
                    await using var reserve = new NpgsqlCommand("""
                        insert into security_operations(operation_id,request_hmac,recovery_hmac,hmac_version,purpose,account_id,issued_at,execute_before,expires_at)
                        values(@id,@request,@recovery,@version,@purpose,@account,@issued,@execute,@expires)
                        on conflict(operation_id) do nothing
                        """, connection, transaction);
                    reserve.Parameters.AddWithValue("id", operationKey.Id);
                    reserve.Parameters.AddWithValue("request", binding.RequestHmac); reserve.Parameters.AddWithValue("recovery", binding.RecoveryHmac);
                    reserve.Parameters.AddWithValue("version", version);
                    reserve.Parameters.AddWithValue("purpose", "request:" + Convert.ToHexString(operations.Mac(version, "purpose", System.Text.Encoding.UTF8.GetBytes(context.Purpose))));
                    reserve.Parameters.AddWithValue("account", request.AccountId);
                    reserve.Parameters.AddWithValue("issued", operationKey.IssuedAt.UtcDateTime);
                    reserve.Parameters.AddWithValue("execute", execute.UtcDateTime); reserve.Parameters.AddWithValue("expires", expires.UtcDateTime);
                    if (await reserve.ExecuteNonQueryAsync(budget.Token) != 1)
                    {
                        await transaction.RollbackAsync(budget.Token);
                        // Never claim ownership of an existing root merely because the cache is empty.
                        await using var existing = new NpgsqlCommand("select request_hmac,recovery_hmac,hmac_version from security_operations where operation_id=@id", connection);
                        existing.Parameters.AddWithValue("id", operationKey.Id);
                        await using var reader = await existing.ExecuteReaderAsync(budget.Token);
                        if (await reader.ReadAsync(budget.Token))
                        {
                            var existingBinding = new SecurityOperationBinding(reader.GetFieldValue<byte[]>(0),reader.GetFieldValue<byte[]>(1),reader.GetInt32(2));
                            treehammock.Services.SecurityOperationService.ValidateBinding(existingBinding,
                                operations.Binding(context, operationKey, existingBinding.KeyVersion));
                        }
                        return Result(AuthenticatedMutationIdempotencyStatus.RecoveryRequired,
                            AuthenticatedMutationIdempotencyConstants.RecoveryRequiredCode, operationKey.Id);
                    }
                }
                await using (var gate = new NpgsqlCommand("select lock_security_operation(@id,@account)", connection, transaction))
                {
                    gate.Parameters.AddWithValue("id", operationKey.Id); gate.Parameters.AddWithValue("account", request.AccountId);
                    await gate.ExecuteNonQueryAsync(budget.Token);
                }
                await using var insert = new NpgsqlCommand("""
                    insert into authenticated_mutation_replays(identity_digest,request_hmac,hmac_version,account_id,expected_account_stamp,
                        operation_id,owner_token,expires_at,replay_until)
                    select @identity,@request,@version,@account,@stamp,operation_id,@owner,expires_at,
                        least(expires_at,clock_timestamp()+make_interval(secs=>@replay))
                    from security_operations where operation_id=@id
                    on conflict(identity_digest) do nothing
                    """, connection, transaction);
                insert.Parameters.AddWithValue("identity", identity); insert.Parameters.AddWithValue("request", mac);
                insert.Parameters.AddWithValue("version", version); insert.Parameters.AddWithValue("account", request.AccountId);
                insert.Parameters.AddWithValue("stamp", request.AccountSecurityStamp!.Value); insert.Parameters.AddWithValue("id", operationKey.Id);
                insert.Parameters.AddWithValue("owner", owner); insert.Parameters.AddWithValue("replay", Math.Clamp(settings.CompletedTtlSeconds, 1, 900));
                if (await insert.ExecuteNonQueryAsync(budget.Token) != 1)
                {
                    await transaction.RollbackAsync(budget.Token);
                    row = await Read(connection, identity, budget.Token);
                    return row is null ? AuthenticatedMutationIdempotencyBeginResult.StoreUnavailableResult()
                        : Existing(row, request, identity, operations);
                }
                try { await transaction.CommitAsync(budget.Token); }
                catch (Exception) { throw new SecurityOperationException("SECURITY_OPERATION_UNKNOWN", 503,
                    new(operationKey.Id, SecurityOperationState.Unknown, null, [])); }
            }
            context.Admitted = true;
            return AuthenticatedMutationIdempotencyBeginResult.StartedResult(new(
                DragonflyAuthenticatedMutationIdempotencyService.BuildCacheKey(request.AccountId, request.Method, request.Route, key),
                owner.ToString("N"), Guid.NewGuid().ToString("N"), Convert.ToHexString(mac), operationKey.Id, identity));
        }
        finally { context.Admission.Release(); }
    }
    private static async Task<bool> CurrentAuthority(NpgsqlConnection connection, AuthenticatedMutationIdempotencyRequest request, CancellationToken token)
    {
        await using var command = new NpgsqlCommand("select exists(select 1 from accounts where account_id=@account and security_stamp=@stamp)", connection);
        command.Parameters.AddWithValue("account", request.AccountId); command.Parameters.AddWithValue("stamp", request.AccountSecurityStamp!.Value);
        return (bool)(await command.ExecuteScalarAsync(token))!;
    }
    private static async Task<Row?> Read(NpgsqlConnection connection, byte[] identity, CancellationToken token)
    {
        await using var command = new NpgsqlCommand("""
            select request_hmac,hmac_version,expected_account_stamp,operation_id,owner_token,
                expires_at>clock_timestamp(),replay_until>clock_timestamp(),completed_at is not null,
                response_status,response_code,safe_response
            from authenticated_mutation_replays where identity_digest=@identity
            """, connection);
        command.Parameters.AddWithValue("identity", identity);
        await using var reader = await command.ExecuteReaderAsync(token);
        return await reader.ReadAsync(token) ? new(reader.GetFieldValue<byte[]>(0),reader.GetInt32(1),reader.GetGuid(2),
            reader.GetGuid(3),reader.GetGuid(4),reader.GetBoolean(5),reader.GetBoolean(6),reader.GetBoolean(7),
            reader.IsDBNull(8)?null:reader.GetInt32(8),reader.IsDBNull(9)?null:reader.GetString(9),reader.IsDBNull(10)?null:reader.GetString(10)) : null;
    }
    private static AuthenticatedMutationIdempotencyBeginResult Existing(Row row, AuthenticatedMutationIdempotencyRequest request,
        byte[] identity, treehammock.Services.SecurityOperationService operations)
    {
        if (row.Stamp != request.AccountSecurityStamp)
            return Result(AuthenticatedMutationIdempotencyStatus.AuthorityChanged, AuthenticatedMutationIdempotencyConstants.AuthorityChangedCode, row.Operation);
        byte[] hmac = operations.Mac(row.Version, "authenticated-replay:request", identity, request.CanonicalRequest!);
        if (!CryptographicOperations.FixedTimeEquals(hmac, row.Hmac))
            return Result(AuthenticatedMutationIdempotencyStatus.ContentConflict, AuthenticatedMutationIdempotencyConstants.ContentConflictCode, row.Operation);
        if (!row.Alive) return Result(AuthenticatedMutationIdempotencyStatus.Expired, AuthenticatedMutationIdempotencyConstants.ExpiredCode, row.Operation);
        if (row.Completed && row.ReplayAlive && row.Response is not null)
            return new(AuthenticatedMutationIdempotencyStatus.ReplayCompleted, StoredResult: new(row.Status!.Value,row.Code!,row.Response), OperationId: row.Operation);
        return Result(AuthenticatedMutationIdempotencyStatus.RecoveryRequired, AuthenticatedMutationIdempotencyConstants.RecoveryRequiredCode, row.Operation);
    }
    private static AuthenticatedMutationIdempotencyBeginResult Result(AuthenticatedMutationIdempotencyStatus status, string reason, Guid? id = null)
        => new(status, ReasonCode: reason, OperationId: id);
    public async Task<bool> CompleteAsync(AuthenticatedMutationIdempotencyReservation owner,
        AuthenticatedMutationIdempotencyStoredResult result, CancellationToken caller)
    {
        if (owner.IdentityDigest is null || owner.OperationId == Guid.Empty || !Guid.TryParseExact(owner.ReservationToken,"N",out var token)) return false;
        if (result.StatusCode is < 100 or > 599 || !System.Text.RegularExpressions.Regex.IsMatch(result.Code,"^[A-Z0-9_]{1,96}$")
            || System.Text.Encoding.UTF8.GetByteCount(result.SafeResponse ?? "")>16384)
            throw new InvalidOperationException("Invalid safe idempotency outcome.");
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(caller);
        budget.CancelAfter(TimeSpan.FromSeconds(storage.SecurityOperations.Settings.ReconciliationSeconds));
        await using var connection = await storage.CreateConnection(budget.Token);
        await using var transaction = await connection.BeginTransactionAsync(budget.Token);
        await Bounds(connection, transaction, storage.SecurityOperations.Settings.LockSeconds,
            storage.SecurityOperations.Settings.ReconciliationSeconds, budget.Token);
        await using (var gate = new NpgsqlCommand("select lock_security_operation(@id,null)",connection,transaction))
        {
            gate.Parameters.AddWithValue("id",owner.OperationId);
            try { await gate.ExecuteNonQueryAsync(budget.Token); }
            catch (PostgresException ex) when (ex.SqlState == "P0404") { return false; }
        }
        await using var write = new NpgsqlCommand("""
            update authenticated_mutation_replays set completed_at=clock_timestamp(),response_status=@status,response_code=@code,safe_response=@body
            where identity_digest=@identity and operation_id=@id and owner_token=@owner and request_hmac=@request
                and completed_at is null and expires_at>clock_timestamp()
            """,connection,transaction);
        write.Parameters.AddWithValue("status",result.StatusCode); write.Parameters.AddWithValue("code",result.Code);
        write.Parameters.Add("body",NpgsqlDbType.Text).Value=(object?)result.SafeResponse??DBNull.Value;
        write.Parameters.AddWithValue("identity",owner.IdentityDigest); write.Parameters.AddWithValue("id",owner.OperationId);
        write.Parameters.AddWithValue("owner",token); write.Parameters.AddWithValue("request",Convert.FromHexString(owner.RequestHmac));
        if (await write.ExecuteNonQueryAsync(budget.Token)!=1) return false;
        await using (var fence = new NpgsqlCommand("""
            update security_operations set state=case when @failed then
                case when exists(select 1 from security_operation_steps where operation_id=@id) then 'PartiallyCommitted' else 'RolledBack' end
                else 'Committed' end,http_status=@status,finished_at=clock_timestamp()
            where operation_id=@id and state='Pending'
            """,connection,transaction))
        {
            fence.Parameters.AddWithValue("id",owner.OperationId); fence.Parameters.AddWithValue("failed",result.StatusCode>=500);
            fence.Parameters.AddWithValue("status",result.StatusCode);
            if (await fence.ExecuteNonQueryAsync(budget.Token)!=1) return false;
        }
        try { await transaction.CommitAsync(budget.Token); }
        catch (Exception) { throw new SecurityOperationException("SECURITY_OPERATION_UNKNOWN",503,
            new(owner.OperationId,SecurityOperationState.Unknown,null,[])); }
        return true;
    }
    private static async Task Bounds(NpgsqlConnection connection, NpgsqlTransaction transaction, int locks, int statements, CancellationToken token)
    {
        await using var command = new NpgsqlCommand("select set_config('lock_timeout',@lock,true),set_config('statement_timeout',@statement,true)", connection, transaction);
        command.Parameters.AddWithValue("lock", (locks * 1000).ToString(System.Globalization.CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("statement", (statements * 1000).ToString(System.Globalization.CultureInfo.InvariantCulture));
        await command.ExecuteNonQueryAsync(token);
    }
}
