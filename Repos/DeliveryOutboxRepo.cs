using treehammock.Rigging.Dependencies;
using Npgsql;
using NpgsqlTypes;
using NodaTime;
using treehammock.Rigging.Database;
using treehammock.Rigging.Delivery;
using treehammock.Rigging.Config;
using Microsoft.Extensions.Options;

namespace treehammock.Repos;

public sealed class DeliveryOutboxRepo(StorageContext storage, IOptions<DeliveryOutboxSettings> options)
{
    private readonly DeliveryOutboxSettings _settings = options.Value;
    public static async Task<DeliveryStageResult> StageInAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        ProtectedDelivery d, CancellationToken token)
    {
        await using var command=new NpgsqlCommand("select result,code,delivery_id from cor12_stage_delivery(@id,@account,@stamp,@purpose,@hash,@expires,@metadata,@key,@nonce,@cipher,@tag,@noticeId,@noticeKey,@noticeNonce,@noticeCipher,@noticeTag,@noticeMetadata)",connection,transaction);
        command.Parameters.AddWithValue("id",d.Id); command.Parameters.AddWithValue("account",d.AccountId);
        command.Parameters.AddWithValue("stamp",d.AccountStamp); command.Parameters.AddWithValue("purpose",d.Purpose);
        command.Parameters.AddWithValue("hash",d.ProofHash); command.Parameters.Add("expires",NpgsqlDbType.TimestampTz).Value=d.ExpiresAt;
        command.Parameters.Add("metadata",NpgsqlDbType.Text).Value=d.MetadataJson; command.Parameters.AddWithValue("key",d.KeyVersion);
        command.Parameters.AddWithValue("nonce",d.Nonce); command.Parameters.AddWithValue("cipher",d.Ciphertext); command.Parameters.AddWithValue("tag",d.Tag);
        var notice=d.Companion;
        if (notice is not null && (d.Purpose!="email" || notice.Purpose!="email-notice" || notice.AccountId!=d.AccountId || notice.AccountStamp!=d.AccountStamp || notice.ProofHash!=d.ProofHash || notice.ExpiresAt!=d.ExpiresAt || notice.Companion is not null))
            throw new InvalidOperationException("Invalid email notification binding");
        command.Parameters.Add("noticeId",NpgsqlDbType.Uuid).Value=(object?)notice?.Id ?? DBNull.Value;
        command.Parameters.Add("noticeKey",NpgsqlDbType.Integer).Value=(object?)notice?.KeyVersion ?? DBNull.Value;
        command.Parameters.Add("noticeNonce",NpgsqlDbType.Bytea).Value=(object?)notice?.Nonce ?? DBNull.Value;
        command.Parameters.Add("noticeCipher",NpgsqlDbType.Bytea).Value=(object?)notice?.Ciphertext ?? DBNull.Value;
        command.Parameters.Add("noticeTag",NpgsqlDbType.Bytea).Value=(object?)notice?.Tag ?? DBNull.Value;
        command.Parameters.Add("noticeMetadata",NpgsqlDbType.Text).Value=(object?)notice?.MetadataJson ?? DBNull.Value;
        await using var reader=await command.ExecuteReaderAsync(token);
        if(!await reader.ReadAsync(token)) throw new InvalidOperationException("Invalid delivery stage response");
        var result = new DeliveryStageResult(reader.GetBoolean(0),reader.GetString(1),reader.IsDBNull(2)?null:reader.GetGuid(2));
        await reader.DisposeAsync();
        if (result.Result && d.Purpose is "factor-1" or "factor-2")
        {
            await using var binding = new NpgsqlCommand("select setup_request_id,setup_version from two_factor_authentications where account_id=@account and setup_request_id=@request and not verified and revoked_at is null",connection,transaction);
            binding.Parameters.AddWithValue("account",d.AccountId);binding.Parameters.AddWithValue("request",result.DeliveryId ?? Guid.Empty);
            await using var row = await binding.ExecuteReaderAsync(token);
            if (!await row.ReadAsync(token)) throw new InvalidOperationException("Missing factor setup binding");
            result = result with { EnrollmentId=row.GetGuid(0),SetupVersion=row.GetInt64(1) };
        }
        return result;
    }
    public async Task<DeliveryStageResult> StageAsync(ProtectedDelivery d,CancellationToken token)
    {
        await using var op=await storage.SecurityOperations.BeginAsync("DeliveryOutboxRepo.Stage",d,d.AccountId,d.AccountStamp,d.Id.ToString("D"),token);
        var result=await StageInAsync(op.Connection,op.Transaction,d,op.CancellationToken);
        await op.CommitAsync(result); return result;
    }
    public async Task<DeliveryAccount?> FindAccountAsync(string email,CancellationToken token)
    {
        using var budget=CancellationTokenSource.CreateLinkedTokenSource(token);
        budget.CancelAfter(TimeSpan.FromSeconds(5));
        CancellationToken operationToken=budget.Token;
        try
        {
        await using var connection=await storage.CreateConnection(operationToken);
        await using var command=new NpgsqlCommand("select account_id,security_stamp,email_address,verify_status from accounts where lower(email_address)=lower(@email)",connection);
        command.Parameters.AddWithValue("email",email);
        await using var reader=await command.ExecuteReaderAsync(operationToken);
        return await reader.ReadAsync(operationToken)?new(reader.GetGuid(0),reader.GetGuid(1),reader.GetString(2),reader.GetInt16(3)):null;

        }
        catch(OperationCanceledException) when(token.IsCancellationRequested) { throw; }
        catch(Exception error) { throw DependencyUnavailableException.Database("delivery_FindAccountAsync",DependencyStage.Execute,error); }
    }
    public async Task<bool> IsPendingAsync(string purpose,string hash,CancellationToken token,Guid? accountId=null)
    {
        using var budget=CancellationTokenSource.CreateLinkedTokenSource(token);
        budget.CancelAfter(TimeSpan.FromSeconds(5));
        CancellationToken operationToken=budget.Token;
        try
        {
        await using var connection=await storage.CreateConnection(operationToken);
        await using var command=new NpgsqlCommand("select cor12_delivery_is_pending(@purpose,@hash,@account)",connection);
        command.Parameters.AddWithValue("purpose",purpose);command.Parameters.AddWithValue("hash",hash);
        command.Parameters.Add("account",NpgsqlDbType.Uuid).Value=(object?)accountId??DBNull.Value;
        return (bool)(await command.ExecuteScalarAsync(operationToken))!;

        }
        catch(OperationCanceledException) when(token.IsCancellationRequested) { throw; }
        catch(Exception error) { throw DependencyUnavailableException.Database("delivery_IsPendingAsync",DependencyStage.Execute,error); }
    }
    public async Task<Guid?> ExistingAsync(Guid accountId,Guid stamp,string purpose,CancellationToken token)
    {
        using var budget=CancellationTokenSource.CreateLinkedTokenSource(token);
        budget.CancelAfter(TimeSpan.FromSeconds(5));
        CancellationToken operationToken=budget.Token;
        try
        {
        await using var connection=await storage.CreateConnection(operationToken);
        await using var command=new NpgsqlCommand("select c.delivery_id from delivery_candidates c join delivery_outbox o using(delivery_id) join accounts a using(account_id) where c.account_id=@account and c.account_stamp=@stamp and a.security_stamp=@stamp and c.purpose=@purpose and c.state='staged' and o.state in ('claimed','accepted','ambiguous') and c.expires_at>clock_timestamp()",connection);
        command.Parameters.AddWithValue("account",accountId); command.Parameters.AddWithValue("stamp",stamp); command.Parameters.AddWithValue("purpose",purpose);
        return await command.ExecuteScalarAsync(operationToken) is Guid id ? id : null;

        }
        catch(OperationCanceledException) when(token.IsCancellationRequested) { throw; }
        catch(Exception error) { throw DependencyUnavailableException.Database("delivery_ExistingAsync",DependencyStage.Execute,error); }
    }
    public async Task<DeliveryJob?> ClaimAsync(CancellationToken token)
    {
        using var budget=CancellationTokenSource.CreateLinkedTokenSource(token);
        budget.CancelAfter(TimeSpan.FromSeconds(5));
        CancellationToken operationToken=budget.Token;
        try
        {
        await using var connection=await storage.CreateConnection(operationToken);
        await using var transaction=await connection.BeginTransactionAsync(operationToken);
        await using var command=new NpgsqlCommand("select * from cor12_claim_delivery(@lease,@seconds,@attempts)",connection,transaction);
        Guid lease=Guid.NewGuid(); command.Parameters.AddWithValue("lease",lease);
        command.Parameters.AddWithValue("seconds",_settings.LeaseSeconds);command.Parameters.AddWithValue("attempts",_settings.MaxAttempts);
        await using var reader=await command.ExecuteReaderAsync(operationToken);
        DeliveryJob? job=null;
        if(await reader.ReadAsync(operationToken))
        {
            var delivery=new ProtectedDelivery(reader.GetGuid(0),reader.GetGuid(1),reader.GetGuid(2),reader.GetString(3),reader.GetString(4),
                reader.GetFieldValue<Instant>(5),reader.GetString(6),reader.GetInt32(7),(byte[])reader[8],(byte[])reader[9],(byte[])reader[10]);
            job=new(delivery,reader.GetString(11),reader.IsDBNull(12)?null:reader.GetGuid(12),reader.GetInt32(13));
        }
        await reader.DisposeAsync();await transaction.CommitAsync(operationToken);return job;

        }
        catch(OperationCanceledException) when(token.IsCancellationRequested) { throw; }
        catch(Exception error) { throw DependencyUnavailableException.Database("delivery_ClaimAsync",DependencyStage.Execute,error); }
    }
    public async Task<bool> CanSendAsync(DeliveryJob job,CancellationToken token)
    {
        using var budget=CancellationTokenSource.CreateLinkedTokenSource(token);budget.CancelAfter(TimeSpan.FromSeconds(5));
        try
        {
            await using var connection=await storage.CreateConnection(budget.Token);
            await using var command=new NpgsqlCommand("select cor23j_delivery_can_send(@id,@lease)",connection);
            command.Parameters.AddWithValue("id",job.Delivery.Id);command.Parameters.AddWithValue("lease",job.LeaseId!.Value);
            return await command.ExecuteScalarAsync(budget.Token) is true;
        }
        catch(OperationCanceledException) when(token.IsCancellationRequested){throw;}
        catch(Exception error){throw DependencyUnavailableException.Database("delivery_CanSendAsync",DependencyStage.Execute,error);}
    }
    public async Task<bool> RecordAsync(DeliveryJob job,DeliverySendResult result,CancellationToken token)
    {
        result=result.Normalize();
        using var budget=CancellationTokenSource.CreateLinkedTokenSource(token);
        budget.CancelAfter(TimeSpan.FromSeconds(5));
        CancellationToken operationToken=budget.Token;
        try
        {
        await using var connection=await storage.CreateConnection(operationToken);await using var transaction=await connection.BeginTransactionAsync(operationToken);
        await using var command=new NpgsqlCommand("select cor12_record_delivery(@id,@lease,@state,@max,@provider,@receipt,@retry,@code)",connection,transaction);
        command.Parameters.AddWithValue("id",job.Delivery.Id);command.Parameters.AddWithValue("lease",job.LeaseId!.Value);
        command.Parameters.AddWithValue("state",result.State==DeliverySendState.NotSubmitted?"not_submitted":result.State.ToString().ToLowerInvariant());command.Parameters.AddWithValue("max",_settings.MaxAttempts);
        command.Parameters.AddWithValue("provider",result.Provider);command.Parameters.Add("receipt",NpgsqlDbType.Text).Value=(object?)result.ReceiptId??DBNull.Value;
        command.Parameters.AddWithValue("retry",result.CanRetry);command.Parameters.AddWithValue("code",result.Code);
        object? recorded=await command.ExecuteScalarAsync(operationToken);
        if(recorded is not bool valid)throw DependencyUnavailableException.InvalidResponse("delivery_RecordAsync");
        await transaction.CommitAsync(operationToken);
        return valid;

        }
        catch(OperationCanceledException) when(token.IsCancellationRequested) { throw; }
        catch(Exception error) { throw DependencyUnavailableException.Database("delivery_RecordAsync",DependencyStage.Execute,error); }
    }
    public async Task<bool> PublishAsync(Guid jobId,CancellationToken token)
    {
        using var budget=CancellationTokenSource.CreateLinkedTokenSource(token);
        budget.CancelAfter(TimeSpan.FromSeconds(5));
        CancellationToken operationToken=budget.Token;
        try
        {
        await using var connection=await storage.CreateConnection(operationToken);await using var transaction=await connection.BeginTransactionAsync(operationToken);
        await using var command=new NpgsqlCommand("select cor12_publish_delivery(@id)",connection,transaction);
        command.Parameters.AddWithValue("id",jobId);
        object? value=await command.ExecuteScalarAsync(operationToken);
        if(value is not bool published)throw DependencyUnavailableException.InvalidResponse("delivery_PublishAsync");
        await transaction.CommitAsync(operationToken);return published;

        }
        catch(OperationCanceledException) when(token.IsCancellationRequested) { throw; }
        catch(Exception error) { throw DependencyUnavailableException.Database("delivery_PublishAsync",DependencyStage.Execute,error); }
    }
}
