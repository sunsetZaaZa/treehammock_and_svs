using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Npgsql;
using NpgsqlTypes;
using treehammock.Rigging.Config;
using treehammock.Rigging.Database;
using treehammock.Rigging.Observability;
namespace treehammock.Rigging.Abuse;

// Each result is returned only after its independent admission transaction commits.
// No proof/account rows are touched; uncertain completion never authorizes work.
public sealed class PostgreSqlAbuseBudgetStore(StorageContext storage, IOptions<AbuseControlSettings> settings) : IPostgreSqlAbuseBudgetStore
{
    private readonly int _timeout = Math.Clamp(settings.Value.PostgreSqlBudgetTimeoutMilliseconds, 50, 5000);
    public static byte[] BudgetHash(AbuseCounterKey key) => SHA256.HashData(Encoding.UTF8.GetBytes("treehammock:abuse-budget:v1:" + key.Value));
    private static void Bind(NpgsqlCommand command, AbuseCounterKey key)
    {
        if (!AbuseCounterPolicyCatalog.SupportsPostgreSqlBudget(key)) throw new InvalidOperationException("Unsupported durable budget policy/dimension.");
        command.Parameters.AddWithValue("policy", NpgsqlDbType.Integer, (int)key.Feature);
        command.Parameters.AddWithValue("dimension", NpgsqlDbType.Integer, (int)key.Dimension);
        command.Parameters.AddWithValue("hash", NpgsqlDbType.Bytea, BudgetHash(key));
    }
    private async Task<T> Run<T>(Func<NpgsqlConnection,NpgsqlTransaction,CancellationToken,Task<T>> execute, CancellationToken token)
    {
        await using var connection = await storage.CreateConnection(token);
        await using var transaction = await connection.BeginTransactionAsync(token);
        await using (var limits = new NpgsqlCommand("select set_config('statement_timeout',@statement,true),set_config('lock_timeout',@lock,true)",connection,transaction))
        {
            limits.Parameters.AddWithValue("statement", _timeout.ToString(System.Globalization.CultureInfo.InvariantCulture));
            limits.Parameters.AddWithValue("lock", Math.Min(250,_timeout/2).ToString(System.Globalization.CultureInfo.InvariantCulture));
            await limits.ExecuteNonQueryAsync(token);
        }
        T result = await execute(connection,transaction,token);
        await transaction.CommitAsync(token);
        return result;
    }
    public async Task<CounterDecision> IncrementAsync(AbuseCounterKey key, AbuseCounterLimit limit, CancellationToken token)
    {
        var admission = await Run(async (connection,transaction,ct) =>
        {
            await using var command = new NpgsqlCommand("select admitted,attempts,retry_ms,reason,cooldown_started from cor23m_increment_budget_v1(@policy,@dimension,@hash,@maximum,@window,@cooldown)",connection,transaction);
            Bind(command,key);command.Parameters.AddWithValue("maximum",limit.MaxAttempts);
            command.Parameters.AddWithValue("window",(long)limit.Window.TotalMilliseconds);
            command.Parameters.AddWithValue("cooldown",(long)(limit.Cooldown?.TotalMilliseconds ?? 0));
            CounterDecision result;bool started;
            await using (var reader = await command.ExecuteReaderAsync(ct))
            {
                if (!await reader.ReadAsync(ct)) throw new InvalidOperationException("Durable budget result missing.");
                bool allowed=reader.GetBoolean(0);int count=reader.GetInt32(1);long retry=reader.GetInt64(2);int reason=reader.GetInt32(3);
                if (count<0 || retry<0 || reason is <0 or >2 || allowed && (count<1 || count>limit.MaxAttempts || reason!=0)) throw new InvalidOperationException("Invalid durable budget result.");
                result=new(allowed,count,limit.MaxAttempts,limit.Window,retry>0?TimeSpan.FromMilliseconds(retry):null,allowed?null:reason==1?AbuseReasonCodes.FailureCooldownActive:AbuseReasonCodes.CounterLimitExceeded,Availability: CounterStoreAvailability.Available);
                started=reader.GetBoolean(4);
                if (started && (allowed || reason != 2 || retry <= 0 || limit.Cooldown is null || limit.Cooldown == TimeSpan.Zero))
                    throw new InvalidOperationException("Invalid durable cooldown transition.");
                result = result with { CooldownCreated = started };
                if (await reader.ReadAsync(ct)) throw new InvalidOperationException("Duplicate durable budget result.");
            }
            return (Decision:result,Started:started);
        },token);
        if (admission.Started) AbuseOperationalTelemetry.RecordCooldownStarted(key.Feature,key.Dimension,AbuseReasonCodes.CounterLimitExceeded,"postgresql");
        return admission.Decision;
    }
    public Task<CooldownDecision> GetCooldownAsync(AbuseCounterKey key,CancellationToken token)
        => Run(async (connection,transaction,ct) =>
        {
            await using var command=new NpgsqlCommand("select cor23m_budget_cooldown_v1(@policy,@dimension,@hash)",connection,transaction);Bind(command,key);
            long retry=(long)(await command.ExecuteScalarAsync(ct) ?? throw new InvalidOperationException("Missing cooldown result."));
            if (retry<0) throw new InvalidOperationException("Invalid cooldown result.");
            return new CooldownDecision(retry>0,retry>0?TimeSpan.FromMilliseconds(retry):null,retry>0?AbuseReasonCodes.FailureCooldownActive:null);
        },token);
    public async Task ResetAsync(AbuseCounterKey key,CancellationToken token)
    {
        _ = await Run(async (connection,transaction,ct) =>
        {
            await using var command=new NpgsqlCommand("select cor23m_reset_budget_v1(@policy,@dimension,@hash)",connection,transaction);Bind(command,key);
            bool complete=(bool)(await command.ExecuteScalarAsync(ct) ?? throw new InvalidOperationException("Missing reset result."));
            if (!complete) throw new InvalidOperationException("Durable reset was not confirmed.");
            return complete;
        },token);
    }
    public Task<int> PurgeExpiredAsync(int batch,bool dryRun,CancellationToken token)
        => Run(async (connection,transaction,ct) =>
        {
            await using var command=new NpgsqlCommand("select cor23m_purge_budgets_v1(@batch,@dry)",connection,transaction);
            command.Parameters.AddWithValue("batch",Math.Clamp(batch,1,100));command.Parameters.AddWithValue("dry",dryRun);
            return (int)(await command.ExecuteScalarAsync(ct) ?? throw new InvalidOperationException("Missing cleanup result."));
        },token);
}
