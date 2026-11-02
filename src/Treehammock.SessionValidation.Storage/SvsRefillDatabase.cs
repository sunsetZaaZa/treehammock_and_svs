using System.Data;
using Npgsql;
using NpgsqlTypes;
namespace Treehammock.SessionValidation.Storage;

internal sealed class SvsRefillDatabase : IAuthorityProjectionLeaseFactory,IAsyncDisposable
{
    private readonly NpgsqlDataSource _source;
    private readonly SessionAuthorityBackend _backend;
    private readonly string _schema,_login,_roles;
    internal static string Policy {get{using var stream=typeof(SvsRefillDatabase).Assembly.GetManifestResourceStream("Treehammock.SessionValidation.Storage.PublicationDatabasePolicy.json")??throw new InvalidOperationException("Missing publication policy.");using var reader=new StreamReader(stream);return reader.ReadToEnd();}}
    internal SvsRefillDatabase(string connectionString,IReadOnlyDictionary<string,string> roles,SessionAuthorityBackend backend,string schema)
    {
        string[] kinds=["App","Coordinator","Validator","Refiller","Maintenance","Owner","ValidatorRead"];
        if(roles.Count!=kinds.Length||kinds.Any(k=>!roles.ContainsKey(k))||roles.Values.Distinct(StringComparer.Ordinal).Count()!=kinds.Length||roles.Values.Any(x=>!System.Text.RegularExpressions.Regex.IsMatch(x,"^[a-z][a-z0-9_]{0,62}$")||x.StartsWith("pg_",StringComparison.Ordinal)||x.StartsWith("yb_",StringComparison.Ordinal))||roles["ValidatorRead"]!="treehammock_svs_read")throw new ArgumentException("Complete distinct named SQL roles required.");
        if(!System.Text.RegularExpressions.Regex.IsMatch(schema,"^[a-z][a-z0-9_]{0,62}$")||schema.StartsWith("pg_",StringComparison.Ordinal)||schema=="information_schema")throw new ArgumentException("Explicit trusted projection schema required.");
        var settings=new NpgsqlConnectionStringBuilder(connectionString);
        if(settings.Username!=roles["Refiller"]||settings.SslMode!=SslMode.VerifyFull||settings.MaxPoolSize is <1 or >8||settings.MinPoolSize!=0||settings.SearchPath!=schema+",pg_catalog,pg_temp"||backend is not (SessionAuthorityBackend.Yugabyte or SessionAuthorityBackend.PostgreSqlLocal))throw new ArgumentException("Dedicated bounded verified-TLS refill pool required.");
        _source=YsqlAuthorityDataSource.Create(connectionString);_login=roles["Refiller"];_roles=System.Text.Json.JsonSerializer.Serialize(roles);_backend=backend;_schema=new NpgsqlCommandBuilder().QuoteIdentifier(schema)+".";
    }
    private async Task<NpgsqlConnection> OpenAsync(CancellationToken token)
    {
        if(System.Transactions.Transaction.Current is not null)throw new InvalidOperationException("Ambient refill transactions forbidden.");
        var connection=await _source.OpenConnectionAsync(token);
        try
        {
            await using var command=new NpgsqlCommand("select current_user=@login and session_user=@login and "+_schema+"ths_database_role_safe('Refiller',@policy) and (select roles=@roles from "+_schema+"ths_database_role_configuration where singleton)",connection){CommandTimeout=3};
            command.Parameters.AddWithValue("login",_login);command.Parameters.AddWithValue("policy",NpgsqlDbType.Jsonb,Policy);command.Parameters.AddWithValue("roles",NpgsqlDbType.Jsonb,_roles);
            if(await command.ExecuteScalarAsync(token) is not true)throw new InvalidOperationException("Unsafe actual refill SQL identity.");return connection;
        }
        catch{await connection.DisposeAsync();throw;}
    }
    internal async Task<Guid?> ResolveAccountAsync(string hash,CancellationToken token)
    {
        if(!YsqlSessionAuthority.IsHash(hash))throw new ArgumentException("Full credential hash required.");await using var connection=await OpenAsync(token);
        await using var command=new NpgsqlCommand("select "+_schema+"ths_svs_refill_route(@hash)",connection){CommandTimeout=3};command.Parameters.AddWithValue("hash",hash);
        return await command.ExecuteScalarAsync(token) is Guid account&&account!=Guid.Empty?account:null;
        // Dispose routing connection BEFORE acquiring the locked projection lease.
    }
    internal async Task<IReadOnlyList<string>> ReadCandidateHashesAsync(string? after,int limit,CancellationToken token)
    {
        if(limit is <1 or >1000||after is not null&&!YsqlSessionAuthority.IsHash(after))throw new ArgumentException("Bounded keyset scan required.");
        await using var connection=await OpenAsync(token);await using var command=new NpgsqlCommand("select credential_hash from "+_schema+"ths_svs_refill_candidates(@after,@limit)",connection){CommandTimeout=3};command.Parameters.AddWithValue("after",NpgsqlDbType.Text,(object?)after??DBNull.Value);command.Parameters.AddWithValue("limit",limit);
        await using var reader=await command.ExecuteReaderAsync(token);var result=new List<string>(limit);while(await reader.ReadAsync(token)){if(result.Count>=limit)throw new DataException("Unbounded refill candidates.");var hash=reader.GetString(0);if(!YsqlSessionAuthority.IsHash(hash))throw new DataException("Invalid refill candidate.");result.Add(hash);}return result;
    }
    public ValueTask DisposeAsync()=>_source.DisposeAsync();
    public override string ToString()=>nameof(SvsRefillDatabase);
    public async Task<IAuthorityProjectionLease> AcquireAsync(Guid account,TimeSpan budget,CancellationToken token)
    {
        if(System.Transactions.Transaction.Current is not null)throw new InvalidOperationException("Ambient projection transactions forbidden.");
        var connection=await OpenAsync(token);NpgsqlTransaction? tx=null;
        try
        {
            tx=await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted,token);
            await using(var setup=new NpgsqlCommand("set local lock_timeout = '"+Math.Max(1,(int)budget.TotalMilliseconds)+"ms'; set local statement_timeout = '"+Math.Max(1,(int)budget.TotalMilliseconds)+"ms';"+
                (_backend==SessionAuthorityBackend.Yugabyte?"set local yb_read_from_followers=off;":""),connection,tx))
                await setup.ExecuteNonQueryAsync(token);
            if(_backend==SessionAuthorityBackend.PostgreSqlLocal)
            { await using var primary=new NpgsqlCommand("select pg_is_in_recovery()",connection,tx);if((bool)(await primary.ExecuteScalarAsync(token))!)throw new InvalidOperationException("Local projection database is a standby."); }
            else if(_backend!=SessionAuthorityBackend.Yugabyte)throw new InvalidOperationException("Unsupported projection backend.");
            AuthorityVersion? version=null;
            await using(var command=new NpgsqlCommand("select revision,lifecycle from "+_schema+"ths_svs_refill_lock(@account)",connection,tx))
            {
                command.Parameters.AddWithValue("account",account);await using var reader=await command.ExecuteReaderAsync(token);
                if(await reader.ReadAsync(token))version=new(account,new(reader.GetInt64(0)),reader.GetString(1));
            }
            return new Lease(connection,tx,account,version,_schema);
        }
        catch { if(tx is not null)await tx.DisposeAsync();await connection.DisposeAsync();throw; }
    }
    private sealed class Lease(NpgsqlConnection connection,NpgsqlTransaction transaction,Guid account,AuthorityVersion? version,string schema) : IAuthorityProjectionLease
    {
        public AuthorityVersion? Authority { get; }=version;
        public async Task<ProjectionCandidate> ReadCurrentAsync(string expectedHash,CancellationToken token)
        {
            // Exactly one fresh post-lock statement supplies candidate hash and all
            // shared 17-column authority facts. The routing hash alone is never authority.
            await using var command=new NpgsqlCommand("select r.*,s.access_token_hash as candidate_hash from "+schema+
                "sessions s left join lateral "+schema+"svs_read_current_session(s.access_token_hash) r on true where s.account_id=@account and s.access_token_hash=@hash",connection,transaction);
            command.Parameters.AddWithValue("account",NpgsqlDbType.Uuid,account);command.Parameters.AddWithValue("hash",NpgsqlDbType.Text,expectedHash);await using var reader=await command.ExecuteReaderAsync(token);
            if(!await reader.ReadAsync(token))return new(null,null);
            CurrentSessionRow? row=null;
            try
            {
                string hash=reader.GetString(17);if(!reader.IsDBNull(0))row=NpgsqlSnapshotExecutor.ReadRow(reader);
                if(await reader.ReadAsync(token))throw new DataException("Ambiguous current session family.");
                return new(hash,row);
            }
            catch { row?.Dispose();throw; }
        }
        public async ValueTask DisposeAsync()
        {
            // Read/lock transaction only. Release after the owning publisher finishes;
            // no revision or domain mutation is committed by building a projection.
            try { await transaction.DisposeAsync(); } finally { await connection.DisposeAsync(); }
        }
    }
}
