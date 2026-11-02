using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Npgsql;
using StackExchange.Redis;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Rigging.Database;
using treehammock.Tests.SqlContracts.Support;
namespace treehammock.Tests.Integration.Database;

// Real PostgreSQL owners plus independent real cache connections. No external providers/messages.
[Trait("Suite","SqlContracts")]
public sealed class Cor23MAbuseBudgetTests
{
    private sealed class OwnedStorage(SqlContractFixture fixture) : StorageContext(Options.Create(Database()),Options.Create(new SecurityOperationSettings {HmacKeys=new(){[1]=Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))}}))
    {
        public Action<int>? OnOpen;
        private static DatabaseSettings Database()
        {
            var c=new NpgsqlConnectionStringBuilder(DeferredSqlProcedureContractSettings.ConnectionString!);
            return new(){servers=c.Host,port=c.Port,database=c.Database,userId=c.Username!,password=c.Password!,maximumPoolSize=32,connectionTimeoutSeconds=3};
        }
        public override async Task<NpgsqlConnection> CreateConnection(CancellationToken token=default)
        {
            var c=await base.CreateConnection(token);
            try { await using var cmd=new NpgsqlCommand($"set search_path to {fixture.Schema},public",c);await cmd.ExecuteNonQueryAsync(token);OnOpen?.Invoke(c.ProcessID);return c; }
            catch { await c.DisposeAsync();throw; }
        }
    }
    private static AbuseControlSettings Settings(AbuseFeature feature=AbuseFeature.Login) => new(){CounterFailureMode=AbuseCounterFailureMode.RequirePostgreSqlBudgetV1,PostgreSqlFallbackPolicies=[feature],PostgreSqlBudgetTimeoutMilliseconds=5000,DragonflyTimeoutMilliseconds=1000};
    private static AbuseCounterKey Key(AbuseFeature feature=AbuseFeature.Login,AbuseCounterDimension dimension=AbuseCounterDimension.IpFingerprint,string? id=null)=>new(feature,dimension,id??Guid.NewGuid().ToString("N"));
    private static PostgreSqlAbuseBudgetStore Budget(StorageContext storage,AbuseControlSettings settings)=>new(storage,Options.Create(settings));
    private static DragonflyAbuseCounterStore Store(IConnectionMultiplexer cache,IPostgreSqlAbuseBudgetStore budget,AbuseControlSettings settings)=>new(Options.Create(new AbuseCounterCacheSettings{database=0}),Options.Create(settings),cache,budget);
    private static async Task<ConnectionMultiplexer> Cache()
    {
        string? endpoint=Environment.GetEnvironmentVariable("TREEHAMMOCK_CORRECTION_CACHE_ENDPOINT"),password=Environment.GetEnvironmentVariable("TREEHAMMOCK_CORRECTION_CACHE_PASSWORD");
        if(string.IsNullOrWhiteSpace(endpoint)||string.IsNullOrWhiteSpace(password))throw new InvalidOperationException("Run the owned correction SQL/cache fixture.");
        var options=new ConfigurationOptions{Password=password,AbortOnConnectFail=true,ConnectTimeout=1000,AsyncTimeout=1000,SyncTimeout=1000};options.EndPoints.Add(endpoint);return await ConnectionMultiplexer.ConnectAsync(options);
    }
    private static async Task<T> Scalar<T>(NpgsqlConnection c,string sql,CancellationToken ct,NpgsqlTransaction? tx=null)
    {await using var command=new NpgsqlCommand(sql,c,tx);return (T)(await command.ExecuteScalarAsync(ct))!;}
    private static string Hash(AbuseCounterKey key)=>"decode('"+Convert.ToHexString(PostgreSqlAbuseBudgetStore.BudgetHash(key))+"','hex')";
    private static string Predicate(AbuseCounterKey key)=>$"policy_id={(int)key.Feature} and dimension_id={(int)key.Dimension} and budget_hash={Hash(key)}";
    [Theory]
    [InlineData(AbuseFeature.Login,AbuseCounterDimension.Account)][InlineData(AbuseFeature.Login,AbuseCounterDimension.IpFingerprint)][InlineData(AbuseFeature.Login,AbuseCounterDimension.IdentifierFingerprint)]
    [InlineData(AbuseFeature.Delivery,AbuseCounterDimension.Account)][InlineData(AbuseFeature.Delivery,AbuseCounterDimension.IpFingerprint)][InlineData(AbuseFeature.Delivery,AbuseCounterDimension.IdentifierFingerprint)]
    public async Task Real_two_owners_enforce_exact_threshold_and_cooldown_during_cache_failure(AbuseFeature feature,AbuseCounterDimension dimension)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>
        {
            await using var first=new OwnedStorage(f);await using var second=new OwnedStorage(f);using var cache1=await Cache();using var cache2=await Cache();var settings=Settings(feature);
            using var one=Store(cache1,Budget(first,settings),settings);using var two=Store(cache2,Budget(second,settings),settings);var key=Key(feature,dimension);var limit=new AbuseCounterLimit(8,TimeSpan.FromSeconds(10),TimeSpan.FromSeconds(5));var cache=cache1.GetDatabase(0);
            try
            {
                // Wrong-type GET makes the real Lua adapter return an infrastructure error.
                await cache.ListLeftPushAsync(key.Value,"owned-wrong-type");
                var results=await f.Observe(Task.WhenAll(Enumerable.Range(0,64).Select(i=>(i%2==0?one:two).IncrementAsync(key,limit,ct))));
                Assert.Equal(8,results.Count(r=>r.CanAdmit));Assert.All(results.Where(r=>r.CanAdmit),r=>Assert.True(r.CurrentCount>0));
                var denied=await one.IncrementAsync(key,limit,ct);Assert.False(denied.CanAdmit);Assert.False(denied.Unavailable);Assert.Equal(AbuseReasonCodes.FailureCooldownActive,denied.ReasonCode);Assert.Equal(9,denied.CurrentCount);
                var c=await f.OpenConnectionAsync(ct);Assert.Equal(9,await Scalar<int>(c,"select attempt_count from abuse_admission_budgets_v1 where "+Predicate(key),ct));
                Assert.True((await two.GetCooldownAsync(key,ct)).BlocksAdmission);
            }
            finally {await cache.KeyDeleteAsync(new RedisKey[]{key.Value,key.CooldownValue});}
        });
    }
    [Theory][InlineData(AbuseFeature.Login)][InlineData(AbuseFeature.Delivery)]
    public async Task Healthy_cache_history_outage_and_cache_recovery_share_one_durable_window(AbuseFeature feature)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>
        {
            await using var storage=new OwnedStorage(f);using var connection=await Cache();var settings=Settings(feature);using var store=Store(connection,Budget(storage,settings),settings);var key=Key(feature);var limit=new AbuseCounterLimit(3,TimeSpan.FromSeconds(10));var cache=connection.GetDatabase(0);
            try
            {
                Assert.True((await store.IncrementAsync(key,limit,ct)).CanAdmit);
                await cache.KeyDeleteAsync(key.Value);await cache.ListLeftPushAsync(key.Value,"owned-wrong-type");
                Assert.Equal(2,(await store.IncrementAsync(key,limit,ct)).CurrentCount);Assert.True((await store.IncrementAsync(key,limit,ct)).CanAdmit);
                await cache.KeyDeleteAsync(key.Value);Assert.False((await store.IncrementAsync(key,limit,ct)).CanAdmit);Assert.False(await cache.KeyExistsAsync(key.Value));
                var c=await f.OpenConnectionAsync(ct);Assert.Equal(4,await Scalar<int>(c,"select attempt_count from abuse_admission_budgets_v1 where "+Predicate(key),ct));
            }
            finally {await cache.KeyDeleteAsync(new RedisKey[]{key.Value,key.CooldownValue});}
        });
    }
    [Fact]
    public async Task PostgreSQL_lock_timeout_does_not_fall_through_to_a_healthy_cache()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>
        {
            await using var storage=new OwnedStorage(f);using var cache=await Cache();var settings=Settings();var budget=Budget(storage,settings);using var store=Store(cache,budget,settings);var key=Key();var limit=new AbuseCounterLimit(5,TimeSpan.FromSeconds(10));
            Assert.True((await budget.IncrementAsync(key,limit,ct)).CanAdmit);
            var owner=await f.OpenConnectionAsync(ct);var observer=await f.OpenConnectionAsync(ct);var tx=await f.BeginTransactionAsync(owner);
            await Scalar<int>(owner,"select attempt_count from abuse_admission_budgets_v1 where "+Predicate(key)+" for update",ct,tx);
            var acquired=new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);storage.OnOpen=pid=>acquired.TrySetResult(pid);
            var work=f.Observe(store.IncrementAsync(key,limit,ct));int pid=await acquired.Task.WaitAsync(ct);
            await SqlInterleavingBarrier.WaitForBlockedAsync(observer,pid,owner.ProcessID,work,ct);
            var result=await work;Assert.True(result.Unavailable);Assert.False(result.CanAdmit);Assert.Equal(AbuseReasonCodes.CounterStoreTimeout,result.ReasonCode);
            Assert.False(await cache.GetDatabase(0).KeyExistsAsync(key.Value));await tx.RollbackAsync(ct);
        });
    }
    [Fact]
    public async Task Real_SQL_window_rollover_samples_time_after_an_observed_row_lock_wait()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>
        {
            await using var storage=new OwnedStorage(f);var key=Key();var budget=Budget(storage,Settings());await budget.IncrementAsync(key,new(1,TimeSpan.FromSeconds(10)),ct);
            var owner=await f.OpenConnectionAsync(ct);var waiter=await f.OpenConnectionAsync(ct);var observer=await f.OpenConnectionAsync(ct);var tx=await f.BeginTransactionAsync(owner);
            await f.ExecuteAsync(owner,"update abuse_admission_budgets_v1 set window_expires_at=clock_timestamp()+interval '90 milliseconds',retain_until=clock_timestamp()+interval '100 milliseconds' where "+Predicate(key),tx,ct);
            var pending=f.Observe(Scalar<int>(waiter,$"select attempts from cor23m_increment_budget_v1(0,1,{Hash(key)},1,10000::bigint,0::bigint)",ct));
            await SqlInterleavingBarrier.WaitForBlockedAsync(observer,waiter.ProcessID,owner.ProcessID,pending,ct);
            await f.ExecuteAsync(owner,"select pg_sleep(0.12)",tx,ct);await tx.CommitAsync(ct);Assert.Equal(1,await pending);
            Assert.True((await budget.IncrementAsync(Key(),new(1,TimeSpan.FromSeconds(10)),ct)).CanAdmit);
        });
    }
    [Fact]
    public async Task Real_SQL_budget_identity_and_reset_do_not_clear_other_policy_or_dimension_limits()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>
        {
            await using var storage=new OwnedStorage(f);var budget=Budget(storage,Settings());string id=Guid.NewGuid().ToString("N");var keys=new[]{Key(id:id),Key(AbuseFeature.Delivery,id:id),Key(dimension:AbuseCounterDimension.Account,id:id)};var limit=new AbuseCounterLimit(1,TimeSpan.FromSeconds(10));
            foreach(var key in keys)Assert.True((await budget.IncrementAsync(key,limit,ct)).CanAdmit);
            await budget.ResetAsync(keys[0],ct);Assert.True((await budget.IncrementAsync(keys[0],limit,ct)).CanAdmit);
            Assert.False((await budget.IncrementAsync(keys[1],limit,ct)).CanAdmit);Assert.False((await budget.IncrementAsync(keys[2],limit,ct)).CanAdmit);
            var c=await f.OpenConnectionAsync(ct);Assert.Equal(3L,await Scalar<long>(c,"select count(*) from abuse_admission_budgets_v1",ct));Assert.Equal(0L,await Scalar<long>(c,"select count(*) from security_operation_steps",ct));
        });
    }
    [Fact]
    public async Task Bounded_real_cleanup_preserves_live_and_locked_windows_and_honors_dry_run()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>
        {
            await using var storage=new OwnedStorage(f);var budget=Budget(storage,Settings());var expired=Key();var live=Key();var limit=new AbuseCounterLimit(1,TimeSpan.FromSeconds(10));await budget.IncrementAsync(expired,limit,ct);await budget.IncrementAsync(live,limit,ct);
            var owner=await f.OpenConnectionAsync(ct);await f.ExecuteAsync(owner,"update abuse_admission_budgets_v1 set window_expires_at='-infinity',retain_until='-infinity' where "+Predicate(expired),cancellation:ct);
            Assert.Equal(1,await budget.PurgeExpiredAsync(1,true,ct));Assert.Equal(2L,await Scalar<long>(owner,"select count(*) from abuse_admission_budgets_v1",ct));
            var tx=await f.BeginTransactionAsync(owner);await Scalar<int>(owner,"select attempt_count from abuse_admission_budgets_v1 where "+Predicate(expired)+" for update",ct,tx);
            Assert.Equal(0,await budget.PurgeExpiredAsync(1,false,ct));await tx.CommitAsync(ct);Assert.Equal(1,await budget.PurgeExpiredAsync(1,false,ct));
            Assert.False((await budget.IncrementAsync(live,limit,ct)).CanAdmit);Assert.True((await budget.IncrementAsync(expired,limit,ct)).CanAdmit);
        });
    }
    [Theory][InlineData(12,1)][InlineData(0,6)][InlineData(2,7)]
    public async Task SQL_rejects_unsupported_policy_dimensions_before_allocating_any_row(int policy,int dimension)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>
        {
            var c=await f.OpenConnectionAsync(ct);await using var command=new NpgsqlCommand($"select admitted from cor23m_increment_budget_v1({policy},{dimension},decode(repeat('ab',32),'hex'),5,10000::bigint,0::bigint)",c);
            var error=await Assert.ThrowsAsync<PostgresException>(()=>command.ExecuteScalarAsync(ct));Assert.Equal("22023",error.SqlState);Assert.Equal(0L,await Scalar<long>(c,"select count(*) from abuse_admission_budgets_v1",ct));
        });
    }
}
