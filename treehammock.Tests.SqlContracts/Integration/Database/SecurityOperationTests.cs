using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Npgsql;
using Shouldly;
using treehammock.DataLayer.Operations;
using treehammock.Repos;
using treehammock.Rigging.Config;
using treehammock.Rigging.Database;
using treehammock.Rigging.Operations;
using treehammock.RiggingSupport.Status;
using treehammock.Rigging.Security;
using NSubstitute;
using treehammock.Services;
using treehammock.Tests.SqlContracts.Support;

namespace treehammock.Tests.Integration.Database;

[Trait("Suite", "SqlContracts")]
public class Cor04SecurityOperationTests
{
    private static SecurityOperationSettings Settings() => new()
    { HmacKeys = new() { [1] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) } };
    private static SecurityOperationRequestContext Context(string? key = null, string? recovery = null, string body = "{\"value\":1}") => new()
    { ClientKey=key ?? SecurityOperationKey.Create(), RecoveryKey=recovery ?? Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
        Purpose="POST:/test/mutation", CanonicalBody=Encoding.UTF8.GetBytes(body) };

    [Fact]
    public Task Another_instance_reconciles_without_reexecuting_and_changed_content_conflicts()
        => SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            var settings = Settings(); await using var first = new FixtureStorage(fixture, settings);
            await using var second = new FixtureStorage(fixture, settings);
            var admin = await fixture.OpenConnectionAsync(); await fixture.ExecuteAsync(admin, "create table cor04_effects(value integer not null)");
            var context = Context();
            using (SecurityOperationRequestContext.Push(context))
            {
                await using (var scope = await first.SecurityOperations.BeginAsync("test.effect", new {value=1}, null, null, null, token))
                {
                    await fixture.ExecuteAsync(scope.Connection, "insert into cor04_effects values(1)", scope.Transaction, token);
                    await scope.CommitAsync(true);
                }
                await first.SecurityOperations.FinishAsync(context, 200, false);
            }
            var duplicate = Context(context.ClientKey, context.RecoveryKey);
            using (SecurityOperationRequestContext.Push(duplicate))
            {
                var replay = await Should.ThrowAsync<SecurityOperationException>(async () =>
                { await using var scope = await second.SecurityOperations.BeginAsync("test.effect", new {value=1}, null, null, null, token); });
                replay.Status!.State.ShouldBe(SecurityOperationState.Committed);
            }
            var changed = Context(context.ClientKey, context.RecoveryKey, "{\"value\":2}");
            using (SecurityOperationRequestContext.Push(changed))
            {
                var conflict = await Should.ThrowAsync<SecurityOperationException>(async () =>
                { await using var scope = await second.SecurityOperations.BeginAsync("test.effect", new {value=2}, null, null, null, token); });
                conflict.Code.ShouldBe("SECURITY_OPERATION_CONFLICT");
            }
            (await Scalar<long>(admin,"select count(*) from cor04_effects",token)).ShouldBe(1);
            var recovered = await second.SecurityOperations.ReconcileAuthorizedAsync(context.ClientKey!, context.RecoveryKey!, token);
            recovered.State.ShouldBe(SecurityOperationState.Committed); recovered.Steps.Single().Code.ShouldBe("SUCCEEDED");
            (await Should.ThrowAsync<SecurityOperationException>(() => second.SecurityOperations.ReconcileAuthorizedAsync(context.ClientKey!, Convert.ToBase64String(new byte[32]),token))).HttpStatus.ShouldBe(404);
        }, TestContext.Current.CancellationToken);

    [Fact]
    public Task Lost_commit_acknowledgment_recovers_real_receipt_with_a_single_connection_pool()
        => SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            var parsed = new NpgsqlConnectionStringBuilder(DeferredSqlProcedureContractSettings.ConnectionString!);
            await using var proxy = new Cor04CommitAckLossProxy(parsed.Host, parsed.Port);
            await using var storage = new FixtureStorage(fixture, Settings(), proxy.Port);
            var admin = await fixture.OpenConnectionAsync(); await fixture.ExecuteAsync(admin,"create table cor04_effects(value integer not null)");
            var context = Context();
            using (SecurityOperationRequestContext.Push(context))
            {
                await Should.ThrowAsync<SecurityOperationException>(async () =>
                {
                    await using var scope = await storage.SecurityOperations.BeginAsync("test.effect",new {value=1},null,null,null,token);
                    await fixture.ExecuteAsync(scope.Connection,"insert into cor04_effects values(1)",scope.Transaction,token);
                    proxy.Arm(); await scope.CommitAsync(true);
                });
                await proxy.Dropped.WaitAsync(TimeSpan.FromSeconds(5),token);
                await storage.SecurityOperations.FinishAsync(context,503,true);
            }
            (await Scalar<long>(admin,"select count(*) from cor04_effects",token)).ShouldBe(1);
            var status = await storage.SecurityOperations.ReconcileAuthorizedAsync(context.ClientKey!,context.RecoveryKey!,token);
            status.State.ShouldBe(SecurityOperationState.PartiallyCommitted); status.Steps.Single().Code.ShouldBe("SUCCEEDED");
            await using var recovered = await storage.CreateConnection(token);
            (await Scalar<int>(recovered,"select 1",token)).ShouldBe(1);
        }, TestContext.Current.CancellationToken);

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)]
    public Task Executor_loss_at_reservation_gate_mutation_receipt_or_commit_has_no_partial_transaction(int boundary)
        => SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            await using var storage = new FixtureStorage(fixture, Settings()); var repo = new SecurityOperationRepo(storage);
            var id = Guid.NewGuid(); DateTimeOffset now=DateTimeOffset.UtcNow;
            await repo.ReserveAsync(id,new(new byte[32],new byte[32],1),"test.crash",now,now.AddSeconds(10),now.AddDays(1),token);
            var admin = await fixture.OpenConnectionAsync(); await fixture.ExecuteAsync(admin,"create table cor04_effects(value integer not null)");
            if (boundary > 0)
            {
                var worker = await fixture.OpenConnectionAsync(); var transaction = await worker.BeginTransactionAsync(token);
                await fixture.ExecuteAsync(worker,$"select lock_security_operation('{id}',null)",transaction,token);
                if(boundary>=2) await fixture.ExecuteAsync(worker,"insert into cor04_effects values(1)",transaction,token);
                if(boundary>=3) await fixture.ExecuteAsync(worker,$"insert into security_operation_steps(operation_id,step_key,request_hmac,outcome_code) values('{id}','test:0',decode(repeat('00',32),'hex'),'SUCCEEDED')",transaction,token);
                if(boundary==4) await transaction.CommitAsync(token);
                await fixture.ExecuteAsync(admin,$"select pg_terminate_backend({worker.ProcessID})",cancellation:token);
                try { await transaction.DisposeAsync(); } catch { }
            }
            await fixture.ExecuteAsync(admin,$"update security_operations set execute_before=clock_timestamp()-interval '1 second' where operation_id='{id}'",cancellation:token);
            var status=await storage.SecurityOperations.ReconcileAsync(id);
            status.State.ShouldBe(boundary==4?SecurityOperationState.PartiallyCommitted:SecurityOperationState.RolledBack);
            (await Scalar<long>(admin,"select count(*) from cor04_effects",token)).ShouldBe(boundary==4?1L:0L);
            (await Scalar<long>(admin,$"select count(*) from security_operation_steps where operation_id='{id}'",token)).ShouldBe(boundary==4?1L:0L);
            var denied=await Should.ThrowAsync<PostgresException>(()=>fixture.ExecuteAsync(admin,$"select lock_security_operation('{id}',null)",cancellation:token));
            denied.SqlState.ShouldBe("P0404");
        }, TestContext.Current.CancellationToken);

    [Fact]
    public Task Real_account_lock_deadline_rolls_back_and_releases_operation_and_pool()
        => SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            var settings=Settings(); settings.ExecutionSeconds=2; settings.LockSeconds=2;
            await using var storage=new FixtureStorage(fixture,settings);
            var admin=await fixture.OpenConnectionAsync(); var id=Guid.NewGuid(); var stamp=Guid.NewGuid();
            await fixture.ExecuteAsync(admin,$"insert into accounts(account_id,email_address,verify_status,security_stamp) values('{id}','cor04@example.invalid',1,'{stamp}')");
            var blocker=await fixture.OpenConnectionAsync(); await using var block=await blocker.BeginTransactionAsync(token);
            await fixture.ExecuteAsync(blocker,$"select 1 from accounts where account_id='{id}' for update",block,token);
            var context=Context();
            using(SecurityOperationRequestContext.Push(context))
            {
                var repo=new AccountRepo(new treehammock.Rigging.Delivery.DeliveryPayloadProtector(Options.Create(new treehammock.Rigging.Config.DeliveryOutboxSettings {EncryptionKeys=new() {{1,Convert.ToBase64String(new byte[32])}}})),storage,Options.Create(new JWTSettings()),NullLogger<AccountRepo>.Instance,Substitute.For<IUserSecretHasher>());
                Task<AccountAdjustResult?> mutation=repo.ModifyUsername(id,stamp,"changed",token);
                fixture.Observe(mutation.ContinueWith(t => { _ = t.Exception; }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default));
                // Observe this exact blocker, not elapsed time as proof of contention.
                bool observed=false;
                for(int attempt=0;attempt<60&&!mutation.IsCompleted;attempt++)
                {
                    observed=await Scalar<bool>(admin,$"select exists(select 1 from pg_stat_activity where {blocker.ProcessID}=any(pg_blocking_pids(pid)))",token);
                    if(observed)break; await Task.Delay(10,token);
                }
                observed.ShouldBeTrue();
                var error=await Should.ThrowAsync<SecurityOperationException>(async()=>await mutation);
                error.Status!.State.ShouldBe(SecurityOperationState.RolledBack);
            }
            await block.RollbackAsync(token);
            (await Scalar<bool>(admin,$"select username is null from accounts where account_id='{id}'",token)).ShouldBeTrue();
            (await Scalar<long>(admin,"select count(*) from security_operation_steps",token)).ShouldBe(0);
            await using var recovered=await storage.CreateConnection(token); (await Scalar<int>(recovered,"select 1",token)).ShouldBe(1);
        },TestContext.Current.CancellationToken);

    [Fact]
    public Task Pending_gate_is_not_rollback_and_expiry_fences_stale_writers()
        => SqlContractFixture.RunAsync(async(fixture,token)=>
        {
            await using var storage=new FixtureStorage(fixture,Settings());var repo=new SecurityOperationRepo(storage);
            var id=Guid.NewGuid();var now=DateTimeOffset.UtcNow;
            await repo.ReserveAsync(id,new(new byte[32],new byte[32],1),"test.fence",now,now.AddSeconds(5),now.AddDays(1),token);
            var worker=await fixture.OpenConnectionAsync();await using var transaction=await worker.BeginTransactionAsync(token);
            await fixture.ExecuteAsync(worker,$"select lock_security_operation('{id}',null)",transaction,token);
            (await storage.SecurityOperations.ReconcileAsync(id)).State.ShouldBe(SecurityOperationState.Pending);
            await transaction.RollbackAsync(token);
            var admin=await fixture.OpenConnectionAsync();await fixture.ExecuteAsync(admin,$"update security_operations set execute_before=clock_timestamp()-interval '1 second' where operation_id='{id}'");
            (await storage.SecurityOperations.ReconcileAsync(id)).State.ShouldBe(SecurityOperationState.RolledBack);
            (await Should.ThrowAsync<PostgresException>(()=>fixture.ExecuteAsync(admin,$"select lock_security_operation('{id}',null)"))).SqlState.ShouldBe("P0404");
            (await storage.SecurityOperations.ReconcileAsync(Guid.NewGuid())).State.ShouldBe(SecurityOperationState.Unknown);
        },TestContext.Current.CancellationToken);

    [Fact]
    public Task Cleanup_is_bounded_and_expired_original_key_cannot_resurrect_work()
        => SqlContractFixture.RunAsync(async(fixture,token)=>
        {
            await using var storage=new FixtureStorage(fixture,Settings());var admin=await fixture.OpenConnectionAsync();
            await fixture.ExecuteAsync(admin,"""
                insert into security_operations(operation_id,request_hmac,recovery_hmac,hmac_version,purpose,issued_at,execute_before,expires_at)
                select gen_random_uuid(),decode(repeat('00',32),'hex'),decode(repeat('00',32),'hex'),1,'test.expiry',clock_timestamp()-interval '2 days',clock_timestamp()-interval '2 days',clock_timestamp()-interval '1 day'
                from generate_series(1,3);
                """);
            (await new SecurityOperationRepo(storage).PurgeAsync(1,token)).ShouldBe(1);
            (await Scalar<long>(admin,"select count(*) from security_operations",token)).ShouldBe(2);
            var context=Context($"{DateTimeOffset.UtcNow.AddDays(-2).ToUnixTimeSeconds()}.{Guid.NewGuid():N}");
            using(SecurityOperationRequestContext.Push(context))
                (await Should.ThrowAsync<SecurityOperationException>(async()=>{await using var scope=await storage.SecurityOperations.BeginAsync("test.expired",new {value=1},null,null,null,token);})).HttpStatus.ShouldBe(410);
        },TestContext.Current.CancellationToken);

    [Fact]
    public Task Recovery_survives_stamp_change_account_deletion_and_HMAC_key_rollover_without_secret_output()
        => SqlContractFixture.RunAsync(async(fixture,token)=>
        {
            var oldSettings=Settings();await using var first=new FixtureStorage(fixture,oldSettings);
            var admin=await fixture.OpenConnectionAsync();var account=Guid.NewGuid();var stamp=Guid.NewGuid();
            await fixture.ExecuteAsync(admin,$"insert into accounts(account_id,email_address,verify_status,security_stamp) values('{account}','revoked@example.invalid',1,'{stamp}')");
            var context=Context();
            using(SecurityOperationRequestContext.Push(context))
            {
                await using(var scope=await first.SecurityOperations.BeginAsync("test.rotation",new {account,stamp},account,stamp,"generation:1",token))
                {
                    await fixture.ExecuteAsync(scope.Connection,$"update accounts set security_stamp=gen_random_uuid() where account_id='{account}'",scope.Transaction,token);
                    await scope.CommitAsync(new {Result=true,Code="ROTATED",AccessToken="do-not-store",Seed="never-persist"});
                }
                await first.SecurityOperations.FinishAsync(context,200,false);
            }
            await fixture.ExecuteAsync(admin,$"delete from accounts where account_id='{account}'");
            var newSettings=Settings();newSettings.ActiveKeyVersion=2;
            newSettings.HmacKeys=new(){[1]=oldSettings.HmacKeys[1],[2]=Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))};
            await using var second=new FixtureStorage(fixture,newSettings);
            var status=await second.SecurityOperations.ReconcileAuthorizedAsync(context.ClientKey!,context.RecoveryKey!,token);
            status.State.ShouldBe(SecurityOperationState.Committed);
            string receipt=await Scalar<string>(admin,"select to_jsonb(s)::text from security_operation_steps s",token);
            receipt.ShouldNotContain("do-not-store");receipt.ShouldNotContain("never-persist");
            // Execute the exceptional HTTP status boundary with a real database,
            // no JWT/session substitution and no ability to enter normal routes.
            var http=new Microsoft.AspNetCore.Http.DefaultHttpContext();http.Request.Method="GET";
            http.Request.Path=SecurityOperationMiddleware.StatusPath;http.Response.Body=new MemoryStream();
            http.Request.Headers[SecurityOperationMiddleware.KeyHeader]=context.ClientKey;
            http.Request.Headers[SecurityOperationMiddleware.RecoveryHeader]=context.RecoveryKey;
            var boundary=new SecurityOperationMiddleware(_=>throw new InvalidOperationException("Status may not enter normal JWT routes."));
            await boundary.InvokeAsync(http,second.SecurityOperations);
            http.Response.StatusCode.ShouldBe(200);http.Response.Body.Position=0;
            using var body=new StreamReader(http.Response.Body);
            string response=await body.ReadToEndAsync(token);
            response.ShouldNotContain("do-not-store");response.ShouldNotContain("never-persist");
        },TestContext.Current.CancellationToken);

    private static async Task<T> Scalar<T>(NpgsqlConnection connection,string sql,CancellationToken token)
    {await using var command=new NpgsqlCommand(sql,connection);return (T)(await command.ExecuteScalarAsync(token))!;}
    private sealed class FixtureStorage : StorageContext
    {
        private readonly SqlContractFixture _fixture;
        public FixtureStorage(SqlContractFixture fixture,SecurityOperationSettings settings,int? proxyPort=null)
            :base(Options.Create(Database(proxyPort)),Options.Create(settings))=>_fixture=fixture;
        private static DatabaseSettings Database(int? port)
        {
            var parsed=new NpgsqlConnectionStringBuilder(DeferredSqlProcedureContractSettings.ConnectionString!);
            return new(){servers=port.HasValue?"127.0.0.1":parsed.Host,port=port??parsed.Port,database=parsed.Database,userId=parsed.Username!,password=parsed.Password!,maximumPoolSize=1};
        }
        public override async Task<NpgsqlConnection> CreateConnection(CancellationToken token=default)
        {
            var connection=await base.CreateConnection(token);
            try{await using var command=new NpgsqlCommand($"set search_path to {_fixture.Schema},public",connection);await command.ExecuteNonQueryAsync(token);return connection;}
            catch{await connection.DisposeAsync();throw;}
        }
    }
}
