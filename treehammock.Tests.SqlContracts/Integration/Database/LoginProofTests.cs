using System.Security.Cryptography;
using NodaTime;
using Npgsql;
using NpgsqlTypes;
using Shouldly;
using treehammock.DataLayer.Cache;
using treehammock.DataLayer.Operations;
using treehammock.Repos;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.Rigging.Operations;
using treehammock.RiggingSupport.Enum;
using treehammock.Tests.SqlContracts.Support;

namespace treehammock.Tests.Integration.Database;

// Actual SQL authority and independent connections. TOTP cryptography/provider
// delivery and Redis are covered by their own adapters, not simulated SQL proof.
[Trait("Suite", "SqlContracts")]
public class Cor10LoginProofTests
{
    private const string Hash = "cor10-pending";
    private const string Good = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string Other = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private static async Task<TwoFactorSession> Seed(SqlContractFixture f, NpgsqlConnection c, CancellationToken token)
    {
        Guid account = Guid.NewGuid(), stamp = Guid.NewGuid();
        await using var command = new NpgsqlCommand("""
            insert into accounts(account_id,email_address,verify_status,security_stamp,web_key)
            values(@account,'cor10@example.invalid',1,@stamp,'cor10-web');
            insert into two_factor_authentications(account_id,two_factor_index,method,verified,phone_number,
                totp_secret_ciphertext,totp_secret_nonce,totp_secret_tag,totp_provider_type,totp_secret_version,totp_key_id,totp_enrollment_id,totp_algorithm,totp_digits,totp_period_seconds,totp_clock_skew_steps)
            values(@account,1,1,true,null,null,null,null,null,null,null,null,null,null,null,null),(@account,2,2,true,'5555550101',null,null,null,null,null,null,null,null,null,null,null),
                (@account,3,3,true,null,decode(repeat('01',20),'hex'),decode(repeat('02',12),'hex'),decode(repeat('03',16),'hex'),1,2,'fixture',gen_random_uuid(),'SHA1',6,30,1);
            """, c);
        command.Parameters.AddWithValue("account", account); command.Parameters.AddWithValue("stamp", stamp);
        await command.ExecuteNonQueryAsync(token);
        Instant now = SystemClock.Instance.GetCurrentInstant();
        var snapshot = new TwoFactorSession(account,"cor10-web",RandomNumberGenerator.GetBytes(64),
            [TwoFactorAuthMethod.EMAIL,TwoFactorAuthMethod.SMS_KEY,TwoFactorAuthMethod.AUTHENTICATOR_APP],
            null,["5555550101"],["1"],["cor10@example.invalid"],null,null,1,0,1,
            now,now.Plus(Duration.FromMinutes(5)),FeatureSet.basic,accountSecurityStamp:stamp);
        await using var begin = new NpgsqlCommand("select * from cor10_begin_login(@hash,@snapshot)",c);
        begin.Parameters.AddWithValue("hash",Hash);
        begin.Parameters.Add("snapshot",NpgsqlDbType.Jsonb).Value=CacheJsonSettings.Serialize(snapshot);
        var result = await Read(begin,token); result.Result.ShouldBeTrue();
        result.Snapshot.ShouldNotBeNull(); return result.Snapshot!;
    }
    private static async Task<LoginProofTransition> Read(NpgsqlCommand command,CancellationToken token)
    {
        await using var reader=await command.ExecuteReaderAsync(token); (await reader.ReadAsync(token)).ShouldBeTrue();
        return new(reader.GetBoolean(0),reader.GetString(1),reader.FieldCount<3||reader.IsDBNull(2)?null:
            CacheJsonSettings.Deserialize<TwoFactorSession>(reader.GetString(2)));
    }
    private static Task<LoginProofTransition> Query(NpgsqlConnection c,NpgsqlTransaction? tx,string sql,CancellationToken token)
        => Execute(c,tx,sql,token);
    private static async Task<LoginProofTransition> Execute(NpgsqlConnection c,NpgsqlTransaction? tx,string sql,CancellationToken token)
    { await using var command=new NpgsqlCommand(sql,c,tx); return await Read(command,token); }
    private static string Issue(TwoFactorSession p,int configuration=2,int method=1,string verifier=Good)
        => $"select * from cor10_issue_challenge('{Hash}','{p.accountSecurityStamp}',{p.progressVersion}::bigint,{configuration}::smallint,{method}::smallint,0::smallint,'{verifier}',clock_timestamp()+interval '2 minutes',5::smallint,30)";
    private static string Complete(TwoFactorSession p,string verifier=Good,bool totp=false,int? method=null)
        => $"select * from cor10_complete_proof('{Hash}','{p.accountSecurityStamp}',{p.progressVersion}::bigint,'{p.challengeId}',{method??(int)p.challengedMethod!.Value}::smallint,'{verifier}',{(totp?"true":"false")},3::smallint)";
    private static string Promote(TwoFactorSession p,string hash="cor10-active")
        => $"select * from promote_twofactor_new_login('{p.accountId}','{Hash}','{p.accountSecurityStamp}','{hash}',decode(repeat('00',64),'hex'),0::smallint,0::smallint,clock_timestamp(),interval '7 days',clock_timestamp()+interval '15 minutes',clock_timestamp()+interval '7 days',null,0::smallint,gen_random_uuid(),{p.progressVersion}::bigint)";
    private static Task<T> Scalar<T>(NpgsqlConnection c,string sql,CancellationToken token)
        => Cor09SessionFamilyTests.Scalar<T>(c,sql,token);
    private static async Task<TwoFactorSession> Current(NpgsqlConnection c,CancellationToken token)
        => CacheJsonSettings.Deserialize<TwoFactorSession>(await Scalar<string>(c,$"select cor10_login_snapshot('{Hash}')::text",token))!;

    [Fact]
    public Task Replaced_code_and_stale_cleanup_cannot_complete_or_cancel_current_challenge()
        => SqlContractFixture.RunAsync(async(f,t)=>
        {
            var c=await f.OpenConnectionAsync();var p=await Seed(f,c,t);
            var old=(await Query(c,null,Issue(p),t)).Snapshot!;
            (await Query(c,null,Issue(old,verifier:Other),t)).Code.ShouldBe("TWO_FACTOR_CHALLENGE_COOLDOWN");
            await f.ExecuteAsync(c,"update pending_two_factor_sessions set next_challenge_allowed_at=clock_timestamp()",cancellation:t);
            var replacement=(await Query(c,null,Issue(old,verifier:Other),t)).Snapshot!;
            replacement.challengeId.ShouldNotBe(old.challengeId); replacement.progressVersion.ShouldBe(old.progressVersion+1);
            (await Query(c,null,Complete(old),t)).Code.ShouldBe("LOGIN_PROOF_STALE");
            (await Query(c,null,$"select * from cor10_cancel_challenge('{Hash}','{old.accountSecurityStamp}',{old.progressVersion},'{old.challengeId}')",t)).Code.ShouldBe("LOGIN_PROOF_STALE");
            (await Query(c,null,Complete(replacement),t)).Code.ShouldBe("TWO_FACTOR_CHALLENGE_INCORRECT");
            var current=await Current(c,t);current.challengeAttempts.ShouldBe((short)1);
            (await Query(c,null,Complete(current,Other),t)).Result.ShouldBeTrue();
            (await Current(c,t)).isComplete.ShouldBeTrue();
        },TestContext.Current.CancellationToken);

    [Fact]
    public Task Concurrent_selections_compare_version_and_have_one_winner()
        => SqlContractFixture.RunAsync(async(f,t)=>
        {
            var observer=await f.OpenConnectionAsync();var p=await Seed(f,observer,t);
            var first=await f.OpenConnectionAsync();var second=await f.OpenConnectionAsync();
            var holding=await f.BeginTransactionAsync(first);var competing=await f.BeginTransactionAsync(second);
            (await Query(first,holding,Issue(p),t)).Result.ShouldBeTrue();
            var pending=f.Observe(Query(second,competing,Issue(p,1,2,Other),t));
            await SqlInterleavingBarrier.WaitForBlockedAsync(observer,second.ProcessID,first.ProcessID,pending,t);
            await holding.CommitAsync(t);(await pending).Code.ShouldBe("LOGIN_PROOF_STALE");await competing.CommitAsync(t);
            var current=await Current(observer,t);current.selectedConfiguration.ShouldBe(TwoFactorAuthConfiguration.EMAIL);
            current.progressVersion.ShouldBe(2);current.challengeResends.ShouldBe((short)1);
        },TestContext.Current.CancellationToken);

    [Theory]
    [InlineData(true)] [InlineData(false)]
    public Task Failure_and_success_observed_on_same_version_cannot_overwrite_each_other(bool successFirst)
        => SqlContractFixture.RunAsync(async(f,t)=>
        {
            var observer=await f.OpenConnectionAsync();var p=(await Query(observer,null,Issue(await Seed(f,observer,t)),t)).Snapshot!;
            var first=await f.OpenConnectionAsync();var second=await f.OpenConnectionAsync();
            var holding=await f.BeginTransactionAsync(first);var competing=await f.BeginTransactionAsync(second);
            (await Query(first,holding,Complete(p,successFirst?Good:Other),t)).Result.ShouldBe(successFirst);
            var pending=f.Observe(Query(second,competing,Complete(p,successFirst?Other:Good),t));
            await SqlInterleavingBarrier.WaitForBlockedAsync(observer,second.ProcessID,first.ProcessID,pending,t);
            await holding.CommitAsync(t);(await pending).Code.ShouldBe("LOGIN_PROOF_STALE");await competing.CommitAsync(t);
            var current=await Current(observer,t);current.isComplete.ShouldBe(successFirst);
            current.challengeAttempts.ShouldBe(successFirst?(short)0:(short)1);
            if(!successFirst) (await Query(observer,null,Complete(current),t)).Result.ShouldBeTrue();
            (await Current(observer,t)).completedMethods.ShouldBe([TwoFactorAuthMethod.EMAIL]);
        },TestContext.Current.CancellationToken);

    [Fact]
    public Task Provider_cancel_keeps_durable_budget_and_cooldown()
        => SqlContractFixture.RunAsync(async(f,t)=>
        {
            var c=await f.OpenConnectionAsync();var p=(await Query(c,null,Issue(await Seed(f,c,t)),t)).Snapshot!;
            var cancelled=await Query(c,null,$"select * from cor10_cancel_challenge('{Hash}','{p.accountSecurityStamp}',{p.progressVersion},'{p.challengeId}')",t);
            cancelled.Result.ShouldBeTrue();cancelled.Snapshot!.challengeId.ShouldBeNull();
            cancelled.Snapshot.challengeResends.ShouldBe(p.challengeResends);
            cancelled.Snapshot.nextChallengeAllowedAt.ShouldBe(p.nextChallengeAllowedAt);
            (await Query(c,null,Issue(cancelled.Snapshot),t)).Code.ShouldBe("TWO_FACTOR_CHALLENGE_COOLDOWN");
        },TestContext.Current.CancellationToken);

    [Fact]
    public Task Ordered_combination_requires_each_durable_proof_before_promotion_and_global_totp_step_is_single_use()
        => SqlContractFixture.RunAsync(async(f,t)=>
        {
            var c=await f.OpenConnectionAsync();var p=(await Query(c,null,Issue(await Seed(f,c,t),5),t)).Snapshot!;
            (await Query(c,null,Promote(p),t)).Result.ShouldBeFalse();
            (await Query(c,null,Complete(p,totp:true,method:3),t)).Code.ShouldBe("LOGIN_PROOF_STALE");
            p=(await Query(c,null,Complete(p),t)).Snapshot!;
            p.completedMethods.ShouldBe([TwoFactorAuthMethod.EMAIL]);p.currentExpectedMethod.ShouldBe(TwoFactorAuthMethod.AUTHENTICATOR_APP);
            (await Query(c,null,Promote(p),t)).Result.ShouldBeFalse();
            p=(await Query(c,null,Issue(p,5,3),t)).Snapshot!;
            (await Query(c,null,$"select * from mark_totp_step_used('{p.accountId}',3::smallint,12345::bigint,(select totp_enrollment_id from two_factor_authentications where account_id='{p.accountId}' and two_factor_index=3))",t)).Result.ShouldBeTrue();
            (await Query(c,null,$"select * from mark_totp_step_used('{p.accountId}',3::smallint,12345::bigint,(select totp_enrollment_id from two_factor_authentications where account_id='{p.accountId}' and two_factor_index=3))",t)).Code.ShouldBe("TOTP_REPLAY_DETECTED");
            p=(await Query(c,null,Complete(p,totp:true),t)).Snapshot!;
            p.completedMethods.ShouldBe([TwoFactorAuthMethod.EMAIL,TwoFactorAuthMethod.AUTHENTICATOR_APP]);p.isComplete.ShouldBeTrue();
            (await Query(c,null,Promote(p),t)).Result.ShouldBeTrue();
            (await Query(c,null,Promote(p,"cor10-retry"),t)).Result.ShouldBeFalse();
            (await Scalar<long>(c,"select count(*) from sessions where session_expiration>clock_timestamp()",t)).ShouldBe(1);
        },TestContext.Current.CancellationToken);

    [Fact]
    public Task Concurrent_final_completion_then_concurrent_promotion_creates_one_active_family()
        => SqlContractFixture.RunAsync(async(f,t)=>
        {
            var observer=await f.OpenConnectionAsync();var p=(await Query(observer,null,Issue(await Seed(f,observer,t)),t)).Snapshot!;
            var first=await f.OpenConnectionAsync();var second=await f.OpenConnectionAsync();
            var holding=await f.BeginTransactionAsync(first);var competing=await f.BeginTransactionAsync(second);
            var completed=await Query(first,holding,Complete(p),t);completed.Result.ShouldBeTrue();
            var pending=f.Observe(Query(second,competing,Complete(p),t));
            await SqlInterleavingBarrier.WaitForBlockedAsync(observer,second.ProcessID,first.ProcessID,pending,t);
            await holding.CommitAsync(t);(await pending).Code.ShouldBe("LOGIN_PROOF_STALE");await competing.CommitAsync(t);
            var promoting=await f.BeginTransactionAsync(first);var duplicate=await f.BeginTransactionAsync(second);
            (await Query(first,promoting,Promote(completed.Snapshot!),t)).Result.ShouldBeTrue();
            var retry=f.Observe(Query(second,duplicate,Promote(completed.Snapshot!,"cor10-other"),t));
            await SqlInterleavingBarrier.WaitForBlockedAsync(observer,second.ProcessID,first.ProcessID,retry,t);
            await promoting.CommitAsync(t);(await retry).Result.ShouldBeFalse();await duplicate.CommitAsync(t);
            (await Scalar<long>(observer,"select count(*) from sessions",t)).ShouldBe(1);
            (await Scalar<long>(observer,"select count(*) from pending_two_factor_sessions",t)).ShouldBe(0);
        },TestContext.Current.CancellationToken);

    [Fact]
    public Task Hard_expiry_after_account_lock_wait_rolls_back_failure_or_success_progress()
        => SqlContractFixture.RunAsync(async(f,t)=>
        {
            var observer=await f.OpenConnectionAsync();var p=(await Query(observer,null,Issue(await Seed(f,observer,t)),t)).Snapshot!;
            var blocker=await f.OpenConnectionAsync();var contender=await f.OpenConnectionAsync();
            var holding=await f.BeginTransactionAsync(blocker);var competing=await f.BeginTransactionAsync(contender);
            await f.ExecuteAsync(blocker,$"select 1 from accounts where account_id='{p.accountId}' for update",holding,t);
            var pending=f.Observe(Query(contender,competing,Complete(p),t));
            await SqlInterleavingBarrier.WaitForBlockedAsync(observer,contender.ProcessID,blocker.ProcessID,pending,t);
            await f.ExecuteAsync(blocker,"update pending_two_factor_sessions set expiration=clock_timestamp()",holding,t);
            await holding.CommitAsync(t);(await pending).Code.ShouldBe("PENDING_TWO_FACTOR_EXPIRED");await competing.CommitAsync(t);
            (await Scalar<long>(observer,"select progress_version from pending_two_factor_sessions",t)).ShouldBe(p.progressVersion);
            (await Scalar<short>(observer,"select challenge_attempts from pending_two_factor_sessions",t)).ShouldBe((short)0);
            (await Scalar<long>(observer,"select count(*) from sessions",t)).ShouldBe(0);
        },TestContext.Current.CancellationToken);

    [Fact]
    public Task Restarted_repository_rehydrates_current_state_and_safe_receipts_exclude_signing_material()
        => SqlContractFixture.RunAsync(async(f,t)=>
        {
            var c=await f.OpenConnectionAsync();var p=await Seed(f,c,t);
            var settings=new SecurityOperationSettings {HmacKeys=new(){[1]=Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))}};
            await using var first=new Cor09RefreshHttpTests.FixtureStorage(f,settings);
            await using var restarted=new Cor09RefreshHttpTests.FixtureStorage(f,settings);
            var repository=new LoginProofRepo(first);p.selectedConfiguration=TwoFactorAuthConfiguration.EMAIL;
            p.challengedMethod=TwoFactorAuthMethod.EMAIL;p.chosenDestination=0;p.challengeCodeHash=Good;
            p.challengeExpiration=SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(2));
            var context=new SecurityOperationRequestContext {ClientKey=SecurityOperationKey.Create(),
                RecoveryKey=Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),Purpose="POST:/account/selecttwofactor",CanonicalBody=[]};
            using(SecurityOperationRequestContext.Push(context))
            { var issued=await repository.IssueAsync(Hash,p,5,30,t);issued.Result.ShouldBeTrue();p=issued.Snapshot!; }
            var recovered=await new LoginProofRepo(restarted).LoadAsync(Hash,t);recovered.ShouldNotBeNull();
            recovered!.challengeId.ShouldBe(p.challengeId);recovered.progressVersion.ShouldBe(p.progressVersion);
            recovered.challengeCodeHash.ShouldBe(Good);recovered.intraCodeKey.ShouldBeNull();
            string receipts=await Scalar<string>(c,"select jsonb_agg(to_jsonb(s))::text from security_operation_steps s",t);
            receipts.ShouldContain("TWO_FACTOR_CHALLENGE_ISSUED");receipts.ShouldNotContain(Good);
            receipts.ShouldNotContain(Convert.ToBase64String(p.preAuthRefreshToken));
            var status=await restarted.SecurityOperations.ReconcileAuthorizedAsync(context.ClientKey,context.RecoveryKey,t);
            status.Steps.Single().Succeeded.ShouldBe(true);
        },TestContext.Current.CancellationToken);
    private static async Task<T> Operation<T>(string purpose,Func<Task<T>> action)
    {
        using var current=SecurityOperationRequestContext.Push(new SecurityOperationRequestContext
        {ClientKey=SecurityOperationKey.Create(),RecoveryKey=Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
            Purpose=purpose,CanonicalBody=[]});
        return await action();
    }

    [Fact]
    public Task Actual_repository_maps_every_transition_and_promotion_consumes_durable_completion()
        => SqlContractFixture.RunAsync(async(f,t)=>
        {
            var c=await f.OpenConnectionAsync();var p=await Seed(f,c,t);
            var settings=new SecurityOperationSettings {HmacKeys=new(){[1]=Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))}};
            await using var storage=new Cor09RefreshHttpTests.FixtureStorage(f,settings);var repository=new LoginProofRepo(storage);
            var begun=await Operation("POST:/account/login",()=>repository.BeginAsync(Hash,p,t));begun.Result.ShouldBeTrue();p=begun.Snapshot!;
            p.selectedConfiguration=TwoFactorAuthConfiguration.EMAIL;p.challengedMethod=TwoFactorAuthMethod.EMAIL;p.chosenDestination=0;
            p.challengeCodeHash=Good;p.challengeExpiration=SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(2));
            var issued=await Operation("POST:/account/selecttwofactor",()=>repository.IssueAsync(Hash,p,5,30,t));issued.Result.ShouldBeTrue();p=issued.Snapshot!;
            var completed=await Operation("POST:/account/twofactorauth",()=>repository.CompleteAsync(Hash,p,Good,false,3,t));completed.Result.ShouldBeTrue();p=completed.Snapshot!;
            var now=SystemClock.Instance.GetCurrentInstant();
            var active=new ActiveSession(p.accountId,RandomNumberGenerator.GetBytes(64),0,now,Period.FromDays(7),
                now.Plus(Duration.FromMinutes(15)),now.Plus(Duration.FromDays(7)),null,p.features,accountSecurityStamp:p.accountSecurityStamp);
            (await Operation("POST:/account/twofactorauth",()=>repository.PromoteAsync(Hash,p,"cor10-active",active,t))).Result.ShouldBeTrue();
            (await repository.LoadAsync(Hash,t)).ShouldBeNull();
            (await Scalar<long>(c,"select count(*) from sessions where generation=1",t)).ShouldBe(1);
            (await Scalar<long>(c,"select count(*) from security_operation_steps where succeeded=true",t)).ShouldBe(4);
        },TestContext.Current.CancellationToken);

    [Fact]
    public Task Completion_commit_ack_loss_is_reconciled_and_restarted_repository_retains_completion()
        => SqlContractFixture.RunAsync(async(f,t)=>
        {
            var c=await f.OpenConnectionAsync();var p=(await Query(c,null,Issue(await Seed(f,c,t)),t)).Snapshot!;
            var parsed=new NpgsqlConnectionStringBuilder(DeferredSqlProcedureContractSettings.ConnectionString!);
            await using var proxy=new Cor04CommitAckLossProxy(parsed.Host,parsed.Port);
            var settings=new SecurityOperationSettings {HmacKeys=new(){[1]=Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))}};
            await using var first=new Cor09RefreshHttpTests.FixtureStorage(f,settings,proxy.Port);
            await using var recovered=new Cor09RefreshHttpTests.FixtureStorage(f,settings);
            var context=new SecurityOperationRequestContext {ClientKey=SecurityOperationKey.Create(),
                RecoveryKey=Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),Purpose="POST:/account/twofactorauth",CanonicalBody=[]};
            using(SecurityOperationRequestContext.Push(context))
            {
                await using(var admission=await first.SecurityOperations.BeginAsync("test.admission",new {admission=true},p.accountId,p.accountSecurityStamp,null,t))
                    await admission.CommitAsync(new {Result=true,Code="ADMITTED"});
                proxy.Arm();
                await Should.ThrowAsync<SecurityOperationException>(()=>new LoginProofRepo(first).CompleteAsync(Hash,p,Good,false,3,t));
            }
            await proxy.Dropped.WaitAsync(TimeSpan.FromSeconds(5),t);
            var status=await recovered.SecurityOperations.ReconcileAuthorizedAsync(context.ClientKey,context.RecoveryKey,t);
            status.Steps.Single(step=>step.Code=="LOGIN_PROOF_ACCEPTED").Succeeded.ShouldBe(true);
            var durable=await new LoginProofRepo(recovered).LoadAsync(Hash,t);durable!.isComplete.ShouldBeTrue();
            durable.challengeCodeHash.ShouldBeNull();durable.challengeId.ShouldBeNull();
            (await Scalar<long>(c,"select count(*) from sessions",t)).ShouldBe(0);
        },TestContext.Current.CancellationToken);

}
