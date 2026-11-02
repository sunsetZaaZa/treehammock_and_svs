using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Npgsql;
using Shouldly;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Config;
using treehammock.Tests.SqlContracts.Support;

namespace treehammock.Tests.Integration.Database;

// Executes actual PostgreSQL locks and verifies state from an independent
// connection. Seeded login is explicit; these are not password/2FA proof tests.
[Trait("Suite", "SqlContracts")]
public class Cor09SessionFamilyTests
{
    [Theory]
    [InlineData(-1,false)]
    [InlineData(0,false)]
    [InlineData(1,false)]
    [InlineData(1,true)]
    public Task Superseding_login_uses_database_time_and_retires_future_dated_family_atomically(int skewDays,bool conflict)
        => SqlContractFixture.RunAsync(async(f,t)=>
        {
            var c=await f.OpenConnectionAsync(t);var old=await Seed(f,c,t);var observer=await f.OpenConnectionAsync(t);
            await f.ExecuteAsync(c,$"update sessions set created_on=clock_timestamp()+make_interval(days=>{skewDays}),session_expiration=clock_timestamp()+interval '7 days' where access_token_hash='{old.Hash}'",cancellation:t);
            string refreshHash=await Scalar<string>(observer,$"select refresh_credential_hash from sessions where access_token_hash='{old.Hash}'",t);
            DateTime before=await Scalar<DateTime>(observer,"select clock_timestamp()",t);string next="replacement-"+Guid.NewGuid().ToString("N");
            await using var command=new NpgsqlCommand("select result from set_session(@hash,@account,@key,0::smallint,0::smallint,clock_timestamp()+make_interval(days=>@skew),interval '7 days',clock_timestamp()+interval '15 minutes',clock_timestamp()+interval '7 days',null,0::smallint,@family,@stamp)",c);
            command.Parameters.AddWithValue("hash",next);command.Parameters.AddWithValue("account",old.Account);command.Parameters.AddWithValue("key",RandomNumberGenerator.GetBytes(64));
            command.Parameters.AddWithValue("skew",skewDays);command.Parameters.AddWithValue("family",conflict?old.Family:Guid.NewGuid());command.Parameters.AddWithValue("stamp",old.Stamp);
            ((short)(await command.ExecuteScalarAsync(t))!).ShouldBe(conflict?(short)5000:(short)1);
            if(conflict)
            {
                (await Scalar<string>(observer,$"select refresh_credential_hash from sessions where access_token_hash='{old.Hash}'",t)).ShouldBe(refreshHash);
                (await Scalar<bool>(observer,$"select cut_off is null from sessions where access_token_hash='{old.Hash}'",t)).ShouldBeTrue();
            }
            else
            {
                (await Scalar<long>(observer,$"select count(*) from get_session('{old.Hash}')",t)).ShouldBe(0);
                (await Scalar<long>(observer,$"select count(*) from get_refresh_session('{refreshHash}','{old.Family}',1)",t)).ShouldBe(0);
                (await Scalar<long>(observer,$"select count(*) from get_session('{next}')",t)).ShouldBe(1);
                await using var issued=new NpgsqlCommand("select created_on>=@before and created_on<=clock_timestamp() from sessions where access_token_hash=@hash",observer);
                issued.Parameters.AddWithValue("before",before);issued.Parameters.AddWithValue("hash",next);((bool)(await issued.ExecuteScalarAsync(t))!).ShouldBeTrue();
            }
        },TestContext.Current.CancellationToken);

    internal sealed record SeededSession(Guid Account, Guid Stamp, Guid Family, byte[] Key, string Access, string Hash, string Refresh);
    internal static JWTSettings Settings() => new() { JsonWebTokenIssuer="cor09", RefreshTokenBytes=64,
        RefreshTokenAliveMinutes=15, RefreshTokenAliveMinutes_Short=15, RefreshTokenAliveDays_DB=7,
        MinimumRefreshIntervalSeconds=1 };
    internal static async Task<SeededSession> Seed(SqlContractFixture fixture,NpgsqlConnection connection,CancellationToken token)
    {
        var account=Guid.NewGuid(); var stamp=Guid.NewGuid(); var family=Guid.NewGuid(); var key=RandomNumberGenerator.GetBytes(64);
        var tokens=new JsonWebTokenUtility(NullLogger<JsonWebTokenUtility>.Instance,Options.Create(Settings()));
        string access=tokens.GenerateAccessToken(key,"cor09-web"),hash=AccessTokenHashUtility.Hash(access);
        await using var command=new NpgsqlCommand("""
            insert into accounts(account_id,email_address,verify_status,security_stamp,web_key)
            values(@account,@email,1,@stamp,'cor09-web');
            select * from set_session(@hash,@account,@key,0::smallint,0::smallint,clock_timestamp()-interval '2 minutes',
                interval '7 days',clock_timestamp()+interval '15 minutes',clock_timestamp()+interval '7 days',null,0::smallint,@family,@stamp);
            update sessions set token_issued_on=clock_timestamp()-interval '2 minutes' where access_token_hash=@hash;
            """,connection);
        command.Parameters.AddWithValue("account",account); command.Parameters.AddWithValue("email",account+"@example.invalid");
        command.Parameters.AddWithValue("stamp",stamp); command.Parameters.AddWithValue("hash",hash);
        command.Parameters.AddWithValue("key",key); command.Parameters.AddWithValue("family",family);
        await command.ExecuteNonQueryAsync(token);
        return new(account,stamp,family,key,access,hash,SessionProtocol.RefreshCredential(key,family));
    }
    internal static async Task<(bool Result,string Code)> Rotate(NpgsqlConnection connection,NpgsqlTransaction? transaction,
        SeededSession session,CancellationToken token,int minimumInterval=1,string? newHash=null)
    {
        await using var command=new NpgsqlCommand("""
            select result,code from refresh_session(@account,@stamp,@family,1::bigint,@old,@refresh,@new,@key,@identity,900,@interval)
            """,connection,transaction);
        command.Parameters.AddWithValue("account",session.Account); command.Parameters.AddWithValue("stamp",session.Stamp);
        command.Parameters.AddWithValue("family",session.Family); command.Parameters.AddWithValue("old",session.Hash);
        command.Parameters.AddWithValue("refresh",AccessTokenHashUtility.Hash(session.Refresh));
        command.Parameters.AddWithValue("new",newHash??AccessTokenHashUtility.Hash(Guid.NewGuid().ToString()));
        command.Parameters.AddWithValue("key",RandomNumberGenerator.GetBytes(64)); command.Parameters.AddWithValue("identity",Guid.NewGuid());
        command.Parameters.AddWithValue("interval",minimumInterval);
        await using var reader=await command.ExecuteReaderAsync(token); (await reader.ReadAsync(token)).ShouldBeTrue();
        return(reader.GetBoolean(0),reader.GetString(1));
    }
    internal static async Task<T> Scalar<T>(NpgsqlConnection connection,string sql,CancellationToken token)
    { await using var command=new NpgsqlCommand(sql,connection); return(T)(await command.ExecuteScalarAsync(token))!; }

    [Fact]
    public Task Concurrent_refresh_rotates_once_and_listed_family_remains_a_revoke_target()
        => SqlContractFixture.RunAsync(async(fixture,token)=>
        {
            var observer=await fixture.OpenConnectionAsync(); var seed=await Seed(fixture,observer,token);
            (await Scalar<string>(observer,$"select refresh_credential_hash from sessions where session_id='{seed.Family}'",token)).ShouldBe(AccessTokenHashUtility.Hash(seed.Refresh));
            var first=await fixture.OpenConnectionAsync(); var second=await fixture.OpenConnectionAsync();
            var holding=await fixture.BeginTransactionAsync(first); var competing=await fixture.BeginTransactionAsync(second);
            (await Rotate(first,holding,seed,token)).Result.ShouldBeTrue();
            var pending=fixture.Observe(Rotate(second,competing,seed,token));
            await SqlInterleavingBarrier.WaitForBlockedAsync(observer,second.ProcessID,first.ProcessID,pending,token);
            await holding.CommitAsync(token); (await pending).Code.ShouldBe("REFRESH_CREDENTIAL_STALE"); await competing.CommitAsync(token);
            (await Scalar<long>(observer,"select count(*) from sessions where session_expiration>clock_timestamp()",token)).ShouldBe(1);
            (await Scalar<long>(observer,"select generation from sessions where session_expiration>clock_timestamp()",token)).ShouldBe(2);
            (await Scalar<Guid>(observer,$"select session_id from list_active_sessions('{seed.Account}','{seed.Stamp}','{seed.Hash}')",token)).ShouldBe(seed.Family);
            await fixture.ExecuteAsync(observer,$"select * from revoke_session_for_account('{seed.Account}','{seed.Family}','{seed.Stamp}','{seed.Hash}')",cancellation:token);
            (await Scalar<long>(observer,"select count(*) from sessions where session_expiration>clock_timestamp()",token)).ShouldBe(0);
            (await Scalar<long>(observer,$"select count(*) from get_refresh_session((select refresh_credential_hash from sessions where generation=2),'{seed.Family}',2)",token)).ShouldBe(0);
        },TestContext.Current.CancellationToken);

    [Theory]
    [InlineData(true)] [InlineData(false)]
    public Task Refresh_and_already_validated_logout_both_lock_orders_leave_family_revoked(bool refreshWins)
        => SqlContractFixture.RunAsync(async(fixture,token)=>
        {
            var observer=await fixture.OpenConnectionAsync(); var seed=await Seed(fixture,observer,token);
            var first=await fixture.OpenConnectionAsync(); var second=await fixture.OpenConnectionAsync();
            var holding=await fixture.BeginTransactionAsync(first); var competing=await fixture.BeginTransactionAsync(second);
            string logout=$"select result,code from logout_current_session('{seed.Account}','{seed.Hash}','{seed.Stamp}')";
            if(refreshWins) (await Rotate(first,holding,seed,token)).Result.ShouldBeTrue();
            else await fixture.ExecuteAsync(first,logout,holding,token);
            Task pending=refreshWins?fixture.Observe(fixture.ExecuteAsync(second,logout,competing,token)):fixture.Observe(Rotate(second,competing,seed,token));
            await SqlInterleavingBarrier.WaitForBlockedAsync(observer,second.ProcessID,first.ProcessID,pending,token);
            await holding.CommitAsync(token); await pending; await competing.CommitAsync(token);
            (await Scalar<long>(observer,"select count(*) from sessions where session_expiration>clock_timestamp()",token)).ShouldBe(0);
        },TestContext.Current.CancellationToken);

    [Theory]
    [InlineData("access_expiration=clock_timestamp()-interval '1 second'",true)]
    [InlineData("session_expiration=clock_timestamp(),access_expiration=clock_timestamp()",false)]
    [InlineData("cut_off=clock_timestamp()",false)]
    public Task Access_and_refresh_lifetimes_have_distinct_exclusive_boundaries(string update,bool allowed)
        => SqlContractFixture.RunAsync(async(fixture,token)=>
        {
            var observer=await fixture.OpenConnectionAsync(); var seed=await Seed(fixture,observer,token);
            await fixture.ExecuteAsync(observer,"update sessions set "+update,cancellation:token);
            (await Rotate(observer,null,seed,token)).Result.ShouldBe(allowed);
            (await Scalar<long>(observer,"select count(*) from sessions",token)).ShouldBe(allowed?2:1);
        },TestContext.Current.CancellationToken);

    [Fact]
    public Task Renewal_rate_and_hard_deadline_are_enforced_without_the_old_three_refresh_limit()
        => SqlContractFixture.RunAsync(async(fixture,token)=>
        {
            var observer=await fixture.OpenConnectionAsync(); var seed=await Seed(fixture,observer,token);
            var hard=await Scalar<DateTime>(observer,"select session_expiration from sessions",token);
            await fixture.ExecuteAsync(observer,"update sessions set token_issued_on=clock_timestamp(),refreshes=32767,refresh_limit=3",cancellation:token);
            (await Rotate(observer,null,seed,token,60)).Code.ShouldBe("REFRESH_TOO_EARLY");
            await fixture.ExecuteAsync(observer,"update sessions set token_issued_on=clock_timestamp()-interval '61 seconds'",cancellation:token);
            (await Rotate(observer,null,seed,token,60)).Result.ShouldBeTrue();
            (await Scalar<DateTime>(observer,"select session_expiration from sessions where generation=2",token)).ShouldBe(hard);
            (await Scalar<short>(observer,"select refreshes from sessions where generation=2",token)).ShouldBe(short.MaxValue);
        },TestContext.Current.CancellationToken);

    [Fact]
    public Task Hard_expiry_during_account_lock_wait_denies_without_partial_rotation()
        => SqlContractFixture.RunAsync(async(fixture,token)=>
        {
            var observer=await fixture.OpenConnectionAsync(); var seed=await Seed(fixture,observer,token);
            var blocker=await fixture.OpenConnectionAsync(); var contender=await fixture.OpenConnectionAsync();
            var holding=await fixture.BeginTransactionAsync(blocker); var competing=await fixture.BeginTransactionAsync(contender);
            await fixture.ExecuteAsync(blocker,$"select 1 from accounts where account_id='{seed.Account}' for update",holding,token);
            var pending=fixture.Observe(Rotate(contender,competing,seed,token));
            await SqlInterleavingBarrier.WaitForBlockedAsync(observer,contender.ProcessID,blocker.ProcessID,pending,token);
            // The contender has its old snapshot and transaction timestamp.
            // Expire current authority under the blocker, then release it.
            await fixture.ExecuteAsync(blocker,"update sessions set session_expiration=clock_timestamp(),access_expiration=clock_timestamp()",holding,token);
            await holding.CommitAsync(token); (await pending).Result.ShouldBeFalse(); await competing.CommitAsync(token);
            (await Scalar<long>(observer,"select count(*) from sessions",token)).ShouldBe(1);
        },TestContext.Current.CancellationToken);

    [Fact]
    public Task Account_stamp_change_fences_the_prior_refresh_credential()
        => SqlContractFixture.RunAsync(async(fixture,token)=>
        {
            var observer=await fixture.OpenConnectionAsync(); var seed=await Seed(fixture,observer,token);
            await fixture.ExecuteAsync(observer,$"select * from logout_all_sessions('{seed.Account}','{seed.Stamp}')",cancellation:token);
            (await Rotate(observer,null,seed,token)).Result.ShouldBeFalse();
            (await Scalar<long>(observer,"select count(*) from sessions",token)).ShouldBe(1);
        },TestContext.Current.CancellationToken);

    [Fact]
    public Task Fresh_password_login_replaces_the_family_and_fences_a_delayed_refresh()
        => SqlContractFixture.RunAsync(async(fixture,token)=>
        {
            var observer=await fixture.OpenConnectionAsync();var seed=await Seed(fixture,observer,token);var replacement=Guid.NewGuid();
            await fixture.ExecuteAsync(observer,$"""
                select * from rotate_active_session('{seed.Account}','{seed.Hash}',repeat('D',64),gen_random_bytes(64),0::smallint,0::smallint,
                    clock_timestamp(),interval '7 days',clock_timestamp()+interval '15 minutes',clock_timestamp()+interval '7 days',
                    null,0::smallint,'{replacement}','{seed.Stamp}')
                """,cancellation:token);
            (await Rotate(observer,null,seed,token)).Result.ShouldBeFalse();
            (await Scalar<Guid>(observer,"select session_id from sessions where session_expiration>clock_timestamp()",token)).ShouldBe(replacement);
            (await Scalar<long>(observer,"select count(*) from sessions where session_expiration>clock_timestamp()",token)).ShouldBe(1);
        },TestContext.Current.CancellationToken);

    [Fact]
    public Task Sensitive_grant_binds_the_stable_family_and_still_denies_the_superseded_generation()
        => SqlContractFixture.RunAsync(async(fixture,token)=>
        {
            var observer=await fixture.OpenConnectionAsync();var seed=await Seed(fixture,observer,token);var attempt=Guid.NewGuid();
            await fixture.ExecuteAsync(observer,$"""
                select * from cor08_begin_password_proof('{seed.Account}','{seed.Stamp}','{seed.Hash}','{attempt}',1::smallint,repeat('a',64),5,900,30);
                select * from cor08_finish_password_proof('{seed.Account}','{seed.Stamp}','{seed.Hash}','{attempt}',true,repeat('b',64),repeat('c',64),10);
                """,cancellation:token); // Trusted verifier substitution is explicit.
            (await Scalar<Guid>(observer,"select family_id from sensitive_action_grants",token)).ShouldBe(seed.Family);
            string validate=$"select cor08_validate_sensitive_grant('{seed.Account}','{seed.Stamp}','{seed.Hash}',repeat('c',64),1::smallint,repeat('a',64),false)";
            (await Scalar<bool>(observer,validate,token)).ShouldBeTrue();
            (await Rotate(observer,null,seed,token)).Result.ShouldBeTrue();
            (await Scalar<bool>(observer,validate,token)).ShouldBeFalse();
        },TestContext.Current.CancellationToken);

    [Fact]
    public Task Expiry_during_new_generation_index_wait_rolls_back_every_rotation_write()
        => SqlContractFixture.RunAsync(async(fixture,token)=>
        {
            var observer=await fixture.OpenConnectionAsync();var seed=await Seed(fixture,observer,token);
            var blocker=await fixture.OpenConnectionAsync();var contender=await fixture.OpenConnectionAsync();
            var holding=await fixture.BeginTransactionAsync(blocker);var competing=await fixture.BeginTransactionAsync(contender);
            var otherAccount=Guid.NewGuid();
            await fixture.ExecuteAsync(observer,$"insert into accounts(account_id,email_address,verify_status,security_stamp) values('{otherAccount}','{otherAccount}@example.invalid',1,'{seed.Stamp}')",cancellation:token);
            const string hash="EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE";
            await fixture.ExecuteAsync(blocker,$"""
                insert into sessions(access_token_hash,account_id,access_expiration,session_expiration,account_security_stamp)
                values('{hash}','{otherAccount}',clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours','{seed.Stamp}')
                """,holding,token);
            await fixture.ExecuteAsync(observer,"update sessions set access_expiration=clock_timestamp()+interval '3 seconds',session_expiration=clock_timestamp()+interval '3 seconds'",cancellation:token);
            var pending=fixture.Observe(Rotate(contender,competing,seed,token,newHash:hash));
            await SqlInterleavingBarrier.WaitForBlockedAsync(observer,contender.ProcessID,blocker.ProcessID,pending,token);
            while(!await Scalar<bool>(observer,"select clock_timestamp()>=session_expiration from sessions",token))
                await Task.Delay(20,token);
            await holding.RollbackAsync(token);(await pending).Code.ShouldBe("REFRESH_CREDENTIAL_EXPIRED");await competing.CommitAsync(token);
            (await Scalar<long>(observer,"select count(*) from sessions",token)).ShouldBe(1);
            (await Scalar<long>(observer,"select max(generation) from sessions",token)).ShouldBe(1);
        },TestContext.Current.CancellationToken);
}
