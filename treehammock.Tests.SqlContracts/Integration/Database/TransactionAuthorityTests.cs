using Npgsql;
using Shouldly;
using treehammock.Tests.SqlContracts.Support;

namespace treehammock.Tests.Integration.Database;

[Trait("Suite", "SqlContracts")]
public class Cor02TransactionAuthorityTests
{
    private const string Id = "'00000000-0000-0000-0000-000000000101'::uuid";
    private const string Stamp = "'00000000-0000-0000-0000-000000000201'::uuid";
    private const string NewStamp = "'00000000-0000-0000-0000-000000000202'::uuid";
    private const string Reset = "'00000000-0000-0000-0000-000000000301'::uuid";
    private static string CreateReset(string reset = Reset) => $"select result,code from create_password_reset_request({reset},{Id},'email','email','proof',1,'fingerprint','masked',true,false,clock_timestamp()+interval '1 hour',5,null,null,{Stamp})";
    private static string PromoteReset => $"select result,code from promote_password_reset({Reset},{Id},decode(repeat('01',128),'hex'),decode(repeat('02',64),'hex'),decode(repeat('03',32),'hex'),decode(repeat('04',16),'hex'),{NewStamp},clock_timestamp()-interval '1 hour','reset-authorization',1::bigint,0::bigint)";
    private const string FactorRequest="'00000000-0000-0000-0000-000000001616'::uuid";
    private static string BeginFactor => $"select result,code from cor16_begin_twofactor_setup({Id},{Stamp},1::smallint,'factor-proof',clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 hour','old@example.invalid',null,null,null,true,{FactorRequest},null,null,'cor16-fixture',repeat('d',64),repeat('a',64))";
    private static string VerifyFactor => $"select result,code from verify_twofactor_setup({Id},{Stamp},1::smallint,'factor-proof',5,clock_timestamp()-interval '100 years',{FactorRequest},1::bigint,(select session_id from sessions where access_token_hash='cor16-fixture'))";
    private static string BeginAuthenticator => $"select result,code from cor08_authorized_begin_authenticator_app_setup({Id},{Stamp},'auth-proof',clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 hour',null,true,1::smallint,decode(repeat('01',20),'hex'),decode(repeat('02',12),'hex'),decode(repeat('03',16),'hex'),2,'fixture',gen_random_uuid(),'SHA1',6,30,1,(select setup_request_id from two_factor_authentications where account_id={Id} and not verified),(select setup_version from two_factor_authentications where account_id={Id} and not verified),'cor02-grant-session',repeat('c',64),repeat('a',64))";
    private static string CompleteAuthenticator => $"select result,code from complete_authenticator_app_setup_and_rotate_session({Id},{Stamp},'auth-proof',1,'cor02-grant-session','new-session','\\x01'::bytea,0::smallint,5::smallint,clock_timestamp()-interval '1 hour',interval '1 hour',clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours',null,0::smallint,{NewStamp})";
    private static string DeleteAccount => Cor18DeleteSql.Commit(Id,Stamp);

    private static async Task SeedAccount(SqlContractFixture fixture, NpgsqlConnection connection, CancellationToken cancellation)
    {
        await fixture.ExecuteAsync(connection, $"insert into accounts(account_id,email_address,verify_status,security_stamp) values({Id},'old@example.invalid',1,{Stamp})", cancellation: cancellation);
        await Cor18DeleteSql.Install(connection,cancellation);
        await Cor16EnrollmentSql.SeedGrant(connection,Guid.Parse(Id.Substring(1,36)),Guid.Parse(Stamp.Substring(1,36)),3,cancellation,new string('d',64),"cor16-fixture");
        await Cor16EnrollmentSql.PublishFixture(connection,Guid.Parse(Id.Substring(1,36)),Guid.Parse(Stamp.Substring(1,36)),1,"factor-proof",Guid.Parse(FactorRequest.Substring(1,36)),cancellation);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Reset_create_and_promote_serialize_without_child_parent_inversion(bool promotionWins)
    {
        await SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            var observer = await fixture.OpenConnectionAsync();
            await SeedAccount(fixture, observer, cancellation);
            (await Query(observer, null, CreateReset(), cancellation)).Result.ShouldBeTrue();
            await fixture.ExecuteAsync(observer, Cor13ResetSql.Bootstrap(Id.Substring(1,36), Reset.Substring(1,36)), cancellation: cancellation);
            var blocker = await fixture.OpenConnectionAsync();
            var contender = await fixture.OpenConnectionAsync();
            var holding = await fixture.BeginTransactionAsync(blocker);
            await fixture.ExecuteAsync(blocker, $"select 1 from accounts where account_id={Id} for update", holding, cancellation);
            var competing = await fixture.BeginTransactionAsync(contender);
            var task = fixture.Observe(Query(contender, competing, promotionWins ? CreateReset("'00000000-0000-0000-0000-000000000302'::uuid") : PromoteReset, cancellation));
            await Observe(fixture, observer, contender, blocker, task, cancellation);
            // The old promoter already owned the reset here, causing a cycle
            // when the account owner attempted to create/cancel that reset.
            (await Query(blocker, holding, promotionWins ? PromoteReset : CreateReset("'00000000-0000-0000-0000-000000000302'::uuid"), cancellation)).Result.ShouldBeTrue();
            await holding.CommitAsync(cancellation);
            var result = await task;
            result.Result.ShouldBeFalse();
            result.Code.ShouldBe(promotionWins ? "ACCOUNT_SECURITY_STAMP_MISMATCH" : "PASSWORD_RESET_CANCELLED");
            await competing.CommitAsync(cancellation);
            (await Scalar<long>(observer, "select count(*) from password_reset_events where code='PASSWORD_RESET_COMPLETED'", cancellation)).ShouldBe(promotionWins ? 1L : 0L);
        }, TestContext.Current.CancellationToken);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Factor_verify_serializes_with_removal_or_authenticator_start(bool replaceWithAuthenticator)
    {
        await SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            var observer = await fixture.OpenConnectionAsync();
            await SeedAccount(fixture, observer, cancellation);
            (await Query(observer, null, BeginFactor, cancellation)).Result.ShouldBeTrue();
            await PrepareGrant(fixture, observer, replaceWithAuthenticator ? 1 : 2, cancellation);
            var blocker = await fixture.OpenConnectionAsync();
            var contender = await fixture.OpenConnectionAsync();
            var holding = await fixture.BeginTransactionAsync(blocker);
            await fixture.ExecuteAsync(blocker, $"select 1 from accounts where account_id={Id} for update", holding, cancellation);
            var competing = await fixture.BeginTransactionAsync(contender);
            var task = fixture.Observe(Query(contender, competing, VerifyFactor, cancellation));
            await Observe(fixture, observer, contender, blocker, task, cancellation);
            var mutation = await Query(blocker, holding, replaceWithAuthenticator ? BeginAuthenticator : $"select result,code from cor08_authorized_remove_twofactor_method({Id},{Stamp},1::smallint,clock_timestamp(),'cor02-grant-session',repeat('c',64),repeat('a',64))", cancellation);
            mutation.Code.ShouldBe(replaceWithAuthenticator ? "AUTHENTICATOR_SETUP_PENDING" : "TWO_FACTOR_METHOD_NOT_CONFIGURED");
            await holding.CommitAsync(cancellation);
            (await task).Code.ShouldBe("TWO_FACTOR_SETUP_CONFLICT");
            await competing.CommitAsync(cancellation);
            (await Scalar<long>(observer, "select count(*) from two_factor_authentications where verified", cancellation)).ShouldBe(0);
        }, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task Email_completion_waits_for_deletion_and_revalidates_the_removed_proof()
    {
        await SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            var observer = await fixture.OpenConnectionAsync();
            await SeedAccount(fixture, observer, cancellation);
            await SeedEmailAndDelete(fixture, observer, cancellation);
            var blocker = await fixture.OpenConnectionAsync();
            var contender = await fixture.OpenConnectionAsync();
            var holding = await fixture.BeginTransactionAsync(blocker);
            await fixture.ExecuteAsync(blocker, $"select 1 from accounts where account_id={Id} for update", holding, cancellation);
            var competing = await fixture.BeginTransactionAsync(contender);
            var task = fixture.Observe(Query(contender, competing, "select result,code from complete_account_email_change('email-proof')", cancellation));
            await Observe(fixture, observer, contender, blocker, task, cancellation);
            (await Query(blocker, holding, DeleteAccount, cancellation)).Result.ShouldBeTrue();
            await holding.CommitAsync(cancellation);
            (await task).Code.ShouldBe("ACCOUNT_ADJUST_TOKEN_MISMATCH");
            await competing.CommitAsync(cancellation);
            (await Scalar<long>(observer, "select count(*) from accounts", cancellation)).ShouldBe(0);
        }, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task Email_completion_rotates_stamp_before_a_waiting_deletion_revalidates()
    {
        await SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            var observer = await fixture.OpenConnectionAsync();
            await SeedAccount(fixture, observer, cancellation);
            await SeedEmailAndDelete(fixture, observer, cancellation);
            var blocker = await fixture.OpenConnectionAsync();
            var contender = await fixture.OpenConnectionAsync();
            var holding = await fixture.BeginTransactionAsync(blocker);
            (await Query(blocker, holding, "select result,code from complete_account_email_change('email-proof')", cancellation)).Result.ShouldBeTrue();
            var competing = await fixture.BeginTransactionAsync(contender);
            var task = fixture.Observe(Query(contender, competing, DeleteAccount, cancellation));
            await Observe(fixture, observer, contender, blocker, task, cancellation);
            await holding.CommitAsync(cancellation);
            (await task).Code.ShouldBe("ACCOUNT_SECURITY_STAMP_MISMATCH");
            await competing.CommitAsync(cancellation);
            (await Scalar<long>(observer, "select count(*) from account_delete_events where event_type='COMPLETED'", cancellation)).ShouldBe(0);
        }, TestContext.Current.CancellationToken);
    }

    [Theory]
    [InlineData("registration", false)] [InlineData("registration", true)]
    [InlineData("email", false)] [InlineData("email", true)]
    [InlineData("factor", false)] [InlineData("factor", true)]
    [InlineData("authenticator", false)] [InlineData("authenticator", true)]
    [InlineData("unlock", false)] [InlineData("unlock", true)]
    [InlineData("reset", false)] [InlineData("reset", true)]
    [InlineData("delete", false)] [InlineData("delete", true)]
    public async Task Completion_rechecks_SQL_time_after_account_or_proof_wait(string kind, bool proofWait)
    {
        await SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            var observer = await fixture.OpenConnectionAsync();
            await SeedAccount(fixture, observer, cancellation);
            var schedule = await SeedExpiry(fixture, observer, kind, cancellation);
            string before = await Scalar<string>(observer, "select jsonb_build_array(email_address,security_stamp,verify_status,unlock_when)::text from accounts", cancellation);
            var blocker = await fixture.OpenConnectionAsync();
            var contender = await fixture.OpenConnectionAsync();
            var holding = await fixture.BeginTransactionAsync(blocker);
            var competing = await fixture.BeginTransactionAsync(contender); // transaction now() precedes expiry
            await fixture.ExecuteAsync(blocker, proofWait ? schedule.Lock : $"select 1 from accounts where account_id={Id} for update", holding, cancellation);
            // Deadline is established after all setup, without relying on host clock.
            await fixture.ExecuteAsync(blocker, schedule.SetExpiry, holding, cancellation);
            // The new deadline is uncommitted; expose it independently from the proof row.
            DateTime deadline = await Scalar<DateTime>(blocker, schedule.Expiry, cancellation, holding);
            var task = fixture.Observe(Query(contender, competing, schedule.Complete, cancellation));
            await Observe(fixture, observer, contender, blocker, task, cancellation);
            await WaitForDatabaseTime(observer, deadline, cancellation);
            await holding.CommitAsync(cancellation);
            var result = await task;
            result.Result.ShouldBeFalse();
            result.Code.ShouldBe(schedule.Code);
            await competing.CommitAsync(cancellation);
            (await Scalar<string>(observer, "select jsonb_build_array(email_address,security_stamp,verify_status,unlock_when)::text from accounts", cancellation)).ShouldBe(before);
            (await Scalar<long>(observer, schedule.SuccessCount, cancellation)).ShouldBe(0);
        }, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task Late_audit_wait_expiry_rolls_back_password_stamp_consumption_and_success_audit()
    {
        await SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            var observer = await fixture.OpenConnectionAsync();
            await SeedAccount(fixture, observer, cancellation);
            (await Query(observer, null, CreateReset(), cancellation)).Result.ShouldBeTrue();
            await fixture.ExecuteAsync(observer, Cor13ResetSql.Bootstrap(Id.Substring(1,36), Reset.Substring(1,36)), cancellation: cancellation);
            await fixture.ExecuteAsync(observer, """
                create function block_success_audit() returns trigger language plpgsql as $$ begin
                    if new.code='PASSWORD_RESET_COMPLETED' then perform pg_advisory_xact_lock(548013002); end if;
                    return new; end; $$;
                create trigger test_late_audit before insert on password_reset_events for each row execute function block_success_audit();
                update password_reset_requests set expires_at=clock_timestamp()+interval '2 seconds';
                """, cancellation: cancellation);
            DateTime deadline = await Scalar<DateTime>(observer, "select expires_at from password_reset_requests", cancellation);
            var blocker = await fixture.OpenConnectionAsync();
            var contender = await fixture.OpenConnectionAsync();
            var holding = await fixture.BeginTransactionAsync(blocker);
            await fixture.ExecuteAsync(blocker, "select pg_advisory_xact_lock(548013002)", holding, cancellation);
            var competing = await fixture.BeginTransactionAsync(contender);
            var task = fixture.Observe(Query(contender, competing, PromoteReset, cancellation));
            await Observe(fixture, observer, contender, blocker, task, cancellation);
            await WaitForDatabaseTime(observer, deadline, cancellation);
            await holding.CommitAsync(cancellation);
            (await task).Code.ShouldBe("PASSWORD_RESET_EXPIRED");
            await competing.CommitAsync(cancellation);
            (await Scalar<Guid>(observer, "select security_stamp from accounts", cancellation)).ShouldBe(Guid.Parse("00000000-0000-0000-0000-000000000201"));
            (await Scalar<long>(observer, "select count(*) from password_reset_requests where consumed_at is not null or cancelled_at is not null", cancellation)).ShouldBe(0);
            (await Scalar<long>(observer, "select count(*) from password_reset_events where code='PASSWORD_RESET_COMPLETED'", cancellation)).ShouldBe(0);
            (await Scalar<bool>(observer, "select hashed_password=decode(repeat('00',128),'hex') from accounts", cancellation)).ShouldBeTrue();
        }, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task Exact_expiry_equality_is_expired_and_authority_ignores_backward_host_skew()
    {
        await SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            var connection = await fixture.OpenConnectionAsync();
            (await Scalar<bool>(connection, "select cor02_expiration_is_live('2026-01-01 00:00:00+00'::timestamptz,'2026-01-01 00:00:00+00'::timestamptz)", cancellation)).ShouldBeFalse();
            await SeedAccount(fixture, connection, cancellation);
            (await Query(connection, null, BeginFactor, cancellation)).Result.ShouldBeTrue();
            await fixture.ExecuteAsync(connection, "update two_factor_authentications set expiration=clock_timestamp()-interval '1 second'", cancellation: cancellation);
            (await Query(connection, null, VerifyFactor, cancellation)).Code.ShouldBe("TWO_FACTOR_SETUP_EXPIRED");
        }, TestContext.Current.CancellationToken);
    }

    [Theory]
    [InlineData(-100)]
    [InlineData(100)]
    public async Task Live_factor_eligibility_uses_database_time_despite_host_skew(int skewYears)
    {
        await SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            var connection = await fixture.OpenConnectionAsync();
            await SeedAccount(fixture, connection, cancellation);
            (await Query(connection, null, BeginFactor, cancellation)).Result.ShouldBeTrue();
            (await Query(connection, null, $"select result,code from verify_twofactor_setup({Id},{Stamp},1::smallint,'factor-proof',5,clock_timestamp()+interval '{skewYears} years',{FactorRequest},1::bigint,(select session_id from sessions where access_token_hash='cor16-fixture'))", cancellation)).Code.ShouldBe("TWO_FACTOR_SETUP_VERIFIED");
        }, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task Proof_replacement_while_waiting_for_account_rejects_the_original_public_token()
    {
        await SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            var observer = await fixture.OpenConnectionAsync();
            await SeedAccount(fixture, observer, cancellation);
            await SeedEmailAndDelete(fixture, observer, cancellation);
            var blocker = await fixture.OpenConnectionAsync();
            var contender = await fixture.OpenConnectionAsync();
            var holding = await fixture.BeginTransactionAsync(blocker);
            await fixture.ExecuteAsync(blocker, $"select 1 from accounts where account_id={Id} for update", holding, cancellation);
            var competing = await fixture.BeginTransactionAsync(contender);
            var task = fixture.Observe(Query(contender, competing, "select result,code from complete_account_email_change('email-proof')", cancellation));
            await Observe(fixture, observer, contender, blocker, task, cancellation);
            await fixture.ExecuteAsync(blocker, "update account_email_change_requests set verify_key_hash='replacement-proof'", holding, cancellation);
            await holding.CommitAsync(cancellation);
            (await task).Code.ShouldBe("ACCOUNT_ADJUST_TOKEN_MISMATCH");
            await competing.CommitAsync(cancellation);
            (await Scalar<string>(observer, "select email_address from accounts", cancellation)).ShouldBe("old@example.invalid");
        }, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task Caller_rollback_undoes_success_mutations_and_success_audit_together()
    {
        await SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            var observer = await fixture.OpenConnectionAsync();
            await SeedAccount(fixture, observer, cancellation);
            (await Query(observer, null, CreateReset(), cancellation)).Result.ShouldBeTrue();
            await fixture.ExecuteAsync(observer, Cor13ResetSql.Bootstrap(Id.Substring(1,36), Reset.Substring(1,36)), cancellation: cancellation);
            var connection = await fixture.OpenConnectionAsync();
            var transaction = await fixture.BeginTransactionAsync(connection);
            (await Query(connection, transaction, PromoteReset, cancellation)).Result.ShouldBeTrue();
            await transaction.RollbackAsync(cancellation);
            (await Scalar<Guid>(observer, "select security_stamp from accounts", cancellation)).ShouldBe(Guid.Parse("00000000-0000-0000-0000-000000000201"));
            (await Scalar<long>(observer, "select count(*) from password_reset_events where code='PASSWORD_RESET_COMPLETED'", cancellation)).ShouldBe(0);
            (await Scalar<long>(observer, "select count(*) from password_reset_requests where consumed_at is not null", cancellation)).ShouldBe(0);
        }, TestContext.Current.CancellationToken);
    }

    [Theory]
    [InlineData("factor")] [InlineData("authenticator")] [InlineData("reset")]
    [InlineData("email")] [InlineData("delete")] [InlineData("unlock")]
    public async Task Issuance_rejects_a_deadline_that_passes_while_waiting_for_account(string kind)
    {
        await SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            var observer = await fixture.OpenConnectionAsync();
            await SeedAccount(fixture, observer, cancellation);
            string sql, table;
            switch (kind)
            {
                case "factor": sql = BeginFactor.Replace("clock_timestamp()+interval '1 hour'", "@deadline"); table = "two_factor_authentications"; break;
                case "authenticator": await PrepareGrant(fixture, observer, 1, cancellation); sql = BeginAuthenticator.Replace("clock_timestamp()+interval '1 hour'", "@deadline"); table = "two_factor_authentications"; break;
                case "reset": sql = CreateReset().Replace("clock_timestamp()+interval '1 hour'", "@deadline"); table = "password_reset_requests"; break;
                case "email": await Cor17EmailSql.Install(observer,cancellation); sql = $"select result,code from cor17_fixture_request_email({Id},{Stamp},'new@example.invalid','email-proof',@deadline)"; table = "account_email_change_requests"; break;
                case "delete": sql = $"select result,code from cor18_fixture_request_delete({Id},{Stamp},null,'delete-proof',@deadline,interval '1 minute',interval '1 hour',5::smallint)"; table = "delete_standby"; break;
                case "unlock":
                    await fixture.ExecuteAsync(observer, "update accounts set unlock_when='2100-01-01 00:00:00+00'", cancellation: cancellation);
                    sql = $"select status=1 as result,status::text as code from start_unlock_account({Id},'unlock-proof',clock_timestamp(),@deadline,1::smallint,1::smallint,{Stamp},'2100-01-01 00:00:00+00'::timestamptz,'00000000-0000-0000-0000-000000000000'::uuid)"; table = "account_recoveries"; break;
                case "activation": sql = $"select result,code from place_activation({Id},{Stamp},'old@example.invalid','activation-proof',clock_timestamp(),1::smallint,0::smallint,@deadline,0::smallint,1::smallint,'test',1::smallint,null)"; table = "activations"; break;
                default: throw new ArgumentOutOfRangeException(nameof(kind));
            }
            var blocker = await fixture.OpenConnectionAsync();
            var contender = await fixture.OpenConnectionAsync();
            var holding = await fixture.BeginTransactionAsync(blocker);
            await fixture.ExecuteAsync(blocker, $"select 1 from accounts where account_id={Id} for update", holding, cancellation);
            DateTime deadline = await Scalar<DateTime>(observer, "select clock_timestamp()+interval '2 seconds'", cancellation);
            var competing = await fixture.BeginTransactionAsync(contender);
            var task = fixture.Observe(Query(contender, competing, sql, cancellation, deadline));
            await Observe(fixture, observer, contender, blocker, task, cancellation);
            await WaitForDatabaseTime(observer, deadline, cancellation);
            await holding.CommitAsync(cancellation);
            (await task).Result.ShouldBeFalse();
            await competing.CommitAsync(cancellation);
            (await Scalar<long>(observer, $"select count(*) from {table}", cancellation)).ShouldBe(0);
            (await Scalar<long>(observer, "select count(*) from password_reset_events where code='PASSWORD_RESET_REQUEST_CREATED'", cancellation)).ShouldBe(0);
            (await Scalar<long>(observer, "select count(*) from account_delete_events where event_type='REQUESTED'", cancellation)).ShouldBe(0);
        }, TestContext.Current.CancellationToken);
    }

    // COR08 requires authority before the existing COR02 contention schedules.
    // Verified-password success below is an explicit trusted-proof substitution.
    private static async Task PrepareGrant(SqlContractFixture fixture, NpgsqlConnection connection, int purpose, CancellationToken cancellation)
    {
        Guid attempt = Guid.NewGuid();
        await fixture.ExecuteAsync(connection, $"""
            insert into sessions(access_token_hash,account_id,created_on,access_expiration,session_expiration,account_security_stamp)
            values('cor02-grant-session',{Id},clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours',{Stamp});
            """, cancellation: cancellation);
        (await Query(connection, null, $"select result,code from cor08_begin_password_proof({Id},{Stamp},'cor02-grant-session','{attempt}'::uuid,{purpose}::smallint,repeat('a',64),5,900,30)", cancellation)).Result.ShouldBeTrue();
        (await Query(connection, null, $"select result,code from cor08_finish_password_proof({Id},{Stamp},'cor02-grant-session','{attempt}'::uuid,true,repeat('b',64),repeat('c',64),10)", cancellation)).Result.ShouldBeTrue();
    }

    private static async Task SeedEmailAndDelete(SqlContractFixture fixture,NpgsqlConnection connection,CancellationToken cancellation)
    {
        await Cor17EmailSql.Install(connection,cancellation);
        await Cor18DeleteSql.Install(connection,cancellation);
        (await Query(connection,null,$"select result,code from cor17_fixture_request_email({Id},{Stamp},'new@example.invalid','email-proof',clock_timestamp()+interval '1 hour')",cancellation)).Result.ShouldBeTrue();
        await fixture.ExecuteAsync(connection,$"select result from cor18_fixture_request_delete({Id},{Stamp},null,'delete-proof',clock_timestamp()+interval '1 hour',interval '1 minute',interval '1 hour',5::smallint);update delete_standby set verified=true where account_id={Id}",cancellation:cancellation);
    }

    private sealed record ExpirySchedule(string Lock, string SetExpiry, string Expiry, string Complete, string Code, string SuccessCount);
    private static async Task<ExpirySchedule> SeedExpiry(SqlContractFixture fixture, NpgsqlConnection connection, string kind, CancellationToken cancellation)
    {
        string table, expiry = "expiration", complete, code, success;
        switch (kind)
        {
            case "registration":
                await fixture.ExecuteAsync(connection, $"update accounts set verify_status=2; insert into account_verifications(account_id,verify_key_hash,verify_status,sent_when,expiration,account_security_stamp) values({Id},'registration-proof',2,clock_timestamp(),interval '1 hour',{Stamp})", cancellation: cancellation);
                return new("select 1 from account_verifications for update", "update account_verifications set sent_when=clock_timestamp(),expiration=interval '2 seconds'", "select sent_when+expiration from account_verifications", $"select result,case when result then 'SUCCESS' else 'EXPIRED' end as code from complete_verify_account({Id},'registration-proof',(select proof_version from account_verifications where verify_key_hash='registration-proof'),{Stamp})", "EXPIRED", "select count(*) from account_verifications where verify_status=1");
            case "email":
                await SeedEmailAndDelete(fixture, connection, cancellation);
                table = "account_email_change_requests"; complete = "select result,code from complete_account_email_change('email-proof')"; code = "ACCOUNT_ADJUST_TOKEN_EXPIRED"; success = "select count(*) from accounts where email_address='new@example.invalid'"; break;
            case "factor":
                (await Query(connection, null, BeginFactor, cancellation)).Result.ShouldBeTrue();
                table = "two_factor_authentications"; complete = VerifyFactor; code = "TWO_FACTOR_SETUP_EXPIRED"; success = "select count(*) from two_factor_authentications where verified"; break;
            case "authenticator":
                await PrepareGrant(fixture, connection, 1, cancellation);
                (await Query(connection, null, BeginAuthenticator, cancellation)).Result.ShouldBeTrue();
                await fixture.ExecuteAsync(connection, $"insert into sessions(access_token_hash,account_id,created_on,access_expiration,session_expiration,account_security_stamp) values('old-session',{Id},clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours',{Stamp})", cancellation: cancellation);
                table = "two_factor_authentications"; complete = CompleteAuthenticator; code = "AUTHENTICATOR_SETUP_EXPIRED"; success = "select count(*) from two_factor_authentications where verified"; break;
            case "unlock":
                await fixture.ExecuteAsync(connection, $"update accounts set unlock_when=clock_timestamp()+interval '1 hour'; insert into account_recoveries(account_id,created_on,status,topic,expiration,token_hash,method,lockout_security_stamp,lockout_unlock_when,lockout_attempt_version) select account_id,clock_timestamp(),1,1,clock_timestamp()+interval '1 hour','unlock-proof',1,security_stamp,unlock_when,'00000000-0000-0000-0000-000000000000'::uuid from accounts", cancellation: cancellation);
                table = "account_recoveries"; complete = "select status=7 as result,status::text as code from verify_unlock_account('unlock-proof')"; code = "5"; success = "select count(*) from account_recoveries where status=7"; break;
            case "reset":
                (await Query(connection, null, CreateReset(), cancellation)).Result.ShouldBeTrue();
                table = "password_reset_requests"; expiry = "expires_at"; complete = PromoteReset; code = "PASSWORD_RESET_EXPIRED"; success = "select count(*) from password_reset_events where code='PASSWORD_RESET_COMPLETED'"; break;
            case "delete":
                await SeedEmailAndDelete(fixture, connection, cancellation);
                table = "delete_standby"; complete = DeleteAccount; code = "ACCOUNT_DELETE_TOKEN_EXPIRED"; success = "select count(*) from account_delete_events where event_type='COMPLETED'"; break;
            case "activation":
                await fixture.ExecuteAsync(connection, $"insert into activations(account_id,created_on,term,off_at,feature_set,code,status) values({Id},clock_timestamp()-interval '1 hour',interval '1 day',clock_timestamp()+interval '1 hour',0,'activation-proof',1)", cancellation: cancellation);
                table = "activations"; expiry = "off_at"; complete = $"select result,code from verify_activation({Id},{Stamp},'old@example.invalid','activation-proof',clock_timestamp()-interval '100 years',0::smallint,1::smallint)"; code = "ACTIVATION_EXPIRED"; success = "select count(*) from activations where status=4"; break;
            default: throw new ArgumentOutOfRangeException(nameof(kind));
        }
        return new($"select 1 from {table} for update", $"update {table} set {expiry}=clock_timestamp()+interval '2 seconds'", $"select {expiry} from {table}", complete, code, success);
    }

    private static async Task Observe(SqlContractFixture fixture, NpgsqlConnection observer, NpgsqlConnection contender,
        NpgsqlConnection blocker, Task task, CancellationToken cancellation)
    {
        var observed = await SqlInterleavingBarrier.WaitForBlockedAsync(observer, contender.ProcessID, blocker.ProcessID, task, cancellation);
        Console.WriteLine($"COR02 run={fixture.RunId} schema={fixture.Schema} contender={observed.ContenderPid} blocker={observed.BlockerPid} wait={observed.WaitEvent} xid={observed.TransactionId}");
    }
    private static async Task WaitForDatabaseTime(NpgsqlConnection connection, DateTime deadline, CancellationToken cancellation)
    {
        while (true)
        {
            await using var command = new NpgsqlCommand("select clock_timestamp() >= @deadline", connection);
            command.Parameters.AddWithValue("deadline", deadline);
            if ((bool)(await command.ExecuteScalarAsync(cancellation))!) return;
            await Task.Delay(20, cancellation); // Yield only; SQL state establishes expiry.
        }
    }
    private static async Task<(bool Result, string Code)> Query(NpgsqlConnection connection, NpgsqlTransaction? transaction, string sql, CancellationToken cancellation, DateTime? deadline = null)
    {
        await using var command = new NpgsqlCommand(sql, connection, transaction) { CommandTimeout = 10 };
        if (deadline is not null) command.Parameters.AddWithValue("deadline", deadline.Value);
        await using var reader = await command.ExecuteReaderAsync(cancellation);
        (await reader.ReadAsync(cancellation)).ShouldBeTrue();
        return (reader.GetBoolean(0), reader.GetString(1));
    }
    private static async Task<T> Scalar<T>(NpgsqlConnection connection, string sql, CancellationToken cancellation, NpgsqlTransaction? transaction = null)
    {
        await using var command = new NpgsqlCommand(sql, connection, transaction) { CommandTimeout = 10 };
        return (T)(await command.ExecuteScalarAsync(cancellation))!;
    }
}
