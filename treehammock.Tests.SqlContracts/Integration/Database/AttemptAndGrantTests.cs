using Npgsql;
using Shouldly;
using treehammock.Tests.SqlContracts.Support;

namespace treehammock.Tests.Integration.Database;

// Real database transitions. Password/factor verification success supplied here is
// an explicit trusted-verifier substitution, not KDF/TOTP or HTTP qualification.
[Trait("Suite", "SqlContracts")]
public class Cor08AttemptAndGrantTests
{
    private const string Id = "'00000000-0000-0000-0000-000000000108'::uuid";
    private const string Stamp = "'00000000-0000-0000-0000-000000000208'::uuid";
    private const string Target = "repeat('a',64)";
    private const string Handle = "repeat('b',64)";
    private const string Token = "repeat('c',64)";
    private static string Failure => $"select result,code from cor08_record_login_failure({Id},{Stamp},1,5)";
    private static string Begin(Guid attempt) => $"select result,code from cor08_begin_password_proof({Id},{Stamp},'cor08-session','{attempt}'::uuid,1::smallint,{Target},5,900,30)";
    private static string Finish(Guid attempt, bool verified) => $"select result,code from cor08_finish_password_proof({Id},{Stamp},'cor08-session','{attempt}'::uuid,{verified.ToString().ToLowerInvariant()},{Handle},{Token},10)";
    private static string Validate(string purpose = "1::smallint", string target = Target, string consume = "false") =>
        $"select cor08_validate_sensitive_grant({Id},{Stamp},'cor08-session',{Token},{purpose},{target},{consume})";
    private static string Setup => $"select result,code from cor08_authorized_begin_authenticator_app_setup({Id},{Stamp},'setup-proof',clock_timestamp(),clock_timestamp()+interval '10 minutes',null,true,1::smallint,decode(repeat('01',20),'hex'),decode(repeat('02',12),'hex'),decode(repeat('03',16),'hex'),2,'fixture',gen_random_uuid(),'SHA1',6,30,1,null,null,'cor08-session',{Token},{Target})";

    private static async Task Seed(SqlContractFixture fixture, NpgsqlConnection connection, CancellationToken cancellation)
        => await fixture.ExecuteAsync(connection, $"""
            insert into accounts(account_id,email_address,verify_status,security_stamp)
            values({Id},'cor08@example.invalid',1,{Stamp});
            insert into sessions(access_token_hash,account_id,created_on,access_expiration,session_expiration,account_security_stamp)
            values('cor08-session',{Id},clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours',{Stamp});
            """, cancellation: cancellation);

    [Fact]
    public Task Concurrent_chargeable_failures_all_increment_and_never_shorten_the_lockout()
        => SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            var observer = await fixture.OpenConnectionAsync(); await Seed(fixture, observer, cancellation);
            var connections = new List<NpgsqlConnection>();
            for (int index = 0; index < 16; index++) connections.Add(await fixture.OpenConnectionAsync());
            var tasks = connections.Select(connection => fixture.Observe(Query(connection, null, Failure, cancellation))).ToArray();
            var outcomes = await Task.WhenAll(tasks); outcomes.All(result => result.Result).ShouldBeTrue();
            (await Scalar<short>(observer, "select login_failures from accounts", cancellation)).ShouldBe((short)16);
            var firstLock = await Scalar<DateTime>(observer, "select unlock_when from accounts", cancellation);
            (await Query(observer, null, Failure, cancellation)).Code.ShouldBe("LOCKED");
            (await Scalar<DateTime>(observer, "select unlock_when from accounts", cancellation)).ShouldBe(firstLock);
            (await Query(observer, null, Failure.Replace(Stamp, "gen_random_uuid()"), cancellation)).Result.ShouldBeFalse();
            (await Scalar<short>(observer, "select login_failures from accounts", cancellation)).ShouldBe((short)17);
        }, TestContext.Current.CancellationToken);

    [Theory]
    [InlineData(false, false)] [InlineData(false, true)]
    [InlineData(true, false)] [InlineData(true, true)]
    public Task Success_or_expired_cleanup_cannot_erase_a_new_failure(bool cleanup, bool failureWins)
        => SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            var observer = await fixture.OpenConnectionAsync(); await Seed(fixture, observer, cancellation);
            if (cleanup) await fixture.ExecuteAsync(observer, "update accounts set login_failures=5,unlock_when=clock_timestamp()-interval '1 second'", cancellation: cancellation);
            var snapshot = await Snapshot(observer, cancellation);
            string clear = $"select result,code from cor08_clear_login_attempts({Id},{Stamp},'{snapshot.Version}'::uuid,{snapshot.Failures}::smallint,{(snapshot.Unlock is null ? "null::timestamptz" : "@unlock")},{cleanup.ToString().ToLowerInvariant()})";
            var blocker = await fixture.OpenConnectionAsync(); var contender = await fixture.OpenConnectionAsync();
            var holding = await fixture.BeginTransactionAsync(blocker); var competing = await fixture.BeginTransactionAsync(contender);
            await fixture.ExecuteAsync(blocker, $"select 1 from accounts where account_id={Id} for update", holding, cancellation);
            var waiting = fixture.Observe(Query(contender, competing, failureWins ? clear : Failure, cancellation, snapshot.Unlock));
            await SqlInterleavingBarrier.WaitForBlockedAsync(observer, contender.ProcessID, blocker.ProcessID, waiting, cancellation);
            (await Query(blocker, holding, failureWins ? Failure : clear, cancellation, snapshot.Unlock)).Result.ShouldBeTrue();
            await holding.CommitAsync(cancellation);
            var result = await waiting; result.Result.ShouldBe(!failureWins);
            if (failureWins) result.Code.ShouldBe("LOGIN_ATTEMPT_STATE_CHANGED");
            await competing.CommitAsync(cancellation);
            (await Scalar<short>(observer, "select login_failures from accounts", cancellation)).ShouldBe(failureWins && cleanup ? (short)6 : (short)1);
            if (failureWins && cleanup) (await Scalar<bool>(observer, "select unlock_when>clock_timestamp() from accounts", cancellation)).ShouldBeTrue();
        }, TestContext.Current.CancellationToken);

    [Fact]
    public Task Concurrent_password_admission_reserves_five_slots_and_wrong_proofs_are_durable()
        => SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            var observer = await fixture.OpenConnectionAsync(); await Seed(fixture, observer, cancellation);
            var connections = new List<NpgsqlConnection>(); var attempts = new List<Guid>();
            for (int index = 0; index < 10; index++) { connections.Add(await fixture.OpenConnectionAsync()); attempts.Add(Guid.NewGuid()); }
            var tasks = connections.Select((connection, index) => fixture.Observe(Query(connection, null, Begin(attempts[index]), cancellation))).ToArray();
            var admitted = await Task.WhenAll(tasks); admitted.Count(result => result.Result).ShouldBe(5);
            for (int index = 0; index < admitted.Length; index++)
                if (admitted[index].Result) (await Query(observer, null, Finish(attempts[index], false), cancellation)).Code.ShouldBe("SENSITIVE_ACTION_REAUTHENTICATION_FAILED");
            (await Scalar<int>(observer, "select admitted from account_reauthentication_budgets", cancellation)).ShouldBe(5);
            (await Scalar<int>(observer, "select failed from account_reauthentication_budgets", cancellation)).ShouldBe(5);
            (await Scalar<long>(observer, "select count(*) from sensitive_action_grants", cancellation)).ShouldBe(0L);
            (await Scalar<short>(observer, "select login_failures from accounts", cancellation)).ShouldBe((short)0);
            (await Query(observer, null, Begin(Guid.NewGuid()), cancellation)).Code.ShouldBe("SENSITIVE_ACTION_ATTEMPT_LIMIT");
        }, TestContext.Current.CancellationToken);

    [Fact]
    public Task Abandon_is_once_only_and_never_refunds_a_new_window_or_charges_failure()
        => SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            var connection = await fixture.OpenConnectionAsync(); await Seed(fixture, connection, cancellation);
            Guid attempt = Guid.NewGuid(); (await Query(connection, null, Begin(attempt), cancellation)).Result.ShouldBeTrue();
            string abandon = $"select cor08_abandon_password_proof({Id},{Stamp},'{attempt}'::uuid)";
            (await Scalar<bool>(connection, abandon, cancellation)).ShouldBeTrue();
            (await Scalar<bool>(connection, abandon, cancellation)).ShouldBeFalse();
            (await Scalar<int>(connection, "select admitted from account_reauthentication_budgets", cancellation)).ShouldBe(0);
            attempt = Guid.NewGuid(); (await Query(connection, null, Begin(attempt), cancellation)).Result.ShouldBeTrue();
            await fixture.ExecuteAsync(connection, "update account_reauthentication_budgets set window_start=clock_timestamp()-interval '1 hour'", cancellation: cancellation);
            (await Query(connection, null, Begin(Guid.NewGuid()), cancellation)).Result.ShouldBeTrue();
            (await Scalar<bool>(connection, $"select cor08_abandon_password_proof({Id},{Stamp},'{attempt}'::uuid)", cancellation)).ShouldBeTrue();
            (await Scalar<int>(connection, "select admitted from account_reauthentication_budgets", cancellation)).ShouldBe(1);
            (await Scalar<int>(connection, "select failed from account_reauthentication_budgets", cancellation)).ShouldBe(0);
        }, TestContext.Current.CancellationToken);

    [Theory]
    [InlineData("purpose")] [InlineData("target")] [InlineData("family")]
    [InlineData("stamp")] [InlineData("policy")] [InlineData("expiry")]
    public Task Grant_rejects_wrong_scope_or_changed_authority(string change)
        => SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            var connection = await fixture.OpenConnectionAsync(); await Seed(fixture, connection, cancellation);
            Guid attempt = Guid.NewGuid(); (await Query(connection, null, Begin(attempt), cancellation)).Result.ShouldBeTrue();
            (await Query(connection, null, Finish(attempt, true), cancellation)).Result.ShouldBeTrue();
            (await Scalar<bool>(connection, Validate(), cancellation)).ShouldBeTrue();
            string validation = Validate();
            switch (change)
            {
                case "purpose": validation = Validate("2::smallint"); break;
                case "target": validation = Validate(target: "repeat('d',64)"); break;
                case "family":
                    await fixture.ExecuteAsync(connection, "update sessions set session_id=gen_random_uuid()", cancellation: cancellation);
                    (await Scalar<bool>(connection, "select s.session_id is distinct from g.family_id from sessions s join sensitive_action_grants g on g.session_hash=s.access_token_hash", cancellation)).ShouldBeTrue();
                    break;
                case "stamp": await fixture.ExecuteAsync(connection, "update accounts set security_stamp=gen_random_uuid()", cancellation: cancellation); break;
                case "policy": await fixture.ExecuteAsync(connection, "update sensitive_action_grants set factor_policy=repeat('d',64)", cancellation: cancellation); break;
                case "expiry": await fixture.ExecuteAsync(connection, "update sensitive_action_grants set expiration=clock_timestamp()", cancellation: cancellation); break;
            }
            (await Scalar<bool>(connection, validation, cancellation)).ShouldBeFalse();
            (await Scalar<long>(connection, "select count(*) from sensitive_action_grants where consumed_on is not null", cancellation)).ShouldBe(0L);
        }, TestContext.Current.CancellationToken);

    [Fact]
    public Task Unbound_session_security_stamp_is_not_mistaken_for_bound_family_authority()
        => SqlContractFixture.RunAsync(async (fixture, cancellation) => {
            var connection = await fixture.OpenConnectionAsync(); await Seed(fixture, connection, cancellation);
            Guid attempt = Guid.NewGuid();(await Query(connection,null,Begin(attempt),cancellation)).Result.ShouldBeTrue();
            (await Query(connection,null,Finish(attempt,true),cancellation)).Result.ShouldBeTrue();
            await fixture.ExecuteAsync(connection,"update sessions set security_stamp=gen_random_uuid()",cancellation:cancellation);
            (await Scalar<bool>(connection,"select s.session_id=g.family_id from sessions s join sensitive_action_grants g on g.session_hash=s.access_token_hash",cancellation)).ShouldBeTrue();
            (await Scalar<bool>(connection,Validate(),cancellation)).ShouldBeTrue();
        },TestContext.Current.CancellationToken);

    [Fact]
    public Task Domain_setup_and_grant_consumption_rollback_together_then_commit_once()
        => SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            var connection = await fixture.OpenConnectionAsync(); await Seed(fixture, connection, cancellation);
            Guid attempt = Guid.NewGuid(); (await Query(connection, null, Begin(attempt), cancellation)).Result.ShouldBeTrue();
            (await Query(connection, null, Finish(attempt, true), cancellation)).Result.ShouldBeTrue();
            var transaction = await fixture.BeginTransactionAsync(connection);
            (await Query(connection, transaction, Setup, cancellation)).Result.ShouldBeTrue();
            await transaction.RollbackAsync(cancellation);
            (await Scalar<bool>(connection, Validate(), cancellation)).ShouldBeTrue();
            (await Scalar<long>(connection, "select count(*) from two_factor_authentications", cancellation)).ShouldBe(0L);
            (await Query(connection, null, Setup, cancellation)).Result.ShouldBeTrue();
            (await Scalar<bool>(connection, Validate(), cancellation)).ShouldBeFalse();
            (await Query(connection, null, Setup, cancellation)).Code.ShouldBe("SENSITIVE_ACTION_GRANT_REQUIRED");
            (await Scalar<long>(connection, "select count(*) from two_factor_authentications", cancellation)).ShouldBe(1L);
            (await Scalar<long>(connection, "select count(*) from sensitive_action_grants where consumed_on is not null", cancellation)).ShouldBe(1L);
        }, TestContext.Current.CancellationToken);

    [Fact]
    public Task Existing_factor_requires_a_pending_proof_session_and_bounded_factor_admission()
        => SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            var connection = await fixture.OpenConnectionAsync(); await Seed(fixture, connection, cancellation);
            await fixture.ExecuteAsync(connection, $"insert into two_factor_authentications(two_factor_index,account_id,method,verified,required,totp_provider_type,totp_secret_ciphertext,totp_secret_nonce,totp_secret_tag,totp_secret_version,totp_key_id,totp_enrollment_id,totp_algorithm,totp_digits,totp_period_seconds,totp_clock_skew_steps) values(1,{Id},3,true,true,1,decode(repeat('01',20),'hex'),decode(repeat('01',12),'hex'),decode(repeat('01',16),'hex'),2,'fixture',gen_random_uuid(),'SHA1',6,30,1)", cancellation: cancellation);
            Guid attempt = Guid.NewGuid(); (await Query(connection, null, Begin(attempt), cancellation)).Result.ShouldBeTrue();
            (await Query(connection, null, Finish(attempt, true), cancellation)).Code.ShouldBe("SENSITIVE_ACTION_FACTOR_PROOF_REQUIRED");
            (await Scalar<long>(connection, "select count(*) from sensitive_action_grants", cancellation)).ShouldBe(0L);
            string reserve = $"select cor08_reserve_factor_proof({Id},{Stamp},'cor08-session',{Handle},5)";
            for (int index = 0; index < 5; index++) (await Scalar<bool>(connection, reserve, cancellation)).ShouldBeTrue();
            (await Scalar<bool>(connection, reserve, cancellation)).ShouldBeFalse();
            // Trusted existing-factor verifier success substitution; no TOTP claim.
            string finish = $"select result,code from cor08_finish_factor_proof({Id},{Stamp},'cor08-session',{Handle},{Token})";
            (await Query(connection, null, finish, cancellation)).Result.ShouldBeTrue();
            (await Query(connection, null, finish, cancellation)).Result.ShouldBeFalse();
            (await Scalar<bool>(connection, Validate(), cancellation)).ShouldBeTrue();
        }, TestContext.Current.CancellationToken);

    [Fact]
    public Task Live_lockout_denies_password_admission_without_returning_credentials_or_reserving_budget()
        => SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            var connection = await fixture.OpenConnectionAsync(); await Seed(fixture, connection, cancellation);
            await fixture.ExecuteAsync(connection, "update accounts set unlock_when=clock_timestamp()+interval '1 hour'", cancellation: cancellation);
            Guid attempt = Guid.NewGuid();
            await using var command = new NpgsqlCommand(Begin(attempt).Replace("select result,code", "select result,code,hashed_password"), connection);
            await using (var reader = await command.ExecuteReaderAsync(cancellation))
            {
                (await reader.ReadAsync(cancellation)).ShouldBeTrue(); reader.GetBoolean(0).ShouldBeFalse();
                reader.GetString(1).ShouldBe("SENSITIVE_ACTION_AUTHORITY_DENIED"); reader.IsDBNull(2).ShouldBeTrue();
            }
            (await Scalar<long>(connection, "select count(*) from sensitive_password_attempts", cancellation)).ShouldBe(0L);
            (await Scalar<long>(connection, "select count(*) from account_reauthentication_budgets", cancellation)).ShouldBe(0L);
        }, TestContext.Current.CancellationToken);

    [Fact]
    public Task Waiting_domain_mutation_rechecks_grant_expiry_before_consuming_or_writing()
        => SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            var observer = await fixture.OpenConnectionAsync(); await Seed(fixture, observer, cancellation);
            Guid attempt = Guid.NewGuid(); (await Query(observer, null, Begin(attempt), cancellation)).Result.ShouldBeTrue();
            (await Query(observer, null, Finish(attempt, true), cancellation)).Result.ShouldBeTrue();
            var blocker = await fixture.OpenConnectionAsync(); var contender = await fixture.OpenConnectionAsync();
            var holding = await fixture.BeginTransactionAsync(blocker);
            await fixture.ExecuteAsync(blocker, $"select 1 from accounts where account_id={Id} for update; update sensitive_action_grants set expiration=clock_timestamp()+interval '2 seconds'", holding, cancellation);
            // SQL time, not host sleep, determines when the uncommitted grant expires.
            DateTime deadline;
            await using (var command = new NpgsqlCommand("select expiration from sensitive_action_grants", blocker, holding)) deadline = (DateTime)(await command.ExecuteScalarAsync(cancellation))!;
            var competing = await fixture.BeginTransactionAsync(contender);
            var waiting = fixture.Observe(Query(contender, competing, Setup, cancellation));
            await SqlInterleavingBarrier.WaitForBlockedAsync(observer, contender.ProcessID, blocker.ProcessID, waiting, cancellation);
            while (true)
            {
                await using var command = new NpgsqlCommand("select clock_timestamp()>=@deadline", observer); command.Parameters.AddWithValue("deadline", deadline);
                if ((bool)(await command.ExecuteScalarAsync(cancellation))!) break;
                await Task.Delay(20, cancellation);
            }
            await holding.CommitAsync(cancellation);
            (await waiting).Code.ShouldBe("SENSITIVE_ACTION_GRANT_REQUIRED"); await competing.CommitAsync(cancellation);
            (await Scalar<long>(observer, "select count(*) from two_factor_authentications", cancellation)).ShouldBe(0L);
            (await Scalar<long>(observer, "select count(*) from sensitive_action_grants where consumed_on is not null", cancellation)).ShouldBe(0L);
        }, TestContext.Current.CancellationToken);

    private static async Task<(Guid Version, short Failures, DateTime? Unlock)> Snapshot(NpgsqlConnection connection, CancellationToken cancellation)
    {
        await using var command = new NpgsqlCommand("select coalesce(v.attempt_version,'00000000-0000-0000-0000-000000000000'::uuid),a.login_failures,a.unlock_when from accounts a left join account_login_attempt_versions v on v.account_id=a.account_id", connection);
        await using var reader = await command.ExecuteReaderAsync(cancellation); (await reader.ReadAsync(cancellation)).ShouldBeTrue();
        return (reader.GetGuid(0), reader.GetInt16(1), reader.IsDBNull(2) ? null : reader.GetDateTime(2));
    }
    private static async Task<(bool Result, string Code)> Query(NpgsqlConnection connection, NpgsqlTransaction? transaction, string sql, CancellationToken cancellation, DateTime? unlock = null)
    {
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        if (sql.Contains("@unlock")) command.Parameters.AddWithValue("unlock", unlock!.Value);
        await using var reader = await command.ExecuteReaderAsync(cancellation); (await reader.ReadAsync(cancellation)).ShouldBeTrue();
        return (reader.GetBoolean(0), reader.GetString(1));
    }
    private static async Task<T> Scalar<T>(NpgsqlConnection connection, string sql, CancellationToken cancellation)
    {
        await using var command = new NpgsqlCommand(sql, connection); return (T)(await command.ExecuteScalarAsync(cancellation))!;
    }
}
