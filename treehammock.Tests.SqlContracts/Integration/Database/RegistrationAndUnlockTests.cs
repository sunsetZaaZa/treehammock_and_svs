using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NodaTime;
using Npgsql;
using NSubstitute;
using Shouldly;
using treehammock.Entities;
using treehammock.Repos;
using treehammock.Rigging.Config;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Actions.Account;
using treehammock.RiggingSupport.Status;
using treehammock.Tests.SqlContracts.Support;

namespace treehammock.Tests.Integration.Database;

[Trait("Suite", "SqlContracts")]
public class Cor11RegistrationAndUnlockTests
{
    private const string Id = "'00000000-0000-0000-0000-000000001101'::uuid";
    private const string OtherId = "'00000000-0000-0000-0000-000000001102'::uuid";
    private const string Stamp = "'00000000-0000-0000-0000-000000001201'::uuid";
    private const string Epoch = "'00000000-0000-0000-0000-000000001301'::uuid";
    private const string Zero = "'00000000-0000-0000-0000-000000000000'::uuid";
    private const string Deadline = "'2100-01-01 00:00:00+00'::timestamptz";
    private static string Setup(string id, string email, string name, string web, string proof, bool emailOnly = false) =>
        emailOnly
            ? $"select outcome from setup_account_email({id},'{email}','{web}','\\x01','\\x02','\\x03','\\x04',0::smallint,'{proof}',clock_timestamp(),interval '1 hour')"
            : $"select outcome from setup_account_both({id},'{name}','{email}','{web}','\\x01','\\x02','\\x03','\\x04',0::smallint,'{proof}',clock_timestamp(),interval '1 hour')";
    private static string Resend(string proof) => $"select result from resend_verify_account('reader@example.invalid','{proof}',interval '1 hour')";
    private static string Begin(string proof, string epoch = Epoch) => $"select status from start_unlock_account({Id},'{proof}',clock_timestamp(),clock_timestamp()+interval '1 hour',2::smallint,1::smallint,{Stamp},{Deadline},{epoch})";
    private static Task<T> Read<T>(NpgsqlConnection connection, NpgsqlTransaction? transaction, string sql, CancellationToken token) => ReadCore<T>(connection, transaction, sql, token);
    private static async Task<T> ReadCore<T>(NpgsqlConnection connection, NpgsqlTransaction? transaction, string sql, CancellationToken token)
    {
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        return (T)(await command.ExecuteScalarAsync(token))!;
    }
    private static async Task SeedVerification(SqlContractFixture fixture, NpgsqlConnection connection, CancellationToken token)
    {
        (await Read<short>(connection, null, Setup(Id, "reader@example.invalid", "reader", "web", "first"), token)).ShouldBe((short)8000);
        (await Read<bool>(connection, null, $"select result from start_verify_account({Id},(select verification_index from account_verifications where verify_key_hash='first'))", token)).ShouldBeTrue();
    }
    private static async Task<string> Complete(NpgsqlConnection connection, CancellationToken token, string proof = "first")
    {
        string version = await Read<string>(connection, null, $"select proof_version::text from account_verifications where verify_key_hash='{proof}'", token);
        string stamp = await Read<string>(connection, null, $"select account_security_stamp::text from account_verifications where verify_key_hash='{proof}'", token);
        return $"select result from complete_verify_account({Id},'{proof}','{version}'::uuid,'{stamp}'::uuid)";
    }
    private static async Task SeedUnlock(SqlContractFixture fixture, NpgsqlConnection connection, CancellationToken token)
    {
        await fixture.ExecuteAsync(connection, $"insert into accounts(account_id,email_address,verify_status,security_stamp,login_failures,unlock_when) values({Id},'reader@example.invalid',1,{Stamp},5,{Deadline}); insert into account_login_attempt_versions values({Id},{Stamp},{Epoch})", cancellation: token);
        (await Read<short>(connection, null, Begin("unlock"), token)).ShouldBe((short)2);
    }
    private static Task<SqlLockObservation> Blocked(NpgsqlConnection observer, NpgsqlConnection worker, NpgsqlConnection owner, Task task, CancellationToken token)
        => SqlInterleavingBarrier.WaitForBlockedAsync(observer, worker.ProcessID, owner.ProcessID, task, token);

    [Theory]
    [InlineData("email", false, 8040)] [InlineData("email", true, 8040)]
    [InlineData("username", false, 8010)] [InlineData("both", false, 8070)]
    [InlineData("id", false, 3000)] [InlineData("web", false, 3500)]
    [InlineData("id", true, 3000)] [InlineData("web", true, 3500)]
    public async Task Uncommitted_signup_winner_maps_named_unique_conflict_without_partial_account(string collision, bool emailOnly, int expected)
    {
        await SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            var observer = await fixture.OpenConnectionAsync();
            var winner = await fixture.OpenConnectionAsync();
            var loser = await fixture.OpenConnectionAsync();
            var winning = await fixture.BeginTransactionAsync(winner);
            (await Read<short>(winner, winning, Setup(Id, "reader@example.invalid", "reader", "web", "first", emailOnly), token)).ShouldBe((short)8000);
            var losing = await fixture.BeginTransactionAsync(loser);
            string sql = Setup(collision == "id" ? Id : OtherId,
                collision is "email" or "both" ? "READER@example.INVALID" : "other@example.invalid",
                collision is "username" or "both" ? "READER" : "other",
                collision == "web" ? "web" : "other-web", "second", emailOnly);
            var task = fixture.Observe(Read<short>(loser, losing, sql, token));
            await Blocked(observer, loser, winner, task, token);
            await winning.CommitAsync(token);
            (await task).ShouldBe((short)expected);
            // The exception subtransaction must leave the caller usable for its receipt/commit.
            (await Read<int>(loser, losing, "select 1", token)).ShouldBe(1);
            await losing.CommitAsync(token);
            (await Read<long>(observer, null, "select count(*) from accounts", token)).ShouldBe(1L);
            (await Read<long>(observer, null, "select count(*) from account_verifications", token)).ShouldBe(1L);
        }, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task Production_signup_repository_commits_duplicate_as_safe_COR04_receipt()
    {
        await SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            var observer = await fixture.OpenConnectionAsync();
            var owner = await fixture.OpenConnectionAsync();
            var holding = await fixture.BeginTransactionAsync(owner);
            (await Read<short>(owner, holding, Setup(Id, "reader@example.invalid", "reader", "web", "first"), token)).ShouldBe((short)8000);
            var settings = new SecurityOperationSettings { HmacKeys = new() { [1] = Convert.ToBase64String(new byte[32]) } };
            var storage = new Cor09RefreshHttpTests.FixtureStorage(fixture, settings);
            var repo = new AccountRepo(new treehammock.Rigging.Delivery.DeliveryPayloadProtector(Options.Create(new treehammock.Rigging.Config.DeliveryOutboxSettings {EncryptionKeys=new() {{1,Convert.ToBase64String(new byte[32])}}})),storage, Options.Create(new JWTSettings()), NullLogger<AccountRepo>.Instance, Substitute.For<IUserSecretHasher>());
            var candidate = new Account(Guid.NewGuid(), "READER@example.INVALID", null, [1], SystemClock.Instance.GetCurrentInstant(), "candidate-web", VerificationStatus.STARTED);
            var task = fixture.Observe(repo.SetupAccount(candidate, "candidate-proof", Period.FromHours(1), AccountSetupAction.EMAIL, new treehammock.Rigging.Delivery.DeliveryIntent(candidate.accountId,Guid.Empty,"verify","candidate-proof",SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromHours(1)),new {mode="start"},new("verify-start","email",candidate.emailAddress!,"test","https://localhost.test/verify")), token));
            int pid = 0;
            while (pid == 0)
            {
                token.ThrowIfCancellationRequested();
                if (task.IsCompleted) { await task; throw new InvalidOperationException("Signup completed before the unique wait"); }
                pid = await Read<int>(observer, null,
                    $"select coalesce((select pid from pg_stat_activity where {owner.ProcessID}=any(pg_blocking_pids(pid)) and query like 'select * from setup_account_email%'),0)", token);
                if (pid == 0) await Task.Delay(20, token);
            }
            await SqlInterleavingBarrier.WaitForBlockedAsync(observer, pid, owner.ProcessID, task, token);
            await holding.CommitAsync(token);
            var result = await task;
            result.Item1.ShouldBeNull();
            result.Item2.ShouldBe(HttpMessage.ACCOUNT_CREATION_DUPLICATE_EMAIL);
            (await Read<long>(observer, null, "select count(*) from security_operation_steps where outcome_code='ACCOUNT_CREATION_DUPLICATE_EMAIL'", token)).ShouldBe(1L);
            (await Read<long>(observer, null, "select count(*) from accounts", token)).ShouldBe(1L);
            string receipt = await Read<string>(observer, null, "select to_jsonb(s)::text from security_operation_steps s", token);
            receipt.ShouldNotContain("candidate-proof"); receipt.ShouldNotContain("candidate-web");
        }, TestContext.Current.CancellationToken);
    }

    [Theory]
    [InlineData("resend")] [InlineData("complete")] [InlineData("repeat")]
    public async Task Verification_commands_serialize_and_revalidate_current_identity(string winnerCommand)
    {
        await SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            var observer = await fixture.OpenConnectionAsync(); await SeedVerification(fixture, observer, token);
            string complete = await Complete(observer, token);
            var owner = await fixture.OpenConnectionAsync(); var worker = await fixture.OpenConnectionAsync();
            var holding = await fixture.BeginTransactionAsync(owner);
            await fixture.ExecuteAsync(owner, $"select 1 from accounts where account_id={Id} for update", holding, token);
            var waiting = await fixture.BeginTransactionAsync(worker);
            var task = fixture.Observe(Read<bool>(worker, waiting, winnerCommand == "complete" ? Resend("second") : complete, token));
            await Blocked(observer, worker, owner, task, token);
            (await Read<bool>(owner, holding, winnerCommand == "resend" ? Resend("second") : complete, token)).ShouldBeTrue();
            await holding.CommitAsync(token);
            (await task).ShouldBe(winnerCommand == "complete"); // Complete winner makes resend a safe no-op.
            await waiting.CommitAsync(token);
            (await Read<long>(observer, null, "select count(*) from account_verifications where verify_status in (0,2,4)", token)).ShouldBe(winnerCommand == "resend" ? 1L : 0L);
            (await Read<long>(observer, null, "select count(*) from account_verifications where verify_status=1", token)).ShouldBe(winnerCommand == "resend" ? 0L : 1L);
        }, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task Simultaneous_resends_leave_one_current_proof_and_stale_expiry_cannot_change_account()
    {
        await SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            var observer = await fixture.OpenConnectionAsync(); await SeedVerification(fixture, observer, token);
            string complete = await Complete(observer, token); string expire = complete.Replace("complete_verify_account", "expire_verify_account");
            (await Read<bool>(observer, null, expire, token)).ShouldBeFalse(); // SQL clock denies premature expiry.
            var owner = await fixture.OpenConnectionAsync(); var worker = await fixture.OpenConnectionAsync();
            var holding = await fixture.BeginTransactionAsync(owner);
            (await Read<bool>(owner, holding, Resend("second"), token)).ShouldBeTrue();
            var waiting = await fixture.BeginTransactionAsync(worker);
            var task = fixture.Observe(Read<bool>(worker, waiting, Resend("third"), token));
            await Blocked(observer, worker, owner, task, token);
            await holding.CommitAsync(token); (await task).ShouldBeTrue(); await waiting.CommitAsync(token);
            (await Read<long>(observer, null, "select count(*) from account_verifications where verify_status in (0,2,4)", token)).ShouldBe(1L);
            (await Read<string>(observer, null, "select verify_key_hash from account_verifications where verify_status=4", token)).ShouldBe("third");
            (await Read<bool>(observer, null, expire, token)).ShouldBeFalse();
            (await Read<bool>(observer, null, complete, token)).ShouldBeFalse();
            (await Read<short>(observer, null, "select verify_status from accounts", token)).ShouldBe((short)4);
            (await Read<long>(observer, null, "select count(*) from account_verifications where verify_status=6", token)).ShouldBe(2L);
            var error = await Should.ThrowAsync<PostgresException>(() => fixture.ExecuteAsync(observer,
                $"insert into account_verifications(account_id,verify_key_hash,account_security_stamp) select {Id},'fourth',security_stamp from accounts", cancellation: token));
            error.ConstraintName.ShouldBe("ux_account_verifications_current");
        }, TestContext.Current.CancellationToken);
    }

    [Theory]
    [InlineData("stamp")] [InlineData("version")]
    public async Task Verification_denies_wrong_server_binding(string mismatch)
    {
        await SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            var connection = await fixture.OpenConnectionAsync(); await SeedVerification(fixture, connection, token);
            string complete = await Complete(connection, token);
            if (mismatch == "stamp") await fixture.ExecuteAsync(connection, "update accounts set security_stamp=gen_random_uuid()", cancellation: token);
            else await fixture.ExecuteAsync(connection, "update account_verifications set proof_version=gen_random_uuid()", cancellation: token);
            (await Read<bool>(connection, null, complete, token)).ShouldBeFalse();
            (await Read<bool>(connection, null, complete.Replace("complete_verify_account", "expire_verify_account"), token)).ShouldBeFalse();
            (await Read<short>(connection, null, "select verify_status from accounts", token)).ShouldBe((short)2);
        }, TestContext.Current.CancellationToken);
    }

    [Theory]
    [InlineData("consume", false)] [InlineData("cancel", false)] [InlineData("replace", false)]
    [InlineData("failure", false)] [InlineData("stamp", false)] [InlineData("lockout", false)]
    [InlineData("consume", true)] [InlineData("cancel", true)] [InlineData("replace", true)]
    [InlineData("failure", true)] [InlineData("stamp", true)] [InlineData("lockout", true)]
    public async Task Unlock_consume_serializes_with_current_request_or_newer_account_authority(string mutation, bool cancelContender)
    {
        await SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            var observer = await fixture.OpenConnectionAsync(); await SeedUnlock(fixture, observer, token);
            var owner = await fixture.OpenConnectionAsync(); var worker = await fixture.OpenConnectionAsync();
            var holding = await fixture.BeginTransactionAsync(owner);
            await fixture.ExecuteAsync(owner, $"select 1 from accounts where account_id={Id} for update", holding, token);
            var waiting = await fixture.BeginTransactionAsync(worker);
            string consume = "select status from verify_unlock_account('unlock')";
            string cancel = $"select status from cancel_unlock_account({Id},'unlock')";
            var task = fixture.Observe(Read<short>(worker, waiting, cancelContender ? cancel : consume, token));
            await Blocked(observer, worker, owner, task, token);
            switch (mutation)
            {
                case "consume": (await Read<short>(owner, holding, consume, token)).ShouldBe((short)7); break;
                case "cancel": (await Read<short>(owner, holding, cancel, token)).ShouldBe((short)4); break;
                case "replace": (await Read<short>(owner, holding, Begin("replacement"), token)).ShouldBe((short)2); break;
                case "failure":
                    (await Read<bool>(owner, holding, $"select result from cor08_record_login_failure({Id},{Stamp},1,5)", token)).ShouldBeTrue();
                    (await Read<bool>(owner, holding, $"select unlock_when={Deadline} from accounts", token)).ShouldBeTrue(); break;
                case "stamp": await fixture.ExecuteAsync(owner, "update accounts set security_stamp=gen_random_uuid()", holding, token); break;
                case "lockout": await fixture.ExecuteAsync(owner, "update accounts set unlock_when=unlock_when+interval '1 hour',login_failures=6", holding, token); break;
            }
            await holding.CommitAsync(token);
            short expected = mutation == "consume" ? (short)11 : mutation is "cancel" or "replace" ? (short)(cancelContender ? 4 : 9) : (short)14;
            (await task).ShouldBe(expected); await waiting.CommitAsync(token);
            (await Read<long>(observer, null, "select count(*) from account_recoveries where status=7", token)).ShouldBe(mutation == "consume" ? 1L : 0L);
            (await Read<bool>(observer, null, "select unlock_when is null from accounts", token)).ShouldBe(mutation == "consume");
            (await Read<short>(observer, null, "select login_failures from accounts", token)).ShouldBe(mutation == "consume" ? (short)0 : mutation is "failure" or "lockout" ? (short)6 : (short)5);
            if (mutation == "replace")
                (await Read<short>(observer, null, "select status from account_recoveries where token_hash='replacement'", token)).ShouldBe((short)2);
            if (mutation == "consume") (await Read<bool>(observer, null, $"select attempt_version<>{Epoch} from account_login_attempt_versions", token)).ShouldBeTrue();
        }, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task Begin_rejects_stale_epoch_and_token_reuse_preserves_replacement()
    {
        await SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            var connection = await fixture.OpenConnectionAsync(); await SeedUnlock(fixture, connection, token);
            (await Read<short>(connection, null, Begin("stale", Zero), token)).ShouldBe((short)14);
            (await Read<short>(connection, null, Begin("replacement"), token)).ShouldBe((short)2);
            (await Read<short>(connection, null, Begin("unlock"), token)).ShouldBe((short)9);
            (await Read<short>(connection, null, "select status from account_recoveries where token_hash='replacement'", token)).ShouldBe((short)2);
            (await Read<short>(connection, null, "select status from account_recoveries where token_hash='unlock'", token)).ShouldBe((short)4);
            (await Read<long>(connection, null, "select count(*) from account_recoveries", token)).ShouldBe(2L);
        }, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task Production_repositories_carry_proof_version_and_lockout_epoch_with_safe_receipts()
    {
        await SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            var connection = await fixture.OpenConnectionAsync();
            var settings = new SecurityOperationSettings { HmacKeys = new() { [1] = Convert.ToBase64String(new byte[32]) } };
            var storage = new Cor09RefreshHttpTests.FixtureStorage(fixture, settings);
            var repo = new AccountRepo(new treehammock.Rigging.Delivery.DeliveryPayloadProtector(Options.Create(new treehammock.Rigging.Config.DeliveryOutboxSettings {EncryptionKeys=new() {{1,Convert.ToBase64String(new byte[32])}}})),storage, Options.Create(new JWTSettings()), NullLogger<AccountRepo>.Instance, Substitute.For<IUserSecretHasher>());
            var candidate = new Account(Guid.NewGuid(), "repository@example.invalid", null, [1], SystemClock.Instance.GetCurrentInstant(), "repository-web", VerificationStatus.STARTED);
            string first = AccountVerificationTokenUtility.HashToken("repository-first");
            var setup = await repo.SetupAccount(candidate, first, Period.FromHours(1), AccountSetupAction.EMAIL, new treehammock.Rigging.Delivery.DeliveryIntent(candidate.accountId,Guid.Empty,"verify",first,SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromHours(1)),new {mode="start"},new("verify-start","email",candidate.emailAddress!,"test","https://localhost.test/verify")), token);
            setup.Item2.ShouldBe(HttpMessage.ACCOUNT_CREATION_SUCCESSED);
            (await repo.StartAccountVerification(candidate.accountId, setup.Item1!.Value, token)).ShouldBe(true);
            (await repo.StartAccountVerification(candidate.accountId, setup.Item1.Value, token)).ShouldBe(false);
            var observed = (await repo.VerifyAccountForUse("repository-first", token))!;
            observed.proofVersion.ShouldNotBe(Guid.Empty); observed.accountSecurityStamp.ShouldNotBe(Guid.Empty);
            (await repo.AccountVerificationExpired(observed, token)).ShouldBe(false);
            string second = AccountVerificationTokenUtility.HashToken("repository-second");
            (await repo.ResendAccountVerification(candidate.emailAddress, second, Period.FromHours(1), token))!.Result.ShouldBeTrue();
            (await repo.AccountPassedVerification(observed, token)).ShouldBe(false);
            var current = (await repo.VerifyAccountForUse("repository-second", token))!;
            current.proofVersion.ShouldNotBe(observed.proofVersion);
            (await repo.AccountPassedVerification(current, token)).ShouldBe(true);
            (await repo.AccountPassedVerification(current, token)).ShouldBe(false);
            await SeedUnlock(fixture, connection, token);
            var recovery = new AccountRecoveryRepo(storage, NullLogger<AccountRecoveryRepo>.Instance);
            var lookup = (await recovery.LookupLockedAccount("reader@example.invalid", Instant.FromUtc(2200,1,1,0,0), token))!;
            // Even a hostile/future host clock cannot authorize or suppress SQL lookup.
            lookup.Result.ShouldBeTrue(); lookup.LockoutAttemptVersion!.Value.ToString("D").ShouldBe("00000000-0000-0000-0000-000000001301");
            (await recovery.BeginUnlock(lookup.AccountId!.Value, "repository-unlock", SystemClock.Instance.GetCurrentInstant(),
                SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromHours(1)), AccountRecovery_Status.STANDBY,
                AccountUnlockDeliveryMethod.EMAIL, lookup.AccountSecurityStamp!.Value, lookup.UnlockWhen!.Value,
                lookup.LockoutAttemptVersion.Value, token)).ShouldBe(AccountRecovery_Status.STANDBY);
            (await recovery.VerifyUnlock("repository-unlock", token)).ShouldBe(AccountRecovery_Status.COMPLETE);
            (await recovery.CancelUnlock(lookup.AccountId.Value, "repository-unlock", token)).ShouldBe(AccountRecovery_Status.BAD_VERIFY);
            string receipts = await Read<string>(connection, null, "select jsonb_agg(to_jsonb(s))::text from security_operation_steps s", token);
            receipts.ShouldNotContain("repository-first"); receipts.ShouldNotContain("repository-second"); receipts.ShouldNotContain("repository-unlock");
            receipts.ShouldContain(current.proofVersion.ToString("D")); receipts.ShouldContain(lookup.LockoutAttemptVersion.Value.ToString("D"));
        }, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task Begin_wait_rechecks_epoch_and_successful_unlock_invalidates_old_attempt_clear()
    {
        await SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            var observer = await fixture.OpenConnectionAsync(); await SeedUnlock(fixture, observer, token);
            var owner = await fixture.OpenConnectionAsync(); var worker = await fixture.OpenConnectionAsync();
            var holding = await fixture.BeginTransactionAsync(owner);
            await fixture.ExecuteAsync(owner, $"select 1 from accounts where account_id={Id} for update", holding, token);
            var waiting = await fixture.BeginTransactionAsync(worker);
            var task = fixture.Observe(Read<short>(worker, waiting, Begin("waiting"), token));
            await Blocked(observer, worker, owner, task, token);
            (await Read<bool>(owner, holding, $"select result from cor08_record_login_failure({Id},{Stamp},1,5)", token)).ShouldBeTrue();
            await holding.CommitAsync(token);
            (await task).ShouldBe((short)14); await waiting.CommitAsync(token);
            (await Read<long>(observer, null, "select count(*) from account_recoveries", token)).ShouldBe(1L);
            string epoch = await Read<string>(observer, null, "select attempt_version::text from account_login_attempt_versions", token);
            (await Read<short>(observer, null, Begin("current", $"'{epoch}'::uuid"), token)).ShouldBe((short)2);
            (await Read<short>(observer, null, "select status from verify_unlock_account('current')", token)).ShouldBe((short)7);
            // Even an empty-state clear observed before unlock must compare the rotated epoch.
            (await Read<bool>(observer, null, $"select result from cor08_clear_login_attempts({Id},{Stamp},'{epoch}'::uuid,0::smallint,null,false)", token)).ShouldBeFalse();
        }, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task New_failure_after_unlock_retains_its_new_lockout()
    {
        await SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            var observer = await fixture.OpenConnectionAsync(); await SeedUnlock(fixture, observer, token);
            var owner = await fixture.OpenConnectionAsync(); var worker = await fixture.OpenConnectionAsync();
            var holding = await fixture.BeginTransactionAsync(owner);
            await fixture.ExecuteAsync(owner, $"select 1 from accounts where account_id={Id} for update", holding, token);
            var waiting = await fixture.BeginTransactionAsync(worker);
            var task = fixture.Observe(Read<bool>(worker, waiting,
                $"select result from cor08_record_login_failure({Id},{Stamp},1,1)", token));
            await Blocked(observer, worker, owner, task, token);
            (await Read<short>(owner, holding, "select status from verify_unlock_account('unlock')", token)).ShouldBe((short)7);
            await holding.CommitAsync(token); (await task).ShouldBeTrue(); await waiting.CommitAsync(token);
            (await Read<bool>(observer, null, "select unlock_when>clock_timestamp() and login_failures=1 from accounts", token)).ShouldBeTrue();
            (await Read<short>(observer, null, "select status from verify_unlock_account('unlock')", token)).ShouldBe((short)11);
            (await Read<bool>(observer, null, "select unlock_when>clock_timestamp() and login_failures=1 from accounts", token)).ShouldBeTrue();
        }, TestContext.Current.CancellationToken);
    }
    [Theory]
    [InlineData("https://localhost:5001",false)] [InlineData("http://localhost:5001",false)]
    [InlineData("http://localhost:8080",false)] [InlineData("https://api.example.test",false)]
    [InlineData("https://localhost:5001",true)] [InlineData("http://localhost:5001",true)]
    [InlineData("http://localhost:8080",true)] [InlineData("https://api.example.test",true)]
    public Task Cor23G_registration_and_resend_URL_payloads_complete_the_actual_verification_state(string origin,bool resend)
        => SqlContractFixture.RunAsync(async(fixture,token)=>
        {
            var connection=await fixture.OpenConnectionAsync();
            string first=treehammock.Rigging.Security.AccountVerificationTokenUtility.GenerateToken();
            string proof=resend?treehammock.Rigging.Security.AccountVerificationTokenUtility.GenerateToken():first;
            string firstHash=treehammock.Rigging.Security.AccountVerificationTokenUtility.HashToken(first);
            (await Read<short>(connection,null,Setup(Id,"reader@example.invalid","reader","web",firstHash),token)).ShouldBe((short)8000);
            (await Read<bool>(connection,null,$"select result from start_verify_account({Id},(select verification_index from account_verifications where verify_key_hash='{firstHash}'))",token)).ShouldBeTrue();
            string url=new treehammock.Rigging.Hosting.VerificationLinkBuilder(origin).Registration(proof);
            string payload=Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(new Uri(url).Query)["payload"].ToString();payload.ShouldBe(proof);
            string hash=treehammock.Rigging.Security.AccountVerificationTokenUtility.HashToken(payload);
            if(resend)(await Read<bool>(connection,null,Resend(hash),token)).ShouldBeTrue();
            (await Read<bool>(connection,null,await Complete(connection,token,hash),token)).ShouldBeTrue();
            (await Read<short>(connection,null,$"select verify_status from accounts where account_id={Id}",token)).ShouldBe((short)1);
        },TestContext.Current.CancellationToken);

}
