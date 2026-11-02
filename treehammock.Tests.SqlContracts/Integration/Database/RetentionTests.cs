using Npgsql;
using Shouldly;
using treehammock.Tests.SqlContracts.Support;
namespace treehammock.Tests.Integration.Database;

// Real installed SQL, independent connections and private owned schemas.
// Operator changes to clocks/leases below are fixture controls, never API inputs.
[Trait("Suite", "SqlContracts")]
public class Cor22RetentionTests
{
    [Fact]
    public Task Expired_parents_wait_for_children_and_live_sensitive_grants_keep_their_own_expiry() => SqlContractFixture.RunAsync(async (f, ct) =>
    {
        var c = await f.OpenConnectionAsync(); var account = await Account(c, ct); var request = Guid.NewGuid(); var proof = Guid.NewGuid();
        await Exec(c, $"insert into password_reset_requests(factor_policy_version,password_reset_request_id,account_id,method,delivery_channel,key_code_hash,key_code_hash_version,destination_fingerprint,destination_masked,created_at,expires_at,max_attempts,account_security_stamp_at_request) select 'policy','{request}','{account}','email','email','hash',1,'fingerprint','masked',clock_timestamp()-interval '30 days',clock_timestamp()-interval '10 days',5,security_stamp from accounts where account_id='{account}';insert into pending_password_reset_sessions(factor_policy_version,account_security_stamp,reset_access_token_hash,password_reset_request_id,account_id,bootstrap_proof,state,created_on,expires_at) select 'policy',security_stamp,'live-reset','{request}','{account}',0,1,clock_timestamp()-interval '30 days',clock_timestamp()+interval '1 hour' from accounts where account_id='{account}';insert into sensitive_action_proof_sessions(proof_id,handle_hash,account_id,credential_stamp,session_hash,family_id,purpose,target_hash,factor_policy,factor_required,expiration,state) select '{proof}','proof-hash','{account}',security_stamp,'session',gen_random_uuid(),1,repeat('a',64),'policy',false,clock_timestamp()-interval '1 hour','Granted' from accounts where account_id='{account}';insert into sensitive_action_grants(token_hash,proof_id,account_id,credential_stamp,session_hash,family_id,purpose,target_hash,factor_policy,policy_version,expiration) select 'grant-hash',proof_id,account_id,credential_stamp,session_hash,family_id,purpose,target_hash,factor_policy,1,clock_timestamp()+interval '1 hour' from sensitive_action_proof_sessions", ct);
        (await Run(c, "reset_requests", ct)).ShouldBe(0);
        (await Run(c, "pending_reset", ct)).ShouldBe(0);
        (await Run(c, "sensitive_proofs", ct)).ShouldBe(0);
        (await Run(c, "sensitive_grants", ct)).ShouldBe(0);
        await Exec(c, "update pending_password_reset_sessions set expires_at=clock_timestamp()-interval '10 days';update sensitive_action_grants set expiration=clock_timestamp()-interval '1 second'", ct);
        (await Run(c, "pending_reset", ct)).ShouldBe(1);
        (await Run(c, "reset_requests", ct)).ShouldBe(1);
        (await Run(c, "sensitive_grants", ct)).ShouldBe(1);
        (await Run(c, "sensitive_proofs", ct)).ShouldBe(1);
    });

    [Fact]
    public Task Terminal_grant_children_drain_before_root_and_surviving_grant_keeps_aged_audit() => SqlContractFixture.RunAsync(async (f, ct) =>
    {
        var c = await f.OpenConnectionAsync(); var account = await Account(c, ct); var old = Guid.NewGuid(); var live = Guid.NewGuid();
        var stamp = await Scalar<Guid>(c, $"select security_stamp from accounts where account_id='{account}'", ct);
        await Exec(c, "create or replace function cor19_is_issuer(p_actor name) returns boolean language plpgsql stable as $$ begin return p_actor=current_user::name;end $$", ct);
        (await Scalar<bool>(c, $"select result from cor19_issue_grant('{live}','{account}','{stamp}','treehammock-v1',2::smallint,1::smallint,0::smallint,null,clock_timestamp()+interval '2 days',1,clock_timestamp()+interval '1 hour','reviewed','redemption',array[]::text[])", ct)).ShouldBeTrue();
        await Exec(c, $"insert into entitlement_grants(grant_id,account_id,origin_stamp,catalog,tier,term,cadence,start_anchor,max_cycles,redeem_before,issuer,issuer_reference,state,revoked_at) values('{old}','{account}','{stamp}','treehammock-v1',2,1,0,'redemption',1,clock_timestamp()-interval '20 days',current_user,'fixture','revoked',clock_timestamp()-interval '10 days');insert into entitlement_grant_cycles(grant_id,cycle,starts_at,ends_at,actor,credential_stamp) select '{old}',i,clock_timestamp()-interval '20 days',clock_timestamp()-interval '10 days','fixture','{stamp}' from generate_series(1,5) i;insert into entitlement_grant_audit(grant_id,account_id,grant_version,action,actor,credential_stamp,happened_at) values('{old}','{account}',1,'revoked','fixture','{stamp}',clock_timestamp()-interval '100 days'),('{live}','{account}',1,'issued','fixture','{stamp}',clock_timestamp()-interval '100 days')", ct);
        (await Run(c, "grant_history", ct)).ShouldBe(0);
        (await Run(c, "grant_audit", ct)).ShouldBe(0);
        for (int i = 0; i < 3; i++) (await Run(c, "grant_cycles", ct, 2)).ShouldBeLessThanOrEqualTo(2);
        (await Run(c, "grant_history", ct)).ShouldBe(1);
        (await Run(c, "grant_audit", ct)).ShouldBe(1);
        (await Scalar<Guid>(c, "select grant_id from entitlement_grants", ct)).ShouldBe(live);
        (await Scalar<long>(c, $"select count(*) from entitlement_grant_audit where grant_id='{live}'", ct)).ShouldBe(2);
    });

    [Fact]
    public Task Forged_temporary_audit_permit_cannot_authorize_history_deletion() => SqlContractFixture.RunAsync(async (f, ct) =>
    {
        var c = await f.OpenConnectionAsync(); var account = await Account(c, ct);
        await Exec(c, $"insert into entitlement_grant_audit(grant_id,account_id,grant_version,action,actor,credential_stamp,happened_at) select gen_random_uuid(),'{account}',1,'issued','fixture',security_stamp,clock_timestamp()-interval '100 days' from accounts where account_id='{account}';create temp table retention_audit_delete_permits(like {f.Schema}.retention_audit_delete_permits)", ct);
        await using var tx = await c.BeginTransactionAsync(ct);
        await Exec(c, "insert into pg_temp.retention_audit_delete_permits select pg_backend_pid(),txid_current(),audit_id,clock_timestamp()-interval '90 days' from entitlement_grant_audit", ct, tx);
        var error = await Should.ThrowAsync<PostgresException>(() => Exec(c, "delete from entitlement_grant_audit", ct, tx));
        error.SqlState.ShouldBe("P1901"); await tx.RollbackAsync(ct);
        (await Scalar<long>(c, "select count(*) from entitlement_grant_audit", ct)).ShouldBe(1);
    });

    [Fact]
    public Task Every_registered_policy_executes_against_the_installed_current_schema() => SqlContractFixture.RunAsync(async (f, ct) =>
    {
        var c = await f.OpenConnectionAsync();
        var jobs = new List<string>();
        await using (var cmd = new NpgsqlCommand("select job_name from retention_jobs order by job_name", c))
        await using (var reader = await cmd.ExecuteReaderAsync(ct))
            while (await reader.ReadAsync(ct)) jobs.Add(reader.GetString(0));
        jobs.Count.ShouldBe(34);
        foreach (var job in jobs) (await Run(c, job, ct)).ShouldBe(0);
    });

    [Fact]
    public Task Suppressed_delete_rolls_back_cursor_and_records_failure_for_retry() => SqlContractFixture.RunAsync(async (f, ct) =>
    {
        var c = await f.OpenConnectionAsync();
        await Exec(c, "insert into password_reset_events(event_type,code,created_at) values('old','OLD',clock_timestamp()-interval '100 days');create function cor22_suppress() returns trigger language plpgsql as $$ begin return null;end $$;create trigger cor22_suppress before delete on password_reset_events for each row execute function cor22_suppress()", ct);
        var lease = await Claim(c, "reset_events", ct);
        var error = await Should.ThrowAsync<PostgresException>(() => Scalar<int>(c, Batch("reset_events", lease), ct));
        error.SqlState.ShouldBe("P2203");
        (await Scalar<long>(c, "select count(*) from password_reset_events", ct)).ShouldBe(1);
        (await Scalar<bool>(c, "select last_success is null and cursor_key is null from retention_jobs where job_name='reset_events'", ct)).ShouldBeTrue();
        await Exec(c, $"select cor22_fail_retention('reset_events','{lease}','P2203');drop trigger cor22_suppress on password_reset_events", ct);
        (await Run(c, "reset_events", ct)).ShouldBe(1);
    });

    private static async Task Exec(NpgsqlConnection c, string sql, CancellationToken ct, NpgsqlTransaction? tx = null)
    { await using var cmd = new NpgsqlCommand(sql, c, tx); await cmd.ExecuteNonQueryAsync(ct); }
    private static async Task<T> Scalar<T>(NpgsqlConnection c, string sql, CancellationToken ct, NpgsqlTransaction? tx = null)
    { await using var cmd = new NpgsqlCommand(sql, c, tx); return (T)(await cmd.ExecuteScalarAsync(ct))!; }
    private static async Task<Guid> Account(NpgsqlConnection c, CancellationToken ct, bool verified = true)
    {
        var id = Guid.NewGuid();
        await Exec(c, $"insert into accounts(account_id,email_address,verify_status,created_on) values('{id}','{id:N}@example.test',{(verified ? 1 : 0)},clock_timestamp()-interval '120 days')", ct);
        return id;
    }
    private static async Task<Guid> Claim(NpgsqlConnection c, string job, CancellationToken ct)
    {
        await Exec(c, $"update retention_jobs set next_run=clock_timestamp()+interval '1 day' where job_name<>'{job}';update retention_jobs set next_run=clock_timestamp()-interval '1 second' where job_name='{job}'", ct);
        return await Scalar<Guid>(c, "select lease_id from cor22_claim_retention()", ct);
    }
    private static string Batch(string job, Guid lease, int limit = 100, bool dry = false, string column = "affected") =>
        $"select {column} from cor22_retention_batch('{job}','{lease}',{limit},8,7,90,30,{dry.ToString().ToLowerInvariant()})";
    private static async Task<int> Run(NpgsqlConnection c, string job, CancellationToken ct, int limit = 100, bool dry = false, string column = "affected") =>
        await Scalar<int>(c, Batch(job, await Claim(c, job, ct), limit, dry, column), ct);

    [Fact]
    public Task Deep_account_history_resumes_after_restart_and_preserves_refreshable_sessions() => SqlContractFixture.RunAsync(async (f, ct) =>
    {
        var c = await f.OpenConnectionAsync(); var id = await Account(c, ct);
        await Exec(c, $"insert into sessions(access_token_hash,account_id,account_security_stamp,created_on,access_expiration,session_expiration) select 'old-'||i,'{id}',security_stamp,clock_timestamp()-interval '30 days',clock_timestamp()-interval '20 days',clock_timestamp()-interval '10 days' from accounts cross join generate_series(1,7) i where account_id='{id}';insert into sessions(access_token_hash,account_id,account_security_stamp,created_on,access_expiration,session_expiration) select 'refreshable','{id}',security_stamp,clock_timestamp()-interval '1 day',clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 day' from accounts where account_id='{id}'", ct);
        (await Run(c, "sessions", ct, 2)).ShouldBe(2);
        var restarted = await f.OpenConnectionAsync();
        for (int i = 0; i < 3; i++) (await Run(restarted, "sessions", ct, 2)).ShouldBeLessThanOrEqualTo(2);
        (await Scalar<long>(c, "select count(*) from sessions", ct)).ShouldBe(1);
        (await Scalar<string>(c, "select access_token_hash from sessions", ct)).ShouldBe("refreshable");
        (await Run(restarted, "sessions", ct, 2)).ShouldBe(0);
    });

    [Fact]
    public Task Reset_history_and_audit_are_independent_and_each_budget_keeps_its_own_deadline() => SqlContractFixture.RunAsync(async (f, ct) =>
    {
        var c = await f.OpenConnectionAsync(); var id = await Account(c, ct);
        await Exec(c, $"insert into password_reset_requests(factor_policy_version,password_reset_request_id,account_id,method,delivery_channel,key_code_hash,key_code_hash_version,destination_fingerprint,destination_masked,created_at,expires_at,max_attempts,account_security_stamp_at_request) select 'policy',gen_random_uuid(),'{id}','email','email','hash',1,'fingerprint','masked',clock_timestamp()-interval '30 days',clock_timestamp()-interval '10 days',5,security_stamp from accounts where account_id='{id}';insert into password_reset_events(account_id,event_type,code,created_at) values('{id}','old','OLD',clock_timestamp()-interval '100 days'),('{id}','recent','RECENT',clock_timestamp()-interval '10 days');insert into password_reset_rate_limits(rate_limit_key,window_started_at,last_request_at,blocked_until) values('old',clock_timestamp()-interval '30 days',clock_timestamp()-interval '30 days',null),('live-window',clock_timestamp()-interval '1 day',clock_timestamp()-interval '1 day',null),('live-block',clock_timestamp()-interval '30 days',clock_timestamp()-interval '30 days',clock_timestamp()+interval '1 hour');insert into activation_creation_budgets values('live',clock_timestamp()+interval '1 hour',5,clock_timestamp()),('old',clock_timestamp()-interval '30 days',5,clock_timestamp()-interval '30 days')", ct);
        (await Run(c, "reset_requests", ct)).ShouldBe(1);
        (await Scalar<long>(c, "select count(*) from password_reset_events", ct)).ShouldBe(2);
        (await Run(c, "reset_events", ct)).ShouldBe(1);
        (await Run(c, "reset_budgets", ct)).ShouldBe(1);
        (await Run(c, "activation_budgets", ct)).ShouldBe(1);
        (await Scalar<int>(c, "select request_count from activation_creation_budgets where budget_key='live'", ct)).ShouldBe(5);
        (await Scalar<long>(c, "select count(*) from password_reset_rate_limits", ct)).ShouldBe(2);
    });

    [Fact]
    public Task Expired_payloads_are_scrubbed_but_live_published_proofs_and_ambiguous_provider_history_survive() => SqlContractFixture.RunAsync(async (f, ct) =>
    {
        var c = await f.OpenConnectionAsync(); var id = await Account(c, ct);
        await Exec(c, $"insert into delivery_candidates(delivery_id,account_id,account_stamp,purpose,proof_hash,expires_at,metadata_json,predecessor,state) select gen_random_uuid(),'{id}',security_stamp,'verify',x,case when x='live' then clock_timestamp()+interval '1 hour' else clock_timestamp()-interval '1 hour' end,'{{}}','fixture',case when x='live' then 'published' else 'staged' end from accounts cross join (values('live'),('expired')) q(x) where account_id='{id}';insert into delivery_outbox(delivery_id,state,key_version,nonce,ciphertext,tag,lease_id,lease_until) select delivery_id,case when proof_hash='live' then 'published' else 'ambiguous' end,1,decode(repeat('00',12),'hex'),decode('01','hex'),decode(repeat('00',16),'hex'),case when proof_hash='expired' then gen_random_uuid() else null end,case when proof_hash='expired' then clock_timestamp()+interval '1 hour' else null end from delivery_candidates", ct);
        (await Run(c, "delivery_payloads", ct)).ShouldBe(1);
        (await Scalar<bool>(c, "select o.ciphertext is null and o.nonce is null and o.tag is null and o.lease_id is null from delivery_outbox o join delivery_candidates c using(delivery_id) where c.proof_hash='expired'", ct)).ShouldBeTrue();
        (await Scalar<string>(c, "select state from delivery_candidates where proof_hash='live'", ct)).ShouldBe("published");
        (await Run(c, "delivery_history", ct)).ShouldBe(0);
        (await Scalar<long>(c, "select count(*) from delivery_candidates", ct)).ShouldBe(2);
    });

    [Fact]
    public Task Pending_login_verification_and_factor_history_preserve_active_proofs_and_verified_factors() => SqlContractFixture.RunAsync(async (f, ct) =>
    {
        var c = await f.OpenConnectionAsync(); var id = await Account(c, ct);
        await Exec(c, $"insert into pending_two_factor_sessions(pre_auth_access_token_hash,account_id,account_security_stamp,expiration) select x,'{id}',security_stamp,case when x='live' then clock_timestamp()+interval '1 hour' else clock_timestamp()-interval '10 days' end from accounts cross join (values('old'),('live')) q(x) where account_id='{id}';insert into account_verifications(account_id,verify_key_hash,account_security_stamp,verify_status,created_on,sent_when,expiration) select '{id}',x,security_stamp,case when x='live' then 0 else 3 end,clock_timestamp()-interval '20 days',case when x='live' then clock_timestamp() else clock_timestamp()-interval '20 days' end,interval '1 day' from accounts cross join (values('old'),('live')) q(x) where account_id='{id}';insert into two_factor_authentications(account_id,two_factor_index,method,verified,created_on,expiration,email_address) values('{id}',1,1,true,clock_timestamp()-interval '20 days',clock_timestamp()-interval '10 days','verified@example.test'),('{id}',2,1,false,clock_timestamp()-interval '20 days',clock_timestamp()-interval '10 days','expired@example.test'),('{id}',3,1,false,clock_timestamp(),clock_timestamp()+interval '1 hour','pending@example.test')", ct);
        (await Run(c, "pending_login", ct)).ShouldBe(1);
        (await Run(c, "verification_history", ct)).ShouldBe(1);
        (await Run(c, "factor_history", ct)).ShouldBe(1);
        (await Scalar<long>(c, "select count(*) from two_factor_authentications", ct)).ShouldBe(2);
        (await Scalar<bool>(c, "select verified from two_factor_authentications where two_factor_index=1", ct)).ShouldBeTrue();
    });

    [Fact]
    public Task Receipt_children_drain_in_bounded_batches_before_root_and_live_receipts_remain() => SqlContractFixture.RunAsync(async (f, ct) =>
    {
        var c = await f.OpenConnectionAsync(); var old = Guid.NewGuid(); var live = Guid.NewGuid();
        await Exec(c, $"insert into security_operations(operation_id,request_hmac,recovery_hmac,hmac_version,purpose,issued_at,execute_before,expires_at,state) values('{old}',decode(repeat('00',32),'hex'),decode(repeat('00',32),'hex'),1,'test',clock_timestamp()-interval '3 days',clock_timestamp()-interval '2 days',clock_timestamp()-interval '1 day','Committed'),('{live}',decode(repeat('00',32),'hex'),decode(repeat('00',32),'hex'),1,'test',clock_timestamp(),clock_timestamp()+interval '1 minute',clock_timestamp()+interval '1 day','Pending');insert into security_operation_steps(operation_id,step_key,request_hmac,outcome_code) select '{old}',i::text,decode(repeat('00',32),'hex'),'OK' from generate_series(1,5) i", ct);
        (await Run(c, "operations", ct)).ShouldBe(0);
        (await Run(c, "operation_steps", ct, 2)).ShouldBe(2);
        (await Run(c, "operation_steps", ct, 2)).ShouldBe(2);
        (await Run(c, "operation_steps", ct, 2)).ShouldBe(1);
        (await Run(c, "operations", ct)).ShouldBe(1);
        (await Scalar<Guid>(c, "select operation_id from security_operations", ct)).ShouldBe(live);
    });

    [Fact]
    public Task Unverified_root_waits_for_children_and_live_lockout_before_releasing_email() => SqlContractFixture.RunAsync(async (f, ct) =>
    {
        var c = await f.OpenConnectionAsync(); var empty = await Account(c, ct, false); var guarded = await Account(c, ct, false);
        await Exec(c, $"insert into pending_two_factor_sessions(pre_auth_access_token_hash,account_id,account_security_stamp,expiration) select 'guard','{guarded}',security_stamp,clock_timestamp()+interval '1 hour' from accounts where account_id='{guarded}';insert into account_login_attempt_versions select '{empty}',security_stamp,gen_random_uuid() from accounts where account_id='{empty}'", ct);
        (await Run(c, "unverified_accounts", ct)).ShouldBe(1);
        (await Scalar<Guid>(c, "select account_id from accounts", ct)).ShouldBe(guarded);
        await Exec(c, $"delete from pending_two_factor_sessions;update accounts set unlock_when=clock_timestamp()+interval '1 hour' where account_id='{guarded}'", ct);
        (await Run(c, "unverified_accounts", ct)).ShouldBe(0);
    });

    [Fact]
    public Task Grant_audit_retention_requires_orphan_age_and_never_allows_ordinary_update_or_delete() => SqlContractFixture.RunAsync(async (f, ct) =>
    {
        var c = await f.OpenConnectionAsync(); var id = await Account(c, ct); var grant = Guid.NewGuid();
        await Exec(c, $"insert into entitlement_grant_audit(grant_id,account_id,grant_version,action,actor,credential_stamp,happened_at) select '{grant}','{id}',1,'issued','fixture',security_stamp,clock_timestamp()-interval '100 days' from accounts where account_id='{id}';insert into entitlement_grant_audit(grant_id,account_id,grant_version,action,actor,credential_stamp,happened_at) select gen_random_uuid(),'{id}',1,'issued','fixture',security_stamp,clock_timestamp() from accounts where account_id='{id}'", ct);
        var delete = await Should.ThrowAsync<PostgresException>(() => Exec(c, "delete from entitlement_grant_audit", ct)); delete.SqlState.ShouldBe("P1901");
        var update = await Should.ThrowAsync<PostgresException>(() => Exec(c, "update entitlement_grant_audit set actor='changed'", ct)); update.SqlState.ShouldBe("P1901");
        (await Run(c, "grant_audit", ct, dry: true, column: "eligible")).ShouldBe(1);
        (await Scalar<long>(c, "select count(*) from entitlement_grant_audit", ct)).ShouldBe(2);
        (await Run(c, "grant_audit", ct)).ShouldBe(1);
        (await Scalar<long>(c, "select count(*) from retention_audit_delete_permits", ct)).ShouldBe(0);
        (await Scalar<long>(c, "select count(*) from entitlement_grant_audit", ct)).ShouldBe(1);
    });

    [Fact]
    public Task Concurrent_claims_skip_owned_job_and_expired_lease_fences_stale_worker() => SqlContractFixture.RunAsync(async (f, ct) =>
    {
        var c = await f.OpenConnectionAsync(); var a = await f.OpenConnectionAsync(); var b = await f.OpenConnectionAsync();
        await Exec(c, "update retention_jobs set next_run=clock_timestamp()+interval '1 day' where job_name not in ('reset_events','logout_events')", ct);
        await using var tx = await a.BeginTransactionAsync(ct);
        var first = await Scalar<string>(a, "select job_name from cor22_claim_retention()", ct, tx);
        var other = await Scalar<string>(b, "select job_name from cor22_claim_retention()", ct); first.ShouldNotBe(other);
        await tx.RollbackAsync(ct);
        var lease = await Claim(c, first, ct);
        await Exec(c, $"update retention_jobs set lease_until=clock_timestamp()-interval '1 second' where job_name='{first}'", ct);
        var replacement = await Claim(b, first, ct); replacement.ShouldNotBe(lease);
        var stale = await Should.ThrowAsync<PostgresException>(() => Scalar<int>(a, Batch(first, lease), ct)); stale.SqlState.ShouldBe("P2202");
        (await Scalar<int>(b, Batch(first, replacement), ct)).ShouldBe(0);
        (await Scalar<bool>(c, $"select cor22_fail_retention('{first}','{lease}','P2203')", ct)).ShouldBeFalse();
    });

    [Fact]
    public Task Work_and_cursor_roll_back_together_and_failure_telemetry_preserves_retry() => SqlContractFixture.RunAsync(async (f, ct) =>
    {
        var c = await f.OpenConnectionAsync();
        await Exec(c, "insert into password_reset_events(event_type,code,created_at) values('old','OLD',clock_timestamp()-interval '100 days')", ct);
        var lease = await Claim(c, "reset_events", ct);
        await using (var tx = await c.BeginTransactionAsync(ct))
        {
            (await Scalar<int>(c, Batch("reset_events", lease), ct, tx)).ShouldBe(1);
            await tx.RollbackAsync(ct);
        }
        (await Scalar<long>(c, "select count(*) from password_reset_events", ct)).ShouldBe(1);
        (await Scalar<bool>(c, "select cursor_key is null and last_success is null from retention_jobs where job_name='reset_events'", ct)).ShouldBeTrue();
        (await Scalar<bool>(c, $"select cor22_fail_retention('reset_events','{lease}','P2203')", ct)).ShouldBeTrue();
        (await Scalar<string>(c, "select failure_code from retention_jobs where job_name='reset_events'", ct)).ShouldBe("P2203");
        (await Run(c, "reset_events", ct)).ShouldBe(1);
    });

    [Fact]
    public Task Dry_run_cursor_covers_deep_history_without_deletion_and_mutating_pass_wraps() => SqlContractFixture.RunAsync(async (f, ct) =>
    {
        var c = await f.OpenConnectionAsync();
        await Exec(c, "insert into password_reset_events(event_type,code,created_at) select 'old','OLD',clock_timestamp()-interval '100 days' from generate_series(1,7)", ct);
        int observed = 0; for (int i = 0; i < 4; i++) observed += await Run(c, "reset_events", ct, 2, true, "eligible");
        observed.ShouldBe(7); (await Scalar<long>(c, "select count(*) from password_reset_events", ct)).ShouldBe(7);
        for (int i = 0; i < 4; i++) await Run(c, "reset_events", ct, 2);
        (await Scalar<long>(c, "select count(*) from password_reset_events", ct)).ShouldBe(0);
        (await Scalar<long>(c, "select passes from retention_jobs where job_name='reset_events'", ct)).ShouldBeGreaterThan(0);
    });

    [Fact]
    public Task Busy_account_is_skipped_and_revisited_after_cursor_wrap() => SqlContractFixture.RunAsync(async (f, ct) =>
    {
        var observer = await f.OpenConnectionAsync(); var id = await Account(observer, ct);
        await Exec(observer, $"insert into pending_two_factor_sessions(pre_auth_access_token_hash,account_id,account_security_stamp,expiration) select 'old','{id}',security_stamp,clock_timestamp()-interval '10 days' from accounts where account_id='{id}'", ct);
        var owner = await f.OpenConnectionAsync(); var worker = await f.OpenConnectionAsync();
        await using var tx = await owner.BeginTransactionAsync(ct);
        await Exec(owner, $"select 1 from accounts where account_id='{id}' for update", ct, tx);
        (await Run(worker, "pending_login", ct)).ShouldBe(0);
        await tx.CommitAsync(ct); (await Run(worker, "pending_login", ct)).ShouldBe(1);
    });

    [Theory, InlineData("limit"), InlineData("audit"), InlineData("null"), InlineData("unknown")]
    public Task Invalid_or_weak_policy_cannot_delete_history(string invalid) => SqlContractFixture.RunAsync(async (f, ct) =>
    {
        var c = await f.OpenConnectionAsync(); var lease = await Claim(c, "reset_events", ct);
        string sql = Batch("reset_events", lease);
        sql = invalid switch { "limit" => sql.Replace(",100,8,", ",101,8,"), "audit" => sql.Replace(",7,90,30,", ",7,1,30,"),
            "null" => sql.Replace(",false)", ",null)"), "unknown" => sql.Replace("'reset_events'", "'arbitrary'"), _ => sql };
        var error = await Should.ThrowAsync<PostgresException>(() => Scalar<int>(c, sql, ct));
        error.SqlState.ShouldBe(invalid == "unknown" ? "P2202" : "P2201");
    });
}
