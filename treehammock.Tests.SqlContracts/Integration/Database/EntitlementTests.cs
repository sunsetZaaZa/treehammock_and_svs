using System.Text.Json;
using NodaTime;
using Npgsql;
using Shouldly;
using treehammock.DataLayer.Entitlements;
using treehammock.Tests.SqlContracts.Support;
namespace treehammock.Tests.Integration.Database;

[Trait("Suite","SqlContracts")]
public class Cor20EntitlementTests
{
    private sealed record Subject(Guid Account,Guid Stamp,Guid Family,Guid Grant,Guid Request,string Session);
    private static async Task Exec(NpgsqlConnection c,string sql,CancellationToken ct,NpgsqlTransaction? tx=null)
    {await using var command=new NpgsqlCommand(sql,c,tx);await command.ExecuteNonQueryAsync(ct);}
    private static async Task<T> Scalar<T>(NpgsqlConnection c,string sql,CancellationToken ct,NpgsqlTransaction? tx=null)
    {await using var command=new NpgsqlCommand(sql,c,tx);return (T)(await command.ExecuteScalarAsync(ct))!;}
    // Explicit, owned-schema qualification substitutes: no deployment role or clock is modified.
    private static Task Clock(NpgsqlConnection c,string now,CancellationToken ct)=>Exec(c,$"create or replace function cor20_now() returns timestamptz language plpgsql volatile as $$ begin return '{now}'::timestamptz;end $$",ct);
    private static Task Gate(NpgsqlConnection c,bool enabled,CancellationToken ct)=>Exec(c,$"create or replace function cor20_grant_rights_enabled() returns boolean language plpgsql stable as $$ begin return {(enabled?"true":"false")};end $$",ct);
    private static string Revoke(Subject a,long version)=>$"select result from cor19_transition_activation('{a.Account}','{a.Stamp}','{a.Session}','{a.Family}','{a.Grant}',{version},'{a.Request}',null,'disable')";
    private static async Task<Subject> Seed(NpgsqlConnection c,CancellationToken ct,short term=6,short cadence=1,int cycles=3,
        string? start=null,string denies="array[]::text[]",bool activate=true,string? authorizedEnd=null)
    {
        var a=new Subject(Guid.NewGuid(),Guid.NewGuid(),Guid.NewGuid(),Guid.NewGuid(),Guid.NewGuid(),Guid.NewGuid().ToString("N"));
        await Exec(c,"create or replace function cor19_is_issuer(p_actor name) returns boolean language plpgsql stable as $$ begin return p_actor=current_user::name;end $$",ct);
        await Clock(c,"2040-01-31T12:34:56Z",ct);
        await Exec(c,$"insert into accounts(account_id,email_address,username,verify_status,security_stamp) values('{a.Account}','{a.Account:N}@example.test','{a.Account:N}',1,'{a.Stamp}');insert into sessions(access_token_hash,account_id,session_id,account_security_stamp,created_on,access_expiration,session_expiration) values('{a.Session}','{a.Account}','{a.Family}','{a.Stamp}',clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours')",ct);
        string approved=start is null?"null":$"'{start}'::timestamptz";string anchor=start is null?"redemption":"approved-boundary";
        string end=authorizedEnd is not null?$"'{authorizedEnd}'::timestamptz":term==11?"null":"'2042-01-01T00:00:00Z'::timestamptz";
        (await Scalar<bool>(c,$"select result from cor19_issue_grant('{a.Grant}','{a.Account}','{a.Stamp}','treehammock-v1',2::smallint,{term}::smallint,{cadence}::smallint,{approved},{end},{cycles},clock_timestamp()+interval '2 hours','reviewed','{anchor}',{denies})",ct)).ShouldBeTrue();
        if(!activate)return a;
        (await Scalar<bool>(c,$"select result from cor19_stage_activation('{a.Request}','{a.Account}','{a.Stamp}','{a.Session}','{a.Family}','{a.Grant}',1,'{new string('a',64)}',clock_timestamp()+interval '10 minutes','{a.Account:N}@example.test',2::smallint,{term}::smallint,{cadence}::smallint,{Cor21CreationSql.Admit(a.Account,a.Stamp,a.Session,a.Family,a.Grant,new string('a',64),$"{a.Account:N}@example.test",2,term,cadence)})",ct)).ShouldBeTrue();
        await Exec(c,$"insert into delivery_candidates(delivery_id,account_id,account_stamp,purpose,proof_hash,expires_at,metadata_json,predecessor,state,terminal_at) values('{a.Request}','{a.Account}','{a.Stamp}','activation','{new string('a',64)}',clock_timestamp()+interval '10 minutes','{{}}','fixture','published',clock_timestamp());select cor19_publish_activation('{a.Request}','{a.Stamp}','{new string('a',64)}')",ct);
        (await Scalar<bool>(c,$"select result from cor19_transition_activation('{a.Account}','{a.Stamp}','{a.Session}','{a.Family}','{a.Grant}',1,'{a.Request}','{new string('a',64)}','verify')",ct)).ShouldBeTrue();return a;
    }
    private static async Task<EntitlementProjection> Projection(NpgsqlConnection c,Subject a,CancellationToken ct)
        => EntitlementProjection.Parse(await Scalar<string>(c,$"select cor20_resolve_account('{a.Account}')::text",ct),a.Account);
    [Theory]
    [InlineData("2023-01-31T12:34:56Z",6,1,"2023-02-28T12:34:56Z")]
    [InlineData("2023-01-31T12:34:56Z",6,2,"2023-03-31T12:34:56Z")]
    [InlineData("2024-02-29T12:34:56Z",10,4,"2028-02-29T12:34:56Z")]
    [InlineData("2024-01-31T12:34:56Z",7,1,"2024-04-30T12:34:56Z")]
    [InlineData("2024-02-28T12:34:56Z",1,1,"2024-02-29T12:34:56Z")]
    [InlineData("2024-02-28T12:34:56Z",2,1,"2024-03-06T12:34:56Z")]
    [InlineData("2024-02-28T12:34:56Z",3,1,"2024-03-13T12:34:56Z")]
    [InlineData("2024-01-31T12:34:56Z",8,1,"2024-07-31T12:34:56Z")]
    [InlineData("2024-01-31T12:34:56Z",9,1,"2024-10-31T12:34:56Z")]
    public async Task PostgreSql_calendar_matches_original_utc_anchor(string start,int term,int cycle,string expected)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{var c=await f.OpenConnectionAsync();
            var actual=await Scalar<Instant>(c,$"select cor20_term_boundary('{start}',{term}::smallint,{cycle})",ct);
            actual.ShouldBe(NodaTime.Text.InstantPattern.ExtendedIso.Parse(expected).Value);
            actual.ShouldBe(treehammock.Services.CalendarTermCalculator.Boundary(NodaTime.Text.InstantPattern.ExtendedIso.Parse(start).Value,(treehammock.RiggingSupport.Enum.DayDuration)term,cycle));});
    }
    [Fact]
    public async Task Production_rights_gate_stays_closed_even_for_audited_active_premium()
    {await SqlContractFixture.RunAsync(async(f,ct)=>{var c=await f.OpenConnectionAsync();var a=await Seed(c,ct);var p=await Projection(c,a,ct);p.RightsEnabled.ShouldBeFalse();p.Features.ShouldBe(treehammock.RiggingSupport.Enum.FeatureSet.basic);p.Grants.Single().Cycle.ShouldBe(1);});}
    [Fact]
    public async Task Late_worker_does_not_extend_or_remove_approved_current_rights_and_retry_records_once()
    {await SqlContractFixture.RunAsync(async(f,ct)=>{var c=await f.OpenConnectionAsync();var a=await Seed(c,ct);await Gate(c,true,ct);await Clock(c,"2040-04-01T00:00:00Z",ct);
        var before=await Projection(c,a,ct);before.Grants.Single().Cycle.ShouldBe(3);before.Grants.Single().MaterializedCycle.ShouldBe(1);before.Features.ShouldBe(treehammock.RiggingSupport.Enum.FeatureSet.premium);
        (await Scalar<int>(c,$"select cor20_materialize_cycles('{a.Account}',64)",ct)).ShouldBe(2);
        (await Scalar<int>(c,$"select cor20_materialize_cycles('{a.Account}',64)",ct)).ShouldBe(0);
        var after=await Projection(c,a,ct);after.EligibilityUntil.ShouldBe(before.EligibilityUntil);after.Version.ShouldBeGreaterThan(before.Version);
        (await Scalar<long>(c,"select count(*) from entitlement_grant_cycles",ct)).ShouldBe(3);
        (await Scalar<long>(c,"select count(*) from entitlement_grant_audit where action='renewed'",ct)).ShouldBe(2);
        await Clock(c,"2040-04-30T12:34:56Z",ct);(await Projection(c,a,ct)).Features.ShouldBe(treehammock.RiggingSupport.Enum.FeatureSet.basic);
        (await Scalar<int>(c,$"select cor20_materialize_cycles('{a.Account}',64)",ct)).ShouldBe(0);
        (await Scalar<long>(c,"select count(*) from entitlement_grant_cycles",ct)).ShouldBe(3);
    });}
    [Fact]
    public async Task Future_start_is_inclusive_and_indefinite_end_is_null()
    {await SqlContractFixture.RunAsync(async(f,ct)=>{var c=await f.OpenConnectionAsync();var a=await Seed(c,ct,start:"2040-02-01T00:00:00Z");await Gate(c,true,ct);
        (await Projection(c,a,ct)).Features.ShouldBe(treehammock.RiggingSupport.Enum.FeatureSet.basic);
        await Clock(c,"2040-02-01T00:00:00Z",ct);(await Projection(c,a,ct)).Grants.Single().Cycle.ShouldBe(1);
        var b=await Seed(c,ct,11,0,1);var indefinite=await Projection(c,b,ct);indefinite.EligibilityUntil.ShouldBeNull();indefinite.Grants.Single().EligibilityUntil.ShouldBeNull();
        await Clock(c,"2050-01-01T00:00:00Z",ct);(await Projection(c,b,ct)).Grants.Single().Cycle.ShouldBe(1);
    });}
    [Fact]
    public async Task Login_profile_existing_session_and_refresh_lookup_have_one_versioned_projection()
    {await SqlContractFixture.RunAsync(async(f,ct)=>{var c=await f.OpenConnectionAsync();var a=await Seed(c,ct);await Gate(c,true,ct);
        var p=await Projection(c,a,ct);
        foreach(var query in new[]{ $"get_session('{a.Session}')",$"check_account_username_creds('{a.Account:N}')",$"check_account_emailaddress_creds('{a.Account:N}@example.test')",$"check_account_both_creds('{a.Account:N}','{a.Account:N}@example.test')",$"view_account('{a.Account}','{a.Stamp}')",$"list_active_sessions('{a.Account}','{a.Stamp}','{a.Session}')",$"get_refresh_session((select refresh_credential_hash from sessions where access_token_hash='{a.Session}'),'{a.Family}',1)"})
        {
            var json=await Scalar<string>(c,$"select entitlement_json from {query}",ct);var found=EntitlementProjection.Parse(json,a.Account);
            found.Version.ShouldBe(p.Version);found.Features.ShouldBe(p.Features);found.Capabilities.ShouldBe(p.Capabilities);
        }
        var other=await f.OpenConnectionAsync();var warm=EntitlementProjection.Parse(await Scalar<string>(other,$"select entitlement_json from validate_cached_session_trust('{a.Session}','{a.Account}',(select security_stamp from sessions where access_token_hash='{a.Session}'),'{a.Stamp}')",ct));warm.Version.ShouldBe(p.Version);
        (await Scalar<long>(c,"select entitlement_version from sessions",ct)).ShouldBe(p.Version);
    });}
    [Fact]
    public async Task Denial_wins_across_overlapping_grants_without_numeric_inheritance()
    {await SqlContractFixture.RunAsync(async(f,ct)=>{var c=await f.OpenConnectionAsync();var a=await Seed(c,ct,denies:"array['account.read']::text[]");await Gate(c,true,ct);
        var p=await Projection(c,a,ct);p.Allows("account.read").ShouldBeFalse();p.Allows("account.manage").ShouldBeTrue();
        // A second audited grant for this same account permits the baseline; the first denial still wins.
        var second=Guid.NewGuid();var request=Guid.NewGuid();
        (await Scalar<bool>(c,$"select result from cor19_issue_grant('{second}','{a.Account}','{a.Stamp}','treehammock-v1',1::smallint,1::smallint,0::smallint,null,'2042-01-01',1,clock_timestamp()+interval '2 hours','overlap','redemption',array[]::text[])",ct)).ShouldBeTrue();
        await Exec(c,$"update activation_creation_budgets set next_request_at=clock_timestamp() where budget_key='a:{a.Account}'",ct);
        (await Scalar<bool>(c,$"select result from cor19_stage_activation('{request}','{a.Account}','{a.Stamp}','{a.Session}','{a.Family}','{second}',1,'{new string('b',64)}',clock_timestamp()+interval '10 minutes','{a.Account:N}@example.test',1::smallint,1::smallint,0::smallint,{Cor21CreationSql.Admit(a.Account,a.Stamp,a.Session,a.Family,second,new string('b',64),$"{a.Account:N}@example.test",1)})",ct)).ShouldBeTrue();
        await Exec(c,$"insert into delivery_candidates(delivery_id,account_id,account_stamp,purpose,proof_hash,expires_at,metadata_json,predecessor,state,terminal_at) values('{request}','{a.Account}','{a.Stamp}','activation','{new string('b',64)}',clock_timestamp()+interval '10 minutes','{{}}','fixture','published',clock_timestamp());select cor19_publish_activation('{request}','{a.Stamp}','{new string('b',64)}')",ct);
        (await Scalar<bool>(c,$"select result from cor19_transition_activation('{a.Account}','{a.Stamp}','{a.Session}','{a.Family}','{second}',1,'{request}','{new string('b',64)}','verify')",ct)).ShouldBeTrue();
        (await Projection(c,a,ct)).Allows("account.read").ShouldBeFalse();
    });}
    [Fact]
    public async Task Two_workers_have_one_cycle_winner_and_revoke_removes_rights_on_another_instance()
    {await SqlContractFixture.RunAsync(async(f,ct)=>{var observer=await f.OpenConnectionAsync();var a=await Seed(observer,ct);await Gate(observer,true,ct);await Clock(observer,"2040-03-01T00:00:00Z",ct);
        var owner=await f.OpenConnectionAsync();var waiter=await f.OpenConnectionAsync();await using var tx=await owner.BeginTransactionAsync(ct);
        (await Scalar<int>(owner,$"select cor20_materialize_cycles('{a.Account}',64)",ct,tx)).ShouldBe(1);
        var pending=f.Observe(Scalar<int>(waiter,$"select cor20_materialize_cycles('{a.Account}',64)",ct));await SqlInterleavingBarrier.WaitForBlockedAsync(observer,waiter.ProcessID,owner.ProcessID,pending,ct);await tx.CommitAsync(ct);(await pending).ShouldBe(0);
        var version=await Scalar<long>(observer,"select version from entitlement_grants",ct);var before=await Projection(observer,a,ct);
        (await Scalar<bool>(owner,Revoke(a,version),ct)).ShouldBeTrue();var after=await Projection(waiter,a,ct);after.Version.ShouldBeGreaterThan(before.Version);after.Features.ShouldBe(treehammock.RiggingSupport.Enum.FeatureSet.basic);
        (await Scalar<int>(observer,$"select cor20_materialize_cycles('{a.Account}',64)",ct)).ShouldBe(0);
    });}
    [Fact]
    public async Task Cycle_allowance_and_authorized_end_bound_even_a_late_batch()
    {await SqlContractFixture.RunAsync(async(f,ct)=>{var c=await f.OpenConnectionAsync();var a=await Seed(c,ct);await Gate(c,true,ct);await Clock(c,"2040-03-31T12:34:56Z",ct);
        (await Scalar<int>(c,"select renewed_cycles from cor20_renew_batch(1)",ct)).ShouldBe(1);(await Scalar<int>(c,"select renewed_cycles from cor20_renew_batch(1)",ct)).ShouldBe(1);(await Scalar<int>(c,"select renewed_cycles from cor20_renew_batch(64)",ct)).ShouldBe(0);
        await Clock(c,"2040-04-30T12:34:56Z",ct);var expired=await Projection(c,a,ct);expired.Grants.Single().Cycle.ShouldBe(0);expired.Features.ShouldBe(treehammock.RiggingSupport.Enum.FeatureSet.basic);
    });}
    [Theory,InlineData(6,1,3),InlineData(11,0,1)]
    public async Task Approved_end_clips_calendar_total_and_is_exclusive(int term,int cadence,int cycles)
    {await SqlContractFixture.RunAsync(async(f,ct)=>{var c=await f.OpenConnectionAsync();var a=await Seed(c,ct,(short)term,(short)cadence,cycles,authorizedEnd:"2040-02-15T00:00:00Z");await Gate(c,true,ct);
        var p=await Projection(c,a,ct);p.EligibilityUntil.ShouldBe(NodaTime.Text.InstantPattern.ExtendedIso.Parse("2040-02-15T00:00:00Z").Value);
        await Clock(c,"2040-02-15T00:00:00Z",ct);(await Projection(c,a,ct)).Grants.Single().Cycle.ShouldBe(0);
        (await Scalar<int>(c,$"select cor20_materialize_cycles('{a.Account}',64)",ct)).ShouldBe(0);
    });}
    [Fact]
    public async Task Pending_approval_and_modified_issued_contract_never_grant_rights()
    {await SqlContractFixture.RunAsync(async(f,ct)=>{var c=await f.OpenConnectionAsync();var pending=await Seed(c,ct,activate:false);await Gate(c,true,ct);
        (await Projection(c,pending,ct)).Features.ShouldBe(treehammock.RiggingSupport.Enum.FeatureSet.basic);
        var active=await Seed(c,ct);await Exec(c,$"update entitlement_grants set max_cycles=4 where grant_id='{active.Grant}'",ct);
        (await Projection(c,active,ct)).Grants.Single().Cycle.ShouldBe(0);
    });}
    [Fact]
    public async Task Renewal_audit_failure_rolls_back_cycle_version_and_compatibility_projection()
    {await SqlContractFixture.RunAsync(async(f,ct)=>{var c=await f.OpenConnectionAsync();var a=await Seed(c,ct);await Gate(c,true,ct);await Clock(c,"2040-03-01T00:00:00Z",ct);var before=await Projection(c,a,ct);
        await Exec(c,"create function skip_cor20_renewed_audit() returns trigger language plpgsql as $$ begin if new.action='renewed' then return null;end if;return new;end $$;create trigger skip_cor20_renewed_audit before insert on entitlement_grant_audit for each row execute function skip_cor20_renewed_audit()",ct);
        await Should.ThrowAsync<PostgresException>(()=>Scalar<int>(c,$"select cor20_materialize_cycles('{a.Account}',64)",ct));
        var after=await Projection(c,a,ct);after.Version.ShouldBe(before.Version);after.Grants.Single().GrantVersion.ShouldBe(before.Grants.Single().GrantVersion);
        (await Scalar<long>(c,"select count(*) from entitlement_grant_cycles",ct)).ShouldBe(1);
        (await Scalar<long>(c,"select count(*) from entitlement_grant_audit where action='renewed'",ct)).ShouldBe(0);
    });}
    [Fact]
    public async Task Account_cutoff_removes_grant_rights_and_capabilities_at_its_boundary()
    {await SqlContractFixture.RunAsync(async(f,ct)=>{var c=await f.OpenConnectionAsync();var a=await Seed(c,ct);await Gate(c,true,ct);
        await Exec(c,$"update accounts set cut_off='2040-02-01T00:00:00Z' where account_id='{a.Account}'",ct);var before=await Projection(c,a,ct);
        before.NextBoundary.ShouldBe(NodaTime.Text.InstantPattern.ExtendedIso.Parse("2040-02-01T00:00:00Z").Value);
        await Clock(c,"2040-02-01T00:00:00Z",ct);var after=await Projection(c,a,ct);after.Capabilities.ShouldBeEmpty();after.Features.ShouldBe(treehammock.RiggingSupport.Enum.FeatureSet.basic);
        after.Version.ShouldBeGreaterThan(before.Version);
    });}
    [Fact]
    public async Task Actual_refresh_output_uses_projection_after_paid_expiry_without_extending_family()
    {await SqlContractFixture.RunAsync(async(f,ct)=>{var c=await f.OpenConnectionAsync();var a=await Seed(c,ct);await Gate(c,true,ct);var paid=await Projection(c,a,ct);
        await Clock(c,"2040-04-30T12:34:56Z",ct);await using var command=new NpgsqlCommand($"select * from refresh_session('{a.Account}','{a.Stamp}','{a.Family}',1,'{a.Session}',(select refresh_credential_hash from sessions where access_token_hash='{a.Session}'),'new-access',decode(repeat('01',64),'hex'),'{Guid.NewGuid()}',900,0)",c);
        await using var reader=await command.ExecuteReaderAsync(ct);(await reader.ReadAsync(ct)).ShouldBeTrue();reader.GetBoolean(0).ShouldBeTrue();var p=EntitlementProjection.Parse(reader.GetString(5),a.Account);p.Features.ShouldBe(treehammock.RiggingSupport.Enum.FeatureSet.basic);p.Version.ShouldBeGreaterThan(paid.Version);
    });}

}
