using Npgsql;
using Shouldly;
using treehammock.Tests.SqlContracts.Support;

namespace treehammock.Tests.Integration.Database;

// Focused existing-feature regression. The schema-local issuer predicate is an explicit authority
// substitute, as in Cor19TrustedActivationTests; actual issuer ACL qualification remains separate.
[Trait("Suite", "SqlContracts")]
public sealed class Cor25ActivationApprovalBoundaryTests
{
    private sealed record Subject(Guid Account, Guid Stamp, Guid Family, Guid Grant, string Session)
    {
        public string Email => $"{Account:N}@example.test";
    }
    private static async Task<Subject> Seed(SqlContractFixture fixture, NpgsqlConnection connection, CancellationToken token)
    {
        var subject = new Subject(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid().ToString("N"));
        await fixture.ExecuteAsync(connection, $"insert into accounts(account_id,email_address,verify_status,security_stamp) values('{subject.Account}','{subject.Email}',1,'{subject.Stamp}');" +
            $"insert into sessions(access_token_hash,account_id,session_id,account_security_stamp,created_on,access_expiration,session_expiration) values('{subject.Session}','{subject.Account}','{subject.Family}','{subject.Stamp}',clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours');" +
            "create or replace function cor19_is_issuer(p_actor name) returns boolean language plpgsql stable as $$ begin return p_actor=current_user::name; end $$;", cancellation: token);
        return subject;
    }
    private static async Task<(bool Result, string Code)> Query(NpgsqlConnection connection, string sql, CancellationToken token)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        await using var reader = await command.ExecuteReaderAsync(token);
        (await reader.ReadAsync(token)).ShouldBeTrue();
        var result = (reader.GetBoolean(0), reader.GetString(1));
        (await reader.ReadAsync(token)).ShouldBeFalse();
        return result;
    }
    private static async Task<long> Count(NpgsqlConnection connection, string sql, CancellationToken token)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        return (long)(await command.ExecuteScalarAsync(token))!;
    }
    private static string Issue(Subject s, int term, int cadence) =>
        $"select result,code from cor19_issue_grant('{s.Grant}','{s.Account}','{s.Stamp}','treehammock-v1',2::smallint,{term}::smallint,{cadence}::smallint,null," +
        (term == 11 ? "null" : "clock_timestamp()+interval '2 years'") +
        $",{(cadence == 0 ? 1 : 3)},clock_timestamp()+interval '2 hours','boundary-approved-{s.Grant:N}','redemption',array[]::text[])";

    [Fact]
    public Task Issuer_rejects_retired_terms_and_cadences_without_grant_or_audit_and_keeps_valid_controls()
        => SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            var connection = await fixture.OpenConnectionAsync(token);
            var cases = Enumerable.Range(1, 11).Select(term => (Term: term, Cadence: 0, Allowed: term is not (4 or 5)))
                .Concat(Enumerable.Range(0, 11).Select(cadence => (Term: 6, Cadence: cadence, Allowed: cadence is 0 or 1)));
            foreach (var test in cases)
            {
                var subject = await Seed(fixture, connection, token);
                var result = await Query(connection, Issue(subject, test.Term, test.Cadence), token);
                result.Result.ShouldBe(test.Allowed);
                result.Code.ShouldBe(test.Allowed ? "ENTITLEMENT_GRANT_ISSUED" : "ENTITLEMENT_INVALID_APPROVAL");
                (await Count(connection, $"select count(*) from entitlement_grants where grant_id='{subject.Grant}'", token)).ShouldBe(test.Allowed ? 1L : 0L);
                (await Count(connection, $"select count(*) from entitlement_grant_audit where grant_id='{subject.Grant}'", token)).ShouldBe(test.Allowed ? 1L : 0L);
            }
        }, TestContext.Current.CancellationToken);

    [Fact]
    public Task Placement_rejects_retired_descriptors_without_request_then_accepts_exact_approved_descriptor()
        => SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            var connection = await fixture.OpenConnectionAsync(token);
            var s = await Seed(fixture, connection, token);
            (await Query(connection, Issue(s, 6, 0), token)).Result.ShouldBeTrue();
            string hash = new('a', 64);
            string Stage(int term, int cadence, string admission) =>
                $"select result,code from cor19_stage_activation('{Guid.NewGuid()}','{s.Account}','{s.Stamp}','{s.Session}','{s.Family}','{s.Grant}',1,'{hash}',clock_timestamp()+interval '10 minutes','{s.Email}',2::smallint,{term}::smallint,{cadence}::smallint,{admission})";
            var retired = new[] { (Term: 4, Cadence: 0), (Term: 5, Cadence: 0) }
                .Concat(Enumerable.Range(2, 9).Select(cadence => (Term: 6, Cadence: cadence)));
            foreach (var descriptor in retired)
            {
                var denied = await Query(connection, Stage(descriptor.Term, descriptor.Cadence, "null"), token);
                denied.Result.ShouldBeFalse(); denied.Code.ShouldBe("ACTIVATION_APPROVAL_MISMATCH");
                (await Count(connection, $"select count(*) from grant_activation_requests where grant_id='{s.Grant}'", token)).ShouldBe(0L);
            }
            var accepted = await Query(connection, Stage(6, 0, Cor21CreationSql.Admit(s.Account, s.Stamp, s.Session, s.Family, s.Grant, hash, s.Email, 2, 6, 0)), token);
            accepted.Result.ShouldBeTrue();
            (await Count(connection, $"select count(*) from grant_activation_requests where grant_id='{s.Grant}'", token)).ShouldBe(1L);
        }, TestContext.Current.CancellationToken);
}
