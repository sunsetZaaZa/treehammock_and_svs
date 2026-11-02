using Npgsql;

namespace treehammock.Tests.SqlContracts.Support;

// Calls the production transition function; overrides are candidate fields, never authority rows.
internal static class Cor13ResetSql
{
    internal static string Bootstrap(string account, string parent, string hash = "reset-authorization") => $"""
        select result from password_reset_requests r cross join lateral transition_pending_password_reset_session(
            '{hash}',r.password_reset_request_id,r.account_id,
            case r.delivery_channel when 'email' then 1 else 2 end::smallint,
            case when cardinality(cor13_reset_configurations(r.account_id,case r.delivery_channel when 'email' then 1 else 2 end::smallint))=0 then 2 else 3 end::smallint,
            cor13_reset_configurations(r.account_id,case r.delivery_channel when 'email' then 1 else 2 end::smallint),
            null::smallint,array[]::smallint[],array[]::smallint[],null::smallint,null::text,null::timestamptz,
            0,0,null::timestamptz,clock_timestamp(),r.expires_at,null::timestamptz,null::timestamptz,null::timestamptz,
            1::smallint,0::bigint,0::bigint,r.key_code_hash) q
            where r.password_reset_request_id='{parent}' and r.account_id='{account}'
        """;

    internal static string Transition(string hash, int operation, long version, long challenge, Dictionary<string,string>? changes = null)
    {
        string[] columns = ["reset_access_token_hash","password_reset_request_id","account_id","bootstrap_proof","state",
            "available_configurations","selected_two_factor_configuration","required_methods","completed_methods","current_expected_method",
            "challenge_code_hash","challenge_expiration","challenge_attempts","challenge_resends","next_challenge_allowed_at",
            "created_on","expires_at","selected_at","two_factor_completed_at","password_changed_at"];
        string args = string.Join(",", columns.Select(c => changes?.GetValueOrDefault(c) ?? "t."+c));
        return $"select q.result from pending_password_reset_sessions t cross join lateral transition_pending_password_reset_session({args},{operation}::smallint,{version}::bigint,{challenge}::bigint,null::text) q where t.reset_access_token_hash='{hash}'";
    }
    // These fixture helpers retain the versions returned by the actual transition.
    internal static Task<(long Session, long Challenge)> BootstrapStateAsync(NpgsqlConnection connection,
        string account, string parent, string hash, CancellationToken token)
        => ReadStateAsync(connection, Bootstrap(account,parent,hash).Replace("select result from password_reset_requests r",
            "select q.result,q.session_version,q.challenge_version from password_reset_requests r"), token);

    internal static Task<(long Session, long Challenge)> TransitionStateAsync(NpgsqlConnection connection,
        string hash, int operation, (long Session, long Challenge) expected, Dictionary<string,string> changes, CancellationToken token)
        => ReadStateAsync(connection, Transition(hash,operation,expected.Session,expected.Challenge,changes)
            .Replace("select q.result from", "select q.result,q.session_version,q.challenge_version from"), token);

    private static async Task<(long Session, long Challenge)> ReadStateAsync(NpgsqlConnection connection, string sql, CancellationToken token)
    {
        await using var command = new NpgsqlCommand(sql,connection);
        await using var reader = await command.ExecuteReaderAsync(token);
        if(!await reader.ReadAsync(token) || !reader.GetBoolean(0))
            throw new InvalidOperationException("The real reset fixture transition was denied.");
        return (reader.GetInt64(1),reader.GetInt64(2));
    }

    internal static Dictionary<string,string> Select(int configuration, string code = "challenge-one")
    {
        bool app = configuration == 3;
        string methods = configuration switch { 1=>"array[2]::smallint[]",3=>"array[3]::smallint[]",4=>"array[2,3]::smallint[]",_=>throw new ArgumentOutOfRangeException(nameof(configuration)) };
        return new() {
            ["state"]=app?"6::smallint":"4::smallint",["selected_two_factor_configuration"]=$"{configuration}::smallint",
            ["required_methods"]=methods,["completed_methods"]="array[]::smallint[]",["current_expected_method"]=app?"3::smallint":"2::smallint",
            ["challenge_code_hash"]=app?"null::text":$"'{code}'",["challenge_expiration"]=app?"null::timestamptz":"least(clock_timestamp()+interval '10 minutes',t.expires_at)",
            ["challenge_resends"]=app?"t.challenge_resends":"t.challenge_resends+1",
            ["next_challenge_allowed_at"]=app?"t.next_challenge_allowed_at":"clock_timestamp()",
            ["selected_at"]="clock_timestamp()",["two_factor_completed_at"]="null::timestamptz"
        };
    }
    internal static Dictionary<string,string> Valid(bool nextApp = false) => new() {
        ["state"]=nextApp?"6::smallint":"7::smallint",["completed_methods"]="array_append(t.completed_methods,t.current_expected_method)",
        ["current_expected_method"]=nextApp?"3::smallint":"null::smallint",["challenge_code_hash"]="null::text",["challenge_expiration"]="null::timestamptz",
        ["two_factor_completed_at"]=nextApp?"null::timestamptz":"clock_timestamp()"
    };
    internal static string Promote(string parent,string account,long version,long challenge,string hash="reset-authorization") => $"""
        select result from promote_password_reset('{parent}','{account}',decode(repeat('09',128),'hex'),decode(repeat('08',64),'hex'),
            decode(repeat('07',32),'hex'),decode(repeat('06',16),'hex'),gen_random_uuid(),clock_timestamp()-interval '100 years',
            '{hash}',{version}::bigint,{challenge}::bigint)
        """;
}
