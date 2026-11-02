using Npgsql;
namespace treehammock.Tests.SqlContracts.Support;

// Owned SQL-boundary fixture: grants below represent completed password/factor attestation.
// The COR08 service/native suites separately exercise password and existing-factor proof.
public static class Cor16EnrollmentSql
{
    public sealed record Grant(string Session,string Token,string Target);
    public static async Task<Grant> SeedGrant(NpgsqlConnection c,Guid account,Guid stamp,int purpose,CancellationToken ct,
        string? token=null,string? session=null,bool factorComplete=true)
    {
        var g=new Grant(session ?? "cor16-session-"+account.ToString("N"),token ?? Guid.NewGuid().ToString("N")+Guid.NewGuid().ToString("N"),new string('a',64));
        await using var cmd=new NpgsqlCommand("""
            update accounts set verify_status=1 where account_id=@account;
            insert into sessions(access_token_hash,account_id,created_on,access_expiration,session_expiration,account_security_stamp)
            values(@session,@account,clock_timestamp(),clock_timestamp()+interval '2 hours',clock_timestamp()+interval '3 hours',@stamp)
            on conflict(access_token_hash) do nothing;
            insert into sensitive_action_proof_sessions(proof_id,handle_hash,account_id,credential_stamp,session_hash,family_id,purpose,target_hash,factor_policy,factor_required,factor_complete,expiration,state)
            select gen_random_uuid(),@token,a.account_id,@stamp,@session,s.session_id,@purpose,@target,cor08_factor_policy(a.account_id),
                exists(select 1 from two_factor_authentications t where t.account_id=@account and t.verified and t.revoked_at is null),@complete,clock_timestamp()+interval '1 hour','Granted'
            from accounts a join sessions s using(account_id) where a.account_id=@account and s.access_token_hash=@session;
            insert into sensitive_action_grants(token_hash,proof_id,account_id,credential_stamp,session_hash,family_id,purpose,target_hash,factor_policy,policy_version,expiration)
            select @token,proof_id,account_id,credential_stamp,session_hash,family_id,purpose,target_hash,factor_policy,1,expiration from sensitive_action_proof_sessions where handle_hash=@token;
            """,c);
        cmd.Parameters.AddWithValue("account",account);cmd.Parameters.AddWithValue("stamp",stamp);cmd.Parameters.AddWithValue("session",g.Session);
        cmd.Parameters.AddWithValue("token",g.Token);cmd.Parameters.AddWithValue("target",g.Target);cmd.Parameters.AddWithValue("purpose",(short)purpose);cmd.Parameters.AddWithValue("complete",factorComplete);
        await cmd.ExecuteNonQueryAsync(ct);return g;
    }
    public static string Begin(Guid account,Guid stamp,int method,string proof,Guid request,Grant g,Guid? expected=null,long? version=null)
        => $"select result,code from cor16_begin_twofactor_setup('{account}','{stamp}',{method}::smallint,'{proof}',clock_timestamp(),clock_timestamp()+interval '20 minutes',(select email_address from accounts where account_id='{account}'),'5555550101','1',null,true,'{request}',{(expected is null?"null::uuid":"'"+expected+"'::uuid")},{(version is null?"null::bigint":version+"::bigint")},'{g.Session}','{g.Token}','{g.Target}')";
    public static string Verify(Guid account,Guid stamp,int method,string proof,Guid request,long version=1,string? family=null,int limit=5)
        => $"select result,code,attempts from verify_twofactor_setup('{account}','{stamp}',{method}::smallint,'{proof}',{limit},clock_timestamp(),'{request}',{version}::bigint,{family ?? $"(select setup_family_id from two_factor_authentications where account_id='{account}' and setup_request_id='{request}')"})";
    public static async Task PublishFixture(NpgsqlConnection c,Guid account,Guid stamp,int method,string hash,Guid request,CancellationToken ct)
    {
        await using var cmd=new NpgsqlCommand("""
            insert into delivery_candidates(delivery_id,account_id,account_stamp,purpose,proof_hash,expires_at,metadata_json,predecessor,state,terminal_at)
            values(@request,@account,@stamp,@purpose,@hash,clock_timestamp()+interval '1 hour','{}','fixture','published',clock_timestamp())
            on conflict(delivery_id) do update set proof_hash=excluded.proof_hash,state='published';
            """,c);cmd.Parameters.AddWithValue("request",request);cmd.Parameters.AddWithValue("account",account);cmd.Parameters.AddWithValue("stamp",stamp);
        cmd.Parameters.AddWithValue("purpose","factor-"+method);cmd.Parameters.AddWithValue("hash",hash);await cmd.ExecuteNonQueryAsync(ct);
    }
}
