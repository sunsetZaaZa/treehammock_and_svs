using Npgsql;
namespace treehammock.Tests.SqlContracts.Support;

// Explicit trusted SQL-boundary substitution for already-attested grants and provider publication.
// COR17 outbox tests exercise the real atomic request/notification producer separately.
public static class Cor17EmailSql
{
    public static async Task Install(NpgsqlConnection c,CancellationToken ct=default)
    {
        await using var cmd=new NpgsqlCommand("""
            create or replace function cor17_fixture_request_email(p_account uuid,p_stamp uuid,p_email text,p_hash text,p_expires timestamptz)
            returns table(result boolean,code text,email_address text) language plpgsql as $$
            declare g text:=encode(digest(gen_random_uuid()::text,'sha256'),'hex'); session_hash text:='cor17-fixture-'||p_account; request uuid:=gen_random_uuid(); answer record;
            begin
                insert into sessions(access_token_hash,account_id,created_on,access_expiration,session_expiration,account_security_stamp)
                values(session_hash,p_account,clock_timestamp(),clock_timestamp()+interval '2 hours',clock_timestamp()+interval '3 hours',p_stamp)
                on conflict(access_token_hash) do nothing;
                insert into sensitive_action_proof_sessions(proof_id,handle_hash,account_id,credential_stamp,session_hash,family_id,purpose,target_hash,factor_policy,factor_required,factor_complete,expiration,state)
                select gen_random_uuid(),g,p_account,p_stamp,session_hash,s.session_id,5,repeat('a',64),cor08_factor_policy(p_account),exists(select 1 from two_factor_authentications t where t.account_id=p_account and t.verified and t.revoked_at is null),true,clock_timestamp()+interval '1 hour','Granted'
                from sessions s where s.account_id=p_account and s.access_token_hash=session_hash;
                insert into sensitive_action_grants(token_hash,proof_id,account_id,credential_stamp,session_hash,family_id,purpose,target_hash,factor_policy,policy_version,expiration)
                select g,proof_id,account_id,credential_stamp,session_hash,family_id,purpose,target_hash,factor_policy,1,expiration from sensitive_action_proof_sessions where handle_hash=g;
                select * into answer from cor17_authorized_request_email(p_account,p_stamp,p_email,p_hash,p_expires,request,session_hash,g,repeat('a',64),(select a.email_address from accounts a where a.account_id=p_account));
                if answer.result then
                    insert into delivery_candidates(delivery_id,account_id,account_stamp,purpose,proof_hash,expires_at,metadata_json,predecessor,state,terminal_at)
                    values(request,p_account,p_stamp,'email',p_hash,p_expires,'{}','fixture','published',clock_timestamp());
                end if;
                return query select answer.result::boolean,answer.code::text,answer.email_address::text;
            end;
            $$;
            """,c);await cmd.ExecuteNonQueryAsync(ct);
    }
}
