using Npgsql;
namespace treehammock.Tests.SqlContracts.Support;

// Explicit legacy-domain fixture: substitutes completed attestation and provider publication.
// COR18 suites separately use the production outbox and repository proof boundary.
public static class Cor18DeleteSql
{
    public static async Task Install(NpgsqlConnection c,CancellationToken ct=default)
    {
        await using var cmd=new NpgsqlCommand("""
            create or replace function cor18_fixture_request_delete(p_account uuid,p_stamp uuid,p_passphrase text,p_hash text,p_expires timestamptz,p_cooldown interval,p_window interval,p_max smallint)
            returns table(result boolean,code text,email_address text,workflow smallint) language plpgsql as $$
            declare g text:=encode(digest(gen_random_uuid()::text,'sha256'),'hex'); session_hash text:='cor18-fixture-'||p_account; request uuid:=gen_random_uuid(); answer record;
            begin
                if not exists(select 1 from accounts a where a.account_id=p_account and a.security_stamp=p_stamp) then return query select false,'ACCOUNT_SECURITY_STAMP_MISMATCH'::text,null::text,0::smallint;return;end if;
                insert into sessions(access_token_hash,account_id,created_on,access_expiration,session_expiration,account_security_stamp)
                values(session_hash,p_account,clock_timestamp(),clock_timestamp()+interval '2 hours',clock_timestamp()+interval '3 hours',p_stamp) on conflict(access_token_hash) do nothing;
                insert into sensitive_action_proof_sessions(proof_id,handle_hash,account_id,credential_stamp,session_hash,family_id,purpose,target_hash,factor_policy,factor_required,factor_complete,expiration,state)
                select gen_random_uuid(),g,p_account,p_stamp,session_hash,s.session_id,6,repeat('a',64),cor08_factor_policy(p_account),exists(select 1 from two_factor_authentications t where t.account_id=p_account and t.verified and t.revoked_at is null),true,clock_timestamp()+interval '1 hour','Granted'
                from sessions s where s.account_id=p_account and s.access_token_hash=session_hash;
                insert into sensitive_action_grants(token_hash,proof_id,account_id,credential_stamp,session_hash,family_id,purpose,target_hash,factor_policy,policy_version,expiration)
                select g,proof_id,account_id,credential_stamp,session_hash,family_id,purpose,target_hash,factor_policy,1,expiration from sensitive_action_proof_sessions where handle_hash=g;
                select * into answer from cor18_admit_delete(p_account,p_stamp,request,p_hash,p_expires,p_cooldown,p_window,p_max,session_hash,g,repeat('a',64));
                if not answer.result then return query select answer.result::boolean,answer.code::text,answer.email_address::text,answer.workflow::smallint;return;end if;
                select * into answer from cor18_stage_delete(p_account,p_stamp,request,p_hash,p_expires,p_passphrase);
                if answer.result then
                    insert into delivery_candidates(delivery_id,account_id,account_stamp,purpose,proof_hash,expires_at,metadata_json,predecessor,state,terminal_at)
                    values(request,p_account,p_stamp,'delete',p_hash,p_expires,jsonb_build_object('admissionId',request)::text,'fixture','published',clock_timestamp());
                end if;
                return query select answer.result::boolean,answer.code::text,(select a.email_address from accounts a where a.account_id=p_account),case when p_passphrase is null then 1::smallint else 2::smallint end;
            end;
            $$;
            """,c);await cmd.ExecuteNonQueryAsync(ct);
    }
    public static string Commit(string account,string stamp,string hash="delete-proof",bool satisfied=true,int limit=5)
        => $"select result,code from commit_account_delete_finalize({account},{stamp},'{hash}',{(satisfied?"true":"false")},{limit}::smallint,interval '1 minute',(select request_id from delete_standby where account_id={account}),(select pass_phrase_hash from delete_standby where account_id={account}), (select s.access_token_hash from sessions s join delete_standby d on d.origin_family=s.session_id where d.account_id={account}))";
}
