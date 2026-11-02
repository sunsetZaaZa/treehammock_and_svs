-- COR02: account first; lock all rows a mutation may touch before authorizing it.
-- Callers retain their public result contracts. No caller timestamp is an authority clock.
create or replace function cor02_lock_account_authority(p_id uuid, p_scope text)
returns boolean language plpgsql as $$
begin
    perform 1 from accounts a where a.account_id = p_id for update;
    if not found then return false; end if;
    if p_scope in ('registration', 'all') then
        perform 1 from account_verifications t where t.account_id = p_id order by t.verification_index for update;
    end if;
    if p_scope in ('email', 'all') then
        perform 1 from account_email_change_requests t where t.account_id = p_id for update;
    end if;
    if p_scope in ('delete', 'all') then
        perform 1 from delete_standby t where t.account_id = p_id for update;
    end if;
    if p_scope in ('unlock', 'all') then
        perform 1 from account_recoveries t where t.account_id = p_id order by t.token_hash for update;
    end if;
    if p_scope in ('reset', 'factor', 'all') then
        perform 1 from password_reset_requests t where t.account_id = p_id order by t.password_reset_request_id for update;
        perform 1 from pending_password_reset_sessions t where t.account_id = p_id order by t.reset_access_token_hash for update;
    end if;
    if p_scope in ('factor', 'email', 'reset', 'all') then
        perform 1 from two_factor_authentications t where t.account_id = p_id order by t.two_factor_index for update;
    end if;
    if p_scope in ('factor', 'email', 'reset', 'all') then
        perform 1 from sessions t where t.account_id = p_id order by t.access_token_hash for update;
        perform 1 from pending_two_factor_sessions t where t.account_id = p_id order by t.pre_auth_access_token_hash for update;
    end if;
    if p_scope in ('activation', 'all') then
        perform 1 from entitlement_grants t where t.account_id=p_id order by t.grant_id for update;
        perform 1 from grant_activation_requests t where t.account_id=p_id order by t.request_id for update;
        perform 1 from activations t where t.account_id = p_id order by t.activation_id for update;
    end if;
    return true;
end;
$$;

-- A late check covers waits in unique indexes, cascades and audit inserts too.
-- Raising inside the function's exception block rolls back its entire mutation,
-- including success audits, before the named expired result is returned.
create or replace function cor02_require_live(p_expiration timestamp with time zone)
returns void language plpgsql as $$
begin
    if not cor02_expiration_is_live(p_expiration, clock_timestamp()) then
        raise exception using errcode = 'P0202', message = 'COR02 authority expired';
    end if;
end;
$$;

create or replace function cor02_expiration_is_live(p_expiration timestamp with time zone, p_authority timestamp with time zone)
returns boolean language sql immutable as $$
    select coalesce(p_expiration > p_authority, false);
$$;

create or replace function start_verify_account(
    p_accountGuid uuid,
    p_verificationIndex bigint)
returns table(result boolean)
language plpgsql
as $$
begin
    perform cor02_lock_account_authority(p_accountGuid, 'registration');
    update account_verifications
       set verify_status = 2,
           sent_when = clock_timestamp()
     where account_id = p_accountGuid
       and verification_index = p_verificationIndex
       and verify_status = 0
       and account_security_stamp = (select security_stamp from accounts where account_id = p_accountGuid)
       and exists (select 1 from accounts where account_id = p_accountGuid and verify_status = 0);

    if not found then
        return query select false;
        return;
    end if;

    update accounts
       set verify_status = 2
     where account_id = p_accountGuid;

    return query select true;
end;
$$;

create or replace function resend_verify_account(
    p_emailAddress text,
    p_verifyKeyHash text,
    p_verificationExpiration interval)
returns table(result boolean, code text, email_address text)
language plpgsql
as $$
declare
    v_account_id uuid;
    v_email_address text;
begin
    select a.account_id, a.email_address
      into v_account_id, v_email_address
      from accounts a
     where lower(a.email_address) = lower(p_emailAddress)
     limit 1;

    if not found then
        return query select true, 'VERIFICATION_RESEND_NOT_APPLICABLE', null::text;
        return;
    end if;

    perform cor02_lock_account_authority(v_account_id, 'registration');
    select a.email_address into v_email_address from accounts a
     where a.account_id = v_account_id and lower(a.email_address) = lower(p_emailAddress);
    if not found then
        return query select true, 'VERIFICATION_RESEND_NOT_APPLICABLE', null::text; return;
    end if;
    if exists (
        select 1
          from accounts a
         where a.account_id = v_account_id
           and a.verify_status = 1) then
        return query select true, 'VERIFICATION_ALREADY_COMPLETE', null::text;
        return;
    end if;

    update account_verifications
       set verify_status = 6
     where account_id = v_account_id
       and verify_status in (0, 2, 4);

    insert into account_verifications(account_id, verify_key_hash, verify_status, sent_when, expiration, account_security_stamp)
    select v_account_id, p_verifyKeyHash, 4, clock_timestamp(), greatest(coalesce(p_verificationExpiration, interval '1 day'), interval '1 minute'), a.security_stamp
      from accounts a where a.account_id = v_account_id;

    update accounts
       set verify_status = 4
     where account_id = v_account_id
       and verify_status <> 1;

    return query select true, 'VERIFICATION_RESEND_STARTED', v_email_address;
end;
$$;

create or replace function complete_verify_account(
    p_accountId uuid,
    p_verifyKeyHash text,
    p_proofVersion uuid,
    p_accountSecurityStamp uuid)
returns table(result boolean)
language plpgsql
as $$
declare
    proof account_verifications%rowtype;
begin
    perform cor02_lock_account_authority(p_accountId, 'registration');
    select t.* into proof from account_verifications t
     join accounts a on a.account_id = t.account_id
     where t.account_id = p_accountId and t.verify_key_hash = p_verifyKeyHash
       and t.proof_version = p_proofVersion
       and t.account_security_stamp = p_accountSecurityStamp
       and a.security_stamp = p_accountSecurityStamp
       and a.verify_status in (2, 4) and t.verify_status in (2, 4);
    if not found or proof.sent_when is null or proof.expiration is null then
        return query select false; return;
    end if;
    if proof.sent_when + proof.expiration <= clock_timestamp() then
        return query select false; return;
    end if;
    update account_verifications t set verify_status = 1, sent_when = null, expiration = null
     where t.verification_index = proof.verification_index and t.proof_version = p_proofVersion
       and t.verify_status in (2, 4);
    if not found then return query select false; return; end if;
    update accounts a set verify_status = 1, login_failures = 0
     where a.account_id = p_accountId and a.security_stamp = p_accountSecurityStamp;
    perform cor02_require_live(proof.sent_when + proof.expiration);
    return query select true;
exception
    when sqlstate 'P0202' then return query select false;
end;
$$;

create or replace function expire_verify_account(
    p_accountId uuid,
    p_verifyKeyHash text,
    p_proofVersion uuid,
    p_accountSecurityStamp uuid)
returns table(result boolean)
language plpgsql
as $$
declare
    proof account_verifications%rowtype;
begin
    perform cor02_lock_account_authority(p_accountId, 'registration');
    select t.* into proof from account_verifications t
     join accounts a on a.account_id = t.account_id
     where t.account_id = p_accountId and t.verify_key_hash = p_verifyKeyHash
       and t.proof_version = p_proofVersion
       and t.account_security_stamp = p_accountSecurityStamp
       and a.security_stamp = p_accountSecurityStamp
       and a.verify_status in (2, 4) and t.verify_status in (2, 4);
    if not found or proof.sent_when is null or proof.expiration is null then
        return query select false; return;
    end if;
    -- A host clock or an old/replaced proof cannot expire the current identity.
    if proof.sent_when + proof.expiration > clock_timestamp() then
        return query select false; return;
    end if;
    update account_verifications t set verify_status = 3
     where t.verification_index = proof.verification_index and t.proof_version = p_proofVersion
       and t.verify_status in (2, 4);
    if not found then return query select false; return; end if;
    update accounts a set verify_status = 3
     where a.account_id = p_accountId and a.security_stamp = p_accountSecurityStamp;
    return query select true;
end;
$$;

create or replace function request_account_email_change(p_accountId uuid,p_accountSecurityStamp uuid,p_newEmailAddress text,p_verifyKeyHash text,p_expiration timestamptz)
returns table(result boolean,code text,email_address text) language plpgsql as $$
begin return query select false,'SENSITIVE_ACTION_GRANT_REQUIRED'::text,null::text;end;
$$;

create or replace function cancel_account_email_change_request(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_verifyKeyHash text)
returns table(result boolean, code text, email_address text)
language plpgsql
as $$
declare
    account_record accounts%rowtype;
    request_record account_email_change_requests%rowtype;
begin
    perform cor17_email_gate();
    perform cor02_lock_account_authority(p_accountId, 'email');
    select a.*
      into account_record
      from accounts a
     where a.account_id = p_accountId;

    if not found then
        return query select false, 'ACCOUNT_NOT_FOUND'::text, null::text;
        return;
    end if;

    if account_record.security_stamp is distinct from p_accountSecurityStamp then
        return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text, null::text;
        return;
    end if;

    select *
      into request_record
      from account_email_change_requests
     where account_id = p_accountId
       and account_security_stamp = p_accountSecurityStamp
       and verify_key_hash = p_verifyKeyHash
     for update;

    if not found then
        return query select false, 'ACCOUNT_ADJUST_TOKEN_MISMATCH'::text, null::text;
        return;
    end if;

    perform cor17_retire_email_request(p_accountId,p_verifyKeyHash);

    return query select true, 'ACCOUNT_ADJUST_EMAIL_CHANGE_CANCELLED'::text, request_record.new_email_address;
exception
    when others then
        return query select false, 'ACCOUNT_ADJUST_EMAIL_CHANGE_CLEANUP_FAILED'::text, null::text;
end;
$$;

create or replace function complete_account_email_change(p_verifyKeyHash text)
returns table(result boolean,code text,account_security_stamp uuid) language plpgsql as $$
declare req account_email_change_requests%rowtype; owner uuid; new_stamp uuid:=gen_random_uuid(); changed integer; family_access timestamptz; family_hard timestamptz; family_cutoff timestamptz; constraint_value text; revocation record;
begin
    perform cor17_email_gate();
    select r.account_id into owner from account_email_change_requests r where r.verify_key_hash=p_verifyKeyHash;
    if not found then return query select false,'ACCOUNT_ADJUST_TOKEN_MISMATCH'::text,null::uuid;return;end if;
    perform cor12_lock_delivery(owner);
    select * into req from account_email_change_requests r where r.account_id=owner and r.verify_key_hash=p_verifyKeyHash for update;
    if not found then return query select false,'ACCOUNT_ADJUST_TOKEN_MISMATCH'::text,null::uuid;return;end if;
    if req.expiration<=clock_timestamp() or req.authorized_until<=clock_timestamp() then
        perform cor17_retire_email_request(owner,req.verify_key_hash);return query select false,'ACCOUNT_ADJUST_TOKEN_EXPIRED'::text,null::uuid;return;
    end if;
    if not cor17_email_live(req) then
        perform cor17_retire_email_request(owner,req.verify_key_hash);return query select false,'ACCOUNT_ADJUST_AUTHORITY_CHANGED'::text,null::uuid;return;
    end if;
    if not exists(select 1 from delivery_candidates c where c.delivery_id=req.request_id and c.account_id=owner and c.proof_hash=p_verifyKeyHash and c.purpose='email' and c.state='published') then
        return query select false,'ACCOUNT_ADJUST_DELIVERY_PENDING'::text,null::uuid;return;
    end if;
    if exists(select 1 from accounts a where lower(a.email_address)=lower(req.new_email_address) and a.account_id<>owner) then
        perform cor17_retire_email_request(owner,req.verify_key_hash);return query select false,'ACCOUNT_ADJUST_DUPLICATE_EMAIL'::text,null::uuid;return;
    end if;
    select s.access_expiration,s.session_expiration,s.cut_off into family_access,family_hard,family_cutoff from sessions s where s.account_id=owner and s.session_id=req.origin_family for update;
    update accounts a set email_address=req.new_email_address,security_stamp=new_stamp where a.account_id=owner and a.security_stamp=req.account_security_stamp and lower(a.email_address)=lower(req.origin_email);
    get diagnostics changed=row_count;if changed<>1 then raise exception 'Email update conflict' using errcode='P1701';end if;
    -- Pending setup authority and the verified email factor must not follow a new registered address.
    delete from two_factor_authentications where account_id=owner and ((method=1 and verified=true) or not verified);
    with remaining as (
        select t.method from two_factor_authentications t where t.account_id=owner and t.verified=true and t.revoked_at is null and (t.expiration is null or t.expiration>clock_timestamp())
        order by t.required desc,t.priority desc,t.two_factor_index
    ), remaining_summary as (
        select coalesce((select method from remaining limit 1),0)::smallint selected_method,nullif((select count(*) from remaining),0)::smallint usage_count
    )
    update accounts a set two_factor_auth_method=remaining_summary.selected_method,two_auth_usage=remaining_summary.usage_count from remaining_summary where a.account_id=owner and a.security_stamp=new_stamp;
    get diagnostics changed=row_count;if changed<>1 then raise exception 'Email summary conflict' using errcode='P1701';end if;
    update sessions set access_expiration=least(access_expiration,greatest(created_on,clock_timestamp())),session_expiration=least(session_expiration,greatest(created_on,clock_timestamp())),cut_off=clock_timestamp() where account_id=owner;
    select * into revocation from revoke_pending_password_reset_sessions_for_account(owner,clock_timestamp(),'ACCOUNT_EMAIL_CHANGED');
    if not coalesce(revocation.result,false) then raise exception 'Reset invalidation failed' using errcode='P1701';end if;
    update password_reset_requests set cancelled_at=coalesce(cancelled_at,clock_timestamp()) where account_id=owner and consumed_at is null;
    delete from pending_two_factor_sessions where account_id=owner;
    delete from sensitive_action_grants where account_id=owner;
    delete from sensitive_action_proof_sessions where account_id=owner;
    delete from sensitive_password_attempts where account_id=owner;
    delete from delete_standby where account_id=owner;
    -- Notice jobs are immutable trusted-address notifications and survive credential rotation.
    update delivery_candidates c set state='superseded',terminal_at=clock_timestamp() where c.account_id=owner and c.state='staged' and c.purpose<>'email-notice';
    update delivery_outbox o set state='superseded',nonce=null,ciphertext=null,tag=null,lease_id=null,lease_until=null from delivery_candidates c where o.delivery_id=c.delivery_id and c.account_id=owner and c.state='superseded';
    delete from account_email_change_requests r where r.account_id=owner and r.request_id=req.request_id and r.verify_key_hash=p_verifyKeyHash;
    get diagnostics changed=row_count;if changed<>1 then raise exception 'Email consumption conflict' using errcode='P1701';end if;
    perform cor02_require_live(req.expiration);perform cor02_require_live(req.authorized_until);
    perform cor02_require_live(family_access);perform cor02_require_live(family_hard);
    if family_cutoff is not null then perform cor02_require_live(family_cutoff);end if;
    return query select true,'ACCOUNT_ADJUST_SUCCEEDED'::text,new_stamp;
exception
    when sqlstate 'P1701' then return query select false,'ACCOUNT_ADJUST_CONFLICT'::text,null::uuid;
    when sqlstate 'P0202' then return query select false,'ACCOUNT_ADJUST_TOKEN_EXPIRED'::text,null::uuid;
    when unique_violation then
        get stacked diagnostics constraint_value=constraint_name;
        if constraint_value='ux_accounts_email_address_lower' then return query select false,'ACCOUNT_ADJUST_DUPLICATE_EMAIL'::text,null::uuid;else raise;end if;
end;
$$;

create or replace function purge_expired_account_email_change_requests(p_now timestamptz default now())
returns table(result boolean,code text,deleted_count integer) language plpgsql as $$
declare affected integer;
begin perform cor17_email_gate();affected:=cor17_purge_email_requests();return query select true,'ACCOUNT_ADJUST_PURGE_SUCCEEDED'::text,affected;end;
$$;

create or replace function request_account_delete(p_accountId uuid,p_accountSecurityStamp uuid,p_passPhraseHash text,p_deleteTokenHash text,p_expiration timestamptz,p_requestCooldown interval,p_requestWindow interval,p_maxRequestsPerWindow smallint)
returns table(result boolean,code text,email_address text,workflow smallint) language plpgsql as $$
begin return query select false,'SENSITIVE_ACTION_GRANT_REQUIRED'::text,null::text,0::smallint;end;
$$;

create or replace function cancel_account_delete_request(p_accountId uuid,p_accountSecurityStamp uuid,p_deleteTokenHash text)
returns table(result boolean,code text,email_address text,workflow smallint) language plpgsql as $$
declare d delete_standby%rowtype; a accounts%rowtype;
begin
    perform cor12_lock_delivery(p_accountId);
    select * into a from accounts where accounts.account_id=p_accountId;
    if not found or a.security_stamp is distinct from p_accountSecurityStamp then return query select false,'ACCOUNT_SECURITY_STAMP_MISMATCH'::text,null::text,0::smallint;return;end if;
    select * into d from delete_standby q where q.account_id=p_accountId and q.delete_token_hash=p_deleteTokenHash for update;
    if not found then return query select false,'ACCOUNT_DELETE_TOKEN_MISMATCH'::text,null::text,0::smallint;return;end if;
    perform cor18_retire_delete(p_accountId,p_deleteTokenHash);
    insert into account_delete_events(account_id,event_type,code) values(p_accountId,'REQUEST_CANCELLED','ACCOUNT_DELETE_REQUEST_CANCELLED');
    return query select true,'ACCOUNT_DELETE_REQUEST_CANCELLED'::text,a.email_address,case when d.pass_phrase_hash is null then 1::smallint else 2::smallint end;
end;
$$;

create or replace function prepare_account_delete_finalize(p_accountId uuid,p_accountSecurityStamp uuid,p_deleteTokenHash text,p_maxFailedFinalizeAttempts smallint,p_finalizeLockout interval,p_sessionHash text)
returns table(result boolean,code text,account_id uuid,workflow smallint,pass_phrase_hash text,request_id uuid) language plpgsql as $$
declare d delete_standby%rowtype; answer text;
begin
    if not exists(select 1 from accounts a where a.account_id=p_accountId) then return query select false,'ACCOUNT_NOT_FOUND'::text,null::uuid,0::smallint,null::text,null::uuid;return;end if;
    -- Read-only snapshot: repository closes this connection before expensive verification.
    select * into d from delete_standby q where q.account_id=p_accountId and q.delete_token_hash=p_deleteTokenHash;
    answer:=cor18_finalize_denial(d,p_accountSecurityStamp,p_sessionHash,p_maxFailedFinalizeAttempts,p_finalizeLockout);
    if answer is not null then return query select false,answer,null::uuid,0::smallint,null::text,null::uuid;return;end if;
    return query select true,'ACCOUNT_DELETE_VERIFIED'::text,p_accountId,case when d.pass_phrase_hash is null then 1::smallint else 2::smallint end,d.pass_phrase_hash,d.request_id;
end;
$$;

create or replace function commit_account_delete_finalize(p_accountId uuid,p_accountSecurityStamp uuid,p_deleteTokenHash text,p_passPhraseSatisfied boolean,p_maxFailedFinalizeAttempts smallint,p_finalizeLockout interval,p_requestId uuid,p_expectedPassPhraseHash text,p_sessionHash text)
returns table(result boolean,code text,account_id uuid) language plpgsql as $$
declare d delete_standby%rowtype; answer text; affected integer; family_access timestamptz;family_hard timestamptz;family_cutoff timestamptz;account_cutoff timestamptz;
begin
    perform cor12_lock_delivery(p_accountId);
    if not exists(select 1 from accounts a where a.account_id=p_accountId and a.security_stamp=p_accountSecurityStamp) then return query select false,'ACCOUNT_SECURITY_STAMP_MISMATCH'::text,null::uuid;return;end if;
    select * into d from delete_standby q where q.account_id=p_accountId and q.delete_token_hash=p_deleteTokenHash for update;
    answer:=cor18_finalize_denial(d,p_accountSecurityStamp,p_sessionHash,p_maxFailedFinalizeAttempts,p_finalizeLockout);
    if answer is not null then return query select false,answer,null::uuid;return;end if;
    if d.request_id is distinct from p_requestId or d.pass_phrase_hash is distinct from p_expectedPassPhraseHash then return query select false,'ACCOUNT_DELETE_CONFLICT'::text,null::uuid;return;end if;
    update account_delete_budgets b set failed_finalize_attempts=0,finalize_locked_until=null where b.account_id=p_accountId and b.finalize_locked_until<=clock_timestamp();
    if d.pass_phrase_hash is not null and p_passPhraseSatisfied is distinct from true then
        update account_delete_budgets b set failed_finalize_attempts=least(b.failed_finalize_attempts+1,p_maxFailedFinalizeAttempts),
            finalize_locked_until=case when b.failed_finalize_attempts+1>=p_maxFailedFinalizeAttempts then clock_timestamp()+p_finalizeLockout else b.finalize_locked_until end where b.account_id=p_accountId;
        get diagnostics affected=row_count;if affected<>1 then raise exception 'Missing delete budget' using errcode='P1801';end if;
        answer:=case when (select b.finalize_locked_until>clock_timestamp() from account_delete_budgets b where b.account_id=p_accountId) then 'ACCOUNT_DELETE_ATTEMPT_LIMITED' else 'ACCOUNT_DELETE_TOKEN_MISMATCH' end;
        insert into account_delete_events(account_id,event_type,code) values(p_accountId,'FINALIZE_FAILED',answer);
        return query select false,answer,null::uuid;return;
    end if;
    select s.access_expiration,s.session_expiration,s.cut_off into family_access,family_hard,family_cutoff from sessions s where s.account_id=p_accountId and s.session_id=d.origin_family;
    select a.cut_off into account_cutoff from accounts a where a.account_id=p_accountId;
    delete from accounts a where a.account_id=p_accountId and a.security_stamp=d.origin_stamp and a.security_stamp=p_accountSecurityStamp and lower(a.email_address)=d.origin_email;
    get diagnostics affected=row_count;if affected<>1 then raise exception 'Delete affected no account' using errcode='P1801';end if;
    -- Audit is emitted only after an affected account and rolls back with cascades/receipt on expiry.
    insert into account_delete_events(account_id,event_type,code,request_id,credential_stamp) values(p_accountId,'COMPLETED','ACCOUNT_DELETE_SUCCEEDED',d.request_id,d.origin_stamp);
    get diagnostics affected=row_count;if affected<>1 then raise exception 'No delete audit effect' using errcode='P1801';end if;
    if least(d.expiration,d.authorized_until,family_access,family_hard,coalesce(family_cutoff,'infinity'::timestamptz),coalesce(account_cutoff,'infinity'::timestamptz))<=clock_timestamp() then raise exception 'Delete deadline elapsed' using errcode='P0202';end if;
    return query select true,'ACCOUNT_DELETE_SUCCEEDED'::text,p_accountId;
exception when sqlstate 'P1801' then return query select false,'ACCOUNT_DELETE_CONFLICT'::text,null::uuid;
    when sqlstate 'P0202' then return query select false,'ACCOUNT_DELETE_TOKEN_EXPIRED'::text,null::uuid;
end;
$$;

create or replace function begin_twofactor_setup(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_method smallint,
    p_tokenHash text,
    p_createdOn timestamp with time zone,
    p_expiration timestamp with time zone,
    p_emailAddress text,
    p_phoneNumber text,
    p_phoneCountryCode text,
    p_authId text,
    p_required boolean)
returns table(result boolean, code text, two_factor_index bigint, expiration timestamp with time zone)
language plpgsql
as $$
begin
    return query select false,'SENSITIVE_ACTION_GRANT_REQUIRED'::text,null::bigint,null::timestamptz;
end;
$$;

create or replace function cancel_twofactor_setup(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_method smallint,
    p_tokenHash text)
returns table(result boolean, code text)
language plpgsql
as $$
declare
    account_record accounts%rowtype;
    deleted_count integer;
begin
    perform cor02_lock_account_authority(p_accountId, 'factor');
    select a.*
      into account_record
      from accounts a
     where a.account_id = p_accountId;

    if not found then
        return query select false, 'ACCOUNT_NOT_FOUND'::text;
        return;
    end if;

    if account_record.security_stamp is distinct from p_accountSecurityStamp then
        return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text;
        return;
    end if;

    delete from two_factor_authentications
     where account_id = p_accountId
       and method = p_method
       and token = p_tokenHash
       and verified = false
       and revoked_at is null;

    get diagnostics deleted_count = row_count;

    return query select (deleted_count > 0),
        case when deleted_count > 0 then 'TWO_FACTOR_SETUP_CANCELLED' else 'TWO_FACTOR_SETUP_NOT_FOUND' end::text;
exception
    when others then
        return query select false, 'TWO_FACTOR_SETUP_CANCEL_FAILED'::text;
end;
$$;

create or replace function verify_twofactor_setup(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_method smallint,
    p_tokenHash text,
    p_maxAttempts integer,
    p_now timestamp with time zone,p_requestId uuid,p_requestVersion bigint,p_familyId uuid)
returns table(result boolean, code text, attempts smallint, expiration timestamp with time zone)
language plpgsql
as $$
declare pending two_factor_authentications%rowtype; changed integer; verified_count smallint; attempts smallint;
begin
    perform cor02_lock_account_authority(p_accountId,'factor');
    select * into pending from two_factor_authentications t where t.account_id=p_accountId and t.method=p_method and not t.verified and
        t.revoked_at is null and t.setup_request_id=p_requestId and t.setup_version=p_requestVersion for update;
    if not found then return query select false,'TWO_FACTOR_SETUP_CONFLICT'::text,0::smallint,null::timestamptz;return;end if;
    perform cor16_require_setup(pending,p_accountSecurityStamp,p_familyId);
    if p_method not in (1,2) or p_maxAttempts is null or p_maxAttempts not between 1 and 32767 or nullif(btrim(p_tokenHash),'') is null then
        return query select false,'TWO_FACTOR_SETUP_INVALID_TOKEN'::text,0::smallint,pending.expiration;return;end if;
    if not exists(select 1 from delivery_candidates c where c.delivery_id=p_requestId and c.account_id=p_accountId and c.proof_hash=pending.token and c.state='published') then
        return query select false,'TWO_FACTOR_SETUP_DELIVERY_PENDING'::text,pending.setup_attempts,pending.expiration;return;end if;
    if pending.setup_attempts>=p_maxAttempts then return query select false,'TWO_FACTOR_SETUP_ATTEMPT_LIMIT'::text,pending.setup_attempts,pending.expiration;return;end if;
    if pending.token is distinct from p_tokenHash then
        attempts:=pending.setup_attempts+1;
        update two_factor_authentications t set setup_attempts=attempts,token=case when attempts>=p_maxAttempts then null else t.token end
            where t.account_id=p_accountId and t.two_factor_index=pending.two_factor_index and t.setup_request_id=p_requestId and t.setup_version=p_requestVersion and not t.verified;
        get diagnostics changed=row_count;if changed<>1 then raise exception 'Setup attempt conflict' using errcode='P1601';end if;
        return query select false,case when attempts>=p_maxAttempts then 'TWO_FACTOR_SETUP_ATTEMPT_LIMIT' else 'TWO_FACTOR_SETUP_INCORRECT' end::text,attempts,pending.expiration;return;
    end if;
    if exists(select 1 from two_factor_authentications t where t.account_id=p_accountId and t.method=p_method and t.verified and t.revoked_at is null) then
        return query select false,'TWO_FACTOR_SETUP_DUPLICATE'::text,0::smallint,pending.expiration;return;end if;
    update two_factor_authentications t set verified=true,token=null,expiration=null,lifespan=null,setup_attempts=0,priority=greatest(t.priority,1)
        where t.account_id=p_accountId and t.two_factor_index=pending.two_factor_index and not t.verified and t.revoked_at is null and
            t.setup_request_id=p_requestId and t.setup_version=p_requestVersion and t.token=p_tokenHash;
    get diagnostics changed=row_count;if changed<>1 then raise exception 'Setup promotion conflict' using errcode='P1601';end if;
    select count(*)::smallint into verified_count from two_factor_authentications t where t.account_id=p_accountId and t.verified and t.revoked_at is null and (t.expiration is null or t.expiration>clock_timestamp());
    update accounts a set two_auth_usage=greatest(verified_count,1)::smallint,two_factor_auth_method=p_method where a.account_id=p_accountId and a.security_stamp=p_accountSecurityStamp;
    get diagnostics changed=row_count;if changed<>1 then raise exception 'Setup summary conflict' using errcode='P1601';end if;
    perform cor02_require_live(pending.expiration);perform cor02_require_live(pending.setup_authorized_until);
    if not exists(select 1 from sessions s where s.account_id=p_accountId and s.session_id=p_familyId and s.account_security_stamp=p_accountSecurityStamp and
        s.access_expiration>clock_timestamp() and s.session_expiration>clock_timestamp() and (s.cut_off is null or s.cut_off>clock_timestamp())) then raise exception 'Setup family expired' using errcode='P1601';end if;
    perform cor16_factor_changed(p_accountId);
    perform cor02_require_live(pending.expiration);perform cor02_require_live(pending.setup_authorized_until);
    return query select true,'TWO_FACTOR_SETUP_VERIFIED'::text,0::smallint,null::timestamptz;
exception
    when sqlstate 'P1601' then return query select false,'TWO_FACTOR_SETUP_AUTHORITY_CHANGED'::text,0::smallint,null::timestamptz;
    when sqlstate 'P0202' then return query select false,'TWO_FACTOR_SETUP_EXPIRED'::text,0::smallint,null::timestamptz;
    when unique_violation then return query select false,'TWO_FACTOR_SETUP_CONFLICT'::text,0::smallint,null::timestamptz;
end;
$$;

create or replace function remove_twofactor_method(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_method smallint,
    p_now timestamp with time zone default now())
returns table(
    result boolean,
    code text,
    removed_method smallint,
    two_factor_methods smallint[],
    available_configurations smallint[])
language plpgsql
as $$
declare
    account_record accounts%rowtype;
    moment timestamp with time zone;
    revoked_count integer := 0;
    remaining_methods smallint[] := array[]::smallint[];
    remaining_configurations smallint[] := array[]::smallint[];
    selected_method smallint := 0;
    usage_count smallint := null;
    reset_session_revoke_result boolean := true;
    reset_session_revoke_code text := null;
begin
    perform cor02_lock_account_authority(p_accountId, 'factor');
    moment := clock_timestamp();
    select *
      into account_record
      from accounts a
     where a.account_id = p_accountId
     for update;

    if not found then
        return query select false,
            'ACCOUNT_NOT_FOUND'::text,
            coalesce(p_method, 0)::smallint,
            array[]::smallint[],
            array[]::smallint[];
        return;
    end if;

    if account_record.security_stamp is distinct from p_accountSecurityStamp then
        return query select false,
            'ACCOUNT_SECURITY_STAMP_MISMATCH'::text,
            coalesce(p_method, 0)::smallint,
            array[]::smallint[],
            array[]::smallint[];
        return;
    end if;

    if p_method not in (1, 2, 3) then
        return query select false,
            'TWO_FACTOR_METHOD_REMOVE_UNSUPPORTED_METHOD'::text,
            coalesce(p_method, 0)::smallint,
            array[]::smallint[],
            array[]::smallint[];
        return;
    end if;

    update two_factor_authentications t
       set verified = false,
           revoked_at = moment,
           revoked_reason = 'user_removed',
           token = null,
           auth_id = null,
           expiration = moment,
           lifespan = case when t.created_on is null then t.lifespan else moment - t.created_on end,
           totp_secret_ciphertext = case when p_method = 3 then null else t.totp_secret_ciphertext end,
           totp_secret_nonce = case when p_method = 3 then null else t.totp_secret_nonce end,
           totp_secret_tag = case when p_method = 3 then null else t.totp_secret_tag end,
           totp_last_used_step = case when p_method = 3 then null else t.totp_last_used_step end,
           totp_provider_enrollment_id = case when p_method = 3 then null else t.totp_provider_enrollment_id end,
           totp_provider_account_binding_hash = case when p_method = 3 then null else t.totp_provider_account_binding_hash end
     where t.account_id = p_accountId
       and t.method = p_method
       and t.verified = true
       and t.revoked_at is null;

    get diagnostics revoked_count = row_count;

    delete from two_factor_authentications t
     where t.account_id = p_accountId
       and t.method = p_method
       and t.verified = false
       and t.revoked_at is null;

    if revoked_count = 0 then
        select coalesce(array_agg(method order by method), array[]::smallint[])
          into remaining_methods
          from (
              select distinct t.method::smallint as method
                from two_factor_authentications t
                join accounts a on a.account_id = t.account_id
               where t.account_id = p_accountId
                 and t.verified = true
                 and t.revoked_at is null
                 and (t.expiration is null or t.expiration > moment)
                 and (
                    (t.method = 1 and nullif(trim(a.email_address), '') is not null)
                    or (t.method = 2 and nullif(trim(t.phone_number), '') is not null)
                    or (
                        t.method = 3
                        and t.totp_provider_type = 1
                        and t.totp_secret_ciphertext is not null
                        and octet_length(t.totp_secret_ciphertext) > 0
                        and t.totp_secret_nonce is not null
                        and octet_length(t.totp_secret_nonce) > 0
                        and t.totp_secret_tag is not null
                        and octet_length(t.totp_secret_tag) > 0
                        and coalesce(t.totp_secret_version, 0) > 0
                    )
                 )
          ) usable;

        remaining_configurations := resolve_available_twofactor_configurations(p_accountId);
        return query select false,
            'TWO_FACTOR_METHOD_NOT_CONFIGURED'::text,
            p_method::smallint,
            coalesce(remaining_methods, array[]::smallint[]),
            coalesce(remaining_configurations, array[]::smallint[]);
        return;
    end if;

    delete from pending_two_factor_sessions p
     where p.account_id = p_accountId;

    select r.result, r.code
      into reset_session_revoke_result, reset_session_revoke_code
      from revoke_pending_password_reset_sessions_for_account(
        p_accountId,
        moment,
        'PASSWORD_RESET_SESSION_REVOKED_BY_TWO_FACTOR_METHOD_REMOVAL') r
     limit 1;

    if coalesce(reset_session_revoke_result, false) = false then
        return query select false,
            'TWO_FACTOR_METHOD_REMOVE_FAILED'::text,
            p_method::smallint,
            array[]::smallint[],
            array[]::smallint[];
        return;
    end if;

    select coalesce(array_agg(method order by method), array[]::smallint[])
      into remaining_methods
      from (
          select distinct t.method::smallint as method
            from two_factor_authentications t
            join accounts a on a.account_id = t.account_id
           where t.account_id = p_accountId
             and t.verified = true
             and t.revoked_at is null
             and (t.expiration is null or t.expiration > moment)
             and (
                (t.method = 1 and nullif(trim(a.email_address), '') is not null)
                or (t.method = 2 and nullif(trim(t.phone_number), '') is not null)
                or (
                    t.method = 3
                    and t.totp_provider_type = 1
                    and t.totp_secret_ciphertext is not null
                    and octet_length(t.totp_secret_ciphertext) > 0
                    and t.totp_secret_nonce is not null
                    and octet_length(t.totp_secret_nonce) > 0
                    and t.totp_secret_tag is not null
                    and octet_length(t.totp_secret_tag) > 0
                    and coalesce(t.totp_secret_version, 0) > 0
                )
             )
      ) usable;

    remaining_configurations := resolve_available_twofactor_configurations(p_accountId);
    usage_count := nullif(cardinality(coalesce(remaining_methods, array[]::smallint[])), 0)::smallint;
    selected_method := coalesce((select method_value from unnest(coalesce(remaining_methods, array[]::smallint[])) as remaining(method_value) order by method_value limit 1), 0)::smallint;

    update accounts a
       set two_factor_auth_method = selected_method,
           two_auth_usage = usage_count
     where a.account_id = p_accountId
       and a.security_stamp = p_accountSecurityStamp;

    return query select true,
        'TWO_FACTOR_METHOD_REMOVED'::text,
        p_method::smallint,
        coalesce(remaining_methods, array[]::smallint[]),
        coalesce(remaining_configurations, array[]::smallint[]);
exception
    when others then
        return query select false,
            'TWO_FACTOR_METHOD_REMOVE_FAILED'::text,
            coalesce(p_method, 0)::smallint,
            array[]::smallint[],
            array[]::smallint[];
end;
$$;

create or replace function begin_authenticator_app_setup(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_setupTokenHash text,
    p_createdOn timestamp with time zone,
    p_expiration timestamp with time zone,
    p_authId text,
    p_required boolean,
    p_totpProviderType smallint,
    p_totpSecretCiphertext bytea,
    p_totpSecretNonce bytea,
    p_totpSecretTag bytea,
    p_totpSecretVersion integer,
    p_totpKeyId text, p_totpEnrollmentId uuid, p_totpAlgorithm text, p_totpDigits integer, p_totpPeriodSeconds integer, p_totpClockSkewSteps integer,p_expectedRequestId uuid,p_expectedVersion bigint)
returns table(result boolean, code text, two_factor_index bigint, expiration timestamp with time zone)
language plpgsql
as $$
declare
    account_record accounts%rowtype;
    target_index bigint;
    provider_type smallint := coalesce(p_totpProviderType, 1)::smallint;
    moment timestamp with time zone;
begin
    perform cor02_lock_account_authority(p_accountId, 'factor');
    moment := clock_timestamp();
    select * into account_record from accounts where account_id = p_accountId for update;
    if not found then return query select false, 'ACCOUNT_NOT_FOUND'::text, null::bigint, null::timestamp with time zone; return; end if;
    if account_record.security_stamp is distinct from p_accountSecurityStamp then return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text, null::bigint, null::timestamp with time zone; return; end if;
    if account_record.verify_status <> 1 then return query select false, 'ACCOUNT_NOT_VERIFIED'::text, null::bigint, null::timestamp with time zone; return; end if;
    if account_record.cut_off is not null and account_record.cut_off <= moment then return query select false, 'ACCOUNT_CUT_OFF_EXPIRED'::text, null::bigint, null::timestamp with time zone; return; end if;
    if provider_type <> 1 then return query select false, 'AUTHENTICATOR_SETUP_UNSUPPORTED_PROVIDER'::text, null::bigint, null::timestamp with time zone; return; end if;
    if p_setupTokenHash is null or btrim(p_setupTokenHash) = '' then return query select false, 'AUTHENTICATOR_SETUP_INVALID_TOKEN'::text, null::bigint, null::timestamp with time zone; return; end if;
    if p_createdOn is null or p_expiration is null or p_expiration <= p_createdOn or p_expiration <= clock_timestamp() then return query select false, 'AUTHENTICATOR_SETUP_INVALID_EXPIRATION'::text, null::bigint, null::timestamp with time zone; return; end if;
    if p_totpSecretCiphertext is null or octet_length(p_totpSecretCiphertext) = 0 or p_totpSecretNonce is null or octet_length(p_totpSecretNonce) = 0 or p_totpSecretTag is null or octet_length(p_totpSecretTag) = 0 or coalesce(p_totpSecretVersion, 0) <> 2 or p_totpEnrollmentId is null or p_totpEnrollmentId='00000000-0000-0000-0000-000000000000'::uuid or p_totpKeyId is null or p_totpAlgorithm not in ('SHA1','SHA256','SHA512') or p_totpDigits not in (6,7,8) or p_totpPeriodSeconds not between 15 and 120 or p_totpClockSkewSteps not between 0 and 2 then return query select false, 'AUTHENTICATOR_SETUP_INVALID_SECRET'::text, null::bigint, null::timestamp with time zone; return; end if;
    if exists (select 1 from two_factor_authentications t where t.account_id = p_accountId and t.method = 3 and t.verified = true and t.revoked_at is null) then return query select false, 'TWO_FACTOR_AUTHENTICATOR_APP_ALREADY_ATTACHED'::text, null::bigint, null::timestamp with time zone; return; end if;

    select t.two_factor_index into target_index from two_factor_authentications t where t.account_id = p_accountId and t.verified = false and t.revoked_at is null order by t.created_on desc, t.two_factor_index desc limit 1 for update;
    if target_index is null then
        select (coalesce(max(t.two_factor_index), -1) + 1)::bigint into target_index from two_factor_authentications t where t.account_id = p_accountId;
        insert into two_factor_authentications(two_factor_index, account_id, token, auth_id, created_on, lifespan, expiration, method, verified, priority, country, email_address, phone_number, phone_country_code, required, totp_secret_ciphertext, totp_secret_nonce, totp_secret_tag, totp_secret_version, totp_key_id, totp_enrollment_id, totp_algorithm, totp_digits, totp_period_seconds, totp_clock_skew_steps, totp_last_used_step, totp_provider_type, totp_provider_enrollment_id, totp_provider_account_binding_hash, setup_attempts, revoked_at, revoked_reason)
        values(target_index, p_accountId, p_setupTokenHash, nullif(trim(p_authId), ''), p_createdOn, p_expiration - p_createdOn, p_expiration, 3, false, 0, null, null, null, null, coalesce(p_required, true), p_totpSecretCiphertext, p_totpSecretNonce, p_totpSecretTag, p_totpSecretVersion, p_totpKeyId, p_totpEnrollmentId, p_totpAlgorithm, p_totpDigits, p_totpPeriodSeconds, p_totpClockSkewSteps, null, provider_type, null, null, 0, null, null);
    else
        update two_factor_authentications set token = p_setupTokenHash, auth_id = nullif(trim(p_authId), ''), created_on = p_createdOn, lifespan = p_expiration - p_createdOn, expiration = p_expiration, method = 3, verified = false, priority = 0, country = null, email_address = null, phone_number = null, phone_country_code = null, required = coalesce(p_required, true), totp_secret_ciphertext = p_totpSecretCiphertext, totp_secret_nonce = p_totpSecretNonce, totp_secret_tag = p_totpSecretTag, totp_secret_version = p_totpSecretVersion, totp_key_id = p_totpKeyId, totp_enrollment_id = p_totpEnrollmentId, totp_algorithm = p_totpAlgorithm, totp_digits = p_totpDigits, totp_period_seconds = p_totpPeriodSeconds, totp_clock_skew_steps = p_totpClockSkewSteps, totp_last_used_step = null, totp_provider_type = provider_type, totp_provider_enrollment_id = null, totp_provider_account_binding_hash = null, setup_attempts = 0, revoked_at = null, revoked_reason = null where account_id = p_accountId and two_factor_index = target_index and verified = false and revoked_at is null;
    end if;
    delete from two_factor_authentications t where t.account_id = p_accountId and t.verified = false and t.revoked_at is null and t.two_factor_index <> target_index;
    perform cor02_require_live(p_expiration);
    return query select true, 'AUTHENTICATOR_SETUP_PENDING'::text, target_index, p_expiration;
exception
    when sqlstate 'P0202' then
        return query select false, 'AUTHENTICATOR_SETUP_INVALID_EXPIRATION'::text, null::bigint, null::timestamp with time zone;
 when unique_violation then
    return query select false, 'TWO_FACTOR_AUTHENTICATOR_APP_ALREADY_ATTACHED'::text, null::bigint, null::timestamp with time zone;
when others then
    return query select false, 'AUTHENTICATOR_SETUP_FAILED'::text, null::bigint, null::timestamp with time zone;
end;
$$;

create or replace function record_authenticator_app_setup_failure(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_setupTokenHash text,
    p_maxAttempts smallint,
    p_now timestamp with time zone)
returns table(result boolean, code text, attempts smallint, expiration timestamp with time zone)
language plpgsql
as $$
declare
    setup_record two_factor_authentications%rowtype;
    safe_max_attempts smallint := greatest(coalesce(p_maxAttempts, 1), 1)::smallint;
    next_attempts smallint;
    moment timestamp with time zone;
begin
    perform cor02_lock_account_authority(p_accountId, 'factor');
    moment := clock_timestamp();
    if not exists (select 1 from accounts a where a.account_id = p_accountId and a.security_stamp = p_accountSecurityStamp and a.verify_status = 1 and (a.cut_off is null or a.cut_off > moment)) then return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text, 0::smallint, null::timestamp with time zone; return; end if;
    select * into setup_record from two_factor_authentications t where t.account_id = p_accountId and t.method = 3 and t.verified = false and t.revoked_at is null and t.token = p_setupTokenHash order by t.created_on desc, t.two_factor_index desc limit 1 for update;
    if not found then return query select false, 'AUTHENTICATOR_SETUP_NOT_FOUND'::text, 0::smallint, null::timestamp with time zone; return; end if;
    perform cor16_require_setup(setup_record,p_accountSecurityStamp,setup_record.setup_family_id);
    if setup_record.expiration is not null and setup_record.expiration <= moment then
        update two_factor_authentications set token = null, expiration = moment, lifespan = moment - created_on, setup_attempts = safe_max_attempts, totp_secret_ciphertext = null, totp_secret_nonce = null, totp_secret_tag = null where account_id = p_accountId and two_factor_index = setup_record.two_factor_index;
        return query select false, 'AUTHENTICATOR_SETUP_EXPIRED'::text, safe_max_attempts, setup_record.expiration; return;
    end if;
    next_attempts := least(setup_record.setup_attempts + 1, safe_max_attempts)::smallint;
    update two_factor_authentications t
       set setup_attempts = next_attempts,
           token = case when next_attempts >= safe_max_attempts then null else t.token end,
           expiration = case when next_attempts >= safe_max_attempts then moment else t.expiration end,
           totp_secret_ciphertext = case when next_attempts >= safe_max_attempts then null else t.totp_secret_ciphertext end,
           totp_secret_nonce = case when next_attempts >= safe_max_attempts then null else t.totp_secret_nonce end,
           totp_secret_tag = case when next_attempts >= safe_max_attempts then null else t.totp_secret_tag end
     where t.account_id = p_accountId
       and t.two_factor_index = setup_record.two_factor_index;
    if next_attempts >= safe_max_attempts then return query select false, 'AUTHENTICATOR_SETUP_ATTEMPT_LIMIT'::text, next_attempts, moment; return; end if;
    return query select false, 'AUTHENTICATOR_SETUP_INCORRECT'::text, next_attempts, setup_record.expiration;
exception
    when sqlstate 'P1601' then return query select false,'AUTHENTICATOR_SETUP_AUTHORITY_CHANGED'::text,0::smallint,null::timestamptz;
    when sqlstate 'P0202' then return query select false,'AUTHENTICATOR_SETUP_EXPIRED'::text,0::smallint,null::timestamptz;
    when others then
    return query select false, 'AUTHENTICATOR_SETUP_FAILURE_RECORD_FAILED'::text, 0::smallint, null::timestamp with time zone;
end;
$$;

create or replace function complete_authenticator_app_setup_and_rotate_session(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_setupTokenHash text,
    p_timeStep bigint,
    p_expectedOldAccessTokenHash text,
    p_newAccessTokenHash text,
    p_refreshToken bytea,
    p_refreshes smallint,
    p_refreshLimit smallint,
    p_createdOn timestamp with time zone,
    p_sessionLifespan interval,
    p_accessExpiration timestamp with time zone,
    p_sessionExpiration timestamp with time zone,
    p_cutOff timestamp with time zone,
    p_features smallint,
    p_sessionSecurityStamp uuid)
returns table(result boolean, code text, account_security_stamp uuid, two_factor_index bigint)
language plpgsql
as $$
declare
    account_record accounts%rowtype;
    setup_record two_factor_authentications%rowtype;
    old_session sessions%rowtype;
    old_cutoff timestamp with time zone;
    new_cutoff timestamp with time zone;
    moment timestamp with time zone;
    new_account_stamp uuid := gen_random_uuid();
    verified_count smallint;changed integer;
begin
    perform cor02_lock_account_authority(p_accountId, 'factor');
    moment := clock_timestamp();
    if p_timeStep is null or p_timeStep < 0 then return query select false, 'TOTP_INVALID_TIME_STEP'::text, null::uuid, null::bigint; return; end if;
    if exists (select 1 from sessions where access_token_hash = p_newAccessTokenHash) then return query select false, 'NEW_SESSION_CONFLICT'::text, null::uuid, null::bigint; return; end if;
    if p_accessExpiration is null or p_sessionExpiration is null or p_accessExpiration <= moment or p_sessionExpiration <= moment or p_accessExpiration > p_sessionExpiration then return query select false, 'SESSION_EXPIRATION_INVALID'::text, null::uuid, null::bigint; return; end if;
    select * into account_record from accounts a where a.account_id = p_accountId and a.security_stamp = p_accountSecurityStamp for update;
    if not found then return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text, null::uuid, null::bigint; return; end if;
    if account_record.verify_status <> 1 then return query select false, 'ACCOUNT_NOT_VERIFIED'::text, null::uuid, null::bigint; return; end if;
    if account_record.cut_off is not null and account_record.cut_off <= moment then return query select false, 'ACCOUNT_CUT_OFF_EXPIRED'::text, null::uuid, null::bigint; return; end if;
    select * into old_session from sessions s where s.account_id = p_accountId and s.access_token_hash = p_expectedOldAccessTokenHash and s.account_security_stamp = p_accountSecurityStamp for update;
    if not found then return query select false, 'OLD_SESSION_NOT_FOUND'::text, null::uuid, null::bigint; return; end if;
    old_cutoff := case when old_session.cut_off is null then account_record.cut_off when account_record.cut_off is null then old_session.cut_off else least(old_session.cut_off, account_record.cut_off) end;
    if old_session.session_expiration <= moment or old_session.access_expiration <= moment or (old_cutoff is not null and old_cutoff <= moment) then return query select false, 'OLD_SESSION_EXPIRED'::text, null::uuid, null::bigint; return; end if;
    select * into setup_record from two_factor_authentications t where t.account_id = p_accountId and t.method = 3 and t.verified = false and t.revoked_at is null and t.token = p_setupTokenHash order by t.created_on desc, t.two_factor_index desc limit 1 for update;
    if not found then return query select false, 'AUTHENTICATOR_SETUP_NOT_FOUND'::text, null::uuid, null::bigint; return; end if;
    perform cor16_require_setup(setup_record,p_accountSecurityStamp,old_session.session_id);
    if setup_record.expiration is not null and setup_record.expiration <= moment then return query select false, 'AUTHENTICATOR_SETUP_EXPIRED'::text, null::uuid, setup_record.two_factor_index; return; end if;
    if setup_record.totp_provider_type <> 1 or setup_record.totp_secret_ciphertext is null or setup_record.totp_secret_nonce is null or setup_record.totp_secret_tag is null then return query select false, 'AUTHENTICATOR_SETUP_INVALID_SECRET'::text, null::uuid, setup_record.two_factor_index; return; end if;
    if setup_record.totp_last_used_step is not null and p_timeStep <= setup_record.totp_last_used_step then return query select false, 'TOTP_REPLAY_DETECTED'::text, null::uuid, setup_record.two_factor_index; return; end if;
    if exists (select 1 from two_factor_authentications t where t.account_id = p_accountId and t.method = 3 and t.verified = true and t.revoked_at is null and t.two_factor_index <> setup_record.two_factor_index) then return query select false, 'TWO_FACTOR_AUTHENTICATOR_APP_ALREADY_ATTACHED'::text, null::uuid, setup_record.two_factor_index; return; end if;
    new_cutoff := case when p_cutOff is null then account_record.cut_off when account_record.cut_off is null then p_cutOff else least(p_cutOff, account_record.cut_off) end;
    if new_cutoff is not null and new_cutoff <= moment then return query select false, 'SESSION_CUT_OFF_EXPIRED'::text, null::uuid, setup_record.two_factor_index; return; end if;
    update two_factor_authentications tfa set verified = true, token = null, expiration = null, lifespan = null, setup_attempts = 0, priority = greatest(tfa.priority, 1), totp_last_used_step = p_timeStep, revoked_at = null, revoked_reason = null where tfa.account_id = p_accountId and tfa.two_factor_index = setup_record.two_factor_index and tfa.verified = false and tfa.revoked_at is null and tfa.setup_request_id=setup_record.setup_request_id and tfa.setup_version=setup_record.setup_version;
    get diagnostics changed=row_count;if changed<>1 then raise exception 'Setup promotion conflict' using errcode='P1601';end if;
    select count(*)::smallint
      into verified_count
      from two_factor_authentications t
     where t.account_id = p_accountId
       and t.verified = true
       and t.revoked_at is null
       and (t.expiration is null or t.expiration > moment)
       and (
            t.method in (1, 2)
            or (
                t.method = 3
                and t.revoked_at is null
                and t.totp_provider_type = 1
                and t.totp_secret_ciphertext is not null
                and octet_length(t.totp_secret_ciphertext) > 0
                and t.totp_secret_nonce is not null
                and octet_length(t.totp_secret_nonce) > 0
                and t.totp_secret_tag is not null
                and octet_length(t.totp_secret_tag) > 0
                and coalesce(t.totp_secret_version, 0) > 0
            )
       );
    update accounts a set security_stamp = new_account_stamp, two_factor_auth_method = 3, two_auth_usage = greatest(verified_count, 1)::smallint where a.account_id = p_accountId and a.security_stamp = p_accountSecurityStamp;
    get diagnostics changed=row_count;if changed<>1 then raise exception 'Setup summary conflict' using errcode='P1601';end if;
    update sessions set access_expiration = least(access_expiration, greatest(created_on, moment)), session_expiration = least(session_expiration, greatest(created_on, moment)) where account_id = p_accountId and session_expiration > moment;
    insert into sessions(session_id, refresh_credential_hash, access_token_hash, account_id, refresh_token, refreshes, refresh_limit, created_on, session_lifespan, access_expiration, session_expiration, cut_off, features, security_stamp, account_security_stamp) values(p_sessionSecurityStamp, session_refresh_credential_hash(p_refreshToken,p_sessionSecurityStamp), p_newAccessTokenHash, p_accountId, p_refreshToken, coalesce(p_refreshes, 0), coalesce(p_refreshLimit, 0), coalesce(p_createdOn, moment), p_sessionLifespan, p_accessExpiration, p_sessionExpiration, new_cutoff, coalesce(p_features, 0), p_sessionSecurityStamp, new_account_stamp);
    delete from pending_two_factor_sessions ptfs where ptfs.account_id = p_accountId;
    perform cor02_require_live(setup_record.setup_authorized_until);
    if setup_record.expiration is not null then perform cor02_require_live(setup_record.expiration); end if;
    perform cor02_require_live(old_session.access_expiration);
    perform cor02_require_live(old_session.session_expiration);
    perform cor02_require_live(p_accessExpiration);
    perform cor02_require_live(p_sessionExpiration);
    if old_cutoff is not null then perform cor02_require_live(old_cutoff); end if;
    if new_cutoff is not null then perform cor02_require_live(new_cutoff); end if;
    perform cor16_factor_changed(p_accountId);
    perform cor02_require_live(setup_record.expiration);perform cor02_require_live(setup_record.setup_authorized_until);
    perform cor02_require_live(old_session.access_expiration);perform cor02_require_live(old_session.session_expiration);
    return query select true, 'AUTHENTICATOR_SETUP_VERIFIED_SESSION_ROTATED'::text, new_account_stamp, setup_record.two_factor_index;
exception
    when sqlstate 'P1601' then return query select false,'AUTHENTICATOR_SETUP_AUTHORITY_CHANGED'::text,null::uuid,null::bigint;
    when sqlstate 'P0202' then
        return query select false, 'AUTHENTICATOR_SETUP_EXPIRED'::text, null::uuid, setup_record.two_factor_index;
 when unique_violation then
    return query select false, 'NEW_SESSION_CONFLICT'::text, null::uuid, null::bigint;
when others then raise;
end;
$$;

create or replace function cancel_authenticator_app_setup(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_setupTokenHash text)
returns table(result boolean, code text)
language plpgsql
as $$
declare deleted_count integer;
begin
    perform cor02_lock_account_authority(p_accountId, 'factor');
    if not exists (select 1 from accounts a where a.account_id = p_accountId and a.security_stamp = p_accountSecurityStamp) then return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text; return; end if;
    if p_setupTokenHash is null or btrim(p_setupTokenHash) = '' then return query select false, 'AUTHENTICATOR_SETUP_INVALID_TOKEN'::text; return; end if;
    delete from two_factor_authentications t where t.account_id = p_accountId and t.method = 3 and t.verified = false and t.revoked_at is null and t.token = p_setupTokenHash;
    get diagnostics deleted_count = row_count;
    return query select true, case when deleted_count > 0 then 'AUTHENTICATOR_SETUP_CANCELLED' else 'AUTHENTICATOR_SETUP_ALREADY_CANCELLED_OR_MISSING' end::text;
exception when others then
    return query select false, 'AUTHENTICATOR_SETUP_CANCEL_FAILED'::text;
end;
$$;

create or replace function verify_account_delete_token(p_deleteTokenHash text)
returns table(result boolean,code text,workflow smallint) language plpgsql as $$
declare owner uuid; d delete_standby%rowtype; affected integer;
begin
    select q.account_id into owner from delete_standby q where q.delete_token_hash=p_deleteTokenHash;
    perform cor12_lock_delivery(owner);
    select * into d from delete_standby q where q.account_id=owner and q.delete_token_hash=p_deleteTokenHash for update;
    if not found then return query select false,'ACCOUNT_DELETE_TOKEN_MISMATCH'::text,0::smallint;return;end if;
    if not cor18_delete_live(d) then perform cor18_retire_delete(owner,p_deleteTokenHash);return query select false,'ACCOUNT_DELETE_AUTHORITY_CHANGED'::text,0::smallint;return;end if;
    if not exists(select 1 from delivery_candidates c where c.account_id=owner and c.purpose='delete' and c.proof_hash=p_deleteTokenHash and c.state='published' and (c.metadata_json::jsonb->>'admissionId')::uuid=d.request_id) then return query select false,'ACCOUNT_DELETE_VERIFY_REQUIRED'::text,0::smallint;return;end if;
    if not d.verified then
        update delete_standby q set verified=true where q.account_id=owner and q.delete_token_hash=p_deleteTokenHash and q.request_id=d.request_id;
        get diagnostics affected=row_count;if affected<>1 then raise exception 'No delete verification effect' using errcode='P1801';end if;
        insert into account_delete_events(account_id,event_type,code,request_id,credential_stamp) values(owner,'VERIFIED','ACCOUNT_DELETE_VERIFIED',d.request_id,d.origin_stamp);
    end if;
    if not cor18_delete_live(d) then raise exception 'Delete authority changed' using errcode='P1801';end if;
    return query select true,'ACCOUNT_DELETE_VERIFIED'::text,case when d.pass_phrase_hash is null then 1::smallint else 2::smallint end;
exception when sqlstate 'P1801' then return query select false,'ACCOUNT_DELETE_AUTHORITY_CHANGED'::text,0::smallint;
end;
$$;

create or replace function purge_expired_delete_standby(p_now timestamptz default now())
returns table(result boolean,code text,deleted_count integer) language plpgsql as $$
declare owner uuid; d delete_standby%rowtype; total integer:=0;
begin
    for owner in select q.account_id from delete_standby q union select a.account_id from account_delete_admissions a order by account_id loop
        perform cor12_lock_delivery(owner);
        select * into d from delete_standby q where q.account_id=owner;
        if found and not cor18_delete_live(d) then perform cor18_retire_delete(owner,d.delete_token_hash);total:=total+1;
            insert into account_delete_events(account_id,event_type,code) values(owner,'PURGED','ACCOUNT_DELETE_PURGE_SUCCEEDED');end if;
        delete from account_delete_admissions q where q.account_id=owner and not cor18_admission_live(q);
    end loop;
    return query select true,'ACCOUNT_DELETE_PURGE_SUCCEEDED'::text,total;
end;
$$;

create or replace function start_unlock_account(
    p_accountId uuid,
    p_tokenHash text,
    p_createdOn timestamp with time zone,
    p_expiration timestamp with time zone,
    p_status smallint,
    p_method smallint,
    p_accountSecurityStamp uuid,
    p_lockoutUnlockWhen timestamp with time zone,
    p_lockoutAttemptVersion uuid)
returns table(status smallint)
language plpgsql
as $$
declare
    v_security_stamp uuid;
    v_unlock_when timestamp with time zone;
    v_attempt_version uuid;
    v_constraint text;
begin
    perform cor02_lock_account_authority(p_accountId, 'unlock');
    if p_method is null or p_method not in (1, 2) or p_status is null or p_status not in (1, 2, 3, 6) then
        return query select 10::smallint;
        return;
    end if;

    select security_stamp, unlock_when
      into v_security_stamp, v_unlock_when
      from accounts
     where account_id = p_accountId;

    if not found or v_unlock_when is null or v_unlock_when <= clock_timestamp() then
        return query select 13::smallint;
        return;
    end if;

    select coalesce((select v.attempt_version from account_login_attempt_versions v
        where v.account_id = p_accountId and v.credential_stamp = v_security_stamp),
        '00000000-0000-0000-0000-000000000000'::uuid) into v_attempt_version;
    if v_attempt_version is distinct from p_lockoutAttemptVersion
        or v_security_stamp is distinct from p_accountSecurityStamp
        or v_unlock_when is distinct from p_lockoutUnlockWhen then
        return query select 14::smallint;
        return;
    end if;

    if p_expiration is null or p_expiration <= clock_timestamp() then
        return query select 5::smallint; return;
    end if;

    update account_recoveries ar
       set status = 4
     where ar.account_id = p_accountId
       and ar.topic = 1 and ar.status in (1, 2, 3, 6);

    insert into account_recoveries(
        account_id,
        created_on,
        status,
        topic,
        expiration,
        token_hash,
        method,
        lockout_security_stamp,
        lockout_unlock_when,
        lockout_attempt_version)
    values(
        p_accountId,
        p_createdOn,
        p_status,
        1,
        p_expiration,
        p_tokenHash,
        p_method,
        p_accountSecurityStamp,
        p_lockoutUnlockWhen,
        p_lockoutAttemptVersion);

    perform cor02_require_live(p_expiration);
    return query select p_status;
exception
    when sqlstate 'P0202' then
        return query select 5::smallint;
    when unique_violation then
        get stacked diagnostics v_constraint = constraint_name;
        if v_constraint in ('account_recoveries_pkey', 'ux_account_recoveries_token_hash') then
            return query select 9::smallint; -- Never resurrect an old token; rollback replacement too.
        else raise; end if;
end;
$$;

create or replace function cancel_unlock_account(
    p_accountId uuid,
    p_tokenHash text)
returns table(status smallint)
language plpgsql
as $$
declare
    v_expected uuid;
    v_recovery account_recoveries%rowtype;
begin
    select ar.request_version into v_expected from account_recoveries ar
     where ar.account_id = p_accountId and ar.token_hash = p_tokenHash;
    perform cor02_lock_account_authority(p_accountId, 'unlock');
    select ar.* into v_recovery from account_recoveries ar
     where ar.account_id = p_accountId and ar.token_hash = p_tokenHash
       and ar.request_version = v_expected and ar.topic = 1;
    if not found then return query select 9::smallint; return; end if;
    if v_recovery.status not in (1, 2, 3, 6) then
        return query select case when v_recovery.status = 4 then 4 else 11 end::smallint; return;
    end if;
    if not exists (
        select 1 from accounts a left join account_login_attempt_versions v
          on v.account_id = a.account_id and v.credential_stamp = a.security_stamp
         where a.account_id = p_accountId and a.security_stamp = v_recovery.lockout_security_stamp
           and a.unlock_when = v_recovery.lockout_unlock_when
           and coalesce(v.attempt_version, '00000000-0000-0000-0000-000000000000'::uuid) = v_recovery.lockout_attempt_version
    ) then
        update account_recoveries ar set status = 14
         where ar.account_id = p_accountId and ar.token_hash = p_tokenHash
           and ar.request_version = v_expected and ar.status in (1, 2, 3, 6);
        return query select 14::smallint; return;
    end if;
    update account_recoveries ar set status = 4
     where ar.account_id = p_accountId and ar.token_hash = p_tokenHash
       and ar.request_version = v_expected and ar.status in (1, 2, 3, 6);
    if not found then return query select 11::smallint; return; end if;
    return query select 4::smallint;
end;
$$;

create or replace function verify_unlock_account(p_tokenHash text)
returns table(status smallint)
language plpgsql
as $$
declare
    v_recovery account_recoveries%rowtype;
    v_account_security_stamp uuid;
    v_account_unlock_when timestamp with time zone;
    cor02_owner uuid;
    v_expected uuid;
    v_attempt_version uuid;
begin
    select t.account_id, t.request_version into cor02_owner, v_expected
      from account_recoveries t where t.token_hash = p_tokenHash;
    perform cor02_lock_account_authority(cor02_owner, 'unlock');
    select *
      into v_recovery
      from account_recoveries ar
     where ar.token_hash = p_tokenHash and ar.account_id = cor02_owner
       and ar.request_version = v_expected and ar.topic = 1
     order by ar.created_on desc
     limit 1;

    if not found then
        return query select 9::smallint;
        return;
    end if;

    if v_recovery.status = 7 then
        return query select 11::smallint;
        return;
    end if;

    if v_recovery.status = 4 then
        return query select 9::smallint;
        return;
    end if;

    if v_recovery.status not in (1, 2, 3, 6) then
        return query select 11::smallint; return;
    end if;
    if v_recovery.expiration <= clock_timestamp() then
        update account_recoveries ar set status = 5
         where ar.account_id = cor02_owner and ar.token_hash = p_tokenHash
           and ar.request_version = v_expected and ar.status in (1, 2, 3, 6);
        return query select 5::smallint; return;
    end if;

    select security_stamp, unlock_when
      into v_account_security_stamp, v_account_unlock_when
      from accounts where account_id = v_recovery.account_id;
    if not found then return query select 14::smallint; return; end if;
    select coalesce((select v.attempt_version from account_login_attempt_versions v
        where v.account_id = cor02_owner and v.credential_stamp = v_account_security_stamp),
        '00000000-0000-0000-0000-000000000000'::uuid) into v_attempt_version;
    if v_attempt_version is distinct from v_recovery.lockout_attempt_version
        or v_account_unlock_when is null
        or v_account_unlock_when <= clock_timestamp()
        or v_account_security_stamp is distinct from v_recovery.lockout_security_stamp
        or v_account_unlock_when is distinct from v_recovery.lockout_unlock_when then
        update account_recoveries ar
           set status = 14
         where ar.account_id = v_recovery.account_id
           and ar.token_hash = p_tokenHash
           and ar.request_version = v_expected and ar.status in (1, 2, 3, 6);
        return query select 14::smallint;
        return;
    end if;

    update account_recoveries ar
       set status = 7
     where ar.account_id = v_recovery.account_id
       and ar.token_hash = p_tokenHash
       and ar.request_version = v_expected and ar.status in (1, 2, 3, 6);
    if not found then return query select 11::smallint; return; end if;

    update accounts
       set unlock_when = null,
           login_failures = 0
     where account_id = v_recovery.account_id
       and security_stamp = v_recovery.lockout_security_stamp
       and unlock_when = v_recovery.lockout_unlock_when
       and coalesce((select v.attempt_version from account_login_attempt_versions v
           where v.account_id = cor02_owner and v.credential_stamp = v_account_security_stamp),
           '00000000-0000-0000-0000-000000000000'::uuid) = v_recovery.lockout_attempt_version;
    if not found then raise exception using errcode = 'P0211', message = 'Unlock binding changed'; end if;
    insert into account_login_attempt_versions(account_id, credential_stamp, attempt_version)
    values(cor02_owner, v_account_security_stamp, gen_random_uuid())
    on conflict(account_id) do update set credential_stamp = excluded.credential_stamp,
        attempt_version = excluded.attempt_version;

    perform cor02_require_live(v_account_unlock_when);
    perform cor02_require_live(v_recovery.expiration);
    return query select 7::smallint;
exception
    when sqlstate 'P0202' then
        return query select 5::smallint;
    when sqlstate 'P0211' then
        return query select 14::smallint;
end;
$$;

create or replace function create_password_reset_request(
    p_passwordResetRequestId uuid,
    p_accountId uuid,
    p_method text,
    p_deliveryChannel text,
    p_keyCodeHash text,
    p_keyCodeHashVersion integer,
    p_destinationFingerprint text,
    p_destinationMasked text,
    p_requiresKeyCode boolean,
    p_requiresTotp boolean,
    p_expiresAt timestamp with time zone,
    p_maxAttempts integer,
    p_requestedByIp inet,
    p_requestedByUserAgent text,
    p_accountSecurityStampAtRequest uuid)
returns table(
    result boolean,
    code text,
    password_reset_request_id uuid,
    account_id uuid,
    expires_at timestamp with time zone)
language plpgsql
as $$
declare
    account_record accounts%rowtype;
    v_created_at timestamp with time zone;
    v_has_sms boolean := false;
    v_method text := lower(nullif(btrim(p_method), ''));
    v_delivery_channel text := lower(nullif(btrim(p_deliveryChannel), ''));
begin
    perform cor02_lock_account_authority(p_accountId, 'reset');
    v_created_at := clock_timestamp();
    select a.*
      into account_record
      from accounts a
     where a.account_id = p_accountId
     for update;

    if not found then
        return query select false, 'PASSWORD_RESET_ACCOUNT_NOT_FOUND'::text, null::uuid, null::uuid, null::timestamp with time zone;
        return;
    end if;

    if account_record.security_stamp is distinct from p_accountSecurityStampAtRequest then
        return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text, null::uuid, p_accountId, null::timestamp with time zone;
        return;
    end if;

    select exists(
        select 1
          from two_factor_authentications t
         where t.account_id = p_accountId
           and t.method = 2
           and t.verified = true
           and t.revoked_at is null
           and (t.expiration is null or t.expiration > v_created_at)
           and t.phone_number is not null
    ) into v_has_sms;

    if v_method is null or v_delivery_channel is null then
        return query select false, 'PASSWORD_RESET_DELIVERY_CHANNEL_INELIGIBLE'::text, null::uuid, p_accountId, null::timestamp with time zone;
        return;
    end if;

    if v_method = 'email' then
        if account_record.verify_status <> 1
           or v_delivery_channel <> 'email'
           or coalesce(p_requiresKeyCode, false) <> true
           or coalesce(p_requiresTotp, false) <> false
           or p_keyCodeHash is null
           or p_keyCodeHashVersion is null then
            return query select false, 'PASSWORD_RESET_DELIVERY_CHANNEL_INELIGIBLE'::text, null::uuid, p_accountId, null::timestamp with time zone;
            return;
        end if;
    elsif v_method = 'sms' then
        if not v_has_sms
           or v_delivery_channel <> 'sms'
           or coalesce(p_requiresKeyCode, false) <> true
           or coalesce(p_requiresTotp, false) <> false
           or p_keyCodeHash is null
           or p_keyCodeHashVersion is null then
            return query select false, 'PASSWORD_RESET_DELIVERY_CHANNEL_INELIGIBLE'::text, null::uuid, p_accountId, null::timestamp with time zone;
            return;
        end if;
    else
        return query select false, 'PASSWORD_RESET_DELIVERY_CHANNEL_INELIGIBLE'::text, null::uuid, p_accountId, null::timestamp with time zone;
        return;
    end if;

    if p_expiresAt is null or p_expiresAt <= clock_timestamp() then
        return query select false, 'PASSWORD_RESET_INVALID_EXPIRATION'::text, null::uuid, p_accountId, null::timestamp with time zone;
        return;
    end if;

    if coalesce(p_maxAttempts, 0) <= 0 then
        return query select false, 'PASSWORD_RESET_INVALID_MAX_ATTEMPTS'::text, null::uuid, p_accountId, null::timestamp with time zone;
        return;
    end if;

    update password_reset_requests pr
       set cancelled_at = v_created_at
     where pr.account_id = p_accountId
       and pr.consumed_at is null
       and pr.cancelled_at is null;

    insert into password_reset_requests(
        factor_policy_version,
        password_reset_request_id,
        account_id,
        method,
        delivery_channel,
        key_code_hash,
        key_code_hash_version,
        destination_fingerprint,
        destination_masked,
        requires_key_code,
        requires_totp,
        created_at,
        expires_at,
        max_attempts,
        requested_by_ip,
        requested_by_user_agent,
        account_security_stamp_at_request)
    values(
        cor13_reset_policy(p_accountId),
        p_passwordResetRequestId,
        p_accountId,
        v_method,
        v_delivery_channel,
        p_keyCodeHash,
        p_keyCodeHashVersion,
        p_destinationFingerprint,
        p_destinationMasked,
        coalesce(p_requiresKeyCode, true),
        coalesce(p_requiresTotp, false),
        v_created_at,
        p_expiresAt,
        p_maxAttempts,
        p_requestedByIp,
        p_requestedByUserAgent,
        p_accountSecurityStampAtRequest);

    insert into password_reset_events(password_reset_request_id, account_id, event_type, code, created_at)
    values(p_passwordResetRequestId, p_accountId, 'password_reset_requested', 'PASSWORD_RESET_REQUEST_CREATED', v_created_at);

    perform cor02_require_live(p_expiresAt);
    return query select true, 'PASSWORD_RESET_REQUEST_CREATED'::text, p_passwordResetRequestId, p_accountId, p_expiresAt;
exception
    when sqlstate 'P0202' then
        return query select false, 'PASSWORD_RESET_INVALID_EXPIRATION'::text, null::uuid, p_accountId, null::timestamp with time zone;
end;
$$;

create or replace function cancel_password_reset_request(
    p_passwordResetRequestId uuid,
    p_cancelledAt timestamp with time zone,
    p_reasonCode text)
returns table(
    result boolean,
    code text,
    account_id uuid,
    cancelled_at timestamp with time zone)
language plpgsql
as $$
declare
    v_reset password_reset_requests%rowtype;
    v_cancelled_at timestamp with time zone := coalesce(p_cancelledAt, now());
    v_reason_code text := coalesce(nullif(btrim(p_reasonCode), ''), 'PASSWORD_RESET_CANCELLED');
    v_event_type text := case
        when coalesce(nullif(btrim(p_reasonCode), ''), '') = 'PASSWORD_RESET_DELIVERY_FAILED' then 'password_reset_delivery_failed'
        else 'password_reset_cancelled'
    end;
    cor02_owner uuid;
begin
    cor02_owner := (select t.account_id from password_reset_requests t where t.password_reset_request_id = p_passwordResetRequestId);
    perform cor02_lock_account_authority(cor02_owner, 'reset');
    select *
      into v_reset
      from password_reset_requests pr
     where pr.password_reset_request_id = p_passwordResetRequestId and pr.account_id = cor02_owner
     for update;

    if not found then
        return query select false, 'PASSWORD_RESET_NOT_FOUND'::text, null::uuid, null::timestamp with time zone;
        return;
    end if;

    if v_reset.consumed_at is not null then
        return query select false, 'PASSWORD_RESET_CONSUMED'::text, v_reset.account_id, v_reset.consumed_at;
        return;
    end if;

    if v_reset.cancelled_at is not null then
        return query select false, 'PASSWORD_RESET_CANCELLED'::text, v_reset.account_id, v_reset.cancelled_at;
        return;
    end if;

    update password_reset_requests pr
       set cancelled_at = v_cancelled_at
     where pr.password_reset_request_id = p_passwordResetRequestId;

    update pending_password_reset_sessions pprs
       set revoked_at = v_cancelled_at,
           revoked_reason = v_reason_code
     where pprs.password_reset_request_id = p_passwordResetRequestId
       and pprs.revoked_at is null;

    insert into password_reset_events(password_reset_request_id, account_id, event_type, code, created_at)
    values(p_passwordResetRequestId, v_reset.account_id, v_event_type, v_reason_code, v_cancelled_at);

    return query select true, v_reason_code, v_reset.account_id, v_cancelled_at;
end;
$$;

create or replace function transition_pending_password_reset_session(
    p_resetAccessTokenHash text,
    p_passwordResetRequestId uuid,
    p_accountId uuid,
    p_bootstrapProof smallint,
    p_state smallint,
    p_availableConfigurations smallint[],
    p_selectedTwoFactorConfiguration smallint,
    p_requiredMethods smallint[],
    p_completedMethods smallint[],
    p_currentExpectedMethod smallint,
    p_challengeCodeHash text,
    p_challengeExpiration timestamp with time zone,
    p_challengeAttempts integer,
    p_challengeResends integer,
    p_nextChallengeAllowedAt timestamp with time zone,
    p_createdOn timestamp with time zone,
    p_expiresAt timestamp with time zone,
    p_selectedAt timestamp with time zone,
    p_twoFactorCompletedAt timestamp with time zone,
    p_passwordChangedAt timestamp with time zone,
    p_transition smallint,
    p_expectedSessionVersion bigint,
    p_expectedChallengeVersion bigint,
    p_bootstrapCodeHash text)
returns table(result boolean, code text, session_version bigint, challenge_version bigint, factor_policy_version text, account_security_stamp uuid)
language plpgsql as $$
declare
    r password_reset_requests%rowtype; old pending_password_reset_sessions%rowtype;
    owner uuid; stamp uuid; policy text; options smallint[]; methods smallint[]; next_method smallint;
    expected_state smallint; cv bigint; sv bigint; denial text:='PASSWORD_RESET_SESSION_STALE';
begin
    owner:=(select t.account_id from password_reset_requests t where t.password_reset_request_id=p_passwordResetRequestId);
    perform cor02_lock_account_authority(owner,'reset');
    select * into r from password_reset_requests t where t.password_reset_request_id=p_passwordResetRequestId;
    select a.security_stamp into stamp from accounts a where a.account_id=owner;
    policy:=cor13_reset_policy(owner);
    if r.account_id is null or owner is distinct from p_accountId or stamp is distinct from r.account_security_stamp_at_request
        or r.consumed_at is not null or r.cancelled_at is not null or r.expires_at<=clock_timestamp()
        or policy is distinct from r.factor_policy_version or p_expiresAt>r.expires_at or p_expiresAt<=clock_timestamp()
        or nullif(btrim(p_resetAccessTokenHash),'') is null then
        return query select false,denial,null::bigint,null::bigint,null::text,null::uuid;return;
    end if;
    select * into old from pending_password_reset_sessions t where t.password_reset_request_id=p_passwordResetRequestId;
    if p_transition=1 then
        -- Creation never overwrites any active or terminal authorization for the parent.
        options:=cor13_reset_configurations(owner,p_bootstrapProof);
        if old.reset_access_token_hash is not null or p_expectedSessionVersion is distinct from 0::bigint or p_expectedChallengeVersion is distinct from 0::bigint
            or p_bootstrapCodeHash is distinct from r.key_code_hash or r.requires_key_code is distinct from true
            or p_bootstrapProof is distinct from (case r.delivery_channel when 'email' then 1 when 'sms' then 2 else 0 end)::smallint
            or p_bootstrapProof not in (1,2) or p_availableConfigurations is distinct from options
            or p_state is distinct from (case when cardinality(options)=0 then 2 else 3 end)::smallint
            or p_selectedTwoFactorConfiguration is not null or cardinality(p_requiredMethods)<>0 or cardinality(p_completedMethods)<>0
            or p_currentExpectedMethod is not null or p_challengeCodeHash is not null or p_challengeExpiration is not null
            or p_challengeAttempts<>0 or p_challengeResends<>0 or p_nextChallengeAllowedAt is not null
            or p_selectedAt is not null or p_twoFactorCompletedAt is not null or p_passwordChangedAt is not null
            or p_createdOn>=p_expiresAt then
            return query select false,denial,null::bigint,null::bigint,null::text,null::uuid;return;
        end if;
        insert into pending_password_reset_sessions(reset_access_token_hash,password_reset_request_id,account_id,bootstrap_proof,
            state,available_configurations,created_on,expires_at,factor_policy_version,account_security_stamp)
        values(p_resetAccessTokenHash,p_passwordResetRequestId,owner,p_bootstrapProof,p_state,options,p_createdOn,p_expiresAt,policy,stamp);
        sv:=1;cv:=0;
    else
        if old.reset_access_token_hash is distinct from p_resetAccessTokenHash or old.revoked_at is not null
            or old.expires_at<=clock_timestamp() or old.state in (8,9,10) or old.session_version is distinct from p_expectedSessionVersion
            or old.challenge_version is distinct from p_expectedChallengeVersion or old.factor_policy_version is distinct from policy
            or old.account_security_stamp is distinct from stamp or old.bootstrap_proof is distinct from p_bootstrapProof
            or old.available_configurations is distinct from p_availableConfigurations or old.created_on is distinct from p_createdOn
            or old.expires_at is distinct from p_expiresAt or p_passwordChangedAt is not null then
            return query select false,denial,null::bigint,null::bigint,null::text,null::uuid;return;
        end if;
        sv:=old.session_version+1;cv:=old.challenge_version;
        methods:=case p_selectedTwoFactorConfiguration when 1 then array[2] when 2 then array[1] when 3 then array[3]
            when 4 then array[2,3] when 5 then array[1,3] else array[]::integer[] end;
        if p_requiredMethods is distinct from methods::smallint[] then
            return query select false,denial,null::bigint,null::bigint,null::text,null::uuid;return;
        end if;
        if p_transition in (2,3) then
            -- Selection/resend can replace only an uncompleted challenge, preserving lifetime budgets.
            if old.state=7 or not (p_selectedTwoFactorConfiguration=any(old.available_configurations))
                or cardinality(old.completed_methods)>0 or cardinality(p_completedMethods)<>0
                or (old.next_challenge_allowed_at is not null and old.next_challenge_allowed_at>clock_timestamp())
                or p_challengeAttempts is distinct from old.challenge_attempts
                or (p_transition=3 and (p_selectedTwoFactorConfiguration is distinct from old.selected_two_factor_configuration
                    or p_selectedAt is distinct from old.selected_at)) then
                return query select false,denial,null::bigint,null::bigint,null::text,null::uuid;return;
            end if;
            next_method:=methods[1];
            expected_state:=case next_method when 1 then 5 when 2 then 4 when 3 then 6 end;
            if p_state is distinct from expected_state or p_currentExpectedMethod is distinct from next_method
                or p_twoFactorCompletedAt is not null or p_selectedAt is null or p_selectedAt>clock_timestamp() then
                return query select false,denial,null::bigint,null::bigint,null::text,null::uuid;return;
            end if;
            if next_method=3 then
                if p_challengeCodeHash is not null or p_challengeExpiration is not null
                    or p_challengeResends is distinct from old.challenge_resends
                    or p_nextChallengeAllowedAt is distinct from old.next_challenge_allowed_at then
                    return query select false,denial,null::bigint,null::bigint,null::text,null::uuid;return;
                end if;
            else
                if nullif(btrim(p_challengeCodeHash),'') is null or p_challengeCodeHash is not distinct from old.challenge_code_hash
                    or p_challengeExpiration is null or p_challengeExpiration>old.expires_at or p_challengeExpiration<=clock_timestamp()
                    or p_challengeResends is distinct from old.challenge_resends+1 or p_challengeResends>r.max_attempts
                    or p_nextChallengeAllowedAt is null
                    or (old.next_challenge_allowed_at is not null and p_nextChallengeAllowedAt<old.next_challenge_allowed_at) then
                    return query select false,denial,null::bigint,null::bigint,null::text,null::uuid;return;
                end if;
            end if;
            cv:=cv+1;
        elsif p_transition in (4,5) then
            if old.current_expected_method is null or old.state not in (4,5,6)
                or p_selectedTwoFactorConfiguration is distinct from old.selected_two_factor_configuration
                or p_selectedAt is distinct from old.selected_at or p_challengeResends is distinct from old.challenge_resends
                or p_nextChallengeAllowedAt is distinct from old.next_challenge_allowed_at then
                return query select false,denial,null::bigint,null::bigint,null::text,null::uuid;return;
            end if;
            if p_transition=4 then
                if p_challengeAttempts is distinct from old.challenge_attempts+1 or p_state is distinct from old.state
                    or p_completedMethods is distinct from old.completed_methods or p_currentExpectedMethod is distinct from old.current_expected_method
                    or p_challengeCodeHash is distinct from old.challenge_code_hash or p_challengeExpiration is distinct from old.challenge_expiration
                    or p_twoFactorCompletedAt is distinct from old.two_factor_completed_at then
                    return query select false,denial,null::bigint,null::bigint,null::text,null::uuid;return;
                end if;
                update password_reset_requests t set attempt_count=t.attempt_count+1,
                    cancelled_at=case when t.attempt_count+1>=t.max_attempts then clock_timestamp() else null end
                    where t.password_reset_request_id=p_passwordResetRequestId returning t.* into r;
            else
                if (old.current_expected_method<>3 and (old.challenge_expiration is null or old.challenge_expiration<=clock_timestamp()))
                    or p_challengeAttempts is distinct from old.challenge_attempts
                    or p_completedMethods is distinct from array_append(old.completed_methods,old.current_expected_method)
                    or p_challengeCodeHash is not null or p_challengeExpiration is not null then
                    return query select false,denial,null::bigint,null::bigint,null::text,null::uuid;return;
                end if;
                select x into next_method from unnest(old.required_methods) with ordinality t(x,n)
                    where not (x=any(p_completedMethods)) order by n limit 1;
                expected_state:=case next_method when 1 then 5 when 2 then 4 when 3 then 6 else 7 end;
                if p_state is distinct from expected_state or p_currentExpectedMethod is distinct from next_method
                    or (next_method is null and (p_twoFactorCompletedAt is null or p_twoFactorCompletedAt>clock_timestamp()))
                    or (next_method is not null and p_twoFactorCompletedAt is not null) then
                    return query select false,denial,null::bigint,null::bigint,null::text,null::uuid;return;
                end if;
                cv:=cv+1;
                if old.current_expected_method<>3 then perform cor02_require_live(old.challenge_expiration);end if;
            end if;
        else
            return query select false,denial,null::bigint,null::bigint,null::text,null::uuid;return;
        end if;
        update pending_password_reset_sessions t set state=case when r.cancelled_at is null then p_state else 10 end,
            selected_two_factor_configuration=p_selectedTwoFactorConfiguration,required_methods=p_requiredMethods,
            completed_methods=p_completedMethods,current_expected_method=p_currentExpectedMethod,
            challenge_code_hash=p_challengeCodeHash,challenge_expiration=p_challengeExpiration,challenge_attempts=p_challengeAttempts,
            challenge_resends=p_challengeResends,next_challenge_allowed_at=p_nextChallengeAllowedAt,selected_at=p_selectedAt,
            two_factor_completed_at=p_twoFactorCompletedAt,session_version=sv,challenge_version=cv,
            revoked_at=r.cancelled_at,revoked_reason=case when r.cancelled_at is not null then 'PASSWORD_RESET_MAX_ATTEMPTS' else null end
            where t.reset_access_token_hash=p_resetAccessTokenHash;
    end if;
    insert into password_reset_events(password_reset_request_id,account_id,event_type,code,created_at)
        values(p_passwordResetRequestId,owner,'password_reset_session_transition','PASSWORD_RESET_SESSION_SAVED',clock_timestamp());
    perform cor02_require_live(r.expires_at);perform cor02_require_live(p_expiresAt);
    return query select true,'PASSWORD_RESET_SESSION_SAVED'::text,sv,cv,policy,stamp;
exception
    when unique_violation then return query select false,denial,null::bigint,null::bigint,null::text,null::uuid;
    when sqlstate 'P0202' then return query select false,'PASSWORD_RESET_SESSION_INVALID_EXPIRATION'::text,null::bigint,null::bigint,null::text,null::uuid;
end;
$$;

create or replace function revoke_pending_password_reset_session(
    p_resetAccessTokenHash text,
    p_revokedAt timestamp with time zone,
    p_reasonCode text,
    p_expectedSessionVersion bigint,
    p_expectedChallengeVersion bigint)
returns table(result boolean, code text)
language plpgsql
as $$
declare
    v_revoked_at timestamp with time zone := coalesce(p_revokedAt, now());
    v_reason_code text := coalesce(nullif(btrim(p_reasonCode), ''), 'PASSWORD_RESET_SESSION_REVOKED');
    v_account_id uuid;
    v_password_reset_request_id uuid;
    cor02_owner uuid;
begin
    cor02_owner := (select t.account_id from pending_password_reset_sessions t where t.reset_access_token_hash = p_resetAccessTokenHash);
    perform cor02_lock_account_authority(cor02_owner, 'reset');
    update pending_password_reset_sessions p
       set revoked_at = v_revoked_at,
           revoked_reason = v_reason_code
     where p.reset_access_token_hash = p_resetAccessTokenHash and p.account_id = cor02_owner
       and p.revoked_at is null
       and p.session_version=p_expectedSessionVersion and p.challenge_version=p_expectedChallengeVersion
     returning p.account_id, p.password_reset_request_id
      into v_account_id, v_password_reset_request_id;

    if not found then
        return query select false, 'PASSWORD_RESET_SESSION_STALE'::text;
        return;
    end if;

    update password_reset_requests t set cancelled_at=clock_timestamp()
        where t.password_reset_request_id=v_password_reset_request_id and t.cancelled_at is null and t.consumed_at is null;
    insert into password_reset_events(password_reset_request_id, account_id, event_type, code, created_at)
    values(v_password_reset_request_id, v_account_id, 'password_reset_session_revoked', v_reason_code, v_revoked_at);

    return query select true, v_reason_code;
end;
$$;

create or replace function revoke_pending_password_reset_sessions_for_account(
    p_accountId uuid,
    p_revokedAt timestamp with time zone,
    p_reasonCode text)
returns table(result boolean, code text, revoked_count integer)
language plpgsql
as $$
declare
    v_revoked_at timestamp with time zone := coalesce(p_revokedAt, now());
    v_reason_code text := coalesce(nullif(btrim(p_reasonCode), ''), 'PASSWORD_RESET_SESSION_REVOKED');
    v_revoked_count integer := 0;
begin
    perform cor02_lock_account_authority(p_accountId, 'reset');
    if p_accountId is null then
        return query select false, 'PASSWORD_RESET_SESSION_ACCOUNT_REQUIRED'::text, 0;
        return;
    end if;

    perform cor02_lock_account_authority(p_accountId,'reset');
    update password_reset_requests t set cancelled_at=clock_timestamp()
        where t.account_id=p_accountId and t.cancelled_at is null and t.consumed_at is null;
    with revoked as (
        update pending_password_reset_sessions p
           set revoked_at = v_revoked_at,
               revoked_reason = v_reason_code
         where p.account_id = p_accountId
           and p.revoked_at is null
         returning p.password_reset_request_id, p.account_id
    ), inserted_events as (
        insert into password_reset_events(password_reset_request_id, account_id, event_type, code, created_at)
        select r.password_reset_request_id,
               r.account_id,
               'password_reset_session_revoked',
               v_reason_code,
               v_revoked_at
          from revoked r
        returning 1
    )
    select count(*)
      into v_revoked_count
      from inserted_events;

    if v_revoked_count = 0 then
        return query select true, 'PASSWORD_RESET_SESSION_NOT_FOUND'::text, 0;
        return;
    end if;

    return query select true, v_reason_code, v_revoked_count;
end;
$$;

create or replace function register_password_reset_failed_attempt(
    p_passwordResetRequestId uuid,
    p_failedAt timestamp with time zone)
returns table(
    result boolean,
    code text,
    account_id uuid,
    attempt_count integer,
    max_attempts integer,
    cancelled_at timestamp with time zone)
language plpgsql
as $$
declare
    v_reset password_reset_requests%rowtype;
    v_failed_at timestamp with time zone := coalesce(p_failedAt, now());
    v_attempt_count integer;
    v_cancelled_at timestamp with time zone;
    cor02_owner uuid;
begin
    cor02_owner := (select t.account_id from password_reset_requests t where t.password_reset_request_id = p_passwordResetRequestId);
    perform cor02_lock_account_authority(cor02_owner, 'reset');
    select *
      into v_reset
      from password_reset_requests pr
     where pr.password_reset_request_id = p_passwordResetRequestId and pr.account_id = cor02_owner
     for update;

    if not found then
        return query select false, 'PASSWORD_RESET_NOT_FOUND'::text, null::uuid, null::integer, null::integer, null::timestamp with time zone;
        return;
    end if;

    if v_reset.consumed_at is not null then
        return query select false, 'PASSWORD_RESET_CONSUMED'::text, v_reset.account_id, v_reset.attempt_count, v_reset.max_attempts, v_reset.cancelled_at;
        return;
    end if;

    if v_reset.cancelled_at is not null then
        return query select false, 'PASSWORD_RESET_CANCELLED'::text, v_reset.account_id, v_reset.attempt_count, v_reset.max_attempts, v_reset.cancelled_at;
        return;
    end if;

    if v_reset.expires_at <= clock_timestamp() then
        update password_reset_requests pr
           set cancelled_at = v_failed_at
         where pr.password_reset_request_id = p_passwordResetRequestId
           and pr.cancelled_at is null;

        update pending_password_reset_sessions pprs
           set revoked_at = v_failed_at,
               revoked_reason = 'PASSWORD_RESET_EXPIRED'
         where pprs.password_reset_request_id = p_passwordResetRequestId
           and pprs.revoked_at is null;

        insert into password_reset_events(password_reset_request_id, account_id, event_type, code, created_at)
        values(p_passwordResetRequestId, v_reset.account_id, 'password_reset_expired', 'PASSWORD_RESET_EXPIRED', v_failed_at);

        return query select false, 'PASSWORD_RESET_EXPIRED'::text, v_reset.account_id, v_reset.attempt_count, v_reset.max_attempts, v_failed_at;
        return;
    end if;

    v_attempt_count := v_reset.attempt_count + 1;

    if v_attempt_count >= v_reset.max_attempts then
        update password_reset_requests pr
           set attempt_count = v_attempt_count,
               cancelled_at = v_failed_at
         where pr.password_reset_request_id = p_passwordResetRequestId
        returning pr.cancelled_at into v_cancelled_at;

        update pending_password_reset_sessions pprs
           set revoked_at = v_failed_at,
               revoked_reason = 'PASSWORD_RESET_ATTEMPTS_EXCEEDED'
         where pprs.password_reset_request_id = p_passwordResetRequestId
           and pprs.revoked_at is null;

        insert into password_reset_events(password_reset_request_id, account_id, event_type, code, created_at)
        values(p_passwordResetRequestId, v_reset.account_id, 'password_reset_attempts_exceeded', 'PASSWORD_RESET_ATTEMPTS_EXCEEDED', v_failed_at);

        return query select false, 'PASSWORD_RESET_ATTEMPTS_EXCEEDED'::text, v_reset.account_id, v_attempt_count, v_reset.max_attempts, v_cancelled_at;
        return;
    end if;

    update password_reset_requests pr
       set attempt_count = v_attempt_count
     where pr.password_reset_request_id = p_passwordResetRequestId;

    insert into password_reset_events(password_reset_request_id, account_id, event_type, code, created_at)
    values(p_passwordResetRequestId, v_reset.account_id, 'password_reset_failed_attempt', 'PASSWORD_RESET_ATTEMPT_RECORDED', v_failed_at);

    return query select true, 'PASSWORD_RESET_ATTEMPT_RECORDED'::text, v_reset.account_id, v_attempt_count, v_reset.max_attempts, null::timestamp with time zone;
end;
$$;

create or replace function promote_password_reset(
    p_passwordResetRequestId uuid,
    p_accountId uuid,
    p_hashedPassword bytea,
    p_saltOne bytea,
    p_siv bytea,
    p_nonce bytea,
    p_newSecurityStamp uuid,
    p_promotedAt timestamp with time zone,
    p_resetAccessTokenHash text,
    p_expectedSessionVersion bigint,
    p_expectedChallengeVersion bigint)
returns table(
    result boolean,
    code text,
    account_id uuid,
    account_security_stamp uuid,
    consumed_at timestamp with time zone)
language plpgsql
as $$
declare
    v_reset password_reset_requests%rowtype;
    proof pending_password_reset_sessions%rowtype;
    v_current_security_stamp uuid;
    v_promoted_at timestamp with time zone := coalesce(p_promotedAt, now());
    cor02_owner uuid;
begin
    cor02_owner := (select t.account_id from password_reset_requests t where t.password_reset_request_id = p_passwordResetRequestId);
    perform cor02_lock_account_authority(cor02_owner, 'reset');
    select *
      into v_reset
      from password_reset_requests pr
     where pr.password_reset_request_id = p_passwordResetRequestId and pr.account_id = cor02_owner
     for update;

    if not found then
        return query select false, 'PASSWORD_RESET_NOT_FOUND'::text, null::uuid, null::uuid, null::timestamp with time zone;
        return;
    end if;

    -- The application host and database can differ by a small clock skew in
    -- host-backed system tests and real deployments. Clamp the supplied
    -- promotion timestamp to the reset row creation time so consuming the
    -- artifact never violates ck_password_reset_consumed_after_created.
    v_promoted_at := greatest(clock_timestamp(), v_reset.created_at);

    if v_reset.account_id is distinct from p_accountId then
        return query select false, 'PASSWORD_RESET_ACCOUNT_MISMATCH'::text, v_reset.account_id, null::uuid, null::timestamp with time zone;
        return;
    end if;

    if v_reset.consumed_at is not null then
        return query select false, 'PASSWORD_RESET_CONSUMED'::text, v_reset.account_id, null::uuid, v_reset.consumed_at;
        return;
    end if;

    if v_reset.cancelled_at is not null then
        return query select false, 'PASSWORD_RESET_CANCELLED'::text, v_reset.account_id, null::uuid, v_reset.cancelled_at;
        return;
    end if;

    if v_reset.expires_at <= clock_timestamp() then
        update password_reset_requests pr
           set cancelled_at = v_promoted_at
         where pr.password_reset_request_id = p_passwordResetRequestId
           and pr.cancelled_at is null;

        update pending_password_reset_sessions pprs
           set revoked_at = v_promoted_at,
               revoked_reason = 'PASSWORD_RESET_EXPIRED'
         where pprs.password_reset_request_id = p_passwordResetRequestId
           and pprs.revoked_at is null;

        insert into password_reset_events(password_reset_request_id, account_id, event_type, code, created_at)
        values(p_passwordResetRequestId, v_reset.account_id, 'password_reset_expired', 'PASSWORD_RESET_EXPIRED', v_promoted_at);

        return query select false, 'PASSWORD_RESET_EXPIRED'::text, v_reset.account_id, null::uuid, v_promoted_at;
        return;
    end if;

    select a.security_stamp
      into v_current_security_stamp
      from accounts a
     where a.account_id = p_accountId
     for update;

    if not found then
        return query select false, 'PASSWORD_RESET_ACCOUNT_NOT_FOUND'::text, v_reset.account_id, null::uuid, null::timestamp with time zone;
        return;
    end if;

    if v_current_security_stamp is distinct from v_reset.account_security_stamp_at_request then
        update password_reset_requests pr
           set cancelled_at = v_promoted_at
         where pr.password_reset_request_id = p_passwordResetRequestId
           and pr.cancelled_at is null;

        update pending_password_reset_sessions pprs
           set revoked_at = v_promoted_at,
               revoked_reason = 'PASSWORD_RESET_ACCOUNT_STALE'
         where pprs.password_reset_request_id = p_passwordResetRequestId
           and pprs.revoked_at is null;

        insert into password_reset_events(password_reset_request_id, account_id, event_type, code, created_at)
        values(p_passwordResetRequestId, v_reset.account_id, 'password_reset_stale_account', 'PASSWORD_RESET_ACCOUNT_STALE', v_promoted_at);

        return query select false, 'PASSWORD_RESET_ACCOUNT_STALE'::text, v_reset.account_id, v_current_security_stamp, v_promoted_at;
        return;
    end if;

    select * into proof from pending_password_reset_sessions t
        where t.reset_access_token_hash=p_resetAccessTokenHash for update;
    if proof.password_reset_request_id is distinct from p_passwordResetRequestId or proof.account_id is distinct from p_accountId
        or proof.revoked_at is not null or proof.expires_at<=clock_timestamp()
        or proof.session_version is distinct from p_expectedSessionVersion or proof.challenge_version is distinct from p_expectedChallengeVersion
        or proof.account_security_stamp is distinct from v_current_security_stamp
        or proof.factor_policy_version is distinct from cor13_reset_policy(p_accountId)
        or v_reset.factor_policy_version is distinct from proof.factor_policy_version
        or not ((proof.state=2 and cardinality(proof.available_configurations)=0 and proof.selected_two_factor_configuration is null
            and cardinality(proof.required_methods)=0 and cardinality(proof.completed_methods)=0)
            or (proof.state=7 and proof.selected_two_factor_configuration is not null and cardinality(proof.required_methods)>0
                and proof.completed_methods=proof.required_methods and proof.two_factor_completed_at is not null
                and proof.current_expected_method is null)) then
        return query select false,'PASSWORD_RESET_AUTHORIZATION_INVALID'::text,p_accountId,null::uuid,null::timestamptz;return;
    end if;

    update accounts a
       set hashed_password = p_hashedPassword,
           salt_one = p_saltOne,
           siv = p_siv,
           nonce = p_nonce,
           security_stamp = p_newSecurityStamp,
           login_failures = 0
     where a.account_id = p_accountId;

    update sessions s
       set cut_off = case
               when s.cut_off is null then v_promoted_at
               when s.cut_off > v_promoted_at then v_promoted_at
               else s.cut_off
           end
     where s.account_id = p_accountId;

    update password_reset_requests pr
       set consumed_at = v_promoted_at
     where pr.password_reset_request_id = p_passwordResetRequestId;

    update pending_password_reset_sessions pprs
       set state = 8,
           password_changed_at = v_promoted_at,
           revoked_at = v_promoted_at,
           revoked_reason = 'PASSWORD_RESET_COMPLETED'
     where pprs.account_id = p_accountId
       and pprs.revoked_at is null;

    update password_reset_requests pr
       set cancelled_at = v_promoted_at
     where pr.account_id = p_accountId
       and pr.password_reset_request_id <> p_passwordResetRequestId
       and pr.consumed_at is null
       and pr.cancelled_at is null;

    insert into password_reset_events(password_reset_request_id, account_id, event_type, code, created_at)
    values(p_passwordResetRequestId, p_accountId, 'password_reset_completed', 'PASSWORD_RESET_COMPLETED', v_promoted_at);

    perform cor02_require_live(v_reset.expires_at);
    perform cor02_require_live(proof.expires_at);
    return query select true, 'PASSWORD_RESET_COMPLETED'::text, p_accountId, p_newSecurityStamp, v_promoted_at;
exception
    when sqlstate 'P0202' then
        return query select false, 'PASSWORD_RESET_EXPIRED'::text, p_accountId, null::uuid, null::timestamp with time zone;
end;
$$;

create or replace function cleanup_expired_password_reset_requests(
    p_now timestamp with time zone,
    p_retention interval)
returns table(
    result boolean,
    code text,
    cancelled_count integer,
    deleted_count integer)
language plpgsql
as $$
declare
    v_now timestamp with time zone;
    v_retention interval := greatest(coalesce(p_retention, interval '30 days'), interval '1 day');
    v_cancelled_count integer := 0;
    v_deleted_count integer := 0;
    cor02_owner uuid;
begin
    for cor02_owner in select distinct t.account_id from password_reset_requests t order by t.account_id loop
        perform cor02_lock_account_authority(cor02_owner, 'reset');
    end loop;
    v_now := least(coalesce(p_now, clock_timestamp()), clock_timestamp());
    update password_reset_requests pr
       set cancelled_at = v_now
     where pr.expires_at <= v_now
       and pr.consumed_at is null
       and pr.cancelled_at is null;

    get diagnostics v_cancelled_count = row_count;

    update pending_password_reset_sessions pprs
       set revoked_at = v_now,
           revoked_reason = 'PASSWORD_RESET_EXPIRED'
      from password_reset_requests pr
     where pprs.password_reset_request_id = pr.password_reset_request_id
       and pr.cancelled_at = v_now
       and pprs.revoked_at is null;

    delete from password_reset_requests pr
     where coalesce(pr.consumed_at, pr.cancelled_at) is not null
       and coalesce(pr.consumed_at, pr.cancelled_at) < v_now - v_retention;

    get diagnostics v_deleted_count = row_count;

    return query select true, 'PASSWORD_RESET_CLEANUP_COMPLETED'::text, v_cancelled_count, v_deleted_count;
end;
$$;

create or replace function place_activation(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_emailAddress text,
    p_code text,
    p_createdOn timestamp with time zone,
    p_term smallint,
    p_interval smallint,
    p_closeOff timestamp with time zone,
    p_featureSet smallint,
    p_platformBacker smallint,
    p_platformText text,
    p_status smallint,
    p_delayedStart interval)
returns table(result boolean, code text, status smallint)
language plpgsql
as $$
begin
    return query select false,'ACTIVATION_TRUSTED_GRANT_REQUIRED'::text,null::smallint;
end;
$$;

create or replace function cancel_activation_request(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_code text,
    p_cancelledOn timestamp with time zone)
returns table(result boolean, code text, status smallint)
language plpgsql
as $$
begin
    return query select false,'ACTIVATION_TRUSTED_GRANT_REQUIRED'::text,null::smallint;
end;
$$;

create or replace function disable_activation(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_emailAddress text,
    p_createdOn timestamp with time zone,
    p_closeOff timestamp with time zone,
    p_status smallint)
returns table(result boolean, code text, status smallint)
language plpgsql
as $$
begin
    return query select false,'ACTIVATION_TRUSTED_GRANT_REQUIRED'::text,null::smallint;
end;
$$;

create or replace function verify_activation(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_emailAddress text,
    p_code text,
    p_createdOn timestamp with time zone,
    p_position smallint,
    p_upperLimit smallint)
returns table(
    result boolean,
    code text,
    feature_set smallint,
    off_at timestamp with time zone,
    day_duration smallint,
    duration_repeat smallint)
language plpgsql
as $$
begin
    return query select false,'ACTIVATION_TRUSTED_GRANT_REQUIRED'::text,null::smallint,null::timestamptz,null::smallint,null::smallint;
end;
$$;
