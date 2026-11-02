-- COR08: account fields remain the counter projection; versions fence clears.
CREATE TABLE account_login_attempt_versions (
    account_id uuid PRIMARY KEY REFERENCES accounts(account_id) ON DELETE CASCADE,
    credential_stamp uuid NOT NULL,
    attempt_version uuid NOT NULL
);
CREATE TABLE account_reauthentication_budgets (
    account_id uuid PRIMARY KEY REFERENCES accounts(account_id) ON DELETE CASCADE,
    credential_stamp uuid NOT NULL,
    window_version uuid NOT NULL,
    window_start timestamptz NOT NULL,
    admitted integer NOT NULL CHECK (admitted >= 0),
    failed integer NOT NULL CHECK (failed >= 0)
);
CREATE TABLE sensitive_password_attempts (
    attempt_id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    credential_stamp uuid NOT NULL,
    window_version uuid NOT NULL,
    session_hash text NOT NULL,
    family_id uuid NOT NULL,
    old_hash bytea NOT NULL,
    purpose smallint NOT NULL CHECK (purpose BETWEEN 1 AND 6),
    target_hash text NOT NULL CHECK (length(target_hash) = 64),
    factor_policy text NOT NULL,
    factor_required boolean NOT NULL,
    created_on timestamptz NOT NULL,
    expiration timestamptz NOT NULL,
    state text NOT NULL CHECK (state IN ('Pending','Failed','Succeeded','Abandoned'))
);
CREATE INDEX sensitive_password_attempts_expiry ON sensitive_password_attempts (expiration, attempt_id);
CREATE TABLE sensitive_action_proof_sessions (
    proof_id uuid PRIMARY KEY,
    handle_hash text NOT NULL UNIQUE,
    account_id uuid NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    credential_stamp uuid NOT NULL,
    session_hash text NOT NULL,
    family_id uuid NOT NULL,
    purpose smallint NOT NULL CHECK (purpose BETWEEN 1 AND 6),
    target_hash text NOT NULL CHECK (length(target_hash) = 64),
    factor_policy text NOT NULL,
    factor_required boolean NOT NULL,
    factor_complete boolean NOT NULL DEFAULT false,
    factor_attempts integer NOT NULL DEFAULT 0 CHECK (factor_attempts >= 0),
    expiration timestamptz NOT NULL,
    state text NOT NULL CHECK (state IN ('Pending','Granted'))
);
CREATE INDEX sensitive_action_proof_expiry ON sensitive_action_proof_sessions (expiration, proof_id);
CREATE TABLE sensitive_action_grants (
    token_hash text PRIMARY KEY,
    proof_id uuid NOT NULL UNIQUE REFERENCES sensitive_action_proof_sessions(proof_id) ON DELETE CASCADE,
    account_id uuid NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    credential_stamp uuid NOT NULL,
    session_hash text NOT NULL,
    family_id uuid NOT NULL,
    purpose smallint NOT NULL CHECK (purpose BETWEEN 1 AND 6),
    target_hash text NOT NULL CHECK (length(target_hash) = 64),
    factor_policy text NOT NULL,
    policy_version integer NOT NULL CHECK (policy_version = 1),
    expiration timestamptz NOT NULL,
    consumed_on timestamptz
);
CREATE INDEX sensitive_action_grants_expiry ON sensitive_action_grants (expiration, token_hash);

create or replace function cor08_record_login_failure(p_account uuid, p_stamp uuid, p_charge integer, p_limit integer)
returns table(result boolean, code text, failures smallint, unlock_when timestamptz, attempt_version uuid)
language plpgsql
as $$
declare a accounts%rowtype; v uuid := gen_random_uuid(); n integer; until_time timestamptz;
begin
    perform cor02_lock_account_authority(p_account, 'account');
    select * into a from accounts where account_id = p_account;
    if not found or a.security_stamp is distinct from p_stamp then
        return query select false,'ACCOUNT_SECURITY_STAMP_MISMATCH'::text,0::smallint,null::timestamptz,null::uuid; return;
    end if;
    if p_charge not between 1 and 3 or p_limit not between 1 and 20 then raise exception 'Invalid attempt policy'; end if;
    n := least(a.login_failures::integer + p_charge,32767);
    until_time := a.unlock_when;
    -- Preserve a live lockout, never shorten/clear it through a delayed failure.
    if n >= p_limit and (until_time is null or until_time <= clock_timestamp()) then
        until_time := clock_timestamp() + make_interval(hours => (n+1)*2);
    end if;
    update accounts set login_failures=n::smallint,unlock_when=until_time where account_id=p_account;
    insert into account_login_attempt_versions values(p_account,p_stamp,v)
    on conflict(account_id) do update set credential_stamp=excluded.credential_stamp,attempt_version=excluded.attempt_version;
    return query select true,case when until_time is not null then 'LOCKED' else 'RECORDED' end::text,n::smallint,until_time,v;
end;
$$;

create or replace function cor08_clear_login_attempts(p_account uuid, p_stamp uuid, p_version uuid,
    p_failures smallint, p_unlock timestamptz, p_expired_cleanup boolean)
returns table(result boolean, code text, failures smallint, unlock_when timestamptz, attempt_version uuid)
language plpgsql
as $$
declare a accounts%rowtype; observed uuid; v uuid := gen_random_uuid();
begin
    perform cor02_lock_account_authority(p_account,'account');
    select * into a from accounts where account_id=p_account;
    if not found or a.security_stamp is distinct from p_stamp then
        return query select false,'ACCOUNT_SECURITY_STAMP_MISMATCH'::text,0::smallint,null::timestamptz,null::uuid; return;
    end if;
    select l.attempt_version into observed from account_login_attempt_versions l where l.account_id=p_account and l.credential_stamp=p_stamp;
    observed := coalesce(observed,'00000000-0000-0000-0000-000000000000'::uuid);
    if observed is distinct from p_version or a.login_failures is distinct from p_failures or a.unlock_when is distinct from p_unlock
        or (p_expired_cleanup and (a.unlock_when is null or a.unlock_when > clock_timestamp()))
        or (not p_expired_cleanup and a.unlock_when is not null) then
        return query select false,'LOGIN_ATTEMPT_STATE_CHANGED'::text,a.login_failures,a.unlock_when,observed; return;
    end if;
    update accounts set login_failures=0,unlock_when=null where account_id=p_account;
    insert into account_login_attempt_versions values(p_account,p_stamp,v)
    on conflict(account_id) do update set credential_stamp=excluded.credential_stamp,attempt_version=excluded.attempt_version;
    return query select true,'CLEARED'::text,0::smallint,null::timestamptz,v;
end;
$$;

-- Includes protected material identity but never last-used TOTP step (proof itself changes it).
create or replace function cor08_factor_policy(p_account uuid)
returns text
language sql
stable
as $$
    select encode(digest(coalesce(jsonb_agg(jsonb_build_array(t.two_factor_index,t.method,t.required,t.expiration,
        t.totp_provider_type,encode(t.totp_secret_ciphertext,'hex'),encode(t.totp_secret_nonce,'hex'),encode(t.totp_secret_tag,'hex'),
        t.totp_secret_version,t.phone_number,t.email_address) order by t.two_factor_index)::text,'[]'),'sha256'),'hex')
    from two_factor_authentications t where t.account_id=p_account and t.verified and t.revoked_at is null;
$$;

create or replace function cor08_live_sensitive_authority(p_account uuid,p_stamp uuid,p_session text,p_family uuid)
returns boolean
language sql
volatile
as $$
    select exists(select 1 from accounts a join sessions s on s.account_id=a.account_id
        where a.account_id=p_account and a.security_stamp=p_stamp and a.verify_status=1
        and (a.unlock_when is null or a.unlock_when <= clock_timestamp())
        and (a.cut_off is null or a.cut_off > clock_timestamp()) and s.access_token_hash=p_session
        and s.session_id=p_family and s.account_security_stamp=p_stamp
        and s.access_expiration > clock_timestamp() and s.session_expiration > clock_timestamp()
        and (s.cut_off is null or s.cut_off > clock_timestamp()));
$$;

create or replace function cor08_begin_password_proof(p_account uuid,p_stamp uuid,p_session text,p_attempt uuid,
    p_purpose smallint,p_target text,p_limit integer,p_window integer,p_lease integer)
returns table(result boolean,code text,hashed_password bytea,factor_required boolean)
language plpgsql
as $$
declare a accounts%rowtype; family uuid; b account_reauthentication_budgets%rowtype; needs_factor boolean;
begin
    perform cor02_lock_account_authority(p_account,'factor');
    select * into a from accounts where account_id=p_account;
    select s.session_id into family from sessions s where s.access_token_hash=p_session and s.account_id=p_account;
    if family is null or not cor08_live_sensitive_authority(p_account,p_stamp,p_session,family) then
        return query select false,'SENSITIVE_ACTION_AUTHORITY_DENIED'::text,null::bytea,false; return;
    end if;
    if p_purpose not between 1 and 6 or length(p_target)<>64 or p_limit not between 1 and 20
        or p_window not between 60 and 3600 or p_lease not between 1 and 60 then raise exception 'Invalid proof policy'; end if;
    needs_factor := exists(select 1 from two_factor_authentications t where t.account_id=p_account and t.verified and t.revoked_at is null);
    -- COR08's executable existing-factor adapter is local TOTP. Other-only accounts
    -- fail closed; owner enrollment/provider PRs extend eligible proof adapters.
    if needs_factor and not exists(select 1 from two_factor_authentications t where t.account_id=p_account
        and t.verified and t.revoked_at is null and t.method=3 and t.totp_provider_type=1
        and (t.expiration is null or t.expiration>clock_timestamp())
        and t.totp_secret_ciphertext is not null and t.totp_secret_nonce is not null and t.totp_secret_tag is not null and t.totp_secret_version>0) then
        return query select false,'SENSITIVE_ACTION_FACTOR_UNAVAILABLE'::text,null::bytea,true; return;
    end if;
    select * into b from account_reauthentication_budgets where account_id=p_account for update;
    if not found then
        insert into account_reauthentication_budgets values(p_account,p_stamp,gen_random_uuid(),clock_timestamp(),0,0) returning * into b;
    elsif b.credential_stamp<>p_stamp or b.window_start+make_interval(secs=>p_window)<=clock_timestamp() then
        update account_reauthentication_budgets set credential_stamp=p_stamp,window_version=gen_random_uuid(),window_start=clock_timestamp(),admitted=0,failed=0
            where account_id=p_account returning * into b;
    end if;
    if b.admitted>=p_limit then return query select false,'SENSITIVE_ACTION_ATTEMPT_LIMIT'::text,null::bytea,needs_factor; return; end if;
    update account_reauthentication_budgets set admitted=admitted+1 where account_id=p_account;
    insert into sensitive_password_attempts values(p_attempt,p_account,p_stamp,b.window_version,p_session,family,a.hashed_password,
        p_purpose,p_target,cor08_factor_policy(p_account),needs_factor,clock_timestamp(),clock_timestamp()+make_interval(secs=>p_lease),'Pending');
    return query select true,'ADMITTED'::text,a.hashed_password,needs_factor;
end;
$$;

create or replace function cor08_abandon_password_proof(p_account uuid,p_stamp uuid,p_attempt uuid)
returns boolean
language plpgsql
as $$
declare r sensitive_password_attempts%rowtype;
begin
    perform cor02_lock_account_authority(p_account,'account');
    select * into r from sensitive_password_attempts where attempt_id=p_attempt and account_id=p_account and credential_stamp=p_stamp for update;
    if not found or r.state<>'Pending' then return false; end if;
    update sensitive_password_attempts set state='Abandoned' where attempt_id=p_attempt;
    update account_reauthentication_budgets set admitted=greatest(0,admitted-1)
        where account_id=p_account and credential_stamp=p_stamp and window_version=r.window_version;
    return true;
end;
$$;

create or replace function cor08_finish_password_proof(p_account uuid,p_stamp uuid,p_session text,p_attempt uuid,p_verified boolean,
    p_handle text,p_token text,p_minutes integer)
returns table(result boolean,code text,expiration timestamptz,factor_required boolean)
language plpgsql
as $$
declare r sensitive_password_attempts%rowtype; id uuid:=gen_random_uuid(); until_time timestamptz;
begin
    perform cor02_lock_account_authority(p_account,'factor');
    select * into r from sensitive_password_attempts where attempt_id=p_attempt and account_id=p_account and credential_stamp=p_stamp and session_hash=p_session for update;
    if not found or r.state<>'Pending' then return query select false,'SENSITIVE_ACTION_PROOF_CONFLICT'::text,null::timestamptz,false; return; end if;
    if not coalesce(p_verified,false) then
        update sensitive_password_attempts set state='Failed' where attempt_id=p_attempt;
        update account_reauthentication_budgets set failed=failed+1 where account_id=p_account and credential_stamp=p_stamp and window_version=r.window_version;
        return query select false,'SENSITIVE_ACTION_REAUTHENTICATION_FAILED'::text,null::timestamptz,r.factor_required; return;
    end if;
    if r.expiration<=clock_timestamp() or not cor08_live_sensitive_authority(p_account,p_stamp,p_session,r.family_id)
        or r.old_hash is distinct from (select hashed_password from accounts where account_id=p_account)
        or r.factor_policy<>cor08_factor_policy(p_account) then
        return query select false,'SENSITIVE_ACTION_AUTHORITY_CHANGED'::text,null::timestamptz,r.factor_required; return;
    end if;
    if p_minutes not between 1 and 60 or length(p_handle)<>64 or length(p_token)<>64 then raise exception 'Invalid grant policy'; end if;
    until_time := least(clock_timestamp()+make_interval(mins=>p_minutes),
        (select least(s.access_expiration,s.session_expiration,coalesce(s.cut_off,s.session_expiration)) from sessions s where s.access_token_hash=p_session));
    update sensitive_password_attempts set state='Succeeded' where attempt_id=p_attempt;
    insert into sensitive_action_proof_sessions values(id,p_handle,p_account,p_stamp,p_session,r.family_id,r.purpose,r.target_hash,r.factor_policy,
        r.factor_required,false,0,until_time,case when r.factor_required then 'Pending' else 'Granted' end);
    if r.factor_required then
        return query select true,'SENSITIVE_ACTION_FACTOR_PROOF_REQUIRED'::text,until_time,true; return;
    end if;
    insert into sensitive_action_grants values(p_token,id,p_account,p_stamp,p_session,r.family_id,r.purpose,r.target_hash,r.factor_policy,1,until_time,null);
    return query select true,'SENSITIVE_ACTION_TOKEN_ISSUED'::text,until_time,false;
end;
$$;

create or replace function cor08_reserve_factor_proof(p_account uuid,p_stamp uuid,p_session text,p_handle text,p_limit integer)
returns boolean
language plpgsql
as $$
declare r sensitive_action_proof_sessions%rowtype;
begin
    perform cor02_lock_account_authority(p_account,'factor');
    select * into r from sensitive_action_proof_sessions where handle_hash=p_handle and account_id=p_account
        and credential_stamp=p_stamp and session_hash=p_session for update;
    if not found or r.state<>'Pending' or not r.factor_required or r.factor_attempts>=p_limit or p_limit not between 1 and 20
        or r.expiration<=clock_timestamp() or not cor08_live_sensitive_authority(p_account,p_stamp,p_session,r.family_id)
        or r.factor_policy<>cor08_factor_policy(p_account) then return false; end if;
    update sensitive_action_proof_sessions set factor_attempts=factor_attempts+1 where proof_id=r.proof_id;
    return true;
end;
$$;

create or replace function cor08_finish_factor_proof(p_account uuid,p_stamp uuid,p_session text,p_handle text,p_token text)
returns table(result boolean,code text,expiration timestamptz,factor_required boolean)
language plpgsql
as $$
declare r sensitive_action_proof_sessions%rowtype;
begin
    perform cor02_lock_account_authority(p_account,'factor');
    select * into r from sensitive_action_proof_sessions where handle_hash=p_handle and account_id=p_account
        and credential_stamp=p_stamp and session_hash=p_session for update;
    if not found or r.state<>'Pending' or r.factor_attempts<1 or not r.factor_required or r.expiration<=clock_timestamp()
        or not cor08_live_sensitive_authority(p_account,p_stamp,p_session,r.family_id) or r.factor_policy<>cor08_factor_policy(p_account) then
        return query select false,'SENSITIVE_ACTION_AUTHORITY_CHANGED'::text,null::timestamptz,true; return;
    end if;
    update sensitive_action_proof_sessions set factor_complete=true,state='Granted' where proof_id=r.proof_id;
    insert into sensitive_action_grants values(p_token,r.proof_id,p_account,p_stamp,p_session,r.family_id,r.purpose,r.target_hash,r.factor_policy,1,r.expiration,null);
    return query select true,'SENSITIVE_ACTION_TOKEN_ISSUED'::text,r.expiration,false;
end;
$$;

create or replace function cor08_validate_sensitive_grant(p_account uuid,p_stamp uuid,p_session text,p_token text,
    p_purpose smallint,p_target text,p_consume boolean)
returns boolean
language plpgsql
as $$
declare g sensitive_action_grants%rowtype;
begin
    perform cor02_lock_account_authority(p_account,'factor');
    select * into g from sensitive_action_grants where token_hash=p_token for update;
    if not found or g.account_id is distinct from p_account or g.credential_stamp is distinct from p_stamp or g.session_hash is distinct from p_session
        or g.purpose is distinct from p_purpose or g.target_hash is distinct from p_target or g.policy_version<>1 or g.consumed_on is not null
        or g.expiration<=clock_timestamp() or not cor08_live_sensitive_authority(p_account,p_stamp,p_session,g.family_id)
        or g.factor_policy<>cor08_factor_policy(p_account)
        or not exists(select 1 from sensitive_action_proof_sessions p where p.proof_id=g.proof_id and p.state='Granted'
            and (not p.factor_required or p.factor_complete)) then return false; end if;
    if p_consume then update sensitive_action_grants set consumed_on=clock_timestamp() where token_hash=p_token; end if;
    return true;
end;
$$;

-- Old unbound entry points retain signatures and fail closed.
create or replace function set_account_login_failures(p_accountGuid uuid, p_failures smallint)
returns table(result boolean, code text)
language plpgsql
as $$
begin
    return query select false,'LOGIN_ATTEMPT_VERSION_REQUIRED'::text;
end;
$$;

-- Old unbound entry points retain signatures and fail closed.
create or replace function set_account_lockout(p_accountGuid uuid, p_expiration interval)
returns table(result boolean, code text)
language plpgsql
as $$
begin
    return query select false,'LOGIN_ATTEMPT_VERSION_REQUIRED'::text;
end;
$$;

-- Old unbound entry points retain signatures and fail closed.
create or replace function remove_account_lockout(p_accountGuid uuid)
returns table(result boolean, code text)
language plpgsql
as $$
begin
    return query select false,'LOGIN_ATTEMPT_VERSION_REQUIRED'::text;
end;
$$;

-- Old unbound entry points retain signatures and fail closed.
create or replace function successful_login(
    p_accountId uuid,
    p_accountSecurityStamp uuid)
returns table(result boolean, code text)
language plpgsql
as $$
begin
    return query select false,'LOGIN_ATTEMPT_VERSION_REQUIRED'::text;
end;
$$;

-- Old unbound entry points retain signatures and fail closed.
create or replace function issue_sensitive_action_token(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_sessionBindingHash text,
    p_tokenHash text,
    p_purpose smallint,
    p_createdOn timestamp with time zone,
    p_expiration timestamp with time zone,
    p_consumeExistingTokens boolean)
returns table(result boolean, code text, token_id uuid, expiration timestamp with time zone)
language plpgsql
as $$
begin
    return query select false,'SENSITIVE_ACTION_LEGACY_GRANT_DENIED'::text,null::uuid,null::timestamp with time zone;
end;
$$;

-- Old unbound entry points retain signatures and fail closed.
create or replace function validate_sensitive_action_token(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_sessionBindingHash text,
    p_tokenHash text,
    p_purpose smallint,
    p_consume boolean,
    p_moment timestamp with time zone)
returns table(result boolean, code text, expiration timestamp with time zone)
language plpgsql
as $$
begin
    return query select false,'SENSITIVE_ACTION_LEGACY_GRANT_DENIED'::text,null::timestamp with time zone;
end;
$$;

-- Old unbound entry points retain signatures and fail closed.
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
begin
    return query select false,'SENSITIVE_ACTION_GRANT_REQUIRED'::text,null::bigint,null::timestamp with time zone;
end;
$$;

-- Grant consumption and domain writes share this function/transaction.
create or replace function cor08_authorized_begin_authenticator_app_setup(
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
    p_totpKeyId text, p_totpEnrollmentId uuid, p_totpAlgorithm text, p_totpDigits integer, p_totpPeriodSeconds integer, p_totpClockSkewSteps integer,p_expectedRequestId uuid,p_expectedVersion bigint,
    p_grant_session text,p_grant_token text,p_grant_target text)
returns table(result boolean, code text, two_factor_index bigint, expiration timestamp with time zone)
language plpgsql
as $$
declare
    account_record accounts%rowtype;
    target_index bigint;
    provider_type smallint := coalesce(p_totpProviderType, 1)::smallint;
    moment timestamp with time zone; prior two_factor_authentications%rowtype; changed integer; request_version bigint;
begin
    if not cor08_validate_sensitive_grant(p_accountId,p_accountSecurityStamp,p_grant_session,p_grant_token,1::smallint,p_grant_target,true) then
        return query select false,'SENSITIVE_ACTION_GRANT_REQUIRED'::text,null::bigint,null::timestamp with time zone; return;
    end if;
    perform cor02_lock_account_authority(p_accountId, 'factor');
    perform cor12_lock_delivery(p_accountId);
    if exists(select 1 from delivery_candidates c join delivery_outbox o using(delivery_id) where c.account_id=p_accountId and c.purpose in ('factor-1','factor-2') and c.state='staged' and o.state in ('claimed','accepted','ambiguous')) then
        raise exception 'Setup delivery is in flight' using errcode='P1601';end if;
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

    select * into prior from two_factor_authentications t where t.account_id=p_accountId and not t.verified and t.revoked_at is null order by t.two_factor_index limit 1 for update;
    if found then
        if p_expectedRequestId is null or p_expectedVersion is null or prior.setup_request_id is distinct from p_expectedRequestId or prior.setup_version is distinct from p_expectedVersion or p_expectedVersion>=9007199254740991 then
            raise exception 'Setup predecessor changed' using errcode='P1601';end if;
        request_version:=p_expectedVersion+1;
    else
        if p_expectedRequestId is not null or p_expectedVersion is not null then raise exception 'Setup predecessor missing' using errcode='P1601';end if;
        request_version:=1;
    end if;
    select t.two_factor_index into target_index from two_factor_authentications t where t.account_id = p_accountId and t.verified = false and t.revoked_at is null order by t.created_on desc, t.two_factor_index desc limit 1 for update;
    if target_index is null then
        insert into two_factor_authentications(account_id, token, auth_id, created_on, lifespan, expiration, method, verified, priority, country, email_address, phone_number, phone_country_code, required, totp_secret_ciphertext, totp_secret_nonce, totp_secret_tag, totp_secret_version, totp_key_id, totp_enrollment_id, totp_algorithm, totp_digits, totp_period_seconds, totp_clock_skew_steps, totp_last_used_step, totp_provider_type, totp_provider_enrollment_id, totp_provider_account_binding_hash, setup_attempts, revoked_at, revoked_reason)
        values(p_accountId, p_setupTokenHash, nullif(trim(p_authId), ''), p_createdOn, p_expiration - p_createdOn, p_expiration, 3, false, 0, null, null, null, null, coalesce(p_required, true), p_totpSecretCiphertext, p_totpSecretNonce, p_totpSecretTag, p_totpSecretVersion, p_totpKeyId, p_totpEnrollmentId, p_totpAlgorithm, p_totpDigits, p_totpPeriodSeconds, p_totpClockSkewSteps, null, provider_type, null, null, 0, null, null) returning two_factor_authentications.two_factor_index into target_index;
    else
        update two_factor_authentications t set token = p_setupTokenHash, auth_id = nullif(trim(p_authId), ''), created_on = p_createdOn, lifespan = p_expiration - p_createdOn, expiration = p_expiration, method = 3, verified = false, priority = 0, country = null, email_address = null, phone_number = null, phone_country_code = null, required = coalesce(p_required, true), totp_secret_ciphertext = p_totpSecretCiphertext, totp_secret_nonce = p_totpSecretNonce, totp_secret_tag = p_totpSecretTag, totp_secret_version = p_totpSecretVersion, totp_key_id = p_totpKeyId, totp_enrollment_id = p_totpEnrollmentId, totp_algorithm = p_totpAlgorithm, totp_digits = p_totpDigits, totp_period_seconds = p_totpPeriodSeconds, totp_clock_skew_steps = p_totpClockSkewSteps, totp_last_used_step = null, totp_provider_type = provider_type, totp_provider_enrollment_id = null, totp_provider_account_binding_hash = null, setup_attempts = 0, revoked_at = null, revoked_reason = null where t.account_id = p_accountId and t.two_factor_index = target_index and t.verified = false and t.revoked_at is null;
    end if;
    get diagnostics changed=row_count;
    if changed<>1 then raise exception 'Setup write conflict' using errcode='P1601';end if;
    perform cor16_bind_setup(p_accountId,target_index,p_totpEnrollmentId,request_version,p_grant_token);
    perform cor16_require_setup(t,p_accountSecurityStamp,t.setup_family_id) from two_factor_authentications t where t.account_id=p_accountId and t.two_factor_index=target_index;
    delete from two_factor_authentications t where t.account_id = p_accountId and t.verified = false and t.revoked_at is null and t.two_factor_index <> target_index;
    perform cor02_require_live(p_expiration);
    perform cor02_require_live((select g.expiration from sensitive_action_grants g where g.token_hash=p_grant_token));
    update delivery_candidates c set state='superseded',terminal_at=clock_timestamp() where c.account_id=p_accountId and c.purpose in ('factor-1','factor-2') and c.state='staged';
    update delivery_outbox o set state='superseded',nonce=null,ciphertext=null,tag=null from delivery_candidates c where o.delivery_id=c.delivery_id and c.account_id=p_accountId and c.purpose in ('factor-1','factor-2') and c.state='superseded' and o.state='queued';
    return query select true, 'AUTHENTICATOR_SETUP_PENDING'::text, target_index, p_expiration;
exception
    when sqlstate 'P1601' then return query select false,'AUTHENTICATOR_SETUP_CONFLICT'::text,null::bigint,null::timestamptz;
    when sqlstate 'P0202' then
        return query select false, 'AUTHENTICATOR_SETUP_INVALID_EXPIRATION'::text, null::bigint, null::timestamp with time zone;
 when unique_violation then
    return query select false, 'TWO_FACTOR_AUTHENTICATOR_APP_ALREADY_ATTACHED'::text, null::bigint, null::timestamp with time zone;
when others then
    return query select false, 'AUTHENTICATOR_SETUP_FAILED'::text, null::bigint, null::timestamp with time zone;
end;
$$;

-- Old unbound entry points retain signatures and fail closed.
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
begin
    return query select false,'SENSITIVE_ACTION_GRANT_REQUIRED'::text,coalesce(p_method,0)::smallint,array[]::smallint[],array[]::smallint[];
end;
$$;

-- Grant consumption and domain writes share this function/transaction.
create or replace function cor08_authorized_remove_twofactor_method(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_method smallint,
    p_now timestamp with time zone,
    p_grant_session text,p_grant_token text,p_grant_target text)
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
    if not cor08_validate_sensitive_grant(p_accountId,p_accountSecurityStamp,p_grant_session,p_grant_token,2::smallint,p_grant_target,true) then
        return query select false,'SENSITIVE_ACTION_GRANT_REQUIRED'::text,coalesce(p_method,0)::smallint,array[]::smallint[],array[]::smallint[]; return;
    end if;
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

    perform cor02_require_live((select g.expiration from sensitive_action_grants g where g.token_hash=p_grant_token));
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
