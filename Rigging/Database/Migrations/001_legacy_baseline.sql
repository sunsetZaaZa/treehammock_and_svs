-- Treehammock canonical greenfield PostgreSQL baseline.
--
-- This project is not deployed anywhere yet, so this file intentionally creates
-- the final development schema directly. No compatibility/backfill layer is included.
-- Repository-facing routines are row-returning PostgreSQL functions invoked as
-- `select * from function(@params...)`.

create extension if not exists pgcrypto;

create table if not exists accounts(
    account_id uuid primary key,
    email_address text not null,
    username text null,
    hashed_password bytea not null default decode(repeat('00', 128), 'hex'),
    created_on timestamp with time zone not null default now(),
    web_key text not null default gen_random_uuid()::text,
    verify_status smallint not null default 0,
    salt_one bytea not null default decode(repeat('00', 64), 'hex'),
    siv bytea not null default decode(repeat('00', 32), 'hex'),
    nonce bytea not null default decode(repeat('00', 16), 'hex'),
    unlock_when timestamp with time zone null,
    login_failures smallint not null default 0,
    features smallint not null default 1,
    entitlement_version bigint not null default 1 check(entitlement_version between 1 and 9007199254740991),
    entitlement_fingerprint text not null default '',
    two_factor_access_token text null,
    two_factor_auth_method smallint not null default 0,
    two_auth_usage smallint null,
    country smallint not null default 0,
    cut_off timestamp with time zone null,
    locked_down smallint null,
    security_stamp uuid not null default gen_random_uuid(),
    constraint ck_accounts_login_failures_nonnegative check (login_failures >= 0)
);

create unique index if not exists ux_accounts_email_address_lower
    on accounts(lower(email_address));

create unique index if not exists ux_accounts_username_lower
    on accounts(lower(username))
    where username is not null;

create unique index if not exists ux_accounts_web_key
    on accounts(web_key);

create index if not exists ix_accounts_security_stamp
    on accounts(account_id, security_stamp);

create table if not exists account_verifications(
    verification_index bigint generated always as identity primary key,
    account_id uuid not null references accounts(account_id) on delete cascade,
    verify_key_hash text not null,
    proof_version uuid not null default gen_random_uuid(),
    account_security_stamp uuid not null,
    verify_status smallint not null default 0,
    sent_when timestamp with time zone null,
    expiration interval null,
    created_on timestamp with time zone not null default now()
);

create unique index if not exists ux_account_verifications_verify_key_hash
    on account_verifications(verify_key_hash);

-- Current means started, sent or refreshed; replaced is a distinct terminal state.
create unique index if not exists ux_account_verifications_current
    on account_verifications(account_id) where verify_status in (0, 2, 4);
create unique index if not exists ux_account_verifications_proof_version
    on account_verifications(proof_version);

create table if not exists account_email_change_requests(
    account_id uuid primary key references accounts(account_id) on delete cascade,
    new_email_address text not null,
    verify_key_hash text not null unique,
    requested_at timestamp with time zone not null default now(),
    expiration timestamp with time zone not null,
    account_security_stamp uuid not null,
    request_id uuid null,origin_email text null,origin_family uuid null,origin_factor_policy text null,authorized_until timestamptz null,origin_grant_hash text null,
    constraint ck_cor17_email_binding check (
        (request_id is null and origin_email is null and origin_family is null and origin_factor_policy is null and authorized_until is null and origin_grant_hash is null) or
        (request_id is not null and origin_email is not null and origin_family is not null and origin_factor_policy is not null and authorized_until is not null and origin_grant_hash is not null))
);

create unique index if not exists ux_account_email_change_new_email_lower
    on account_email_change_requests(lower(new_email_address));

create unique index ux_cor17_email_request_id on account_email_change_requests(request_id) where request_id is not null;

create index if not exists ix_account_email_change_expiration
    on account_email_change_requests(expiration);

create index if not exists ix_account_verifications_account_status
    on account_verifications(account_id, verify_status);

create table if not exists sessions(
    access_token_hash text primary key,
    -- Stable logical family. security_stamp identifies the current token generation.
    session_id uuid not null default gen_random_uuid(),
    generation bigint not null default 1 check (generation between 1 and 9007199254740991),
    protocol_version integer not null default 2 check (protocol_version = 2),
    refresh_credential_hash text null check (length(refresh_credential_hash) = 64),
    token_issued_on timestamp with time zone not null default clock_timestamp(),
    account_id uuid not null references accounts(account_id) on delete cascade,
    refresh_token bytea not null default decode(repeat('00', 64), 'hex'),
    refreshes smallint not null default 0,
    refresh_limit smallint not null default 0,
    created_on timestamp with time zone not null default now(),
    session_lifespan interval null,
    access_expiration timestamp with time zone not null,
    session_expiration timestamp with time zone not null,
    cut_off timestamp with time zone null,
    features smallint not null default 1,
    entitlement_version bigint not null default 1 check(entitlement_version between 1 and 9007199254740991),
    security_stamp uuid not null default gen_random_uuid(),
    account_security_stamp uuid not null,
    constraint ck_sessions_refreshes_nonnegative check (refreshes >= 0),
    constraint ck_sessions_refresh_limit_nonnegative check (refresh_limit >= 0),
    constraint ck_sessions_expiration_order check (session_expiration >= created_on),
    constraint ck_sessions_access_not_after_session check (access_expiration <= session_expiration)
);

create unique index if not exists ux_sessions_session_id
    on sessions(session_id, generation);

create unique index if not exists ux_sessions_refresh_credential_hash
    on sessions(refresh_credential_hash) where refresh_credential_hash is not null;

create index if not exists ix_sessions_account_session_id
    on sessions(account_id, session_id);

create index if not exists ix_sessions_account_active
    on sessions(account_id, session_expiration desc, created_on desc);

create index if not exists ix_sessions_account_stamp
    on sessions(account_id, account_security_stamp);

create index if not exists ix_sessions_expiration
    on sessions(session_expiration);


create table if not exists account_sensitive_action_tokens(
    token_id uuid primary key default gen_random_uuid(),
    account_id uuid not null references accounts(account_id) on delete cascade,
    session_binding_hash text not null,
    token_hash text not null,
    purpose smallint not null,
    created_on timestamp with time zone not null default now(),
    expiration timestamp with time zone not null,
    consumed_on timestamp with time zone null,
    account_security_stamp uuid not null,
    attempts integer not null default 0,
    constraint ck_sensitive_action_purpose_positive check (purpose > 0),
    constraint ck_sensitive_action_expiration_order check (expiration > created_on),
    constraint ck_sensitive_action_attempts_nonnegative check (attempts >= 0)
);

create unique index if not exists ux_sensitive_action_token_hash
    on account_sensitive_action_tokens(token_hash);

create index if not exists ix_sensitive_action_account_session_purpose
    on account_sensitive_action_tokens(account_id, session_binding_hash, purpose, expiration desc);

create index if not exists ix_sensitive_action_expiration
    on account_sensitive_action_tokens(expiration);

create table if not exists two_factor_authentications(
    two_factor_index bigint generated by default as identity (minvalue 0 start with 0 no cycle) not null,
    account_id uuid not null references accounts(account_id) on delete cascade,
    token text null,
    auth_id text null,
    created_on timestamp with time zone not null default now(),
    lifespan interval null,
    expiration timestamp with time zone null,
    method smallint not null,
    verified boolean not null default false,
    priority smallint not null default 0,
    country smallint null,
    email_address text null,
    phone_number text null,
    phone_country_code text null,
    required boolean not null default false,
    totp_secret_ciphertext bytea null,
    totp_secret_nonce bytea null,
    totp_secret_tag bytea null,
    totp_secret_version integer null,
    totp_key_id text null,
    totp_enrollment_id uuid null,
    totp_algorithm text null,
    totp_digits integer null,
    totp_period_seconds integer null,
    totp_clock_skew_steps integer null,
    totp_row_version bigint null,
    totp_last_used_step bigint null,
    totp_provider_type smallint null,
    totp_provider_enrollment_id text null,
    totp_provider_account_binding_hash text null,
    setup_request_id uuid null,
    setup_version bigint null,
    setup_origin_stamp uuid null,
    setup_family_id uuid null,
    setup_factor_policy text null,
    setup_authorized_until timestamp with time zone null,
    setup_attempts smallint not null default 0,
    revoked_at timestamp with time zone null,
    revoked_reason text null,
    constraint ck_two_factor_setup_attempts_nonnegative check(setup_attempts >= 0),
    constraint ck_two_factor_totp_provider_type check(totp_provider_type in (1, 2)),
    primary key(account_id, two_factor_index)
);

-- Current greenfield v2 contract. This trigger removes abandoned material on every writer/lifecycle path.
create or replace function cor15_enrollment_contract()
returns trigger language plpgsql as $$
begin
    if new.method <> 3 or new.revoked_at is not null or new.totp_secret_ciphertext is null then
        new.totp_secret_ciphertext := null; new.totp_secret_nonce := null; new.totp_secret_tag := null;
        new.totp_secret_version := null; new.totp_last_used_step := null; new.totp_provider_type := null;
        new.totp_provider_enrollment_id := null; new.totp_provider_account_binding_hash := null;
        new.totp_key_id := null; new.totp_enrollment_id := null; new.totp_algorithm := null;
        new.totp_digits := null; new.totp_period_seconds := null; new.totp_clock_skew_steps := null; new.totp_row_version := null;
    else
        if tg_op = 'UPDATE' and old.method = 3 and old.verified and old.revoked_at is null and
            old.totp_enrollment_id is distinct from new.totp_enrollment_id then
            raise exception 'Verified TOTP enrollment identity is immutable' using errcode='23514';
        end if;
        if tg_op = 'UPDATE' and old.totp_enrollment_id = new.totp_enrollment_id then
            if new.account_id is distinct from old.account_id or new.totp_algorithm is distinct from old.totp_algorithm or
                new.totp_digits is distinct from old.totp_digits or new.totp_period_seconds is distinct from old.totp_period_seconds or
                new.totp_clock_skew_steps is distinct from old.totp_clock_skew_steps then
                raise exception 'TOTP parameters are immutable within an enrollment' using errcode='23514';
            end if;
            if old.totp_last_used_step is not null and (new.totp_last_used_step is null or new.totp_last_used_step < old.totp_last_used_step) then
                raise exception 'TOTP replay state cannot decrease' using errcode='23514';
            end if;
            new.totp_row_version := old.totp_row_version + case when
                (new.totp_key_id,new.totp_secret_ciphertext,new.totp_secret_nonce,new.totp_secret_tag) is distinct from
                (old.totp_key_id,old.totp_secret_ciphertext,old.totp_secret_nonce,old.totp_secret_tag) then 1 else 0 end;
        else
            new.totp_row_version := 1;
        end if;
    end if;
    return new;
end;
$$;



create trigger cor15_enrollment_contract_before_write before insert or update on two_factor_authentications
for each row execute function cor15_enrollment_contract();
alter table two_factor_authentications add constraint ck_cor15_enrollment_shape check (
    (totp_secret_ciphertext is null and totp_secret_nonce is null and totp_secret_tag is null and totp_secret_version is null and
     totp_key_id is null and totp_enrollment_id is null and totp_algorithm is null and totp_digits is null and
     totp_period_seconds is null and totp_clock_skew_steps is null and totp_row_version is null and totp_last_used_step is null and
     totp_provider_type is null and totp_provider_enrollment_id is null and totp_provider_account_binding_hash is null and
     (method <> 3 or revoked_at is not null or not verified))
    or
    (method = 3 and revoked_at is null and totp_provider_type = 1 and totp_provider_type is not null and totp_secret_version = 2 and
     octet_length(totp_secret_ciphertext) between 20 and 64 and octet_length(totp_secret_nonce) = 12 and octet_length(totp_secret_tag) = 16 and
     totp_enrollment_id is not null and totp_enrollment_id <> '00000000-0000-0000-0000-000000000000'::uuid and
     totp_key_id ~ '^[A-Za-z0-9_-]{1,64}$' and totp_algorithm in ('SHA1','SHA256','SHA512') and totp_digits in (6,7,8) and
     totp_period_seconds between 15 and 120 and totp_clock_skew_steps between 0 and 2 and totp_row_version > 0 and
     totp_provider_enrollment_id is null and totp_provider_account_binding_hash is null and
     totp_secret_ciphertext is not null and totp_secret_nonce is not null and totp_secret_tag is not null and totp_secret_version is not null and
     totp_key_id is not null and totp_algorithm is not null and totp_digits is not null and totp_period_seconds is not null and
     totp_clock_skew_steps is not null and totp_row_version is not null));
create unique index ux_cor15_totp_enrollment_id on two_factor_authentications(totp_enrollment_id) where totp_enrollment_id is not null;

create index if not exists ix_two_factor_account_verified
    on two_factor_authentications(account_id, verified, priority);

create unique index if not exists ux_two_factor_one_pending_setup_per_account
    on two_factor_authentications(account_id)
    where verified = false and revoked_at is null;

create unique index if not exists ux_two_factor_one_verified_email_per_account
    on two_factor_authentications(account_id)
    where verified = true and method = 1 and revoked_at is null;

create unique index if not exists ux_two_factor_one_verified_sms_per_account
    on two_factor_authentications(account_id)
    where verified = true and method = 2 and revoked_at is null;

create unique index if not exists ux_two_factor_one_verified_authenticator_app
    on two_factor_authentications(account_id)
    where verified = true and method = 3 and revoked_at is null;


create table if not exists pending_two_factor_sessions(
    pre_auth_access_token_hash text primary key,
    progress_version bigint not null default 1 check(progress_version between 1 and 9007199254740991),
    challenge_id uuid null,
    login_metadata jsonb null,
    account_id uuid not null references accounts(account_id) on delete cascade,
    account_security_stamp uuid not null,
    two_auth_usage smallint null,
    created_on timestamp with time zone not null default now(),
    expiration timestamp with time zone not null,
    selected_two_factor_configuration smallint null,
    state smallint not null default 1,
    available_configurations smallint[] not null default array[]::smallint[],
    required_methods smallint[] not null default array[]::smallint[],
    completed_methods smallint[] not null default array[]::smallint[],
    current_expected_method smallint null,
    selected_at timestamp with time zone null,
    completed_at timestamp with time zone null,
    challenged_method smallint null,
    chosen_destination smallint null,
    challenge_code_hash text null,
    challenge_provider_transaction_id text null,
    challenge_expiration timestamp with time zone null,
    challenge_attempts smallint not null default 0,
    challenge_resends smallint not null default 0,
    next_challenge_allowed_at timestamp with time zone null,
    constraint ck_pending_two_factor_selected_configuration check(selected_two_factor_configuration is null or selected_two_factor_configuration between 0 and 6),
    constraint ck_pending_two_factor_state_range check(state between 1 and 7),
    constraint ck_pending_two_factor_current_expected_method check(current_expected_method is null or current_expected_method between 1 and 3),
    constraint ck_pending_two_factor_attempts_nonnegative check(challenge_attempts >= 0),
    constraint ck_pending_two_factor_resends_nonnegative check(challenge_resends >= 0)
);

create index if not exists ix_pending_two_factor_account_current
    on pending_two_factor_sessions(account_id, account_security_stamp, expiration desc);


-- COR12: one current candidate per account/purpose, encrypted payload only.
create table if not exists delivery_candidates(
    delivery_id uuid primary key,
    account_id uuid not null references accounts(account_id) on delete cascade,
    account_stamp uuid not null,
    purpose text not null check(purpose in ('verify','unlock','reset','email','delete','factor-1','factor-2','reset-factor','email-notice','activation')),
    proof_hash text not null,
    expires_at timestamptz not null,
    metadata_json text not null,
    predecessor text not null,
    state text not null check(state in ('staged','published','superseded','rejected','expired')),
    created_at timestamptz not null default clock_timestamp(),
    terminal_at timestamptz null
);
create unique index if not exists ux_delivery_candidates_current
    on delivery_candidates(account_id,purpose) where state='staged' and purpose<>'email-notice';
create unique index if not exists ux_delivery_candidates_email
    on delivery_candidates(lower(metadata_json::jsonb->>'newEmailAddress')) where purpose='email' and state='staged';
create index if not exists ix_delivery_candidates_proof on delivery_candidates(purpose,proof_hash);
create table if not exists delivery_outbox(
    delivery_id uuid primary key references delivery_candidates(delivery_id) on delete cascade,
    state text not null check(state in ('queued','claimed','accepted','ambiguous','published','rejected','superseded','expired')),
    key_version integer not null check(key_version>0),
    nonce bytea null,
    ciphertext bytea null,
    tag bytea null,
    lease_id uuid null,
    lease_until timestamptz null,
    attempts integer not null default 0,
    next_attempt timestamptz not null default clock_timestamp(),
    constraint ck_delivery_payload check((nonce is null and ciphertext is null and tag is null)
        or (nonce is not null and ciphertext is not null and tag is not null
            and octet_length(nonce)=12 and octet_length(tag)=16 and octet_length(ciphertext) between 1 and 65536))
);
create index if not exists ix_delivery_outbox_work on delivery_outbox(state,next_attempt);

-- COR23I current greenfield setup: one immutable identity/receipt per attempted submission.
create table if not exists delivery_attempts(
    attempt_id uuid primary key,
    delivery_id uuid not null references delivery_outbox(delivery_id) on delete cascade,
    attempt_number integer not null check(attempt_number between 1 and 5),
    state text not null check(state in ('claimed','accepted','not_submitted','rejected','unknown')),
    provider text not null default 'none' check(provider ~ '^[a-z0-9-]{1,32}$'),
    receipt_id text null check(receipt_id is null or (length(receipt_id) between 1 and 128 and receipt_id !~ '[^A-Za-z0-9_.@:-]')),
    code text not null default 'DELIVERY_CLAIMED' check(code ~ '^[A-Z0-9_]{1,64}$'),
    can_retry boolean not null default false check(not can_retry or state='not_submitted'),
    created_at timestamptz not null default clock_timestamp(),
    recorded_at timestamptz null,
    unique(delivery_id,attempt_number)
);

create or replace function cor23i_attempt_identity()
returns trigger language plpgsql as $$
begin
    if new.attempt_id is distinct from old.attempt_id or new.delivery_id is distinct from old.delivery_id
        or new.attempt_number is distinct from old.attempt_number or new.created_at is distinct from old.created_at then
        raise exception 'Delivery attempt identity is immutable' using errcode='P2301';end if;
    if old.state in ('accepted','not_submitted','rejected') and new is distinct from old then
        raise exception 'Definitive delivery receipt is immutable' using errcode='P2301';end if;
    if old.state='unknown' and new.state not in ('unknown','accepted','rejected') then
        raise exception 'Unknown delivery cannot become retryable' using errcode='P2301';end if;
    return new;
end;
$$;
create trigger cor23i_delivery_attempt_identity before update on delivery_attempts
for each row execute function cor23i_attempt_identity();



create or replace function resolve_available_twofactor_configurations(p_accountId uuid)
returns smallint[]
language sql
volatile
as $$
    with usable_methods as (
        select distinct t.method::smallint as method
          from two_factor_authentications t
          join accounts a on a.account_id = t.account_id
         where t.account_id = p_accountId
           and t.verified = true
           and t.revoked_at is null
           and (t.expiration is null or t.expiration > clock_timestamp())
           and (
                (t.method = 1 and nullif(trim(a.email_address), '') is not null)
                or (t.method = 2 and nullif(trim(t.phone_number), '') is not null)
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
           )
    ), flags as (
        select coalesce(bool_or(method = 1), false) as has_email,
               coalesce(bool_or(method = 2), false) as has_sms,
               coalesce(bool_or(method = 3), false) as has_authenticator_app
          from usable_methods
    )
    select coalesce(array_agg(option_row.configuration order by option_row.ordinal), array[]::smallint[])
      from flags
      cross join lateral (
        values
            (1, 1::smallint, flags.has_sms),
            (2, 2::smallint, flags.has_email),
            (3, 3::smallint, flags.has_authenticator_app),
            (4, 4::smallint, flags.has_sms and flags.has_authenticator_app),
            (5, 5::smallint, flags.has_email and flags.has_authenticator_app)
      ) as option_row(ordinal, configuration, is_available)
     where option_row.is_available;
$$;

create table if not exists account_recoveries(
    account_id uuid not null references accounts(account_id) on delete cascade,
    created_on timestamp with time zone not null default now(),
    status smallint not null,
    topic smallint not null,
    expiration timestamp with time zone not null,
    token_hash text not null,
    method smallint not null,
    lockout_security_stamp uuid not null,
    lockout_unlock_when timestamp with time zone not null,
    lockout_attempt_version uuid not null,
    request_version uuid not null default gen_random_uuid(),
    primary key(account_id, token_hash)
);

create unique index if not exists ux_account_recoveries_token_hash
    on account_recoveries(token_hash);


create unique index if not exists ux_account_recoveries_current
    on account_recoveries(account_id) where topic = 1 and status in (1, 2, 3, 6);
create unique index if not exists ux_account_recoveries_request_version
    on account_recoveries(request_version);

create table if not exists password_reset_requests(
    factor_policy_version text not null,
    password_reset_request_id uuid primary key,
    account_id uuid not null references accounts(account_id) on delete cascade,
    method text not null,
    delivery_channel text null,
    key_code_hash text null,
    key_code_hash_version integer null,
    destination_fingerprint text not null,
    destination_masked text not null,
    requires_key_code boolean not null default true,
    requires_totp boolean not null default false,
    created_at timestamp with time zone not null default now(),
    expires_at timestamp with time zone not null,
    consumed_at timestamp with time zone null,
    cancelled_at timestamp with time zone null,
    attempt_count integer not null default 0,
    max_attempts integer not null,
    requested_by_ip inet null,
    requested_by_user_agent text null,
    account_security_stamp_at_request uuid not null,
    constraint ck_password_reset_method check (
        method in ('sms', 'email')
    ),
    constraint ck_password_reset_delivery_channel check (
        delivery_channel is not null and delivery_channel in ('email', 'sms')
    ),
    constraint ck_password_reset_key_code_hash_not_blank check (key_code_hash is null or length(btrim(key_code_hash)) > 0),
    constraint ck_password_reset_key_code_hash_version_positive check (key_code_hash_version is null or key_code_hash_version > 0),
    constraint ck_password_reset_destination_fingerprint_not_blank check (length(btrim(destination_fingerprint)) > 0),
    constraint ck_password_reset_destination_masked_not_blank check (length(btrim(destination_masked)) > 0),
    constraint ck_password_reset_attempt_count_nonnegative check (attempt_count >= 0),
    constraint ck_password_reset_max_attempts_positive check (max_attempts > 0),
    constraint ck_password_reset_expiration check (expires_at > created_at),
    constraint ck_password_reset_consumed_after_created check (consumed_at is null or consumed_at >= created_at),
    constraint ck_password_reset_cancelled_after_created check (cancelled_at is null or cancelled_at >= created_at),
    constraint ck_password_reset_method_requirements check (
        delivery_channel is not null and (
        (method = 'sms' and delivery_channel = 'sms' and requires_key_code = true and requires_totp = false and key_code_hash is not null and key_code_hash_version is not null)
        or
        (method = 'email' and delivery_channel = 'email' and requires_key_code = true and requires_totp = false and key_code_hash is not null and key_code_hash_version is not null)
        )
    )
);

create unique index if not exists ux_password_reset_requests_one_active_per_account
    on password_reset_requests(account_id)
    where consumed_at is null
      and cancelled_at is null;

create index if not exists ix_password_reset_requests_account_created
    on password_reset_requests(account_id, created_at desc);

create index if not exists ix_password_reset_requests_expires_at
    on password_reset_requests(expires_at);

create index if not exists ix_password_reset_requests_destination_fingerprint_active
    on password_reset_requests(destination_fingerprint)
    where consumed_at is null
      and cancelled_at is null;

create table if not exists pending_password_reset_sessions(
    session_version bigint not null default 1 check(session_version > 0),
    challenge_version bigint not null default 0 check(challenge_version >= 0),
    factor_policy_version text not null,
    account_security_stamp uuid not null,
    reset_access_token_hash text primary key,
    password_reset_request_id uuid not null unique references password_reset_requests(password_reset_request_id) on delete cascade,
    account_id uuid not null references accounts(account_id) on delete cascade,
    bootstrap_proof smallint not null,
    state smallint not null,
    available_configurations smallint[] not null default array[]::smallint[],
    selected_two_factor_configuration smallint null,
    required_methods smallint[] not null default array[]::smallint[],
    completed_methods smallint[] not null default array[]::smallint[],
    current_expected_method smallint null,
    challenge_code_hash text null,
    challenge_expiration timestamp with time zone null,
    challenge_attempts integer not null default 0,
    challenge_resends integer not null default 0,
    next_challenge_allowed_at timestamp with time zone null,
    created_on timestamp with time zone not null default now(),
    expires_at timestamp with time zone not null,
    selected_at timestamp with time zone null,
    two_factor_completed_at timestamp with time zone null,
    password_changed_at timestamp with time zone null,
    revoked_at timestamp with time zone null,
    revoked_reason text null,
    constraint ck_pending_password_reset_hash_not_blank check(length(btrim(reset_access_token_hash)) > 0),
    constraint ck_pending_password_reset_bootstrap_proof check(bootstrap_proof between 0 and 3),
    constraint ck_pending_password_reset_state check(state between 1 and 10),
    constraint ck_pending_password_reset_selected_configuration check(selected_two_factor_configuration is null or selected_two_factor_configuration between 0 and 6),
    constraint ck_pending_password_reset_current_expected_method check(current_expected_method is null or current_expected_method between 1 and 3),
    constraint ck_pending_password_reset_attempts_nonnegative check(challenge_attempts >= 0),
    constraint ck_pending_password_reset_resends_nonnegative check(challenge_resends >= 0),
    constraint ck_pending_password_reset_expiration check(expires_at > created_on),
    constraint ck_pending_password_reset_revoked_reason check(revoked_reason is null or length(btrim(revoked_reason)) > 0)
);

create index if not exists ix_pending_password_reset_sessions_account_current
    on pending_password_reset_sessions(account_id, expires_at desc)
    where revoked_at is null;

create index if not exists ix_pending_password_reset_sessions_request
    on pending_password_reset_sessions(password_reset_request_id)
    where password_reset_request_id is not null;

create index if not exists ix_pending_password_reset_sessions_expiration
    on pending_password_reset_sessions(expires_at)
    where revoked_at is null;

create table if not exists password_reset_rate_limits(
    rate_limit_key text primary key,
    window_started_at timestamp with time zone not null,
    request_count integer not null default 0,
    last_request_at timestamp with time zone null,
    blocked_until timestamp with time zone null,
    constraint ck_password_reset_rate_limit_key_not_blank check (length(btrim(rate_limit_key)) > 0),
    constraint ck_password_reset_rate_limit_request_count_nonnegative check (request_count >= 0),
    constraint ck_password_reset_rate_limit_last_request_after_window check (last_request_at is null or last_request_at >= window_started_at)
);

create index if not exists ix_password_reset_rate_limits_blocked_until
    on password_reset_rate_limits(blocked_until)
    where blocked_until is not null;

create index if not exists ix_password_reset_rate_limits_window_started
    on password_reset_rate_limits(window_started_at);

create table if not exists password_reset_events(
    password_reset_event_id bigint generated always as identity primary key,
    password_reset_request_id uuid null,
    account_id uuid null references accounts(account_id) on delete set null,
    event_type text not null,
    code text not null,
    created_at timestamp with time zone not null default now(),
    constraint ck_password_reset_events_event_type check (length(btrim(event_type)) > 0),
    constraint ck_password_reset_events_code check (length(btrim(code)) > 0)
);

create index if not exists ix_password_reset_events_account_time
    on password_reset_events(account_id, created_at desc);

create index if not exists ix_password_reset_events_request_time
    on password_reset_events(password_reset_request_id, created_at desc);


-- COR19 current trusted authority; historical activations are never entitlement sources.
create table if not exists entitlement_grants(
    grant_id uuid primary key,
    account_id uuid not null references accounts(account_id) on delete cascade,
    origin_stamp uuid not null,
    catalog text not null check(catalog='treehammock-v1'),
    tier smallint not null check(tier in (1,2)),
    term smallint not null check(term in (1,2,3,6,7,8,9,10,11)),
    cadence smallint not null check(cadence in (0,1)),
    start_anchor text not null check(start_anchor in ('redemption','approved-boundary')),
    denied_capabilities text[] not null default array[]::text[],
    approved_start timestamptz null,
    authorized_end timestamptz null,
    max_cycles integer not null check(max_cycles between 1 and 1000),
    redeem_before timestamptz not null,
    issuer name not null,
    issuer_reference text not null check(length(issuer_reference) between 1 and 256),
    version bigint not null default 1 check(version between 1 and 9007199254740991),
    state text not null default 'approved' check(state in ('approved','active','revoked')),
    issued_at timestamptz not null default clock_timestamp(),
    activated_at timestamptz null,
    starts_at timestamptz null,
    eligibility_until timestamptz null,
    materialized_cycle integer not null default 0,
    materialized_until timestamptz null,
    revoked_at timestamptz null,
    constraint ck_cor20_approval check ((start_anchor='redemption' and approved_start is null) or (start_anchor='approved-boundary' and approved_start is not null)),
    constraint ck_cor20_cycles check ((cadence=1 or max_cycles=1) and (term<>11 or (cadence=0 and max_cycles=1)) and materialized_cycle between 0 and max_cycles),
    constraint ck_cor20_denials check (denied_capabilities <@ array['account.read','account.manage']::text[] and cardinality(denied_capabilities)<=2),
    constraint ck_cor20_calendar_state check ((starts_at is null and eligibility_until is null and materialized_cycle=0 and materialized_until is null) or
        (starts_at is not null and materialized_cycle>=1 and (eligibility_until is null or eligibility_until>starts_at) and (term=11 or eligibility_until is not null)))
);
create table if not exists entitlement_grant_cycles(
    grant_id uuid not null references entitlement_grants(grant_id) on delete cascade,
    cycle integer not null check(cycle between 1 and 1000),
    starts_at timestamptz not null,
    ends_at timestamptz null,
    recorded_at timestamptz not null default clock_timestamp(),
    actor text not null,
    credential_stamp uuid not null,
    primary key(grant_id,cycle)
);
create index if not exists ix_entitlement_grants_account on entitlement_grants(account_id,grant_id);
create table if not exists grant_activation_requests(
    request_id uuid primary key,
    grant_id uuid not null unique references entitlement_grants(grant_id) on delete cascade,
    account_id uuid not null references accounts(account_id) on delete cascade,
    grant_version bigint not null,
    origin_stamp uuid not null,
    family_id uuid not null,
    proof_hash text null check(proof_hash is null or proof_hash ~ '^[a-f0-9]{64}$'),
    expires_at timestamptz not null,
    state text not null check(state in ('queued','pending','active','revoked')),
    consumed_at timestamptz null
);
create table if not exists entitlement_grant_audit(
    audit_id bigint generated always as identity primary key,
    grant_id uuid not null,
    account_id uuid not null,
    grant_version bigint not null,
    action text not null check(action in ('issued','placed','published','redeemed','revoked','renewed')),
    actor text not null,
    credential_stamp uuid not null,
    family_id uuid null,
    happened_at timestamptz not null default clock_timestamp(),
    approval jsonb null
);
revoke all on entitlement_grants,entitlement_grant_cycles,grant_activation_requests,entitlement_grant_audit from public;

create table if not exists activations(
    activation_id bigint generated always as identity primary key,
    account_id uuid not null references accounts(account_id) on delete cascade,
    created_on timestamp with time zone not null default now(),
    term interval not null,
    off_at timestamp with time zone not null,
    feature_set smallint not null,
    code text not null,
    status smallint not null,
    day_duration smallint not null default 0,
    duration_repeat smallint not null default 0,
    platform_backer smallint null,
    platform_text text null,
    delayed_start timestamp with time zone null
);

create unique index if not exists ux_activations_code
    on activations(code);

create table if not exists delete_standby(
    account_id uuid primary key references accounts(account_id) on delete cascade,
    pass_phrase_hash text null,
    delete_token_hash text not null unique,
    expiration timestamp with time zone not null,
    verified boolean not null default false,
    request_id uuid not null unique,
    origin_stamp uuid not null,
    origin_email text not null,
    origin_family uuid not null,
    origin_factor_policy text not null,
    authorized_until timestamptz not null,
    constraint ck_cor18_delete_authority check(authorized_until<=expiration and request_id<>'00000000-0000-0000-0000-000000000000'::uuid)
);

create index if not exists ix_delete_standby_expiration
    on delete_standby(expiration);

-- Admission state survives cancellation, delivery failure and proof cleanup.
create table account_delete_budgets(
    account_id uuid primary key references accounts(account_id) on delete cascade,
    window_start timestamptz not null,
    requested_count integer not null check(requested_count>0),
    next_request_allowed_at timestamptz not null,
    failed_finalize_attempts integer not null default 0,
    finalize_locked_until timestamptz null
);
create table account_delete_admissions(
    account_id uuid primary key references accounts(account_id) on delete cascade,
    admission_id uuid not null unique,
    proof_hash text not null,
    origin_stamp uuid not null,
    origin_email text not null,
    origin_family uuid not null,
    origin_factor_policy text not null,
    authorized_until timestamptz not null,
    expires_at timestamptz not null,
    grant_hash text not null
);

create table if not exists account_delete_events(
    delete_event_id bigint generated always as identity primary key,
    account_id uuid null,
    event_type text not null,
    code text not null,
    request_id uuid null,
    credential_stamp uuid null,
    created_at timestamp with time zone not null default now(),
    constraint ck_account_delete_events_event_type check (length(trim(event_type)) > 0),
    constraint ck_account_delete_events_code check (length(trim(code)) > 0)
);

create index if not exists ix_account_delete_events_account_time
    on account_delete_events(account_id, created_at desc);

create index if not exists ix_account_delete_events_type_time
    on account_delete_events(event_type, created_at desc);

create table if not exists session_logout_events(
    logout_event_id bigint generated always as identity primary key,
    account_id uuid null,
    access_token_hash text null,
    logout_scope text not null,
    reason text null,
    requested_at timestamp with time zone not null default now(),
    completed boolean not null default false,
    code text null
);

create index if not exists ix_session_logout_events_account_time
    on session_logout_events(account_id, requested_at desc);

create or replace function setup_account_email(
    p_accountId uuid,
    p_emailAddress text,
    p_webKey text,
    p_hashedPassword bytea,
    p_saltOne bytea,
    p_siv bytea,
    p_nonce bytea,
    p_country smallint,
    p_verifyKeyHash text,
    p_createdOn timestamp with time zone,
    p_verificationExpiration interval)
returns table(verification_index bigint, outcome smallint)
language plpgsql
as $$
declare
    v_verification_index bigint;
    v_constraint text;
begin
    perform cor17_email_gate();perform cor17_purge_email_requests();
    if exists(select 1 from account_email_change_requests q where lower(q.new_email_address)=lower(p_emailAddress) and cor17_email_live(q)) then return query select null::bigint,8040::smallint;return;end if;
    if exists (select 1 from accounts where account_id = p_accountId) then
        return query select null::bigint, 3000::smallint;
        return;
    end if;

    if exists (select 1 from accounts where web_key = p_webKey) then
        return query select null::bigint, 3500::smallint;
        return;
    end if;

    if exists (select 1 from accounts where lower(email_address) = lower(p_emailAddress)) then
        return query select null::bigint, 8040::smallint;
        return;
    end if;

    insert into accounts(
        account_id, email_address, username, hashed_password, created_on, web_key,
        verify_status, salt_one, siv, nonce, unlock_when, login_failures,
        features, two_factor_auth_method, country)
    values(
        p_accountId, p_emailAddress, null, p_hashedPassword, p_createdOn, p_webKey,
        0, p_saltOne, p_siv, p_nonce, null, 0,
        0, 0, p_country);

    insert into account_verifications(account_id, verify_key_hash, verify_status, sent_when, expiration, account_security_stamp)
    select p_accountId, p_verifyKeyHash, 0, null, greatest(coalesce(p_verificationExpiration, interval '1 day'), interval '1 minute'), a.security_stamp
      from accounts a where a.account_id = p_accountId
    returning account_verifications.verification_index into v_verification_index;

    return query select v_verification_index, 8000::smallint;
exception
    when unique_violation then
        -- The subtransaction has rolled back all candidate writes; the caller
        -- can persist the deterministic result in its COR04 receipt.
        get stacked diagnostics v_constraint = constraint_name;
        if v_constraint = 'accounts_pkey' then
            return query select null::bigint, 3000::smallint;
        elsif v_constraint = 'ux_accounts_web_key' then
            return query select null::bigint, 3500::smallint;
        elsif v_constraint = 'ux_accounts_email_address_lower' then
            return query select null::bigint, 8040::smallint;
        else
            raise; -- Unknown constraints remain infrastructure failures, never duplicates.
        end if;
end;
$$;

create or replace function setup_account_both(
    p_accountId uuid,
    p_username text,
    p_emailAddress text,
    p_webKey text,
    p_hashedPassword bytea,
    p_saltOne bytea,
    p_siv bytea,
    p_nonce bytea,
    p_country smallint,
    p_verifyKeyHash text,
    p_createdOn timestamp with time zone,
    p_verificationExpiration interval)
returns table(verification_index bigint, outcome smallint)
language plpgsql
as $$
declare
    v_verification_index bigint;
    v_constraint text;
    v_email_exists boolean;
    v_username_exists boolean;
begin
    perform cor17_email_gate();perform cor17_purge_email_requests();
    if exists(select 1 from account_email_change_requests q where lower(q.new_email_address)=lower(p_emailAddress) and cor17_email_live(q)) then return query select null::bigint,8040::smallint;return;end if;
    if exists (select 1 from accounts where account_id = p_accountId) then
        return query select null::bigint, 3000::smallint;
        return;
    end if;

    if exists (select 1 from accounts where web_key = p_webKey) then
        return query select null::bigint, 3500::smallint;
        return;
    end if;

    select exists(select 1 from accounts where lower(email_address) = lower(p_emailAddress)) into v_email_exists;
    select exists(select 1 from accounts where lower(username) = lower(p_username)) into v_username_exists;

    if v_email_exists and v_username_exists then
        return query select null::bigint, 8070::smallint;
        return;
    end if;

    if v_email_exists then
        return query select null::bigint, 8040::smallint;
        return;
    end if;

    if v_username_exists then
        return query select null::bigint, 8010::smallint;
        return;
    end if;

    insert into accounts(
        account_id, email_address, username, hashed_password, created_on, web_key,
        verify_status, salt_one, siv, nonce, unlock_when, login_failures,
        features, two_factor_auth_method, country)
    values(
        p_accountId, p_emailAddress, p_username, p_hashedPassword, p_createdOn, p_webKey,
        0, p_saltOne, p_siv, p_nonce, null, 0,
        0, 0, p_country);

    insert into account_verifications(account_id, verify_key_hash, verify_status, sent_when, expiration, account_security_stamp)
    select p_accountId, p_verifyKeyHash, 0, null, greatest(coalesce(p_verificationExpiration, interval '1 day'), interval '1 minute'), a.security_stamp
      from accounts a where a.account_id = p_accountId
    returning account_verifications.verification_index into v_verification_index;

    return query select v_verification_index, 8000::smallint;
exception
    when unique_violation then
        -- The subtransaction has rolled back all candidate writes; the caller
        -- can persist the deterministic result in its COR04 receipt.
        get stacked diagnostics v_constraint = constraint_name;
        if v_constraint = 'accounts_pkey' then
            return query select null::bigint, 3000::smallint;
        elsif v_constraint = 'ux_accounts_web_key' then
            return query select null::bigint, 3500::smallint;
        elsif v_constraint in ('ux_accounts_email_address_lower', 'ux_accounts_username_lower') then
            select exists(select 1 from accounts where lower(email_address) = lower(p_emailAddress)) into v_email_exists;
            select exists(select 1 from accounts where lower(username) = lower(p_username)) into v_username_exists;
            return query select null::bigint,
                case when v_email_exists and v_username_exists then 8070
                     when v_constraint = 'ux_accounts_email_address_lower' then 8040
                     else 8010 end::smallint;
        else
            raise; -- Unknown constraints remain infrastructure failures, never duplicates.
        end if;
end;
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

create or replace function verify_account_for_use(p_verifyKeyHash text)
returns table(
    account_id uuid,
    verify_key_hash text,
    verify_status smallint,
    sent_when timestamp with time zone,
    expiration interval,
    proof_version uuid,
    account_security_stamp uuid)
language sql
stable
as $$
    select av.account_id,
           av.verify_key_hash,
           av.verify_status,
           av.sent_when,
           av.expiration,
           av.proof_version,
           av.account_security_stamp
      from account_verifications av
     where av.verify_key_hash = p_verifyKeyHash
     limit 1;
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

create or replace function get_session(p_accessTokenHash text)
returns table(
    account_id uuid,
    refresh_token bytea,
    refreshes smallint,
    refresh_limit smallint,
    created_on timestamp with time zone,
    session_lifespan interval,
    access_expiration timestamp with time zone,
    session_expiration timestamp with time zone,
    cut_off timestamp with time zone,
    features smallint,
    security_stamp uuid,
    account_security_stamp uuid,
    session_id uuid,
    generation bigint,
    protocol_version integer,
    entitlement_json text)
language plpgsql
volatile
as $$
declare owner uuid; projection jsonb;
begin
    select s.account_id into owner from sessions s where s.access_token_hash=p_accessTokenHash;
    if owner is null then return;end if;
    projection:=cor20_resolve_account(owner);
    return query select s.account_id,
           s.refresh_token,
           s.refreshes,
           s.refresh_limit,
           s.created_on,
           s.session_lifespan,
           s.access_expiration,
           s.session_expiration,
           case
               when s.cut_off is null then a.cut_off
               when a.cut_off is null then s.cut_off
               else least(s.cut_off, a.cut_off)
           end as cut_off,
           (projection->>'features')::smallint,
           s.security_stamp,
           s.account_security_stamp,
           s.session_id, s.generation, s.protocol_version, projection::text
      from sessions s
      join accounts a on a.account_id = s.account_id
     where s.access_token_hash = p_accessTokenHash
       and s.account_security_stamp = a.security_stamp
     limit 1;
end;
$$;

create or replace function get_current_active_session_hash(
    p_accountId uuid)
returns table(active_access_token_hash text)
language sql
stable
as $$
    select s.access_token_hash
      from sessions s
      join accounts a on a.account_id = s.account_id
     where s.account_id = p_accountId
       and s.account_security_stamp = a.security_stamp
       and s.session_expiration > now()
     order by s.created_on desc nulls last,
              s.session_expiration desc,
              s.access_token_hash desc
     limit 1;
$$;

create or replace function check_account_emailaddress_creds(p_emailAddress text)
returns table(
    account_id uuid,
    hashed_password bytea,
    web_key text,
    refresh_token bytea,
    refreshes smallint,
    refresh_limit smallint,
    created_on timestamp with time zone,
    lifespan interval,
    salt_one bytea,
    siv bytea,
    nonce bytea,
    unlock_when timestamp with time zone,
    login_failures smallint,
    verify_status smallint,
    features smallint,
    two_factor_access_token text,
    two_factor_auth_method smallint,
    two_auth_usage smallint,
    cut_off timestamp with time zone,
    account_security_stamp uuid,
    active_access_token_hash text,entitlement_json text)
language plpgsql
volatile
as $$
declare owner uuid; projection jsonb;
begin
    select a.account_id into owner from accounts a where lower(a.email_address)=lower(p_emailAddress) limit 1;
    if owner is null then return;end if;
    projection:=cor20_resolve_account(owner);
    return query select a.account_id,
           a.hashed_password,
           a.web_key,
           s.refresh_token,
           coalesce(s.refreshes, 0)::smallint,
           coalesce(s.refresh_limit, 0)::smallint,
           coalesce(s.created_on, now()),
           s.session_lifespan,
           a.salt_one,
           a.siv,
           a.nonce,
           a.unlock_when,
           coalesce(a.login_failures, 0)::smallint,
           coalesce(a.verify_status, 0)::smallint,
           (projection->>'features')::smallint,
           a.two_factor_access_token,
           coalesce(a.two_factor_auth_method, 0)::smallint,
           coalesce(a.two_auth_usage, 0)::smallint,
           case
               when s.cut_off is null then a.cut_off
               when a.cut_off is null then s.cut_off
               else least(s.cut_off, a.cut_off)
           end as cut_off,
           a.security_stamp,
           s.access_token_hash,projection::text
      from accounts a
      left join lateral (
            select sessions.access_token_hash,
                   sessions.refresh_token,
                   sessions.refreshes,
                   sessions.refresh_limit,
                   sessions.created_on,
                   sessions.session_lifespan,
                   sessions.session_expiration,
                   sessions.cut_off,
                   sessions.features
              from sessions
             where sessions.account_id = a.account_id
               and sessions.account_security_stamp = a.security_stamp
               and sessions.session_expiration > now()
             order by sessions.created_on desc nulls last,
                      sessions.session_expiration desc,
                      sessions.access_token_hash desc
             limit 1
      ) s on true
     where lower(a.email_address) = lower(p_emailAddress)
     limit 1;
end;
$$;

create or replace function check_account_username_creds(p_username text)
returns table(
    account_id uuid,
    hashed_password bytea,
    web_key text,
    refresh_token bytea,
    refreshes smallint,
    refresh_limit smallint,
    created_on timestamp with time zone,
    lifespan interval,
    salt_one bytea,
    siv bytea,
    nonce bytea,
    unlock_when timestamp with time zone,
    login_failures smallint,
    verify_status smallint,
    features smallint,
    two_factor_access_token text,
    two_factor_auth_method smallint,
    two_auth_usage smallint,
    cut_off timestamp with time zone,
    account_security_stamp uuid,
    active_access_token_hash text,
    entitlement_json text)
language plpgsql
volatile
as $$
declare owner uuid; projection jsonb;
begin
    select a.account_id into owner from accounts a where lower(a.username)=lower(p_username) limit 1;
    if owner is null then return;end if;
    projection:=cor20_resolve_account(owner);
    return query select a.account_id,
           a.hashed_password,
           a.web_key,
           s.refresh_token,
           coalesce(s.refreshes, 0)::smallint,
           coalesce(s.refresh_limit, 0)::smallint,
           coalesce(s.created_on, now()),
           s.session_lifespan,
           a.salt_one,
           a.siv,
           a.nonce,
           a.unlock_when,
           coalesce(a.login_failures, 0)::smallint,
           coalesce(a.verify_status, 0)::smallint,
           (projection->>'features')::smallint,
           a.two_factor_access_token,
           coalesce(a.two_factor_auth_method, 0)::smallint,
           coalesce(a.two_auth_usage, 0)::smallint,
           case
               when s.cut_off is null then a.cut_off
               when a.cut_off is null then s.cut_off
               else least(s.cut_off, a.cut_off)
           end as cut_off,
           a.security_stamp,
           s.access_token_hash, projection::text
      from accounts a
      left join lateral (
            select sessions.access_token_hash,
                   sessions.refresh_token,
                   sessions.refreshes,
                   sessions.refresh_limit,
                   sessions.created_on,
                   sessions.session_lifespan,
                   sessions.session_expiration,
                   sessions.cut_off,
                   sessions.features
              from sessions
             where sessions.account_id = a.account_id
               and sessions.account_security_stamp = a.security_stamp
               and sessions.session_expiration > now()
             order by sessions.created_on desc nulls last,
                      sessions.session_expiration desc,
                      sessions.access_token_hash desc
             limit 1
      ) s on true
     where lower(a.username) = lower(p_username)
     limit 1;
end;
$$;

create or replace function check_account_both_creds(p_username text, p_emailAddress text)
returns table(
    account_id uuid,
    hashed_password bytea,
    web_key text,
    refresh_token bytea,
    refreshes smallint,
    refresh_limit smallint,
    created_on timestamp with time zone,
    lifespan interval,
    salt_one bytea,
    siv bytea,
    nonce bytea,
    unlock_when timestamp with time zone,
    login_failures smallint,
    verify_status smallint,
    features smallint,
    two_factor_access_token text,
    two_factor_auth_method smallint,
    two_auth_usage smallint,
    cut_off timestamp with time zone,
    account_security_stamp uuid,
    active_access_token_hash text,entitlement_json text)
language plpgsql
volatile
as $$
declare owner uuid; projection jsonb;
begin
    select a.account_id into owner from accounts a where lower(a.username)=lower(p_username) and lower(a.email_address)=lower(p_emailAddress) limit 1;
    if owner is null then return;end if;
    projection:=cor20_resolve_account(owner);
    return query select a.account_id,
           a.hashed_password,
           a.web_key,
           s.refresh_token,
           coalesce(s.refreshes, 0)::smallint,
           coalesce(s.refresh_limit, 0)::smallint,
           coalesce(s.created_on, now()),
           s.session_lifespan,
           a.salt_one,
           a.siv,
           a.nonce,
           a.unlock_when,
           coalesce(a.login_failures, 0)::smallint,
           coalesce(a.verify_status, 0)::smallint,
           (projection->>'features')::smallint,
           a.two_factor_access_token,
           coalesce(a.two_factor_auth_method, 0)::smallint,
           coalesce(a.two_auth_usage, 0)::smallint,
           case
               when s.cut_off is null then a.cut_off
               when a.cut_off is null then s.cut_off
               else least(s.cut_off, a.cut_off)
           end as cut_off,
           a.security_stamp,
           s.access_token_hash,projection::text
      from accounts a
      left join lateral (
            select sessions.access_token_hash,
                   sessions.refresh_token,
                   sessions.refreshes,
                   sessions.refresh_limit,
                   sessions.created_on,
                   sessions.session_lifespan,
                   sessions.session_expiration,
                   sessions.cut_off,
                   sessions.features
              from sessions
             where sessions.account_id = a.account_id
               and sessions.account_security_stamp = a.security_stamp
               and sessions.session_expiration > now()
             order by sessions.created_on desc nulls last,
                      sessions.session_expiration desc,
                      sessions.access_token_hash desc
             limit 1
      ) s on true
     where lower(a.username) = lower(p_username)
       and lower(a.email_address) = lower(p_emailAddress)
     limit 1;
end;
$$;


create or replace function get_account_reauthentication_credentials(
    p_accountId uuid,
    p_accountSecurityStamp uuid)
returns table(
    result boolean,
    code text,
    hashed_password bytea,
    verify_status smallint,
    cut_off timestamp with time zone,
    account_security_stamp uuid)
language sql
stable
as $$
    select true,
           'FOUND'::text,
           a.hashed_password,
           a.verify_status,
           a.cut_off,
           a.security_stamp
      from accounts a
     where a.account_id = p_accountId
       and a.security_stamp = p_accountSecurityStamp
     limit 1;
$$;

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
declare
    insertedTokenId uuid;
    accountVerified smallint;
    accountCutOff timestamp with time zone;
begin
    if p_purpose is null or p_purpose <= 0 then
        return query select false, 'INVALID_PURPOSE'::text, null::uuid, null::timestamp with time zone;
        return;
    end if;

    if p_sessionBindingHash is null or btrim(p_sessionBindingHash) = '' or p_tokenHash is null or btrim(p_tokenHash) = '' then
        return query select false, 'INVALID_TOKEN_REQUEST'::text, null::uuid, null::timestamp with time zone;
        return;
    end if;

    if p_expiration <= p_createdOn or p_expiration <= now() then
        return query select false, 'TOKEN_EXPIRATION_INVALID'::text, null::uuid, null::timestamp with time zone;
        return;
    end if;

    select a.verify_status, a.cut_off
      into accountVerified, accountCutOff
      from accounts a
     where a.account_id = p_accountId
       and a.security_stamp = p_accountSecurityStamp
     for update;

    if not found then
        return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text, null::uuid, null::timestamp with time zone;
        return;
    end if;

    if accountVerified <> 1 then
        return query select false, 'ACCOUNT_NOT_VERIFIED'::text, null::uuid, null::timestamp with time zone;
        return;
    end if;

    if accountCutOff is not null and accountCutOff <= now() then
        return query select false, 'ACCOUNT_CUT_OFF_EXPIRED'::text, null::uuid, null::timestamp with time zone;
        return;
    end if;

    if coalesce(p_consumeExistingTokens, true) then
        update account_sensitive_action_tokens sat
           set consumed_on = coalesce(sat.consumed_on, p_createdOn)
         where sat.account_id = p_accountId
           and sat.session_binding_hash = p_sessionBindingHash
           and sat.purpose = p_purpose
           and sat.consumed_on is null
           and sat.expiration > p_createdOn;
    end if;

    insert into account_sensitive_action_tokens(
        account_id,
        session_binding_hash,
        token_hash,
        purpose,
        created_on,
        expiration,
        account_security_stamp)
    values(
        p_accountId,
        p_sessionBindingHash,
        p_tokenHash,
        p_purpose,
        p_createdOn,
        p_expiration,
        p_accountSecurityStamp)
    returning account_sensitive_action_tokens.token_id
    into insertedTokenId;

    return query select true, 'SENSITIVE_ACTION_TOKEN_ISSUED'::text, insertedTokenId, p_expiration;
exception
    when unique_violation then
        return query select false, 'SENSITIVE_ACTION_TOKEN_CONFLICT'::text, null::uuid, null::timestamp with time zone;
    when others then
        raise;
end;
$$;

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
declare
    tokenRecord account_sensitive_action_tokens%rowtype;
begin
    select *
      into tokenRecord
      from account_sensitive_action_tokens t
     where t.token_hash = p_tokenHash
     for update;

    if not found then
        return query select false, 'SENSITIVE_ACTION_TOKEN_INVALID'::text, null::timestamp with time zone;
        return;
    end if;

    if tokenRecord.account_id <> p_accountId
       or tokenRecord.account_security_stamp <> p_accountSecurityStamp
       or tokenRecord.session_binding_hash <> p_sessionBindingHash
       or tokenRecord.purpose <> p_purpose then
        return query select false, 'SENSITIVE_ACTION_TOKEN_INVALID'::text, tokenRecord.expiration;
        return;
    end if;

    if tokenRecord.consumed_on is not null then
        return query select false, 'SENSITIVE_ACTION_TOKEN_CONSUMED'::text, tokenRecord.expiration;
        return;
    end if;

    if tokenRecord.expiration <= p_moment then
        return query select false, 'SENSITIVE_ACTION_TOKEN_EXPIRED'::text, tokenRecord.expiration;
        return;
    end if;

    if coalesce(p_consume, false) then
        update account_sensitive_action_tokens
           set consumed_on = p_moment
         where token_id = tokenRecord.token_id;
    end if;

    return query select true, 'SENSITIVE_ACTION_TOKEN_VALID'::text, tokenRecord.expiration;
end;
$$;

create or replace function set_session(
    p_accessTokenHash text,
    p_accountId uuid,
    p_refreshToken bytea,
    p_refreshes smallint,
    p_refreshLimit smallint,
    p_createdOn timestamp with time zone,
    p_sessionLifespan interval,
    p_accessExpiration timestamp with time zone,
    p_sessionExpiration timestamp with time zone,
    p_cutOff timestamp with time zone,
    p_features smallint,
    p_securityStamp uuid,
    p_accountSecurityStamp uuid)
returns table(result smallint, code text)
language plpgsql
as $$
declare
    currentAccountCutOff timestamp with time zone;
    effectiveNewCutOff timestamp with time zone;
    issuedAt timestamp with time zone;
begin
    if exists (select 1 from sessions where access_token_hash = p_accessTokenHash) then
        return query select 5000::smallint, 'NEW_SESSION_CONFLICT'::text; -- IntraMessage.AUTHENTICATION_DUPLICATE
        return;
    end if;

    -- A direct successful login mints a new active session. Lock the account row
    -- before expiring/inserting session rows so concurrent logins for an account
    -- serialize and cannot leave multiple active sessions behind.
    select a.cut_off
      into currentAccountCutOff
      from accounts a
     where a.account_id = p_accountId
       and a.security_stamp = p_accountSecurityStamp
     for update;

    if not found then
        return query select 5000::smallint, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text;
        return;
    end if;

    issuedAt := clock_timestamp();

    if currentAccountCutOff is not null and currentAccountCutOff <= clock_timestamp() then
        return query select 5000::smallint, 'ACCOUNT_CUT_OFF_EXPIRED'::text;
        return;
    end if;

    effectiveNewCutOff := case
        when p_cutOff is null then currentAccountCutOff
        when currentAccountCutOff is null then p_cutOff
        else least(p_cutOff, currentAccountCutOff)
    end;

    if effectiveNewCutOff is not null and effectiveNewCutOff <= clock_timestamp() then
        return query select 5000::smallint, 'SESSION_CUT_OFF_EXPIRED'::text;
        return;
    end if;

    update sessions
       set access_expiration = least(access_expiration, greatest(created_on, issuedAt)),
           session_expiration = least(session_expiration, greatest(created_on, issuedAt)),
           cut_off = case when cut_off is null or cut_off > issuedAt then issuedAt else cut_off end,
           refresh_credential_hash = null
     where account_id = p_accountId
       and session_expiration > clock_timestamp();

    insert into sessions(
        session_id,
        refresh_credential_hash,
        access_token_hash,
        account_id,
        refresh_token,
        refreshes,
        refresh_limit,
        created_on,
        session_lifespan,
        access_expiration,
        session_expiration,
        cut_off,
        features,
        security_stamp,
        account_security_stamp)
    values(
        p_securityStamp,
        session_refresh_credential_hash(p_refreshToken,p_securityStamp),
        p_accessTokenHash,
        p_accountId,
        p_refreshToken,
        coalesce(p_refreshes, 0),
        coalesce(p_refreshLimit, 0),
        issuedAt,
        p_sessionLifespan,
        p_accessExpiration,
        p_sessionExpiration,
        effectiveNewCutOff,
        p_features,
        p_securityStamp,
        p_accountSecurityStamp);

    return query select 1::smallint, 'SUCCESSFUL'::text; -- IntraMessage.SUCCESSFUL
exception
    when unique_violation then
        return query select 5000::smallint, 'NEW_SESSION_CONFLICT'::text;
    when others then
        raise;
end;
$$;



create or replace function set_account_lockout(p_accountGuid uuid, p_expiration interval)
returns table(result boolean, code text)
language plpgsql
as $$
begin
    update accounts
       set unlock_when = now() + p_expiration
     where account_id = p_accountGuid;

    return query select found, case when found then 'LOCKED' else 'ACCOUNT_NOT_FOUND' end::text;
end;
$$;

create or replace function remove_account_lockout(p_accountGuid uuid)
returns table(result boolean, code text)
language plpgsql
as $$
begin
    update accounts
       set unlock_when = null,
           login_failures = 0
     where account_id = p_accountGuid;

    return query select found, case when found then 'UNLOCKED' else 'ACCOUNT_NOT_FOUND' end::text;
end;
$$;

create or replace function set_account_login_failures(p_accountGuid uuid, p_failures smallint)
returns table(result boolean, code text)
language plpgsql
as $$
begin
    update accounts
       set login_failures = p_failures
     where account_id = p_accountGuid;

    return query select found, case when found then 'UPDATED' else 'ACCOUNT_NOT_FOUND' end::text;
end;
$$;

create or replace function successful_login(
    p_accountId uuid,
    p_accountSecurityStamp uuid)
returns table(result boolean, code text)
language plpgsql
as $$
begin
    update accounts
       set login_failures = 0
     where account_id = p_accountId
       and security_stamp = p_accountSecurityStamp;

    return query select found, case when found then 'UPDATED' else 'ACCOUNT_STAMP_MISMATCH' end::text;
end;
$$;


create or replace function rotate_account_security_stamp(p_accountId uuid)
returns table(result boolean, code text, account_security_stamp uuid)
language plpgsql
as $$
declare
    rotatedAccountSecurityStamp uuid;
begin
    update accounts
       set security_stamp = gen_random_uuid(),
           two_factor_access_token = null,
           two_auth_usage = null
     where account_id = p_accountId
     returning security_stamp into rotatedAccountSecurityStamp;

    if rotatedAccountSecurityStamp is null then
        return query select false, 'ACCOUNT_NOT_FOUND'::text, null::uuid;
        return;
    end if;

    -- DB-backed sessions are expired immediately. Any Redis entries that still
    -- exist will also fail trust validation because their account stamp is stale.
    update sessions
       set access_expiration = least(access_expiration, greatest(created_on, now())),
           session_expiration = least(session_expiration, greatest(created_on, now()))
     where account_id = p_accountId
       and session_expiration > now();

    delete from pending_two_factor_sessions
     where account_id = p_accountId;

    return query select true, 'ROTATED'::text, rotatedAccountSecurityStamp;
end;
$$;

-- Account operation contract functions. Account operations must be driven by
-- authenticated account context rather than body-supplied ownership fields.
create or replace function edit_account_username(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_username text)
returns table(result boolean, code text)
language plpgsql
as $$
declare
    account_record accounts%rowtype;
    normalized_username text := nullif(btrim(p_username), '');
begin
    select a.*
      into account_record
      from accounts a
     where a.account_id = p_accountId;

    if not found then
        return query select false, 'ACCOUNT_NOT_FOUND'::text;
        return;
    end if;

    if account_record.security_stamp <> p_accountSecurityStamp then
        return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text;
        return;
    end if;

    if normalized_username is null or char_length(normalized_username) > 128 then
        return query select false, 'ACCOUNT_ADJUST_FAILED'::text;
        return;
    end if;

    if exists (
        select 1
          from accounts
         where account_id <> p_accountId
           and username is not null
           and lower(username) = lower(normalized_username)
    ) then
        return query select false, 'ACCOUNT_ADJUST_DUPLICATE_USERNAME'::text;
        return;
    end if;

    update accounts
       set username = normalized_username
     where account_id = p_accountId
       and security_stamp = p_accountSecurityStamp;

    if found then
        return query select true, 'ACCOUNT_ADJUST_SUCCEEDED'::text;
    else
        return query select false, 'ACCOUNT_ADJUST_FAILED'::text;
    end if;
exception
    when unique_violation then
        return query select false, 'ACCOUNT_ADJUST_DUPLICATE_USERNAME'::text;
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
    select a.*
      into account_record
      from accounts a
     where a.account_id = p_accountId;

    if not found then
        return query select false, 'ACCOUNT_NOT_FOUND'::text, null::text;
        return;
    end if;

    if account_record.security_stamp <> p_accountSecurityStamp then
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
    when sqlstate 'P1801' then return query select false,'ACCOUNT_DELETE_CONFLICT'::text,null::uuid;
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

create or replace function rotate_active_session(
    p_accountId uuid,
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
    p_securityStamp uuid,
    p_accountSecurityStamp uuid)
returns table(status smallint, code text)
language plpgsql
as $$
declare
    oldSessionLocked boolean := false;
    currentAccountCutOff timestamp with time zone;
    effectiveOldCutOff timestamp with time zone;
    effectiveNewCutOff timestamp with time zone;
begin
    if exists (select 1 from sessions where access_token_hash = p_newAccessTokenHash) then
        return query select 3::smallint, 'NEW_SESSION_CONFLICT'::text;
        return;
    end if;

    -- Lock the account before touching session rows so direct login, refresh
    -- rotation, and 2FA promotion all serialize on the same account-scoped
    -- session ownership boundary.
    select a.cut_off
      into currentAccountCutOff
      from accounts a
     where a.account_id = p_accountId
       and a.security_stamp = p_accountSecurityStamp
     for update;

    if not found then
        return query select 2::smallint, 'OLD_SESSION_MISMATCH'::text;
        return;
    end if;

    select case
               when s.cut_off is null then currentAccountCutOff
               when currentAccountCutOff is null then s.cut_off
               else least(s.cut_off, currentAccountCutOff)
           end
      into effectiveOldCutOff
      from sessions s
     where s.account_id = p_accountId
       and s.access_token_hash = p_expectedOldAccessTokenHash
       and s.account_security_stamp = p_accountSecurityStamp
       and s.session_expiration > clock_timestamp()
     for update;

    oldSessionLocked := found;

    if not oldSessionLocked or (effectiveOldCutOff is not null and effectiveOldCutOff <= clock_timestamp()) then
        return query select 2::smallint, 'OLD_SESSION_MISMATCH'::text;
        return;
    end if;

    effectiveNewCutOff := case
        when p_cutOff is null then currentAccountCutOff
        when currentAccountCutOff is null then p_cutOff
        else least(p_cutOff, currentAccountCutOff)
    end;

    if effectiveNewCutOff is not null and effectiveNewCutOff <= clock_timestamp() then
        return query select 2::smallint, 'OLD_SESSION_MISMATCH'::text;
        return;
    end if;

    update sessions
       set access_expiration = least(access_expiration, greatest(created_on, clock_timestamp())),
           session_expiration = least(session_expiration, greatest(created_on, clock_timestamp()))
     where account_id = p_accountId
       and access_token_hash <> p_expectedOldAccessTokenHash
       and session_expiration > clock_timestamp();

    insert into sessions(
        session_id,
        refresh_credential_hash,
        access_token_hash,
        account_id,
        refresh_token,
        refreshes,
        refresh_limit,
        created_on,
        session_lifespan,
        access_expiration,
        session_expiration,
        cut_off,
        features,
        security_stamp,
        account_security_stamp)
    values(
        p_securityStamp,
        session_refresh_credential_hash(p_refreshToken,p_securityStamp),
        p_newAccessTokenHash,
        p_accountId,
        p_refreshToken,
        coalesce(p_refreshes, 0),
        coalesce(p_refreshLimit, 0),
        p_createdOn,
        p_sessionLifespan,
        p_accessExpiration,
        p_sessionExpiration,
        effectiveNewCutOff,
        p_features,
        p_securityStamp,
        p_accountSecurityStamp);

    update sessions
       set access_expiration = least(access_expiration, greatest(created_on, clock_timestamp())),
           session_expiration = least(session_expiration, greatest(created_on, clock_timestamp()))
     where account_id = p_accountId
       and access_token_hash = p_expectedOldAccessTokenHash
       and session_expiration > clock_timestamp();

    if not found then
        delete from sessions where access_token_hash = p_newAccessTokenHash;
        return query select 2::smallint, 'OLD_SESSION_MISMATCH'::text;
        return;
    end if;

    update accounts
       set login_failures = 0
     where account_id = p_accountId;

    return query select 1::smallint, 'SUCCEEDED'::text;
exception
    when unique_violation then
        return query select 3::smallint, 'NEW_SESSION_CONFLICT'::text;
    when others then
        raise;
end;
$$;

create or replace function promote_twofactor_new_login(
    p_accountId uuid,
    p_expectedTwoFactorAccessToken text,
    p_accountSecurityStamp uuid,
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
    p_securityStamp uuid,
    p_expectedProofVersion bigint)
returns table(result boolean, code text)
language plpgsql
as $$
declare
    pending_expiry timestamptz;
    currentAccountCutOff timestamp with time zone;
    currentPendingToken text;
    effectiveNewCutOff timestamp with time zone;
begin
    if exists (select 1 from sessions where access_token_hash = p_newAccessTokenHash) then
        return query select false, 'NEW_SESSION_CONFLICT'::text;
        return;
    end if;

    select a.cut_off,
           a.two_factor_access_token
      into currentAccountCutOff,
           currentPendingToken
      from accounts a
     where a.account_id = p_accountId
       and a.security_stamp = p_accountSecurityStamp
     for update;

    if not found then
        return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text;
        return;
    end if;

    if currentPendingToken is distinct from p_expectedTwoFactorAccessToken then
        return query select false, 'PENDING_TWO_FACTOR_MISMATCH'::text;
        return;
    end if;

    perform 1 from pending_two_factor_sessions p where p.pre_auth_access_token_hash=p_expectedTwoFactorAccessToken and p.account_id=p_accountId for update;
    select p.expiration into pending_expiry from pending_two_factor_sessions p
    where p.pre_auth_access_token_hash=p_expectedTwoFactorAccessToken and p.account_id=p_accountId
        and p.account_security_stamp=p_accountSecurityStamp and p.login_metadata is not null
        and p.progress_version=p_expectedProofVersion and p.state=5 and p.completed_at is not null
        and cardinality(p.required_methods)>0 and p.completed_methods=p.required_methods
        and p.current_expected_method is null and p.challenge_code_hash is null
        and p.selected_two_factor_configuration=any(resolve_available_twofactor_configurations(p_accountId))
        and coalesce(p.login_metadata->>'priorActiveAccessTokenHash','')='';
    if not found or not exists(select 1 from accounts a where a.account_id=p_accountId and a.verify_status=1 and (a.unlock_when is null or a.unlock_when<=clock_timestamp())) then
        return query select false,'LOGIN_PROOF_INCOMPLETE_OR_STALE'::text; return;
    end if;
    perform cor02_require_live(pending_expiry);
    if not exists (
        select 1
          from pending_two_factor_sessions p
         where p.account_id = p_accountId
           and p.pre_auth_access_token_hash = p_expectedTwoFactorAccessToken
           and p.account_security_stamp = p_accountSecurityStamp
           and p.expiration > clock_timestamp()) then
        return query select false, 'PENDING_TWO_FACTOR_MISMATCH'::text;
        return;
    end if;

    if currentAccountCutOff is not null and currentAccountCutOff <= clock_timestamp() then
        return query select false, 'ACCOUNT_CUT_OFF_EXPIRED'::text;
        return;
    end if;

    effectiveNewCutOff := case
        when p_cutOff is null then currentAccountCutOff
        when currentAccountCutOff is null then p_cutOff
        else least(p_cutOff, currentAccountCutOff)
    end;

    if effectiveNewCutOff is not null and effectiveNewCutOff <= clock_timestamp() then
        return query select false, 'SESSION_CUT_OFF_EXPIRED'::text;
        return;
    end if;

    update sessions
       set access_expiration = least(access_expiration, greatest(created_on, clock_timestamp())),
           session_expiration = least(session_expiration, greatest(created_on, clock_timestamp()))
     where account_id = p_accountId
       and session_expiration > clock_timestamp();

    insert into sessions(
        session_id,
        refresh_credential_hash,
        access_token_hash,
        account_id,
        refresh_token,
        refreshes,
        refresh_limit,
        created_on,
        session_lifespan,
        access_expiration,
        session_expiration,
        cut_off,
        features,
        security_stamp,
        account_security_stamp)
    values(
        p_securityStamp,
        session_refresh_credential_hash(p_refreshToken,p_securityStamp),
        p_newAccessTokenHash,
        p_accountId,
        p_refreshToken,
        coalesce(p_refreshes, 0),
        coalesce(p_refreshLimit, 0),
        p_createdOn,
        p_sessionLifespan,
        p_accessExpiration,
        p_sessionExpiration,
        effectiveNewCutOff,
        coalesce(p_features, 0),
        p_securityStamp,
        p_accountSecurityStamp);

    update accounts
       set login_failures = 0,
           unlock_when = null,
           two_factor_access_token = null,
           two_auth_usage = null
     where account_id = p_accountId
       and security_stamp = p_accountSecurityStamp
       and two_factor_access_token = p_expectedTwoFactorAccessToken;

    if not found then
        raise exception '2FA pending marker changed during promote_twofactor_new_login for account %', p_accountId;
    end if;

    delete from pending_two_factor_sessions
     where pre_auth_access_token_hash = p_expectedTwoFactorAccessToken;

    perform cor02_require_live(pending_expiry);
    perform cor02_require_live(p_accessExpiration);
    if effectiveNewCutOff is not null then perform cor02_require_live(effectiveNewCutOff); end if;
    return query select true, 'TWO_FACTOR_NEW_LOGIN_PROMOTED'::text;
exception
    when sqlstate 'P0202' then return query select false,'PENDING_TWO_FACTOR_EXPIRED'::text;
    when unique_violation then
        return query select false, 'NEW_SESSION_CONFLICT'::text;
    when others then
        raise;
end;
$$;

create or replace function promote_twofactor_rotation_login(
    p_accountId uuid,
    p_expectedTwoFactorAccessToken text,
    p_accountSecurityStamp uuid,
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
    p_securityStamp uuid,
    p_expectedProofVersion bigint)
returns table(result boolean, code text)
language plpgsql
as $$
declare
    pending_expiry timestamptz;
    currentAccountCutOff timestamp with time zone;
    currentPendingToken text;
    oldSessionCutOff timestamp with time zone;
    oldSessionExpiration timestamp with time zone;
    effectiveOldCutOff timestamp with time zone;
    effectiveNewCutOff timestamp with time zone;
begin
    if exists (select 1 from sessions where access_token_hash = p_newAccessTokenHash) then
        return query select false, 'NEW_SESSION_CONFLICT'::text;
        return;
    end if;

    select a.cut_off,
           a.two_factor_access_token
      into currentAccountCutOff,
           currentPendingToken
      from accounts a
     where a.account_id = p_accountId
       and a.security_stamp = p_accountSecurityStamp
     for update;

    if not found then
        return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text;
        return;
    end if;

    if currentPendingToken is distinct from p_expectedTwoFactorAccessToken then
        return query select false, 'PENDING_TWO_FACTOR_MISMATCH'::text;
        return;
    end if;

    perform 1 from pending_two_factor_sessions p where p.pre_auth_access_token_hash=p_expectedTwoFactorAccessToken and p.account_id=p_accountId for update;
    select p.expiration into pending_expiry from pending_two_factor_sessions p
    where p.pre_auth_access_token_hash=p_expectedTwoFactorAccessToken and p.account_id=p_accountId
        and p.account_security_stamp=p_accountSecurityStamp and p.login_metadata is not null
        and p.progress_version=p_expectedProofVersion and p.state=5 and p.completed_at is not null
        and cardinality(p.required_methods)>0 and p.completed_methods=p.required_methods
        and p.current_expected_method is null and p.challenge_code_hash is null
        and p.selected_two_factor_configuration=any(resolve_available_twofactor_configurations(p_accountId))
        and coalesce(p.login_metadata->>'priorActiveAccessTokenHash','')=p_expectedOldAccessTokenHash;
    if not found or not exists(select 1 from accounts a where a.account_id=p_accountId and a.verify_status=1 and (a.unlock_when is null or a.unlock_when<=clock_timestamp())) then
        return query select false,'LOGIN_PROOF_INCOMPLETE_OR_STALE'::text; return;
    end if;
    perform cor02_require_live(pending_expiry);
    if not exists (
        select 1
          from pending_two_factor_sessions p
         where p.account_id = p_accountId
           and p.pre_auth_access_token_hash = p_expectedTwoFactorAccessToken
           and p.account_security_stamp = p_accountSecurityStamp
           and p.expiration > clock_timestamp()) then
        return query select false, 'PENDING_TWO_FACTOR_MISMATCH'::text;
        return;
    end if;

    select s.cut_off,
           s.session_expiration
      into oldSessionCutOff,
           oldSessionExpiration
      from sessions s
     where s.account_id = p_accountId
       and s.access_token_hash = p_expectedOldAccessTokenHash
       and s.account_security_stamp = p_accountSecurityStamp
     for update;

    if not found then
        return query select false, 'OLD_SESSION_NOT_FOUND'::text;
        return;
    end if;

    effectiveOldCutOff := case
        when oldSessionCutOff is null then currentAccountCutOff
        when currentAccountCutOff is null then oldSessionCutOff
        else least(oldSessionCutOff, currentAccountCutOff)
    end;

    if oldSessionExpiration <= clock_timestamp() or (effectiveOldCutOff is not null and effectiveOldCutOff <= clock_timestamp()) then
        return query select false, 'OLD_SESSION_EXPIRED'::text;
        return;
    end if;

    effectiveNewCutOff := case
        when p_cutOff is null then currentAccountCutOff
        when currentAccountCutOff is null then p_cutOff
        else least(p_cutOff, currentAccountCutOff)
    end;

    if effectiveNewCutOff is not null and effectiveNewCutOff <= clock_timestamp() then
        return query select false, 'SESSION_CUT_OFF_EXPIRED'::text;
        return;
    end if;

    update sessions
       set access_expiration = least(access_expiration, greatest(created_on, clock_timestamp())),
           session_expiration = least(session_expiration, greatest(created_on, clock_timestamp()))
     where account_id = p_accountId
       and access_token_hash <> p_expectedOldAccessTokenHash
       and session_expiration > clock_timestamp();

    insert into sessions(
        session_id,
        refresh_credential_hash,
        access_token_hash,
        account_id,
        refresh_token,
        refreshes,
        refresh_limit,
        created_on,
        session_lifespan,
        access_expiration,
        session_expiration,
        cut_off,
        features,
        security_stamp,
        account_security_stamp)
    values(
        p_securityStamp,
        session_refresh_credential_hash(p_refreshToken,p_securityStamp),
        p_newAccessTokenHash,
        p_accountId,
        p_refreshToken,
        coalesce(p_refreshes, 0),
        coalesce(p_refreshLimit, 0),
        p_createdOn,
        p_sessionLifespan,
        p_accessExpiration,
        p_sessionExpiration,
        effectiveNewCutOff,
        coalesce(p_features, 0),
        p_securityStamp,
        p_accountSecurityStamp);

    update sessions
       set access_expiration = least(access_expiration, greatest(created_on, clock_timestamp())),
           session_expiration = least(session_expiration, greatest(created_on, clock_timestamp()))
     where account_id = p_accountId
       and access_token_hash = p_expectedOldAccessTokenHash
       and session_expiration > clock_timestamp();

    if not found then
        raise exception 'Old 2FA rotation session changed during promote_twofactor_rotation_login for account %', p_accountId;
    end if;

    update accounts
       set login_failures = 0,
           unlock_when = null,
           two_factor_access_token = null,
           two_auth_usage = null
     where account_id = p_accountId
       and security_stamp = p_accountSecurityStamp
       and two_factor_access_token = p_expectedTwoFactorAccessToken;

    if not found then
        raise exception '2FA pending marker changed during promote_twofactor_rotation_login for account %', p_accountId;
    end if;

    delete from pending_two_factor_sessions
     where pre_auth_access_token_hash = p_expectedTwoFactorAccessToken;

    perform cor02_require_live(pending_expiry);
    perform cor02_require_live(p_accessExpiration);
    if effectiveNewCutOff is not null then perform cor02_require_live(effectiveNewCutOff); end if;
    return query select true, 'TWO_FACTOR_ROTATION_LOGIN_PROMOTED'::text;
exception
    when sqlstate 'P0202' then return query select false,'PENDING_TWO_FACTOR_EXPIRED'::text;
    when unique_violation then
        return query select false, 'NEW_SESSION_CONFLICT'::text;
    when others then
        raise;
end;
$$;

create or replace function validate_cached_session_trust(
    p_accessTokenHash text,
    p_accountId uuid,
    p_securityStamp uuid,
    p_accountSecurityStamp uuid)
returns table(
    status smallint,
    code text,
    access_expiration timestamp with time zone,
    session_expiration timestamp with time zone,
    cut_off timestamp with time zone,
    security_stamp uuid,
    account_security_stamp uuid,
    session_id uuid,
    generation bigint,
    protocol_version integer,
    entitlement_json text)
language plpgsql
volatile
as $$
declare
    a accounts%rowtype; s sessions%rowtype; cutoff timestamptz; status_code smallint; outcome text; projection jsonb;
begin
    perform cor02_lock_account_authority(p_accountId,'activation');
    select * into a from accounts where account_id=p_accountId;
    select * into s from sessions where access_token_hash=p_accessTokenHash and account_id=p_accountId;
    cutoff := least(s.cut_off,a.cut_off);
    if a.account_id is null then status_code:=3; outcome:='ACCOUNT_NOT_FOUND';
    elsif s.access_token_hash is null then status_code:=2; outcome:='SESSION_NOT_FOUND';
    elsif s.security_stamp is distinct from p_securityStamp then status_code:=4; outcome:='SECURITY_STAMP_MISMATCH';
    elsif s.account_security_stamp is distinct from p_accountSecurityStamp or a.security_stamp is distinct from p_accountSecurityStamp then status_code:=6; outcome:='ACCOUNT_SECURITY_STAMP_MISMATCH';
    elsif s.access_expiration<=clock_timestamp() or s.session_expiration<=clock_timestamp() or cutoff<=clock_timestamp() then status_code:=5; outcome:='SESSION_EXPIRED';
    elsif a.verify_status<>1 or a.unlock_when>clock_timestamp() then status_code:=5; outcome:='ACCOUNT_AUTHORITY_EXPIRED';
    else status_code:=1; outcome:='VALID'; end if;
    if status_code=1 then projection:=cor20_resolve_account(p_accountId);end if;
    if status_code=1 and (s.access_expiration<=clock_timestamp() or s.session_expiration<=clock_timestamp() or cutoff<=clock_timestamp()) then
        status_code:=5;outcome:='SESSION_EXPIRED';projection:=null;
    end if;
    return query select status_code,outcome,s.access_expiration,s.session_expiration,cutoff,s.security_stamp,a.security_stamp,s.session_id,s.generation,s.protocol_version,projection::text;
end;
$$;

create or replace function expire_session(p_accessTokenHash text, p_newExpiration timestamp with time zone)
returns table(result boolean, code text)
language plpgsql
as $$
declare
    effectiveExpiration timestamp with time zone := coalesce(p_newExpiration, now());
begin
    update sessions
       set access_expiration = least(access_expiration, effectiveExpiration),
           session_expiration = least(session_expiration, effectiveExpiration)
     where access_token_hash = p_accessTokenHash;

    return query select found, case when found then 'EXPIRED' else 'SESSION_NOT_FOUND' end::text;
end;
$$;

create or replace function revoke_session(p_accessTokenHash text)
returns table(result boolean, code text)
language plpgsql
as $$
begin
    -- Legacy compatibility wrapper. Runtime repository code uses expire_session; hard deletion is reserved for cleanup jobs.
    update sessions
       set access_expiration = least(access_expiration, greatest(created_on, now())),
           session_expiration = least(session_expiration, greatest(created_on, now()))
     where access_token_hash = p_accessTokenHash;

    return query select found, case when found then 'EXPIRED' else 'SESSION_NOT_FOUND' end::text;
end;
$$;


create or replace function logout_current_session(
    p_accountId uuid,
    p_accessTokenHash text,
    p_accountSecurityStamp uuid,
    p_reason text default 'current-session-logoff')
returns table(result boolean, code text)
language plpgsql
as $$
declare family uuid; changed boolean;
begin
    perform cor02_lock_account_authority(p_accountId,'account');
    if not exists(select 1 from accounts a where a.account_id=p_accountId and a.security_stamp = p_accountSecurityStamp) then
        insert into session_logout_events(account_id,access_token_hash,logout_scope,reason,
            completed,code)
        values(p_accountId,p_accessTokenHash,'current',p_reason,false,'ACCOUNT_SECURITY_STAMP_MISMATCH');
        return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text; return;
    end if;
    select s.session_id into family from sessions s where s.access_token_hash=p_accessTokenHash and s.account_id=p_accountId and s.account_security_stamp=p_accountSecurityStamp;
    perform 1 from sessions s where s.account_id=p_accountId and s.session_id=family order by s.generation for update;
    update sessions s set access_expiration=least(s.access_expiration,greatest(s.created_on,clock_timestamp())),
        session_expiration=least(s.session_expiration,greatest(s.created_on,clock_timestamp()))
        where s.account_id=p_accountId and s.session_id=family and s.account_security_stamp=p_accountSecurityStamp and s.session_expiration>clock_timestamp();
    changed:=found;
    insert into session_logout_events(account_id,access_token_hash,logout_scope,reason,completed,code)
    values(p_accountId,p_accessTokenHash,'current',p_reason,true,case when changed then 'CURRENT_SESSION_LOGGED_OUT' else 'SESSION_ALREADY_MISSING_OR_STALE' end);
    if changed then return query select true, 'CURRENT_SESSION_LOGGED_OUT'::text;
    else return query select true, 'SESSION_ALREADY_MISSING_OR_STALE'::text; end if;
end;
$$;

create or replace function logout_all_sessions(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_reason text default 'logout-all')
returns table(result boolean, code text, account_security_stamp uuid)
language plpgsql
as $$
declare
    newStamp uuid := gen_random_uuid();
begin
    update accounts
       set security_stamp = newStamp,
           two_factor_access_token = null,
           two_auth_usage = null
     where account_id = p_accountId
       and security_stamp = p_accountSecurityStamp;

    if not found then
        insert into session_logout_events(
            account_id,
            logout_scope,
            reason,
            completed,
            code)
        values(
            p_accountId,
            'all',
            p_reason,
            false,
            'ACCOUNT_SECURITY_STAMP_MISMATCH');

        return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text, null::uuid;
        return;
    end if;

    update sessions
       set access_expiration = least(access_expiration, greatest(created_on, now())),
           session_expiration = least(session_expiration, greatest(created_on, now()))
     where account_id = p_accountId;

    delete from pending_two_factor_sessions
     where account_id = p_accountId;

    insert into session_logout_events(
        account_id,
        logout_scope,
        reason,
        completed,
        code)
    values(
        p_accountId,
        'all',
        p_reason,
        true,
        'ALL_SESSIONS_LOGGED_OUT');

    return query select true, 'ALL_SESSIONS_LOGGED_OUT'::text, newStamp;
end;
$$;


create or replace function list_active_sessions(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_currentAccessTokenHash text)
returns table(
    session_id uuid,
    created_on timestamp with time zone,
    access_expiration timestamp with time zone,
    session_expiration timestamp with time zone,
    features smallint,
    is_current boolean,
    entitlement_json text)
language plpgsql
volatile
as $$
declare owner uuid; projection jsonb;
begin
    select a.account_id into owner from accounts a where a.account_id=p_accountId and a.security_stamp=p_accountSecurityStamp;
    if owner is null then return;end if;
    projection:=cor20_resolve_account(owner);
    return query select s.session_id,
           s.created_on,
           s.access_expiration,
           s.session_expiration,
           (projection->>'features')::smallint,
           s.session_id = (select c.session_id from sessions c where c.access_token_hash=p_currentAccessTokenHash and c.account_id=p_accountId) as is_current, projection::text
      from sessions s
      join accounts a on a.account_id = s.account_id
     where s.account_id = p_accountId
       and a.security_stamp = p_accountSecurityStamp
       and s.account_security_stamp = a.security_stamp
       and s.session_expiration > clock_timestamp()
       and (case
                when s.cut_off is null then a.cut_off
                when a.cut_off is null then s.cut_off
                else least(s.cut_off, a.cut_off)
            end is null
            or case
                when s.cut_off is null then a.cut_off
                when a.cut_off is null then s.cut_off
                else least(s.cut_off, a.cut_off)
            end > clock_timestamp())
     order by is_current desc,
              s.created_on desc nulls last,
              s.session_expiration desc,
              s.session_id desc;
end;
$$;

create or replace function revoke_session_for_account(
    p_accountId uuid,
    p_targetSessionId uuid,
    p_accountSecurityStamp uuid,
    p_currentAccessTokenHash text)
returns table(result boolean, code text)
language plpgsql
as $$
declare
    targetAccessTokenHash text;
begin
    perform cor02_lock_account_authority(p_accountId,'account');
    if not exists (
        select 1
          from accounts a
         where a.account_id = p_accountId
           and a.security_stamp = p_accountSecurityStamp
    ) then
        insert into session_logout_events(
            account_id,
            logout_scope,
            reason,
            completed,
            code)
        values(
            p_accountId,
            'session',
            'session-management-revoke',
            false,
            'ACCOUNT_SECURITY_STAMP_MISMATCH');

        return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text;
        return;
    end if;

    select s.access_token_hash
      into targetAccessTokenHash
      from sessions s
     where s.account_id = p_accountId
       and s.session_id = p_targetSessionId
       and s.account_security_stamp = p_accountSecurityStamp
       and s.session_expiration > clock_timestamp()
     order by s.generation desc limit 1 for update;

    if not found then
        insert into session_logout_events(
            account_id,
            logout_scope,
            reason,
            completed,
            code)
        values(
            p_accountId,
            'session',
            'session-management-revoke',
            true,
            'SESSION_ALREADY_MISSING_OR_STALE');

        return query select true, 'SESSION_ALREADY_MISSING_OR_STALE'::text;
        return;
    end if;

    update sessions
       set access_expiration = least(access_expiration, greatest(created_on, clock_timestamp())),
           session_expiration = least(session_expiration, greatest(created_on, clock_timestamp()))
     where account_id = p_accountId
       and session_id = p_targetSessionId
       and account_security_stamp = p_accountSecurityStamp;

    insert into session_logout_events(
        account_id,
        access_token_hash,
        logout_scope,
        reason,
        completed,
        code)
    values(
        p_accountId,
        targetAccessTokenHash,
        'session',
        'session-management-revoke',
        true,
        case
            when p_targetSessionId = (select s.session_id from sessions s where s.access_token_hash=p_currentAccessTokenHash and s.account_id=p_accountId) then 'CURRENT_SESSION_REVOKED'
            else 'SESSION_REVOKED'
        end);

    return query select true,
        case
            when p_targetSessionId = (select s.session_id from sessions s where s.access_token_hash=p_currentAccessTokenHash and s.account_id=p_accountId) then 'CURRENT_SESSION_REVOKED'::text
            else 'SESSION_REVOKED'::text
        end;
end;
$$;

create or replace function get_twofactor_details(p_accountId uuid)
returns table(
    method smallint,
    auth_id text,
    phone_number text,
    phone_country_code text,
    email_address text)
language sql
stable
as $$
    select t.method,
           t.auth_id,
           t.phone_number,
           t.phone_country_code,
           case when t.method = 1 then a.email_address else t.email_address end as email_address
      from two_factor_authentications t
      join accounts a on a.account_id = t.account_id
     where t.account_id = p_accountId
       and t.verified = true
       and t.revoked_at is null
       and (t.expiration is null or t.expiration > now())
       and (
            t.method <> 3
            or (
                t.revoked_at is null
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
     order by t.priority desc,
              t.two_factor_index asc;
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
    select a.*
      into account_record
      from accounts a
     where a.account_id = p_accountId;

    if not found then
        return query select false, 'ACCOUNT_NOT_FOUND'::text;
        return;
    end if;

    if account_record.security_stamp <> p_accountSecurityStamp then
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
    moment timestamp with time zone := coalesce(p_now, now());
    revoked_count integer := 0;
    remaining_methods smallint[] := array[]::smallint[];
    remaining_configurations smallint[] := array[]::smallint[];
    selected_method smallint := 0;
    usage_count smallint := null;
    reset_session_revoke_result boolean := true;
    reset_session_revoke_code text := null;
begin
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

    if account_record.security_stamp <> p_accountSecurityStamp then
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
    moment timestamp with time zone := coalesce(p_createdOn, now());
begin
    select * into account_record from accounts where account_id = p_accountId for update;
    if not found then return query select false, 'ACCOUNT_NOT_FOUND'::text, null::bigint, null::timestamp with time zone; return; end if;
    if account_record.security_stamp <> p_accountSecurityStamp then return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text, null::bigint, null::timestamp with time zone; return; end if;
    if account_record.verify_status <> 1 then return query select false, 'ACCOUNT_NOT_VERIFIED'::text, null::bigint, null::timestamp with time zone; return; end if;
    if account_record.cut_off is not null and account_record.cut_off <= moment then return query select false, 'ACCOUNT_CUT_OFF_EXPIRED'::text, null::bigint, null::timestamp with time zone; return; end if;
    if provider_type <> 1 then return query select false, 'AUTHENTICATOR_SETUP_UNSUPPORTED_PROVIDER'::text, null::bigint, null::timestamp with time zone; return; end if;
    if p_setupTokenHash is null or btrim(p_setupTokenHash) = '' then return query select false, 'AUTHENTICATOR_SETUP_INVALID_TOKEN'::text, null::bigint, null::timestamp with time zone; return; end if;
    if p_createdOn is null or p_expiration is null or p_expiration <= p_createdOn or p_expiration <= now() then return query select false, 'AUTHENTICATOR_SETUP_INVALID_EXPIRATION'::text, null::bigint, null::timestamp with time zone; return; end if;
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
    return query select true, 'AUTHENTICATOR_SETUP_PENDING'::text, target_index, p_expiration;
exception when unique_violation then
    return query select false, 'TWO_FACTOR_AUTHENTICATOR_APP_ALREADY_ATTACHED'::text, null::bigint, null::timestamp with time zone;
when others then
    return query select false, 'AUTHENTICATOR_SETUP_FAILED'::text, null::bigint, null::timestamp with time zone;
end;
$$;

create or replace function get_pending_authenticator_app_setup(
    p_accountId uuid,
    p_accountSecurityStamp uuid,
    p_setupTokenHash text,
    p_now timestamp with time zone)
returns table(result boolean, code text, two_factor_index bigint, expiration timestamp with time zone, setup_attempts smallint, totp_secret_ciphertext bytea, totp_secret_nonce bytea, totp_secret_tag bytea, totp_secret_version integer, totp_last_used_step bigint, totp_provider_type smallint, totp_key_id text, totp_enrollment_id uuid, totp_algorithm text, totp_digits integer, totp_period_seconds integer, totp_clock_skew_steps integer, totp_row_version bigint)
language plpgsql
stable
as $$
begin
    if p_setupTokenHash is null or btrim(p_setupTokenHash) = '' then return query select false, 'AUTHENTICATOR_SETUP_INVALID_TOKEN'::text, null::bigint, null::timestamp with time zone, 0::smallint, null::bytea, null::bytea, null::bytea, null::integer, null::bigint, null::smallint, null::text, null::uuid, null::text, null::integer, null::integer, null::integer, null::bigint; return; end if;
    if not exists (select 1 from accounts a where a.account_id = p_accountId and a.security_stamp = p_accountSecurityStamp and a.verify_status = 1 and (a.cut_off is null or a.cut_off > coalesce(p_now, now()))) then return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text, null::bigint, null::timestamp with time zone, 0::smallint, null::bytea, null::bytea, null::bytea, null::integer, null::bigint, null::smallint, null::text, null::uuid, null::text, null::integer, null::integer, null::integer, null::bigint; return; end if;
    perform cor16_require_setup(t,p_accountSecurityStamp,t.setup_family_id) from two_factor_authentications t
        where t.account_id=p_accountId and t.token=p_setupTokenHash and not t.verified and t.revoked_at is null;
    return query select true, 'AUTHENTICATOR_SETUP_FOUND'::text, t.two_factor_index, t.expiration, t.setup_attempts, t.totp_secret_ciphertext, t.totp_secret_nonce, t.totp_secret_tag, t.totp_secret_version, t.totp_last_used_step, t.totp_provider_type, t.totp_key_id, t.totp_enrollment_id, t.totp_algorithm, t.totp_digits, t.totp_period_seconds, t.totp_clock_skew_steps, t.totp_row_version from two_factor_authentications t where t.account_id = p_accountId and t.method = 3 and t.verified = false and t.revoked_at is null and t.token = p_setupTokenHash and (t.expiration is null or t.expiration > coalesce(p_now, now())) and t.totp_provider_type = 1 and t.totp_secret_ciphertext is not null and t.totp_secret_nonce is not null and t.totp_secret_tag is not null order by t.created_on desc, t.two_factor_index desc limit 1;
    if not found then return query select false, 'AUTHENTICATOR_SETUP_NOT_FOUND'::text, null::bigint, null::timestamp with time zone, 0::smallint, null::bytea, null::bytea, null::bytea, null::integer, null::bigint, null::smallint, null::text, null::uuid, null::text, null::integer, null::integer, null::integer, null::bigint; end if;
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
    moment timestamp with time zone := coalesce(p_now, now());
begin
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
    moment timestamp with time zone := coalesce(p_createdOn, now());
    new_account_stamp uuid := gen_random_uuid();
    verified_count smallint;
begin
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
    if setup_record.expiration is not null and setup_record.expiration <= moment then return query select false, 'AUTHENTICATOR_SETUP_EXPIRED'::text, null::uuid, setup_record.two_factor_index; return; end if;
    if setup_record.totp_provider_type <> 1 or setup_record.totp_secret_ciphertext is null or setup_record.totp_secret_nonce is null or setup_record.totp_secret_tag is null then return query select false, 'AUTHENTICATOR_SETUP_INVALID_SECRET'::text, null::uuid, setup_record.two_factor_index; return; end if;
    if setup_record.totp_last_used_step is not null and p_timeStep <= setup_record.totp_last_used_step then return query select false, 'TOTP_REPLAY_DETECTED'::text, null::uuid, setup_record.two_factor_index; return; end if;
    if exists (select 1 from two_factor_authentications t where t.account_id = p_accountId and t.method = 3 and t.verified = true and t.revoked_at is null and t.two_factor_index <> setup_record.two_factor_index) then return query select false, 'TWO_FACTOR_AUTHENTICATOR_APP_ALREADY_ATTACHED'::text, null::uuid, setup_record.two_factor_index; return; end if;
    new_cutoff := case when p_cutOff is null then account_record.cut_off when account_record.cut_off is null then p_cutOff else least(p_cutOff, account_record.cut_off) end;
    if new_cutoff is not null and new_cutoff <= moment then return query select false, 'SESSION_CUT_OFF_EXPIRED'::text, null::uuid, setup_record.two_factor_index; return; end if;
    update two_factor_authentications tfa set verified = true, token = null, expiration = null, lifespan = null, setup_attempts = 0, priority = greatest(tfa.priority, 1), totp_last_used_step = p_timeStep, revoked_at = null, revoked_reason = null where tfa.account_id = p_accountId and tfa.two_factor_index = setup_record.two_factor_index and tfa.verified = false and tfa.revoked_at is null;
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
    update sessions set access_expiration = least(access_expiration, greatest(created_on, moment)), session_expiration = least(session_expiration, greatest(created_on, moment)) where account_id = p_accountId and session_expiration > moment;
    insert into sessions(session_id, refresh_credential_hash, access_token_hash, account_id, refresh_token, refreshes, refresh_limit, created_on, session_lifespan, access_expiration, session_expiration, cut_off, features, security_stamp, account_security_stamp) values(p_sessionSecurityStamp, session_refresh_credential_hash(p_refreshToken,p_sessionSecurityStamp), p_newAccessTokenHash, p_accountId, p_refreshToken, coalesce(p_refreshes, 0), coalesce(p_refreshLimit, 0), moment, p_sessionLifespan, p_accessExpiration, p_sessionExpiration, new_cutoff, coalesce(p_features, 0), p_sessionSecurityStamp, new_account_stamp);
    delete from pending_two_factor_sessions ptfs where ptfs.account_id = p_accountId;
    return query select true, 'AUTHENTICATOR_SETUP_VERIFIED_SESSION_ROTATED'::text, new_account_stamp, setup_record.two_factor_index;
exception when unique_violation then
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
    if not exists (select 1 from accounts a where a.account_id = p_accountId and a.security_stamp = p_accountSecurityStamp) then return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text; return; end if;
    if p_setupTokenHash is null or btrim(p_setupTokenHash) = '' then return query select false, 'AUTHENTICATOR_SETUP_INVALID_TOKEN'::text; return; end if;
    delete from two_factor_authentications t where t.account_id = p_accountId and t.method = 3 and t.verified = false and t.revoked_at is null and t.token = p_setupTokenHash;
    get diagnostics deleted_count = row_count;
    return query select true, case when deleted_count > 0 then 'AUTHENTICATOR_SETUP_CANCELLED' else 'AUTHENTICATOR_SETUP_ALREADY_CANCELLED_OR_MISSING' end::text;
exception when others then
    return query select false, 'AUTHENTICATOR_SETUP_CANCEL_FAILED'::text;
end;
$$;

create or replace function get_verified_totp_enrollment_for_account(
    p_accountId uuid,
    p_now timestamp with time zone)
returns table(account_id uuid, two_factor_index bigint, method smallint, totp_provider_type smallint, totp_provider_enrollment_id text, totp_provider_account_binding_hash text, totp_secret_ciphertext bytea, totp_secret_nonce bytea, totp_secret_tag bytea, totp_secret_version integer, totp_last_used_step bigint, totp_key_id text, totp_enrollment_id uuid, totp_algorithm text, totp_digits integer, totp_period_seconds integer, totp_clock_skew_steps integer, totp_row_version bigint)
language sql
stable
as $$
    select t.account_id, t.two_factor_index, t.method, t.totp_provider_type, t.totp_provider_enrollment_id, t.totp_provider_account_binding_hash, t.totp_secret_ciphertext, t.totp_secret_nonce, t.totp_secret_tag, t.totp_secret_version, t.totp_last_used_step, t.totp_key_id, t.totp_enrollment_id, t.totp_algorithm, t.totp_digits, t.totp_period_seconds, t.totp_clock_skew_steps, t.totp_row_version
      from two_factor_authentications t
     where t.account_id = p_accountId
       and t.method = 3
       and t.verified = true
       and t.revoked_at is null
       and (t.expiration is null or t.expiration > coalesce(p_now, now()))
       and ((t.totp_provider_type = 1 and t.totp_secret_ciphertext is not null and t.totp_secret_nonce is not null and t.totp_secret_tag is not null) or (t.totp_provider_type = 2 and t.totp_provider_enrollment_id is not null and t.totp_provider_account_binding_hash is not null))
     order by t.required desc, t.priority asc, t.two_factor_index asc
     limit 1;
$$;

create or replace function mark_totp_step_used(
    p_accountId uuid,
    p_twoFactorIndex bigint,
    p_timeStep bigint, p_enrollmentId uuid)
returns table(result boolean, code text)
language plpgsql
as $$
declare existing_step bigint; provider_type smallint;
begin
    if p_timeStep is null or p_timeStep < 0 then return query select false, 'TOTP_INVALID_TIME_STEP'::text; return; end if;
    select t.totp_last_used_step, t.totp_provider_type into existing_step, provider_type from two_factor_authentications t where t.account_id = p_accountId and t.two_factor_index = p_twoFactorIndex and t.totp_enrollment_id = p_enrollmentId and t.method = 3 and t.verified = true and t.revoked_at is null for update;
    if not found then return query select false, 'TOTP_ENROLLMENT_NOT_FOUND'::text; return; end if;
    if provider_type <> 1 then return query select false, 'TOTP_PROVIDER_MANAGED_NOT_LOCAL'::text; return; end if;
    if existing_step is not null and p_timeStep <= existing_step then return query select false, 'TOTP_REPLAY_DETECTED'::text; return; end if;
    update two_factor_authentications t set totp_last_used_step = p_timeStep where t.account_id = p_accountId and t.two_factor_index = p_twoFactorIndex and t.totp_enrollment_id = p_enrollmentId and t.method = 3 and t.verified = true and t.revoked_at is null and t.totp_provider_type = 1;
    return query select true, 'TOTP_STEP_ACCEPTED'::text;
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

create or replace function view_account(
    p_accountId uuid,
    p_accountSecurityStamp uuid)
returns table(
    result boolean,
    code text,
    email_address text,
    username text,
    created_on timestamp with time zone,
    verify_status smallint,
    country smallint,
    features smallint,
    two_factor_enabled boolean,
    two_factor_configuration smallint,
    two_factor_methods smallint[],
    entitlement_json text)
language plpgsql
volatile
as $$
declare
    account_record accounts%rowtype; projection jsonb;
begin
    perform cor02_lock_account_authority(p_accountId,'activation');
    select a.*
      into account_record
      from accounts a
     where a.account_id = p_accountId;

    if not found then
        return query select
            false,
            'ACCOUNT_NOT_FOUND'::text,
            null::text,
            null::text,
            null::timestamp with time zone,
            null::smallint,
            null::smallint,
            null::smallint,
            false,
            0::smallint,
            array[]::smallint[],null::text;
        return;
    end if;

    if account_record.security_stamp <> p_accountSecurityStamp then
        return query select
            false,
            'ACCOUNT_SECURITY_STAMP_MISMATCH'::text,
            null::text,
            null::text,
            null::timestamp with time zone,
            null::smallint,
            null::smallint,
            null::smallint,
            false,
            0::smallint,
            array[]::smallint[],null::text;
        return;
    end if;

    projection:=cor20_resolve_account(p_accountId);
    return query
    with usable_methods as (
        select distinct t.method::smallint as method
          from two_factor_authentications t
         where t.account_id = p_accountId
           and t.verified = true
           and t.revoked_at is null
           and (t.expiration is null or t.expiration > now())
           and (
                (t.method = 1 and nullif(trim(account_record.email_address), '') is not null)
                or (t.method = 2 and nullif(trim(t.phone_number), '') is not null)
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
           )
    ), method_summary as (
        select coalesce(array_agg(method order by method), array[]::smallint[]) as methods,
               coalesce(bool_or(method = 1), false) as has_email,
               coalesce(bool_or(method = 2), false) as has_sms,
               coalesce(bool_or(method = 3), false) as has_authenticator_app
          from usable_methods
    )
    select
        true,
        'ACCOUNT_VIEW_SUCCEEDED'::text,
        account_record.email_address,
        account_record.username,
        account_record.created_on,
        account_record.verify_status,
        account_record.country,
        (projection->>'features')::smallint,
        cardinality(method_summary.methods) > 0,
        case
            when method_summary.has_sms and not method_summary.has_email and not method_summary.has_authenticator_app then 1::smallint
            when method_summary.has_email and not method_summary.has_sms and not method_summary.has_authenticator_app then 2::smallint
            when method_summary.has_authenticator_app and not method_summary.has_email and not method_summary.has_sms then 3::smallint
            when method_summary.has_sms and method_summary.has_authenticator_app and not method_summary.has_email then 4::smallint
            when method_summary.has_email and method_summary.has_authenticator_app and not method_summary.has_sms then 5::smallint
            when cardinality(method_summary.methods) = 0 then 0::smallint
            else 6::smallint
        end,
        method_summary.methods,projection::text
      from method_summary;
end;
$$;

create or replace function lookup_locked_recovery_account(
    p_identifier text,
    p_now timestamp with time zone)
returns table(
    result boolean,
    code text,
    account_id uuid,
    email_address text,
    phone_number text,
    phone_country_code text,
    account_security_stamp uuid,
    unlock_when timestamp with time zone,
    lockout_attempt_version uuid)
language plpgsql
as $$
begin
    return query select true, 'ACCOUNT_UNLOCK_ACCOUNT_FOUND'::text,
        a.account_id, a.email_address, sms.phone_number, sms.phone_country_code,
        a.security_stamp, a.unlock_when,
        coalesce(v.attempt_version, '00000000-0000-0000-0000-000000000000'::uuid)
      from accounts a
      left join account_login_attempt_versions v
        on v.account_id = a.account_id and v.credential_stamp = a.security_stamp
      left join lateral (
        select t.phone_number, t.phone_country_code from two_factor_authentications t
         where t.account_id = a.account_id and t.method = 2 and t.verified = true
           and t.revoked_at is null and t.phone_number is not null
           and (t.expiration is null or t.expiration > clock_timestamp())
         order by t.required desc, t.priority asc, t.two_factor_index asc limit 1
      ) sms on true
     where (lower(a.email_address) = lower(nullif(btrim(p_identifier), ''))
         or lower(a.username) = lower(nullif(btrim(p_identifier), '')))
       and a.unlock_when > clock_timestamp()
     order by case when lower(a.email_address) = lower(nullif(btrim(p_identifier), '')) then 0 else 1 end
     limit 1;
    if not found then
        return query select false, 'ACCOUNT_UNLOCK_NOT_LOCKED'::text,
            null::uuid, null::text, null::text, null::text, null::uuid,
            null::timestamp with time zone, null::uuid;
    end if;
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



create or replace function lookup_password_reset_account(
    p_identifier text,
    p_now timestamp with time zone)
returns table(
    result boolean,
    code text,
    account_id uuid,
    email_address text,
    phone_number text,
    phone_country_code text,
    account_security_stamp uuid,
    email_verified boolean,
    sms_verified boolean,
    authenticator_verified boolean)
language plpgsql
as $$
declare
    normalized_identifier text := lower(nullif(btrim(p_identifier), ''));
    phone_identifier text := regexp_replace(coalesce(p_identifier, ''), '[^0-9+]', '', 'g');
    phone_identifier_digits text := regexp_replace(coalesce(p_identifier, ''), '[^0-9]', '', 'g');
    account_record accounts%rowtype;
    v_phone_number text;
    v_phone_country_code text;
    has_authenticator boolean := false;
begin
    if normalized_identifier is null then
        return query select false, 'PASSWORD_RESET_ACCOUNT_NOT_FOUND'::text, null::uuid, null::text, null::text, null::text, null::uuid, false, false, false;
        return;
    end if;

    select a.*
      into account_record
      from accounts a
     where lower(a.email_address) = normalized_identifier
        or lower(a.username) = normalized_identifier
        or exists (
            select 1
              from two_factor_authentications t
             where t.account_id = a.account_id
               and t.method = 2
               and t.verified = true
               and t.revoked_at is null
               and (t.expiration is null or t.expiration > p_now)
               and t.phone_number is not null
               and (
                    lower(t.phone_number) = normalized_identifier
                 or regexp_replace(coalesce(t.phone_number, ''), '[^0-9+]', '', 'g') = phone_identifier
                 or regexp_replace(coalesce(t.phone_country_code, '') || coalesce(t.phone_number, ''), '[^0-9+]', '', 'g') = phone_identifier
                 or regexp_replace(coalesce(t.phone_number, ''), '[^0-9]', '', 'g') = phone_identifier_digits
                 or regexp_replace(coalesce(t.phone_country_code, '') || coalesce(t.phone_number, ''), '[^0-9]', '', 'g') = phone_identifier_digits
               )
        )
     order by case
        when lower(a.email_address) = normalized_identifier then 0
        when lower(a.username) = normalized_identifier then 1
        else 2
     end
     limit 1;

    if not found then
        return query select false, 'PASSWORD_RESET_ACCOUNT_NOT_FOUND'::text, null::uuid, null::text, null::text, null::text, null::uuid, false, false, false;
        return;
    end if;

    select t.phone_number, t.phone_country_code
      into v_phone_number, v_phone_country_code
      from two_factor_authentications t
     where t.account_id = account_record.account_id
       and t.method = 2
       and t.verified = true
       and t.revoked_at is null
       and t.phone_number is not null
       and (t.expiration is null or t.expiration > p_now)
     order by t.required desc, t.priority asc, t.two_factor_index asc
     limit 1;

    has_authenticator := exists(
        select 1
          from two_factor_authentications t
         where t.account_id = account_record.account_id
           and t.method = 3
           and t.verified = true
           and t.revoked_at is null
           and (t.expiration is null or t.expiration > p_now)
           and t.totp_secret_ciphertext is not null
           and t.totp_secret_nonce is not null
           and t.totp_secret_tag is not null
    );

    return query select
        true,
        'PASSWORD_RESET_ACCOUNT_FOUND'::text,
        account_record.account_id,
        account_record.email_address,
        v_phone_number,
        v_phone_country_code,
        account_record.security_stamp,
        account_record.verify_status = 1,
        v_phone_number is not null,
        has_authenticator;
end;
$$;

create or replace function get_password_reset_totp_enrollment(
    p_accountId uuid,
    p_now timestamp with time zone)
returns table(
    account_id uuid,
    two_factor_index bigint,
    method smallint,
    totp_secret_ciphertext bytea,
    totp_secret_nonce bytea,
    totp_secret_tag bytea,
    totp_secret_version integer,
    totp_last_used_step bigint, totp_key_id text, totp_enrollment_id uuid, totp_algorithm text, totp_digits integer, totp_period_seconds integer, totp_clock_skew_steps integer, totp_row_version bigint)
language sql
stable
as $$
    select e.account_id,
           e.two_factor_index,
           e.method,
           e.totp_secret_ciphertext,
           e.totp_secret_nonce,
           e.totp_secret_tag,
           e.totp_secret_version,
           e.totp_last_used_step, e.totp_key_id, e.totp_enrollment_id, e.totp_algorithm, e.totp_digits, e.totp_period_seconds, e.totp_clock_skew_steps, e.totp_row_version
      from get_verified_totp_enrollment_for_account(p_accountId, p_now) e
     where e.totp_provider_type = 1;
$$;

create or replace function mark_password_reset_totp_step_used(
    p_accountId uuid,
    p_twoFactorIndex bigint,
    p_timeStep bigint, p_enrollmentId uuid)
returns table(
    result boolean,
    code text)
language sql
as $$
    select result,
           code
      from mark_totp_step_used(p_accountId, p_twoFactorIndex, p_timeStep, p_enrollmentId);
$$;

create or replace function register_password_reset_request_rate_limit(
    p_rateLimitKey text,
    p_now timestamp with time zone,
    p_requestWindow interval,
    p_requestLimit integer,
    p_requestCooldown interval,
    p_blockPeriod interval)
returns table(
    result boolean,
    code text,
    request_count integer,
    blocked_until timestamp with time zone,
    retry_after_seconds integer)
language plpgsql
as $$
declare
    v_key text := nullif(btrim(p_rateLimitKey), '');
    v_now timestamp with time zone := coalesce(p_now, now());
    v_window interval := greatest(coalesce(p_requestWindow, interval '24 hours'), interval '1 second');
    v_limit integer := greatest(coalesce(p_requestLimit, 1), 1);
    v_cooldown interval := greatest(coalesce(p_requestCooldown, interval '0 seconds'), interval '0 seconds');
    v_block_period interval := greatest(coalesce(p_blockPeriod, interval '1 minute'), interval '1 second');
    v_row password_reset_rate_limits%rowtype;
    v_retry_at timestamp with time zone;
    v_retry_after_seconds integer;
    v_request_count integer;
begin
    if v_key is null then
        return query select false, 'PASSWORD_RESET_RATE_LIMIT_INVALID_KEY'::text, null::integer, null::timestamp with time zone, null::integer;
        return;
    end if;

    insert into password_reset_rate_limits(rate_limit_key, window_started_at, request_count, last_request_at, blocked_until)
    values(v_key, v_now, 0, null, null)
    on conflict (rate_limit_key) do nothing;

    select *
      into v_row
      from password_reset_rate_limits prrl
     where prrl.rate_limit_key = v_key
     for update;

    if v_row.blocked_until is not null and v_row.blocked_until > v_now then
        v_retry_after_seconds := ceiling(extract(epoch from (v_row.blocked_until - v_now)))::integer;
        return query select false, 'PASSWORD_RESET_RATE_LIMITED'::text, v_row.request_count, v_row.blocked_until, v_retry_after_seconds;
        return;
    end if;

    if v_row.window_started_at + v_window <= v_now then
        update password_reset_rate_limits prrl
           set window_started_at = v_now,
               request_count = 1,
               last_request_at = v_now,
               blocked_until = null
         where prrl.rate_limit_key = v_key;

        return query select true, 'PASSWORD_RESET_RATE_LIMIT_OK'::text, 1::integer, null::timestamp with time zone, 0::integer;
        return;
    end if;

    if v_row.last_request_at is not null
       and v_cooldown > interval '0 seconds'
       and v_row.last_request_at + v_cooldown > v_now then
        v_retry_at := v_row.last_request_at + v_cooldown;
        v_retry_after_seconds := ceiling(extract(epoch from (v_retry_at - v_now)))::integer;

        return query select false, 'PASSWORD_RESET_REQUEST_COOLDOWN'::text, v_row.request_count, v_retry_at, v_retry_after_seconds;
        return;
    end if;

    if v_row.request_count >= v_limit then
        update password_reset_rate_limits prrl
           set last_request_at = v_now,
               blocked_until = v_now + v_block_period
         where prrl.rate_limit_key = v_key
        returning prrl.blocked_until into v_retry_at;

        v_retry_after_seconds := ceiling(extract(epoch from (v_retry_at - v_now)))::integer;
        return query select false, 'PASSWORD_RESET_RATE_LIMITED'::text, v_row.request_count, v_retry_at, v_retry_after_seconds;
        return;
    end if;

    update password_reset_rate_limits prrl
       set request_count = prrl.request_count + 1,
           last_request_at = v_now,
           blocked_until = null
     where prrl.rate_limit_key = v_key
    returning prrl.request_count into v_request_count;

    return query select true, 'PASSWORD_RESET_RATE_LIMIT_OK'::text, v_request_count, null::timestamp with time zone, 0::integer;
end;
$$;

create or replace function cleanup_password_reset_rate_limits(
    p_now timestamp with time zone,
    p_retention interval)
returns table(
    result boolean,
    code text,
    deleted_count integer)
language plpgsql
as $$
declare
    v_now timestamp with time zone := coalesce(p_now, now());
    v_retention interval := greatest(coalesce(p_retention, interval '7 days'), interval '1 hour');
    v_deleted_count integer := 0;
begin
    delete from password_reset_rate_limits prrl
     where prrl.window_started_at < v_now - v_retention
       and (prrl.blocked_until is null or prrl.blocked_until < v_now);

    get diagnostics v_deleted_count = row_count;

    return query select true, 'PASSWORD_RESET_RATE_LIMIT_CLEANUP_COMPLETED'::text, v_deleted_count;
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
    v_created_at timestamp with time zone := now();
    v_has_sms boolean := false;
    v_method text := lower(nullif(btrim(p_method), ''));
    v_delivery_channel text := lower(nullif(btrim(p_deliveryChannel), ''));
begin
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

    if v_method is null then
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

    if p_expiresAt <= v_created_at then
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

    return query select true, 'PASSWORD_RESET_REQUEST_CREATED'::text, p_passwordResetRequestId, p_accountId, p_expiresAt;
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
begin
    select *
      into v_reset
      from password_reset_requests pr
     where pr.password_reset_request_id = p_passwordResetRequestId
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

-- COR13: account stamp plus immutable factor material define the policy snapshot.
-- A replay-use counter is runtime proof state, not a factor-policy change.
create or replace function cor13_reset_policy(p_account uuid)
returns text language sql stable set timezone = 'UTC' as $$
    select encode(digest(jsonb_build_array(a.security_stamp,a.verify_status,a.email_address,
        (select jsonb_agg((to_jsonb(t)-'totp_last_used_step'-'setup_attempts') ||
            jsonb_build_object('live',t.expiration is null or t.expiration>clock_timestamp())
            order by t.two_factor_index) from two_factor_authentications t where t.account_id=p_account))::text,'sha256'),'hex')
    from accounts a where a.account_id=p_account;
$$;

create or replace function cor13_reset_configurations(p_account uuid,p_bootstrap smallint)
returns smallint[] language plpgsql as $$
declare email_ok boolean; sms_ok boolean; app_ok boolean; options smallint[]:=array[]::smallint[];
begin
    select a.verify_status=1 and p_bootstrap<>1 into email_ok from accounts a where a.account_id=p_account;
    sms_ok:=p_bootstrap<>2 and exists(select 1 from two_factor_authentications t where t.account_id=p_account and t.method=2
        and t.verified and t.revoked_at is null and t.phone_number is not null and (t.expiration is null or t.expiration>clock_timestamp()));
    app_ok:=exists(select 1 from two_factor_authentications t where t.account_id=p_account and t.method=3
        and t.verified and t.revoked_at is null and (t.expiration is null or t.expiration>clock_timestamp())
        and t.totp_provider_type=1 and octet_length(t.totp_secret_ciphertext)>0 and octet_length(t.totp_secret_nonce)>0
        and octet_length(t.totp_secret_tag)>0 and coalesce(t.totp_secret_version,0)>0);
    if sms_ok then options:=array_append(options,1::smallint);end if;
    if email_ok then options:=array_append(options,2::smallint);end if;
    if app_ok then options:=array_append(options,3::smallint);end if;
    if sms_ok and app_ok then options:=array_append(options,4::smallint);end if;
    if email_ok and app_ok then options:=array_append(options,5::smallint);end if;
    return options;
end;
$$;

create or replace function get_pending_password_reset_session(
    p_resetAccessTokenHash text)
returns table(
    password_reset_request_id uuid,
    account_id uuid,
    reset_access_token_hash text,
    bootstrap_proof smallint,
    state smallint,
    available_configurations smallint[],
    selected_two_factor_configuration smallint,
    required_methods smallint[],
    completed_methods smallint[],
    current_expected_method smallint,
    challenge_code_hash text,
    challenge_expiration timestamp with time zone,
    challenge_attempts integer,
    challenge_resends integer,
    next_challenge_allowed_at timestamp with time zone,
    created_on timestamp with time zone,
    expires_at timestamp with time zone,
    selected_at timestamp with time zone,
    two_factor_completed_at timestamp with time zone,
    password_changed_at timestamp with time zone,
    session_version bigint, challenge_version bigint, factor_policy_version text, account_security_stamp uuid)
language sql
stable
as $$
    select p.password_reset_request_id,
           p.account_id,
           p.reset_access_token_hash,
           p.bootstrap_proof,
           p.state,
           p.available_configurations,
           p.selected_two_factor_configuration,
           p.required_methods,
           p.completed_methods,
           p.current_expected_method,
           p.challenge_code_hash,
           p.challenge_expiration,
           p.challenge_attempts,
           p.challenge_resends,
           p.next_challenge_allowed_at,
           p.created_on,
           p.expires_at,
           p.selected_at,
           p.two_factor_completed_at,
           p.password_changed_at,
           p.session_version,p.challenge_version,p.factor_policy_version,p.account_security_stamp
      from pending_password_reset_sessions p
     where p.reset_access_token_hash = p_resetAccessTokenHash
       and p.revoked_at is null and p.expires_at>clock_timestamp()
       and p.factor_policy_version=cor13_reset_policy(p.account_id)
       and exists(select 1 from password_reset_requests r join accounts a using(account_id)
           where r.password_reset_request_id=p.password_reset_request_id and r.account_id=p.account_id
             and r.cancelled_at is null and r.consumed_at is null and r.expires_at>clock_timestamp()
             and a.security_stamp=p.account_security_stamp and r.account_security_stamp_at_request=a.security_stamp)
     limit 1;
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
begin
    perform cor02_lock_account_authority((select t.account_id from pending_password_reset_sessions t where t.reset_access_token_hash=p_resetAccessTokenHash),'reset');
    update pending_password_reset_sessions p
       set revoked_at = v_revoked_at,
           revoked_reason = v_reason_code
     where p.reset_access_token_hash = p_resetAccessTokenHash
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

create or replace function get_password_reset_request_for_finalize(
    p_passwordResetRequestId uuid)
returns table(
    result boolean,
    code text,
    password_reset_request_id uuid,
    account_id uuid,
    method text,
    delivery_channel text,
    key_code_hash text,
    key_code_hash_version integer,
    requires_key_code boolean,
    requires_totp boolean,
    expires_at timestamp with time zone,
    consumed_at timestamp with time zone,
    cancelled_at timestamp with time zone,
    attempt_count integer,
    max_attempts integer,
    account_security_stamp_at_request uuid,
    email_verified boolean,
    sms_verified boolean,
    authenticator_verified boolean,
    current_email_address text,
    current_phone_number text,
    current_phone_country_code text)
language plpgsql
as $$
declare
    v_reset password_reset_requests%rowtype;
    v_email_address text;
    v_phone_number text;
    v_phone_country_code text;
    v_email_verified boolean := false;
    v_sms_verified boolean := false;
    v_authenticator_verified boolean := false;
begin
    select *
      into v_reset
      from password_reset_requests pr
     where pr.password_reset_request_id = p_passwordResetRequestId
     limit 1;

    if not found then
        return query select false, 'PASSWORD_RESET_NOT_FOUND'::text, null::uuid, null::uuid, null::text, null::text, null::text, null::integer, null::boolean, null::boolean, null::timestamp with time zone, null::timestamp with time zone, null::timestamp with time zone, null::integer, null::integer, null::uuid, false, false, false, null::text, null::text, null::text;
        return;
    end if;

    select a.email_address,
           a.verify_status = 1
      into v_email_address,
           v_email_verified
      from accounts a
     where a.account_id = v_reset.account_id;

    select t.phone_number, t.phone_country_code
      into v_phone_number, v_phone_country_code
      from two_factor_authentications t
     where t.account_id = v_reset.account_id
       and t.method = 2
       and t.verified = true
       and t.revoked_at is null
       and t.phone_number is not null
       and (t.expiration is null or t.expiration > now())
     order by t.required desc, t.priority asc, t.two_factor_index asc
     limit 1;

    v_sms_verified := v_phone_number is not null;

    v_authenticator_verified := exists(
        select 1
          from two_factor_authentications t
         where t.account_id = v_reset.account_id
           and t.method = 3
           and t.verified = true
           and t.revoked_at is null
           and (t.expiration is null or t.expiration > now())
           and t.totp_provider_type = 1
           and t.totp_secret_ciphertext is not null
           and octet_length(t.totp_secret_ciphertext) > 0
           and t.totp_secret_nonce is not null
           and octet_length(t.totp_secret_nonce) > 0
           and t.totp_secret_tag is not null
           and octet_length(t.totp_secret_tag) > 0
           and coalesce(t.totp_secret_version, 0) > 0
    );

    if v_reset.consumed_at is not null then
        return query select false, 'PASSWORD_RESET_CONSUMED'::text, v_reset.password_reset_request_id, v_reset.account_id, v_reset.method, v_reset.delivery_channel, v_reset.key_code_hash, v_reset.key_code_hash_version, v_reset.requires_key_code, v_reset.requires_totp, v_reset.expires_at, v_reset.consumed_at, v_reset.cancelled_at, v_reset.attempt_count, v_reset.max_attempts, v_reset.account_security_stamp_at_request, v_email_verified, v_sms_verified, v_authenticator_verified, v_email_address, v_phone_number, v_phone_country_code;
        return;
    end if;

    if v_reset.cancelled_at is not null then
        return query select false, 'PASSWORD_RESET_CANCELLED'::text, v_reset.password_reset_request_id, v_reset.account_id, v_reset.method, v_reset.delivery_channel, v_reset.key_code_hash, v_reset.key_code_hash_version, v_reset.requires_key_code, v_reset.requires_totp, v_reset.expires_at, v_reset.consumed_at, v_reset.cancelled_at, v_reset.attempt_count, v_reset.max_attempts, v_reset.account_security_stamp_at_request, v_email_verified, v_sms_verified, v_authenticator_verified, v_email_address, v_phone_number, v_phone_country_code;
        return;
    end if;

    if v_reset.expires_at <= now() then
        return query select false, 'PASSWORD_RESET_EXPIRED'::text, v_reset.password_reset_request_id, v_reset.account_id, v_reset.method, v_reset.delivery_channel, v_reset.key_code_hash, v_reset.key_code_hash_version, v_reset.requires_key_code, v_reset.requires_totp, v_reset.expires_at, v_reset.consumed_at, v_reset.cancelled_at, v_reset.attempt_count, v_reset.max_attempts, v_reset.account_security_stamp_at_request, v_email_verified, v_sms_verified, v_authenticator_verified, v_email_address, v_phone_number, v_phone_country_code;
        return;
    end if;

    return query select true, 'PASSWORD_RESET_READY'::text, v_reset.password_reset_request_id, v_reset.account_id, v_reset.method, v_reset.delivery_channel, v_reset.key_code_hash, v_reset.key_code_hash_version, v_reset.requires_key_code, v_reset.requires_totp, v_reset.expires_at, v_reset.consumed_at, v_reset.cancelled_at, v_reset.attempt_count, v_reset.max_attempts, v_reset.account_security_stamp_at_request, v_email_verified, v_sms_verified, v_authenticator_verified, v_email_address, v_phone_number, v_phone_country_code;
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
begin
    select *
      into v_reset
      from password_reset_requests pr
     where pr.password_reset_request_id = p_passwordResetRequestId
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

    if v_reset.expires_at <= v_failed_at then
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
begin
    perform cor02_lock_account_authority(p_accountId,'reset');
    select *
      into v_reset
      from password_reset_requests pr
     where pr.password_reset_request_id = p_passwordResetRequestId
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

    if v_reset.expires_at <= v_promoted_at then
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

    return query select true, 'PASSWORD_RESET_COMPLETED'::text, p_accountId, p_newSecurityStamp, v_promoted_at;
exception when sqlstate 'P0202' then
    return query select false,'PASSWORD_RESET_EXPIRED'::text,p_accountId,null::uuid,null::timestamptz;
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
    v_now timestamp with time zone := coalesce(p_now, now());
    v_retention interval := greatest(coalesce(p_retention, interval '30 days'), interval '1 day');
    v_cancelled_count integer := 0;
    v_deleted_count integer := 0;
begin
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


create table if not exists system_test_delivery_messages(
    delivery_id uuid primary key,
    created_at timestamptz not null default now(),
    channel text not null,
    purpose text not null,
    destination text not null,
    subject text null,
    body text not null,
    code text null,
    correlation_id text null
);

create index if not exists ix_system_test_delivery_messages_lookup
    on system_test_delivery_messages(channel, purpose, destination, created_at desc);



create or replace function session_refresh_credential_hash(p_key bytea,p_identity uuid)
returns text
language sql
immutable
as $$
    select upper(encode(digest(translate(rtrim(encode(hmac(convert_to('treehammock:refresh:v2:' || replace(p_identity::text,'-',''),'UTF8'),p_key,'sha256'),'base64'),'='),'+/','-_'),'sha256'),'hex'));
$$;

-- Refresh uses its own credential through the hard family deadline. An expired
-- access JWS is never admitted to ordinary authentication as a consequence.
create or replace function get_refresh_session(p_hash text,p_family uuid,p_generation bigint)
returns table(account_id uuid,refresh_token bytea,refreshes smallint,refresh_limit smallint,
    created_on timestamptz,session_lifespan interval,access_expiration timestamptz,
    session_expiration timestamptz,cut_off timestamptz,features smallint,security_stamp uuid,
    account_security_stamp uuid,session_id uuid,generation bigint,protocol_version integer,
    access_token_hash text,web_key text,
    entitlement_json text)
language plpgsql
volatile
as $$
declare owner uuid; projection jsonb;
begin
    select s.account_id into owner from sessions s where s.refresh_credential_hash=p_hash and s.session_id=p_family and s.generation=p_generation;
    if owner is null then return;end if;
    projection:=cor20_resolve_account(owner);
    return query select s.account_id,s.refresh_token,s.refreshes,s.refresh_limit,s.created_on,s.session_lifespan,
        s.access_expiration,s.session_expiration,least(s.cut_off,a.cut_off),(projection->>'features')::smallint,s.security_stamp,
        s.account_security_stamp,s.session_id,s.generation,s.protocol_version,s.access_token_hash,a.web_key, projection::text
    from sessions s join accounts a on a.account_id=s.account_id
    where s.refresh_credential_hash=p_hash and s.session_id=p_family and s.generation=p_generation
        and s.protocol_version=2 and s.account_security_stamp=a.security_stamp and a.verify_status=1
        and (a.unlock_when is null or a.unlock_when<=clock_timestamp())
        and s.session_expiration>clock_timestamp() and (s.cut_off is null or s.cut_off>clock_timestamp())
        and (a.cut_off is null or a.cut_off>clock_timestamp());
end;
$$;

create or replace function refresh_session(p_account uuid,p_stamp uuid,p_family uuid,p_generation bigint,
    p_old_hash text,p_refresh_hash text,p_new_hash text,p_key bytea,p_identity uuid,
    p_access_seconds integer,p_minimum_interval integer)
returns table(result boolean,code text,access_expiration timestamptz,session_expiration timestamptz,cut_off timestamptz,entitlement_json text)
language plpgsql
as $$
declare a accounts%rowtype; s sessions%rowtype; moment timestamptz; until_time timestamptz; cutoff timestamptz; projection jsonb;
begin
    -- SecurityOperationScope holds its operation root before this account gate.
    perform cor02_lock_account_authority(p_account,'account');
    select * into a from accounts where account_id=p_account;
    select * into s from sessions where access_token_hash=p_old_hash and account_id=p_account for update;
    moment:=clock_timestamp();
    cutoff:=least(s.cut_off,a.cut_off);
    if a.account_id is null or a.security_stamp is distinct from p_stamp or a.verify_status<>1
        or (a.unlock_when is not null and a.unlock_when>moment) or s.access_token_hash is null
        or s.account_security_stamp is distinct from p_stamp or s.session_id is distinct from p_family
        or s.generation is distinct from p_generation or s.protocol_version<>2
        or s.refresh_credential_hash is distinct from p_refresh_hash
        or s.session_expiration<=moment or cutoff<=moment then
        return query select false,'REFRESH_CREDENTIAL_STALE'::text,null::timestamptz,null::timestamptz,null::timestamptz,null::text; return;
    end if;
    if p_access_seconds not between 60 and 316310340 or p_minimum_interval not between 1 and 86400
        or p_minimum_interval>p_access_seconds or p_generation>=9007199254740991
        or octet_length(p_key) not between 32 and 512 or p_identity is null
        or p_identity='00000000-0000-0000-0000-000000000000'::uuid or p_identity=s.security_stamp
        or p_new_hash is null or length(p_new_hash)<>64 then raise exception 'Invalid refresh policy'; end if;
    if s.token_issued_on+make_interval(secs=>p_minimum_interval)>moment then
        return query select false,'REFRESH_TOO_EARLY'::text,null::timestamptz,null::timestamptz,null::timestamptz,null::text; return;
    end if;
    until_time:=least(moment+make_interval(secs=>p_access_seconds),s.session_expiration,cutoff);
    insert into sessions(access_token_hash,session_id,generation,protocol_version,refresh_credential_hash,token_issued_on,
        account_id,refresh_token,refreshes,refresh_limit,created_on,session_lifespan,access_expiration,
        session_expiration,cut_off,features,security_stamp,account_security_stamp)
    values(p_new_hash,p_family,p_generation+1,2,session_refresh_credential_hash(p_key,p_identity),moment,
        p_account,p_key,least(s.refreshes::integer+1,32767)::smallint,0,s.created_on,s.session_lifespan,
        until_time,s.session_expiration,cutoff,s.features,p_identity,p_stamp);
    update sessions set access_expiration=least(s.access_expiration,moment),
        session_expiration=greatest(s.created_on,moment) where access_token_hash=p_old_hash;
    -- Recheck after all lock/index waits. An expiry exception rolls back this
    -- function's writes before a controlled denial and its receipt are committed.
    perform cor02_require_live(until_time);
    perform cor02_require_live(s.session_expiration);
    if cutoff is not null then perform cor02_require_live(cutoff); end if;
    projection:=cor20_resolve_account(p_account);
    perform cor02_require_live(until_time);
    return query select true,'SESSION_REFRESHED'::text,until_time,s.session_expiration,cutoff,projection::text;
exception
    when sqlstate 'P0202' then
        return query select false,'REFRESH_CREDENTIAL_EXPIRED'::text,null::timestamptz,null::timestamptz,null::timestamptz,null::text;
    when unique_violation then
        return query select false,'REFRESH_CONFLICT'::text,null::timestamptz,null::timestamptz,null::timestamptz,null::text;
end;
$$;
-- COR10 is part of current pre-1.0 setup, not an appended migration.
create or replace function cor10_login_snapshot(p_hash text)
returns jsonb language sql volatile as $$
    select p.login_metadata || jsonb_build_object(
        'progressVersion',p.progress_version,'challengeId',p.challenge_id,
        'availableConfigurationsSnapshot',p.available_configurations,
        'selectedConfiguration',p.selected_two_factor_configuration,'state',p.state,
        'requiredMethods',p.required_methods,'completedMethods',p.completed_methods,
        'currentExpectedMethod',p.current_expected_method,'challengedMethod',p.challenged_method,
        'chosenDestination',p.chosen_destination,'challengeCodeHash',p.challenge_code_hash,
        'intraCodeKey',null,'challengeProviderTransactionId',p.challenge_provider_transaction_id,
        'challengeAttempts',p.challenge_attempts,'challengeResends',p.challenge_resends,
        'challengeExpiration',to_char(p.challenge_expiration at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'nextChallengeAllowedAt',to_char(p.next_challenge_allowed_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'expiration',to_char(p.expiration at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
    from pending_two_factor_sessions p join accounts a on a.account_id=p.account_id
    where p.pre_auth_access_token_hash=p_hash and p.login_metadata is not null
        and a.security_stamp=p.account_security_stamp and a.two_factor_access_token=p_hash
        and a.verify_status=1 and (a.unlock_when is null or a.unlock_when<=clock_timestamp())
        and p.expiration>clock_timestamp() and (a.cut_off is null or a.cut_off>clock_timestamp())
        and (nullif(p.login_metadata->>'cutOff','') is null or (p.login_metadata->>'cutOff')::timestamptz>clock_timestamp());
$$;

create or replace function cor10_lock_login(p_hash text,p_stamp uuid,p_version bigint)
returns pending_two_factor_sessions language plpgsql as $$
declare owner uuid; a accounts%rowtype; p pending_two_factor_sessions%rowtype;
begin
    select t.account_id into owner from pending_two_factor_sessions t where t.pre_auth_access_token_hash=p_hash;
    perform cor02_lock_account_authority(owner,'account');
    select * into a from accounts where account_id=owner;
    select * into p from pending_two_factor_sessions t where t.pre_auth_access_token_hash=p_hash for update;
    if p.account_id is null or p.login_metadata is null or p.account_security_stamp is distinct from p_stamp
        or a.security_stamp is distinct from p_stamp or a.two_factor_access_token is distinct from p_hash
        or a.verify_status<>1 or (a.unlock_when is not null and a.unlock_when>clock_timestamp()) then
        raise exception using errcode='P1001',message='Pending login authority changed'; end if;
    if p.progress_version<>p_version or p_version<1 or p_version>9007199254740991 then
        raise exception using errcode='P1001',message='Pending login version changed'; end if;
    perform cor02_require_live(p.expiration);
    if a.cut_off is not null then perform cor02_require_live(a.cut_off); end if;
    if nullif(p.login_metadata->>'cutOff','') is not null then perform cor02_require_live((p.login_metadata->>'cutOff')::timestamptz); end if;
    return p;
end;
$$;

create or replace function cor10_begin_login(p_hash text,p_snapshot jsonb)
returns table(result boolean,code text,snapshot text) language plpgsql as $$
declare owner uuid:=(p_snapshot->>'accountId')::uuid; stamp uuid:=(p_snapshot->>'accountSecurityStamp')::uuid;
    a accounts%rowtype; expires timestamptz:=(p_snapshot->>'expiration')::timestamptz;
begin
    perform cor02_lock_account_authority(owner,'account');
    select * into a from accounts where account_id=owner;
    if a.account_id is null or a.security_stamp is distinct from stamp or a.verify_status<>1
        or (a.unlock_when is not null and a.unlock_when>clock_timestamp()) then
        return query select false,'PENDING_TWO_FACTOR_MISMATCH'::text,null::text;return; end if;
    perform cor02_require_live(expires);
    if a.cut_off is not null then perform cor02_require_live(a.cut_off); end if;
    if nullif(p_snapshot->>'cutOff','') is not null then perform cor02_require_live((p_snapshot->>'cutOff')::timestamptz); end if;
    if octet_length(decode(p_snapshot->>'preAuthRefreshToken','base64')) not between 32 and 512
        or p_snapshot->>'webKey' is distinct from a.web_key or p_snapshot->>'state'<>'SelectionRequired'
        or (p_snapshot->>'progressVersion')::bigint is distinct from 1::bigint then raise exception 'Invalid initial login metadata'; end if;
    if nullif(p_snapshot->>'priorActiveAccessTokenHash','') is not null and not exists(
        select 1 from sessions s where s.account_id=owner and s.access_token_hash=p_snapshot->>'priorActiveAccessTokenHash'
        and s.account_security_stamp=stamp and s.session_expiration>clock_timestamp()) then
        return query select false,'PENDING_TWO_FACTOR_MISMATCH'::text,null::text;return; end if;
    delete from pending_two_factor_sessions t where t.account_id=owner;
    insert into pending_two_factor_sessions(pre_auth_access_token_hash,account_id,account_security_stamp,created_on,expiration,
        available_configurations,login_metadata)
    values(p_hash,owner,stamp,clock_timestamp(),expires,resolve_available_twofactor_configurations(owner),
        p_snapshot || jsonb_build_object('challengeCodeHash',null,'intraCodeKey',null,'challengeId',null));
    update accounts set two_factor_access_token=p_hash,two_auth_usage=0 where account_id=owner;
    perform cor02_require_live(expires);
    if a.cut_off is not null then perform cor02_require_live(a.cut_off); end if;
    if nullif(p_snapshot->>'cutOff','') is not null then perform cor02_require_live((p_snapshot->>'cutOff')::timestamptz); end if;
    return query select true,'PENDING_TWO_FACTOR_SET'::text,cor10_login_snapshot(p_hash)::text;
exception
    when sqlstate 'P0202' then return query select false,'PENDING_TWO_FACTOR_EXPIRED'::text,null::text;
end;
$$;

create or replace function cor10_issue_challenge(p_hash text,p_stamp uuid,p_version bigint,p_configuration smallint,
    p_method smallint,p_destination smallint,p_verifier text,p_expires timestamptz,p_limit smallint,p_cooldown integer)
returns table(result boolean,code text,snapshot text) language plpgsql as $$
declare p pending_two_factor_sessions%rowtype; required smallint[]; completed smallint[]; expected smallint; expires timestamptz;
begin
    p:=cor10_lock_login(p_hash,p_stamp,p_version);
    if p_version=9007199254740991 then return query select false,'LOGIN_PROOF_VERSION_LIMIT'::text,null::text;return;end if;
    if p.state in (5,6,7) or not p_configuration=any(p.available_configurations)
        or not p_configuration=any(resolve_available_twofactor_configurations(p.account_id)) then
        return query select false,'TWO_FACTOR_CONFIGURATION_UNAVAILABLE'::text,cor10_login_snapshot(p_hash)::text;return;end if;
    required:=case p_configuration when 1 then array[2]::smallint[] when 2 then array[1]::smallint[]
        when 3 then array[3]::smallint[] when 4 then array[2,3]::smallint[] when 5 then array[1,3]::smallint[] end;
    if p.selected_two_factor_configuration is distinct from p_configuration then completed:=array[]::smallint[];
    else completed:=p.completed_methods;end if;
    expected:=required[cardinality(completed)+1];
    if expected is distinct from p_method or p_destination is null or p_destination<0
        or (p_method=3 and p_destination<>0)
        or (p_method<>3 and p_destination>=coalesce(jsonb_array_length(p.login_metadata->case p_method when 1 then 'emailAddresses' else 'phoneNumbers' end),0)) or p_cooldown not between 1 and 86400 or p_limit<1 then
        return query select false,'TWO_FACTOR_METHOD_NOT_CURRENTLY_REQUIRED'::text,cor10_login_snapshot(p_hash)::text;return;end if;
    -- Advancing a delivered proof to local TOTP is not a resend. Reselecting or
    -- replacing an existing challenge, including TOTP, retains durable cooldown.
    if not (p_method=3 and p.challenge_id is null and cardinality(completed)>0)
        and p.next_challenge_allowed_at>clock_timestamp() then
        return query select false,'TWO_FACTOR_CHALLENGE_COOLDOWN'::text,cor10_login_snapshot(p_hash)::text;return;end if;
    if p_method<>3 and p.challenge_resends>=p_limit then
        return query select false,'TWO_FACTOR_CHALLENGE_RESEND_LIMIT'::text,cor10_login_snapshot(p_hash)::text;return;end if;
    if p_method<>3 and (p_verifier is null or length(p_verifier)<>64) then raise exception 'Missing challenge verifier'; end if;
    expires:=least(p_expires,p.expiration); perform cor02_require_live(expires);
    update pending_two_factor_sessions t set progress_version=t.progress_version+1,challenge_id=gen_random_uuid(),
        selected_two_factor_configuration=p_configuration,selected_at=coalesce(t.selected_at,clock_timestamp()),
        required_methods=required,completed_methods=completed,current_expected_method=expected,
        state=case expected when 1 then 3 when 2 then 2 when 3 then 4 end,
        challenged_method=expected,chosen_destination=p_destination,challenge_code_hash=case when p_method=3 then null else p_verifier end,
        challenge_expiration=expires,challenge_attempts=0,completed_at=null,
        challenge_resends=case when p_method=3 then t.challenge_resends else least(t.challenge_resends::integer+1,32767)::smallint end,
        next_challenge_allowed_at=clock_timestamp()+make_interval(secs=>p_cooldown)
        where t.pre_auth_access_token_hash=p_hash;
    perform cor02_require_live(expires);
    perform cor10_lock_login(p_hash,p_stamp,p_version+1);
    return query select true,'TWO_FACTOR_CHALLENGE_ISSUED'::text,cor10_login_snapshot(p_hash)::text;
exception
    when sqlstate 'P1001' then return query select false,'LOGIN_PROOF_STALE'::text,null::text;
    when sqlstate 'P0202' then return query select false,'PENDING_TWO_FACTOR_EXPIRED'::text,null::text;
end;
$$;

create or replace function cor10_cancel_challenge(p_hash text,p_stamp uuid,p_version bigint,p_challenge uuid)
returns table(result boolean,code text,snapshot text) language plpgsql as $$
declare p pending_two_factor_sessions%rowtype;
begin
    p:=cor10_lock_login(p_hash,p_stamp,p_version);
    if p_version=9007199254740991 then return query select false,'LOGIN_PROOF_VERSION_LIMIT'::text,null::text;return;end if;
    if p.challenge_id is distinct from p_challenge or p_challenge is null then
        return query select false,'LOGIN_PROOF_STALE'::text,null::text;return;end if;
    update pending_two_factor_sessions t set progress_version=t.progress_version+1,challenge_id=null,
        challenged_method=null,challenge_code_hash=null,challenge_expiration=null,chosen_destination=null
        where t.pre_auth_access_token_hash=p_hash;
    -- Keep the durable resend count and cooldown even after provider failure.
    perform cor02_require_live(p.expiration);
    perform cor10_lock_login(p_hash,p_stamp,p_version+1);
    return query select true,'TWO_FACTOR_CHALLENGE_CANCELLED'::text,cor10_login_snapshot(p_hash)::text;
exception
    when sqlstate 'P1001' then return query select false,'LOGIN_PROOF_STALE'::text,null::text;
    when sqlstate 'P0202' then return query select false,'PENDING_TWO_FACTOR_EXPIRED'::text,null::text;
end;
$$;

create or replace function cor10_complete_proof(p_hash text,p_stamp uuid,p_version bigint,p_challenge uuid,p_method smallint,
    p_verifier text,p_totp boolean,p_limit smallint)
returns table(result boolean,code text,snapshot text) language plpgsql as $$
declare p pending_two_factor_sessions%rowtype; accepted boolean; completed smallint[]; next_method smallint; attempts smallint;
begin
    p:=cor10_lock_login(p_hash,p_stamp,p_version);
    if p_version=9007199254740991 then return query select false,'LOGIN_PROOF_VERSION_LIMIT'::text,null::text;return;end if;
    if p.state in (5,6,7) or p.challenge_id is distinct from p_challenge or p_challenge is null
        or p.current_expected_method is distinct from p_method or p.challenged_method is distinct from p_method
        or not p.selected_two_factor_configuration=any(resolve_available_twofactor_configurations(p.account_id)) then
        return query select false,'LOGIN_PROOF_STALE'::text,null::text;return;end if;
    perform cor02_require_live(p.challenge_expiration);
    if p_limit<1 then raise exception 'Invalid proof attempt policy';end if;
    if p.challenge_attempts>=p_limit then return query select false,'TWO_FACTOR_CHALLENGE_ATTEMPT_LIMIT'::text,null::text;return;end if;
    accepted:=case when p_method=3 then coalesce(p_totp,false)
        else p_verifier is not null and p.challenge_code_hash is not null and p_verifier=p.challenge_code_hash end;
    if not accepted then
        attempts:=least(p.challenge_attempts::integer+1,32767)::smallint;
        update pending_two_factor_sessions t set challenge_attempts=attempts,progress_version=t.progress_version+1,
            state=case when attempts>=p_limit then 7 else t.state end,
            challenge_code_hash=case when attempts>=p_limit then null else t.challenge_code_hash end
            where t.pre_auth_access_token_hash=p_hash;
        perform cor02_require_live(p.challenge_expiration);
        perform cor10_lock_login(p_hash,p_stamp,p_version+1);
        return query select false,case when attempts>=p_limit then 'TWO_FACTOR_CHALLENGE_ATTEMPT_LIMIT' else 'TWO_FACTOR_CHALLENGE_INCORRECT' end::text,cor10_login_snapshot(p_hash)::text;return;
    end if;
    completed:=array_append(p.completed_methods,p_method);
    next_method:=p.required_methods[cardinality(completed)+1];
    update pending_two_factor_sessions t set progress_version=t.progress_version+1,completed_methods=completed,
        state=case when next_method is null then 5 when next_method=3 then 4 when next_method=2 then 2 else 3 end,
        current_expected_method=next_method,completed_at=case when next_method is null then clock_timestamp() else null end,
        challenge_id=null,challenged_method=null,challenge_code_hash=null,challenge_expiration=null,chosen_destination=null,challenge_attempts=0
        where t.pre_auth_access_token_hash=p_hash;
    perform cor02_require_live(p.challenge_expiration);
    perform cor10_lock_login(p_hash,p_stamp,p_version+1);
    return query select true,'LOGIN_PROOF_ACCEPTED'::text,cor10_login_snapshot(p_hash)::text;
exception
    when sqlstate 'P1001' then return query select false,'LOGIN_PROOF_STALE'::text,null::text;
    when sqlstate 'P0202' then return query select false,'PENDING_TWO_FACTOR_EXPIRED'::text,null::text;
end;
$$;

create or replace function cor12_delivery_predecessor(p_account uuid,p_purpose text)
returns text language plpgsql stable as $$
begin
    return (select jsonb_build_array(a.security_stamp,
      case p_purpose
        when 'verify' then jsonb_build_array(a.verify_status,(select jsonb_agg(jsonb_build_array(v.verification_index,v.proof_version,v.verify_status) order by v.verification_index) from account_verifications v where v.account_id=a.account_id and v.verify_status in (0,2,4)))
        when 'unlock' then jsonb_build_array(a.unlock_when,(select v.attempt_version from account_login_attempt_versions v where v.account_id=a.account_id and v.credential_stamp=a.security_stamp),(select jsonb_agg(jsonb_build_array(r.request_version,r.status) order by r.request_version) from account_recoveries r where r.account_id=a.account_id and r.topic=1 and r.status in (1,2,3,6)))
        when 'reset-factor' then jsonb_build_array((select jsonb_agg(encode(digest(to_jsonb(t)::text,'sha256'),'hex') order by t.reset_access_token_hash) from pending_password_reset_sessions t where t.account_id=a.account_id),(select jsonb_agg(jsonb_build_array(r.password_reset_request_id,r.consumed_at,r.cancelled_at) order by r.password_reset_request_id) from password_reset_requests r where r.account_id=a.account_id))
        when 'email-notice' then jsonb_build_array('trusted-address-notice')
        when 'activation' then (select jsonb_agg(jsonb_build_array(g.grant_id,g.version,g.state,q.request_id,q.origin_stamp,q.family_id) order by g.grant_id) from entitlement_grants g join grant_activation_requests q using(grant_id) where g.account_id=a.account_id and q.state in ('queued','pending'))
        when 'email' then (select jsonb_build_array(r.verify_key_hash,r.requested_at) from account_email_change_requests r where r.account_id=a.account_id)
        when 'delete' then (select jsonb_build_array(d.request_id,d.delete_token_hash,d.origin_stamp) from delete_standby d where d.account_id=a.account_id)
        when 'reset' then (select jsonb_agg(jsonb_build_array(r.password_reset_request_id,r.consumed_at,r.cancelled_at) order by r.password_reset_request_id) from password_reset_requests r where r.account_id=a.account_id and r.cancelled_at is null and r.consumed_at is null)
        else (select jsonb_agg(jsonb_build_array(t.two_factor_index,t.token,t.verified,t.revoked_at) order by t.two_factor_index) from two_factor_authentications t where t.account_id=a.account_id and t.method=right(p_purpose,1)::smallint)
      end)::text from accounts a where a.account_id=p_account);
end;
$$;

create or replace function cor12_lock_delivery(p_account uuid)
returns void language plpgsql as $$
begin
    perform cor02_lock_account_authority(p_account,'all');
    perform 1 from delivery_candidates c where c.account_id=p_account order by c.delivery_id for update;
    perform 1 from delivery_outbox o join delivery_candidates c using(delivery_id)
     where c.account_id=p_account order by o.delivery_id for update of o;
end;
$$;

create or replace function cor12_delivery_is_pending(p_purpose text,p_hash text,p_account uuid default null)
returns boolean language plpgsql as $$
begin
    return exists(select 1 from delivery_candidates c join delivery_outbox o using(delivery_id)
      where (p_account is null or c.account_id=p_account) and c.purpose=p_purpose and c.proof_hash=p_hash and c.state='staged'
        and o.state in ('queued','claimed','accepted','ambiguous') and c.expires_at>clock_timestamp() and
        (p_purpose<>'activation' or cor19_request_live(c.delivery_id,c.account_stamp,c.proof_hash)) and
        (p_purpose<>'delete' or exists(select 1 from delete_standby d where d.account_id=c.account_id and d.delete_token_hash=p_hash and cor18_delete_live(d))) and
        (p_purpose<>'email' or exists(select 1 from account_email_change_requests q where q.request_id=c.delivery_id and cor17_email_live(q))));
end;
$$;

create or replace function cor12_expire_delivery(p_id uuid)
returns void language plpgsql as $$
declare owner uuid;
begin
    select c.account_id into owner from delivery_candidates c where c.delivery_id=p_id;
    if not found then return;end if;
    perform cor12_lock_delivery(owner);
    update delivery_attempts a set state='unknown',code='DELIVERY_EXPIRED_WITHOUT_RECEIPT',recorded_at=clock_timestamp() where a.delivery_id=p_id and a.state='claimed';
    update delivery_candidates c set state='expired',terminal_at=clock_timestamp() where c.delivery_id=p_id and c.state='staged';
    update delivery_outbox o set state='expired',nonce=null,ciphertext=null,tag=null,lease_id=null,lease_until=null where o.delivery_id=p_id and o.state not in ('published','rejected','superseded','expired');
end;
$$;

create or replace function cor12_stage_delivery(p_id uuid,p_account uuid,p_stamp uuid,p_purpose text,p_hash text,
    p_expires timestamptz,p_metadata text,p_key integer,p_nonce bytea,p_cipher bytea,p_tag bytea,p_noticeId uuid default null,p_noticeKey integer default null,p_noticeNonce bytea default null,p_noticeCipher bytea default null,p_noticeTag bytea default null,p_noticeMetadata text default null)
returns table(result boolean,code text,delivery_id uuid) language plpgsql as $$
declare a accounts%rowtype; prior delivery_candidates%rowtype; prior_state text; m jsonb:=p_metadata::jsonb; existing_delete delete_standby%rowtype; setup_result record; notice_result record; constraint_value text;
begin
    if p_purpose in ('email','email-notice') then perform cor17_email_gate();perform cor17_purge_email_requests();end if;
    perform cor12_lock_delivery(p_account);
    select * into a from accounts where account_id=p_account;
    if not found or a.security_stamp is distinct from p_stamp then
        return query select false,'ACCOUNT_SECURITY_STAMP_MISMATCH'::text,null::uuid;return;
    end if;
    if p_purpose is null or p_purpose not in ('verify','unlock','reset','email','delete','factor-1','factor-2','reset-factor','email-notice','activation') or nullif(btrim(p_hash),'') is null
       or p_expires is null or p_expires<=clock_timestamp() or p_expires>clock_timestamp()+interval '24 hours'
       or m is null or jsonb_typeof(m)<>'object' or p_key is null or p_key<=0 or p_nonce is null or octet_length(p_nonce)<>12 or p_cipher is null or octet_length(p_cipher)>65536 or p_tag is null or octet_length(p_tag)<>16 then
        return query select false,'DELIVERY_INVALID_CANDIDATE'::text,null::uuid;return;
    end if;
    if p_purpose='activation' and (not cor08_live_sensitive_authority(p_account,p_stamp,m->>'sessionHash',(m->>'familyId')::uuid) or not cor19_grant_live((m->>'grantId')::uuid,p_account,p_stamp,(m->>'grantVersion')::bigint)) then return query select false,'ACTIVATION_TRUSTED_GRANT_REQUIRED'::text,null::uuid;return;end if;
    if p_purpose='activation' and not cor21_creation_live((m->>'admissionId')::uuid,p_account,p_stamp,(m->>'familyId')::uuid,(m->>'grantId')::uuid,(m->>'grantVersion')::bigint,p_hash) then return query select false,'ACTIVATION_CREATION_ADMISSION_REQUIRED'::text,null::uuid;return;end if;
    if p_purpose='delete' and not exists(select 1 from account_delete_admissions q where q.account_id=p_account and q.admission_id=(m->>'admissionId')::uuid and q.proof_hash=p_hash and q.origin_stamp=p_stamp and cor18_admission_live(q)) then
        return query select false,'ACCOUNT_DELETE_AUTHORITY_CHANGED'::text,null::uuid;return;end if;
    if p_purpose='email' and not cor08_validate_sensitive_grant(p_account,p_stamp,m->>'grantSession',m->>'grantToken',5::smallint,m->>'grantTarget',false) then
        return query select false,'SENSITIVE_ACTION_GRANT_REQUIRED'::text,null::uuid;return;end if;
    if p_purpose in ('factor-1','factor-2') and not cor08_validate_sensitive_grant(p_account,p_stamp,m->>'grantSession',m->>'grantToken',
        case p_purpose when 'factor-1' then 3::smallint else 4::smallint end,m->>'grantTarget',false) then
        return query select false,'SENSITIVE_ACTION_GRANT_REQUIRED'::text,null::uuid;return;end if;
    if p_purpose in ('factor-1','factor-2') and exists(select 1 from delivery_candidates c join delivery_outbox o using(delivery_id)
        where c.account_id=p_account and c.purpose in ('factor-1','factor-2') and c.state='staged' and o.state in ('claimed','accepted','ambiguous')) then
        return query select false,'TWO_FACTOR_SETUP_DELIVERY_PENDING'::text,null::uuid;return;end if;
    select c.* into prior from delivery_candidates c where c.account_id=p_account and (c.purpose=p_purpose or (p_purpose in ('factor-1','factor-2') and c.purpose in ('factor-1','factor-2'))) and c.state='staged' and p_purpose<>'email-notice';
    if found then
        if prior.expires_at<=clock_timestamp() then perform cor12_expire_delivery(prior.delivery_id);
        else
            select o.state into prior_state from delivery_outbox o where o.delivery_id=prior.delivery_id;
            if prior_state in ('claimed','accepted','ambiguous') and p_purpose in ('factor-1','factor-2') then return query select false,'TWO_FACTOR_SETUP_DELIVERY_PENDING'::text,null::uuid;return;end if;
            if prior_state in ('claimed','accepted','ambiguous') and p_purpose='activation' then return query select false,'ACTIVATION_CONFLICT'::text,null::uuid;return;end if;
            if prior_state in ('claimed','accepted','ambiguous') and p_purpose='delete' then return query select false,'ACCOUNT_DELETE_CONFLICT'::text,null::uuid;return;end if;
            if prior_state in ('claimed','accepted','ambiguous') and p_purpose='email' then return query select false,'ACCOUNT_ADJUST_CONFLICT'::text,null::uuid;return;end if;
            if prior_state in ('claimed','accepted','ambiguous') then
                return query select true,'DELIVERY_PENDING'::text,prior.delivery_id;return;
            end if;
        end if;
    end if;
    case p_purpose
      when 'verify' then
        if a.verify_status=1 then return query select true,'VERIFICATION_ALREADY_COMPLETE'::text,null::uuid;return;end if;
        if m->>'mode'='start' and not exists(select 1 from account_verifications v where v.account_id=p_account and v.verify_key_hash=p_hash and v.verification_index=(m->>'verificationIndex')::bigint and v.verify_status=0 and v.account_security_stamp=p_stamp) then
            return query select false,'DELIVERY_STALE_CANDIDATE'::text,null::uuid;return;
        end if;
      when 'unlock' then
        if a.unlock_when is null or a.unlock_when<=clock_timestamp() then return query select false,'ACCOUNT_UNLOCK_NOT_LOCKED'::text,null::uuid;return;end if;
        if a.unlock_when is distinct from (m->>'lockoutUnlockWhen')::timestamptz or
           coalesce((select v.attempt_version from account_login_attempt_versions v where v.account_id=p_account and v.credential_stamp=p_stamp),'00000000-0000-0000-0000-000000000000'::uuid) is distinct from (m->>'lockoutAttemptVersion')::uuid then
            return query select false,'ACCOUNT_UNLOCK_STALE_LOCKOUT'::text,null::uuid;return;
        end if;
        if (m->>'method')::integer not in (1,2) then return query select false,'ACCOUNT_UNLOCK_BAD_METHOD'::text,null::uuid;return;end if;
      when 'email' then
        if p_noticeId is null or p_noticeKey is null or p_noticeKey<=0 or p_noticeNonce is null or octet_length(p_noticeNonce)<>12 or p_noticeCipher is null or octet_length(p_noticeCipher)>65536 or p_noticeTag is null or octet_length(p_noticeTag)<>16 or p_noticeMetadata is null then
            return query select false,'DELIVERY_INVALID_CANDIDATE'::text,null::uuid;return;end if;
        select * into setup_result from cor17_authorized_request_email(p_account,p_stamp,m->>'newEmailAddress',p_hash,p_expires,p_id,m->>'grantSession',m->>'grantToken',m->>'grantTarget',m->>'originEmail');
        if not setup_result.result then return query select false,setup_result.code::text,null::uuid;return;end if;
      when 'email-notice' then
        if not exists(select 1 from account_email_change_requests q where q.account_id=p_account and q.verify_key_hash=p_hash and q.origin_grant_hash is not null and q.account_security_stamp=p_stamp and
            q.origin_email=lower(m->>'originEmail') and m->>'requestProofHash'=p_hash and cor17_email_live(q)) then return query select false,'ACCOUNT_ADJUST_AUTHORITY_CHANGED'::text,null::uuid;return;end if;
      when 'activation' then
        select * into setup_result from cor19_stage_activation(p_id,p_account,p_stamp,m->>'sessionHash',(m->>'familyId')::uuid,(m->>'grantId')::uuid,(m->>'grantVersion')::bigint,p_hash,p_expires,m->>'emailAddress',(m->>'tier')::smallint,(m->>'term')::smallint,(m->>'cadence')::smallint,(m->>'admissionId')::uuid);
        if not setup_result.result then return query select false,setup_result.code::text,null::uuid;return;end if;
      when 'delete' then
        select * into setup_result from cor18_stage_delete(p_account,p_stamp,(m->>'admissionId')::uuid,p_hash,p_expires,m->>'passPhraseHash');
        if not setup_result.result then return query select false,setup_result.code::text,null::uuid;return;end if;
      when 'reset-factor' then
        if not exists(select 1 from password_reset_requests q where q.password_reset_request_id=(m->>'resetId')::uuid and q.account_id=p_account and q.cancelled_at is null and q.consumed_at is null and q.expires_at>clock_timestamp()) or
            exists(select 1 from pending_password_reset_sessions q where q.reset_access_token_hash=m->>'sessionHash' and q.revoked_at is not null) then
            return query select false,'PASSWORD_RESET_SESSION_REVOKED'::text,null::uuid;return;
        end if;
      when 'reset' then
        if (m->>'resetId')::uuid is distinct from p_id or (m->>'maxAttempts')::integer<=0 or (m->>'method') not in ('email','sms') then return query select false,'PASSWORD_RESET_FAILED'::text,null::uuid;return;end if;
      else
        if exists(select 1 from two_factor_authentications t where t.account_id=p_account and t.method=right(p_purpose,1)::smallint and t.verified and t.revoked_at is null) then
            return query select false,'TWO_FACTOR_SETUP_DUPLICATE'::text,null::uuid;return;
        end if;
        if p_purpose='factor-1' and lower(m->>'emailAddress') is distinct from lower(a.email_address) then return query select false,'TWO_FACTOR_SETUP_INVALID_DESTINATION'::text,null::uuid;return;end if;
        if p_purpose='factor-2' and nullif(btrim(m->>'phoneNumber'),'') is null then return query select false,'TWO_FACTOR_SETUP_INVALID_DESTINATION'::text,null::uuid;return;end if;
    end case;
    if p_purpose in ('factor-1','factor-2') then
        select * into setup_result from cor16_begin_twofactor_setup(p_account,p_stamp,right(p_purpose,1)::smallint,p_hash,clock_timestamp(),p_expires,
            m->>'emailAddress',m->>'phoneNumber',m->>'phoneCountryCode',null,coalesce((m->>'required')::boolean,true),p_id,
            (m->>'expectedEnrollmentId')::uuid,(m->>'expectedVersion')::bigint,m->>'grantSession',m->>'grantToken',m->>'grantTarget');
        if not setup_result.result then return query select false,setup_result.code::text,null::uuid;return;end if;
    end if;
    update delivery_candidates c set state='superseded' ,terminal_at=clock_timestamp() where c.account_id=p_account and (c.purpose=p_purpose or (p_purpose in ('factor-1','factor-2') and c.purpose in ('factor-1','factor-2'))) and c.state='staged' and p_purpose<>'email-notice';
    update delivery_outbox o set state='superseded',nonce=null,ciphertext=null,tag=null,lease_id=null,lease_until=null from delivery_candidates c
      where o.delivery_id=c.delivery_id and c.account_id=p_account and (c.purpose=p_purpose or (p_purpose in ('factor-1','factor-2') and c.purpose in ('factor-1','factor-2'))) and c.state='superseded' and o.state='queued';
    insert into delivery_candidates(delivery_id,account_id,account_stamp,purpose,proof_hash,expires_at,metadata_json,predecessor,state)
    values(p_id,p_account,p_stamp,p_purpose,p_hash,p_expires,p_metadata,cor12_delivery_predecessor(p_account,p_purpose),'staged');
    if not found then raise exception 'Delivery candidate write missing' using errcode='P1901';end if;
    insert into delivery_outbox(delivery_id,state,key_version,nonce,ciphertext,tag) values(p_id,'queued',p_key,p_nonce,p_cipher,p_tag);
    if not found then raise exception 'Delivery job write missing' using errcode='P1901';end if;
    perform cor02_require_live(p_expires);
    if p_purpose='email' then
        select * into notice_result from cor12_stage_delivery(p_noticeId,p_account,p_stamp,'email-notice',p_hash,p_expires,p_noticeMetadata,p_noticeKey,p_noticeNonce,p_noticeCipher,p_noticeTag);
        if not coalesce(notice_result.result,false) or notice_result.delivery_id is distinct from p_noticeId then raise exception 'Email notification staging failed' using errcode='P1701';end if;
        if not exists(select 1 from account_email_change_requests q where q.request_id=p_id and cor17_email_live(q)) then raise exception 'Email authority expired during staging' using errcode='P1701';end if;
    end if;
    if p_purpose='delete' and not exists(select 1 from delete_standby d where d.account_id=p_account and d.delete_token_hash=p_hash and cor18_delete_live(d)) then raise exception 'Delete authority expired during staging' using errcode='P1801';end if;
    if p_purpose='activation' and not cor19_request_live(p_id,p_stamp,p_hash) then raise exception 'Activation authority expired during staging' using errcode='P1902';end if;
    return query select true,'DELIVERY_PENDING'::text,p_id;
exception
    when sqlstate 'P1902' then return query select false,'ACTIVATION_EXPIRED'::text,null::uuid;
    when sqlstate 'P1801' then return query select false,'ACCOUNT_DELETE_CONFLICT'::text,null::uuid;
    when sqlstate 'P1701' then return query select false,'ACCOUNT_ADJUST_CONFLICT'::text,null::uuid;
    when unique_violation then
        get stacked diagnostics constraint_value=constraint_name;
        if constraint_value in ('ux_delivery_candidates_email','ux_account_email_change_new_email_lower') then return query select false,'ACCOUNT_ADJUST_DUPLICATE_EMAIL'::text,null::uuid;
        elsif constraint_value in ('delivery_candidates_pkey','ux_delivery_candidates_current') then return query select false,'DELIVERY_CANDIDATE_CONFLICT'::text,null::uuid;else raise;end if;
    when sqlstate 'P0202' then return query select false,'DELIVERY_EXPIRED'::text,null::uuid;
end;
$$;

create or replace function cor23j_delivery_can_send(p_id uuid,p_lease uuid)
returns boolean language plpgsql as $$
declare owner uuid; c delivery_candidates%rowtype; o delivery_outbox%rowtype;
begin
    select t.account_id into owner from delivery_candidates t where t.delivery_id=p_id;
    if not found then return false;end if;
    if exists(select 1 from delivery_candidates q where q.delivery_id=p_id and q.purpose='email') then perform cor17_email_gate();end if;
    perform cor12_lock_delivery(owner);
    select t.* into c from delivery_candidates t where t.delivery_id=p_id;
    select j.* into o from delivery_outbox j where j.delivery_id=p_id;
    if c.delivery_id is null or o.delivery_id is null or c.state<>'staged' or o.state<>'claimed'
        or o.lease_id is distinct from p_lease or o.lease_until is null or o.lease_until<=clock_timestamp() or c.expires_at<=clock_timestamp()
        or not exists(select 1 from delivery_attempts a where a.attempt_id=p_lease and a.delivery_id=p_id and a.state='claimed') then return false;end if;
    if c.purpose<>'email-notice' and (c.predecessor is distinct from cor12_delivery_predecessor(owner,c.purpose)
        or not exists(select 1 from accounts a where a.account_id=owner and a.security_stamp=c.account_stamp)) then return false;end if;
    if c.purpose='activation' and not cor19_request_live(p_id,c.account_stamp,c.proof_hash) then return false;end if;
    if c.purpose='delete' and not exists(select 1 from delete_standby d where d.account_id=owner and d.delete_token_hash=c.proof_hash and cor18_delete_live(d)) then return false;end if;
    if c.purpose='email' and not exists(select 1 from account_email_change_requests q where q.request_id=p_id and q.verify_key_hash=c.proof_hash and cor17_email_live(q)) then return false;end if;
    if c.purpose in ('factor-1','factor-2') then
        begin
            if not exists(select 1 from two_factor_authentications t where t.account_id=owner and t.setup_request_id=p_id and t.token=c.proof_hash and not t.verified) then return false;end if;
            perform cor16_require_setup(t,c.account_stamp,t.setup_family_id) from two_factor_authentications t where t.account_id=owner and t.setup_request_id=p_id;
        exception when sqlstate 'P1601' or sqlstate 'P0202' then return false;end;
    end if;
    -- This authorizes dispatch at this boundary; later security revocation still fences publication/consumption.
    return c.expires_at>clock_timestamp() and o.lease_until>clock_timestamp();
end;
$$;

create or replace function cor12_claim_delivery(p_lease uuid,p_seconds integer,p_max integer)
returns table(delivery_id uuid,account_id uuid,account_stamp uuid,purpose text,proof_hash text,expires_at timestamptz,
    metadata_json text,key_version integer,nonce bytea,ciphertext bytea,tag bytea,state text,lease_id uuid,attempts integer)
language plpgsql as $$
declare chosen uuid; owner uuid; c delivery_candidates%rowtype; o delivery_outbox%rowtype;
begin
    if p_seconds not between 5 and 120 or p_max not between 1 and 5 then raise exception 'Invalid delivery claim policy';end if;
    -- Include expired/abandoned jobs so retained payload is erased/reconciled without a send.
    select t.delivery_id,t.account_id into chosen,owner from delivery_candidates t join delivery_outbox j using(delivery_id)
     where t.state='staged' and (t.expires_at<=clock_timestamp() or (j.state='claimed' and j.lease_until<=clock_timestamp()) or
          j.state='accepted' or (j.state='queued' and j.next_attempt<=clock_timestamp())) order by t.created_at,t.delivery_id limit 1;
    if not found then
        delete from delivery_candidates t using (select q.delivery_id from delivery_candidates q where q.state<>'staged' and q.terminal_at<clock_timestamp()-interval '7 days' order by q.terminal_at,q.delivery_id limit 100) old where t.delivery_id=old.delivery_id and t.state<>'staged';return;
    end if;
    if exists(select 1 from delivery_candidates q where q.delivery_id=chosen and q.purpose='email') then perform cor17_email_gate();end if;
    perform cor12_lock_delivery(owner);
    select * into c from delivery_candidates t where t.delivery_id=chosen;
    select * into o from delivery_outbox j where j.delivery_id=chosen;
    if c.state<>'staged' then return;end if;
    if c.expires_at<=clock_timestamp() then perform cor12_expire_delivery(chosen);return query select c.delivery_id,c.account_id,c.account_stamp,c.purpose,c.proof_hash,c.expires_at,c.metadata_json,o.key_version,'\x'::bytea,'\x'::bytea,'\x'::bytea,'expired'::text,null::uuid,o.attempts;return;end if;
    if o.state='claimed' then
        if o.lease_until<=clock_timestamp() then
            update delivery_attempts a set state='unknown',code='DELIVERY_ABANDONED',recorded_at=clock_timestamp()
                where a.attempt_id=o.lease_id and a.delivery_id=chosen and a.state='claimed';
            update delivery_outbox j set state='ambiguous',lease_until=null where j.delivery_id=chosen;return query select c.delivery_id,c.account_id,c.account_stamp,c.purpose,c.proof_hash,c.expires_at,c.metadata_json,o.key_version,'\x'::bytea,'\x'::bytea,'\x'::bytea,'ambiguous'::text,o.lease_id,o.attempts;end if;
        return;
    end if;
    if c.purpose<>'email-notice' and (c.predecessor is distinct from cor12_delivery_predecessor(owner,c.purpose) or not exists(select 1 from accounts a where a.account_id=owner and a.security_stamp=c.account_stamp)) then
        update delivery_candidates t set state='superseded',terminal_at=clock_timestamp() where t.delivery_id=chosen;
        update delivery_outbox j set state='superseded',nonce=null,ciphertext=null,tag=null,lease_id=null,lease_until=null where j.delivery_id=chosen;return query select c.delivery_id,c.account_id,c.account_stamp,c.purpose,c.proof_hash,c.expires_at,c.metadata_json,o.key_version,'\x'::bytea,'\x'::bytea,'\x'::bytea,'superseded'::text,null::uuid,o.attempts;return;
    end if;
    if c.purpose='activation' and not cor19_request_live(chosen,c.account_stamp,c.proof_hash) then perform cor12_expire_delivery(chosen);return;end if;
    if c.purpose='delete' and not exists(select 1 from delete_standby d where d.account_id=owner and d.delete_token_hash=c.proof_hash and cor18_delete_live(d)) then perform cor12_expire_delivery(chosen);return;end if;
    if c.purpose='email' and not exists(select 1 from account_email_change_requests q where q.request_id=chosen and q.verify_key_hash=c.proof_hash and cor17_email_live(q)) then perform cor12_expire_delivery(chosen);return;end if;
    if c.purpose in ('factor-1','factor-2') then
        begin
            if not exists(select 1 from two_factor_authentications t where t.account_id=owner and t.setup_request_id=chosen and t.token=c.proof_hash and not t.verified) then
                raise exception 'Setup no longer pending' using errcode='P1601';end if;
            perform cor16_require_setup(t,c.account_stamp,t.setup_family_id) from two_factor_authentications t where t.account_id=owner and t.setup_request_id=chosen;
        exception when sqlstate 'P1601' or sqlstate 'P0202' then
            perform cor12_expire_delivery(chosen);return;
        end;
    end if;
    if o.state='queued' then
        if o.attempts>=p_max or o.next_attempt>clock_timestamp() then return;end if;
        update delivery_outbox j set state='claimed',lease_id=p_lease,lease_until=clock_timestamp()+make_interval(secs=>p_seconds),attempts=j.attempts+1
          where j.delivery_id=chosen and j.state='queued' returning j.* into o;
        if not found then return;end if;
        insert into delivery_attempts(attempt_id,delivery_id,attempt_number,state) values(p_lease,chosen,o.attempts,'claimed');
    elsif o.state<>'accepted' then return;end if;
    if c.purpose='activation' and not cor19_request_live(chosen,c.account_stamp,c.proof_hash) then perform cor12_expire_delivery(chosen);return;end if;
    if c.purpose='delete' and not exists(select 1 from delete_standby d where d.account_id=owner and d.delete_token_hash=c.proof_hash and cor18_delete_live(d)) then perform cor12_expire_delivery(chosen);return;end if;
    if c.purpose='email' and not exists(select 1 from account_email_change_requests q where q.request_id=chosen and cor17_email_live(q)) then perform cor12_expire_delivery(chosen);return;end if;
    return query select c.delivery_id,c.account_id,c.account_stamp,c.purpose,c.proof_hash,c.expires_at,c.metadata_json,
        o.key_version,coalesce(o.nonce,'\x'::bytea),coalesce(o.ciphertext,'\x'::bytea),coalesce(o.tag,'\x'::bytea),o.state,o.lease_id,o.attempts;
end;
$$;

create or replace function cor12_record_delivery(p_id uuid,p_lease uuid,p_state text,p_max integer,
    p_provider text default 'none',p_receipt text default null,p_retry boolean default false,p_code text default 'DELIVERY_OUTCOME')
returns boolean language plpgsql as $$
declare owner uuid; c delivery_candidates%rowtype; o delivery_outbox%rowtype; a delivery_attempts%rowtype;
begin
    if p_state is null or p_state not in ('accepted','not_submitted','rejected','unknown') or p_max is null or p_max not between 1 and 5
        or p_retry is null or (p_retry and p_state<>'not_submitted') or p_provider is null or p_provider !~ '^[a-z0-9-]{1,32}$'
        or p_code is null or p_code !~ '^[A-Z0-9_]{1,64}$'
        or (p_receipt is not null and (length(p_receipt) not between 1 and 128 or p_receipt ~ '[^A-Za-z0-9_.@:-]')) then return false;end if;
    select t.account_id into owner from delivery_candidates t where t.delivery_id=p_id;
    if not found then return false;end if;
    perform cor12_lock_delivery(owner);
    select t.* into c from delivery_candidates t where t.delivery_id=p_id;
    select j.* into o from delivery_outbox j where j.delivery_id=p_id;
    select t.* into a from delivery_attempts t where t.attempt_id=p_lease and t.delivery_id=p_id;
    if a.attempt_id is null then return false;end if;
    -- Exact result replay cannot replace a final receipt, even after publication cleared the lease.
    if a.state in ('accepted','not_submitted','rejected') then
        return a.state=p_state and a.provider=p_provider and a.receipt_id is not distinct from p_receipt and a.can_retry=p_retry and a.code=p_code;
    end if;
    if c.delivery_id is null or o.delivery_id is null or p_lease is null or c.state<>'staged' or o.state not in ('claimed','ambiguous') or o.lease_id is distinct from p_lease then return false;end if;
    -- A late definitive accepted/rejected receipt may resolve its own unknown attempt; never requeue uncertainty.
    if a.state='unknown' and p_state='not_submitted' then return false;end if;
    if c.expires_at<=clock_timestamp() then perform cor12_expire_delivery(p_id);return false;end if;
    update delivery_attempts t set state=p_state,provider=p_provider,receipt_id=p_receipt,can_retry=p_retry,code=p_code,recorded_at=clock_timestamp()
        where t.attempt_id=p_lease and t.delivery_id=p_id;
    if p_state='accepted' then
        update delivery_outbox j set state='accepted',nonce=null,ciphertext=null,tag=null,lease_until=null where j.delivery_id=p_id;
    elsif p_state='not_submitted' and p_retry and o.state='claimed' and o.attempts<p_max then
        update delivery_outbox j set state='queued',next_attempt=clock_timestamp()+make_interval(secs=>least(300,5*(2^o.attempts)::integer)),lease_id=null,lease_until=null where j.delivery_id=p_id;
    elsif p_state='unknown' then
        update delivery_outbox j set state='ambiguous',lease_until=null where j.delivery_id=p_id;
    else
        update delivery_candidates t set state='rejected',terminal_at=clock_timestamp() where t.delivery_id=p_id;
        update delivery_outbox j set state='rejected',nonce=null,ciphertext=null,tag=null,lease_id=null,lease_until=null where j.delivery_id=p_id;
    end if;
    return true;
end;
$$;

create or replace function cor12_publish_delivery(p_id uuid)
returns boolean language plpgsql as $$
declare owner uuid; c delivery_candidates%rowtype; m jsonb; ok boolean:=false; status_value smallint;
begin
    select t.account_id into owner from delivery_candidates t where t.delivery_id=p_id;
    if not found then return false;end if;
    if exists(select 1 from delivery_candidates q where q.delivery_id=p_id and q.purpose='email') then perform cor17_email_gate();end if;
    perform cor12_lock_delivery(owner);
    select * into c from delivery_candidates t where t.delivery_id=p_id;
    if not found or c.state<>'staged' or not exists(select 1 from delivery_outbox j where j.delivery_id=p_id and j.state='accepted') then return false;end if;
    if c.expires_at<=clock_timestamp() then perform cor12_expire_delivery(p_id);return false;end if;
    if c.purpose<>'email-notice' and (not exists(select 1 from accounts a where a.account_id=owner and a.security_stamp=c.account_stamp) or c.predecessor is distinct from cor12_delivery_predecessor(owner,c.purpose)) then
        update delivery_candidates t set state='superseded',terminal_at=clock_timestamp() where t.delivery_id=p_id;
        update delivery_outbox j set state='superseded' where j.delivery_id=p_id;return false;
    end if;
    m:=c.metadata_json::jsonb;
    -- Nested exception scope rolls back every domain replacement on failure/late expiry.
    begin
      case c.purpose
        when 'verify' then
          if m->>'mode'='start' then select r.result into ok from start_verify_account(owner,(m->>'verificationIndex')::bigint) r;
          else select r.result into ok from resend_verify_account((select a.email_address from accounts a where a.account_id=owner),c.proof_hash,make_interval(secs=>(m->>'verificationSeconds')::integer)) r;end if;
          if ok then update account_verifications v set expiration=c.expires_at-v.sent_when where v.account_id=owner and v.verify_key_hash=c.proof_hash and v.verify_status in (2,4);end if;
        when 'unlock' then
          select r.status into status_value from start_unlock_account(owner,c.proof_hash,clock_timestamp(),c.expires_at,2::smallint,(m->>'method')::smallint,c.account_stamp,(m->>'lockoutUnlockWhen')::timestamptz,(m->>'lockoutAttemptVersion')::uuid) r;
          ok:=status_value=2;
        when 'email' then ok:=exists(select 1 from account_email_change_requests q where q.request_id=p_id and q.verify_key_hash=c.proof_hash and cor17_email_live(q));
        when 'email-notice' then ok:=true;
        when 'activation' then ok:=cor19_publish_activation(p_id,c.account_stamp,c.proof_hash);
        when 'delete' then ok:=exists(select 1 from delete_standby d where d.account_id=owner and d.delete_token_hash=c.proof_hash and cor18_delete_live(d));
        when 'reset-factor' then
          select r.result into ok from transition_pending_password_reset_session(m->>'sessionHash',(m->>'resetId')::uuid,owner,(m->>'bootstrapProof')::smallint,(m->>'state')::smallint,
            array(select x::smallint from jsonb_array_elements_text(m->'availableConfigurations') x),(m->>'selectedConfiguration')::smallint,
            array(select x::smallint from jsonb_array_elements_text(m->'requiredMethods') x),array(select x::smallint from jsonb_array_elements_text(m->'completedMethods') x),
            (m->>'currentExpectedMethod')::smallint,c.proof_hash,c.expires_at,(m->>'challengeAttempts')::integer,(m->>'challengeResends')::integer,
            (m->>'nextChallengeAllowedAt')::timestamptz,(m->>'createdOn')::timestamptz,(m->>'expiresAt')::timestamptz,(m->>'selectedAt')::timestamptz,
            (m->>'twoFactorCompletedAt')::timestamptz,(m->>'passwordChangedAt')::timestamptz,
            (m->>'transition')::smallint,(m->>'expectedSessionVersion')::bigint,(m->>'expectedChallengeVersion')::bigint,null) r;
        when 'reset' then select r.result into ok from create_password_reset_request(p_id,owner,m->>'method',m->>'deliveryChannel',c.proof_hash,(m->>'hashVersion')::integer,m->>'destinationFingerprint',m->>'destinationMasked',true,coalesce((m->>'requiresTotp')::boolean,false),c.expires_at,(m->>'maxAttempts')::integer,(m->>'requestedByIp')::inet,m->>'requestedByUserAgent',c.account_stamp) r;
        else
          ok:=exists(select 1 from two_factor_authentications t where t.account_id=owner and t.setup_request_id=p_id and t.token=c.proof_hash and not t.verified and t.revoked_at is null);
          if ok then perform cor16_require_setup(t,c.account_stamp,t.setup_family_id) from two_factor_authentications t where t.account_id=owner and t.setup_request_id=p_id;end if;
      end case;
      if not coalesce(ok,false) then raise exception using errcode='P0212',message='Delivery publication denied';end if;
      perform cor02_require_live(c.expires_at);
      update delivery_candidates t set state='published',terminal_at=clock_timestamp() where t.delivery_id=p_id and t.state='staged';
      update delivery_outbox j set state='published',nonce=null,ciphertext=null,tag=null,lease_id=null,lease_until=null where j.delivery_id=p_id;
      if c.purpose='activation' and not cor19_request_live(p_id,c.account_stamp,c.proof_hash) then raise exception 'Activation publication expired' using errcode='P0212';end if;
      if c.purpose='email' and not exists(select 1 from account_email_change_requests q where q.request_id=p_id and cor17_email_live(q)) then raise exception 'Email authority expired during publication' using errcode='P1701';end if;
      if c.purpose='delete' and not exists(select 1 from delete_standby d where d.account_id=owner and d.delete_token_hash=c.proof_hash and cor18_delete_live(d)) then raise exception 'Delete authority expired during publication' using errcode='P1801';end if;
      return true;
    exception when sqlstate 'P1801' or sqlstate 'P0212' or sqlstate 'P0202' or sqlstate 'P1601' or sqlstate 'P1701' or unique_violation then
      update delivery_candidates t set state=case when c.expires_at<=clock_timestamp() then 'expired' else 'rejected' end,terminal_at=clock_timestamp() where t.delivery_id=p_id;
      update delivery_outbox j set state=case when c.expires_at<=clock_timestamp() then 'expired' else 'rejected' end,nonce=null,ciphertext=null,tag=null,lease_id=null,lease_until=null where j.delivery_id=p_id;
      return false;
    end;
end;
$$;

-- Internal cancellation compares immutable job identity and stamp; it cannot cancel a later candidate.
create or replace function cor12_cancel_delivery(p_id uuid,p_account uuid,p_stamp uuid)
returns boolean language plpgsql as $$
begin
    perform cor12_lock_delivery(p_account);
    if not exists(select 1 from accounts a where a.account_id=p_account and a.security_stamp=p_stamp) then return false;end if;
    update delivery_candidates c set state='rejected',terminal_at=clock_timestamp() where c.delivery_id=p_id and c.account_id=p_account and c.account_stamp=p_stamp and c.state='staged';
    if not found then return false;end if;
    update delivery_outbox o set state='rejected',nonce=null,ciphertext=null,tag=null,lease_id=null,lease_until=null where o.delivery_id=p_id;
    return true;
end;
$$;

-- Operator maintenance: authenticated v2 decrypt/reencrypt/verification occurs outside locks; this write is CAS fenced.
create or replace function cor15_reencrypt_totp(
    p_accountId uuid, p_enrollmentId uuid, p_expectedVersion bigint, p_oldKeyId text,
    p_newKeyId text, p_ciphertext bytea, p_nonce bytea, p_tag bytea)
returns boolean language plpgsql as $$
declare current_record two_factor_authentications%rowtype;
begin
    perform cor02_lock_account_authority(p_accountId, 'factor');
    select * into current_record from two_factor_authentications t
        where t.account_id=p_accountId and t.totp_enrollment_id=p_enrollmentId for update;
    if not found or current_record.method<>3 or current_record.revoked_at is not null or
        current_record.totp_row_version is distinct from p_expectedVersion or current_record.totp_key_id is distinct from p_oldKeyId or
        current_record.totp_secret_version<>2 or p_newKeyId is null or p_newKeyId !~ '^[A-Za-z0-9_-]{1,64}$' or
        p_ciphertext is null or octet_length(p_ciphertext)<>octet_length(current_record.totp_secret_ciphertext) or
        p_nonce is null or octet_length(p_nonce)<>12 or p_tag is null or octet_length(p_tag)<>16 then return false; end if;
    update two_factor_authentications set totp_key_id=p_newKeyId, totp_secret_ciphertext=p_ciphertext,
        totp_secret_nonce=p_nonce, totp_secret_tag=p_tag
        where account_id=p_accountId and totp_enrollment_id=p_enrollmentId and totp_row_version=p_expectedVersion;
    return found;
end;
$$;

-- COR16 current setup authority. These are current definitions, not a schema migration.
create or replace function cor16_clear_setup_authority()
returns trigger language plpgsql as $$
begin
    if new.verified or new.revoked_at is not null or new.token is null then
        new.setup_request_id:=null;new.setup_version:=null;new.setup_origin_stamp:=null;
        new.setup_family_id:=null;new.setup_factor_policy:=null;new.setup_authorized_until:=null;
    end if;
    return new;
end;
$$;
create trigger cor16_setup_lifecycle before insert or update on two_factor_authentications
for each row execute function cor16_clear_setup_authority();
alter table two_factor_authentications add constraint ck_cor16_setup_binding check (
    (setup_request_id is null and setup_version is null and setup_origin_stamp is null and setup_family_id is null and setup_factor_policy is null and setup_authorized_until is null)
    or (not verified and revoked_at is null and token is not null and expiration is not null and
        setup_request_id is not null and setup_request_id<>'00000000-0000-0000-0000-000000000000'::uuid and
        setup_version is not null and setup_version between 1 and 9007199254740991 and setup_origin_stamp is not null and
        setup_family_id is not null and setup_factor_policy is not null and setup_authorized_until is not null));
create unique index ux_cor16_setup_request on two_factor_authentications(setup_request_id) where setup_request_id is not null;

create or replace function cor16_require_setup(p_row two_factor_authentications,p_stamp uuid,p_family uuid)
returns void language plpgsql as $$
begin
    if (p_row.expiration is not null and p_row.expiration<=clock_timestamp()) or (p_row.setup_authorized_until is not null and p_row.setup_authorized_until<=clock_timestamp()) then
        raise exception 'Setup expired' using errcode='P0202';end if;
    if p_row.setup_request_id is null or p_row.setup_version is null or p_row.setup_origin_stamp is distinct from p_stamp or
        p_row.setup_family_id is distinct from p_family or p_family is null or p_row.setup_factor_policy is distinct from cor08_factor_policy(p_row.account_id) or
        p_row.verified or p_row.revoked_at is not null or p_row.token is null or p_row.expiration is null or
        p_row.expiration<=clock_timestamp() or p_row.setup_authorized_until is null or p_row.setup_authorized_until<=clock_timestamp() or
        not exists(select 1 from accounts a join sessions s using(account_id) where a.account_id=p_row.account_id and
            a.security_stamp=p_stamp and a.verify_status=1 and (a.cut_off is null or a.cut_off>clock_timestamp()) and
            (a.unlock_when is null or a.unlock_when<=clock_timestamp()) and s.session_id=p_family and s.account_security_stamp=p_stamp and
            s.access_expiration>clock_timestamp() and s.session_expiration>clock_timestamp() and (s.cut_off is null or s.cut_off>clock_timestamp())) then
        raise exception 'Setup authority changed or expired' using errcode='P1601';
    end if;
end;
$$;

create or replace function cor16_bind_setup(p_account uuid,p_index bigint,p_request uuid,p_version bigint,p_grant text)
returns void language plpgsql as $$
declare g record; changed integer;
begin
    select * into g from sensitive_action_grants where token_hash=p_grant and account_id=p_account and consumed_on is not null;
    if not found or g.expiration<=clock_timestamp() then raise exception 'Setup grant missing' using errcode='P1601';end if;
    update two_factor_authentications t set setup_request_id=p_request,setup_version=p_version,setup_origin_stamp=g.credential_stamp,
        setup_family_id=g.family_id,setup_factor_policy=g.factor_policy,setup_authorized_until=least(t.expiration,g.expiration)
        where t.account_id=p_account and t.two_factor_index=p_index and not t.verified and t.revoked_at is null and t.token is not null;
    get diagnostics changed=row_count;
    if changed<>1 then raise exception 'Setup binding conflict' using errcode='P1601';end if;
end;
$$;

create or replace function cor16_factor_changed(p_account uuid)
returns void language plpgsql as $$
declare revocation record;
begin
    select * into revocation from revoke_pending_password_reset_sessions_for_account(p_account,clock_timestamp(),'TWO_FACTOR_POLICY_CHANGED');
    if not coalesce(revocation.result,false) then raise exception 'Reset revocation failed' using errcode='P1601';end if;
    delete from pending_two_factor_sessions where account_id=p_account;
    delete from sensitive_action_grants where account_id=p_account;
    delete from sensitive_action_proof_sessions where account_id=p_account;
    delete from sensitive_password_attempts where account_id=p_account;
end;
$$;

create or replace function cor16_begin_twofactor_setup(p_accountId uuid,p_accountSecurityStamp uuid,p_method smallint,p_tokenHash text,
    p_createdOn timestamptz,p_expiration timestamptz,p_emailAddress text,p_phoneNumber text,p_phoneCountryCode text,p_authId text,p_required boolean,
    p_requestId uuid,p_expectedRequestId uuid,p_expectedVersion bigint,p_grantSession text,p_grantToken text,p_grantTarget text)
returns table(result boolean,code text,two_factor_index bigint,expiration timestamptz)
language plpgsql as $$
declare a accounts%rowtype; prior two_factor_authentications%rowtype; idx bigint; version bigint; changed integer;purpose smallint;
begin
    perform cor02_lock_account_authority(p_accountId,'factor');
    select * into a from accounts where account_id=p_accountId;
    purpose:=case p_method when 1 then 3 when 2 then 4 else 0 end;
    if not found or a.security_stamp is distinct from p_accountSecurityStamp or purpose=0 or
        not cor08_validate_sensitive_grant(p_accountId,p_accountSecurityStamp,p_grantSession,p_grantToken,purpose,p_grantTarget,false) then
        return query select false,'SENSITIVE_ACTION_GRANT_REQUIRED'::text,null::bigint,null::timestamptz;return;
    end if;
    if p_requestId is null or p_requestId='00000000-0000-0000-0000-000000000000'::uuid or nullif(btrim(p_tokenHash),'') is null or
        p_createdOn is null or p_expiration is null or p_expiration<=clock_timestamp() or p_expiration<=p_createdOn or
        (p_method=1 and lower(p_emailAddress) is distinct from lower(a.email_address)) or
        (p_method=2 and (nullif(btrim(p_phoneNumber),'') is null or nullif(btrim(p_phoneCountryCode),'') is null)) then
        return query select false,'TWO_FACTOR_SETUP_INVALID_DESTINATION'::text,null::bigint,null::timestamptz;return;
    end if;
    if exists(select 1 from two_factor_authentications t where t.account_id=p_accountId and t.method=p_method and t.verified and t.revoked_at is null) then
        return query select false,'TWO_FACTOR_SETUP_DUPLICATE'::text,null::bigint,null::timestamptz;return;
    end if;
    select * into prior from two_factor_authentications t where t.account_id=p_accountId and not t.verified and t.revoked_at is null order by t.two_factor_index limit 1 for update;
    if found then
        if prior.setup_request_id is distinct from p_expectedRequestId or prior.setup_version is distinct from p_expectedVersion or p_expectedRequestId is null or
            p_expectedVersion is null or p_expectedVersion>=9007199254740991 then
            return query select false,'TWO_FACTOR_SETUP_CONFLICT'::text,null::bigint,null::timestamptz;return;
        end if;
        idx:=prior.two_factor_index;version:=p_expectedVersion+1;
    else
        if p_expectedRequestId is not null or p_expectedVersion is not null then return query select false,'TWO_FACTOR_SETUP_CONFLICT'::text,null::bigint,null::timestamptz;return;end if;
        idx:=null;version:=1;
    end if;
    if not cor08_validate_sensitive_grant(p_accountId,p_accountSecurityStamp,p_grantSession,p_grantToken,purpose,p_grantTarget,true) then
        raise exception 'Setup grant changed' using errcode='P1601';end if;
    if prior.account_id is null then
        insert into two_factor_authentications(account_id,method,verified,token,created_on,expiration,lifespan,email_address,phone_number,phone_country_code,required)
        values(p_accountId,p_method,false,p_tokenHash,p_createdOn,p_expiration,p_expiration-p_createdOn,case when p_method=1 then lower(a.email_address) end,
            case when p_method=2 then btrim(p_phoneNumber) end,case when p_method=2 then btrim(p_phoneCountryCode) end,p_required) returning two_factor_authentications.two_factor_index into idx;
        get diagnostics changed=row_count;
    else
        update two_factor_authentications t set method=p_method,token=p_tokenHash,created_on=p_createdOn,expiration=p_expiration,lifespan=p_expiration-p_createdOn,
            email_address=case when p_method=1 then lower(a.email_address) end,phone_number=case when p_method=2 then btrim(p_phoneNumber) end,
            phone_country_code=case when p_method=2 then btrim(p_phoneCountryCode) end,required=p_required,setup_attempts=0
        where t.account_id=p_accountId and t.two_factor_index=idx and not t.verified and t.revoked_at is null and t.setup_request_id=p_expectedRequestId and t.setup_version=p_expectedVersion;
        get diagnostics changed=row_count;
    end if;
    if changed<>1 then raise exception 'Setup write conflict' using errcode='P1601';end if;
    perform cor16_bind_setup(p_accountId,idx,p_requestId,version,p_grantToken);
    perform cor16_require_setup(t,p_accountSecurityStamp,t.setup_family_id) from two_factor_authentications t where t.account_id=p_accountId and t.two_factor_index=idx;
    return query select true,'TWO_FACTOR_SETUP_PENDING'::text,idx,p_expiration;
exception when sqlstate 'P1601' or unique_violation then return query select false,'TWO_FACTOR_SETUP_CONFLICT'::text,null::bigint,null::timestamptz;
end;
$$;

-- COR17 current registered-email authority and serialized reservation lifecycle.
create or replace function cor17_email_gate() returns void language sql as $$ select pg_advisory_xact_lock(548017001); $$;

create or replace function cor17_email_live(p_row account_email_change_requests)
returns boolean language plpgsql as $$
begin
    return (select coalesce(p_row.request_id is not null and p_row.origin_grant_hash is not null and p_row.expiration>clock_timestamp() and p_row.authorized_until>clock_timestamp() and
        p_row.origin_factor_policy=cor08_factor_policy(p_row.account_id) and
        exists(select 1 from accounts a join sessions s using(account_id) where a.account_id=p_row.account_id and a.security_stamp=p_row.account_security_stamp and
            lower(a.email_address)=lower(p_row.origin_email) and a.verify_status=1 and (a.cut_off is null or a.cut_off>clock_timestamp()) and
            (a.unlock_when is null or a.unlock_when<=clock_timestamp()) and s.session_id=p_row.origin_family and s.account_security_stamp=p_row.account_security_stamp and
            s.access_expiration>clock_timestamp() and s.session_expiration>clock_timestamp() and (s.cut_off is null or s.cut_off>clock_timestamp())),false));
end;
$$;

create or replace function cor17_retire_email_request(p_account uuid,p_hash text)
returns integer language plpgsql as $$
declare removed integer;
begin
    update delivery_candidates c set state='expired',terminal_at=clock_timestamp() where c.account_id=p_account and c.purpose='email' and c.proof_hash=p_hash and c.state='staged';
    update delivery_outbox o set state='expired',nonce=null,ciphertext=null,tag=null,lease_id=null,lease_until=null from delivery_candidates c where o.delivery_id=c.delivery_id and c.account_id=p_account and c.purpose='email' and c.proof_hash=p_hash and c.state='expired';
    delete from account_email_change_requests r where r.account_id=p_account and r.verify_key_hash=p_hash;
    get diagnostics removed=row_count;return removed;
end;
$$;

create or replace function cor17_purge_email_requests()
returns integer language plpgsql as $$
declare r record; retired integer:=0;
begin
    perform cor17_email_gate();
    for r in
        select q.account_id,q.verify_key_hash from account_email_change_requests q where not cor17_email_live(q)
        union select c.account_id,c.proof_hash from delivery_candidates c where c.purpose='email' and c.state='staged' and
            (c.expires_at<=clock_timestamp() or not exists(select 1 from account_email_change_requests q where q.request_id=c.delivery_id and q.verify_key_hash=c.proof_hash and cor17_email_live(q)))
        order by account_id limit 100
    loop
        perform 1 from accounts a where a.account_id=r.account_id for update skip locked;
        if not found then continue;end if;
        if exists(select 1 from account_email_change_requests q where q.account_id=r.account_id and q.verify_key_hash=r.verify_key_hash and not cor17_email_live(q)) or
           exists(select 1 from delivery_candidates c where c.account_id=r.account_id and c.purpose='email' and c.proof_hash=r.verify_key_hash and c.state='staged' and
                (c.expires_at<=clock_timestamp() or not exists(select 1 from account_email_change_requests q where q.request_id=c.delivery_id and q.verify_key_hash=c.proof_hash and cor17_email_live(q)))) then
            retired:=retired+cor17_retire_email_request(r.account_id,r.verify_key_hash);
        end if;
    end loop;
    return retired;
end;
$$;

create or replace function cor17_authorized_request_email(p_account uuid,p_stamp uuid,p_email text,p_hash text,p_expires timestamptz,p_request uuid,p_session text,p_grant text,p_target text,p_origin text)
returns table(result boolean,code text,email_address text) language plpgsql as $$
declare g record; changed integer; constraint_value text; normalized text:=lower(nullif(btrim(p_email),''));
begin
    perform cor17_email_gate();
    perform cor17_purge_email_requests();
    perform cor12_lock_delivery(p_account);
    if not cor08_validate_sensitive_grant(p_account,p_stamp,p_session,p_grant,5::smallint,p_target,false) then return query select false,'SENSITIVE_ACTION_GRANT_REQUIRED'::text,null::text;return;end if;
    if normalized is null or length(normalized)>1024 or p_request is null or nullif(p_hash,'') is null or p_expires is null or p_expires<=clock_timestamp() or
        not exists(select 1 from accounts a where a.account_id=p_account and lower(a.email_address)=lower(p_origin)) then return query select false,'ACCOUNT_ADJUST_FAILED'::text,null::text;return;end if;
    if exists(select 1 from accounts a where lower(a.email_address)=normalized) or exists(select 1 from account_email_change_requests r where r.account_id<>p_account and lower(r.new_email_address)=normalized) then
        return query select false,'ACCOUNT_ADJUST_DUPLICATE_EMAIL'::text,null::text;return;end if;
    if not cor08_validate_sensitive_grant(p_account,p_stamp,p_session,p_grant,5::smallint,p_target,true) then raise exception 'Email grant changed' using errcode='P1701';end if;
    select * into g from sensitive_action_grants where token_hash=p_grant;
    insert into account_email_change_requests(account_id,new_email_address,verify_key_hash,requested_at,expiration,account_security_stamp,request_id,origin_email,origin_family,origin_factor_policy,authorized_until,origin_grant_hash)
    values(p_account,normalized,p_hash,clock_timestamp(),p_expires,p_stamp,p_request,lower(p_origin),g.family_id,g.factor_policy,least(p_expires,g.expiration),p_grant)
    on conflict(account_id) do update set new_email_address=excluded.new_email_address,verify_key_hash=excluded.verify_key_hash,requested_at=excluded.requested_at,expiration=excluded.expiration,account_security_stamp=excluded.account_security_stamp,
        request_id=excluded.request_id,origin_email=excluded.origin_email,origin_family=excluded.origin_family,origin_factor_policy=excluded.origin_factor_policy,authorized_until=excluded.authorized_until,origin_grant_hash=excluded.origin_grant_hash;
    get diagnostics changed=row_count;if changed<>1 then raise exception 'Email reservation conflict' using errcode='P1701';end if;
    if not exists(select 1 from account_email_change_requests q where q.account_id=p_account and q.request_id=p_request and cor17_email_live(q)) then raise exception 'Email authority changed' using errcode='P1701';end if;
    return query select true,'ACCOUNT_ADJUST_EMAIL_VERIFICATION_PENDING'::text,normalized;
exception
    when sqlstate 'P1701' then return query select false,'ACCOUNT_ADJUST_CONFLICT'::text,null::text;
    when unique_violation then
        get stacked diagnostics constraint_value=constraint_name;
        if constraint_value='ux_account_email_change_new_email_lower' then return query select false,'ACCOUNT_ADJUST_DUPLICATE_EMAIL'::text,null::text;else raise;end if;
end;
$$;

-- COR18 destructive authority and budgets are current setup definitions.
create or replace function cor18_origin_live(p_account uuid,p_stamp uuid,p_email text,p_family uuid,p_policy text,p_until timestamptz,p_expires timestamptz)
returns boolean language plpgsql as $$
begin return p_until>clock_timestamp() and p_expires>clock_timestamp() and p_policy=cor08_factor_policy(p_account) and exists(
    select 1 from accounts a join sessions s using(account_id) where a.account_id=p_account and a.security_stamp=p_stamp and lower(a.email_address)=p_email and a.verify_status=1 and
    (a.cut_off is null or a.cut_off>clock_timestamp()) and (a.unlock_when is null or a.unlock_when<=clock_timestamp()) and
    s.session_id=p_family and s.account_security_stamp=p_stamp and s.access_expiration>clock_timestamp() and s.session_expiration>clock_timestamp() and (s.cut_off is null or s.cut_off>clock_timestamp()));end;
$$;
create or replace function cor18_delete_live(p_row delete_standby)
returns boolean language plpgsql as $$
begin return coalesce(p_row.request_id is not null and cor18_origin_live(p_row.account_id,p_row.origin_stamp,p_row.origin_email,p_row.origin_family,p_row.origin_factor_policy,p_row.authorized_until,p_row.expiration),false);end;
$$;
create or replace function cor18_admission_live(p_row account_delete_admissions)
returns boolean language plpgsql as $$
begin return coalesce(cor18_origin_live(p_row.account_id,p_row.origin_stamp,p_row.origin_email,p_row.origin_family,p_row.origin_factor_policy,p_row.authorized_until,p_row.expires_at),false);end;
$$;
create or replace function cor18_retire_delete(p_account uuid,p_hash text)
returns void language plpgsql as $$
begin
    update delivery_candidates c set state='expired',terminal_at=clock_timestamp() where c.account_id=p_account and c.purpose='delete' and c.proof_hash=p_hash and c.state='staged';
    update delivery_outbox o set state='expired',nonce=null,ciphertext=null,tag=null,lease_id=null,lease_until=null from delivery_candidates c where c.delivery_id=o.delivery_id and c.account_id=p_account and c.purpose='delete' and c.proof_hash=p_hash and c.state='expired';
    delete from delete_standby q where q.account_id=p_account and q.delete_token_hash=p_hash;
end;
$$;
create or replace function cor18_revoke_delete(p_account uuid)
returns void language plpgsql as $$
begin
    perform cor18_retire_delete(p_account,d.delete_token_hash) from delete_standby d where d.account_id=p_account;
    delete from account_delete_admissions q where q.account_id=p_account;
end;
$$;
create or replace function cor18_admit_delete(p_account uuid,p_stamp uuid,p_id uuid,p_hash text,p_expires timestamptz,p_cooldown interval,p_window interval,p_max smallint,p_session text,p_grant text,p_target text)
returns table(result boolean,code text,email_address text,workflow smallint) language plpgsql as $$
declare a accounts%rowtype; b account_delete_budgets%rowtype; g record; decision_time timestamptz; affected integer;
begin
    perform cor12_lock_delivery(p_account);
    if not cor08_validate_sensitive_grant(p_account,p_stamp,p_session,p_grant,6::smallint,p_target,false) then return query select false,'SENSITIVE_ACTION_GRANT_REQUIRED'::text,null::text,0::smallint;return;end if;
    select * into a from accounts where accounts.account_id=p_account;
    if p_id is null or p_id='00000000-0000-0000-0000-000000000000'::uuid or nullif(btrim(p_hash),'') is null or p_expires<=clock_timestamp() or p_cooldown<=interval '0' or p_window<=interval '0' or p_max<=0 or p_cooldown is null or p_window is null or p_max is null or p_expires is null then return query select false,'ACCOUNT_DELETE_FAILED'::text,null::text,0::smallint;return;end if;
    perform cor18_retire_delete(p_account,d.delete_token_hash) from delete_standby d where d.account_id=p_account and not cor18_delete_live(d);
    select * into b from account_delete_budgets q where q.account_id=p_account for update;
    decision_time:=clock_timestamp();
    if found and (b.next_request_allowed_at>decision_time or (b.window_start+p_window>decision_time and b.requested_count>=p_max) or b.finalize_locked_until>decision_time) then return query select false,'ACCOUNT_DELETE_RATE_LIMITED'::text,null::text,0::smallint;return;end if;
    if exists(select 1 from delivery_candidates c join delivery_outbox o using(delivery_id) where c.account_id=p_account and c.purpose='delete' and c.state='staged' and o.state in ('claimed','accepted','ambiguous')) then return query select false,'ACCOUNT_DELETE_CONFLICT'::text,null::text,0::smallint;return;end if;
    select * into g from sensitive_action_grants q where q.token_hash=p_grant;
    if not cor08_validate_sensitive_grant(p_account,p_stamp,p_session,p_grant,6::smallint,p_target,true) then return query select false,'SENSITIVE_ACTION_GRANT_REQUIRED'::text,null::text,0::smallint;return;end if;
    if not exists(select 1 from sensitive_action_grants v where v.token_hash=p_grant and v.account_id=p_account and v.consumed_on is not null) then raise exception 'No delete grant consumption effect' using errcode='P1801';end if;
    insert into account_delete_budgets(account_id,window_start,requested_count,next_request_allowed_at) values(p_account,decision_time,1,decision_time+p_cooldown)
    on conflict(account_id) do update set window_start=case when account_delete_budgets.window_start+p_window<=decision_time then decision_time else account_delete_budgets.window_start end,
        requested_count=case when account_delete_budgets.window_start+p_window<=decision_time then 1 else account_delete_budgets.requested_count+1 end,next_request_allowed_at=decision_time+p_cooldown;
    get diagnostics affected=row_count;if affected<>1 then raise exception 'No delete budget effect' using errcode='P1801';end if;
    insert into account_delete_admissions(account_id,admission_id,proof_hash,origin_stamp,origin_email,origin_family,origin_factor_policy,authorized_until,expires_at,grant_hash)
    values(p_account,p_id,p_hash,p_stamp,lower(a.email_address),g.family_id,g.factor_policy,least(g.expiration,p_expires),p_expires,p_grant)
    on conflict(account_id) do update set admission_id=excluded.admission_id,proof_hash=excluded.proof_hash,origin_stamp=excluded.origin_stamp,origin_email=excluded.origin_email,origin_family=excluded.origin_family,origin_factor_policy=excluded.origin_factor_policy,authorized_until=excluded.authorized_until,expires_at=excluded.expires_at,grant_hash=excluded.grant_hash;
    get diagnostics affected=row_count;if affected<>1 or not exists(select 1 from account_delete_admissions q where q.admission_id=p_id and cor18_admission_live(q)) then raise exception 'No live delete admission' using errcode='P1801';end if;
    insert into account_delete_events(account_id,event_type,code,request_id,credential_stamp) values(p_account,'ADMITTED','ACCOUNT_DELETE_PENDING',p_id,p_stamp);
    return query select true,'ACCOUNT_DELETE_PENDING'::text,a.email_address,0::smallint;
exception when sqlstate 'P1801' then return query select false,'ACCOUNT_DELETE_CONFLICT'::text,null::text,0::smallint;
end;
$$;
create or replace function cor18_stage_delete(p_account uuid,p_stamp uuid,p_admission uuid,p_hash text,p_expires timestamptz,p_passphrase text)
returns table(result boolean,code text) language plpgsql as $$
declare q account_delete_admissions%rowtype;affected integer;
begin
    perform cor12_lock_delivery(p_account);
    select * into q from account_delete_admissions a where a.account_id=p_account and a.admission_id=p_admission and a.proof_hash=p_hash for update;
    if not found or q.origin_stamp is distinct from p_stamp or q.expires_at is distinct from p_expires or not cor18_admission_live(q) then return query select false,'ACCOUNT_DELETE_AUTHORITY_CHANGED'::text;return;end if;
    insert into delete_standby(account_id,pass_phrase_hash,delete_token_hash,expiration,verified,request_id,origin_stamp,origin_email,origin_family,origin_factor_policy,authorized_until)
    values(p_account,nullif(btrim(p_passphrase),''),p_hash,p_expires,false,q.admission_id,q.origin_stamp,q.origin_email,q.origin_family,q.origin_factor_policy,q.authorized_until)
    on conflict(account_id) do update set pass_phrase_hash=excluded.pass_phrase_hash,delete_token_hash=excluded.delete_token_hash,expiration=excluded.expiration,verified=false,request_id=excluded.request_id,
        origin_stamp=excluded.origin_stamp,origin_email=excluded.origin_email,origin_family=excluded.origin_family,origin_factor_policy=excluded.origin_factor_policy,authorized_until=excluded.authorized_until;
    get diagnostics affected=row_count;if affected<>1 then raise exception 'No delete reservation effect' using errcode='P1801';end if;
    delete from account_delete_admissions a where a.account_id=p_account and a.admission_id=p_admission;
    get diagnostics affected=row_count;if affected<>1 then raise exception 'No delete admission consumption' using errcode='P1801';end if;
    return query select true,'ACCOUNT_DELETE_PENDING'::text;
end;
$$;
create or replace function cor18_finalize_denial(p_row delete_standby,p_stamp uuid,p_session text,p_max smallint,p_lockout interval)
returns text language plpgsql as $$
begin
    if p_max is null or p_max<=0 or p_lockout is null or p_lockout<=interval '0' then return 'ACCOUNT_DELETE_FAILED';end if;
    if p_row.account_id is null then return 'ACCOUNT_DELETE_TOKEN_MISMATCH';end if;
    if p_row.origin_stamp is distinct from p_stamp or not cor18_delete_live(p_row) or not exists(select 1 from sessions s where s.account_id=p_row.account_id and s.session_id=p_row.origin_family and s.access_token_hash=p_session and s.access_expiration>clock_timestamp() and s.account_security_stamp=p_stamp) then return 'ACCOUNT_DELETE_AUTHORITY_CHANGED';end if;
    if not exists(select 1 from account_delete_budgets b where b.account_id=p_row.account_id) then return 'ACCOUNT_DELETE_CONFLICT';end if;
    if exists(select 1 from account_delete_budgets b where b.account_id=p_row.account_id and b.finalize_locked_until>clock_timestamp()) then return 'ACCOUNT_DELETE_ATTEMPT_LIMITED';end if;
    if not p_row.verified or not exists(select 1 from delivery_candidates c where c.account_id=p_row.account_id and c.purpose='delete' and c.proof_hash=p_row.delete_token_hash and c.state='published' and (c.metadata_json::jsonb->>'admissionId')::uuid=p_row.request_id) then return 'ACCOUNT_DELETE_VERIFY_REQUIRED';end if;
    return null;
end;
$$;
-- COR18: security events revoke destructive generations, while admission budgets survive.
create or replace function cor18_account_security_event() returns trigger language plpgsql as $$
begin
    if new.security_stamp is distinct from old.security_stamp or lower(new.email_address) is distinct from lower(old.email_address) or new.cut_off is distinct from old.cut_off or new.unlock_when is distinct from old.unlock_when then perform cor18_revoke_delete(new.account_id);end if;return new;
end;
$$;
create trigger cor18_account_security_event after update on accounts for each row execute function cor18_account_security_event();
create or replace function cor18_family_security_event() returns trigger language plpgsql as $$
declare owner uuid; family uuid;
begin
    owner:=case when TG_OP='DELETE' then old.account_id else new.account_id end;
    family:=case when TG_OP='DELETE' then old.session_id else new.session_id end;
    if TG_OP='DELETE' or new.access_expiration<=clock_timestamp() or new.session_expiration<=clock_timestamp() or new.cut_off<=clock_timestamp() or new.account_security_stamp is distinct from old.account_security_stamp then
        perform cor18_retire_delete(owner,d.delete_token_hash) from delete_standby d where d.account_id=owner and d.origin_family=family;
        delete from account_delete_admissions q where q.account_id=owner and q.origin_family=family;
    end if;
    if TG_OP='DELETE' then return old;else return new;end if;
end;
$$;
create trigger cor18_family_security_event after update or delete on sessions for each row execute function cor18_family_security_event();
create or replace function cor18_factor_security_event() returns trigger language plpgsql as $$
declare owner uuid;
begin
    owner:=case when TG_OP='DELETE' then old.account_id else new.account_id end;
    if TG_OP='UPDATE' and (old.verified and old.revoked_at is null)=(new.verified and new.revoked_at is null) and
        row(old.two_factor_index,old.method,old.required,old.expiration,old.email_address,old.phone_number,old.phone_country_code,old.totp_provider_type,old.totp_algorithm,old.totp_digits,old.totp_period_seconds,old.totp_clock_skew_steps,old.totp_secret_ciphertext,old.totp_secret_nonce,old.totp_secret_tag,old.totp_secret_version) is not distinct from
        row(new.two_factor_index,new.method,new.required,new.expiration,new.email_address,new.phone_number,new.phone_country_code,new.totp_provider_type,new.totp_algorithm,new.totp_digits,new.totp_period_seconds,new.totp_clock_skew_steps,new.totp_secret_ciphertext,new.totp_secret_nonce,new.totp_secret_tag,new.totp_secret_version) then return new;end if;
    if (TG_OP<>'INSERT' and old.verified and old.revoked_at is null) or (TG_OP<>'DELETE' and new.verified and new.revoked_at is null) then perform cor18_revoke_delete(owner);end if;
    if TG_OP='DELETE' then return old;else return new;end if;
end;
$$;
create trigger cor18_factor_security_event after insert or update or delete on two_factor_authentications for each row execute function cor18_factor_security_event();

-- The issuer role is provisioned by the operator outside application setup. Absent role fails closed.
create or replace function cor19_is_issuer(p_actor name)
returns boolean language plpgsql stable as $$
declare role_oid oid; actor_oid oid;
begin
    select oid into role_oid from pg_roles where rolname='treehammock_entitlement_issuer';
    select oid into actor_oid from pg_roles where rolname=p_actor;
    if role_oid is null or actor_oid is null then return false;end if;
    return pg_has_role(actor_oid,role_oid,'member');
end;
$$;
create or replace function cor19_audit(p_grant uuid,p_action text,p_actor text,p_stamp uuid,p_family uuid,p_approval jsonb default null)
returns void language plpgsql as $$
begin
    insert into entitlement_grant_audit(grant_id,account_id,grant_version,action,actor,credential_stamp,family_id,approval)
    select g.grant_id,g.account_id,g.version,p_action,p_actor,p_stamp,p_family,p_approval from entitlement_grants g where g.grant_id=p_grant;
    if not found then raise exception 'Grant audit write missing' using errcode='P1901';end if;
end;
$$;
create or replace function cor19_issue_grant(p_grant uuid,p_account uuid,p_stamp uuid,p_catalog text,p_tier smallint,p_term smallint,p_cadence smallint,p_start timestamptz,p_end timestamptz,p_cycles integer,p_redeem timestamptz,p_reference text,p_anchor text,p_denied text[])
returns table(result boolean,code text) language plpgsql as $$
declare moment timestamptz; tested_boundary timestamptz;
begin
    moment:=cor20_now();
    if not cor19_is_issuer(current_user::name) then return query select false,'ENTITLEMENT_ISSUER_REQUIRED'::text;return;end if;
    perform cor02_lock_account_authority(p_account,'activation');
    if not exists(select 1 from accounts a where a.account_id=p_account and a.security_stamp=p_stamp and a.verify_status=1 and (a.cut_off is null or a.cut_off>clock_timestamp()) and (a.unlock_when is null or a.unlock_when<=clock_timestamp())) then
        return query select false,'ACCOUNT_SECURITY_STAMP_MISMATCH'::text;return;end if;
    if p_grant is null or p_grant='00000000-0000-0000-0000-000000000000'::uuid or p_catalog is distinct from 'treehammock-v1' or p_tier is null or p_tier not in (1,2) or p_term is null or p_term not in (1,2,3,6,7,8,9,10,11) or p_cadence is null or p_cadence not in (0,1) or p_cycles is null or p_cycles not between 1 and 1000 or (p_cadence=0 and p_cycles<>1) or (p_term=11 and (p_cadence<>0 or p_cycles<>1)) or p_anchor is null or p_anchor not in ('redemption','approved-boundary') or (p_anchor='redemption' and p_start is not null) or (p_anchor='approved-boundary' and (p_start is null or p_start<=moment)) or p_denied is null or not(p_denied <@ cor20_capabilities(p_tier)) or cardinality(p_denied)>2 or p_redeem is null or p_redeem<=clock_timestamp() or (p_end is not null and p_end<=greatest(clock_timestamp(),p_start)) or (p_term<>11 and p_end is null) or nullif(btrim(p_reference),'') is null or length(p_reference)>256 then
        return query select false,'ENTITLEMENT_INVALID_APPROVAL'::text;return;end if;
    tested_boundary:=cor20_term_boundary(coalesce(p_start,p_redeem),p_term,p_cycles);
    insert into entitlement_grants(grant_id,account_id,origin_stamp,catalog,tier,term,cadence,approved_start,authorized_end,max_cycles,redeem_before,issuer,issuer_reference,start_anchor,denied_capabilities)
    values(p_grant,p_account,p_stamp,p_catalog,p_tier,p_term,p_cadence,p_start,p_end,p_cycles,p_redeem,current_user,p_reference,p_anchor,array(select distinct c from unnest(p_denied) c order by c));
    if not found then raise exception 'Grant issue missing' using errcode='P1901';end if;
    perform cor19_audit(p_grant,'issued',current_user,p_stamp,null,jsonb_build_object('anchor',p_anchor,'deniedCapabilities',to_jsonb(array(select distinct c from unnest(p_denied) c order by c)),'catalog',p_catalog,'tier',p_tier,'term',p_term,'cadence',p_cadence,'start',p_start,'end',p_end,'maxCycles',p_cycles,'redeemBefore',p_redeem,'reference',p_reference));
    perform cor02_require_live(p_redeem);
    perform cor02_require_live(coalesce(p_end,p_redeem));
    if not cor19_is_issuer(current_user::name) or not exists(select 1 from accounts a where a.account_id=p_account and a.security_stamp=p_stamp and a.verify_status=1 and (a.cut_off is null or a.cut_off>clock_timestamp()) and (a.unlock_when is null or a.unlock_when<=clock_timestamp())) then raise exception 'Issuer authority expired' using errcode='P1902';end if;
    return query select true,'ENTITLEMENT_GRANT_ISSUED'::text;
exception when invalid_parameter_value or datetime_field_overflow then return query select false,'ENTITLEMENT_INVALID_APPROVAL'::text;
 when unique_violation then return query select false,'ACTIVATION_CONFLICT'::text;
 when sqlstate 'P0202' or sqlstate 'P1902' then return query select false,'ACTIVATION_EXPIRED'::text;
end;
$$;
create or replace function cor19_grant_live(p_grant uuid,p_account uuid,p_stamp uuid,p_version bigint)
returns boolean language plpgsql volatile as $$
begin
    return exists(select 1 from entitlement_grants g where g.grant_id=p_grant and g.account_id=p_account and g.origin_stamp=p_stamp and g.version=p_version and g.state='approved' and g.redeem_before>clock_timestamp() and (g.authorized_end is null or g.authorized_end>clock_timestamp()) and cor19_is_issuer(g.issuer) and cor20_approval_audited(g.grant_id));
end;
$$;
create or replace function cor19_stage_activation(p_request uuid,p_account uuid,p_stamp uuid,p_session text,p_family uuid,p_grant uuid,p_version bigint,p_hash text,p_expires timestamptz,p_email text,p_tier smallint,p_term smallint,p_cadence smallint,p_admission uuid default null)
returns table(result boolean,code text) language plpgsql as $$
begin
    perform cor02_lock_account_authority(p_account,'activation');
    if not cor08_live_sensitive_authority(p_account,p_stamp,p_session,p_family) then return query select false,'ACCOUNT_SECURITY_STAMP_MISMATCH'::text;return;end if;
    if not cor19_grant_live(p_grant,p_account,p_stamp,p_version) then return query select false,'ACTIVATION_TRUSTED_GRANT_REQUIRED'::text;return;end if;
    if not exists(select 1 from accounts a join entitlement_grants g on g.account_id=a.account_id where a.account_id=p_account and g.grant_id=p_grant and lower(a.email_address)=lower(p_email) and g.tier=p_tier and g.term=p_term and g.cadence=p_cadence) then
        return query select false,'ACTIVATION_APPROVAL_MISMATCH'::text;return;end if;
    if p_hash is null or p_hash !~ '^[a-f0-9]{64}$' or p_expires is null or p_expires<=clock_timestamp() or p_expires>clock_timestamp()+interval '15 minutes' or exists(select 1 from grant_activation_requests q where q.account_id=p_account and q.state in ('queued','pending') and q.expires_at>clock_timestamp()) then return query select false,'ACTIVATION_CONFLICT'::text;return;end if;
    if not cor21_creation_live(p_admission,p_account,p_stamp,p_family,p_grant,p_version,p_hash) then
        return query select false,'ACTIVATION_CREATION_ADMISSION_REQUIRED'::text;return;end if;
    update activation_creation_admissions set consumed_at=clock_timestamp()
        where account_id=p_account and admission_id=p_admission and consumed_at is null and expires_at>clock_timestamp();
    if not found then raise exception 'Creation admission consumption missing' using errcode='P2101';end if;
    insert into grant_activation_requests(request_id,grant_id,account_id,grant_version,origin_stamp,family_id,proof_hash,expires_at,state)
    select p_request,p_grant,p_account,p_version,p_stamp,p_family,p_hash,least(p_expires,g.redeem_before,coalesce(g.authorized_end,p_expires)),'queued' from entitlement_grants g where g.grant_id=p_grant;
    if not found then raise exception 'Activation reservation missing' using errcode='P1901';end if;
    perform cor19_audit(p_grant,'placed','account',p_stamp,p_family);
    if not exists(select 1 from activation_creation_admissions q where q.account_id=p_account and q.admission_id=p_admission and q.expires_at>clock_timestamp()) then raise exception 'Creation admission expired during staging' using errcode='P1902';end if;
    if not cor08_live_sensitive_authority(p_account,p_stamp,p_session,p_family) or not cor19_grant_live(p_grant,p_account,p_stamp,p_version) then raise exception 'Activation authority expired' using errcode='P1902';end if;
    return query select true,'ACTIVATION_CREATED'::text;
exception when unique_violation then return query select false,'ACTIVATION_CONFLICT'::text;
 when sqlstate 'P1902' then return query select false,'ACTIVATION_EXPIRED'::text;
end;
$$;
create or replace function cor19_request_live(p_request uuid,p_stamp uuid,p_hash text)
returns boolean language plpgsql volatile as $$
begin
    return exists(select 1 from grant_activation_requests q join accounts a using(account_id) join sessions s on s.account_id=q.account_id and s.session_id=q.family_id
      where q.request_id=p_request and q.origin_stamp=p_stamp and a.security_stamp=p_stamp and q.proof_hash=p_hash and q.state in ('queued','pending') and q.expires_at>clock_timestamp()
      and cor19_grant_live(q.grant_id,q.account_id,p_stamp,q.grant_version) and cor08_live_sensitive_authority(q.account_id,p_stamp,s.access_token_hash,q.family_id));
end;
$$;
create or replace function cor19_publish_activation(p_request uuid,p_stamp uuid,p_hash text)
returns boolean language plpgsql as $$
declare g uuid; family uuid;
begin
    if not cor19_request_live(p_request,p_stamp,p_hash) then return false;end if;
    update grant_activation_requests q set state='pending' where q.request_id=p_request and q.state='queued' returning q.grant_id,q.family_id into g,family;
    if not found then return false;end if;
    perform cor19_audit(g,'published','delivery-worker',p_stamp,family);
    if not cor19_request_live(p_request,p_stamp,p_hash) then raise exception 'Activation publication expired' using errcode='P0212';end if;
    return true;
end;
$$;
create or replace function cor19_transition_activation(p_account uuid,p_stamp uuid,p_session text,p_family uuid,p_grant uuid,p_version bigint,p_request uuid,p_hash text,p_action text)
returns table(result boolean,code text,grant_version bigint,starts_at timestamptz,eligibility_until timestamptz,entitlement_json text,term smallint,tier smallint,cadence smallint) language plpgsql as $$
declare g entitlement_grants%rowtype; q grant_activation_requests%rowtype; anchor_time timestamptz; until_time timestamptz; first_end timestamptz; projection jsonb;
begin
    perform cor12_lock_delivery(p_account);
    if not cor08_live_sensitive_authority(p_account,p_stamp,p_session,p_family) then return query select false,'ACCOUNT_SECURITY_STAMP_MISMATCH'::text,null::bigint,null::timestamptz,null::timestamptz,null::text,null::smallint,null::smallint,null::smallint;return;end if;
    select * into g from entitlement_grants t where t.grant_id=p_grant and t.account_id=p_account;
    if not found or g.version is distinct from p_version then return query select false,'ACTIVATION_CONFLICT'::text,null::bigint,null::timestamptz,null::timestamptz,null::text,null::smallint,null::smallint,null::smallint;return;end if;
    select * into q from grant_activation_requests t where t.grant_id=p_grant;
    if p_action='verify' then
        if q.request_id is distinct from p_request or q.state is distinct from 'pending' or q.family_id is distinct from p_family or q.origin_stamp is distinct from p_stamp or p_hash is null or q.proof_hash is distinct from p_hash or not cor19_request_live(p_request,p_stamp,p_hash) or not exists(select 1 from delivery_candidates c where c.delivery_id=p_request and c.state='published' and c.proof_hash=p_hash) then
            return query select false,'ACTIVATION_CODE_MISMATCH'::text,null::bigint,null::timestamptz,null::timestamptz,null::text,null::smallint,null::smallint,null::smallint;return;end if;
        update grant_activation_requests set state='active',proof_hash=null,consumed_at=clock_timestamp() where request_id=p_request and state='pending' and proof_hash=p_hash;
        if not found then raise exception 'Code consumption missing' using errcode='P1901';end if;
        anchor_time:=cor20_now();
        if g.start_anchor='approved-boundary' then
            if g.approved_start<=anchor_time then raise exception 'Approved start boundary passed' using errcode='P1902';end if;
            anchor_time:=g.approved_start;
        end if;
        until_time:=least(cor20_term_boundary(anchor_time,g.term,g.max_cycles),g.authorized_end);
        first_end:=least(cor20_term_boundary(anchor_time,g.term,1),until_time);
        if until_time<=anchor_time then raise exception 'Approved eligibility exhausted' using errcode='P1902';end if;
        update entitlement_grants set state='active',activated_at=clock_timestamp(),starts_at=anchor_time,eligibility_until=until_time,
            materialized_cycle=1,materialized_until=first_end,version=version+1 where grant_id=p_grant and state='approved' and version=p_version;
        if not found then raise exception 'Activation CAS missing' using errcode='P1901';end if;
        insert into entitlement_grant_cycles(grant_id,cycle,starts_at,ends_at,actor,credential_stamp)
            values(p_grant,1,anchor_time,first_end,'redemption',p_stamp);
        if not found then raise exception 'First cycle record missing' using errcode='P2001';end if;
        perform cor19_audit(p_grant,'redeemed','account',p_stamp,p_family,jsonb_build_object('startsAt',anchor_time,'eligibilityUntil',until_time));
        projection:=cor20_resolve_account(p_account);
        perform cor02_require_live(least(q.expires_at,g.redeem_before,coalesce(g.authorized_end,q.expires_at)));
        if not cor08_live_sensitive_authority(p_account,p_stamp,p_session,p_family) then raise exception 'Authority expired' using errcode='P1902';end if;
        return query select true,'ACTIVATION_VERIFIED'::text,p_version+1,anchor_time,until_time,projection::text,g.term,g.tier,g.cadence;
    elsif p_action in ('disable','cancel') then
        if g.state='revoked' or (p_action='cancel' and (q.request_id is distinct from p_request or q.state not in ('queued','pending') or q.family_id is distinct from p_family)) then return query select false,'ACTIVATION_CONFLICT'::text,null::bigint,null::timestamptz,null::timestamptz,null::text,null::smallint,null::smallint,null::smallint;return;end if;
        update entitlement_grants set state='revoked',revoked_at=clock_timestamp(),version=version+1 where grant_id=p_grant and version=p_version and state in ('approved','active');
        if not found then raise exception 'Revocation CAS missing' using errcode='P1901';end if;
        if q.request_id is not null then
            update grant_activation_requests set state='revoked',proof_hash=null where grant_id=p_grant;
            if not found then raise exception 'Activation revocation missing' using errcode='P1901';end if;
        end if;
        update delivery_candidates set state='superseded',terminal_at=clock_timestamp() where delivery_id=q.request_id and state='staged';
        update delivery_outbox set state='superseded',nonce=null,ciphertext=null,tag=null,lease_id=null,lease_until=null where delivery_id=q.request_id and state not in ('published','rejected','expired','superseded');
        perform cor19_audit(p_grant,'revoked','account',p_stamp,p_family);
        if not cor08_live_sensitive_authority(p_account,p_stamp,p_session,p_family) then raise exception 'Authority expired' using errcode='P1902';end if;
        projection:=cor20_resolve_account(p_account);
        return query select true,'ACTIVATION_DISABLED'::text,p_version+1,g.starts_at,g.eligibility_until,projection::text,g.term,g.tier,g.cadence;
    else return query select false,'ACTIVATION_INVALID'::text,null::bigint,null::timestamptz,null::timestamptz,null::text,null::smallint,null::smallint,null::smallint;end if;
exception when sqlstate 'P0202' or sqlstate 'P1902' then return query select false,'ACTIVATION_EXPIRED'::text,null::bigint,null::timestamptz,null::timestamptz,null::text,null::smallint,null::smallint,null::smallint;
end;
$$;

create or replace function cor19_protect_audit() returns trigger language plpgsql security definer as $$
declare permitted boolean:=false;
begin
    if TG_OP='DELETE' then
        execute format('with permit as (delete from %I.retention_audit_delete_permits
            where backend=pg_backend_pid() and transaction_id=txid_current() and audit_id=$1
            and cutoff<=clock_timestamp()-interval ''90 days'' and $2<cutoff returning 1)
            select exists(select 1 from permit)',TG_TABLE_SCHEMA) into permitted using old.audit_id,old.happened_at;
        if permitted and not exists(select 1 from entitlement_grants g where g.grant_id=old.grant_id) then return old;end if;
    end if;
    raise exception 'Grant audit is append-only outside authorized expired-history retention' using errcode='P1901';
end;
$$;
create trigger cor19_protect_audit before update or delete on entitlement_grant_audit for each row execute function cor19_protect_audit();

-- COR20 current calendar, eligibility and projection contract. No deployment migration.
create or replace function cor20_now() returns timestamptz language plpgsql volatile as $$
begin return clock_timestamp();end;
$$;
create or replace function cor20_grant_rights_enabled() returns boolean language plpgsql stable as $$
begin return false;end; -- COR21 qualification must precede reviewed release enablement.
$$;
create or replace function cor20_capabilities(p_tier smallint) returns text[] language plpgsql immutable as $$
begin
    case p_tier when 1,2 then return array['account.manage','account.read']::text[];
        else return array[]::text[];end case;
end;
$$;
create or replace function cor20_term_boundary(p_start timestamptz,p_term smallint,p_cycle integer)
returns timestamptz language plpgsql immutable as $$
declare local_start timestamp; boundary timestamp; units integer;
begin
    if p_start is null or p_cycle is null or p_cycle not between 0 and 1000 or p_term is null or p_term not in (1,2,3,6,7,8,9,10,11) then raise exception 'Invalid calendar contract' using errcode='22023';end if;
    if not isfinite(p_start) or extract(year from p_start at time zone 'UTC') not between 1 and 9999 then raise exception 'Unsupported calendar range' using errcode='22023';end if;
    if p_cycle=0 then return p_start;end if;
    if p_term=11 then return null;end if;
    local_start:=p_start at time zone 'UTC';
    if p_term in (1,2,3) then
        units:=case p_term when 1 then 1 when 2 then 7 else 14 end;
        boundary:=local_start+make_interval(days=>units*p_cycle);
    else
        units:=case p_term when 6 then 1 when 7 then 3 when 8 then 6 when 9 then 9 when 10 then 12 end;
        -- Add to the original UTC anchor; never accumulate February clamping drift.
        boundary:=local_start+make_interval(months=>units*p_cycle);
    end if;
    if extract(year from boundary) not between 1 and 9999 then raise exception 'Unsupported calendar range' using errcode='22023';end if;
    return boundary at time zone 'UTC';
end;
$$;
create or replace function cor20_cycle_at(p_start timestamptz,p_term smallint,p_max integer,p_until timestamptz,p_now timestamptz)
returns integer language plpgsql immutable as $$
declare low integer:=1; high integer:=p_max; middle integer; boundary timestamptz;
begin
    if p_start is null or p_now is null or p_max is null or p_max not between 1 and 1000 or p_term is null or p_term not in (1,2,3,6,7,8,9,10,11) or (p_term=11 and p_max<>1) then raise exception 'Invalid cycle contract' using errcode='22023';end if;
    if p_now<p_start or (p_until is not null and p_now>=p_until) then return 0;end if;
    if p_term=11 then return 1;end if;
    boundary:=cor20_term_boundary(p_start,p_term,p_max);
    if p_now>=boundary then return 0;end if;
    while low<high loop
        middle:=(low+high)/2;
        if p_now>=cor20_term_boundary(p_start,p_term,middle) then low:=middle+1;else high:=middle;end if;
    end loop;
    return low;
end;
$$;
create or replace function cor20_approval_audited(p_grant uuid)
returns boolean language plpgsql volatile as $$
begin
    return exists(select 1 from entitlement_grants g join entitlement_grant_audit z using(grant_id)
        where g.grant_id=p_grant and z.action='issued' and z.grant_version=1 and z.account_id=g.account_id
        and z.credential_stamp=g.origin_stamp and z.actor=g.issuer::text and z.approval->>'catalog'=g.catalog
        and (z.approval->>'tier')::smallint=g.tier and (z.approval->>'term')::smallint=g.term
        and (z.approval->>'cadence')::smallint=g.cadence and z.approval->>'anchor'=g.start_anchor
        and (z.approval->>'start')::timestamptz is not distinct from g.approved_start
        and (z.approval->>'end')::timestamptz is not distinct from g.authorized_end
        and (z.approval->>'maxCycles')::integer=g.max_cycles and (z.approval->>'redeemBefore')::timestamptz=g.redeem_before
        and z.approval->>'reference'=g.issuer_reference
        and coalesce(array(select jsonb_array_elements_text(z.approval->'deniedCapabilities')),array[]::text[])=g.denied_capabilities);
end;
$$;
create or replace function cor20_activation_audited(p_grant uuid)
returns boolean language plpgsql volatile as $$
begin
    return exists(select 1 from entitlement_grants g join entitlement_grant_audit z using(grant_id)
        where g.grant_id=p_grant and z.action='redeemed' and z.account_id=g.account_id
        and (z.approval->>'startsAt')::timestamptz=g.starts_at
        and (z.approval->>'eligibilityUntil')::timestamptz is not distinct from g.eligibility_until
        and g.eligibility_until is not distinct from least(cor20_term_boundary(g.starts_at,g.term,g.max_cycles),g.authorized_end));
end;
$$;
create or replace function cor20_resolve_account(p_account uuid)
returns jsonb language plpgsql volatile as $$
declare a accounts%rowtype; g entitlement_grants%rowtype; moment timestamptz; boundary timestamptz;
    next_boundary timestamptz; eligible_until timestamptz; unbounded boolean; paid boolean; enabled boolean;
    features_value smallint; capabilities text[]; denied text[]; current_cycle integer; grants jsonb;
    signature text; old_signature text; projection jsonb; iteration integer; account_live boolean;
begin
    perform cor02_lock_account_authority(p_account,'activation');
    select * into a from accounts t where t.account_id=p_account;
    if not found then return null;end if;
    for iteration in 1..3 loop
        moment:=cor20_now();enabled:=cor20_grant_rights_enabled();
        account_live:=a.verify_status=1 and (a.cut_off is null or a.cut_off>moment) and (a.unlock_when is null or a.unlock_when<=moment);
        next_boundary:=null;eligible_until:=null;unbounded:=false;paid:=false;denied:=array[]::text[];grants:='[]'::jsonb;
        for g in select * from entitlement_grants t where t.account_id=p_account order by t.grant_id loop
            current_cycle:=0;
            if g.state='active' and cor19_is_issuer(g.issuer) and cor20_approval_audited(g.grant_id) and cor20_activation_audited(g.grant_id) then
                current_cycle:=cor20_cycle_at(g.starts_at,g.term,g.max_cycles,g.eligibility_until,moment);
                if account_live then
                    if g.starts_at>moment then next_boundary:=least(next_boundary,g.starts_at);end if;
                    if current_cycle>0 then
                        boundary:=least(cor20_term_boundary(g.starts_at,g.term,current_cycle),g.eligibility_until);
                        next_boundary:=least(next_boundary,boundary);
                        eligible_until:=greatest(eligible_until,g.eligibility_until);
                        if g.eligibility_until is null then unbounded:=true;end if;
                        if enabled then
                            if g.tier=2 then paid:=true;end if;
                            denied:=denied||g.denied_capabilities;
                        end if;
                    end if;
                else current_cycle:=0;end if;
            end if;
            grants:=grants||jsonb_build_array(jsonb_build_object('grantId',g.grant_id,'grantVersion',g.version,'state',g.state,'tier',g.tier,'term',g.term,'cadence',g.cadence,'anchor',g.start_anchor,'startsAt',g.starts_at,'eligibilityUntil',g.eligibility_until,'cycle',current_cycle,'maxCycles',g.max_cycles,'materializedCycle',g.materialized_cycle,'issuerTrusted',cor19_is_issuer(g.issuer)));
        end loop;
        if unbounded then eligible_until:=null;end if;
        features_value:=case when paid then 2::smallint else 1::smallint end;
        -- Baseline capabilities are explicit; any currently eligible approved denial wins over all allows.
        capabilities:=array(select c from unnest(cor20_capabilities(features_value)) c where not(c=any(denied)) order by c);
        if not account_live then capabilities:=array[]::text[];end if;
        if a.cut_off>moment then
            next_boundary:=least(next_boundary,a.cut_off);
            if eligible_until is not null or unbounded then eligible_until:=least(eligible_until,a.cut_off);end if;
        end if;
        if a.unlock_when>moment then next_boundary:=least(next_boundary,a.unlock_when);end if;
        projection:=jsonb_build_object('accountId',p_account,'features',features_value,'capabilities',to_jsonb(capabilities),'rightsEnabled',enabled,
            'eligibilityUntil',eligible_until,'nextBoundary',next_boundary,'evaluatedAt',moment,'grants',grants);
        signature:=encode(digest((projection-'evaluatedAt')::text,'sha256'),'hex');
        if signature is distinct from a.entitlement_fingerprint then
            update accounts t set entitlement_version=t.entitlement_version+1,entitlement_fingerprint=signature,features=features_value
                where t.account_id=p_account returning t.* into a;
            if not found then raise exception 'Entitlement account projection missing' using errcode='P2001';end if;
        end if;
        projection:=projection||jsonb_build_object('version',a.entitlement_version);
        update sessions t set features=features_value,entitlement_version=a.entitlement_version
            where t.account_id=p_account and (t.features is distinct from features_value or t.entitlement_version is distinct from a.entitlement_version);
        -- A blocked mirror write cannot return the entitlement from before its boundary.
        if next_boundary is null or next_boundary>cor20_now() then return projection;end if;
    end loop;
    raise exception 'Entitlement snapshot boundary changed repeatedly' using errcode='P2002';
end;
$$;
create or replace function cor20_grant_projection_event() returns trigger language plpgsql as $$
begin
    if exists(select 1 from accounts a where a.account_id=coalesce(new.account_id,old.account_id)) then
        perform cor20_resolve_account(coalesce(new.account_id,old.account_id));end if;
    return null;
end;
$$;
create trigger cor20_grant_projection_event after insert or update or delete on entitlement_grants for each row execute function cor20_grant_projection_event();
create or replace function cor20_materialize_cycles(p_account uuid,p_limit integer)
returns integer language plpgsql as $$
declare a accounts%rowtype; g entitlement_grants%rowtype; cycle_value integer; due integer; renewed integer:=0;
    cycle_start timestamptz; cycle_end timestamptz; moment timestamptz;
begin
    if p_limit is null or p_limit not between 1 and 64 then raise exception 'Invalid renewal budget' using errcode='22023';end if;
    perform cor02_lock_account_authority(p_account,'activation');
    select * into a from accounts where account_id=p_account;moment:=cor20_now();
    if not found or a.verify_status<>1 or a.cut_off<=moment or a.unlock_when>moment then return 0;end if;
    for g in select * from entitlement_grants t where t.account_id=p_account and t.state='active' and t.cadence=1 order by t.grant_id loop
        if not cor19_is_issuer(g.issuer) or not cor20_approval_audited(g.grant_id) or not cor20_activation_audited(g.grant_id) then continue;end if;
        due:=cor20_cycle_at(g.starts_at,g.term,g.max_cycles,g.eligibility_until,moment);
        -- Expired grants never acquire a new renewal record or resurrect rights.
        if due=0 then continue;end if;
        while g.materialized_cycle<due and renewed<p_limit loop
            cycle_value:=g.materialized_cycle+1;
            cycle_start:=cor20_term_boundary(g.starts_at,g.term,cycle_value-1);
            cycle_end:=least(cor20_term_boundary(g.starts_at,g.term,cycle_value),g.eligibility_until);
            if cycle_value>g.max_cycles or cycle_start>=g.eligibility_until then exit;end if;
            insert into entitlement_grant_cycles(grant_id,cycle,starts_at,ends_at,actor,credential_stamp)
                values(g.grant_id,cycle_value,cycle_start,cycle_end,'renewal-worker',a.security_stamp);
            if not found then raise exception 'Renewal record missing' using errcode='P2001';end if;
            update entitlement_grants t set materialized_cycle=cycle_value,materialized_until=cycle_end,version=t.version+1
                where t.grant_id=g.grant_id and t.version=g.version and t.state='active' and t.materialized_cycle=g.materialized_cycle returning t.* into g;
            if not found then raise exception 'Renewal CAS missing' using errcode='P2001';end if;
            perform cor19_audit(g.grant_id,'renewed','renewal-worker',a.security_stamp,null,jsonb_build_object('cycle',cycle_value,'startsAt',cycle_start,'endsAt',cycle_end));
            if not exists(select 1 from accounts x where x.account_id=p_account and x.security_stamp=a.security_stamp and x.verify_status=1 and (x.cut_off is null or x.cut_off>cor20_now()) and (x.unlock_when is null or x.unlock_when<=cor20_now())) or not cor19_is_issuer(g.issuer) or cor20_now()>=g.eligibility_until then
                raise exception 'Renewal authority expired' using errcode='P2002';end if;
            renewed:=renewed+1;
        end loop;
        if renewed>=p_limit then exit;end if;
    end loop;
    return renewed;
end;
$$;
create or replace function cor20_renew_batch(p_limit integer)
returns table(result boolean,code text,renewed_cycles integer) language plpgsql as $$
declare owner uuid; renewed integer:=0;
begin
    if p_limit is null or p_limit not between 1 and 64 then raise exception 'Invalid renewal budget' using errcode='22023';end if;
    for owner in select a.account_id from accounts a where exists(select 1 from entitlement_grants g where g.account_id=a.account_id and g.state='active' and g.cadence=1 and g.materialized_cycle<g.max_cycles and case when g.starts_at is not null then cor20_cycle_at(g.starts_at,g.term,g.max_cycles,g.eligibility_until,cor20_now()) else 0 end>g.materialized_cycle)
        order by a.account_id limit 16 for update of a skip locked loop
        renewed:=renewed+cor20_materialize_cycles(owner,p_limit-renewed);
        if renewed>=p_limit then exit;end if;
    end loop;
    return query select true,'ENTITLEMENT_RENEWAL_RECONCILED'::text,renewed;
exception when sqlstate 'P2002' then return query select false,'ENTITLEMENT_RENEWAL_AUTHORITY_CHANGED'::text,0;
end;
$$;

create or replace function cor20_session_projection_insert() returns trigger language plpgsql as $$
declare projection jsonb;
begin
    projection:=cor20_resolve_account(new.account_id);
    if projection is null then raise exception 'Session entitlement account missing' using errcode='P2001';end if;
    new.features:=(projection->>'features')::smallint;
    new.entitlement_version:=(projection->>'version')::bigint;
    return new;
end;
$$;
create trigger cor20_session_projection_insert before insert on sessions for each row execute function cor20_session_projection_insert();

-- COR21: request budgets survive delivery denial, cancellation, cache loss and terminal cleanup.
create table if not exists activation_creation_budgets(
    budget_key text primary key,
    window_end timestamptz not null,
    request_count integer not null check(request_count>=0),
    next_request_at timestamptz not null
);
create table if not exists activation_creation_admissions(
    account_id uuid primary key references accounts(account_id) on delete cascade,
    admission_id uuid not null unique,
    origin_stamp uuid not null,
    family_id uuid not null,
    grant_id uuid not null,
    grant_version bigint not null,
    proof_hash text not null check(proof_hash ~ '^[a-f0-9]{64}$'),
    expires_at timestamptz not null,
    consumed_at timestamptz null
);
revoke all on activation_creation_budgets,activation_creation_admissions from public;

create or replace function cor21_admit_creation(p_account uuid,p_stamp uuid,p_session text,p_family uuid,
    p_grant uuid,p_version bigint,p_hash text,p_email text,p_tier smallint,p_term smallint,p_cadence smallint,p_ip text,
    p_account_max integer default 5,p_identifier_max integer default 5,p_ip_max integer default 50,
    p_window integer default 900,p_cooldown integer default 60)
returns table(result boolean,code text,admission_id uuid,retry_after_seconds integer) language plpgsql as $$
declare moment timestamptz; key_value text; keys text[]; maximum integer; b activation_creation_budgets%rowtype;
    retry_until timestamptz; pending_until timestamptz; ticket uuid:=gen_random_uuid(); registered_email text;
begin
    perform cor02_lock_account_authority(p_account,'activation');
    if not cor08_live_sensitive_authority(p_account,p_stamp,p_session,p_family) then
        return query select false,'ACCOUNT_SECURITY_STAMP_MISMATCH'::text,null::uuid,null::integer;return;end if;
    if not cor19_grant_live(p_grant,p_account,p_stamp,p_version) then
        return query select false,'ACTIVATION_TRUSTED_GRANT_REQUIRED'::text,null::uuid,null::integer;return;end if;
    select lower(a.email_address) into registered_email from accounts a join entitlement_grants g using(account_id)
        where a.account_id=p_account and g.grant_id=p_grant and lower(btrim(p_email))=lower(a.email_address)
        and g.tier=p_tier and g.term=p_term and g.cadence=p_cadence;
    if not found then return query select false,'ACTIVATION_APPROVAL_MISMATCH'::text,null::uuid,null::integer;return;end if;
    if p_hash is null or p_hash !~ '^[a-f0-9]{64}$' or p_ip is null or p_ip !~ '^[a-f0-9]{32}$'
        or p_account_max is null or p_account_max not between 1 and 5 or p_identifier_max is null or p_identifier_max not between 1 and 5
        or p_ip_max is null or p_ip_max not between 1 and 50 or p_window is null or p_window not between 900 and 86400
        or p_cooldown is null or p_cooldown not between 60 and 86400 then
        return query select false,'ACTIVATION_INVALID'::text,null::uuid,null::integer;return;end if;
    -- Account serialization plus the unique grant reservation is the pending cap (one).
    if exists(select 1 from grant_activation_requests q where q.grant_id=p_grant) then
        return query select false,'ACTIVATION_CONFLICT'::text,null::uuid,null::integer;return;end if;
    select max(q.expires_at) into pending_until from grant_activation_requests q where q.account_id=p_account and q.state in ('queued','pending') and q.expires_at>clock_timestamp();
    if pending_until is not null then
        return query select false,'ACTIVATION_CREATION_PENDING'::text,null::uuid,greatest(1,ceil(extract(epoch from pending_until-clock_timestamp()))::integer);return;end if;
    keys:=array['a:'||p_account::text,'i:'||encode(public.digest(registered_email,'sha256'),'hex'),'p:'||p_ip];
    -- Account key is first; an exhausted account cannot allocate fresh IP budget rows.
    -- All accounts take the remaining identifier/IP keys in the same order.
    foreach key_value in array (select array_agg(k order by k) from unnest(keys) k) loop
        insert into activation_creation_budgets(budget_key,window_end,request_count,next_request_at)
            values(key_value,clock_timestamp()+make_interval(secs=>p_window),0,clock_timestamp()) on conflict do nothing;
        select * into b from activation_creation_budgets where budget_key=key_value for update;
        if not found then raise exception 'Creation budget missing' using errcode='P2101';end if;
        moment:=clock_timestamp();retry_until:=moment;
        maximum:=case left(key_value,2) when 'a:' then p_account_max when 'i:' then p_identifier_max else p_ip_max end;
        if b.window_end>moment and b.request_count>=maximum then retry_until:=greatest(retry_until,b.window_end);end if;
        if left(key_value,2)='a:' then retry_until:=greatest(retry_until,b.next_request_at);end if;
        if retry_until>moment then return query select false,'ABUSE_ACTIVATION_CREATION_THROTTLE_EXCEEDED'::text,null::uuid,
            greatest(1,ceil(extract(epoch from retry_until-moment))::integer);return;end if;
    end loop;
    moment:=clock_timestamp();
    foreach key_value in array keys loop
        update activation_creation_budgets set request_count=case when window_end<=moment then 1 else request_count+1 end,
            window_end=case when window_end<=moment then moment+make_interval(secs=>p_window) else window_end end,
            next_request_at=case when left(key_value,2)='a:' then moment+make_interval(secs=>p_cooldown) else moment end
            where budget_key=key_value;
        if not found then raise exception 'Creation budget charge missing' using errcode='P2101';end if;
    end loop;
    insert into activation_creation_admissions(account_id,admission_id,origin_stamp,family_id,grant_id,grant_version,proof_hash,expires_at)
        values(p_account,ticket,p_stamp,p_family,p_grant,p_version,p_hash,moment+interval '2 minutes')
        on conflict(account_id) do update set admission_id=excluded.admission_id,origin_stamp=excluded.origin_stamp,
            family_id=excluded.family_id,grant_id=excluded.grant_id,grant_version=excluded.grant_version,
            proof_hash=excluded.proof_hash,expires_at=excluded.expires_at,consumed_at=null;
    if not found then raise exception 'Creation admission missing' using errcode='P2101';end if;
    if not cor08_live_sensitive_authority(p_account,p_stamp,p_session,p_family) or not cor19_grant_live(p_grant,p_account,p_stamp,p_version) then
        raise exception 'Creation authority expired' using errcode='P1902';end if;
    return query select true,'ACTIVATION_CREATION_ADMITTED'::text,ticket,null::integer;
end;
$$;
create or replace function cor21_creation_live(p_admission uuid,p_account uuid,p_stamp uuid,p_family uuid,p_grant uuid,p_version bigint,p_hash text)
returns boolean language sql volatile as $$
    select exists(select 1 from activation_creation_admissions q where q.account_id=p_account and q.admission_id=p_admission
        and q.origin_stamp=p_stamp and q.family_id=p_family and q.grant_id=p_grant and q.grant_version=p_version
        and q.proof_hash=p_hash and q.expires_at>clock_timestamp() and q.consumed_at is null);
$$;

-- COR22 current greenfield retention contract. Fixed policies, no arbitrary SQL.
create table retention_jobs(
    job_name text primary key,
    lease_id uuid null,lease_until timestamptz null,next_run timestamptz not null default clock_timestamp(),
    cursor_account uuid null,cursor_key text null,
    last_attempt timestamptz null,last_success timestamptz null,last_failure timestamptz null,
    failure_code text null,failures bigint not null default 0,
    last_eligible integer not null default 0,last_affected integer not null default 0,
    last_dry_run boolean null,passes bigint not null default 0,
    constraint ck_cor22_lease check((lease_id is null)=(lease_until is null))
);
insert into retention_jobs(job_name) values ('activation_admissions'),('activation_budgets'),('activation_requests'),('delete_admissions'),('delete_budgets'),('delete_proofs'),('delete_events'),('delivery_payloads'),('delivery_history'),('email_reservations'),('factor_history'),('grant_cycles'),('grant_history'),('grant_audit'),('legacy_activations'),('logout_events'),('pending_login'),('pending_reset'),('reauth_budgets'),('recovery_proofs'),('reset_budgets'),('reset_events'),('reset_requests'),('sensitive_attempts'),('sensitive_grants'),('sensitive_proofs'),('sensitive_tokens'),('sessions'),('operation_steps'),('mutation_replays'),('operations'),('test_deliveries'),('unverified_accounts'),('verification_history');
create table retention_audit_delete_permits(
    backend integer not null,transaction_id bigint not null,audit_id bigint not null,cutoff timestamptz not null,
    primary key(backend,transaction_id,audit_id)
);
revoke all on retention_jobs,retention_audit_delete_permits from public;

create or replace function cor22_grant_obsolete(g entitlement_grants,p_history integer)
returns boolean language sql volatile as $$
    select case when g.state='revoked' then g.revoked_at
        when g.state='approved' then g.redeem_before
        when g.state='active' then g.eligibility_until else null end
        <clock_timestamp()-make_interval(days=>greatest(p_history,7));
$$;

-- A root deletion cannot cascade an unbounded collection. Keep live lockouts and
-- every remaining FK child; only the one-row login continuity marker may cascade.
create or replace function cor22_account_empty(p_account uuid)
returns boolean language plpgsql as $$
declare fk record; present boolean;
begin
    for fk in select ns.nspname,c.relname,a.attname from pg_constraint f
        join pg_class c on c.oid=f.conrelid join pg_namespace ns on ns.oid=c.relnamespace
        join pg_attribute a on a.attrelid=c.oid and a.attnum=f.conkey[1]
        where f.contype='f' and f.confrelid='accounts'::regclass and cardinality(f.conkey)=1
        and c.relname<>'account_login_attempt_versions'
    loop
        execute format('select exists(select 1 from %I.%I where %I=$1)',fk.nspname,fk.relname,fk.attname) into present using p_account;
        if present then return false;end if;
    end loop;
    return true;
end;
$$;

create or replace function cor22_retention_policy(p_job text)
returns table(table_name text,key_sql text,account_sql text,predicate_sql text)
language plpgsql as $$
begin
    case p_job
    when 'activation_admissions' then table_name:='activation_creation_admissions';key_sql:='t.account_id::text';account_sql:='t.account_id';predicate_sql:='t.expires_at<=clock_timestamp()';
    when 'activation_budgets' then table_name:='activation_creation_budgets';key_sql:='t.budget_key';account_sql:=null;predicate_sql:='greatest(t.window_end,t.next_request_at)<clock_timestamp()-make_interval(days=>p_history)';
    when 'activation_requests' then table_name:='grant_activation_requests';key_sql:='t.request_id::text';account_sql:='t.account_id';predicate_sql:='t.expires_at<clock_timestamp()-make_interval(days=>p_history)';
    when 'delete_admissions' then table_name:='account_delete_admissions';key_sql:='t.account_id::text';account_sql:='t.account_id';predicate_sql:='t.expires_at<=clock_timestamp()';
    when 'delete_budgets' then table_name:='account_delete_budgets';key_sql:='t.account_id::text';account_sql:='t.account_id';predicate_sql:='greatest(t.window_start+interval ''7 days'',t.next_request_allowed_at,coalesce(t.finalize_locked_until,t.window_start))<clock_timestamp()-make_interval(days=>p_history)';
    when 'delete_proofs' then table_name:='delete_standby';key_sql:='t.account_id::text';account_sql:='t.account_id';predicate_sql:='t.expiration<clock_timestamp()-make_interval(days=>p_history)';
    when 'delete_events' then table_name:='account_delete_events';key_sql:='t.delete_event_id::text';account_sql:=null;predicate_sql:='t.created_at<clock_timestamp()-make_interval(days=>p_audit)';
    when 'delivery_payloads' then table_name:='delivery_candidates';key_sql:='t.delivery_id::text';account_sql:='t.account_id';predicate_sql:='t.expires_at<=clock_timestamp() and (t.state=''staged'' or exists(select 1 from delivery_outbox o where o.delivery_id=t.delivery_id and (o.ciphertext is not null or o.nonce is not null or o.tag is not null or o.lease_id is not null)))';
    when 'delivery_history' then table_name:='delivery_candidates';key_sql:='t.delivery_id::text';account_sql:='t.account_id';predicate_sql:='t.expires_at<clock_timestamp()-make_interval(days=>p_history)';
    when 'email_reservations' then table_name:='account_email_change_requests';key_sql:='t.account_id::text';account_sql:='t.account_id';predicate_sql:='t.expiration<=clock_timestamp()';
    when 'factor_history' then table_name:='two_factor_authentications';key_sql:='t.two_factor_index::text';account_sql:='t.account_id';predicate_sql:='(t.revoked_at<clock_timestamp()-make_interval(days=>p_history) or (not t.verified and coalesce(t.setup_authorized_until,t.expiration,t.created_on+interval ''1 day'')<=clock_timestamp()))';
    when 'grant_cycles' then table_name:='entitlement_grant_cycles';key_sql:='jsonb_build_array(t.grant_id,t.cycle)::text';account_sql:='(select g.account_id from entitlement_grants g where g.grant_id=t.grant_id)';predicate_sql:='exists(select 1 from entitlement_grants g where g.grant_id=t.grant_id and cor22_grant_obsolete(g,p_history))';
    when 'grant_history' then table_name:='entitlement_grants';key_sql:='t.grant_id::text';account_sql:='t.account_id';predicate_sql:='cor22_grant_obsolete(t,p_history) and not exists(select 1 from entitlement_grant_cycles c where c.grant_id=t.grant_id) and not exists(select 1 from grant_activation_requests r where r.grant_id=t.grant_id) and not exists(select 1 from activation_creation_admissions a where a.grant_id=t.grant_id)';
    when 'grant_audit' then table_name:='entitlement_grant_audit';key_sql:='t.audit_id::text';account_sql:=null;predicate_sql:='t.happened_at<clock_timestamp()-make_interval(days=>p_audit) and not exists(select 1 from entitlement_grants g where g.grant_id=t.grant_id)';
    when 'legacy_activations' then table_name:='activations';key_sql:='t.activation_id::text';account_sql:='t.account_id';predicate_sql:='t.off_at<clock_timestamp()-make_interval(days=>p_history)';
    when 'logout_events' then table_name:='session_logout_events';key_sql:='t.logout_event_id::text';account_sql:=null;predicate_sql:='t.requested_at<clock_timestamp()-make_interval(days=>p_audit)';
    when 'pending_login' then table_name:='pending_two_factor_sessions';key_sql:='t.pre_auth_access_token_hash';account_sql:='t.account_id';predicate_sql:='t.expiration<clock_timestamp()-make_interval(days=>p_history)';
    when 'pending_reset' then table_name:='pending_password_reset_sessions';key_sql:='t.reset_access_token_hash';account_sql:='t.account_id';predicate_sql:='t.expires_at<clock_timestamp()-make_interval(days=>p_history)';
    when 'reauth_budgets' then table_name:='account_reauthentication_budgets';key_sql:='t.account_id::text';account_sql:='t.account_id';predicate_sql:='t.window_start+interval ''7 days''<clock_timestamp()-make_interval(days=>p_history) and not exists(select 1 from sensitive_password_attempts a where a.account_id=t.account_id and a.window_version=t.window_version and a.expiration>clock_timestamp())';
    when 'recovery_proofs' then table_name:='account_recoveries';key_sql:='t.token_hash';account_sql:='t.account_id';predicate_sql:='t.expiration<clock_timestamp()-make_interval(days=>p_history)';
    when 'reset_budgets' then table_name:='password_reset_rate_limits';key_sql:='t.rate_limit_key';account_sql:=null;predicate_sql:='greatest(t.window_started_at+interval ''168 hours'',coalesce(t.last_request_at,t.window_started_at)+interval ''168 hours'',coalesce(t.blocked_until,t.window_started_at))<clock_timestamp()-make_interval(days=>p_history)';
    when 'reset_events' then table_name:='password_reset_events';key_sql:='t.password_reset_event_id::text';account_sql:=null;predicate_sql:='t.created_at<clock_timestamp()-make_interval(days=>p_audit)';
    when 'reset_requests' then table_name:='password_reset_requests';key_sql:='t.password_reset_request_id::text';account_sql:='t.account_id';predicate_sql:='t.expires_at<clock_timestamp()-make_interval(days=>p_history) and not exists(select 1 from pending_password_reset_sessions s where s.password_reset_request_id=t.password_reset_request_id)';
    when 'sensitive_attempts' then table_name:='sensitive_password_attempts';key_sql:='t.attempt_id::text';account_sql:='t.account_id';predicate_sql:='t.expiration<=clock_timestamp()';
    when 'sensitive_grants' then table_name:='sensitive_action_grants';key_sql:='t.token_hash';account_sql:='t.account_id';predicate_sql:='t.expiration<=clock_timestamp()';
    when 'sensitive_proofs' then table_name:='sensitive_action_proof_sessions';key_sql:='t.proof_id::text';account_sql:='t.account_id';predicate_sql:='t.expiration<=clock_timestamp() and not exists(select 1 from sensitive_action_grants g where g.proof_id=t.proof_id)';
    when 'sensitive_tokens' then table_name:='account_sensitive_action_tokens';key_sql:='t.token_id::text';account_sql:='t.account_id';predicate_sql:='t.expiration<clock_timestamp()-make_interval(days=>p_history)';
    when 'sessions' then table_name:='sessions';key_sql:='t.access_token_hash';account_sql:='t.account_id';predicate_sql:='least(t.session_expiration,coalesce(t.cut_off,t.session_expiration))<clock_timestamp()-make_interval(days=>p_history)';
    when 'operation_steps' then table_name:='security_operation_steps';key_sql:='jsonb_build_array(t.operation_id,t.step_key)::text';account_sql:=null;predicate_sql:='exists(select 1 from security_operations o where o.operation_id=t.operation_id and o.expires_at<clock_timestamp()-interval ''2 minutes'' and o.execute_before<=clock_timestamp())';
    when 'mutation_replays' then table_name:='authenticated_mutation_replays';key_sql:='encode(t.identity_digest,''hex'')';account_sql:=null;predicate_sql:='t.expires_at<=clock_timestamp() and t.replay_until<=clock_timestamp() and exists(select 1 from security_operations o where o.operation_id=t.operation_id and o.expires_at<clock_timestamp()-interval ''2 minutes'' and o.execute_before<=clock_timestamp())';
    when 'operations' then table_name:='security_operations';key_sql:='t.operation_id::text';account_sql:=null;predicate_sql:='t.expires_at<clock_timestamp()-interval ''2 minutes'' and t.execute_before<=clock_timestamp() and not exists(select 1 from security_operation_steps s where s.operation_id=t.operation_id) and not exists(select 1 from authenticated_mutation_replays r where r.operation_id=t.operation_id)';
    when 'test_deliveries' then table_name:='system_test_delivery_messages';key_sql:='t.delivery_id::text';account_sql:=null;predicate_sql:='t.created_at<clock_timestamp()-interval ''1 day''';
    when 'verification_history' then table_name:='account_verifications';key_sql:='t.verification_index::text';account_sql:='t.account_id';predicate_sql:='coalesce(t.sent_when,t.created_on)+t.expiration<clock_timestamp()-make_interval(days=>p_history)';
    when 'unverified_accounts' then table_name:='accounts';key_sql:='t.account_id::text';account_sql:='t.account_id';predicate_sql:='t.verify_status<>1 and t.created_on<clock_timestamp()-make_interval(days=>p_unverified) and (t.unlock_when is null or t.unlock_when<=clock_timestamp()) and cor22_account_empty(t.account_id)';
    else raise exception 'Unknown retention class' using errcode='P2201';
    end case;
    return next;
end;
$$;

create or replace function cor22_claim_retention()
returns table(job_name text,lease_id uuid) language plpgsql security definer as $$
declare chosen text;token uuid:=gen_random_uuid();
begin
    select j.job_name into chosen from retention_jobs j where j.next_run<=clock_timestamp()
        and (j.lease_until is null or j.lease_until<=clock_timestamp())
        order by j.next_run,j.job_name limit 1 for update skip locked;
    if chosen is null then return;end if;
    update retention_jobs j set lease_id=token,lease_until=clock_timestamp()+interval '60 seconds',last_attempt=clock_timestamp()
        where j.job_name=chosen;
    return query select chosen,token;
end;
$$;

create or replace function cor22_fail_retention(p_job text,p_lease uuid,p_code text)
returns boolean language plpgsql security definer as $$
begin
    update retention_jobs set last_failure=clock_timestamp(),failure_code=case
        when p_code~'^[A-Z0-9]{5}$' then p_code when p_code in ('deadline','dependency') then p_code else 'dependency' end,
        failures=failures+1,lease_id=null,lease_until=null,next_run=clock_timestamp()+interval '60 seconds'
        where job_name=p_job and lease_id=p_lease;
    return found;
end;
$$;

create or replace function cor22_retention_batch(p_job text,p_lease uuid,p_limit integer,p_accounts integer,
    p_history integer,p_audit integer,p_unverified integer,p_dry boolean)
returns table(eligible integer,affected integer,wrapped boolean)
language plpgsql security definer as $$
declare job retention_jobs%rowtype;policy record;owner uuid;owners uuid[];ids tid[];keys text[];
    query text;pred text;n integer;changed integer;outbox_count integer;last_owner uuid;last_key text;account_key text;
begin
    if p_limit is null or p_limit not between 1 and 100 or p_accounts is null or p_accounts not between 1 and 8
        or p_history is null or p_history not between 7 and 3650 or p_audit is null or p_audit not between 90 and 3650
        or p_unverified is null or p_unverified not between 30 and 3650 or p_dry is null then
        raise exception 'Invalid retention policy' using errcode='P2201';end if;
    select j.* into job from retention_jobs j where j.job_name=p_job for update;
    if not found or p_lease is null or job.lease_id is null or job.lease_until is null or job.lease_id is distinct from p_lease or job.lease_until<=clock_timestamp() then
        raise exception 'Retention lease changed' using errcode='P2202';end if;
    select * into policy from cor22_retention_policy(p_job);
    pred:=replace(replace(replace(policy.predicate_sql,'p_history',p_history::text),'p_audit',p_audit::text),'p_unverified',p_unverified::text);
    eligible:=0;affected:=0;wrapped:=false;last_owner:=job.cursor_account;last_key:=job.cursor_key;
    if policy.account_sql is not null then
        -- Global email gate precedes roots; roots precede children. Never take the
        -- unbounded 'all authority' gate merely to prune a bounded child batch.
        perform cor17_email_gate();
        query:=format('select array_agg(q.account_id order by q.account_id) from (
            select a.account_id from accounts a where ($1::uuid is null or a.account_id>$1 or (a.account_id=$1 and $2::text is not null))
            and exists(select 1 from %I t where (%s)=a.account_id and (%s))
            order by a.account_id limit $3 for update of a skip locked) q',policy.table_name,policy.account_sql,pred);
        execute query into owners using job.cursor_account,job.cursor_key,p_accounts;
    else owners:=array[null::uuid];end if;
    foreach owner in array coalesce(owners,array[]::uuid[]) loop
        account_key:=case when owner is not distinct from job.cursor_account then job.cursor_key else null end;
        query:=format('select array_agg(q.row_id order by q.row_key),array_agg(q.row_key order by q.row_key) from (
            select t.ctid row_id,(%s) row_key from %I t where (%s) and (%s)
            and ($1::text is null or (%s)>$1) order by (%s) limit $2 for update of t skip locked) q',
            policy.key_sql,policy.table_name,pred,
            case when policy.account_sql is null then 'true' else '('||policy.account_sql||')=$3' end,policy.key_sql,policy.key_sql);
        execute query into ids,keys using account_key,p_limit-eligible,owner;
        n:=coalesce(cardinality(ids),0);eligible:=eligible+n;
        last_owner:=owner;last_key:=case when eligible=p_limit then keys[n] else null end;
        if policy.account_sql is null and n>0 then last_key:=keys[n];end if;
        if not p_dry and n>0 then
            if p_job='delivery_payloads' then
                -- Expiry invalidates proofs independently of ambiguous provider acceptance.
                execute 'update delivery_candidates t set state=case when state=''staged'' then ''expired'' else state end,
                    terminal_at=coalesce(terminal_at,clock_timestamp()) where t.ctid=any($1)' using ids;
                get diagnostics changed=row_count;
                if changed<>n then raise exception 'Retention write suppressed' using errcode='P2203';end if;
                select count(*) into outbox_count from delivery_outbox o where o.delivery_id::text=any(keys);
                execute 'update delivery_outbox o set state=case when o.state in (''queued'',''claimed'',''accepted'',''ambiguous'') then ''expired'' else o.state end,
                    nonce=null,ciphertext=null,tag=null,lease_id=null,lease_until=null
                    where o.delivery_id::text=any($1)' using keys;
                get diagnostics changed=row_count;
                if changed<>outbox_count then raise exception 'Retention payload write suppressed' using errcode='P2203';end if;
                update delivery_attempts a set state='unknown',code='DELIVERY_EXPIRED_WITHOUT_RECEIPT',recorded_at=clock_timestamp() where a.delivery_id::text=any(keys) and a.state='claimed';
            else
                if p_job='grant_audit' then
                    insert into retention_audit_delete_permits(backend,transaction_id,audit_id,cutoff)
                        select pg_backend_pid(),txid_current(),t.audit_id,clock_timestamp()-make_interval(days=>p_audit)
                        from entitlement_grant_audit t where t.ctid=any(ids);
                end if;
                execute format('delete from %I t where t.ctid=any($1) and (%s)',policy.table_name,pred) using ids;
                get diagnostics changed=row_count;
                if changed<>n then raise exception 'Retention write suppressed' using errcode='P2203';end if;
            end if;
            affected:=affected+n;
        end if;
        if eligible>=p_limit then exit;end if;
    end loop;
    if policy.account_sql is null then
        if eligible<p_limit then last_key:=null;wrapped:=true;end if;
    elsif owners is null or cardinality(owners)<p_accounts and eligible<p_limit then
        last_owner:=null;last_key:=null;wrapped:=true;
    end if;
    -- Fence at the end as well: an expired lease cannot commit deletions or cursor.
    if job.lease_until<=clock_timestamp() then raise exception 'Retention lease expired' using errcode='P2202';end if;
    update retention_jobs set cursor_account=last_owner,cursor_key=last_key,lease_id=null,lease_until=null,
        next_run=clock_timestamp()+interval '30 seconds',last_success=clock_timestamp(),
        last_eligible=eligible,last_affected=affected,last_dry_run=p_dry,failure_code=null,
        passes=passes+case when wrapped then 1 else 0 end where job_name=p_job and lease_id=p_lease;
    if not found then raise exception 'Retention claim changed' using errcode='P2202';end if;
    return next;
end;
$$;

-- Audit updates remain forbidden. Retention permits are exact-row, transaction-
-- and backend-bound, private, single-use, and only for aged orphan grant history.


-- Freeze trusted lookup order at installation, with temporary objects last.
do $cor22$
declare routine text;trusted text:=current_schema();
begin
    foreach routine in array array['cor22_claim_retention()','cor22_fail_retention(text,uuid,text)',
        'cor22_retention_batch(text,uuid,integer,integer,integer,integer,integer,boolean)','cor19_protect_audit()']
    loop execute format('alter function %I.%s set search_path to pg_catalog,%I,public,pg_temp',trusted,routine,trusted);end loop;
end;
$cor22$;

-- COR23M: independent version-1 authoritative Login/Delivery admission budgets.
-- State contains fixed-size hashes, never raw destinations/IPs/tokens or proof state.
create table abuse_admission_budgets_v1 (
    policy_id integer not null check (policy_id in (0,2)),
    dimension_id integer not null check (dimension_id in (0,1,2)),
    budget_hash bytea not null check (octet_length(budget_hash)=32),
    attempt_count integer not null check (attempt_count>=0),
    window_expires_at timestamptz not null,
    cooldown_until timestamptz,
    retain_until timestamptz not null,
    primary key(policy_id,dimension_id,budget_hash),
    check(retain_until>=window_expires_at and (cooldown_until is null or retain_until>=cooldown_until))
);
create index abuse_admission_budgets_v1_expiry on abuse_admission_budgets_v1(retain_until);

create or replace function cor23m_increment_budget_v1(p_policy integer,p_dimension integer,p_hash bytea,p_maximum integer,p_window_ms bigint,p_cooldown_ms bigint)
returns table(admitted boolean,attempts integer,retry_ms bigint,reason integer,cooldown_started boolean)
language plpgsql as $$
declare v_row abuse_admission_budgets_v1%rowtype;v_now timestamptz;v_retry bigint;v_started boolean:=false;
begin
    if p_policy is null or p_policy not in (0,2) or p_dimension is null or p_dimension not in (0,1,2)
        or p_hash is null or octet_length(p_hash)<>32 or p_maximum is null or p_maximum not between 1 and 1000000
        or p_window_ms is null or p_window_ms not between 1 and 86400000 or p_cooldown_ms is null or p_cooldown_ms not between 0 and 86400000 then
        raise exception 'invalid version-1 abuse budget request' using errcode='22023';
    end if;
    -- Atomic upsert acquires the unique row even against concurrent insertion/expiry cleanup.
    -- The harmless update retains its lock through this admission transaction.
    insert into abuse_admission_budgets_v1 as b(policy_id,dimension_id,budget_hash,attempt_count,window_expires_at,retain_until)
    values(p_policy,p_dimension,p_hash,0,'-infinity','-infinity')
    on conflict(policy_id,dimension_id,budget_hash) do update set attempt_count=b.attempt_count
    returning b.* into v_row;
    -- Sample real server time AFTER waiting for the admission row; never transaction start time.
    v_now:=clock_timestamp();
    if v_row.cooldown_until>v_now then
        v_retry:=greatest(1,ceil(extract(epoch from(v_row.cooldown_until-v_now))*1000)::bigint);
        return query select false,case when v_row.window_expires_at>v_now then v_row.attempt_count else 0 end,v_retry,1,false;
        return;
    end if;
    v_row.cooldown_until:=null;
    if v_row.window_expires_at<=v_now then
        v_row.attempt_count:=1;
        v_row.window_expires_at:=v_now+p_window_ms*interval '1 millisecond';
    else
        v_row.attempt_count:=least(v_row.attempt_count::bigint+1,2147483647)::integer;
    end if;
    if v_row.attempt_count>p_maximum and p_cooldown_ms>0 then
        v_row.cooldown_until:=v_now+p_cooldown_ms*interval '1 millisecond';v_started:=true;
    end if;
    v_row.retain_until:=greatest(v_row.window_expires_at,coalesce(v_row.cooldown_until,v_row.window_expires_at));
    update abuse_admission_budgets_v1 as b set attempt_count=v_row.attempt_count,window_expires_at=v_row.window_expires_at,
        cooldown_until=v_row.cooldown_until,retain_until=v_row.retain_until
        where b.policy_id=p_policy and b.dimension_id=p_dimension and b.budget_hash=p_hash;
    if v_row.attempt_count<=p_maximum then
        return query select true,v_row.attempt_count,0::bigint,0,false;
    else
        v_retry:=greatest(1,ceil(extract(epoch from(coalesce(v_row.cooldown_until,v_row.window_expires_at)-v_now))*1000)::bigint);
        return query select false,v_row.attempt_count,v_retry,2,v_started;
    end if;
end;
$$;

create or replace function cor23m_budget_cooldown_v1(p_policy integer,p_dimension integer,p_hash bytea)
returns bigint language plpgsql as $$
declare v_until timestamptz;v_now timestamptz;
begin
    if p_policy is null or p_policy not in(0,2) or p_dimension is null or p_dimension not in(0,1,2) or p_hash is null or octet_length(p_hash)<>32 then
        raise exception 'invalid version-1 abuse budget key' using errcode='22023';
    end if;
    select b.cooldown_until into v_until from abuse_admission_budgets_v1 b
        where b.policy_id=p_policy and b.dimension_id=p_dimension and b.budget_hash=p_hash for update;
    v_now:=clock_timestamp();
    return case when v_until>v_now then greatest(1,ceil(extract(epoch from(v_until-v_now))*1000)::bigint) else 0::bigint end;
end;
$$;

create or replace function cor23m_reset_budget_v1(p_policy integer,p_dimension integer,p_hash bytea)
returns boolean language plpgsql as $$
begin
    if p_policy is null or p_policy not in(0,2) or p_dimension is null or p_dimension not in(0,1,2) or p_hash is null or octet_length(p_hash)<>32 then
        raise exception 'invalid version-1 abuse budget key' using errcode='22023';
    end if;
    update abuse_admission_budgets_v1 as b set attempt_count=0,window_expires_at='-infinity',cooldown_until=null,retain_until='-infinity'
        where b.policy_id=p_policy and b.dimension_id=p_dimension and b.budget_hash=p_hash;
    return true;
end;
$$;

create or replace function cor23m_purge_budgets_v1(p_batch integer,p_dry boolean)
returns integer language plpgsql as $$
declare v_count integer;v_now timestamptz:=clock_timestamp();
begin
    if p_batch is null or p_batch not between 1 and 100 or p_dry is null then
        raise exception 'invalid abuse budget cleanup batch' using errcode='22023';
    end if;
    if p_dry then
        select count(*)::integer into v_count from(select 1 from abuse_admission_budgets_v1 b where b.retain_until<=v_now
            order by b.retain_until,b.policy_id,b.dimension_id,b.budget_hash limit p_batch for update skip locked) eligible;
        return v_count;
    end if;
    with expired as(select b.policy_id,b.dimension_id,b.budget_hash from abuse_admission_budgets_v1 b where b.retain_until<=v_now
        order by b.retain_until,b.policy_id,b.dimension_id,b.budget_hash limit p_batch for update skip locked),
    deleted as(delete from abuse_admission_budgets_v1 b using expired e
        where b.policy_id=e.policy_id and b.dimension_id=e.dimension_id and b.budget_hash=e.budget_hash returning 1)
    select count(*)::integer into v_count from deleted;
    return v_count;
end;
$$;

-- Freeze lookup order independently of caller search_path, including trusted private test schemas.
do $cor23m$
declare routine text;trusted text:=current_schema();
begin
    foreach routine in array array['cor23m_increment_budget_v1(integer,integer,bytea,integer,bigint,bigint)',
        'cor23m_budget_cooldown_v1(integer,integer,bytea)','cor23m_reset_budget_v1(integer,integer,bytea)','cor23m_purge_budgets_v1(integer,boolean)']
    loop execute format('alter function %I.%s set search_path to pg_catalog,%I,public,pg_temp',trusted,routine,trusted);end loop;
end;
$cor23m$;
