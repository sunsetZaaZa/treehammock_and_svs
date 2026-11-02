\set ON_ERROR_STOP on
-- Drain all SVS database connections before removal. This does not restore PUBLIC privileges.
begin;
set local search_path=pg_catalog;
revoke treehammock_svs_read from treehammock_svs;
revoke all on all tables in schema public from treehammock_svs_read;
revoke all on all sequences in schema public from treehammock_svs_read;
revoke all on all functions in schema public from treehammock_svs_read;
revoke select (account_id, security_stamp, cut_off, verify_status, unlock_when, entitlement_version) on public.accounts from treehammock_svs_read;
revoke select (access_token_hash, account_id, session_id, generation, protocol_version, security_stamp, account_security_stamp, refresh_token, access_expiration, session_expiration, cut_off) on public.sessions from treehammock_svs_read;
revoke select (account_id, grant_id, origin_stamp, issuer, catalog, tier, term, cadence, start_anchor, approved_start, authorized_end, max_cycles, redeem_before, issuer_reference, denied_capabilities, eligibility_until, starts_at, state, version, materialized_cycle) on public.entitlement_grants from treehammock_svs_read;
revoke select (grant_id, action, grant_version, account_id, credential_stamp, actor, approval) on public.entitlement_grant_audit from treehammock_svs_read;
revoke all on schema public from treehammock_svs_read;
do $db$ begin execute format('revoke all on database %I from treehammock_svs_read',current_database());end $db$;
drop role treehammock_svs;
drop role treehammock_svs_read;
commit;
