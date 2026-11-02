-- Install under a trusted explicit schema path; captured per function so isolated schema fixtures stay isolated.
-- SVS-04: dedicated SELECT-only authority path. No legacy writer semantics changed.

create or replace function svs_read_approval_audited(p_grant uuid)
returns boolean language plpgsql stable security invoker set search_path from current as $$
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

create or replace function svs_read_activation_audited(p_grant uuid)
returns boolean language plpgsql stable security invoker set search_path from current as $$
begin
    return exists(select 1 from entitlement_grants g join entitlement_grant_audit z using(grant_id)
        where g.grant_id=p_grant and z.action='redeemed' and z.account_id=g.account_id
        and (z.approval->>'startsAt')::timestamptz=g.starts_at
        and (z.approval->>'eligibilityUntil')::timestamptz is not distinct from g.eligibility_until
        and g.eligibility_until is not distinct from least(cor20_term_boundary(g.starts_at,g.term,g.max_cycles),g.authorized_end));
end;
$$;

create or replace function svs_read_entitlements(p_account uuid,p_moment timestamptz)
returns jsonb language plpgsql stable security invoker set search_path from current as $$
declare a record; g record; moment timestamptz; boundary timestamptz;
    next_boundary timestamptz; eligible_until timestamptz; unbounded boolean; paid boolean; enabled boolean;
    features_value smallint; capabilities text[]; denied text[]; current_cycle integer; grants jsonb;
    projection jsonb; account_live boolean;
begin
    select t.account_id,t.verify_status,t.cut_off,t.unlock_when,t.entitlement_version into a from accounts t where t.account_id=p_account;
    if not found then return null;end if;
        moment:=p_moment;enabled:=cor20_grant_rights_enabled();
        account_live:=a.verify_status=1 and (a.cut_off is null or a.cut_off>moment) and (a.unlock_when is null or a.unlock_when<=moment);
        next_boundary:=null;eligible_until:=null;unbounded:=false;paid:=false;denied:=array[]::text[];grants:='[]'::jsonb;
        for g in select t.grant_id,t.version,t.state,t.tier,t.term,t.cadence,t.start_anchor,t.starts_at,t.eligibility_until,t.max_cycles,t.materialized_cycle,t.issuer,t.denied_capabilities from entitlement_grants t where t.account_id=p_account order by t.grant_id loop
            current_cycle:=0;
            if g.state='active' and cor19_is_issuer(g.issuer) and svs_read_approval_audited(g.grant_id) and svs_read_activation_audited(g.grant_id) then
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
        return projection||jsonb_build_object('version',a.entitlement_version);
end;
$$;

create or replace function svs_read_current_session(p_hash text)
returns table(access_token_hash text,account_id uuid,family_id uuid,generation bigint,protocol_version integer,
    session_stamp uuid,session_account_stamp uuid,account_stamp uuid,signing_key bytea,
    access_expiration timestamptz,hard_expiration timestamptz,session_cutoff timestamptz,account_cutoff timestamptz,
    verification_status smallint,unlock_when timestamptz,read_at timestamptz,entitlement_json text)
language sql stable security invoker set search_path from current as $$
    select s.access_token_hash,s.account_id,s.session_id,s.generation,s.protocol_version,
        s.security_stamp,s.account_security_stamp,a.security_stamp,s.refresh_token,
        s.access_expiration,s.session_expiration,s.cut_off,a.cut_off,a.verify_status,a.unlock_when,
        statement_timestamp(),svs_read_entitlements(a.account_id,statement_timestamp())::text
    from sessions s join accounts a on a.account_id=s.account_id
    where s.access_token_hash=p_hash;
$$;
-- No ambient function grant. SVS-05 provisions and proves the dedicated identity.
revoke all on function svs_read_approval_audited(uuid),svs_read_activation_audited(uuid),
    svs_read_entitlements(uuid,timestamptz),svs_read_current_session(text) from public;
