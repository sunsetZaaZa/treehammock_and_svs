\set ON_ERROR_STOP on
-- Run only against an operator-owned, backed-up current-baseline database.
-- Required: psql -v preserve_roles='["actual_app_writer","actual_issuer",...]' -f this-file
-- No password is embedded; provision login authentication separately through the secret manager.
begin;
set local search_path = pg_catalog;
set local lock_timeout = '5s';
set local statement_timeout = '60s';
create temporary table svs05_preserve(role_name name primary key) on commit drop;
insert into svs05_preserve select value::name from jsonb_array_elements_text(:'preserve_roles'::jsonb);
do $guard$
begin
 if not (select rolsuper from pg_roles where rolname=current_user) then raise exception 'Designated superuser provisioning identity required';end if;
 if not exists(select 1 from svs05_preserve) then raise exception 'Explicit exhaustive writer/issuer/operator preservation list required';end if;
 if exists(select 1 from svs05_preserve p left join pg_roles r on r.rolname=p.role_name where r.oid is null or p.role_name in ('treehammock_svs','treehammock_svs_read') or p.role_name like 'pg_%' or p.role_name like 'yb_%') then raise exception 'Invalid preservation role';end if;
 if exists(select 1 from pg_roles where rolname in ('treehammock_svs','treehammock_svs_read')) then raise exception 'SVS identity already exists; inspect rather than adopting unknown grants';end if;
 if exists(select 1 from pg_namespace where nspname not in ('public','information_schema') and nspname not like 'pg_%') then raise exception 'Unreviewed schema';end if;
 if exists(select 1 from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname='public' and p.prokind='p') then raise exception 'Unreviewed procedures';end if;
 if exists(select 1 from pg_default_acl where defaclobjtype not in ('f','r','S')) then raise exception 'Unreviewed default privilege kind';end if;
 -- A new cluster role inherits PUBLIC on every database. Isolate all other databases first.
 if exists(select 1 from pg_database d cross join lateral aclexplode(coalesce(d.datacl,acldefault('d',d.datdba))) a where d.datname<>current_database() and d.datallowconn and a.grantee=0 and a.privilege_type='CONNECT') then raise exception 'Other database PUBLIC CONNECT must be isolated explicitly before provisioning';end if;
 if to_regprocedure('public.svs_read_current_session(text)') is null then raise exception 'Install verified SVS-04 pure reader closure first';end if;
end
$guard$;
-- Preserve each existing PUBLIC right, including its grant option, to the explicit roles.
-- Nothing assumes the application runs as its table owner or as a superuser.
do $hardening$
declare o record; a record; r record; target text; kind text; sqlkind text;
begin
 for o in select c.oid,c.relowner,n.nspname,c.relname,c.relkind,c.relacl from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relkind in ('r','p','v','m','f','S') loop
  kind:=case when o.relkind='S' then 'S' else 'r' end;
  target:=format('%I.%I',o.nspname,o.relname);sqlkind:=case when o.relkind='S' then 'SEQUENCE' else 'TABLE' end;
  for a in select * from aclexplode(coalesce(o.relacl,acldefault(kind::"char",o.relowner))) where grantee=0 loop
   for r in select role_name from svs05_preserve loop execute format('grant %s on %s %s to %I%s',a.privilege_type,sqlkind,target,r.role_name,case when a.is_grantable then ' with grant option' else '' end);end loop;
  end loop;
  execute format('revoke all on %s %s from public',sqlkind,target);
  if o.relkind<>'S' then
   for a in select t.attname,x.* from pg_attribute t cross join lateral aclexplode(t.attacl) x where t.attrelid=o.oid and t.attnum>0 and not t.attisdropped and x.grantee=0 loop
    for r in select role_name from svs05_preserve loop execute format('grant %s (%I) on table %s to %I%s',a.privilege_type,a.attname,target,r.role_name,case when a.is_grantable then ' with grant option' else '' end);end loop;
    execute format('revoke %s (%I) on table %s from public',a.privilege_type,a.attname,target);
   end loop;
  end if;
 end loop;
 for o in select p.oid,p.proowner,p.proacl from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname='public' or (n.nspname='pg_catalog' and (p.proname like 'lo\_%' escape '\' or p.proname in ('loopen','loclose','loread','lowrite','pg_read_file','pg_read_binary_file','pg_stat_file','pg_ls_dir'))) loop
  for a in select * from aclexplode(coalesce(o.proacl,acldefault('f',o.proowner))) where grantee=0 loop
   for r in select role_name from svs05_preserve loop execute format('grant %s on function %s to %I%s',a.privilege_type,o.oid::regprocedure,r.role_name,case when a.is_grantable then ' with grant option' else '' end);end loop;
  end loop;
  execute format('revoke all on function %s from public',o.oid::regprocedure);
 end loop;
 for o in select oid,nspowner,nspacl from pg_namespace where nspname='public' loop
  for a in select * from aclexplode(coalesce(o.nspacl,acldefault('n',o.nspowner))) where grantee=0 loop
   for r in select role_name from svs05_preserve loop execute format('grant %s on schema public to %I%s',a.privilege_type,r.role_name,case when a.is_grantable then ' with grant option' else '' end);end loop;
  end loop;
 end loop;
 for o in select datdba,datacl from pg_database where datname=current_database() loop
  for a in select * from aclexplode(coalesce(o.datacl,acldefault('d',o.datdba))) where grantee=0 loop
   for r in select role_name from svs05_preserve loop execute format('grant %s on database %I to %I%s',a.privilege_type,current_database(),r.role_name,case when a.is_grantable then ' with grant option' else '' end);end loop;
  end loop;
 end loop;
 execute format('revoke all on database %I from public',current_database());
 revoke all on schema public from public;
 -- Global function defaults exist even without pg_default_acl rows. Freeze every current creator.
 for o in select r.rolname,r.oid,coalesce(d.defaclacl,acldefault('f',r.oid)) as acl from pg_roles r left join pg_default_acl d on d.defaclrole=r.oid and d.defaclnamespace=0 and d.defaclobjtype='f' loop
  if exists(select 1 from aclexplode(o.acl) where grantee=0 and privilege_type='EXECUTE') then
   for r in select role_name from svs05_preserve loop execute format('alter default privileges for role %I grant execute on functions to %I',o.rolname,r.role_name);end loop;
  end if;
  execute format('alter default privileges for role %I revoke execute on functions from public',o.rolname);
 end loop;
 for o in select d.*,n.nspname,r.rolname from pg_default_acl d left join pg_namespace n on n.oid=d.defaclnamespace join pg_roles r on r.oid=d.defaclrole loop
  kind:=case o.defaclobjtype when 'f' then 'FUNCTIONS' when 'S' then 'SEQUENCES' else 'TABLES' end;
  target:=case when o.defaclnamespace=0 then '' else format(' in schema %I',o.nspname) end;
  for a in select * from aclexplode(o.defaclacl) where grantee=0 loop
   for r in select role_name from svs05_preserve loop execute format('alter default privileges for role %I%s grant %s on %s to %I%s',o.rolname,target,a.privilege_type,kind,r.role_name,case when a.is_grantable then ' with grant option' else '' end);end loop;
   execute format('alter default privileges for role %I%s revoke %s on %s from public',o.rolname,target,a.privilege_type,kind);
  end loop;
 end loop;
end
$hardening$;
create role treehammock_svs_read nologin nosuperuser nocreatedb nocreaterole noinherit noreplication nobypassrls;
create role treehammock_svs login nosuperuser nocreatedb nocreaterole inherit noreplication nobypassrls connection limit 16;
grant treehammock_svs_read to treehammock_svs;
grant usage on schema public to treehammock_svs_read;
do $database$ begin execute format('grant connect on database %I to treehammock_svs_read',current_database());end $database$;
alter role treehammock_svs set default_transaction_read_only = on;
alter role treehammock_svs set search_path = pg_catalog, public, pg_temp;
alter role treehammock_svs set statement_timeout = '3s';
alter role treehammock_svs set lock_timeout = '500ms';
grant select (account_id, security_stamp, cut_off, verify_status, unlock_when, entitlement_version) on public.accounts to treehammock_svs_read;
grant select (access_token_hash, account_id, session_id, generation, protocol_version, security_stamp, account_security_stamp, refresh_token, access_expiration, session_expiration, cut_off) on public.sessions to treehammock_svs_read;
grant select (account_id, grant_id, origin_stamp, issuer, catalog, tier, term, cadence, start_anchor, approved_start, authorized_end, max_cycles, redeem_before, issuer_reference, denied_capabilities, eligibility_until, starts_at, state, version, materialized_cycle) on public.entitlement_grants to treehammock_svs_read;
grant select (grant_id, action, grant_version, account_id, credential_stamp, actor, approval) on public.entitlement_grant_audit to treehammock_svs_read;
alter function public.svs_read_approval_audited(uuid) set search_path = pg_catalog, public, pg_temp;
grant execute on function public.svs_read_approval_audited(uuid) to treehammock_svs_read;
alter function public.svs_read_activation_audited(uuid) set search_path = pg_catalog, public, pg_temp;
grant execute on function public.svs_read_activation_audited(uuid) to treehammock_svs_read;
alter function public.svs_read_entitlements(uuid,timestamp with time zone) set search_path = pg_catalog, public, pg_temp;
grant execute on function public.svs_read_entitlements(uuid,timestamp with time zone) to treehammock_svs_read;
alter function public.svs_read_current_session(text) set search_path = pg_catalog, public, pg_temp;
grant execute on function public.svs_read_current_session(text) to treehammock_svs_read;
alter function public.cor19_is_issuer(name) set search_path = pg_catalog, public, pg_temp;
grant execute on function public.cor19_is_issuer(name) to treehammock_svs_read;
alter function public.cor20_grant_rights_enabled() set search_path = pg_catalog, public, pg_temp;
grant execute on function public.cor20_grant_rights_enabled() to treehammock_svs_read;
alter function public.cor20_capabilities(smallint) set search_path = pg_catalog, public, pg_temp;
grant execute on function public.cor20_capabilities(smallint) to treehammock_svs_read;
alter function public.cor20_term_boundary(timestamp with time zone,smallint,integer) set search_path = pg_catalog, public, pg_temp;
grant execute on function public.cor20_term_boundary(timestamp with time zone,smallint,integer) to treehammock_svs_read;
alter function public.cor20_cycle_at(timestamp with time zone,smallint,integer,timestamp with time zone,timestamp with time zone) set search_path = pg_catalog, public, pg_temp;
grant execute on function public.cor20_cycle_at(timestamp with time zone,smallint,integer,timestamp with time zone,timestamp with time zone) to treehammock_svs_read;
commit;
