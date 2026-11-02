-- Run only against the owned COR22 qualification schema. psql -v account=<fixture UUID> -v identifier=<fixture phone/email>
\set ON_ERROR_STOP on
begin read only;
set local statement_timeout='5s';
select case when current_schema() like 'cor22_%' then true else false end as owned_schema \gset
\if :owned_schema
\else
  \echo 'Owned cor22_ schema required'
  \quit 2
\endif

-- Exact reset identifier shape: OR email/username and normalized verified phone.
explain (analyze,buffers,wal,format json)
select a.account_id from accounts a
where lower(a.email_address)=lower(nullif(btrim(:'identifier'),''))
or lower(a.username)=lower(nullif(btrim(:'identifier'),''))
or exists(select 1 from two_factor_authentications t where t.account_id=a.account_id
    and t.method=2 and t.verified and t.revoked_at is null and (t.expiration is null or t.expiration>clock_timestamp())
    and t.phone_number is not null and (
        lower(t.phone_number)=lower(nullif(btrim(:'identifier'),''))
        or regexp_replace(coalesce(t.phone_number,''),'[^0-9+]','','g')=regexp_replace(:'identifier','[^0-9+]','','g')
        or regexp_replace(coalesce(t.phone_country_code,'')||coalesce(t.phone_number,''),'[^0-9+]','','g')=regexp_replace(:'identifier','[^0-9+]','','g')
        or regexp_replace(coalesce(t.phone_number,''),'[^0-9]','','g')=regexp_replace(:'identifier','[^0-9]','','g')
        or regexp_replace(coalesce(t.phone_country_code,'')||coalesce(t.phone_number,''),'[^0-9]','','g')=regexp_replace(:'identifier','[^0-9]','','g')))
order by case when lower(a.email_address)=lower(nullif(btrim(:'identifier'),'')) then 0
    when lower(a.username)=lower(nullif(btrim(:'identifier'),'')) then 1 else 2 end limit 1;

explain (analyze,buffers,wal,format json)
select two_factor_index from two_factor_authentications where account_id=:'account'::uuid
    and (revoked_at<clock_timestamp()-interval '7 days' or
        (not verified and coalesce(setup_authorized_until,expiration,created_on+interval '1 day')<=clock_timestamp()))
order by two_factor_index::text limit 100;

explain (analyze,buffers,wal,format json)
select access_token_hash from sessions where account_id=:'account'::uuid
    and least(session_expiration,coalesce(cut_off,session_expiration))<clock_timestamp()-interval '7 days'
order by access_token_hash limit 100;

-- Every FK reachable from accounts, including grandchildren. An unconditional
-- valid leading-column index is a candidate, not proof of acceptable delete cost.
with recursive graph(parent) as (
    select 'accounts'::regclass::oid union
    select f.conrelid from pg_constraint f join graph g on g.parent=f.confrelid where f.contype='f')
select f.conname,f.confrelid::regclass as parent,f.conrelid::regclass as child,f.conkey,
    exists(select 1 from pg_index i where i.indrelid=f.conrelid and i.indisvalid and i.indisready and i.indpred is null
        and (select array_agg(x.attnum::smallint order by x.ord) from unnest(i.indkey) with ordinality x(attnum,ord)
            where x.ord<=cardinality(f.conkey))=f.conkey) as unconditional_leading_index
from pg_constraint f join graph g on g.parent=f.confrelid where f.contype='f'
order by parent::text,child::text,f.conname;

-- Root deletion is never ANALYZE-executed by this plan capture.
explain (format json) delete from accounts where account_id=:'account'::uuid;
rollback;
