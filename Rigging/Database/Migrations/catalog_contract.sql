-- Structural fingerprint for exact legacy adoption and fresh/upgrade comparison.
-- Caller sets search_path to the inspected schema before executing this query.
with namespace as (select oid from pg_namespace where nspname = @schema), objects as (
    select 'relation:' || c.relname as key, json_build_array(c.relkind,c.relpersistence,c.relrowsecurity,c.relforcerowsecurity,c.reloptions)::text as value
      from pg_class c where c.relnamespace = (select oid from namespace)
       and c.relkind in ('r','p','v','m') and c.relname <> 'treehammock_schema_history'
    union all
    select 'column:' || c.relname || ':' || a.attnum, json_build_array(a.attname,
           format_type(a.atttypid,a.atttypmod), a.attnotnull, a.attidentity, a.attgenerated,
           a.attcollation::regcollation::text,
           pg_get_expr(d.adbin,d.adrelid))::text
      from pg_class c join pg_attribute a on a.attrelid=c.oid
      left join pg_attrdef d on d.adrelid=c.oid and d.adnum=a.attnum
     where c.relnamespace=(select oid from namespace) and a.attnum>0 and not a.attisdropped
       and c.relkind in ('r','p','v','m') and c.relname <> 'treehammock_schema_history'
    union all
    select 'constraint:' || c.relname || ':' || x.conname, pg_get_constraintdef(x.oid)
      from pg_constraint x join pg_class c on c.oid=x.conrelid
     where c.relnamespace=(select oid from namespace) and c.relname <> 'treehammock_schema_history'
    union all
    select 'index:' || c.relname, pg_get_indexdef(c.oid)
      from pg_class c join pg_index i on i.indexrelid=c.oid join pg_class t on t.oid=i.indrelid
     where c.relnamespace=(select oid from namespace) and t.relname <> 'treehammock_schema_history'
    union all
    -- Routine bodies and security/privilege attributes are exact structured data.
    -- Only complete selected-schema identifiers in the ordered search_path are normalized.
    select 'function:' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')',
           jsonb_build_object('kind',p.prokind,'language',l.lanname,'owner',pg_get_userbyid(p.proowner),
             'arguments',pg_get_function_arguments(p.oid),'result',pg_get_function_result(p.oid),
             'body',p.prosrc,'binary',p.probin,'volatility',p.provolatile,'strict',p.proisstrict,
             'security_definer',p.prosecdef,'leakproof',p.proleakproof,'parallel',p.proparallel,
             'cost',p.procost,'rows',p.prorows,'privileges',p.proacl,
             'settings',coalesce((
               select jsonb_agg(case when split_part(setting,'=',1) = 'search_path' then
                 jsonb_build_array('search_path',(
                   select jsonb_agg(case when btrim(path.parts[1]) in (@schema, '"' || @schema || '"')
                     then '@schema' else btrim(path.parts[1]) end order by path.ordinal)
                   from regexp_matches(substring(setting from 13),
                     '\s*("(?:[^"]|"")*"|[^,"]+)\s*(?:,|$)', 'g')
                     with ordinality as path(parts,ordinal)))
                 else jsonb_build_array(split_part(setting,'=',1),substring(setting from position('=' in setting)+1))
                 end order by configured.ordinal)
               from unnest(p.proconfig) with ordinality as configured(setting,ordinal)
             ),'[]'::jsonb))::text
      from pg_proc p join pg_language l on l.oid=p.prolang
     where p.pronamespace=(select oid from namespace) and p.prokind in ('f','p')
       and not exists(select 1 from pg_depend d where d.classid='pg_proc'::regclass and d.objid=p.oid and d.deptype='e')
    union all
    select 'trigger:' || c.relname || ':' || t.tgname, pg_get_triggerdef(t.oid)
      from pg_trigger t join pg_class c on c.oid=t.tgrelid
     where c.relnamespace=(select oid from namespace) and not t.tgisinternal and c.relname <> 'treehammock_schema_history'
    union all
    select 'sequence:' || sequencename, json_build_array(data_type,start_value,min_value,max_value,increment_by,cycle,cache_size)::text
      from pg_sequences where schemaname=@schema and sequencename not like 'treehammock_schema_history%'
)
select coalesce(jsonb_object_agg(key, case when key like 'function:%' then value else replace(value, quote_ident(@schema) || '.', '@schema.') end order by key)::text, '{}') from objects;
