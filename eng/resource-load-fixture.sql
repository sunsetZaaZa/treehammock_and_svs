-- Disposable owned schema only; deliberately creates deep histories.
\set ON_ERROR_STOP on
begin;
do $$ begin
    if current_schema() not like 'cor22_%' or current_setting('treehammock.qualification',true) is distinct from 'owned-cor22' then
        raise exception 'Owned COR22 qualification schema and explicit marker required';
    end if;
end $$;
create table cor22_load_accounts(account_id uuid primary key);
insert into cor22_load_accounts select gen_random_uuid() from generate_series(1,50);
insert into accounts(account_id,email_address,verify_status,created_on)
    select account_id,account_id::text||'@example.test',1,clock_timestamp()-interval '120 days' from cor22_load_accounts;
insert into sessions(access_token_hash,account_id,account_security_stamp,created_on,access_expiration,session_expiration)
    select a.account_id::text||':'||i,a.account_id,a.security_stamp,clock_timestamp()-interval '30 days',
        clock_timestamp()-interval '20 days',clock_timestamp()-interval '10 days'
    from accounts a join cor22_load_accounts l using(account_id) cross join generate_series(1,200) i;
insert into sessions(access_token_hash,account_id,account_security_stamp,access_expiration,session_expiration)
    select 'live:'||a.account_id,a.account_id,a.security_stamp,clock_timestamp()+interval '1 hour',clock_timestamp()+interval '1 day'
    from accounts a join cor22_load_accounts l using(account_id);
insert into two_factor_authentications(account_id,two_factor_index,method,verified,created_on,expiration,email_address)
    select a.account_id,i::smallint,1,false,clock_timestamp()-interval '30 days',clock_timestamp()-interval '10 days','expired@example.test'
    from accounts a join cor22_load_accounts l using(account_id) cross join generate_series(1,200) i;
insert into two_factor_authentications(account_id,two_factor_index,method,verified,phone_number,phone_country_code)
    select a.account_id,201,2,true,'555'||lpad(row_number() over(order by a.account_id)::text,7,'0'),'+1'
    from accounts a join cor22_load_accounts l using(account_id);
insert into password_reset_events(account_id,event_type,code,created_at)
    select a.account_id,'fixture','FIXTURE',clock_timestamp()-interval '100 days'
    from accounts a join cor22_load_accounts l using(account_id) cross join generate_series(1,200) i;
commit;
analyze;
select 'COR22 disposable fixture seeded' as outcome,count(*) as accounts from cor22_load_accounts;
