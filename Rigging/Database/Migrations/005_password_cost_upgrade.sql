-- Cost-only upgrade preserves credential/session epochs. Reset changes either
-- stamp or old hash, so a delayed verified old password cannot overwrite it.
create or replace function upgrade_account_password_hash(
    p_account uuid, p_stamp uuid, p_old_hash bytea, p_new_hash bytea)
returns boolean
language plpgsql
as $$
begin
    perform cor02_lock_account_authority(p_account, 'account');
    if p_new_hash is null or octet_length(p_new_hash) <> 128 then
        raise exception 'Invalid password hash storage length';
    end if;
    update accounts set hashed_password = p_new_hash
    where account_id = p_account and security_stamp = p_stamp and hashed_password = p_old_hash;
    return found;
end;
$$;
