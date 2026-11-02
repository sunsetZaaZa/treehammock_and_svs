-- One key: immutable request binding + unique owner and lease generation.
local ttl = tonumber(ARGV[5])
if not ttl or ttl < 1 or ttl > 900000 or ttl % 1 ~= 0 then
    return redis.error_reply('invalid replay lease')
end
if redis.call('EXISTS', KEYS[1]) == 1 then
    if redis.call('HGET', KEYS[1], 'request') ~= ARGV[3]
        or redis.call('HGET', KEYS[1], 'operation') ~= ARGV[4] then return -1 end
    return redis.call('HGET', KEYS[1], 'state') == 'completed' and 2 or 0
end
redis.call('HSET', KEYS[1], 'state', 'pending', 'owner', ARGV[1],
    'generation', ARGV[2], 'request', ARGV[3], 'operation', ARGV[4])
redis.call('PEXPIRE', KEYS[1], ttl)
return 1
