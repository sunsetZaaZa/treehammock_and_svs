local ttl = tonumber(ARGV[5])
if not ttl or ttl < 1 or ttl > 900000 or ttl % 1 ~= 0 or string.len(ARGV[6]) > 16384 then
    return redis.error_reply('invalid replay completion')
end
if redis.call('HGET', KEYS[1], 'state') ~= 'pending'
    or redis.call('HGET', KEYS[1], 'owner') ~= ARGV[1]
    or redis.call('HGET', KEYS[1], 'generation') ~= ARGV[2]
    or redis.call('HGET', KEYS[1], 'request') ~= ARGV[3]
    or redis.call('HGET', KEYS[1], 'operation') ~= ARGV[4] then return 0 end
redis.call('HSET', KEYS[1], 'state', 'completed', 'result', ARGV[6])
redis.call('PEXPIRE', KEYS[1], ttl)
return 1
