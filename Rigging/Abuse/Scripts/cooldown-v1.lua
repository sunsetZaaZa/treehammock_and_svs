-- Read/repair one cooldown. A legacy immortal value cannot become permanent denial.
local repair = tonumber(ARGV[1])
if not repair or repair < 1 or repair > 86400000 or repair % 1 ~= 0 then
    return redis.error_reply('invalid cooldown repair interval')
end
local value = redis.call('GET', KEYS[1])
if not value then return 0 end
local ttl = redis.call('PTTL', KEYS[1])
if ttl == -1 then
    redis.call('PEXPIRE', KEYS[1], repair)
    ttl = repair
end
return ttl >= 0 and math.max(1, ttl) or 0
