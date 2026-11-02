-- Fixed-window admission. Only KEYS[1] (counter) and KEYS[2] (cooldown).
-- Reply: allowed, count, retry milliseconds, reason (0/1 cooldown/2 limit), started.
-- Validate all inputs/key values BEFORE any mutation: Redis script errors do not roll back.
local maximum = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local cooldown = tonumber(ARGV[3])
if not maximum or maximum < 1 or maximum > 1000000 or maximum % 1 ~= 0
    or not window or window < 1 or window > 86400000 or window % 1 ~= 0
    or not cooldown or cooldown < 0 or cooldown > 86400000 or cooldown % 1 ~= 0 then
    return redis.error_reply('invalid abuse counter arguments')
end
local raw = redis.call('GET', KEYS[1])
local count = 0
if raw then count = tonumber(raw) end
if not count or count < 0 or count % 1 ~= 0 then
    return redis.error_reply('invalid abuse counter value')
end
-- GET also checks the cooldown's type before the first write.
local cooling = redis.call('GET', KEYS[2])
local counterTtl = redis.call('PTTL', KEYS[1])
local cooldownTtl = redis.call('PTTL', KEYS[2])
if raw and counterTtl == -1 then
    redis.call('PEXPIRE', KEYS[1], window)
    counterTtl = window
end
if cooling and cooldownTtl == -1 then
    -- Legacy immortal cooldown gets one finite interval, even when new cooldown is zero.
    cooldownTtl = cooldown > 0 and cooldown or window
    redis.call('PEXPIRE', KEYS[2], cooldownTtl)
end
if cooling and cooldownTtl >= 0 then
    return {0, math.min(count, 2147483647), math.max(1, cooldownTtl), 1, 0}
end
count = math.min(count + 1, 2147483647)
-- Preserve the actual absolute expiry, including PTTL zero; rescheduling from a rounded
-- PTTL could slide the boundary under a continuous stream of sub-millisecond calls.
if raw and counterTtl >= 0 then
    redis.call('SET', KEYS[1], string.format('%.0f', count), 'KEEPTTL')
else
    counterTtl = window
    redis.call('SET', KEYS[1], string.format('%.0f', count), 'PX', window)
end
if count <= maximum then
    return {1, count, 0, 0, 0}
end
if cooldown > 0 then
    local created = redis.call('SET', KEYS[2], ARGV[4], 'PX', cooldown, 'NX')
    if created then return {0, count, cooldown, 2, 1} end
    return {0, count, math.max(1, redis.call('PTTL', KEYS[2])), 1, 0}
end
return {0, count, math.max(1, counterTtl), 2, 0}
