-- One bounded route hash; server clock, explicit permit/epoch fencing, no user-budget keys.
local key = KEYS[1]
local clock = redis.call('TIME')
local now = clock[1]*1000 + math.floor(clock[2]/1000)
local window, opened, lease, slots = tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3]), tonumber(ARGV[4])
local nonce = ARGV[5]
local ttl = window + opened + lease
local function touch() redis.call('PEXPIRE',key,ttl) end
local gen = redis.call('HGET',key,'generation')
if not gen then
    gen=nonce
    redis.call('HSET',key,'generation',gen,'count',0,'window',now+window,'open',0)
end
local untilOpen = tonumber(redis.call('HGET',key,'open') or '0')
if untilOpen > now then touch(); return {0,gen,0,'',untilOpen-now} end
if untilOpen > 0 then
    local probe=redis.call('HGET',key,'probe')
    local untilProbe=tonumber(redis.call('HGET',key,'probe_until') or '0')
    if probe and untilProbe > now then touch(); return {0,gen,0,'',untilProbe-now} end
    if probe then
        redis.call('HDEL',key,'probe','probe_until')
        redis.call('HSET',key,'open',now+opened)
        touch(); return {0,gen,0,'',opened}
    end
    redis.call('HSET',key,'probe',nonce,'probe_until',now+lease)
    touch(); return {1,gen,0,nonce,0}
end
for slot=1,slots do
    local field='permit:'..slot
    local deadline='until:'..slot
    if tonumber(redis.call('HGET',key,deadline) or '0') <= now then
        redis.call('HSET',key,field,nonce,deadline,now+lease)
        touch(); return {1,gen,slot,nonce,0}
    end
end
touch(); return {0,gen,0,'',lease}
