-- Finish only a current, unexpired permit. Duplicate/stale completions cannot mutate health.
local key=KEYS[1]
local clock=redis.call('TIME')
local now=clock[1]*1000+math.floor(clock[2]/1000)
local gen, slot, permit, evidence, replacement = ARGV[1],tonumber(ARGV[2]),ARGV[3],tonumber(ARGV[4]),ARGV[5]
local threshold,window,opened,lease,slots=tonumber(ARGV[6]),tonumber(ARGV[7]),tonumber(ARGV[8]),tonumber(ARGV[9]),tonumber(ARGV[10])
if redis.call('HGET',key,'generation') ~= gen then return 0 end
local field=slot==0 and 'probe' or 'permit:'..slot
local deadline=slot==0 and 'probe_until' or 'until:'..slot
if redis.call('HGET',key,field) ~= permit or tonumber(redis.call('HGET',key,deadline) or '0') <= now then return 0 end
redis.call('HDEL',key,field,deadline)
local function rotate(openUntil)
    redis.call('HSET',key,'generation',replacement,'open',openUntil)
    for i=1,slots do redis.call('HDEL',key,'permit:'..i,'until:'..i) end
    redis.call('HDEL',key,'probe','probe_until')
end
if slot==0 then
    if evidence==1 then
        rotate(0); redis.call('HSET',key,'count',0,'window',now+window)
    else rotate(now+opened) end
elseif evidence==2 then
    if tonumber(redis.call('HGET',key,'window') or '0') <= now then
        redis.call('HSET',key,'count',0,'window',now+window)
    end
    local count=redis.call('HINCRBY',key,'count',1)
    if count>=threshold then rotate(now+opened) end
end
redis.call('PEXPIRE',key,window+opened+lease)
return 1
