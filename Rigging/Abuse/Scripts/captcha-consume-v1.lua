if redis.call('GET',KEYS[1]) ~= 'issued' then return 0 end
if redis.call('PTTL',KEYS[1]) <= 0 then redis.call('DEL',KEYS[1]) return 0 end
redis.call('SET',KEYS[1],'consumed','KEEPTTL')
return 1
