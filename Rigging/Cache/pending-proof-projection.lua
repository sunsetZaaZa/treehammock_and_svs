local incoming = cjson.decode(ARGV[1])
local previous = redis.call('GET',KEYS[1])
if previous then
    local ok, current = pcall(cjson.decode, previous)
    if ok and type(current) == 'table' and type(current.progressVersion) == 'number'
        and current.progressVersion >= incoming.progressVersion and current.progressVersion <= 9007199254740991
        and current.progressVersion == math.floor(current.progressVersion) then return 0 end
end
redis.call('PSETEX',KEYS[1],ARGV[2],ARGV[1])
return 1
