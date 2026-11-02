-- Local Lua boundary checks. This deterministic command shim is NOT Redis/Dragonfly qualification.
local root = assert(arg[1])
local increment = assert(loadfile(root .. '/Rigging/Abuse/Scripts/increment-v1.lua'))
local lookup = assert(loadfile(root .. '/Rigging/Abuse/Scripts/cooldown-v1.lua'))
local values, ttls, writes
local function reset()
    values, ttls, writes = {}, {}, 0
    KEYS = {'counter', 'cooldown'}
    ARGV = {'5', '1000', '0', 'active'}
end
redis = {
    error_reply = function(message) return {err=message} end,
    call = function(command, key, value, mode, duration)
        if command == 'GET' then return values[key] or false end
        if command == 'PTTL' then return values[key] and (ttls[key] or -1) or -2 end
        writes = writes + 1
        if command == 'PEXPIRE' then ttls[key] = tonumber(value); return 1 end
        if command == 'SET' then
            if mode == 'KEEPTTL' then
                assert(values[key] and ttls[key] and ttls[key] >= 0)
                values[key] = tostring(value)
            else
                assert(mode == 'PX' and duration >= 1 and duration <= 86400000)
                values[key], ttls[key] = tostring(value), duration
            end
            return 'OK'
        end
        error('Unexpected command: ' .. command)
    end
}
reset()
values.counter, ttls.counter = '4', 0
local result = increment()
assert(result[1] == 1 and result[2] == 5 and ttls.counter == 0)
result = increment()
assert(result[1] == 0 and result[2] == 6 and result[3] == 1 and ttls.counter == 0)
assert(values.cooldown == nil)
print('Passed: zero remaining TTL preserves boundary and zero cooldown does not create a key')
reset()
values.counter, ttls.counter, values.cooldown, ttls.cooldown = '9', -1, 'legacy', -1
result = increment()
assert(result[1] == 0 and result[2] == 9 and result[4] == 1)
assert(ttls.counter == 1000 and ttls.cooldown == 1000)
assert(values.counter == '9')
print('Passed: active immortal cooldown repairs both TTLs without incrementing')
reset()
ARGV[2] = '0'
result = increment()
assert(result.err and writes == 0)
reset()
values.counter = 'not-a-number'
result = increment()
assert(result.err and writes == 0)
print('Passed: invalid arguments and invalid counters fail before mutation')
reset()
KEYS, ARGV = {'cooldown'}, {'1'}
values.cooldown, ttls.cooldown = 'legacy', -1
assert(lookup() == 1 and ttls.cooldown == 1)
values.cooldown, ttls.cooldown = 'active', 0
assert(lookup() == 1 and ttls.cooldown == 0)
values.cooldown = nil
assert(lookup() == 0)
print('Passed: lookup repairs absent expiry and handles exact zero/absent boundaries')
