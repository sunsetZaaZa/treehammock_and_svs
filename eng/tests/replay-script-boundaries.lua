-- Deterministic local command shim; NOT Redis/Dragonfly runtime qualification.
local root = assert(arg[1])
local reserve = assert(loadfile(root .. '/Rigging/Replay/Scripts/reserve-v2.lua'))
local complete = assert(loadfile(root .. '/Rigging/Replay/Scripts/complete-v2.lua'))
local renew = assert(loadfile(root .. '/Rigging/Replay/Scripts/renew-v2.lua'))
local hash, ttl, writes = nil, nil, 0
KEYS = {'owned'}
redis = {
    error_reply = function(message) return {err=message} end,
    call = function(command, key, ...)
        local values = {...}
        if command == 'EXISTS' then return hash and 1 or 0 end
        if command == 'HGET' then return hash and hash[values[1]] or false end
        writes = writes + 1
        if command == 'HSET' then
            hash = hash or {}
            for i = 1, #values, 2 do hash[values[i]] = values[i+1] end
            return 1
        end
        if command == 'PEXPIRE' then ttl = values[1]; return 1 end
        error('Unexpected command: ' .. command)
    end
}
ARGV = {'a', 'generation-a', 'request', 'operation', '40'}
assert(reserve() == 1 and ttl == 40)
hash, ttl = nil, nil -- Observed lease expiry, followed by a new owner.
ARGV = {'b', 'generation-b', 'request', 'operation', '1000'}
assert(reserve() == 1)
ARGV = {'a', 'generation-a', 'request', 'operation', '1000', 'late-a'}
assert(complete() == 0 and renew() == 0 and hash.owner == 'b')
print('Passed: late completion and renewal cannot overwrite replacement owner')
ARGV = {'b', 'wrong-generation', 'request', 'operation', '1000', 'wrong'}
assert(complete() == 0 and renew() == 0)
ARGV = {'b', 'generation-b', 'changed-request', 'operation', '1000'}
assert(reserve() == -1)
ARGV = {'b', 'generation-b', 'request', 'changed-operation', '1000'}
assert(reserve() == -1)
print('Passed: generation, content and operation fences reject mismatches')
ARGV = {'b', 'generation-b', 'request', 'operation', '1000', 'original'}
assert(renew() == 1 and complete() == 1)
ARGV[6] = 'overwrite'
assert(complete() == 0 and hash.result == 'original' and reserve() == 2)
print('Passed: original completed result is immutable')
local before = writes
ARGV[5] = '0'
assert(reserve().err and complete().err and renew().err and writes == before)
ARGV[5], ARGV[6] = '1000', string.rep('x', 16385)
assert(complete().err and writes == before)
print('Passed: invalid TTL and oversized envelope fail before writes')
