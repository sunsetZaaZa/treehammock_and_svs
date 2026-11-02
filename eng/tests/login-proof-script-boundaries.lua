-- Executes the shipped script with a local Redis command/JSON shim.
-- This supplements, and does not qualify, actual Redis/Dragonfly execution.
local root=assert(arg[1])
local run=assert(loadfile(root..'/Rigging/Cache/pending-proof-projection.lua'))
local value,ttl,writes=nil,nil,0
local payloads={one={progressVersion=1},two={progressVersion=2},three={progressVersion=3},old={},number=42,
    string={progressVersion='3'},fraction={progressVersion=2.5},huge={progressVersion=9007199254740992}}
cjson={decode=function(text) return assert(payloads[text],'Malformed JSON') end}
KEYS={'owned'}
redis={call=function(command,key,...)
    local a={...}
    if command=='GET' then return value or false end
    if command=='PSETEX' then writes=writes+1;ttl=a[1];value=a[2];return 'OK' end
    error('Unexpected command '..command)
end}
ARGV={'two',30000};assert(run()==1 and value=='two' and ttl==30000)
ARGV={'one',86400000};assert(run()==0 and value=='two' and ttl==30000 and writes==1)
ARGV={'two',86400000};assert(run()==0 and ttl==30000 and writes==1)
ARGV={'three',20000};assert(run()==1 and value=='three' and ttl==20000 and writes==2)
for _,restored in ipairs({'old','number','string','fraction','huge','malformed'}) do
    value=restored;ARGV={'three',12000};assert(run()==1 and value=='three' and ttl==12000)
end
print('Passed: 10 projection boundary scenarios; stale/equal TTL, newer state, malformed or invalid lineage repair')
