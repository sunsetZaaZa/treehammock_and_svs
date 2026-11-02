-- THS-04. All keys are declared; no flags permitting undeclared keys.
-- The exact shared codec is authoritative. Lua uses only envelope/string checks;
-- authority revisions NEVER pass through tonumber/cjson numeric conversion.
-- ARGV: exists, prior bytes, next bytes, env, epoch, policy, account, nonce,
-- revision, state, TTL milliseconds, prior nonce, prior revision, credential hash.
local function revision(s)
  return type(s)=='string' and (s=='0' or string.match(s,'^[1-9][0-9]*$'))
    and (#s<19 or (#s==19 and s<='9223372036854775807'))
end
local function less(a,b) return #a<#b or (#a==#b and a<b) end
local function hex(s,n,pattern) return type(s)=='string' and #s==n and not string.find(s,pattern) end
local function envelope(raw)
  if #raw==0 or #raw>65536 then return nil end
  local ok,r=pcall(cjson.decode,raw)
  if not ok or type(r)~='table' or r.schema~=1 or r.environment~=ARGV[4] or r.epoch~=ARGV[5]
    or r.policy~=ARGV[6] or r.accountId~=ARGV[7] or not revision(r.revision)
    or not hex(r.nonce,64,'[^0-9A-F]') or (r.state~='Ready' and r.state~='Blocked') then return nil end
  return r
end
if (#KEYS~=1 and #KEYS~=2) or #ARGV~=14 or (ARGV[1]~='0' and ARGV[1]~='1') then return -1 end
if not hex(ARGV[5],32,'[^0-9a-f]') or not hex(ARGV[7],32,'[^0-9a-f]') then return -1 end
local prefix='svs:authority:v1:'..ARGV[4]..':'..ARGV[5]..':'
if KEYS[1]~=prefix..'account:'..ARGV[7] then return -1 end
local next=envelope(ARGV[3])
if not next or next.nonce~=ARGV[8] or next.revision~=ARGV[9] or next.state~=ARGV[10] then return -1 end
local ttl=tonumber(ARGV[11]) -- TTL only, never a revision/generation/version.
if next.state=='Ready' then
  if #KEYS~=2 or not string.match(ARGV[11],'^[1-9][0-9]*$') or not ttl or ttl%1~=0 or ttl<1 or ttl>300000 or next.revision=='0'
    or not hex(ARGV[14],64,'[^0-9A-F]') or next.credentialHash~=ARGV[14]
    or KEYS[2]~=prefix..'credential:'..ARGV[14] then return -1 end
  -- Preflight wrong-type index before writing anything. Runtime/OOM errors still
  -- do not provide rollback; callers treat every command error as unknown.
  local kind=redis.call('TYPE',KEYS[2]).ok
  if kind~='none' and kind~='string' then return -1 end
else
  if #KEYS~=1 or ttl~=0 or ARGV[14]~='' then return -1 end
  local count=0;for _ in pairs(next) do count=count+1 end
  if count~=8 then return -1 end
end
local prior=redis.call('GET',KEYS[1])
if ARGV[1]=='0' then
  if next.state~='Blocked' or ARGV[2]~='' or ARGV[12]~='' or ARGV[13]~='' then return -1 end
  if prior then return 0 end
else
  if not prior or prior~=ARGV[2] then return 0 end
  local old=envelope(prior)
  if not old or old.nonce~=ARGV[12] or old.revision~=ARGV[13] or old.nonce==next.nonce
    or less(next.revision,old.revision) then return -1 end
  if old.state=='Ready' and next.state=='Ready' and old.revision~=next.revision then return -1 end
end
if next.state=='Blocked' then
  redis.call('SET',KEYS[1],ARGV[3]) -- Persistent fence; TTL must not forget its nonce.
else
  redis.call('SET',KEYS[1],ARGV[3],'PX',ARGV[11])
  redis.call('SET',KEYS[2],ARGV[7],'PX',ARGV[11]) -- Routing only; record binds full hash.
end
return 1
