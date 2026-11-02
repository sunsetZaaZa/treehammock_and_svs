-- Deterministic Lua command shim. Not Redis/Dragonfly/concurrency qualification.
local root=assert(arg[1])
local acquire=assert(loadfile(root..'/Rigging/Abuse/Scripts/provider-health-acquire-v1.lua'))
local complete=assert(loadfile(root..'/Rigging/Abuse/Scripts/provider-health-complete-v1.lua'))
local hashes,ttls,now,serial={}, {},100000,0
redis={call=function(command,key,...)
 local a={...}
 if command=='TIME' then return {math.floor(now/1000), (now%1000)*1000} end
 hashes[key]=hashes[key] or {}
 local h=hashes[key]
 if command=='HGET' then return h[a[1]] or false end
 if command=='HSET' then for i=1,#a,2 do h[a[i]]=tostring(a[i+1]) end return 1 end
 if command=='HDEL' then for _,f in ipairs(a) do h[f]=nil end return 1 end
 if command=='HINCRBY' then h[a[1]]=tostring(tonumber(h[a[1]] or '0')+a[2]);return tonumber(h[a[1]]) end
 if command=='PEXPIRE' then assert(a[1]>0 and a[1]<=4620000);ttls[key]=a[1];return 1 end
 error('Unexpected '..command)
end}
local function nonce() serial=serial+1;return 'id'..serial end
local function get(key)
 KEYS={key or 'route'};ARGV={10000,1000,45000,4,nonce()};local a=acquire();a.key=KEYS[1];return a
end
local function finish(p,e)
 KEYS={p.key};ARGV={p[2],p[3],p[4],e,nonce(),2,10000,1000,45000,4};return complete()
end
local function reset() hashes={};ttls={};now=100000 end
reset()
for i=1,30 do assert(finish(get(),0)==1) end
assert(hashes.route.count=='0' and get()[1]==1)
print('Passed neutral recipient/config/unknown evidence never increments health')
reset();local first=get();local other=get();assert(finish(first,2)==1);assert(finish(first,2)==0);assert(hashes.route.count=='1')
assert(finish(other,2)==1 and get()[1]==0);assert(finish(other,2)==0)
assert(get('healthy-provider')[1]==1)
print('Passed exact threshold, duplicate fence and other-route isolation')
now=now+1001;local probe=get();assert(probe[1]==1 and probe[3]==0);assert(get()[1]==0)
assert(finish(probe,1)==1);assert(get()[1]==1 and hashes.route.count=='0')
print('Passed one half-open probe and accepted recovery')
assert(finish(other,1)==0)
print('Passed stale success cannot close a newer epoch')
reset();local p=get();finish(p,2);p=get();finish(p,2);now=now+1001;p=get();assert(finish(p,0)==1 and get()[1]==0)
print('Passed neutral probe does not prove healthy recovery')
now=now+1001;p=get();assert(finish(p,2)==1 and get()[1]==0)
print('Passed outage probe reopens circuit')
now=now+1001;p=get();now=now+45001;assert(get()[1]==0);assert(finish(p,1)==0);now=now+1001;assert(get()[1]==1)
print('Passed abandoned probe lease reopens with bounded wait and late result fence')
reset();local p1=get();local p2=get();get();get();assert(get()[1]==0);finish(p1,0);assert(get()[1]==1)
print('Passed bounded live permit capacity and neutral release')
now=now+45001;assert(finish(p2,2)==0 and get()[1]==1)
print('Passed expired closed permits reusable and old completion ignored')
reset();p=get();finish(p,2);now=now+10001;p=get();finish(p,2);assert(hashes.route.count=='1' and get()[1]==1)
print('Passed fixed outage window does not accumulate forever')
assert(ttls.route==56000)
local count=0;for _ in pairs(hashes.route) do count=count+1 end;assert(count<=12)
print('Passed bounded fields and expiring route state; no user-budget deletion')
