#!/usr/bin/env python3
"""Generate public synthetic SVS12 goldens; --check verifies reviewed bytes."""
from pathlib import Path
import json,hashlib,hmac,base64
import argparse
a=argparse.ArgumentParser();a.add_argument('--check',action='store_true');args=a.parse_args()
def write(path,data):
 text=json.dumps(data,indent=2)+'\n'
 if args.check:assert path.read_text()==text,'Fixture drift: '+str(path)
 else:path.write_text(text)
r=Path(__file__).resolve().parents[2];f=r/'tests/Treehammock.SessionValidation.ContractTests/Fixtures/GoldenSessions';f.mkdir(parents=True,exist_ok=True)
cases=[]
def case(id,**kw):cases.append(dict(id=id,expectedCore='Active',expectedCoordinator='Active',expectedToken='Passed',**{})|kw)
case('issued-no-exp');case('ignored-jwt-exp',token='expired-exp');case('ignored-jwt-nbf',token='future-nbf')
for id,token,status in [('preauth-twofactor','preauth','Failed'),('wrong-signing-key','wrong-key','Failed'),('wrong-issuer','wrong-issuer','Failed'),('hs384','hs384','Failed'),('unsigned','unsigned','Failed'),('missing-jti','missing-jti','Malformed'),('empty-jti','empty-jti','Malformed'),('missing-purpose','missing-purpose','Malformed'),('empty-purpose','empty-purpose','Malformed'),('missing-webkey','missing-webkey','Malformed'),('empty-webkey','empty-webkey','Malformed'),('opaque-refresh','opaque-refresh','Failed'),('malformed-jws','malformed','Failed')]:case(id,token=token,expectedToken=status,expectedCore='Unauthenticated',expectedCoordinator='Unauthenticated')
case('forbidden-capability',capabilities=['account.read'],requiredCapability='account.manage',expectedCore='Forbidden',expectedCoordinator='Forbidden')
case('empty-capabilities-eligible',capabilities=[],expectedCore='Forbidden',expectedCoordinator='Forbidden')
case('bad-signature-not-forbidden',capabilities=[],token='wrong-key',expectedToken='Failed',expectedCore='Unauthenticated',expectedCoordinator='Unauthenticated')
for id,state in [('locked-account','Locked'),('unverified-account','Unverified'),('disabled-account','Disabled'),('deleted-account','Deleted')]:case(id,accountState=state,expectedCore='Unauthenticated',expectedCoordinator='Unauthenticated')
case('unknown-account-evidence',accountState='Unknown',expectedCore='Unavailable',expectedCoordinator='Unavailable')
case('unlock-equality',unlockTicks=0);case('unlock-future',unlockTicks=1,accountState='Locked',expectedCore='Unauthenticated',expectedCoordinator='Unauthenticated')
for name in ['access','hard','cutoff']:
 for offset in [-1,0,1]:
  case(name+('-before' if offset==-1 else '-equal' if offset==0 else '-after'),**{name+'Ticks':offset},expectedToken='Expired' if name=='access' and offset<=0 else 'Passed',expectedCore='Unauthenticated' if offset<=0 else 'Active',expectedCoordinator='Unauthenticated' if offset<=0 else 'Active')
for id,mutation in [('stale-family','family'),('stale-generation','generation'),('stale-session-stamp','session-stamp'),('stale-account-stamp','account-stamp'),('second-login-old-credential','rotation'),('revoked-family','revocation'),('logout','logout')]:case(id,authority=mutation,expectedCore='Unauthenticated',expectedCoordinator='Unauthenticated')
for id,version in [('generation-zero',0),('generation-too-large',9007199254740992)]:case(id,generation=version,expectedCore='Unauthenticated',expectedCoordinator='Unavailable')
case('generation-max-exact',generation=9007199254740991)
case('wrong-session-protocol',protocol=1,expectedCore='Unauthenticated',expectedCoordinator='Unavailable')
case('empty-family',emptyFamily=True,expectedCore='Unauthenticated',expectedCoordinator='Unavailable')
case('credential-binding-mismatch',badBinding=True,expectedCoordinator='Unavailable')
case('missing-signing-key',shortKey=True,expectedCoordinator='Unavailable')
case('entitlement-version-zero',entitlementVersion=0,expectedCore='Unavailable',expectedCoordinator='Unavailable')
case('future-projection',evaluatedTicks=1,expectedCore='Unavailable',expectedCoordinator='Unavailable')
for offset in [-1,0,1]:case('term-boundary'+str(offset),boundaryTicks=offset,expectedCore='Unavailable' if offset<=0 else 'Active',expectedCoordinator='Unavailable' if offset<=0 else 'Active')
for offset in [-1,0,1]:case('grant-eligibility'+str(offset),eligibilityTicks=offset,expectedCoordinator='Unavailable' if offset<=0 else 'Active')
case('grant-rights-disabled-tier-two',featureTier=2,expectedCore='Unavailable',expectedCoordinator='Unavailable')
case('unknown-capability',capabilities=['unsupported'],expectedCore='Unavailable',expectedCoordinator='Unavailable')
case('missing-action-policy',requiredCapability='',expectedCore='Unavailable',expectedCoordinator='Unavailable',expectedTreehammock='Active')
corpus={'format':'SVS12Parity.v1','syntheticOnly':True,'nativeQualification':False,'now':'2026-10-20T12:00:00Z','issuer':'test-issuer','testKeyHex':'5D'*64,'cases':cases}
write(f/'session-cases.json',corpus)
def b64(b):return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
base={'iss':'test-issuer','webKey':'svs12-public-fixture','purpose':'active_v2','jti':'11111111111141118111111111111111','iat':1792497600}
tokens={}
for kind in ['issued','preauth','wrong-key','wrong-issuer','hs384','unsigned','missing-jti','empty-jti','missing-purpose','empty-purpose','missing-webkey','empty-webkey','opaque-refresh','malformed','expired-exp','future-nbf']:
 claims=dict(base);alg='HS256';key=bytes([93])*64
 if kind=='preauth':claims['purpose']='preauth_2fa'
 if kind=='wrong-key':key=bytes([64])*64
 if kind=='wrong-issuer':claims['iss']='wrong-issuer'
 if kind=='hs384':alg='HS384'
 if kind=='unsigned':alg='none'
 if kind.startswith('missing-'):claims.pop(kind[8:].replace('webkey','webKey'))
 if kind.startswith('empty-'):claims[kind[6:].replace('webkey','webKey')]=' '
 if kind=='expired-exp':claims['exp']=1
 if kind=='future-nbf':claims['nbf']=4000000000
 header=b64(json.dumps({'alg':alg,'typ':'JWT'},separators=(',',':')).encode());payload=b64(json.dumps(claims,separators=(',',':')).encode());body=header+'.'+payload
 token=body+'.'+(b64(hmac.new(key,body.encode(),hashlib.sha384 if alg=='HS384' else hashlib.sha256).digest()) if alg!='none' else '')
 if kind=='opaque-refresh':token=base64.b64encode(bytes([22])*32).decode()
 if kind=='malformed':token='not.a.valid.jws'
 tokens[kind]=token
write(f/'tokens.json',{'format':'SVS12Tokens.v1','syntheticOnly':True,'origin':'Deterministic portable fixture; validation runner also uses freshly minted exact current TreeHammock issuer output.','tokens':tokens})
print('cases',len(cases))
