"""Live network/auth driver. Only bounded, secret-free case results leave stdout."""
import base64,email,email.policy,html,http.client,json,re,secrets,socket,ssl,sys,time,uuid
from pathlib import Path
from urllib.parse import quote,urlparse,parse_qs
from common import Refused,require,Resp
FIXTURE=Path('/run/fixture')
def request(host,port,path,body=None,headers=None,*,certificate=True):
    context=ssl.create_default_context(cafile=str(FIXTURE/'services-ca.pem'));context.minimum_version=ssl.TLSVersion.TLSv1_2
    if certificate:context.load_cert_chain(FIXTURE/'controller.pem',FIXTURE/'controller.key')
    connection=http.client.HTTPSConnection(host,port,timeout=6,context=context)
    try:
        data=None if body is None else json.dumps(body,separators=(',',':')).encode();h=dict(headers or {})
        if data is not None:h['Content-Type']='application/json'
        connection.request('GET' if body is None else 'POST',path,data,h);response=connection.getresponse();raw=response.read(65537);require(len(raw)<=65536,'HTTP_REPLY_BOUND')
        return response.status,raw
    finally:connection.close()
def operation_headers():return {'Security-Operation-Key':str(int(time.time()))+'.'+uuid.uuid4().hex,'Security-Operation-Recovery-Key':base64.b64encode(secrets.token_bytes(32)).decode(),'Idempotency-Key':secrets.token_hex(24)}
def auth(path,body=None,token=None,status=200,extra=None):
    headers=operation_headers()
    if token:headers['Authorization']='Bearer '+token
    headers.update(extra or {});code,raw=request('writer',5001,path,body,headers)
    require(code==status,'AUTH_OWNER_STATUS_REFUSED');value=json.loads(raw);require(value.get('success') is True,'AUTH_OWNER_OUTCOME_REFUSED');return value['data']
def delivery(recipient,kind,seen):
    deadline=time.monotonic()+30
    while time.monotonic()<deadline:
        for p in sorted(Path('/capture').glob('*.json'),reverse=True):
            if p.name in seen:continue
            item=json.loads(p.read_text())
            if item['recipient']!=recipient:continue
            message=email.message_from_bytes(base64.b64decode(item['message']),policy=email.policy.default)
            bodies=[part.get_content() for part in message.walk() if part.get_content_type() in ['text/html','text/plain']]
            text=html.unescape('\n'.join(str(x) for x in bodies))
            if kind=='verification':
                links=re.findall(r'https://writer:5001/account/verifyaccount\?[^\s"<>]+',text)
                if links:
                    parsed=urlparse(links[0]);require(set(parse_qs(parsed.query))=={'payload'},'VERIFICATION_LINK_REFUSED');seen.add(p.name);return parsed.path+'?'+parsed.query
            else:
                # The actual HTML template encloses the generated factor code in
                # a numeric paragraph. Do not guess/reuse an earlier delivery.
                codes=re.findall(r'>\s*([0-9]{6,8})\s*<',text)
                if codes:seen.add(p.name);return codes[-1]
        time.sleep(.1)
    raise Refused('REAL_DELIVERY_NOT_OBSERVED')
def caller(number,replica,credential,expected):
    code,raw=request('caller-'+str(number),9443,'/validate',dict(credential=credential,action='backup.read',replica=replica));require(code==expected,'CALLER_DECISION_REFUSED');value=json.loads(raw);require(value.get('caller')=='caller-'+str(number) and value.get('replica')==replica,'CALLER_IDENTITY_REFUSED');return value['decision']
def matrix(token,status):
    for c in [1,2]:
        for r in [0,1]:caller(c,r,token,status)
def flows():
    recipient='fixture-'+secrets.token_hex(6)+'@svs15.test';password=secrets.token_hex(24)+'aA!9';seen=set()
    auth('/account/setupaccount',dict(emailAddress=recipient,password=password,country='USA'),status=202)
    link=delivery(recipient,'verification',seen)
    deadline=time.monotonic()+30
    while True:
        code,body=request('writer',5001,link);require(code==200,'VERIFY_OWNER_STATUS_REFUSED')
        if body==b'<p>Your verification delivery is pending. Try again shortly.</p>':
            require(time.monotonic()<deadline,'VERIFY_OWNER_TIMEOUT');time.sleep(.1);continue
        require(b'Your account has been verified' in body or b'Account verified' in body,'VERIFY_SUCCESS_PAGE_REFUSED');break
    login=auth('/account/requestaccess',dict(emailAddress=recipient,password=password));token=login['accessToken'];require(bool(token),'LOGIN_CREDENTIAL_MISSING');matrix(token,200)
    first=login['session'];time.sleep(1.1)
    renewed=auth('/account/refresh',{k:first[k] for k in ['protocolVersion','sessionId','generation','refreshToken']});require(renewed['session']['generation']>first['generation'],'REFRESH_OWNER_DID_NOT_ROTATE');matrix(token,401);token=renewed['accessToken'];matrix(token,200)
    target='enroll:'+json.dumps([1,recipient,None,True,None,None],separators=(',',':'))
    grant=auth('/account/reauthenticate',dict(password=password,purpose=3,target=target),token)['sensitiveActionToken']
    setup=auth('/account/setuptwofactormethod',dict(method=1,contact=recipient,countryCode=None,required=True),token,status=202,extra={'Sensitive-Action-Token':grant})
    factor=delivery(recipient,'code',seen)
    verified=auth('/account/verifytwofactormethod',dict(method=1,codeKey=factor,enrollmentId=setup['enrollmentId'],setupVersion=setup['setupVersion']),token);require(verified.get('result')=='SUCCESS','FACTOR_ENROLLMENT_REFUSED')
    pending=auth('/account/requestaccess',dict(emailAddress=recipient,password=password));pre=pending['twoFactorAccessToken'];matrix(pre,401)
    auth('/account/twofactor/select',dict(configuration='EMAIL',twoFactorAccessToken=pre))
    factor=delivery(recipient,'code',seen)
    complete=auth('/account/twofactorauth',dict(method=1,codeKey=factor),extra={'AccessToken':pre});require(complete.get('result')=='SUCCESS','FACTOR_LOGIN_REFUSED');token=complete['accessToken'];matrix(token,200)
    # The same SDK path handles malformed credentials with no positive admission.
    matrix('fixture-invalid-credential',401)
    for i in [1,2]:
        try:request('caller-'+str(i),9443,'/health',certificate=False)
        except (ssl.SSLError,OSError,http.client.HTTPException):continue
        raise Refused('CALLER_ACCEPTED_MISSING_DRIVER_CERT')
    from common import save
    save(Path('/session/current.json'),{'credential':token})
    return ['account-registration-and-real-SMTP-verification','two-callers-by-two-SVS-authentic-login','refresh-rotates-and-denies-old-credential','required-email-twofactor-owner-flow','preauth-and-malformed-credential-denied','caller-driver-mtls-required']
def outage():
    # The orchestrator pauses only this owned YSQL container after all four paths
    # are warm. No SQL/control state is used to authorize this read-only probe.
    token=json.loads(Path('/session/current.json').read_text())['credential'];matrix(token,200)
    return ['four-warm-signed-cache-paths-during-owned-YSQL-pause']
def cache_setup(phase):
    v=json.loads((FIXTURE/'private.json').read_text());info={};cp=v['cachePasswords'][phase];host='172.29.90.'+('31' if phase=='old' else '30');tls='cache-'+phase
    client=Resp(host,'fixture-admin',cp['admin'],FIXTURE/'cache-ca.pem',tls)
    try:
        for line in client.command('INFO','server').splitlines():
            if ':' in line:
                k,value=line.split(':',1);info[k]=value
        require(info.get('dragonfly_version')==v['images']['dragonflyVersion'],'CACHE_ENGINE_VERSION_MISMATCH')
        sys.path.insert(0,'/peer/eng/session-validation');import importlib.util
        spec=importlib.util.spec_from_file_location('acl','/peer/eng/session-validation/render-ths10-cache-policy.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        users={k:'fixture-'+phase+'-'+k for k in ['writer','validator','refiller','active','pending','abuse']}
        plan=module.render(dict(environment='svs15',epoch=v['epoch'],**users))
        for row in plan['users']:client.command(*row['arguments'],'>'+cp[row['role']],'on')
        client.command('ACL','SAVE')
        return {k:info[k] for k in ['run_id','dragonfly_version']}
    finally:client.close()
def ready():
    config=json.loads((FIXTURE/'controller.json').read_text());end=time.monotonic()+90
    # Status queries are read-only. Do not retry isolate/prepare/activate commands.
    while time.monotonic()<end:
        try:
            for peer in config['peers']:
                uri=urlparse(peer['uri']);nonce=secrets.token_hex(32).upper()
                status,raw=request(uri.hostname,uri.port,'/internal/v2/authority-fleet',dict(action='status',nonce=nonce,bootId=str(uuid.UUID(int=0)),generation=0,barrier=str(uuid.UUID(int=0)),inventoryHash='',protocol='authority-fleet.v2'))
                require(status==200,'FLEET_STATUS_REFUSED');value=json.loads(raw);require(value['instance']==peer['id'] and value['kind']==peer['kind'] and value['nonce']==nonce and value['protocol']=='authority-fleet.v2','FLEET_STATUS_IDENTITY_REFUSED')
            return dict(status='Ready',peers=len(config['peers']))
        except (Refused,OSError,http.client.HTTPException):time.sleep(.5)
    raise Refused('ALL_PEER_STARTUP_TIMEOUT')
def main():
    require(len(sys.argv)==2 and sys.argv[1] in ['flows','cache-old','cache-new','ready','outage'],'NATIVE_DRIVER_USAGE')
    value=ready() if sys.argv[1]=='ready' else outage() if sys.argv[1]=='outage' else flows() if sys.argv[1]=='flows' else cache_setup(sys.argv[1][6:])
    print(json.dumps(dict(status='Passed',cases=value) if isinstance(value,list) else value))
if __name__=='__main__':
    try:main()
    except Exception as error:print(str(error) if isinstance(error,Refused) else 'NATIVE_DRIVER_FAILED',file=sys.stderr);sys.exit(1)
