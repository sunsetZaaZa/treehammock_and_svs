"""Create ephemeral TLS/configuration; no static private keys or passwords in source."""
import base64,importlib.util,json,os,secrets,shutil,uuid
from pathlib import Path
from common import ROOT,run,save,require
SERVICES=['writer','svs-1','svs-2','caller-1','caller-2','operator','smtp','yugabyte','cache-old','cache-new']
DATA={'yugabyte':'172.29.90.20','cache-new':'172.29.90.30','cache-old':'172.29.90.31'}
def rolemap(phase):
    return {**{k:'fixture_'+phase+'_'+v for k,v in [('App','app'),('Coordinator','coordinator'),('Validator','validator'),('Refiller','refiller'),('Maintenance','maintenance')]},'Owner':'fixture_owner','ValidatorRead':'treehammock_svs_read'}
def cacheusers(phase):return {k:'fixture-'+phase+'-'+k for k in ['writer','validator','refiller','active','pending','abuse']}
def issue(store,name,root,sans,client=False):
    key=store/(name+'.key');csr=store/(name+'.csr');pem=store/(name+'.pem');ext=store/(name+'.ext')
    ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage='+('clientAuth' if client else 'serverAuth')+'\nsubjectAltName='+','.join(sans)+'\n')
    run(['openssl','req','-new','-newkey','rsa:2048','-nodes','-keyout',key,'-out',csr,'-subj','/CN='+name])
    run(['openssl','x509','-req','-in',csr,'-CA',store/(root+'.pem'),'-CAkey',store/(root+'.key'),'-set_serial',str(secrets.randbits(120)+1),'-days','2','-extfile',ext,'-out',pem])
    run(['openssl','pkcs12','-export','-inkey',key,'-in',pem,'-out',store/(name+'.pfx'),'-passout','pass:'])
    from hashlib import sha256
    return sha256(run(['openssl','x509','-in',pem,'-outform','DER'])).hexdigest().upper()
def create(state,peer,lock):
    state=Path(state);state.mkdir(mode=0o700,parents=True,exist_ok=False);store=state/'ca-private';store.mkdir(mode=0o700)
    for ca in ['services-ca','clients-ca','controller-ca','sql-ca','cache-ca']:
        run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN='+ca,'-keyout',store/(ca+'.key'),'-out',store/(ca+'.pem'),'-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign'])
    pins={}
    for service in SERVICES:
        d=state/service;d.mkdir(mode=0o750)
        for ca in ['services-ca','clients-ca','controller-ca','sql-ca','cache-ca']:shutil.copyfile(store/(ca+'.pem'),d/(ca+'.pem'))
        (d/'trust.pem').write_bytes(b''.join((store/(c+'.pem')).read_bytes() for c in ['services-ca','cache-ca','sql-ca']))
    for name,ip in [('writer','172.29.93.11'),('svs-1','172.29.91.21'),('svs-2','172.29.91.22'),('caller-1','172.29.93.41'),('caller-2','172.29.93.42'),('smtp','172.29.94.20')]:
        pins[name]=issue(store,name,'services-ca',['DNS:'+name,'IP:'+ip,'IP:127.0.0.1'])
        for suffix in ['pfx','pem','key']:shutil.copyfile(store/(name+'.'+suffix),state/name/('server.'+suffix))
    for name,ip in [('writer','172.29.92.11'),('svs-1','172.29.92.21'),('svs-2','172.29.92.22')]:
        pins[name+'-fleet']=issue(store,name+'-fleet','services-ca',['DNS:'+name,'IP:'+ip,'IP:127.0.0.1'])
        shutil.copyfile(store/(name+'-fleet.pfx'),state/name/'fleet.pfx')
    for number in [1,2]:
        name='caller-'+str(number);identity='spiffe://svs15.test/service/'+name
        pins[name+'-client']=issue(store,name+'-client','clients-ca',['URI:'+identity],True)
        shutil.copyfile(store/(name+'-client.pfx'),state/name/'client.pfx')
    pins['controller']=issue(store,'controller','controller-ca',['URI:spiffe://svs15.test/controller'],True)
    for suffix in ['pem','key','pfx']:shutil.copyfile(store/('controller.'+suffix),state/'operator'/('controller.'+suffix))
    for name,ip in DATA.items():
        pins[name]=issue(store,name,'sql-ca' if name=='yugabyte' else 'cache-ca',['DNS:'+name,'IP:'+ip,'IP:127.0.0.1'])
        for suffix in ['pem','key']:shutil.copyfile(store/(name+'.'+suffix),state/name/('server.'+suffix))
    # Yugabyte's certificate filename is the advertised private node IP.
    shutil.copyfile(state/'yugabyte/server.pem',state/'yugabyte/node.172.29.90.20.crt');shutil.copyfile(state/'yugabyte/server.key',state/'yugabyte/node.172.29.90.20.key');shutil.copyfile(store/'sql-ca.pem',state/'yugabyte/ca.crt')
    v={'realm':str(uuid.uuid4()),'epoch':str(uuid.uuid4()),'pins':pins,'images':lock,'sqlAdmin':secrets.token_hex(32),'smtp':secrets.token_hex(32),'keys':{k:base64.b64encode(secrets.token_bytes(32)).decode() for k in ['operations','outbox','totp']},'passwords':{p:{k:secrets.token_hex(32) for k in rolemap(p)} for p in ['old','new']},'cachePasswords':{p:{k:secrets.token_hex(32) for k in [*cacheusers(p),'admin']} for p in ['old','new']}}
    save(state/'private.json',v);save(state/'smtp/config.json',{'secret':v['smtp']})
    (state/'smtp/captures').mkdir();(state/'operator/captures').mkdir();(state/'operator/session').mkdir()
    for phase in ['old','new']:
        d=state/('cache-'+phase)
        (d/'acl').write_text('user default off resetpass resetkeys resetchannels -@all\nuser fixture-admin on >'+v['cachePasswords'][phase]['admin']+' ~* &* +@all\n')
        (d/'flags').write_text('--bind='+DATA['cache-'+phase]+'\n--port=6379\n--tls=true\n--tls_cert_file=/run/fixture/server.pem\n--tls_key_file=/run/fixture/server.key\n--aclfile=/run/fixture/acl\n--maxmemory=384mb\n--proactor_threads=2\n--dbnum=16\n')
    save(state/'operator/private.json',v)
    uid=os.getuid() or 1654;gid=os.getgid() or 1654
    # Run all application processes without root, and let Yugabyte read its own TLS.
    for p in state.rglob('*'):
        p.chmod(0o750 if p.is_dir() else 0o640)
        if os.getuid()==0:os.chown(p,uid,gid)
    state.chmod(0o700);(state/'private.json').chmod(0o600);store.chmod(0o700)
    return v
def connection(role,secret,pool=2):
    return f'Host=172.29.90.20;Port=5433;Database=treehammock;Username={role};Password={secret};SSL Mode=VerifyFull;Root Certificate=/run/fixture/sql-ca.pem;Enlist=false;Pooling=true;Maximum Pool Size={pool};Minimum Pool Size=0;Timeout=2;Command Timeout=3;Cancellation Timeout=1000;Search Path=public,pg_catalog,pg_temp'
def database(role,secret):return dict(servers='172.29.90.20',port=5433,database='treehammock',userId=role,password=secret,profile='Production',sessionReadBackend='Yugabyte',sessionReadSchema='public',rootCertificate='/run/fixture/sql-ca.pem',lc_collation='en_US.UTF-8',maximumPoolSize=8,minimumPoolSize=0,commandTimeoutSeconds=5,connectionTimeoutSeconds=2)
def configure(state,peer,phase,info):
    state=Path(state);peer=Path(peer);v=json.loads((state/'private.json').read_text());roles=rolemap(phase);users=cacheusers(phase);passwords=v['passwords'][phase];cp=v['cachePasswords'][phase];pins=v['pins'];ip=DATA['cache-'+phase];tls='cache-'+phase
    require(info['dragonfly_version']==v['images']['dragonflyVersion'],'CACHE_ENGINE_VERSION_MISMATCH');require(len(info['run_id'])==40 and all(x in '0123456789abcdef' for x in info['run_id']),'CACHE_RUN_ID_REQUIRED')
    fleet=lambda name,ip:dict(instanceId=name,realm=v['realm'],checkpointPath='/state/fleet.checkpoint',bindAddress=ip,port=5444,serverCertificatePath='/run/fixture/fleet.pfx',serverCertificatePassword='',controllerRootCertificatePath='/run/fixture/controller-ca.pem',controllerPins=[pins['controller']],drainTimeoutMilliseconds=10000)
    cache=lambda kind:dict(address=ip,port=6379,tlsName=tls,username=users[kind],password=cp[kind],rootCertificatePath='/run/fixture/cache-ca.pem',leafSha256=pins[tls])
    host=json.loads((ROOT/'deploy/session-validation/host.example.json').read_text())
    host.update(serverCertificatePath='/run/fixture/server.pfx',serverRootCertificatePath='/run/fixture/services-ca.pem',clientRootCertificatePath='/run/fixture/clients-ca.pem',serverCertificatePassword='',databaseConnectionString=connection(roles['Validator'],passwords['Validator'],8),roles={k[0].lower()+k[1:]:val for k,val in roles.items()},cache=cache('validator'),issuer='svs15.test',callers=[dict(identity='spiffe://svs15.test/service/caller-'+str(i),actions=['backup.read'],leafSha256=[pins['caller-'+str(i)+'-client']]) for i in [1,2]])
    # Fixture-only mapping to the existing account.read capability.
    host['actionPolicy']={'version':'svs15-actions.v1','requirements':{'backup.read':'account.read'}}
    host['refill'].update(databaseConnectionString=connection(roles['Refiller'],passwords['Refiller']),publisherCache=cache('refiller'),environment='svs15',epoch=v['epoch'],policy='auth.v1',primaryRunId=info['run_id'],dragonflyVersion=info['dragonfly_version'])
    for i in [1,2]:
        name='svs-'+str(i);h=json.loads(json.dumps(host));h.update(bindAddress='172.29.91.'+str(20+i),fleet=fleet(name,'172.29.92.'+str(20+i)));save(state/name/'host.json',h)
    settings=json.loads((peer/'appsettings.json').read_text())
    settings.update(DatabaseSettings=database(roles['App'],passwords['App']),DatabaseRoles=dict(CoordinatorUser=roles['Coordinator'],CoordinatorPassword=passwords['Coordinator'],ValidatorUser=roles['Validator'],RefillerUser=roles['Refiller'],ValidatorReadRole=roles['ValidatorRead'],MaintenanceUser=roles['Maintenance'],OwnerRole=roles['Owner'],CoordinatorPoolSize=2),AuthorityFleet=fleet('writer','172.29.92.11'),AuthorityCacheWriter=dict(Host=ip,Port=6379,TlsHost=tls,User=users['writer'],Password=cp['writer'],Database=0,Environment='svs15',Epoch=v['epoch'],Policy='auth.v1',DragonflyVersion=info['dragonfly_version'],PrimaryRunId=info['run_id']),AuthorityCacheReader=dict(User=users['validator'],Password=cp['validator']),AuthorityCacheAccess=dict(RefillerUser=users['refiller'],ValidatorUser=users['validator'],LegacyUsers=[users[k] for k in ['active','pending','abuse']]),SystemTestSettings=dict(Enabled=False,EnableTestInspectionEndpoints=False,TestKey=''),SecurityOperationSettings=dict(ActiveKeyVersion=1,HmacKeys={'1':v['keys']['operations']}))
    for section,kind in [('ActiveUserBundleSettings','active'),('TwoFactorSessionBundleSettings','pending'),('AbuseCounterBundleSettings','abuse')]:settings[section].update(servers=ip,ssl=True,sslHost=tls,user=users[kind],password=cp[kind])
    settings['JWTSettings'].update(JsonWebTokenIssuer='svs15.test',MinimumRefreshIntervalSeconds=1)
    settings['HostingSettings'].update(BindAddress='172.29.93.11',Port=5001,UseHttps=True,Protocols='Http1AndHttp2',UseForwardedHeaders=False)
    settings['RegistrationSettings']['PublicOrigin']='https://writer:5001'
    settings['LoginSettings']['TwoFactorChallengePepper']=secrets.token_hex(32)
    settings['PasswordResetSettings']['CodeHashPepper']=secrets.token_hex(32)
    settings['SMTPSettings'].update(SMTPQualifiedDomain='smtp',SMTPPort=2525,SMTPUsername='fixture',SMTPPassword=v['smtp'],TransportMode='RequiredStartTls',AllowIsolatedPlaintext=False)
    settings['DeliveryOutboxSettings'].update(EncryptionKeys={'1':v['keys']['outbox']},PollSeconds=1)
    settings['TotpSettings'].update(ActiveProtectionKeyId='fixture',ProtectionKeys={'fixture':v['keys']['totp']})
    settings['RetentionSettings']['Enabled']=False
    settings['Logging']['LogLevel']={'Default':'None'}
    settings['Kestrel']={'Certificates':{'Default':{'Path':'/run/fixture/server.pfx','Password':''}}}
    save(state/'writer/appsettings.Fixture.json',settings)
    for i in [1,2]:
        clients=[]
        for j in [1,2]:
            clients.append(dict(tlsName='svs-'+str(j),privateAddress='172.29.91.'+str(20+j),port=8443,serverRootCertificatePath='/run/fixture/services-ca.pem',serverLeafSha256=[pins['svs-'+str(j)]],clientCertificatePath='/run/fixture/client.pfx',clientCertificatePassword='',clientRootCertificatePath='/run/fixture/clients-ca.pem',serviceIdentity='spiffe://svs15.test/service/caller-'+str(i),policyVersion='svs15-actions.v1',requestTimeoutMilliseconds=4000,maximumConcurrentCalls=8,maximumConnections=2,shutdownTimeoutMilliseconds=3000))
        save(state/('caller-'+str(i))/'config.json',dict(identity='caller-'+str(i),address='172.29.93.'+str(40+i),driverPin=pins['controller'],clients=clients))
    peers=[]
    for name,kind,route in [('writer','TreeHammock','172.29.92.11'),('svs-1','SVS','172.29.92.21'),('svs-2','SVS','172.29.92.22')]:
        identities=[dict(purpose=a,kind=b,name=c) for a,b,c in ([('app','SQL',roles['App']),('coordinator','SQL',roles['Coordinator']),('cache-reader','Cache',users['validator']),('cache-writer','Cache',users['writer'])] if kind=='TreeHammock' else [('validator','SQL',roles['Validator']),('refiller','SQL',roles['Refiller']),('cache-reader','Cache',users['validator']),('cache-refiller','Cache',users['refiller'])])]
        peers.append(dict(id=name,kind=kind,uri='https://'+route+':5444/',serverPin=pins[name+'-fleet'],identities=identities))
    target=dict(host=ip,port=6379,tlsHost=tls,database=0,version=info['dragonfly_version'],runId=info['run_id'],adminUser='fixture-admin',adminPassword=cp['admin'],subjects=list(users.values()))
    if phase=='old':v['retiredCache']=target;save(state/'private.json',v);save(state/'operator/private.json',v)
    controller=dict(database=database('yugabyte',v['sqlAdmin']),realm=v['realm'],clientCertificatePath='/run/fixture/controller.pfx',clientCertificatePassword='',peerRootCertificatePath='/run/fixture/services-ca.pem',peers=peers,caches=[v['retiredCache']],candidateCache=target if phase=='new' else None,environment='svs15',epoch=v['epoch'],policy='auth.v1')
    save(state/'operator/controller.json',controller)
    # Newly written configuration must stay readable by the nonroot fixture UID.
    uid=os.getuid() or 1654;gid=os.getgid() or 1654
    for p in state.rglob('*.json'):
        p.chmod(0o640)
        if os.getuid()==0:os.chown(p,uid,gid)
