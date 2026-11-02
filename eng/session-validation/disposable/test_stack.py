import copy,hashlib,json,os,ssl,subprocess,tempfile,time,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
import common,fixture,native,stack
from common import ROOT,Refused
class BoundaryTests(unittest.TestCase):
    def setUp(self):self.topology=json.loads(stack.COMPOSE.read_text())
    def test_exact_private_service_inventory(self):self.assertEqual(stack.check_topology(self.topology)['services'],10)
    def test_published_data_port_refused(self):
        self.topology['services']['yugabyte']['ports']=['5433:5433']
        with self.assertRaises(Refused):stack.check_topology(self.topology)
    def test_host_network_and_docker_socket_refused(self):
        for key,value in [('network_mode','host'),('privileged',True),('devices',['/dev/kvm'])]:
            v=copy.deepcopy(self.topology);v['services']['operator'][key]=value
            with self.subTest(key=key),self.assertRaises(Refused):stack.check_topology(v)
        self.topology['services']['operator']['volumes'].append(dict(type='bind',source='/var/run/docker.sock',target='/var/run/docker.sock'))
        with self.assertRaises(Refused):stack.check_topology(self.topology)
    def test_caller_data_network_and_other_service_secrets_refused(self):
        v=copy.deepcopy(self.topology);v['services']['caller-1']['networks']['data']={}
        with self.assertRaises(Refused):stack.check_topology(v)
        self.topology['services']['caller-2']['volumes'][0]['source']='${SVS15_STATE}/operator'
        with self.assertRaises(Refused):stack.check_topology(self.topology)
    def test_external_or_unbounded_process_refused(self):
        v=copy.deepcopy(self.topology);v['networks']['data']['internal']=False
        with self.assertRaises(Refused):stack.check_topology(v)
        self.topology['services']['writer']['pids_limit']=4096
        with self.assertRaises(Refused):stack.check_topology(self.topology)
    def test_image_lock_cannot_float(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'lock.json';v={k:'registry.test/'+k+'@sha256:'+'a'*64 for k in ['toolchain','yugabyte','dragonfly']};v['dragonflyVersion']='1.34.0';p.write_text(json.dumps(v));self.assertEqual(common.images(p),v)
            for bad in ['latest','sdk:10.0','sdk@sha256:bad']:
                v['toolchain']=bad;p.write_text(json.dumps(v))
                with self.subTest(bad=bad),self.assertRaises(Refused):common.images(p)
    def test_peer_must_be_exact_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'peer.zip'
            with zipfile.ZipFile(p,'w') as z:z.writestr('source/treehammock-main/treehammock.csproj','fake')
            with self.assertRaises(Refused):stack.extract_peer(p,Path(tmp)/'out')
    def test_actual_runtime_role_connections_for_negative_probes(self):
        class Target:
            def __init__(self):self.sqls=[]
            def sql(self,value):self.sqls.append(value)
        target=Target();v={'passwords':{'new':{k:'generated-private-fixture' for k in fixture.rolemap('new')}}};cases=stack.permission_probes(target,v)
        self.assertEqual(len(cases),2)
        for kind,sql in zip(['Validator','Refiller'],target.sqls):
            self.assertIn('user='+fixture.rolemap('new')[kind],sql);self.assertTrue(sql.startswith('\\connect '));self.assertIn('session_user <> current_user',sql);self.assertIn('when insufficient_privilege',sql);self.assertNotIn('session authorization',sql.lower());self.assertNotIn('transaction read only',sql.lower())
    def test_remote_docker_context_refused(self):
        with self.assertRaises(Refused):stack.verify_docker({'DOCKER_HOST':'tcp://remote:2375'})
        with patch.object(stack,'run',return_value=json.dumps([{'Endpoints':{'docker':{'Host':'ssh://remote'}}}]).encode()):
            with self.assertRaises(Refused):stack.verify_docker({})
    def test_commands_use_only_unique_owned_project(self):
        calls=[]
        with patch.object(stack,'run',side_effect=lambda args,**kw:calls.append((args,kw)) or b''):
            target=stack.Stack(Path('/private'),'svs15-12345678',{});target.compose('down','--volumes','--remove-orphans')
        self.assertEqual(calls[0][0][:4],['docker','compose','--project-name','svs15-12345678']);self.assertNotIn('prune',calls[0][0])
    def test_exception_does_not_echo_child_output(self):
        with self.assertRaises(Refused) as error:common.run(['python3','-c','import sys;print("private-canary");sys.exit(1)'])
        self.assertEqual(str(error.exception),'CHILD_PROCESS_FAILED')
    def test_unavailable_peer_is_not_pruned_from_status_inventory(self):
        peers=[dict(id='writer',kind='TreeHammock',uri='https://172.29.92.11:5444/'),dict(id='svs-1',kind='SVS',uri='https://172.29.92.21:5444/'),dict(id='svs-2',kind='SVS',uri='https://172.29.92.22:5444/')]
        calls=[]
        def request(host,port,path,body):
            calls.append(host)
            if host.endswith('.22'):raise OSError()
            p=next(p for p in peers if host in p['uri']);return 200,json.dumps(dict(instance=p['id'],kind=p['kind'],nonce=body['nonce'],protocol='authority-fleet.v2')).encode()
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);(p/'controller.json').write_text(json.dumps({'peers':peers}))
            with patch.object(native,'FIXTURE',p),patch.object(native,'request',side_effect=request),patch.object(native.time,'monotonic',side_effect=[0,1,91]),patch.object(native.time,'sleep'):
                with self.assertRaises(Refused) as error:native.ready()
        self.assertEqual(str(error.exception),'ALL_PEER_STARTUP_TIMEOUT');self.assertEqual(len(calls),3)
class FixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='svs15-unit-');cls.state=Path(cls.temp.name)/'state';cls.peer=ROOT
        cls.lock={k:'registry.test/'+k+'@sha256:'+'a'*64 for k in ['toolchain','yugabyte','dragonfly']};cls.lock['dragonflyVersion']='fixture-test-version'
        # Managed local host cannot chown to the container UID. Ownership mapping
        # stays mandatory in the live runner; this test checks modes and TLS bytes.
        cls.owner_patch=patch.object(fixture.os,'chown');cls.owner_patch.start()
        cls.v=fixture.create(cls.state,cls.peer,cls.lock)
        fixture.configure(cls.state,cls.peer,'old',dict(run_id='a'*40,dragonfly_version='fixture-test-version'))
        fixture.configure(cls.state,cls.peer,'new',dict(run_id='b'*40,dragonfly_version='fixture-test-version'))
    @classmethod
    def tearDownClass(cls):cls.owner_patch.stop();cls.temp.cleanup()
    def test_rotation_and_complete_three_peer_inventory(self):
        config=json.loads((self.state/'operator/controller.json').read_text());self.assertEqual([p['id'] for p in config['peers']],['writer','svs-1','svs-2']);self.assertEqual(config['caches'][0]['runId'],'a'*40);self.assertEqual(config['candidateCache']['runId'],'b'*40)
        self.assertTrue(set(fixture.rolemap('old').values()).intersection(fixture.rolemap('new').values())=={'fixture_owner','treehammock_svs_read'})
    def test_each_caller_has_own_uri_pin_and_key(self):
        pins=self.v['pins'];self.assertNotEqual(pins['caller-1-client'],pins['caller-2-client'])
        for i in [1,2]:
            cert=self.state/'ca-private'/('caller-'+str(i)+'-client.pem');out=common.run(['openssl','x509','-in',cert,'-text','-noout']).decode();self.assertIn('URI:spiffe://svs15.test/service/caller-'+str(i),out)
            cfg=json.loads((self.state/('svs-'+str(i))/'host.json').read_text());self.assertEqual(len(cfg['callers']),2)
    def test_no_ca_private_keys_are_mounted(self):
        for service in fixture.SERVICES:
            self.assertFalse(any(p.name.endswith('-ca.key') for p in (self.state/service).rglob('*')))
            self.assertLessEqual(len(list((self.state/service).glob('*.pfx'))),2)
    def test_real_database_and_provider_configuration(self):
        cfg=json.loads((self.state/'writer/appsettings.Fixture.json').read_text());self.assertEqual(cfg['DatabaseSettings']['profile'],'Production');self.assertEqual(cfg['DatabaseSettings']['sessionReadBackend'],'Yugabyte');self.assertFalse(cfg['SystemTestSettings']['Enabled']);self.assertEqual(cfg['SMTPSettings']['TransportMode'],'RequiredStartTls');self.assertEqual(cfg['HostingSettings']['UseForwardedHeaders'],False)
    def test_foreground_refill_credentials_are_distinct(self):
        cfg=json.loads((self.state/'svs-1/host.json').read_text());self.assertNotEqual(cfg['cache']['username'],cfg['refill']['publisherCache']['username']);self.assertNotEqual(cfg['cache']['password'],cfg['refill']['publisherCache']['password']);self.assertNotEqual(cfg['databaseConnectionString'],cfg['refill']['databaseConnectionString']);self.assertIn('SSL Mode=VerifyFull',cfg['databaseConnectionString']);self.assertEqual(cfg['actionPolicy']['requirements'],{'backup.read':'account.read'})
    def test_bad_engine_observation_cannot_configure(self):
        with self.assertRaises(Refused):fixture.configure(self.state,self.peer,'new',dict(run_id='x'*40,dragonfly_version='unexpected'))
    def test_private_fixture_files_are_not_world_readable(self):
        for p in self.state.rglob('*'):
            self.assertEqual(p.stat().st_mode&7,0,p.name)
    def test_operation_headers_are_fresh_and_well_formed(self):
        first=native.operation_headers();second=native.operation_headers();self.assertNotEqual(first,second);self.assertRegex(first['Security-Operation-Key'],r'^\d+\.[a-f0-9]{32}$')
    def test_real_starttls_fixture_accepts_only_authenticated_mail(self):
        import base64,smtplib,smtp_sink,threading
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(self.state/'smtp/server.pem',self.state/'smtp/server.key')
        with patch.object(smtp_sink,'CONTEXT',context,create=True),patch.object(smtp_sink,'SECRET',self.v['smtp'],create=True),patch.object(smtp_sink,'CAPTURE',self.state/'smtp/captures'):
            server=smtp_sink.Server(('127.0.0.1',0),smtp_sink.Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                with smtplib.SMTP('127.0.0.1',server.server_address[1],timeout=4) as client:
                    client.starttls(context=ssl.create_default_context(cafile=str(self.state/'smtp/services-ca.pem')))
                    with self.assertRaises(smtplib.SMTPAuthenticationError):client.login('fixture','wrong-fixture-secret')
                    client.login('fixture',self.v['smtp']);client.sendmail('fixture@svs15.test',['recipient@svs15.test'],'Subject: fixture\r\n\r\nfixture-message')
                files=list((self.state/'smtp/captures').glob('*.json'));self.assertEqual(len(files),1);self.assertIn(b'fixture-message',base64.b64decode(json.loads(files[0].read_text())['message']))
            finally:server.shutdown();server.server_close();thread.join(4)
    @unittest.skipUnless(os.environ.get('SVS15_DOTNET'),'Set SVS15_DOTNET for compiled caller loopback TLS checks')
    def test_compiled_caller_actual_tls_and_failed_authorization(self):
        import http.client
        directory=self.state/'caller-1';config=json.loads((directory/'config.json').read_text());config['address']='127.0.0.1'
        for options in config['clients']:
            for key in ['serverRootCertificatePath','clientCertificatePath','clientRootCertificatePath']:options[key]=options[key].replace('/run/fixture',str(directory))
            options['privateAddress']='127.0.0.1';options['port']=1
        (directory/'config.json').write_text(json.dumps(config))
        env={**os.environ,'SVS15_FIXTURE_DIRECTORY':str(directory),'DOTNET_ROOT':str(Path(os.environ['SVS15_DOTNET']).parent),'DOTNET_PROCESSOR_COUNT':'4'}
        dll=ROOT/'tests/Treehammock.SessionValidation.DisposableCaller/bin/Release/net10.0/Treehammock.SessionValidation.DisposableCaller.dll'
        process=subprocess.Popen([os.environ['SVS15_DOTNET'],str(dll)],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        def request(identity,path='/health',body=None,headers=None):
            ctx=ssl.create_default_context(cafile=str(directory/'services-ca.pem'))
            if identity:ctx.load_cert_chain(self.state/'ca-private'/(identity+'.pem'),self.state/'ca-private'/(identity+'.key'))
            connection=http.client.HTTPSConnection('127.0.0.1',9443,timeout=2,context=ctx)
            try:
                h={'Content-Type':'application/json',**(headers or {})};connection.request('POST' if body else 'GET',path,json.dumps(body) if body else None,h);reply=connection.getresponse();return reply.status,reply.read()
            finally:connection.close()
        try:
            end=time.monotonic()+15
            while True:
                try:status,body=request('controller');break
                except (OSError,http.client.HTTPException):
                    if process.poll() is not None or time.monotonic()>end:self.fail('Compiled caller startup failed')
                    time.sleep(.1)
            self.assertEqual(status,200);self.assertEqual(json.loads(body)['caller'],'caller-1')
            for identity in [None,'caller-2-client']:
                with self.subTest(identity=identity),self.assertRaises((OSError,http.client.HTTPException)):
                    request(identity,headers={'X-Forwarded-Client-Cert':'forged-controller'})
            status,body=request('controller','/validate',dict(credential='fixture-invalid',action='unsupported.action',replica=0));self.assertEqual(status,503);self.assertNotIn(b'fixture-invalid',body);self.assertEqual(json.loads(body)['decision'],'Unavailable')
        finally:
            process.terminate()
            try:process.wait(timeout=12)
            except subprocess.TimeoutExpired:process.kill();process.wait()
if __name__=='__main__':unittest.main()
