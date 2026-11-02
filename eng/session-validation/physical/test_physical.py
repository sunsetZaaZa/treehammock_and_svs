import copy,importlib.util,json,os,subprocess,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
render=module('render','render-deployment.py');probe=module('probe','probe-host.py');alpn=module('alpn','verify-alpn.py');credentials=module('credentials','probe-credentials.py')
class PhysicalTests(unittest.TestCase):
    def setUp(self):self.inventory=json.loads((render.DEPLOY/'physical/datacenter.example.json').read_text())
    def test_source_units_separate_identities_credentials_core_and_resources(self):
        text=(render.DEPLOY/'systemd/svs@.service').read_text()
        for value in ['User=svs-%i','LoadCredential=host.json:','%d/host.json','LimitCORE=0','LimitNOFILE=4096','TasksMax=256','CPUQuota=200%','MemoryMax=768M','NoNewPrivileges=yes','CapabilityBoundingSet=','ProtectSystem=strict','ProtectProc=invisible','StateDirectory=svs-%i','TimeoutStopSec=30','KillSignal=SIGTERM','IPAddressDeny=any','StandardOutput=null']:self.assertIn(value,text)
        self.assertNotIn('MemoryDenyWriteExecute=yes',text);self.assertNotIn('ExecStopPost=',text)
    def test_default_proxy_cannot_run_before_reviewed_override(self):
        self.assertIn('ExecStart=/usr/bin/false',(render.DEPLOY/'systemd/svs-proxy@.service').read_text())
    def test_public_duplicate_injected_and_colliding_identity_inventory_refused(self):
        for change in [dict(ingressIp='0.0.0.0'),dict(databaseIp='8.8.8.8'),dict(datacenter='dc1\nExecStart=/bin/sh'),dict(replicaUids=[1654,1654]),dict(replicaUids=[1660,1655]),dict(tlsName='bad..name'),dict(haproxyIp=self.inventory['ingressIp'])]:
            with self.subTest(change=change),self.assertRaises(render.Refused):render.validate({**self.inventory,**change})
    def test_proxy_templates_are_private_opaque_TLS_without_retry_or_header_identity(self):
        nginx=(render.DEPLOY/'nginx/grpc.conf').read_text();haproxy=(render.DEPLOY/'haproxy/internal.cfg').read_text()
        self.assertIn('ssl_preread on;',nginx);self.assertIn('proxy_next_upstream off;',nginx);self.assertNotIn('ssl_certificate',nginx);self.assertNotIn('grpc_set_header',nginx);self.assertNotIn('listen 0.0.0.0',nginx)
        self.assertIn('mode tcp',haproxy);self.assertIn('retries 0',haproxy);self.assertIn('reject if !svs_ingress',haproxy);self.assertNotIn(' ssl ',haproxy);self.assertNotIn('send-proxy',haproxy)
    def test_fresh_renderer_cannot_overwrite_and_does_not_cascade_address_replacements(self):
        value=copy.deepcopy(self.inventory);value['ingressIp'],value['haproxyIp']=value['haproxyIp'],value['ingressIp']
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'rendered';result=render.render(value,out);self.assertEqual(result['status'],'RenderedOnly')
            self.assertIn('listen '+value['ingressIp']+':9443',(out/'nginx/grpc.conf').read_text());self.assertIn('server '+value['haproxyIp']+':9443',(out/'nginx/grpc.conf').read_text())
            with self.assertRaises(render.Refused):render.render(value,out)
            host=json.loads((out/'physical/host-1.example.json').read_text());self.assertEqual(host['fleet']['checkpointPath'],'/var/lib/svs-1/fleet.checkpoint');self.assertIn('/run/credentials/svs@1.service/',host['serverCertificatePath']);self.assertIn('Port=5433',host['databaseConnectionString'])
    def test_firewall_keeps_writer_routes_and_blocks_unreviewed_origin_and_uid_egress(self):
        text=render.firewall(self.inventory);self.assertNotIn('flush ruleset',text);self.assertIn('policy accept;',text);self.assertIn('ct direction reply accept',text);self.assertIn('10.77.2.11',text);self.assertIn('meta skuid { 1654, 1655 } reject',text);self.assertIn('tcp dport 8444 accept',text);self.assertIn('drop\n',text);self.assertNotIn('iifname \"lo\" accept',text);self.assertNotIn('oifname \"lo\" accept',text)
    def test_sysctl_example_enables_no_speculative_performance_tuning(self):
        text=(render.DEPLOY/'linux/sysctl.d/90-session-validation.example.conf').read_text();active=[x for x in text.splitlines() if x.strip() and not x.startswith('#')]
        self.assertIn('fs.suid_dumpable = 0',active);self.assertTrue(all('conntrack' not in x and 'somaxconn' not in x and 'numa' not in x and 'port_range' not in x for x in active))
    def fixture_process(self,tmp):
        proc=tmp/'proc';path=proc/'123';path.mkdir(parents=True);(path/'status').write_text('Uid:\t1654 1654 1654 1654\nNoNewPrivs:\t1\nCapEff:\t00000000\n');(path/'limits').write_text('Max core file size        0 0 bytes\nMax open files            4096 4096 files\n');(path/'fd').mkdir();(path/'cgroup').write_text('0::/system.slice/svs@1.service\n');cgroup=tmp/'cgroup/system.slice/svs@1.service';cgroup.mkdir(parents=True)
        for name,value in [('memory.max','805306368'),('memory.swap.max','0'),('pids.max','256'),('cpu.max','200000 100000')]: (cgroup/name).write_text(value)
        return proc,tmp/'cgroup',path,cgroup
    def test_readonly_process_probe_checks_core_uid_caps_and_cgroup_ceiling(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc,groups,path,cgroup=self.fixture_process(Path(tmp));result=probe.inspect(123,1654,proc,groups);self.assertEqual(result['status'],'ScopedProcessLimitsPassed');self.assertEqual(result['full_physical_qualification'],'NotRun')
            (cgroup/'memory.max').write_text('max')
            with self.assertRaises(probe.Refused):probe.inspect(123,1654,proc,groups)
    def test_capability_or_dump_limit_bypass_cannot_pass_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc,groups,path,cgroup=self.fixture_process(Path(tmp));(path/'status').write_text('Uid:\t1654 1654 1654 1654\nNoNewPrivs:\t0\nCapEff:\t00000001\n')
            with self.assertRaises(probe.Refused):probe.inspect(123,1654,proc,groups)
            (path/'status').write_text('Uid:\t1654 1654 1654 1654\nNoNewPrivs:\t1\nCapEff:\t00000000\n');(path/'limits').write_text('Max core file size  unlimited unlimited bytes\nMax open files 4096 4096 files\n')
            with self.assertRaises(probe.Refused):probe.inspect(123,1654,proc,groups)
    def test_systemd_runtime_credentials_require_readonly_private_distinct_files(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            key=Path(tmp)/'credential';key.touch();key.chmod(0o400)
            inventory={'version':1,'items':[{'path':str(key),'owner_uid':1654}]}
            info=key.stat()
            # Synthetic UID only; metadata audit never reads the file contents.
            from types import SimpleNamespace
            synthetic=SimpleNamespace(st_dev=info.st_dev,st_ino=info.st_ino,st_uid=1654,st_mode=info.st_mode,st_nlink=1)
            with patch.object(credentials.Path,'stat',return_value=synthetic):
                self.assertEqual(credentials.audit(inventory)['status'],'ScopedCredentialMetadataPassed')
                with self.assertRaises(credentials.Refused):credentials.audit({'version':1,'items':inventory['items']*2})
                synthetic.st_mode=0o100600
                with self.assertRaises(credentials.Refused):credentials.audit(inventory)
            link=Path(tmp)/'linked';link.symlink_to(key)
            with self.assertRaises(credentials.Refused):credentials.audit({'version':1,'items':[{'path':str(link),'owner_uid':1654}]})
    def test_alpn_probe_refuses_external_target_before_reading_keys(self):
        with self.assertRaises(ValueError):alpn.verify('8.8.8.8',9443,'svs.example.internal','not-used','not-used','not-used',['A'*64])
if __name__=='__main__':unittest.main()
