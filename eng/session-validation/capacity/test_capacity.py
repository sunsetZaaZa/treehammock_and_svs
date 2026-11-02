import importlib.util,json,os,ssl,subprocess,tempfile,threading,unittest
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
spec=importlib.util.spec_from_file_location('load',Path(__file__).with_name('load-capacity.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class CapacityDriverTests(unittest.TestCase):
    def test_external_or_unbounded_load_refused(self):
        for target in ['http://127.0.0.1:8443/health/live','https://8.8.8.8:8443/health/live','https://localhost:8443/health/live','https://127.0.0.1:8443/debug','https://127.0.0.1:8443/validate?credential=private']:
            with self.subTest(target=target),self.assertRaises(module.Refused):module.validate(target,10,2,1)
        for requests,concurrency,timeout in [(10001,4,1),(100,65,1),(100,4,11)]:
            with self.assertRaises(module.Refused):module.validate('https://127.0.0.1:8443/health/live',requests,concurrency,timeout)
    def test_private_ipv4_and_ipv6_are_allowed(self):
        for address in ['127.0.0.1','10.0.0.2','172.29.93.41','192.168.1.2','[fd00::1]']:module.validate('https://'+address+':9443/validate',1,1,1)
    def test_wrong_payload_route_refused_before_network(self):
        with self.assertRaises(module.Refused):module.load('https://127.0.0.1:9443/health/live',None,1,1,1,b'private')
        with self.assertRaises(module.Refused):module.load('https://127.0.0.1:9443/validate',None,1,1,1)
    def test_real_TLS_worker_count_reuse_and_redacted_exploratory_report(self):
        class Handler(BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'
            def do_GET(self):
                self.send_response(503);self.send_header('Content-Length','0');self.end_headers()
            def log_message(self,*args):pass
        with tempfile.TemporaryDirectory() as tmp:
            tmp=Path(tmp);cert=tmp/'cert.pem';key=tmp/'key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=fixture','-addext','subjectAltName=IP:127.0.0.1','-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            server=ThreadingHTTPServer(('127.0.0.1',0),Handler);context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key);server.socket=context.wrap_socket(server.socket,server_side=True);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:result=module.load('https://127.0.0.1:'+str(server.server_port)+'/health/live',ssl.create_default_context(cafile=str(cert)),40,4,2)
            finally:server.shutdown();server.server_close();thread.join(3)
            self.assertEqual(result['requests'],40);self.assertEqual(result['status_counts'],{'503':40});self.assertLessEqual(result['connection_attempts'],4);self.assertLessEqual(result['p95_ms'],result['p99_ms']);self.assertEqual(result['native_acceptance'],'NotRun');self.assertNotIn('127.0.0.1',json.dumps(result))
            if os.environ.get('SVS17_LOAD_REPORT'):Path(os.environ['SVS17_LOAD_REPORT']).write_text(json.dumps({**result,'scope':'Local TLS load-driver self-test against Python 503 fixture; not backend capacity'},indent=2)+'\n')
if __name__=='__main__':unittest.main()
