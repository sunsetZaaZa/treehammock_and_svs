import base64,gzip,importlib.util,io,json,os,subprocess,tarfile,tempfile,unittest,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('scanner',ROOT/'eng/session-validation/scan-security-output.py');scanner=importlib.util.module_from_spec(spec);spec.loader.exec_module(scanner)
class SecurityTests(unittest.TestCase):
    def test_private_material_inventory_owner_mode_shared_file_and_role(self):
        spec=importlib.util.spec_from_file_location('inventory',Path(__file__).with_name('audit-private-material.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'fixture.pfx';p.write_bytes(b'synthetic-private-container');p.chmod(0o600)
            item=dict(service='caller-1',purpose='caller',path=str(p),owner_uid=os.getuid());value=dict(version=1,items=[item]);self.assertEqual(module.audit(value)['private_files'],1)
            p.chmod(0o640)
            with self.assertRaises(module.Refused):module.audit(value)
            p.chmod(0o600)
            with self.assertRaises(module.Refused):module.audit(dict(version=1,items=[item,item]))
            with self.assertRaises(module.Refused):module.audit(dict(version=1,items=[{**item,'purpose':'signing'}]))
    def test_clean_logs_pass(self):
        s=scanner.Scanner();s.inspect(b'{"status":"Passed","count":10}');self.assertEqual(s.result()['status'],'Passed')
    def test_canary_encodings_refused(self):
        value='synthetic-private-canary-16'
        for data in [value.encode(),base64.b64encode(value.encode()),value.encode().hex().encode()]:
            with self.subTest(data=data):
                s=scanner.Scanner([value]);s.inspect(data);self.assertIn('SECRET_CANARY',s.result()['rules']);self.assertNotIn(value,json.dumps(s.result()))
    def test_token_private_key_and_assignment_refused(self):
        for data in [b'-----BEGIN PRIVATE KEY-----',b'password=synthetic-private',b'eyJhbGciOiJIUzI1NiJ9.abcdefghijk.abcdefghijk']:
            s=scanner.Scanner();s.inspect(data);self.assertEqual(s.result()['status'],'Refused')
    def test_nested_zip_and_gzip_cannot_hide_canary(self):
        b=io.BytesIO()
        with zipfile.ZipFile(b,'w') as z:z.writestr('log.gz',gzip.compress(b'synthetic-hidden-canary'))
        s=scanner.Scanner(['synthetic-hidden-canary']);s.inspect(b.getvalue());self.assertIn('SECRET_CANARY',s.result()['rules'])
    def test_tar_link_and_zip_link_refused(self):
        b=io.BytesIO()
        with tarfile.open(fileobj=b,mode='w') as t:
            m=tarfile.TarInfo('link');m.type=tarfile.SYMTYPE;m.linkname='/private';t.addfile(m)
        with self.assertRaises(scanner.Refused):scanner.Scanner().inspect(b.getvalue())
        b=io.BytesIO()
        with zipfile.ZipFile(b,'w') as z:
            m=zipfile.ZipInfo('link');m.create_system=3;m.external_attr=0o120777<<16;z.writestr(m,'/private')
        with self.assertRaises(scanner.Refused):scanner.Scanner().inspect(b.getvalue())
    def test_expansion_and_depth_bounds_refused(self):
        with self.assertRaises(scanner.Refused):scanner.Scanner(maximum=1024).inspect(gzip.compress(b'a'*2048))
        with self.assertRaises(scanner.Refused):scanner.Scanner(depth=0).inspect(gzip.compress(b'fixture'))
    def test_dump_and_private_container_detection(self):
        data=bytearray(20);data[:4]=b'\x7fELF';data[5]=1;data[16]=4
        s=scanner.Scanner();s.inspect(data);self.assertIn('CORE_DUMP',s.result()['rules'])
        for name in ['server.pfx','crash.dmp','core.123']:
            s=scanner.Scanner();s.inspect(b'fixture',name);self.assertIn('PRIVATE_OR_DUMP_ARTIFACT',s.result()['rules'])
    def test_symlink_cannot_escape_export_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'link';p.symlink_to('/etc/passwd')
            with self.assertRaises(scanner.Refused):scanner.Scanner().path(p)
    def test_cli_does_not_echo_canary_or_filename(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'synthetic-secret-in-name';p.write_bytes(b'password=synthetic-secret-value')
            r=subprocess.run(['python3',ROOT/'eng/session-validation/scan-security-output.py',p],capture_output=True);self.assertEqual(r.returncode,1);self.assertNotIn(b'synthetic-secret',r.stdout+r.stderr)
    def test_secure_launcher_overrides_dump_and_debug_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);exe=root/'dotnet';exe.write_text('#!/usr/bin/env bash\n[[ $(ulimit -c) == 0 && $DOTNET_EnableDiagnostics == 0 && $DOTNET_DbgEnableMiniDump == 0 && $COMPlus_DbgEnableMiniDump == 0 ]] || exit 17\n[[ -z ${DOTNET_DiagnosticPorts-} && -z ${DOTNET_STARTUP_HOOKS-} ]] || exit 18\necho SECURE_LAUNCHER_PASSED\n');exe.chmod(0o700)
            env={**os.environ,'PATH':str(root)+':'+os.environ['PATH'],'DOTNET_EnableDiagnostics':'1','DOTNET_DbgEnableMiniDump':'1','COMPlus_DbgEnableMiniDump':'1','DOTNET_DiagnosticPorts':'private-test','DOTNET_STARTUP_HOOKS':'private-test'}
            r=subprocess.run(['bash',ROOT/'eng/session-validation/secure-exec.sh','/private/fixture.dll'],env=env,capture_output=True);self.assertEqual(r.returncode,0);self.assertEqual(r.stdout.strip(),b'SECURE_LAUNCHER_PASSED')
    def test_source_export_has_no_private_key_material(self):
        import re
        found=[]
        for p in ROOT.rglob('*'):
            if not p.is_file() or set(p.relative_to(ROOT).parts)&{'bin','obj','.git','__pycache__'}:continue
            data=p.read_bytes()
            if p.suffix.lower() in {'.pfx','.p12','.key'} or re.search(rb'-----BEGIN (?:[A-Z ]*PRIVATE KEY)-----\r?\n[A-Za-z0-9+/=\r\n]{40,}',data):found.append(p.name)
        self.assertEqual(found,[])
if __name__=='__main__':unittest.main()
