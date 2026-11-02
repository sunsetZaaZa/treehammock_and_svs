import importlib.util,json,subprocess,sys,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent;s=importlib.util.spec_from_file_location('sanitize',HERE/'sanitize-operations.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class SanitizeTests(unittest.TestCase):
    def v(self):return dict(health=dict(live=True,ready=True,mode='CacheReady',databaseFallbackReady=False,cacheReady=True,refillReady=False,authorityWriteReady=False,serverCertificateNearExpiry=True,clockOffsetKnown=False),requests=dict(capacity=64,active=2,peak=5,accepted=8,rejected=1,queued=0))
    def test_export_cannot_create_authority(self):self.assertFalse(m.sanitize(self.v())['grant_rights'])
    def test_extra_secret_or_identity_fields_refused(self):
        for key in ['token','accountId','caller','exception','authorization']:
            for location in ['health','requests',None]:
                v=self.v();(v if location is None else v[location])[key]='private-canary-value'
                with self.assertRaises(m.Refused):m.sanitize(v)
    def test_bad_counters_or_forged_authority_refused(self):
        for k,x in [('capacity',True),('active',float('nan')),('queued',1),('rejected',-1),('active',65)]:
            v=self.v();v['requests'][k]=x
            with self.assertRaises(m.Refused):m.sanitize(v)
        v=self.v();v['health']['authorityWriteReady']=True
        with self.assertRaises(m.Refused):m.sanitize(v)
    def test_reconciliation_is_operator_codes_only(self):
        r=m.reconcile(self.v());self.assertEqual(r['commands_executed'],0);self.assertFalse(r['grant_rights']);self.assertIn('PRESERVE_CACHE_BOUNDS_RESTORE_DATABASE_NO_FORCED_ADMISSION',r['actions'])
    def test_duplicate_JSON_refused_without_echo(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'input';p.write_text('{"health":"private-canary-value","health":{}}');r=subprocess.run([sys.executable,str(HERE/'sanitize-operations.py'),str(p)],capture_output=True,text=True);self.assertNotEqual(r.returncode,0);self.assertNotIn('private-canary-value',r.stdout+r.stderr);self.assertIn('DUPLICATE_FIELD_REFUSED',r.stdout)
if __name__=='__main__':unittest.main()
