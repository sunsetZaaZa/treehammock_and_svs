import copy,hashlib,json,os,subprocess,tempfile,time,unittest
from pathlib import Path
import rollout as r

def enc(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
class RolloutTests(unittest.TestCase):
    def context(self):return dict(version=1,scope='Synthetic',old_source_sha256='a'*64,svs_source_sha256='b'*64,replicas=['svs-1','svs-2'])
    def row(self,replica='svs-1'):
        identity=dict(account='1'*32,family='2'*32,generation=7,protocol=2)
        return dict(token='private-shadow-fixture',old=dict(decision='Active',identity=identity),svs=dict(decision='Active',identity=identity.copy()),replica=replica,cache_hit=True,sql_reads=0,duration_us=10,writer_fence_us=3)
    def report(self,rows=None):return r.collect(b'\n'.join(enc(v) for v in rows or [self.row(),self.row('svs-2')]),b'K'*32,self.context())
    def test_no_raw_token_or_identity_and_job_local_fingerprint(self):
        a=self.report();blob=enc(a);self.assertNotIn(b'private-shadow-fixture',blob);self.assertNotIn(b'1'*32,blob);self.assertNotIn(b'2'*32,blob);self.assertFalse(a['grant_rights']);b=r.collect(enc(self.row()),b'J'*32,self.context());self.assertNotEqual(a['observations'][0]['fingerprint'],b['observations'][0]['fingerprint']);self.assertEqual(a['observations'][0]['fingerprint'],a['observations'][1]['fingerprint'])
    def test_escalation_and_identity_drift_are_counted(self):
        v=self.row();v['old']=dict(decision='Unauthenticated',identity=None);out=self.report([v]);self.assertEqual((1,1),(out['mismatches'],out['escalations']));v=self.row();v['svs']['identity']['family']='3'*32;self.assertEqual(1,self.report([v])['escalations'])
    def test_cache_hit_sql_violation_and_replica_counts(self):
        v=self.row();v['sql_reads']=1;out=self.report([v]);self.assertEqual(1,out['cache_hit_sql_violations']);self.assertEqual(0,out['replica_counts']['svs-2'])
    def test_missing_unknown_duplicate_and_nonfinite_fields_refused(self):
        for transform in [lambda v:v.update(extra='secret'),lambda v:v.pop('token'),lambda v:v.update(duration_us=float('nan'))]:
            v=self.row();transform(v)
            with self.assertRaises(r.Refused):self.report([v])
        with self.assertRaises(r.Refused):r.decode(b'{"a":1,"a":2}')
    def test_bounds_bool_numbers_and_subject_on_refusal(self):
        for key,value in [('sql_reads',True),('duration_us',-1),('token','x'*8193),('cache_hit',1),('replica','svs-9')]:
            v=self.row();v[key]=value
            with self.assertRaises(r.Refused):self.report([v])
        v=self.row();v['old']['decision']='Forbidden'
        with self.assertRaises(r.Refused):self.report([v])
        with self.assertRaises(r.Refused):r.collect(enc(self.row())*20000,b'K'*32,self.context())
    def test_identical_providers_are_not_independent(self):
        c=self.context();c['old_source_sha256']=c['svs_source_sha256']
        with self.assertRaises(r.Refused):r.collect(enc(self.row()),b'K'*32,c)
    def test_private_owned_regular_input_and_exclusive_output(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'input';p.write_bytes(b'safe');p.chmod(0o600);self.assertEqual(b'safe',r.private_read(p));p.chmod(0o644)
            with self.assertRaises(r.Refused):r.private_read(p)
            p.chmod(0o600);link=Path(d)/'link';link.symlink_to(p)
            with self.assertRaises(r.Refused):r.private_read(link)
            out=Path(d)/'out';r.private_write(out,{'safe':True});self.assertEqual(0o600,out.stat().st_mode&0o777)
            with self.assertRaises(r.Refused):r.private_write(out,{})
    def fixture(self):
        directory=tempfile.TemporaryDirectory();self.addCleanup(directory.cleanup);p=Path(directory.name)
        subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(p/'key')],check=True,capture_output=True)
        public=subprocess.check_output(['openssl','pkey','-in',str(p/'key'),'-pubout'])
        policy=dict(version=1,old_source_sha256='a'*64,svs_source_sha256='b'*64,trusted_key_sha256=hashlib.sha256(public).hexdigest(),replicas=['svs-1','svs-2'],min_samples_per_replica=1,max_p99_us=100,max_fallback_sql_reads=0,max_writer_fence_us=20,previous_basis_points=0,next_basis_points=100,packet_max_age_seconds=3600)
        report=self.report();report['scope']='StagingTrustedSample';proof=b'unit-test proof; not native acceptance';now=int(time.time())
        packet=dict(version=1,kind='NativeQualification',observed_basis_points=0,issued_at=now-1,expires_at=now+300,old_source_sha256='a'*64,svs_source_sha256='b'*64,comparison_sha256=hashlib.sha256(enc(report)).hexdigest(),approved_policy_sha256=hashlib.sha256(enc(policy)).hexdigest(),checks={g:dict(status='Passed',artifact='proof') for g in r.GATES},artifacts={'proof':dict(path='/unit-test-proof',sha256=hashlib.sha256(proof).hexdigest())})
        return p,public,policy,report,packet,proof,now
    def invoke(self,f,mutate=None,signature_fault=False,proof_fault=False):
        p,public,policy,report,packet,proof,now=f
        if mutate:mutate(policy,report,packet)
        packet['comparison_sha256']=hashlib.sha256(enc(report)).hexdigest();packet['approved_policy_sha256']=hashlib.sha256(enc(policy)).hexdigest();(p/'packet').write_bytes(enc(packet));subprocess.run(['openssl','pkeyutl','-sign','-inkey',str(p/'key'),'-rawin','-in',str(p/'packet'),'-out',str(p/'sig')],check=True,capture_output=True);sig=(p/'sig').read_bytes()
        if signature_fault:sig=bytes([sig[0]^1])+sig[1:]
        return r.gate(enc(report),enc(policy),enc(packet),sig,public,lambda _:b'wrong' if proof_fault else proof,now)
    def test_signed_complete_fixture_produces_review_only_plan(self):
        # Generated test trust anchor and invented proof live only in TemporaryDirectory.
        out=self.invoke(self.fixture());self.assertEqual('ReviewPlanEligible',out['status']);self.assertFalse(out['configuration_applied']);self.assertFalse(out['grant_rights']);self.assertEqual(0,out['deployment_commands_executed'])
    def test_wrong_signature_trust_or_proof_refused(self):
        for kwargs in [dict(signature_fault=True),dict(proof_fault=True),dict(mutate=lambda p,r,q:p.update(trusted_key_sha256='0'*64))]:
            with self.assertRaises(r.Refused):self.invoke(self.fixture(),**kwargs)
    def test_missing_failed_or_unqualified_native_gates_refused(self):
        for transform in [lambda p,v,q:q['checks'].pop('writer_coverage'),lambda p,v,q:q['checks']['revocation'].update(status='NotRun'),lambda p,v,q:q.update(kind='Synthetic')]:
            with self.assertRaises(r.Refused):self.invoke(self.fixture(),transform)
    def test_stale_future_and_unbound_source_refused(self):
        for transform in [lambda p,v,q:q.update(issued_at=q['issued_at']-7200),lambda p,v,q:q.update(issued_at=q['expires_at']+1),lambda p,v,q:q.update(svs_source_sha256='c'*64)]:
            with self.assertRaises(r.Refused):self.invoke(self.fixture(),transform)
    def test_synthetic_missing_replica_or_insufficient_samples_refused(self):
        for transform in [lambda p,v,q:v.update(scope='Synthetic'),lambda p,v,q:v['replica_counts'].pop('svs-2'),lambda p,v,q:p.update(min_samples_per_replica=2)]:
            with self.assertRaises(r.Refused):self.invoke(self.fixture(),transform)
    def test_parity_escalation_sql_and_budget_failures_block(self):
        for key in ['mismatches','escalations','cache_hit_sql_violations','p99_duration_us','p99_writer_fence_us','fallback_sql_reads']:
            with self.subTest(key=key),self.assertRaises(r.Refused):self.invoke(self.fixture(),lambda p,v,q:v.update({key:999999}))
    def test_cannot_skip_ramp_steps_or_use_boolean_budget(self):
        for transform in [lambda p,v,q:p.update(next_basis_points=10000),lambda p,v,q:p.update(min_samples_per_replica=True)]:
            with self.assertRaises(r.Refused):self.invoke(self.fixture(),transform)
    def test_all_sequential_ramp_steps_require_same_full_gate(self):
        for previous,next_tier in zip(r.TIERS,r.TIERS[1:]):
            out=self.invoke(self.fixture(),lambda p,v,q:(p.update(previous_basis_points=previous,next_basis_points=next_tier),q.update(observed_basis_points=previous)));self.assertEqual(next_tier,out['proposed_basis_points'])
    def test_signed_report_cannot_smuggle_fields_or_hide_observation_drift(self):
        for transform in [lambda p,v,q:v.update(token='private'),lambda p,v,q:v['observations'][0].update(identity_match=False),lambda p,v,q:v['observations'][0].update(replica='svs-2')]:
            with self.assertRaises(r.Refused):self.invoke(self.fixture(),transform)
    def test_controlled_two_replica_shadow_never_grants_on_drift(self):
        rows=[self.row('svs-'+str(1+i%2)) for i in range(200)];rows[101]['svs']['identity']['generation']=8;report=self.report(rows);self.assertEqual({'svs-1':100,'svs-2':100},report['replica_counts']);self.assertEqual(1,report['escalations']);self.assertFalse(report['grant_rights'])
    def test_report_and_policy_tampering_after_signing_is_refused(self):
        f=self.fixture();self.invoke(f);p,public,policy,report,packet,proof,now=f
        for changed_report,changed_policy in [(dict(report,samples=3),policy),(report,dict(policy,max_p99_us=999))]:
            with self.assertRaises(r.Refused):r.gate(enc(changed_report),enc(changed_policy),(p/'packet').read_bytes(),(p/'sig').read_bytes(),public,lambda _:proof,now)
    def test_cli_collect_creates_private_sanitized_output(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)
            for name,data in [('rows',enc(self.row())),('context',enc(self.context())),('jobkey',b'K'*32)]:
                (p/name).write_bytes(data);(p/name).chmod(0o600)
            args=[sys_executable(),r.__file__,'collect','--input',str(p/'rows'),'--context',str(p/'context'),'--job-key',str(p/'jobkey'),'--output',str(p/'out')]
            result=subprocess.run(args,capture_output=True,text=True);self.assertEqual(0,result.returncode);self.assertNotIn('private-shadow-fixture',result.stdout+result.stderr+(p/'out').read_text());self.assertEqual(0o600,(p/'out').stat().st_mode&0o777)
            (p/'out').unlink();(p/'rows').chmod(0o644);result=subprocess.run(args,capture_output=True,text=True);self.assertNotEqual(0,result.returncode);self.assertFalse((p/'out').exists())
    def test_cli_never_echoes_secret_or_filename_and_default_blocks(self):
        script=Path(r.__file__)
        result=subprocess.run([sys_executable(),str(script),'gate','--comparison','/private-fixture-secret','--policy','/private-fixture-secret','--public-key','/private-fixture-secret'],capture_output=True,text=True);self.assertNotEqual(0,result.returncode);self.assertNotIn('private-fixture-secret',result.stdout+result.stderr);self.assertEqual('NATIVE_QUALIFICATION_REQUIRED',json.loads(result.stdout)['code'])
def sys_executable():
    import sys
    return sys.executable
if __name__=='__main__':unittest.main()
