import copy,hashlib,json,os,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
import qualification as q
class QualificationTests(unittest.TestCase):
    def plan(self):
        budgets=dict(min_requests_per_replica=1,min_requests_per_second_per_server_core=1,max_p99_us=1000,max_sql_read_p99_us=1000,max_pool_wait_p99_us=1000,max_server_cpu_percent=100,max_working_set_bytes=100000,max_file_descriptors=100,max_writer_fence_p99_us=1000,max_revocation_lag_us=1000,max_fallback_sql_reads=100,max_publisher_writes=100)
        return dict(version=1,run_id='1'*32,scope='IsolatedStaging',source_sha256='a'*64,inventory_sha256='b'*64,replicas=['svs-1','svs-2'],benchmark_dll='/private/benchmark.dll',benchmark_sha256='c'*64,dotnet='/private/dotnet',hook='/private/hook.py',hook_sha256='d'*64,budgets=budgets,phases=[dict(name=n,duration_seconds=86460 if n=='soak-24h' else 10,concurrency=4,requests_per_second=100,request_limit=100000000,clients_file='/private/clients.json',vectors_file='/private/vectors.json') for n in q.PHASES])
    def bench(self):return dict(status='Completed',requests=100,unexpectedDecisions=0,falseActive=0,tupleMismatches=0,latencyOverflow=0,seconds=10,p50Us=64,p95Us=128,p99Us=256,replicaSamples={'svs-1':50,'svs-2':50},decisions=dict(Active=100,Unauthenticated=0,Forbidden=0,Unavailable=0),nativeQualified=False,grantRights=False,releaseReady=False)
    def observer(self,phase='hot-cache'):
        row=dict(cores=1,cpu_seconds=1,working_set_peak_bytes=10000,file_descriptors_peak=10,sql_read_p99_us=10,pool_wait_p99_us=10,writer_fence_p99_us=10,revocation_lag_us=10,hit_requests=50,hit_sql=0,hit_control=0,hit_hint=0,fallback_sql_reads=0,publisher_writes=0,mutation_samples=0,mutation_false_active=0,writer_fence_samples=0)
        return dict(version=1,phase=phase,source_sha256='a'*64,inventory_sha256='b'*64,run_id='1'*32,fault_verified=True,isolation_verified=True,credentials_only_synthetic=True,elapsed_seconds=10,proof_sha256='e'*64,servers={'svs-1':row,'svs-2':row.copy()})
    def test_schedule_contains_all_drills_and_real_24h_minimum(self):
        p=q.schedule();self.assertEqual(15,len(p['phase_order']));self.assertGreaterEqual(p['soak_seconds'],86400);self.assertFalse(p['release_ready'])
    def test_complete_plan_is_valid_but_not_a_native_approval(self):self.assertEqual(self.plan(),q.validate_plan(self.plan()))
    def test_missing_reordered_or_duplicated_drill_refused(self):
        for transform in [lambda p:p['phases'].pop(),lambda p:p['phases'].reverse(),lambda p:p['phases'].append(p['phases'][0])]:
            p=self.plan();transform(p)
            with self.assertRaises(q.Refused):q.validate_plan(p)
    def test_invalid_scope_single_replica_and_short_soak_refused(self):
        for transform in [lambda p:p.update(scope='Production'),lambda p:p.update(replicas=['svs-1']),lambda p:p['phases'][-1].update(duration_seconds=3600)]:
            p=self.plan();transform(p)
            with self.assertRaises(q.Refused):q.validate_plan(p)
    def test_boolean_nonfinite_and_out_of_range_budgets_refused(self):
        for value in [True,0,-1,float('nan'),float('inf')]:
            p=self.plan();p['budgets']['max_p99_us']=value
            with self.assertRaises(q.Refused):q.validate_plan(p)
    def test_limits_and_unknown_fields_refused(self):
        for transform in [lambda p:p['phases'][0].update(concurrency=65),lambda p:p.update(extra='private'),lambda p:p['phases'][0].update(request_limit=100000001)]:
            p=self.plan();transform(p)
            with self.assertRaises(q.Refused):q.validate_plan(p)
    def test_observer_success_is_pending_independent_review(self):
        out=q.observer_check(self.plan(),'hot-cache',self.bench(),self.observer());self.assertEqual('BudgetChecksPassedPendingIndependentReview',out['status']);self.assertFalse(out['release_ready']);self.assertEqual('Unqualified',out['native_acceptance'])
    def test_source_inventory_run_id_phase_binding_refused(self):
        for key,value in [('source_sha256','c'*64),('inventory_sha256','c'*64),('run_id','c'*32),('phase','soak-24h')]:
            o=self.observer();o[key]=value
            with self.assertRaises(q.Refused):q.observer_check(self.plan(),'hot-cache',self.bench(),o)
    def test_fault_isolation_and_real_synthetic_credentials_required(self):
        for key in ['fault_verified','isolation_verified','credentials_only_synthetic']:
            o=self.observer();o[key]=False
            with self.assertRaises(q.Refused):q.observer_check(self.plan(),'hot-cache',self.bench(),o)
    def test_false_active_drift_errors_or_overflow_block(self):
        for key in ['falseActive','unexpectedDecisions','tupleMismatches','latencyOverflow']:
            b=self.bench();b[key]=1
            with self.assertRaises(q.Refused):q.observer_check(self.plan(),'hot-cache',b,self.observer())
    def test_cancelled_or_forged_native_pass_does_not_qualify(self):
        for update in [dict(status='Cancelled'),dict(nativeQualified=True),dict(grantRights=True),dict(releaseReady=True)]:
            b=self.bench();b.update(update)
            with self.assertRaises(q.Refused):q.observer_check(self.plan(),'hot-cache',b,self.observer())
    def test_absent_replica_no_samples_and_counter_total_refused(self):
        for transform in [lambda b:b['replicaSamples'].pop('svs-2'),lambda b:b['replicaSamples'].update({'svs-2':0}),lambda b:b['decisions'].update(Active=99)]:
            b=self.bench();transform(b)
            with self.assertRaises(q.Refused):q.observer_check(self.plan(),'hot-cache',b,self.observer())
    def test_cache_hit_sql_control_and_hint_are_all_zero(self):
        for key in ['hit_sql','hit_control','hit_hint']:
            o=self.observer();o['servers']['svs-1'][key]=1
            with self.assertRaises(q.Refused):q.observer_check(self.plan(),'hot-cache',self.bench(),o)
    def test_native_resource_fence_lag_sql_and_pressure_budgets(self):
        for key in ['working_set_peak_bytes','file_descriptors_peak','sql_read_p99_us','pool_wait_p99_us','writer_fence_p99_us','revocation_lag_us','fallback_sql_reads','publisher_writes','cpu_seconds']:
            o=self.observer();o['servers']['svs-1'][key]=100000001
            with self.subTest(key=key),self.assertRaises(q.Refused):q.observer_check(self.plan(),'hot-cache',self.bench(),o)
    def test_native_server_core_throughput_not_driver_cpu_is_used(self):
        p=self.plan();p['budgets']['min_requests_per_second_per_server_core']=6
        with self.assertRaises(q.Refused):q.observer_check(p,'hot-cache',self.bench(),self.observer())
    def test_soak_cannot_be_declared_from_short_run_or_zero_hits(self):
        b=self.bench();o=self.observer('soak-24h')
        with self.assertRaises(q.Refused):q.observer_check(self.plan(),'soak-24h',b,o)
        b.update(seconds=86400,requests=10000000,replicaSamples={'svs-1':5000000,'svs-2':5000000},decisions=dict(Active=10000000,Unauthenticated=0,Forbidden=0,Unavailable=0));o['elapsed_seconds']=86400;self.assertEqual('Unqualified',q.observer_check(self.plan(),'soak-24h',b,o)['native_acceptance']);o['servers']['svs-1']['hit_requests']=0;o['servers']['svs-2']['hit_requests']=0
        with self.assertRaises(q.Refused):q.observer_check(self.plan(),'soak-24h',b,o)
    def test_observer_unknown_fields_and_nonfinite_values_refused(self):
        for transform in [lambda o:o.update(token='private'),lambda o:o.update(elapsed_seconds=float('nan')),lambda o:o['servers']['svs-1'].update(cpu_seconds=True)]:
            o=self.observer();transform(o)
            with self.assertRaises(q.Refused):q.observer_check(self.plan(),'hot-cache',self.bench(),o)
    def test_concurrent_mutation_phase_requires_real_witness_samples(self):
        o=self.observer('refresh-race')
        with self.assertRaises(q.Refused):q.observer_check(self.plan(),'refresh-race',self.bench(),o)
        o['servers']['svs-1'].update(mutation_samples=2,writer_fence_samples=2);q.observer_check(self.plan(),'refresh-race',self.bench(),o)
        o['servers']['svs-1']['mutation_false_active']=1
        with self.assertRaises(q.Refused):q.observer_check(self.plan(),'refresh-race',self.bench(),o)
    def test_private_subprocess_output_and_errors_do_not_echo_secrets(self):
        self.assertEqual({'safe':True},q.invoke([sys.executable,'-c','import json,sys; x=json.load(sys.stdin); print(json.dumps({"safe":bool(x)}))'],{'private':'fixture'},2))
        with self.assertRaises(q.Refused) as e:q.invoke([sys.executable,'-c','import sys; print("private-fixture",file=sys.stderr); sys.exit(1)'],{},2)
        self.assertNotIn('private-fixture',str(e.exception))
    def test_timeout_stops_child_process_group(self):
        start=time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):q.invoke([sys.executable,'-c','import time; time.sleep(30)'],{},.1)
        self.assertLess(time.monotonic()-start,3)
    def test_partial_run_always_requests_owned_cleanup(self):
        with tempfile.TemporaryDirectory() as d:
            plan=self.plan();blob=b'fixture';plan['benchmark_sha256']=plan['hook_sha256']=hashlib.sha256(blob).hexdigest();calls=[]
            def invoke(argv,payload,timeout):
                op=payload['operation'];calls.append(op)
                if op=='preflight':return dict(status='Prepared',run_id=plan['run_id'],inventory_sha256=plan['inventory_sha256'])
                if op=='cleanup':return dict(status='Cleaned',run_id=plan['run_id'])
                raise q.Refused('FIXTURE_FAULT')
            with patch.object(q,'private_read',return_value=blob),patch.object(q,'invoke',side_effect=invoke),self.assertRaises(q.Refused):q.run(plan,str(Path(d)/'out'))
            self.assertEqual('cleanup',calls[-1]);status=json.loads((Path(d)/'out/RUN_STATUS.json').read_text());self.assertTrue(status['cleanup_verified']);self.assertEqual('Interrupted',status['status'])
    def test_cli_schedule_never_approves_native(self):
        p=subprocess.run([sys.executable,str(Path(q.__file__)),'schedule'],capture_output=True,text=True,check=True);self.assertEqual('NotRun',json.loads(p.stdout)['native_acceptance'])
if __name__=='__main__':unittest.main()
