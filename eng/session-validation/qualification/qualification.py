#!/usr/bin/env python3
"""SVS-22 private, bounded load/soak driver and independent-observer checks."""
import argparse,hashlib,json,math,os,resource,signal,subprocess,sys,tempfile,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'rollout'))
from rollout import Refused,need,closed,integer,digest,decode,private_read,private_write
PHASES=['cold-cache','hot-cache','mixed-refusals','login-storm','refresh-race','logout-race','ysql-leader-transfer','cache-loss','refill-outage','replica-loss','haproxy-failover','tls-rotation','network-partition','recovery','soak-24h']
MAX_OUTPUT=1048576

def schedule():
    return dict(version=1,status='PendingIsolatedNativeTargets',phase_order=PHASES,soak_seconds=86460,minimum_measured_soak_seconds=86400,maximum_worker_count=64,requires_approved_budgets=True,requires_source_bound_observer=True,native_acceptance='NotRun',grant_rights=False,release_ready=False)
def finite(v,low,high):need(type(v) in {int,float} and math.isfinite(v) and low<=v<=high,'METRIC_BOUND');return v
def validate_plan(v):
    closed(v,['version','run_id','scope','source_sha256','inventory_sha256','replicas','benchmark_dll','benchmark_sha256','dotnet','hook','hook_sha256','budgets','phases'])
    integer(v['version'],1,1);need(type(v['run_id']) is str and __import__('re').fullmatch('[a-f0-9]{32}',v['run_id']),'RUN_ID_REQUIRED');need(v['scope']=='IsolatedStaging','ISOLATED_TARGETS_REQUIRED');digest(v['source_sha256']);digest(v['inventory_sha256']);digest(v['benchmark_sha256']);digest(v['hook_sha256'])
    replicas=v['replicas'];need(type(replicas) is list and 2<=len(replicas)<=8 and len(set(replicas))==len(replicas) and all(r in ['svs-'+str(i) for i in range(1,9)] for r in replicas),'PHYSICAL_REPLICAS_REQUIRED')
    for n in ['benchmark_dll','dotnet','hook']:need(type(v[n]) is str and Path(v[n]).is_absolute() and '..' not in Path(v[n]).parts,'ABSOLUTE_TOOL_REQUIRED')
    b=v['budgets'];closed(b,['min_requests_per_replica','min_requests_per_second_per_server_core','max_p99_us','max_sql_read_p99_us','max_pool_wait_p99_us','max_server_cpu_percent','max_working_set_bytes','max_file_descriptors','max_writer_fence_p99_us','max_revocation_lag_us','max_fallback_sql_reads','max_publisher_writes'])
    for n,x in b.items():integer(x,0 if n in {'max_fallback_sql_reads','max_publisher_writes'} else 1,2**53-1)
    need(type(v['phases']) is list and [p.get('name') for p in v['phases']]==PHASES,'COMPLETE_DRILL_SCHEDULE_REQUIRED')
    for p in v['phases']:
        closed(p,['name','duration_seconds','concurrency','requests_per_second','request_limit','clients_file','vectors_file']);integer(p['duration_seconds'],1,90000);integer(p['concurrency'],1,64);integer(p['requests_per_second'],1,100000);integer(p['request_limit'],1,100000000)
        if p['name']=='soak-24h':need(p['duration_seconds']>=86460,'FULL_SOAK_REQUIRED')
        for key in ['clients_file','vectors_file']:need(type(p[key]) is str and Path(p[key]).is_absolute(),'PRIVATE_VECTOR_INPUT_REQUIRED')
    return v

def observer_check(plan,phase,bench,observer):
    closed(observer,['version','phase','source_sha256','inventory_sha256','run_id','fault_verified','isolation_verified','credentials_only_synthetic','elapsed_seconds','proof_sha256','servers'])
    integer(observer['version'],1,1);need(digest(observer['proof_sha256'])!='0'*64,'NATIVE_TRACE_REQUIRED');need(observer['phase']==phase and observer['source_sha256']==plan['source_sha256'] and observer['inventory_sha256']==plan['inventory_sha256'] and observer['run_id']==plan['run_id'],'OBSERVER_BINDING_REFUSED')
    for n in ['fault_verified','isolation_verified','credentials_only_synthetic']:need(observer[n] is True,'FAULT_OR_ISOLATION_UNPROVEN')
    need(bench.get('status')=='Completed' and bench.get('nativeQualified') is False and bench.get('grantRights') is False and bench.get('releaseReady') is False,'BENCHMARK_NOT_COMPLETE')
    finite(bench['seconds'],.001,90030);finite(observer['elapsed_seconds'],bench['seconds'],90100)
    for key in ['falseActive','unexpectedDecisions','tupleMismatches','latencyOverflow']:integer(bench[key],0,0)
    phase_plan=next(p for p in plan['phases'] if p['name']==phase);need(bench['seconds']>=(86400 if phase=='soak-24h' else phase_plan['duration_seconds']),'PHASE_NOT_COMPLETED')
    need(bench['p50Us']<=bench['p95Us']<=bench['p99Us'],'QUANTILE_ORDER')
    for key in ['p50Us','p95Us','p99Us']:integer(bench[key],0,plan['budgets']['max_p99_us'])
    need(type(bench['replicaSamples']) is dict and set(bench['replicaSamples'])==set(plan['replicas']),'BENCHMARK_REPLICA_GAP')
    for value in bench['replicaSamples'].values():integer(value,plan['budgets']['min_requests_per_replica'],100000000)
    integer(bench['requests'],1,100000000);need(sum(bench['replicaSamples'].values())==bench['requests'],'BENCHMARK_TOTAL')
    need(type(bench['decisions']) is dict and set(bench['decisions'])=={'Active','Unauthenticated','Forbidden','Unavailable'},'DECISION_COUNTERS')
    for x in bench['decisions'].values():integer(x,0,100000000)
    need(sum(bench['decisions'].values())==bench['requests'],'DECISION_TOTAL')
    need(type(observer['servers']) is dict and set(observer['servers'])==set(plan['replicas']),'OBSERVER_REPLICA_GAP');cores=0;hits=0;mutation_samples=0;writer_samples=0
    metric_keys=['cores','cpu_seconds','working_set_peak_bytes','file_descriptors_peak','sql_read_p99_us','pool_wait_p99_us','writer_fence_p99_us','revocation_lag_us','hit_requests','hit_sql','hit_control','hit_hint','fallback_sql_reads','publisher_writes','mutation_samples','mutation_false_active','writer_fence_samples']
    b=plan['budgets']
    for row in observer['servers'].values():
        closed(row,metric_keys);cores+=integer(row['cores'],1,1024);finite(row['cpu_seconds'],0,90000000)
        need(row['cpu_seconds']/observer['elapsed_seconds']/row['cores']*100<=b['max_server_cpu_percent'],'SERVER_CPU_BUDGET')
        for metric,budget in [('working_set_peak_bytes','max_working_set_bytes'),('file_descriptors_peak','max_file_descriptors'),('sql_read_p99_us','max_sql_read_p99_us'),('pool_wait_p99_us','max_pool_wait_p99_us'),('writer_fence_p99_us','max_writer_fence_p99_us'),('revocation_lag_us','max_revocation_lag_us'),('fallback_sql_reads','max_fallback_sql_reads'),('publisher_writes','max_publisher_writes')]:integer(row[metric],0,b[budget])
        hits+=integer(row['hit_requests'],0,100000000);mutation_samples+=integer(row['mutation_samples'],0,100000000);writer_samples+=integer(row['writer_fence_samples'],0,100000000);integer(row['mutation_false_active'],0,0)
        for key in ['hit_sql','hit_control','hit_hint']:integer(row[key],0,0)
    need(bench['requests']/bench['seconds']/cores>=b['min_requests_per_second_per_server_core'],'THROUGHPUT_BUDGET')
    if phase in {'login-storm','refresh-race','logout-race'}:need(mutation_samples>0 and writer_samples>0,'MUTATION_WITNESS_REQUIRED')
    if phase in {'hot-cache','soak-24h'}:need(hits>0,'NO_CACHE_HIT_OBSERVATION')
    if phase=='soak-24h':need(bench['seconds']>=86400 and observer['elapsed_seconds']>=86400,'SOAK_NOT_COMPLETED')
    return dict(phase=phase,status='BudgetChecksPassedPendingIndependentReview',source_sha256=plan['source_sha256'],inventory_sha256=plan['inventory_sha256'],run_id=plan['run_id'],native_acceptance='Unqualified',grant_rights=False,release_ready=False)

def child_limit():resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_FSIZE,(MAX_OUTPUT,MAX_OUTPUT))
def invoke(argv,payload,timeout):
    # No shell, no raw stderr, bounded disk output, and a separately cancellable
    # process group. Environment contains only runtime locations, never tokens.
    env={k:os.environ[k] for k in ['PATH','DOTNET_ROOT','DOTNET_PROCESSOR_COUNT'] if k in os.environ};env['DOTNET_CLI_TELEMETRY_OPTOUT']='1'
    with tempfile.TemporaryFile() as out:
        p=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=out,stderr=subprocess.DEVNULL,env=env,start_new_session=True,preexec_fn=child_limit)
        try:
            p.communicate(json.dumps(payload,separators=(',',':')).encode(),timeout=timeout);need(p.returncode==0,'CHILD_FAILED');out.seek(0);data=out.read(MAX_OUTPUT+1);need(len(data)<=MAX_OUTPUT,'CHILD_OUTPUT_BOUND');return decode(data)
        finally:
            if p.poll() is None:
                os.killpg(p.pid,signal.SIGTERM)
                try:p.wait(timeout=5)
                except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()

def run(plan,output):
    validate_plan(plan);need(Path(output).is_absolute() and not Path(output).exists(),'NEW_PRIVATE_OUTPUT_REQUIRED')
    # Binary/hook bytes and parent paths are independently owned/reviewed input.
    need(hashlib.sha256(private_read(plan['benchmark_dll'],16*1024*1024)).hexdigest()==plan['benchmark_sha256'],'BENCHMARK_DIGEST')
    need(hashlib.sha256(private_read(plan['hook'],MAX_OUTPUT)).hexdigest()==plan['hook_sha256'],'HOOK_DIGEST')
    output=Path(output);output.mkdir(mode=0o700);records=[];cleanup=False;outcome='Interrupted';cleanup_ok=False
    def hook(operation,phase=None):
        return invoke([sys.executable,plan['hook']],dict(version=1,operation=operation,phase=phase,run_id=plan['run_id'],scope=plan['scope'],source_sha256=plan['source_sha256'],inventory_sha256=plan['inventory_sha256']),120)
    try:
        # Mark cleanup before preflight: an adapter that fails after allocating
        # owned resources must still receive idempotent cleanup for this run id.
        cleanup=True;prepared=hook('preflight');need(prepared==dict(status='Prepared',run_id=plan['run_id'],inventory_sha256=plan['inventory_sha256']),'OWNED_PREFLIGHT_REFUSED')
        for phase in plan['phases']:
            name=phase['name'];need(hook('begin',name)==dict(status='Begun',run_id=plan['run_id'],phase=name),'FAULT_BEGIN_UNVERIFIED')
            try:
                clients=decode(private_read(phase['clients_file'],65536));vectors=decode(private_read(phase['vectors_file'],262144))
                need(type(clients) is list and {c['replica'] for c in clients}==set(plan['replicas']) and len(clients)==len(plan['replicas']),'EXACT_CLIENT_INVENTORY_REQUIRED')
                # Vectors file contains credential file paths, never inline tokens.
                need(type(vectors) is list and 1<=len(vectors)<=8,'VECTOR_BOUND');materialized=[]
                for vector in vectors:
                    closed(vector,['label','credential_file','action','expectedDecision','account','family','generation','protocol']);entry={k:v for k,v in vector.items() if k!='credential_file'};entry['credential']=private_read(vector['credential_file'],8192).decode('ascii').strip();materialized.append(entry)
                payload=dict(clients=clients,vectors=materialized,durationSeconds=phase['duration_seconds'],concurrency=phase['concurrency'],requestsPerSecond=phase['requests_per_second'],requestLimit=phase['request_limit'])
                bench=invoke([plan['dotnet'],plan['benchmark_dll'],'--stdin'],payload,phase['duration_seconds']+30);observer=hook('observe',name);check=observer_check(plan,name,bench,observer);record=dict(check=check,benchmark=bench,observer=observer);private_write(output/(name+'.json'),record);records.append(check)
            finally:need(hook('end',name)==dict(status='Ended',run_id=plan['run_id'],phase=name),'FAULT_END_UNVERIFIED')
        outcome='MeasuredUnqualified'
    finally:
        if cleanup:
            try:cleanup_ok=hook('cleanup')==dict(status='Cleaned',run_id=plan['run_id'])
            except Exception:cleanup_ok=False
        private_write(output/'RUN_STATUS.json',dict(status=outcome if cleanup_ok else 'CleanupUnverified',completed_phases=len(records),cleanup_verified=cleanup_ok,native_acceptance='Unqualified',grant_rights=False,release_ready=False))
    need(cleanup_ok,'CLEANUP_NOT_VERIFIED');return dict(status=outcome,completed_phases=len(records),native_acceptance='Unqualified',grant_rights=False,release_ready=False)
def main():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));signal.signal(signal.SIGTERM,lambda *_:(_ for _ in ()).throw(KeyboardInterrupt()));a=argparse.ArgumentParser();s=a.add_subparsers(dest='command',required=True);s.add_parser('schedule');r=s.add_parser('run');r.add_argument('--plan',required=True);r.add_argument('--output',required=True);v=a.parse_args()
    if v.command=='schedule':print(json.dumps(schedule()))
    else:print(json.dumps(run(decode(private_read(v.plan,65536)),v.output)))
if __name__=='__main__':
    try:main()
    except BaseException as e:
        print(json.dumps(dict(status='Blocked',code=str(e) if isinstance(e,Refused) else 'QUALIFICATION_INTERRUPTED_OR_REFUSED',native_acceptance='NotRun',grant_rights=False,release_ready=False)));sys.exit(1)
