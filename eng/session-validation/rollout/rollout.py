#!/usr/bin/env python3
"""SVS-21 bounded private comparison and review-only promotion planning."""
import argparse,hashlib,hmac,json,math,os,re,resource,stat,subprocess,sys,tempfile,time
from pathlib import Path
MAX_BYTES=8*1024*1024
DECISIONS={'Active','Unauthenticated','Forbidden','Unavailable'}
TIERS=[0,100,500,2500,10000]
GATES={'database_readonly','cache_get_only','publisher_acl','writer_coverage','all_peer_barriers','revocation','mtls_rotation','owner_denial','isolation','native_parity','load_budget'}
class Refused(Exception):pass
def need(value,code):
    if not value:raise Refused(code)
def closed(value,keys):need(type(value) is dict and set(value)==set(keys),'SCHEMA_REFUSED')
def integer(v,low,high):need(type(v) is int and low<=v<=high,'BOUND_REFUSED');return v
def digest(v):need(type(v) is str and re.fullmatch('[a-f0-9]{64}',v) is not None,'DIGEST_REFUSED');return v
def unique(pairs):
    d={}
    for k,v in pairs:
        need(k not in d,'DUPLICATE_PROPERTY');d[k]=v
    return d
def decode(data):
    try:return json.loads(data,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(Refused('NONFINITE_REFUSED')))
    except Refused:raise
    except Exception:raise Refused('JSON_REFUSED') from None
def private_read(path,limit=MAX_BYTES):
    # Refuse links throughout the path and verify the opened inode; no path or
    # payload content is reflected in an error. Owned directory mounts still
    # require operator isolation against a hostile concurrent rename.
    p=Path(path);need(p.is_absolute() and '..' not in p.parts,'PRIVATE_INPUT_REQUIRED')
    need(not any(x.is_symlink() for x in [p,*p.parents]),'PRIVATE_INPUT_REQUIRED')
    try:
        fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as f:
            info=os.fstat(f.fileno());need(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode) in {0o400,0o600} and info.st_size<=limit,'PRIVATE_INPUT_REQUIRED')
            data=f.read(limit+1);need(len(data)<=limit,'INPUT_BOUND');return data
    except Refused:raise
    except Exception:raise Refused('PRIVATE_INPUT_REQUIRED') from None
def identity(v,decision):
    if decision!='Active':need(v is None,'SUBJECT_ON_REFUSAL');return None
    closed(v,['account','family','generation','protocol'])
    for key in ['account','family']:need(type(v[key]) is str and re.fullmatch('[0-9a-f]{32}',v[key]) is not None and v[key]!='0'*32,'IDENTITY_REFUSED')
    integer(v['generation'],1,2**63-1);integer(v['protocol'],2,2);return v

def collect(data,key,context):
    need(type(key) in {bytes,bytearray} and len(key)==32,'JOB_KEY_REQUIRED')
    closed(context,['version','scope','old_source_sha256','svs_source_sha256','replicas'])
    integer(context['version'],1,1);need(context['scope'] in {'Synthetic','GoldenReference','StagingTrustedSample'},'SCOPE_REFUSED')
    old=digest(context['old_source_sha256']);svs=digest(context['svs_source_sha256']);need(old!=svs,'INDEPENDENT_SOURCES_REQUIRED')
    replicas=context['replicas'];need(type(replicas) is list and 1<=len(replicas)<=8 and len(set(replicas))==len(replicas) and all(type(r) is str and re.fullmatch('svs-[1-8]',r) for r in replicas),'REPLICA_INVENTORY_REQUIRED')
    need(type(data) is bytes and 0<len(data)<=MAX_BYTES,'INPUT_BOUND')
    rows=data.splitlines();need(1<=len(rows)<=10000,'RECORD_BOUND')
    coverage={r:0 for r in replicas};out=[];durations=[];fences=[];mismatch=escalation=hit_sql=fallback=0
    for line in rows:
        need(0<len(line)<=16384,'RECORD_BOUND');v=decode(line)
        closed(v,['token','old','svs','replica','cache_hit','sql_reads','duration_us','writer_fence_us'])
        token=v['token'];need(type(token) is str and 1<=len(token)<=8192 and all(0x20<ord(c)<0x7f for c in token),'TOKEN_SHAPE_REFUSED')
        for k in ['old','svs']:
            closed(v[k],['decision','identity']);need(v[k]['decision'] in DECISIONS,'DECISION_REFUSED');identity(v[k]['identity'],v[k]['decision'])
        need(v['replica'] in coverage and type(v['cache_hit']) is bool,'REPLICA_OR_CACHE_REFUSED')
        sql=integer(v['sql_reads'],0,8);duration=integer(v['duration_us'],0,100000000);fence=integer(v['writer_fence_us'],0,100000000)
        same=v['old']==v['svs'];escalated=v['svs']['decision']=='Active' and (v['old']['decision']!='Active' or v['old']['identity']!=v['svs']['identity'])
        mismatch+=not same;escalation+=escalated;hit_sql+=v['cache_hit'] and sql!=0;fallback+=sql if not v['cache_hit'] else 0
        coverage[v['replica']]+=1;durations.append(duration);fences.append(fence)
        # Job-local keyed fingerprint only. Account/family IDs and tokens never
        # leave this process in exported evidence. Python cannot promise heap zeroing.
        out.append(dict(fingerprint=hmac.new(key,b'SVS21-shadow-v1\0'+token.encode('ascii'),hashlib.sha256).hexdigest(),old=v['old']['decision'],svs=v['svs']['decision'],identity_match=v['old']['identity']==v['svs']['identity'],replica=v['replica']))
    p99=lambda values:sorted(values)[math.ceil(len(values)*.99)-1]
    return dict(version=1,status='CollectedUnqualified',scope=context['scope'],old_source_sha256=old,svs_source_sha256=svs,replica_counts=coverage,samples=len(rows),mismatches=mismatch,escalations=escalation,cache_hit_sql_violations=hit_sql,fallback_sql_reads=fallback,p99_duration_us=p99(durations),p99_writer_fence_us=p99(fences),observations=out,native_acceptance='NotRun',grant_rights=False,release_ready=False)

def gate(report_bytes,policy_bytes,packet_bytes,signature,public_key,artifact_reader,now=None):
    now=int(time.time()) if now is None else now
    policy=decode(policy_bytes)
    closed(policy,['version','old_source_sha256','svs_source_sha256','trusted_key_sha256','replicas','min_samples_per_replica','max_p99_us','max_fallback_sql_reads','max_writer_fence_us','previous_basis_points','next_basis_points','packet_max_age_seconds'])
    integer(policy['version'],1,1);digest(policy['old_source_sha256']);digest(policy['svs_source_sha256']);need(policy['old_source_sha256']!=policy['svs_source_sha256'],'INDEPENDENT_SOURCES_REQUIRED')
    need(hashlib.sha256(public_key).hexdigest()==digest(policy['trusted_key_sha256']),'TRUST_KEY_REFUSED');need(type(signature) is bytes and len(signature)==64,'SIGNATURE_REFUSED')
    integer(policy['min_samples_per_replica'],1,10000);integer(policy['max_p99_us'],1,100000000);integer(policy['max_fallback_sql_reads'],0,80000);integer(policy['max_writer_fence_us'],1,100000000);integer(policy['packet_max_age_seconds'],1,86400)
    previous=integer(policy['previous_basis_points'],0,10000);next_tier=integer(policy['next_basis_points'],0,10000);need(previous in TIERS[:-1] and TIERS[TIERS.index(previous)+1]==next_tier,'RAMP_STEP_REFUSED')
    need(0<len(packet_bytes)<=65536 and len(public_key)<=8192,'SIGNATURE_REFUSED')
    with tempfile.TemporaryDirectory(prefix='svs21-verify-') as d:
        p=Path(d)
        for n,data in [('packet',packet_bytes),('signature',signature),('key',public_key)]:
            (p/n).write_bytes(data);(p/n).chmod(0o600)
        try:
            key_kind=subprocess.run(['openssl','pkey','-pubin','-in',str(p/'key'),'-outform','DER'],capture_output=True,timeout=5)
            need(key_kind.returncode==0 and len(key_kind.stdout)==44 and key_kind.stdout.startswith(bytes.fromhex('302a300506032b6570032100')),'ED25519_REQUIRED')
            r=subprocess.run(['openssl','pkeyutl','-verify','-pubin','-inkey',str(p/'key'),'-rawin','-in',str(p/'packet'),'-sigfile',str(p/'signature')],capture_output=True,timeout=5)
        except Exception:raise Refused('SIGNATURE_REFUSED') from None
        need(r.returncode==0,'SIGNATURE_REFUSED')
    packet=decode(packet_bytes)
    closed(packet,['version','kind','issued_at','expires_at','observed_basis_points','old_source_sha256','svs_source_sha256','comparison_sha256','approved_policy_sha256','checks','artifacts'])
    integer(packet['version'],1,1);need(packet['kind']=='NativeQualification','NATIVE_QUALIFICATION_REQUIRED');need(integer(packet['observed_basis_points'],0,10000)==previous,'PREVIOUS_STAGE_REFUSED')
    issued=integer(packet['issued_at'],0,2**63-1);expires=integer(packet['expires_at'],0,2**63-1);need(issued<=now<expires and 0<=now-issued<=policy['packet_max_age_seconds'] and expires-issued<=policy['packet_max_age_seconds'],'STALE_PACKET')
    need(packet['approved_policy_sha256']==hashlib.sha256(policy_bytes).hexdigest() and packet['comparison_sha256']==hashlib.sha256(report_bytes).hexdigest(),'ARTIFACT_BINDING_REFUSED')
    for n in ['old_source_sha256','svs_source_sha256']:need(packet[n]==policy[n],'SOURCE_BINDING_REFUSED')
    need(type(packet['checks']) is dict and set(packet['checks'])==GATES and type(packet['artifacts']) is dict and 1<=len(packet['artifacts'])<=32,'NATIVE_CHECKS_REQUIRED')
    for name,item in packet['artifacts'].items():
        need(re.fullmatch('[a-z][a-z0-9-]{0,63}',name) is not None,'ARTIFACT_NAME_REFUSED');closed(item,['path','sha256']);need(type(item['path']) is str,'ARTIFACT_REFUSED');need(hashlib.sha256(artifact_reader(item['path'])).hexdigest()==digest(item['sha256']),'ARTIFACT_DIGEST_REFUSED')
    for item in packet['checks'].values():
        closed(item,['status','artifact']);need(item['status']=='Passed' and item['artifact'] in packet['artifacts'],'NATIVE_CHECKS_REQUIRED')
    report=decode(report_bytes)
    closed(report,['version','status','scope','old_source_sha256','svs_source_sha256','replica_counts','samples','mismatches','escalations','cache_hit_sql_violations','fallback_sql_reads','p99_duration_us','p99_writer_fence_us','observations','native_acceptance','grant_rights','release_ready'])
    need(report.get('version')==1 and report.get('status')=='CollectedUnqualified' and report.get('scope')=='StagingTrustedSample' and report.get('native_acceptance')=='NotRun' and report.get('grant_rights') is False and report.get('release_ready') is False,'QUALIFIED_SAMPLE_REQUIRED')
    for n in ['old_source_sha256','svs_source_sha256']:need(report.get(n)==policy[n],'SOURCE_BINDING_REFUSED')
    replicas=policy['replicas'];need(type(replicas) is list and 1<=len(replicas)<=8 and all(type(r) is str and re.fullmatch('svs-[1-8]',r) for r in replicas) and len(set(replicas))==len(replicas),'REPLICA_INVENTORY_REQUIRED')
    coverage=report.get('replica_counts');need(type(coverage) is dict and set(coverage)==set(replicas),'REPLICA_COVERAGE_REQUIRED')
    for count in coverage.values():integer(count,policy['min_samples_per_replica'],10000)
    observations=report['observations'];need(type(observations) is list and len(observations)==report['samples'],'OBSERVATION_TOTAL_REFUSED')
    observed={name:0 for name in replicas};mismatches=escalations=0
    for item in observations:
        closed(item,['fingerprint','old','svs','identity_match','replica']);digest(item['fingerprint']);need(item['old'] in DECISIONS and item['svs'] in DECISIONS and type(item['identity_match']) is bool and item['replica'] in observed,'OBSERVATION_REFUSED')
        observed[item['replica']]+=1;mismatches+=item['old']!=item['svs'] or not item['identity_match'];escalations+=item['svs']=='Active' and (item['old']!='Active' or not item['identity_match'])
    need(observed==coverage and mismatches==report['mismatches'] and escalations==report['escalations'],'AGGREGATE_REFUSED')

    need(integer(report.get('samples'),1,10000)==sum(coverage.values()),'SAMPLE_TOTAL_REFUSED')
    for n in ['mismatches','escalations','cache_hit_sql_violations']:integer(report.get(n),0,0)
    integer(report.get('p99_duration_us'),0,policy['max_p99_us']);integer(report.get('p99_writer_fence_us'),0,policy['max_writer_fence_us']);integer(report.get('fallback_sql_reads'),0,policy['max_fallback_sql_reads'])
    return dict(status='ReviewPlanEligible',previous_basis_points=previous,proposed_basis_points=next_tier,deployment_commands_executed=0,configuration_applied=False,grant_rights=False,release_ready=False)

def private_write(path,value):
    p=Path(path);need(p.is_absolute() and not p.exists() and not p.is_symlink(),'NEW_PRIVATE_OUTPUT_REQUIRED')
    need(not any(x.is_symlink() for x in p.parents),'NEW_PRIVATE_OUTPUT_REQUIRED')
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as f:json.dump(value,f,sort_keys=True,separators=(',',':'));f.write('\n')
def main():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    a=argparse.ArgumentParser();s=a.add_subparsers(dest='command',required=True)
    c=s.add_parser('collect');c.add_argument('--input',required=True);c.add_argument('--job-key',required=True);c.add_argument('--context',required=True);c.add_argument('--output',required=True)
    g=s.add_parser('gate');g.add_argument('--comparison',required=True);g.add_argument('--policy',required=True);g.add_argument('--public-key',required=True);g.add_argument('--packet');g.add_argument('--signature')
    v=a.parse_args()
    if v.command=='collect':
        key=bytearray(private_read(v.job_key,32))
        try:result=collect(private_read(v.input),key,decode(private_read(v.context,8192)));private_write(v.output,result)
        finally:key[:]=b'\0'*len(key)
        print(json.dumps(dict(status='CollectedUnqualified',samples=result['samples'],grant_rights=False,release_ready=False)))
    else:
        need(v.packet is not None and v.signature is not None,'NATIVE_QUALIFICATION_REQUIRED')
        result=gate(private_read(v.comparison),private_read(v.policy,8192),private_read(v.packet,65536),private_read(v.signature,64),private_read(v.public_key,8192),private_read)
        print(json.dumps(result))
if __name__=='__main__':
    try:main()
    except Exception as e:
        print(json.dumps(dict(status='Blocked',code=str(e) if isinstance(e,Refused) else 'INPUT_REFUSED',deployment_commands_executed=0,grant_rights=False,release_ready=False)));sys.exit(1)
