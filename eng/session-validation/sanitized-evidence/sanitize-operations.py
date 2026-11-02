#!/usr/bin/env python3
"""Closed-schema advisory export/reconciliation. Never echoes refused input."""
import argparse,json,sys
from pathlib import Path
class Refused(RuntimeError):pass
BOOLS={'live','ready','databaseFallbackReady','cacheReady','refillReady','authorityWriteReady','serverCertificateNearExpiry','clockOffsetKnown'}
def sanitize(v):
    if not isinstance(v,dict) or set(v)!={'health','requests'}:raise Refused('SNAPSHOT_SCHEMA_REFUSED')
    h=v['health'];r=v['requests']
    if not isinstance(h,dict) or set(h)!=BOOLS|{'mode'} or any(type(h[k]) is not bool for k in BOOLS) or h['mode'] not in {'NotReady','CacheReady','DatabaseFallbackReady','CacheAndDatabaseReady'} or h['authorityWriteReady'] or h['clockOffsetKnown']:raise Refused('HEALTH_SCHEMA_REFUSED')
    if not isinstance(r,dict) or set(r)!={'capacity','active','peak','accepted','rejected','queued'} or any(type(x) is not int or not 0<=x<2**63 for x in r.values()) or not 1<=r['capacity']<=2048 or not r['active']<=r['peak']<=r['capacity'] or r['queued']!=0:raise Refused('CAPACITY_SCHEMA_REFUSED')
    mode='NotReady' if not h['ready'] else 'CacheAndDatabaseReady' if h['cacheReady'] and h['databaseFallbackReady'] else 'CacheReady' if h['cacheReady'] else 'DatabaseFallbackReady'
    if h['mode']!=mode or h['ready'] and not(h['live'] and (h['cacheReady'] or h['databaseFallbackReady'])):raise Refused('INCONSISTENT_ADVISORY_SNAPSHOT')
    return dict(schema='svs-operations.v1',snapshot=v,native_execution='NotRun',grant_rights=False,release_ready=False)
def reconcile(v):
    sanitize(v);h=v['health'];r=v['requests'];a=[]
    if not h['ready']:a.append('KEEP_FAIL_CLOSED_AND_INSPECT_FLEET')
    if h['cacheReady'] and not h['databaseFallbackReady']:a.append('PRESERVE_CACHE_BOUNDS_RESTORE_DATABASE_NO_FORCED_ADMISSION')
    if h['databaseFallbackReady'] and not h['cacheReady']:a.append('PRESERVE_SQL_RESERVE_VERIFY_CACHE_IDENTITY_EPOCH')
    if h['cacheReady'] and not h['refillReady']:a.append('INSPECT_LOCAL_REFILL_WITHOUT_INVALIDATING_VALID_HITS')
    if h['serverCertificateNearExpiry']:a.append('PLAN_KEY_ROTATION_WITH_COMPLETE_DRAIN_BARRIER')
    if not h['clockOffsetKnown']:a.append('VERIFY_EXTERNAL_CLOCK_OFFSET')
    if r['active']==r['capacity']:a.append('OBSERVED_REQUEST_SATURATION')
    if r['rejected']:a.append('REVIEW_REJECTION_RATE_AND_WRITER_RESERVE')
    return dict(status='RecommendationsOnly',actions=a,commands_executed=0,grant_rights=False,release_ready=False)
def unique(pairs):
    d={}
    for k,v in pairs:
        if k in d:raise Refused('DUPLICATE_FIELD_REFUSED')
        d[k]=v
    return d
def main():
    p=argparse.ArgumentParser();p.add_argument('input',type=Path);p.add_argument('--reconcile',action='store_true');a=p.parse_args()
    if not a.input.is_file() or a.input.is_symlink() or a.input.stat().st_size>16384:raise Refused('BOUNDED_SNAPSHOT_REQUIRED')
    v=json.loads(a.input.read_text(),object_pairs_hook=unique);print(json.dumps(reconcile(v) if a.reconcile else sanitize(v),sort_keys=True))
if __name__=='__main__':
    try:main()
    except Exception as e:print(json.dumps(dict(status='Refused',code=str(e) if isinstance(e,Refused) else 'SANITIZATION_FAILED')));sys.exit(1)
