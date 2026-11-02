#!/usr/bin/env python3
"""Static F02 evidence only. This does not execute or qualify YSQL account-state parity."""
from pathlib import Path
import hashlib
import json
import re

ROOT=Path(__file__).resolve().parents[2]

def inspect():
    path=ROOT/'Rigging/Database/Baseline/000_canonical_database.sql'
    sql=path.read_text()
    def function(name):
        matches=list(re.finditer(r'create or replace function\s+'+re.escape(name)+r'\s*\(',sql,re.I))
        if len(matches)!=1:
            raise ValueError('Expected exactly one current function definition: '+name)
        start=matches[0].start();end=sql.index('$$;',start)+3
        return sql[start:end]
    cold=function('get_session');warm=function('validate_cached_session_trust');resolver=function('cor20_resolve_account')
    result={
        'finding':'SVS00-F02','status':'OpenNativeAdjudicationRequired','scope':'Static source observation only; native cases NotRun',
        'sql_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
        'cold_get_session':{
            'explicit_verified_predicate':bool(re.search(r'\bverify_status\b',cold)),
            'explicit_unlock_predicate':bool(re.search(r'\bunlock_when\b',cold)),
            'account_stamp_match':bool(re.search(r's\.account_security_stamp\s*=\s*a\.security_stamp',cold)),
            'calls_entitlement_resolver':'cor20_resolve_account' in cold},
        'warm_validate_cached_session_trust':{
            'explicit_verified_predicate':bool(re.search(r'a\.verify_status\s*<>\s*1',warm)),
            'explicit_unlock_predicate':bool(re.search(r'a\.unlock_when\s*>\s*clock_timestamp\(\)',warm)),
            'account_authority_expired_code':"ACCOUNT_AUTHORITY_EXPIRED" in warm},
        'resolver':{
            'derives_account_live':'account_live:=a.verify_status=1' in resolver,
            'inactive_account_empties_capabilities':"if not account_live then capabilities:=array[]::text[]" in resolver,
            'volatile_and_mutating':'update accounts' in resolver and 'update sessions' in resolver},
        'decision':'Do not equate projection currentness or no capabilities with verified/unlocked identity; do not mark local HTTP mock results as native parity proof.',
        'owners':['SVS-04','SVS-05','SVS-12'],
        'required_native_cases':[
            'Verified, unlocked, current stamp/session: hot and cold accept the same subject.',
            'Unverified account with otherwise current session: hot and cold deny identity, not just one capability.',
            'Future unlock_when: hot and cold deny identity; include an Authenticate-only route as well as RequireCapability.',
            'Expired account cutoff and exact time boundaries: both deny.',
            'Account stamp changed, second login, rotation and logout: old credential cannot authorize on either path.',
            'Read projection with actual SVS DB credentials is nonmutating and cannot call write/lock-capable legacy resolver.'
        ],
        'native_cases_executed':0,'release_ready':False
    }
    return result

if __name__=='__main__':
    print(json.dumps(inspect(),indent=2))
