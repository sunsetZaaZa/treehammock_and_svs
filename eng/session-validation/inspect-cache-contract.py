#!/usr/bin/env python3
"""Static contract/scope consistency only; no native Dragonfly/YSQL or coherence qualification."""
from pathlib import Path
import json,re
S=Path(__file__).resolve().parents[2]
schema=json.loads((S/'contracts/coherent-cache-v1.schema.json').read_text());blocked,ready=schema['oneOf']
assert len(blocked['properties'])==8 and len(ready['properties'])==16
for obj in [blocked,ready,*[ready['properties'][n] for n in ['identity','lifetime','account','entitlements']]]:
 assert obj['additionalProperties'] is False and set(obj['required'])==set(obj['properties'])
for n in ['revision']:assert ready['properties'][n]['type']=='string'
assert ready['properties']['identity']['properties']['generation']['type']=='string'
assert ready['properties']['entitlements']['properties']['version']['type']=='string'
acl=json.loads((S/'deploy/session-validation/SVS06_CACHE_ACL_REQUIREMENTS.json').read_text());assert acl['data_commands']==['GET'] and not acl['native_qualified']
reader=(S/'src/Treehammock.SessionValidation.Storage/CoherentSessionCacheReader.cs').read_text()
assert 'CommandFlags.DemandMaster|CommandFlags.NoRedirect' in reader
assert 'internal static SessionCacheAdmission ForQualification' in reader
assert not re.search(r'public\s+\w+\s+Enable\b|StringSetAsync|KeyDeleteAsync|ScriptEvaluateAsync|Npgsql',reader)
assert 'CredentialKey(hash)' in reader and 'AccountKey(account)' in reader
coordinator=(S/'src/Treehammock.SessionValidation.Storage/SessionEvidenceCoordinator.cs').read_text()
assert 'GetByteCount(credential)>8192' in coordinator and 'TimeSpan.FromSeconds(5)' in coordinator
assert 'cache.ReadAsync' in coordinator and 'ReadOwned(hash' in coordinator
print(json.dumps(dict(status='PASS',schema_version=1,blocked_fields=8,ready_fields=16,validator_data_commands=['GET'],public_enable_path=False,scope='Source structure only; no actual ACL, CAS, primary, writer or failover proof',native_cases_executed=0),indent=2))
