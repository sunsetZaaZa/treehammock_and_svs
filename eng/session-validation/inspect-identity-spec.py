#!/usr/bin/env python3
"""Source consistency checks only. Does not parse/execute YSQL or qualify actual ACLs."""
from pathlib import Path
import hashlib,json,re
S=Path(__file__).resolve().parents[2]
spec=json.loads((S/'deploy/session-validation/validator-role-specification.json').read_text());sql=(S/'Rigging/Database/Baseline/000_canonical_database.sql').read_text()
assert len(spec['functions'])==9 and sum(len(x) for x in spec['columns'].values())==44
for f in spec['functions']:
 name=f['signature'].split('.')[1].split('(')[0];m=re.search(r'create or replace function '+name+r'\s*\(.*?\$\$(.*?)\$\$;',sql,re.I|re.S);assert m
 assert hashlib.sha256(m[1].encode()).hexdigest()==f['source_sha256']
 assert not re.search(r'\bsecurity\s+definer\b',m[0],re.I)
provision=(S/'deploy/session-validation/sql/provision-validator-identity.sql').read_text()
actual={t:set(c.strip() for c in cs.split(',')) for cs,t in re.findall(r'^grant select \(([^)]+)\) on (public\.\w+) to treehammock_svs_read;',provision,re.M)}
assert actual=={t:set(cs) for t,cs in spec['columns'].items()}
assert set(re.findall(r'^grant execute on function (.+) to treehammock_svs_read;',provision,re.M))=={f['signature'] for f in spec['functions']}
assert ':\'preserve_roles\'' in provision and 'connection limit 16' in provision
remove=(S/'deploy/session-validation/sql/remove-validator-identity.sql').read_text()
assert not re.search(r'\bdrop\s+owned\b|\bcascade\b',remove,re.I)
print(json.dumps(dict(status='PASS',required_columns=44,pure_function_closure=9,source_fingerprints_match=True,grant_statements_match=True,scope='Static source consistency only; SQL syntax/DDL/native permissions not executed',native_cases_executed=0),indent=2))
