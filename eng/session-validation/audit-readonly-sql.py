#!/usr/bin/env python3
"""Conservative current-source dependency audit; never a substitute for native role/snapshot proof."""
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
SQL=ROOT/'Rigging/Database/Baseline/000_canonical_database.sql'

def audit():
    text=SQL.read_text()
    assert text==(SQL.parent/'000_treehammock_canonical_database.sql').read_text()
    pattern=r'create\s+or\s+replace\s+function\s+(\w+)\s*\(.*?\$\$;'
    funcs={m[1].lower():m[0] for m in re.finditer(pattern,text,re.I|re.S)}
    tables=set(re.findall(r'create\s+table\s+(?:if\s+not\s+exists\s+)?(\w+)',text,re.I))
    triggers=[]
    for m in re.finditer(r'create\s+(?:constraint\s+)?trigger\s+(\w+)\b.*?\bon\s+(\w+)\b.*?execute\s+(?:function|procedure)\s+(\w+)\(',text,re.I|re.S):
        triggers.append(dict(name=m[1],table=m[2],function=m[3]))
    def calls(body):return sorted(n for n in funcs if re.search(r'(?<!function )\b'+re.escape(n)+r'\s*\(',body.split('$$',1)[-1],re.I))
    def writes(body):return sorted(set(re.findall(r'\b(?:update|insert\s+into|delete\s+from)\s+(?:public\.)?(\w+)',body,re.I))&tables)
    def closure(roots,include_triggers):
        seen=set();todo=list(roots)
        while todo:
            n=todo.pop()
            if n in seen:continue
            seen.add(n);body=funcs[n];todo+=calls(body)
            if include_triggers:
                todo += [t['function'] for t in triggers if t['table'] in writes(body) and t['function'] in funcs]
        return sorted(seen)
    old=closure(['get_session','validate_cached_session_trust','cor02_lock_account_authority','cor20_resolve_account'],True)
    new=closure(['svs_read_current_session'],True)
    observations={}
    for n in sorted(set(old+new)):
        body=funcs[n]
        observations[n]=dict(sha256=hashlib.sha256(body.encode()).hexdigest(),calls=calls(body),
            reads=sorted(set(re.findall(r'\b(?:from|join)\s+(?:public\.)?(\w+)',body,re.I))&tables),
            writes=writes(body),row_locks=bool(re.search(r'\bfor\s+(?:no\s+key\s+)?(?:update|share)',body,re.I)),
            dynamic_sql=bool(re.search(r'\bexecute\s+(?:format|[\'\"])',body,re.I)),
            security_definer='security definer' in body.lower(),
            volatility='volatile' if 'volatile' in body.lower() else 'stable' if 'stable' in body.lower() else 'immutable' if 'immutable' in body.lower() else 'volatile-default')
    assert not any(observations[n]['writes'] or observations[n]['row_locks'] or observations[n]['dynamic_sql'] or observations[n]['security_definer'] or observations[n]['volatility'].startswith('volatile') for n in new)
    extra=(ROOT/'deploy/session-validation/sql/validator-read-functions.sql').read_text()
    assert text.endswith(extra)
    # Every pre-existing routine, trigger, grant and table remains byte-for-byte unchanged.
    assert hashlib.sha256(text[:-len(extra)-2].encode()).hexdigest() == '1743da64491c5e7d715c4276fdb9f610d2310c8964b4e3f1655ab52bf5bb80a6'
    original=funcs['cor20_resolve_account']
    derived=funcs['svs_read_entitlements'].replace('public.','').replace('svs_read_approval_audited','cor20_approval_audited').replace('svs_read_activation_audited','cor20_activation_audited')
    original=original[original.index('account_live:='):original.index('        signature:=')]
    derived=derived[derived.index('account_live:='):derived.index('        return projection')]
    derived=re.sub(r'for g in select t\.grant_id,.*? from entitlement_grants t','for g in select * from entitlement_grants t',derived)
    assert original == derived, 'Effective entitlement policy derivation drift'
    assert 'select *' not in funcs['svs_read_entitlements'], 'Broad account/secret read'

    return dict(stage='SVS-04',status='PASS_STATIC_ONLY',sql_sha256=hashlib.sha256(SQL.read_bytes()).hexdigest(),
        legacy_closure=old,readonly_closure=new,routines=observations,triggers=triggers,
        legacy_privilege_conclusion='Do not grant the mutating or lock-taking legacy closure to SVS',
        readonly_privilege_assumptions='SECURITY INVOKER; four new routines REVOKE PUBLIC EXECUTE; dedicated login and minimum column/table/function grants with actual deny probes belong to SVS-05',
        snapshot_assumptions='One STABLE statement snapshot; RepeatableRead READ ONLY, yb_read_from_followers=off; actual target version and isolation semantics NotRun',
        caveats=['Conservative possible trigger closure, not executed branch coverage','Dynamic SQL and FK/cascade/trigger denial need native privilege proof','No live query plan, latency or lock-wait claim'],
        native_cases_executed=0,release_ready=False)
if __name__=='__main__':print(json.dumps(audit(),indent=2))
