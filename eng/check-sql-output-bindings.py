#!/usr/bin/env python3
"""COR23B supplemental SQL output-name audit; not a PostgreSQL parser or execution oracle."""
import argparse
import hashlib
import json
import re
from pathlib import Path

CANONICAL = 'Rigging/Database/Baseline/000_treehammock_canonical_database.sql'
REPORT = 'docs/corrections/SQL_OUTPUT_BINDING_REVIEW.json'
FUNCTION = re.compile(r'^create or replace function (\w+)\(.*?^\$\$;', re.M | re.S)


def mask(text):
    # Keep offsets. Bodies use $$; mask inner SQL literals and comments only.
    return re.sub(r"'(?:''|[^'])*'|--[^\n]*|/\*[\s\S]*?\*/", lambda m: re.sub(r'[^\n]', ' ', m[0]), text)


def definitions(sql):
    starts = list(re.finditer(r'^create or replace function (\w+)\(', sql, re.M | re.I))
    rows = {}
    for n, start in enumerate(starts):
        end = starts[n+1].start() if n+1 < len(starts) else len(sql)
        part = sql[start.start():end]
        opening = re.search(r'\bas\s+(\$\w*\$)', part, re.I)
        if not opening: raise ValueError('Unsupported function body')
        close = part.find(opening[1], opening.end())
        if close < 0 or start[1] in rows: raise ValueError('Unterminated or duplicate function')
        rows[start[1]] = part[:close+len(opening[1])]
    if not rows: raise ValueError('Missing canonical function definitions')
    return rows


def validate_critical(sql):
    funcs = definitions(sql)
    if re.search(r"set_config\s*\(\s*'plpgsql\.variable_conflict'", sql, re.I) or re.search(r'#variable_conflict\s+(?:use_column|use_variable)|(?:set|set_config)\s*\(?\s*plpgsql\.variable_conflict', mask(sql), re.I):
        raise ValueError('Preserve the PostgreSQL default conflict setting')
    body = mask(funcs['cor08_authorized_begin_authenticator_app_setup'])
    update = re.findall(r'update\s+two_factor_authentications\s+t\s+set\s+token\s*=.*?;', body, re.S | re.I)
    if len(update) != 1 or not re.search(r'where\s+t\.account_id\s*=\s*p_accountId\s+and\s+t\.two_factor_index\s*=\s*target_index\s+and\s+t\.verified\s*=\s*false\s+and\s+t\.revoked_at\s+is\s+null\s*;', update[0], re.I):
        raise ValueError('Authenticator replacement must qualify its exact account/index/pending/live predicate')
    for name, code in [('begin_authenticator_app_setup', 'SENSITIVE_ACTION_GRANT_REQUIRED'), ('disable_activation', 'ACTIVATION_TRUSTED_GRANT_REQUIRED')]:
        body = funcs[name].split('as $$', 1)[1]
        if code not in body or re.search(r'\b(?:update|insert|delete|perform)\b', mask(body), re.I):
            raise ValueError('Legacy entry point must remain a nonmutating denial: '+name)


def audit(sql):
    validate_critical(sql)
    rows = []
    for name, definition in definitions(sql).items():
        header, body = definition.split('as $$', 1)
        table = re.search(r'returns table\((.*?)\)\s*language', header, re.S | re.I)
        outputs = [part.strip().split()[0] for part in table[1].split(',')] if table else []
        text = mask(body)
        candidates = []
        for statement in re.finditer(r'[^;]+;', text):
            tail = re.search(r'\b(?:where|having|order\s+by|on)\b[\s\S]*', statement[0], re.I)
            if not tail: continue
            for output in outputs:
                for match in re.finditer(r'(?<![\w.])'+re.escape(output)+r'\b(?!\s*\.)', tail[0], re.I):
                    offset = statement.start()+tail.start()+match.start()
                    candidates.append(dict(output=output, body_line=text[:offset].count('\n')+1,
                        context=' '.join(text[max(0,offset-65):offset+85].split()),
                        disposition='LexicalCandidate; grammar position and branch require native review'))
        rows.append(dict(function=name, definition_sha256=hashlib.sha256(definition.encode()).hexdigest(),
                         table_outputs=outputs, candidates=candidates))
    return dict(schema_version=1, basis='All current canonical function definitions indexed; conservative lexical candidates, not a binding proof',
                qualification='NotRun', conflict_setting='Default error required; no preference override added',
                critical_predicate='Qualified account/index/verified/revoked references; unchanged signature and conditions',
                function_count=len(rows), table_returning_count=sum(bool(r['table_outputs']) for r in rows),
                candidate_count=sum(len(r['candidates']) for r in rows), functions=rows)


def validate(root):
    expected = audit((root/CANONICAL).read_text())
    if json.loads((root/REPORT).read_text()) != expected:
        raise ValueError('SQL binding audit stale; refresh after intentional source review')
    return expected


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument('--refresh',action='store_true')
    args=parser.parse_args()
    try:
        if args.refresh:
            (args.root/REPORT).write_text(json.dumps(audit((args.root/CANONICAL).read_text()),indent=2)+'\n')
        report=validate(args.root)
        print(f"Source audit consistent: {report['function_count']} functions, {report['candidate_count']} lexical candidates. Native binding qualification pending.")
        return 0
    except (ValueError,KeyError,OSError) as e:
        print(str(e));return 1


if __name__=='__main__': raise SystemExit(main())
