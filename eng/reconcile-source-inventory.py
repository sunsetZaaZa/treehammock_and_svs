#!/usr/bin/env python3
"""Reconcile current source and scoped follow-ups. Indexing is not qualification."""
import argparse
import csv
import hashlib
import html
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = 'docs/corrections/'
MANIFEST = DOCS + 'SOURCE_RECONCILIATION.json'
CATALOG = DOCS + 'APPLICATION_SURFACE_INDEX.json'
FOLLOWUPS = DOCS + 'SOURCE_FINDING_FOLLOWUPS.json'
GENERATED = {MANIFEST, CATALOG, DOCS + 'ADDED_FILES.json', DOCS + 'COR23_FOLLOWUP_PLAN.md',
             'docs/release/API_ENDPOINT_MATRIX.md', 'docs/sql/SQL_CONTRACT_MATRIX_1_0_0.md',
             'docs/testing/treehammock-test-suite-inventory.html'}
IGNORED = {'.git', '.docker', 'bin', 'obj', 'TestResults', '.correction-results', '.artifacts', 'artifacts', '__pycache__'}
CANONICAL = 'Rigging/Database/Baseline/000_treehammock_canonical_database.sql'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def source_files(root):
    result = {}
    for p in sorted(root.rglob('*')):
        name = p.relative_to(root).as_posix()
        if IGNORED.intersection(p.relative_to(root).parts):
            continue
        if p.is_symlink():
            raise ValueError('Source symlink requires explicit reconciliation: ' + name)
        if not p.is_file():
            continue
        if not p.resolve().is_relative_to(root.resolve()):
            raise ValueError('Source must be an owned regular file: ' + name)
        result[name] = p
    return result


def load(root, name):
    return json.loads((root / name).read_text(encoding='utf-8'))


def validate_followups(root):
    items = load(root, FOLLOWUPS)['followups']
    findings = {f['id']: f for f in load(root, DOCS + 'FINDING_CLOSURE.json')['findings'] if f['owner'].startswith('COR23')}
    owners = {f['owner'] for f in findings.values()}
    if len(items) != len(findings) or {i['finding'] for i in items} != set(findings) or {i['pr'] for i in items} != owners:
        raise ValueError('Every review-derived COR23 finding must have exactly one scoped owner')
    all_owners = {f['owner'] for f in load(root, DOCS + 'FINDING_CLOSURE.json')['findings']} | {'COR01', 'COR02', 'COR23', 'COR24'}
    for item in items:
        f = findings[item['finding']]
        if (item['pr'], item['priority'], item['title']) != (f['owner'], f['priority'], f['title']):
            raise ValueError('Finding identity/ownership changed: ' + item['finding'])
        if not item['target_paths'] or not item['planned_regressions'] or not item['current_recheck']:
            raise ValueError('Incomplete actionable specification: ' + item['pr'])
        if len(set(item['dependencies'])) != len(item['dependencies']) or not set(item['dependencies']) <= all_owners:
            raise ValueError('Unknown or repeated dependency: ' + item['pr'])
        if 'COR23' not in item['dependencies'] or item['pr'] in item['dependencies'] or 'COR24' in item['dependencies']:
            raise ValueError('Invalid qualification/program dependency: ' + item['pr'])
        for name in item['target_paths'] + [item['review_reference']]:
            if Path(name).is_absolute() or '..' in Path(name).parts or not (root / name).is_file() or not (root / name).resolve().is_relative_to(root.resolve()):
                raise ValueError('Invalid target/evidence path: ' + name)
        if item['review_reference'] not in [DOCS + p for p in f['review_references']]:
            raise ValueError('Specification evidence does not own finding')
        report = (root / item['review_reference']).read_bytes()
        text = item['implementation_specification']
        if digest(report) != item['review_sha256'] or digest(text.encode()) != item['specification_sha256'] or text.strip() not in report.decode():
            raise ValueError('Frozen specification identity changed: ' + item['pr'])
        if not all(word.lower() in text.lower() for word in ('Implementation', 'Acceptance')):
            raise ValueError('Missing implementation/acceptance contract')
        if item['qualification'] != 'NotRun':
            raise ValueError('Follow-up index cannot assert runtime qualification')
    graph = {i['pr']: set(i['dependencies']) & owners for i in items}
    done = set()
    while graph:
        ready = {p for p, deps in graph.items() if deps <= done}
        if not ready:
            raise ValueError('Follow-up dependency cycle')
        done.update(ready)
        graph = {p: deps for p, deps in graph.items() if p not in ready}
    return items


def uncomment_cs(text):
    # Preserve quoted literals used by attributes; mask comments without moving lines.
    token = r'@"(?:""|[^"])*"|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*[\s\S]*?\*/'
    return re.sub(token, lambda m: re.sub(r'[^\n]', ' ', m[0]) if m[0].startswith(('//', '/*')) else m[0], text)


def endpoints(root):
    result = []
    for p in sorted((root / 'Controllers').glob('*.cs')):
        s = uncomment_cs(p.read_text())
        cls = re.search(r'public\s+(?:sealed\s+)?class\s+(\w+Controller)\s*:', s)
        if not cls:
            continue
        routes = re.findall(r'\[Route\("([^"]*)"\)\]', s[:cls.start()])
        if len(routes) != 1:
            raise ValueError('Unsupported controller route shape: ' + p.name)
        matches = list(re.finditer(r'\[Http(Get|Post|Put|Delete|Patch|Head|Options)(?:\("([^"]*)"\))?\]', s))
        if len(matches) != len(re.findall(r'\[Http\w+', s)):
            raise ValueError('Unsupported HTTP attribute expression: ' + p.name)
        for i, m in enumerate(matches):
            end = matches[i+1].start() if i+1 < len(matches) else len(s)
            segment = s[m.end():end]
            method = re.search(r'\bpublic\s+(?:async\s+)?[\w<>,?\[\].]+\s+(\w+)\s*\(', segment)
            if not method or '[NonAction]' in segment[:method.start()]:
                raise ValueError('Unsupported action signature: ' + p.name)
            route = '/'.join(x.strip('/') for x in [routes[0], m[2] or ''] if x.strip('/'))
            if any(x in route for x in ('[', ']', '{', '}', '~')):
                raise ValueError('Route templates require explicit parser support: ' + route)
            result.append(dict(method=m[1].upper(), route='/' + route, controller=cls[1], action=method[1],
                               path=p.relative_to(root).as_posix(), line=s[:m.start()].count('\n')+1,
                               qualification='SourceIndexed; MVC discovery and HTTP policy NotRun'))
    keys = [(x['method'], x['route']) for x in result]
    if len(set(keys)) != len(keys) or not result:
        raise ValueError('Duplicate or empty MVC endpoint surface')
    middleware = root / 'Rigging/Operations/SecurityOperationMiddleware.cs'
    s = middleware.read_text()
    path = re.search(r'public const string StatusPath = "([^"]+)";', s)
    if not path:
        raise ValueError('Status middleware route needs explicit reconciliation')
    if not re.search(r'if\s*\(!HttpMethods\.IsGet\(http\.Request\.Method\)\)', s):
        raise ValueError('Status middleware method needs explicit reconciliation')
    result.append(dict(method='GET', route=path[1], controller=None, action='SecurityOperationMiddleware.InvokeAsync',
                       path=middleware.relative_to(root).as_posix(), line=s[:path.start()].count('\n')+1,
                       qualification='SourceIndexed middleware protocol; runtime NotRun'))
    return sorted(result, key=lambda x: (x['route'], x['method']))


def functions(root):
    sql = (root / CANONICAL).read_text()
    # Current canonical dialect uses unquoted names and dollar-quoted function bodies.
    starts = list(re.finditer(r'^[ \t]*create\s+or\s+replace\s+function\s+(\w+)\s*\(', sql, re.I | re.M))
    if len(starts) != len(re.findall(r'^[ \t]*create\s+(?:or\s+replace\s+)?function\b', sql, re.I | re.M)):
        raise ValueError('Unsupported SQL function declaration')
    result = []
    repos = {p.relative_to(root).as_posix(): p.read_text() for folder in ('Repos', 'Rigging', 'Services')
             for p in (root / folder).rglob('*.cs')}
    for n, m in enumerate(starts):
        bound = starts[n+1].start() if n+1 < len(starts) else len(sql)
        part = sql[m.start():bound]
        opening = re.search(r'\bas\s+(\$\w*\$)', part, re.I)
        if not opening:
            raise ValueError('Unsupported SQL body: ' + m[1])
        close = part.find(opening[1], opening.end())
        if close < 0:
            raise ValueError('Unterminated SQL body')
        definition = part[:close+len(opening[1])]
        header = ' '.join(part[:opening.start()].split())
        refs = sorted(p for p, s in repos.items() if re.search(r'\b'+re.escape(m[1])+r'\s*\(', s, re.I))
        result.append(dict(name=m[1], declaration=header, definition_sha256=digest(definition.encode()), path=CANONICAL,
                           line=sql[:m.start()].count('\n')+1, lexical_csharp_references=refs,
                           qualification='SourceIndexed; parameters/readers/locks/query plans require native review'))
    if not result or len({i['name'] for i in result}) != len(result):
        raise ValueError('Empty/overloaded SQL catalog needs explicit support')
    return result


def mask_test_literals(text):
    """Mask C# comments and literals, retaining offsets; unsupported/unclosed tokens fail."""
    def comment(i):
        if text.startswith('//', i):
            end = text.find('\n', i + 2)
            return len(text) if end < 0 else end
        if text.startswith('/*', i):
            end = text.find('*/', i + 2)
            if end < 0: raise ValueError('Unterminated C# comment')
            return end + 2
        return None

    def literal(i):
        match = re.match(r'(?:\$+@?|@\$?)?"', text[i:])
        if text[i:i+1] == "'":
            j = i + 1
            while j < len(text):
                if text[j] == '\\': j += 2
                elif text[j] == "'": return j + 1
                else: j += 1
            raise ValueError('Unterminated C# character literal')
        if not match: return None
        opening = match[0]
        quote = i + len(opening) - 1
        raw = re.match(r'"{3,}', text[quote:])
        if raw:
            end = text.find(raw[0], quote + len(raw[0]))
            if end < 0: raise ValueError('Unterminated C# raw string')
            return end + len(raw[0])
        verbatim, interpolated = '@' in opening, '$' in opening
        j = quote + 1
        while j < len(text):
            if not verbatim and text[j] == '\\': j += 2
            elif verbatim and text.startswith('""', j): j += 2
            elif text[j] == '"': return j + 1
            elif interpolated and text.startswith('{{', j): j += 2
            elif interpolated and text[j] == '{':
                depth = 1
                j += 1
                while j < len(text) and depth:
                    end = comment(j) or literal(j)
                    if end is not None: j = end; continue
                    if text[j] == '{': depth += 1
                    elif text[j] == '}': depth -= 1
                    j += 1
                if depth: raise ValueError('Unterminated C# interpolation')
            else: j += 1
        raise ValueError('Unterminated C# string')

    result = list(text)
    i = 0
    while i < len(text):
        end = comment(i) or literal(i)
        if end is None: i += 1; continue
        result[i:end] = ['\n' if c == '\n' else ' ' for c in text[i:end]]
        i = end
    return ''.join(result)


def test_declarations(text, path):
    """Index supported attributed method declarations, never expanded native rows."""
    s = mask_test_literals(text)
    marker = r'(?<!\w)(Fact|Theory)(?:Attribute)?\b'
    # Independent comma-or-section guard includes grouped and qualified spellings,
    # even when the section/signature parser cannot consume the declaration.
    declared = len(re.findall(r'(?:\[|,)\s*(?:(?:\w+::)?[\w.]+\.)?' + marker, s))
    result = []
    i = 0
    while i < len(s):
        if s[i] != '[': i += 1; continue
        start = i
        attributes = []
        while i < len(s) and s[i] == '[':
            section_start = i
            stack, entry_start, entries = [']'], i + 1, []
            i += 1
            while i < len(s) and stack:
                c = s[i]
                if c in '([{': stack.append({'(': ')', '[': ']', '{': '}'}[c])
                elif c in ')]}':
                    if c != stack[-1]: raise ValueError('Unbalanced C# attribute/array: ' + path)
                    stack.pop()
                    if not stack: entries.append(s[entry_start:i])
                elif c == ',' and len(stack) == 1:
                    entries.append(s[entry_start:i]); entry_start = i + 1
                i += 1
            if stack:
                if re.search(marker, s[section_start:]): raise ValueError('Unterminated test attribute: ' + path)
                break
            for entry in entries:
                if not re.search(marker, entry): continue
                attribute = re.fullmatch(r'\s*(?:(?:global::)?Xunit\.)?(Fact|Theory)(?:Attribute)?\s*(?:\([\s\S]*\))?\s*', entry)
                if not attribute: raise ValueError('Unsupported test attribute syntax: ' + path)
                attributes.append(attribute[1])
            while i < len(s) and s[i].isspace(): i += 1
        if not attributes: continue
        if len(attributes) != 1: raise ValueError('Repeated/mixed test attributes: ' + path)
        method = re.match(r'public\s+(?:(?:async|static|virtual|override|sealed|new|unsafe)\s+)*[\w<>,?\[\].]+\s+(\w+)\s*\(', s[i:])
        if not method: raise ValueError('Unsupported test method declaration: ' + path)
        result.append(dict(path=path, method=method[1], attribute=attributes[0], line=s[:start].count('\n')+1))
    identities = [(row['path'], row['method']) for row in result]
    if declared != len(result) or len(set(identities)) != len(identities):
        raise ValueError('Unsupported/ambiguous test declaration: ' + path)
    return result


def tests(root):
    result = []
    for folder in ('treehammock.Tests', 'treehammock.Tests.SqlContracts', 'treehammock.Tests.System'):
        for p in sorted((root / folder).rglob('*.cs')):
            if not IGNORED.intersection(p.relative_to(root).parts):
                result.extend(test_declarations(p.read_text(), p.relative_to(root).as_posix()))
    return result


def feature_index(root, api, sql, cases):
    # Preserve explicit unresolved references; a lexical match never proves the claim.
    text = (root / 'docs/release/RELEASE_FEATURE_MATRIX.md').read_text()
    files = source_files(root)
    classes = {}
    for name, p in files.items():
        if name.endswith('.cs'):
            for cls in re.findall(r'\b(?:class|interface|enum|record)\s+(\w+)', uncomment_cs(p.read_text())):
                classes.setdefault(cls, []).append(name)
    result = []
    for line in text.splitlines():
        cells = [c.strip() for c in line.strip('|').split('|')]
        if len(cells) != 6 or cells[0] in ('Area', '---') or not line.startswith('|'):
            continue
        anchors = re.findall(r'`([^`]+)`', cells[4]+' '+cells[5])
        resolved = []
        for anchor in anchors:
            targets = []
            if anchor in files: targets.append(anchor)
            if anchor in classes: targets += classes[anchor]
            targets += [i['path'] for i in api if anchor == i['method']+' '+i['route']]
            targets += [i['path'] for i in sql if anchor == i['name']]
            resolved.append(dict(anchor=anchor, paths=sorted(set(targets)), disposition='SourceLocated' if targets else 'UnresolvedClaimAnchor'))
        result.append(dict(area=cells[0], feature=cells[1], declared_status=cells[2],
                           qualification='PendingIntegratedQualification', anchors=resolved,
                           unanchored_verification_text=cells[5] if not re.findall(r'`([^`]+)`',cells[5]) else None))
    if not result:
        raise ValueError('Feature matrix is empty')
    return result


def build_catalog(root):
    api, sql, cases = endpoints(root), functions(root), tests(root)
    return dict(schema_version=1, basis='Static source index; not compiler, MVC, SQL or executed test evidence',
                endpoints=api, sql_functions=sql, attributed_test_methods=cases,
                features=feature_index(root, api, sql, cases))


def build_manifest(root, items):
    with (root / (DOCS+'FILE_REVIEW_INVENTORY.csv')).open(encoding='utf-8', newline='') as stream:
        historical = {i['path']: i for i in csv.DictReader(stream)}
    focused = {i['path']: i for i in load(root, DOCS+'FOCUSED_SOURCE_REVIEW.json')['files']}
    gates = load(root, DOCS+'REVIEW_GATES.json')['gates']
    gate_paths = {p: g['id'] for g in gates if g['kind']=='source' for p in g['baseline_paths']}
    rows = []
    for name, p in source_files(root).items():
        if name in GENERATED:
            continue
        old = historical.get(name)
        unchanged = bool(old and old['sha256']==digest(p.read_bytes()))
        disposition = ('HistoricalSourceEvidenceRetained; RuntimePending' if unchanged and name not in gate_paths else
                       'HistoricalEvidenceRequiresCurrentSourceRecheck; RuntimePending' if old else
                       'AddedCorrectionArtifact; ReviewAndRuntimePending')
        rows.append(dict(path=name, sha256=digest(p.read_bytes()), historical_sha256=old['sha256'] if old else None,
                         changed_from_original=not unchanged if old else None, disposition=disposition,
                         historical_qualification=old['qualification'] if old else None,
                         focused_review=focused.get(name),
                         review_owner='COR23', qualification_owner='COR24', source_gate=gate_paths.get(name),
                         finding_owners=sorted(i['pr'] for i in items if name in i['target_paths']),
                         evidence_reference=DOCS+'FILE_REVIEW_INVENTORY.csv' if old else DOCS+'ADDED_FILES.json'))
    return dict(schema_version=1, qualification='Blocked: reconciliation/indexing does not complete pending source or native review',
                original_inventory_rows=len(historical), legacy_source_gate_rows=len(gate_paths),
                generated_files=sorted(GENERATED), generated_policy='Checked by deterministic regeneration; ADDED_FILES checked by correction evidence validator. Excluded from content hash to avoid self-reference.',
                files=rows)


def markdown_followups(items):
    text = '# COR23 follow-up implementation plan\n\nEvery owner is scoped to one review-derived finding. The frozen review is preserved; current notes and the pre-1.0 policy supersede historical compatibility proposals. Planned cases are acceptance targets, not executed results. COR24 follows all scoped corrections and native qualification.\n\n'
    for i in items:
        text += '## '+i['pr']+' — '+i['finding']+'\n\n'+i['title']+'\n\n'
        if i.get('implementation_status'):
            text += '**Implementation:** '+i['implementation_status']+'; native qualification '+i['qualification']+'. See ['+Path(i['implementation_reference']).name+']('+i['implementation_reference'].removeprefix(DOCS)+').\n\n'
        text += '**Dependencies:** '+', '.join(i['dependencies'])+'.\n\n**Current files:** '+', '.join('`'+p+'`' for p in i['target_paths'])+'.\n\n'
        text += '**Coordination (not sequencing):** '+(', '.join(i.get('coordination_references', [])) or 'none')+'.\n\n'
        text += '**Current recheck:** '+i['current_recheck']+'\n\n**Schema policy:** '+i['schema_policy']+'\n\n'
        text += '**Planned regressions:**\n\n'+''.join('- `'+c+'`\n' for c in i['planned_regressions'])+'\n'
        text += '**Frozen specification:** ['+Path(i['review_reference']).name+']('+i['review_reference'].removeprefix(DOCS)+')\n\n'
        # Demote headings so each owner remains one section.
        text += re.sub(r'^#', '##', i['implementation_specification'], flags=re.M)+'\n'
    return text.rstrip()+'\n'


def outputs(root):
    items = validate_followups(root)
    catalog = build_catalog(root)
    data = {CATALOG: json.dumps(catalog, indent=2)+'\n', MANIFEST:json.dumps(build_manifest(root, items),indent=2)+'\n',
            DOCS+'COR23_FOLLOWUP_PLAN.md':markdown_followups(items)}
    data['docs/release/API_ENDPOINT_MATRIX.md'] = '# Current API source index — COR23\n\nGenerated by `eng/reconcile-source-inventory.py --refresh`. This indexes literal controller routes plus the explicit security-operation status middleware route. It does not establish effective authentication, capability policy, response envelopes, HTTP bounds, or test execution. Native MVC descriptor parity is required by `Cor23ReconciliationContractTests`; real routed denial and mutation tests remain COR24. The full literal index includes three system-test actions, discoverable only with the validated Testing inspection capability. COR23D authors deployable-host denial and owned-fixture persistence checks; their native execution remains NotRun.\n\n| Method | Route | Source | Action | Qualification |\n|---|---|---|---|---|\n'+''.join('| '+e['method']+' | `'+e['route']+'` | `'+e['path']+'` | '+e['action']+' | NotRun |\n' for e in catalog['endpoints'])
    data['docs/sql/SQL_CONTRACT_MATRIX_1_0_0.md'] = '# Current canonical SQL source index — COR23\n\nGenerated from the current pre-1.0 canonical setup. All '+str(len(catalog['sql_functions']))+' function declarations are indexed. This replaces the stale 89-function matrix. Declarations and lexical C# references are source metadata, not executable parameter/reader contracts or measured plans. Zero lexical references can mean SQL-internal use, dynamic calls or a legacy denied surface; it does not prove unused code. PostgreSQL catalog parity, every actual repository result reader, supported branch execution, account-first lock graph, exact expiry and measured query plans remain native qualification obligations. Frozen R06 and scoped COR23A/B/C evidence remain open. The generated baselines/checksummed setup remain authoritative.\n\n'
    for f in catalog['sql_functions']:
        data['docs/sql/SQL_CONTRACT_MATRIX_1_0_0.md'] += '## '+f['name']+'\n\n```sql\n'+f['declaration']+'\n```\n\nSource line: '+str(f['line'])+'. Definition SHA256: `'+f['definition_sha256']+'`.\n\nLexical C# references: '+(', '.join('`'+p+'`' for p in f['lexical_csharp_references']) or 'none indexed; classify at native repository/SQL review')+'.\n\nQualification: pending native catalog, branch/result-reader and contention evidence.\n\n'
    title = 'Current attributed test source inventory — COR23'
    data['docs/testing/treehammock-test-suite-inventory.html'] = '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'+title+'</title><style>body{font:16px system-ui;margin:2rem;max-width:1100px}table{border-collapse:collapse}td,th{padding:.4rem;text-align:left;border:1px solid #ccc}code{overflow-wrap:anywhere}</style><h1>'+title+'</h1><p>Static attributed methods: '+str(len(catalog['attributed_test_methods']))+'. Theory data rows are not expanded. These are source declarations, not runtime discovery, execution, coverage or passing counts. All native execution remains pending. Generated by eng/reconcile-source-inventory.py; no embedded external assets or scripts.</p><table><thead><tr><th>Source file</th><th>Method</th><th>Attribute</th><th>Line</th></tr></thead><tbody>'+''.join('<tr><td><code>'+html.escape(t['path'])+'</code></td><td>'+html.escape(t['method'])+'</td><td>'+t['attribute']+'</td><td>'+str(t['line'])+'</td></tr>' for t in catalog['attributed_test_methods'])+'</tbody></table></html>\n'
    data = {name: text.rstrip()+'\n' if name.endswith('.md') else text for name, text in data.items()}
    return data, catalog


def check(root):
    expected, catalog = outputs(root)
    drift = [p for p, text in expected.items() if not (root/p).is_file() or (root/p).read_text()!=text]
    if drift:
        raise ValueError('Unreconciled source/generated artifact drift: '+', '.join(drift))
    return dict(status='SourceMappingConsistent', qualification='Blocked', endpoints=len(catalog['endpoints']),
                sql_functions=len(catalog['sql_functions']), attributed_test_methods=len(catalog['attributed_test_methods']),
                features=len(catalog['features']), unresolved_feature_anchors=sum(not a['paths'] for f in catalog['features'] for a in f['anchors']),
                followups=len(validate_followups(root)), source_files=len(source_files(root)))


def release_blockers(root):
    blockers = []
    for f in load(root, DOCS+'FINDING_CLOSURE.json')['findings']:
        if f['status'] not in ('Closed', 'Dispositioned'):
            blockers.append(f['id']+': '+f['status'])
    for g in load(root, DOCS+'REVIEW_GATES.json')['gates']:
        if g['status'] != 'Passed':
            blockers.append(g['id']+': '+g['status'])
    # This tool never substitutes source metadata for final qualification evidence.
    blockers.append('COR24 independent native/HTTP/provider/dependency/recovery/resource qualification required')
    return blockers


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--refresh', action='store_true', help='Regenerate source indexes/dispositions; cannot close findings/gates')
    parser.add_argument('--check', action='store_true', help='Check without writing (default)')
    parser.add_argument('--require-qualified', action='store_true', help='Fail blocked rather than treating index consistency as release qualification')
    args = parser.parse_args()
    if args.refresh and (args.check or args.require_qualified):
        parser.error('Refresh and qualification/check modes are mutually exclusive')
    try:
        if args.refresh:
            # Ensure generated paths exist before enumerating administrative exclusions.
            for name in GENERATED-{DOCS+'ADDED_FILES.json'}:
                (args.root/name).parent.mkdir(parents=True, exist_ok=True)
                (args.root/name).touch(exist_ok=True)
            data, _ = outputs(args.root)
            for name, text in data.items(): (args.root/name).write_text(text, encoding='utf-8')
        report = check(args.root)
        if args.require_qualified:
            report['blockers'] = release_blockers(args.root)
            report['status'] = 'Blocked'
        print(json.dumps(report, indent=2))
        return 2 if args.require_qualified else 0
    except (ValueError, KeyError, OSError) as exc:
        print(json.dumps(dict(status='Failed', error=str(exc))))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
