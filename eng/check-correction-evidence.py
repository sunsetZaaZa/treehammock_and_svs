#!/usr/bin/env python3
"""COR01 evidence integrity. This never runs or simulates application tests."""
import argparse
import csv
import hashlib
import importlib.util
import json
import re
import sys
import subprocess
import tempfile
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

ARCHIVE_SHA = '229ef2275f1caeff3a6a40186e678f7440a90fd54add2e0ba8de0fd6c645758f'
MANIFEST_SHA = '3e2202b95ab15d1cb18aadf73d9266982995b26259de83b64bfcfe219ea8b107'
STATES = {'Open', 'InProgress', 'FixedPendingQualification', 'Closed', 'Dispositioned'}
LANE_STATES = {'Passed', 'Failed', 'Blocked', 'NotRun'}
KNOWN_OWNERS = {f'COR{n:02d}' for n in range(1, 25)} | {'COR23' + chr(n) for n in range(65, 91)} | {'COR23A' + chr(n) for n in range(65, 71)}
TRANSITIONS = {
    'Open': {'Open', 'InProgress', 'Dispositioned'},
    'InProgress': {'InProgress', 'Open', 'FixedPendingQualification', 'Dispositioned'},
    'FixedPendingQualification': {'FixedPendingQualification', 'InProgress', 'Closed', 'Dispositioned'},
    'Closed': {'Closed', 'InProgress'},
    'Dispositioned': {'Dispositioned', 'Open'},
}



# Historical path keys belong to the immutable pre-1.0 inventory.  The current
# documentation has functional filenames; this closed mapping restores path
# resolution without rewriting historical source hashes or inventing evidence.
BASELINE_DOCUMENT_RELOCATIONS = {
    'docs/release/API_ENDPOINT_MATRIX_1_0_0.md': 'docs/release/API_ENDPOINT_MATRIX.md',
    'docs/release/GITHUB_CI_CD_RELEASE_1_0_0.md': 'docs/release/GITHUB_CI_CD_RELEASE.md',
    'docs/release/PASSWORD_RESET_1_0_0.md': 'docs/release/PASSWORD_RESET.md',
    'docs/release/RELEASE_FEATURE_MATRIX_1_0_0.md': 'docs/release/RELEASE_FEATURE_MATRIX.md',
    'docs/sql/SQL_CONTRACT_MATRIX_1_0_0.md': 'docs/sql/SQL_CONTRACT_MATRIX.md',
    'docs/testing/treehammock-test-suite-inventory.html': 'docs/testing/treehammock-test-suite-inventory.html',
}


# Evidence ledger references are append-only. Historical implementation review
# documents retain their original bytes at descriptive paths; only this lookup
# translates the frozen record pointers. Unknown names still fail closed.
HISTORICAL_REVIEW_RELOCATIONS = {'COR23AA_IMPLEMENTATION.md': 'evidence/implementation-history/host-lane-application-ownership.md',
 'COR23AB_IMPLEMENTATION.md': 'evidence/implementation-history/host-prerequisites.md',
 'COR23AC_IMPLEMENTATION.md': 'evidence/implementation-history/account-failure-envelopes.md',
 'COR23AD_IMPLEMENTATION.md': 'evidence/implementation-history/two-factor-flow-disposal.md',
 'COR23AE_IMPLEMENTATION.md': 'evidence/implementation-history/registration-verification-commit.md',
 'COR23AF_IMPLEMENTATION.md': 'evidence/implementation-history/authenticator-predecessor-binding.md',
 'COR23A_IMPLEMENTATION.md': 'evidence/implementation-history/activation-reader-scopes.md',
 'COR23B_ADDITIONAL_REVIEW.md': 'evidence/implementation-history/postgresql-replacement-source-review.md',
 'COR23B_IMPLEMENTATION.md': 'evidence/implementation-history/postgresql-replacement-predicates.md',
 'COR23C_IMPLEMENTATION.md': 'evidence/implementation-history/durable-factor-identities.md',
 'COR23D_IMPLEMENTATION.md': 'evidence/implementation-history/test-composition-privileged-routes.md',
 'COR23E_IMPLEMENTATION.md': 'evidence/implementation-history/private-security-responses.md',
 'COR23F_IMPLEMENTATION.md': 'evidence/implementation-history/bounded-http-bodies-errors.md',
 'COR23G_IMPLEMENTATION.md': 'evidence/implementation-history/verification-origin-host-profiles.md',
 'COR23H_IMPLEMENTATION.md': 'evidence/implementation-history/smtp-tls-enforcement.md',
 'COR23I_IMPLEMENTATION.md': 'evidence/implementation-history/delivery-uncertainty-retries.md',
 'COR23J_IMPLEMENTATION.md': 'evidence/implementation-history/delivery-lifetimes-cancellation.md',
 'COR23K_IMPLEMENTATION.md': 'evidence/implementation-history/recipient-failures-provider-health.md',
 'COR23L_IMPLEMENTATION.md': 'evidence/implementation-history/twilio-startup-prerequisites.md',
 'COR23M_IMPLEMENTATION.md': 'evidence/implementation-history/authoritative-admission-fallback.md',
 'COR23N_IMPLEMENTATION.md': 'evidence/implementation-history/shared-cache-lifecycle.md',
 'COR23O_IMPLEMENTATION.md': 'evidence/implementation-history/readiness-probe-budgets.md',
 'COR23P_IMPLEMENTATION.md': 'evidence/implementation-history/operational-transition-counts.md',
 'COR23Q_IMPLEMENTATION.md': 'evidence/implementation-history/proof-runner-fail-fast.md',
 'COR23R_IMPLEMENTATION.md': 'evidence/implementation-history/coverage-collection-contract.md',
 'COR23S_IMPLEMENTATION.md': 'evidence/implementation-history/build-test-configuration-identity.md',
 'COR23T_IMPLEMENTATION.md': 'evidence/implementation-history/release-inputs-credentials.md',
 'COR23U_IMPLEMENTATION.md': 'evidence/implementation-history/source-version-digest-promotion.md',
 'COR23V_IMPLEMENTATION.md': 'evidence/implementation-history/powershell-api-output-tag.md',
 'COR23W_IMPLEMENTATION.md': 'evidence/implementation-history/compose-prerequisite-checks.md',
 'COR23X_IMPLEMENTATION.md': 'evidence/implementation-history/isolated-fixture-state.md',
 'COR23Y_IMPLEMENTATION.md': 'evidence/implementation-history/isolated-owned-test-resources.md',
 'COR23Z_IMPLEMENTATION.md': 'evidence/implementation-history/bounded-test-acquisition-cleanup.md'}


def historical_review_path(root, name):
    return safe_path(root, HISTORICAL_REVIEW_RELOCATIONS.get(name, name))


def baseline_document(root, name):
    """Resolve a source inventory path, accepting only reviewed documentation moves."""
    target = BASELINE_DOCUMENT_RELOCATIONS.get(name, name)
    path = safe_path(root, target)
    require(path.is_file(), f'Missing current baseline document: {target}')
    return path


def verify_initial_import(root, expected_ledger_digest=None):
    """Allow an explicitly hash-pinned mature import, without treating history as qualification."""
    docs = root / 'docs/corrections'
    findings = read_json(docs / 'FINDING_CLOSURE.json')['findings']
    gates = read_json(docs / 'REVIEW_GATES.json')['gates']
    require(all(g['status'] == 'Open' for g in gates), 'Initial import cannot close review gates')
    if expected_ledger_digest is None:
        require(all(f['status'] == 'Open' and not f['history'] for f in findings),
                'Initial import must preserve all findings Open unless the imported ledger digest is explicitly pinned')
        return
    require(re.fullmatch(r'[a-f0-9]{64}', expected_ledger_digest) is not None,
            'Malformed imported ledger digest')
    require(digest(docs / 'FINDING_CLOSURE.json') == expected_ledger_digest,
            'Imported ledger does not match the reviewed, pinned digest')
    for finding in findings:
        require(finding['status'] in {'Open', 'InProgress', 'FixedPendingQualification'},
                'Initial import cannot close or disposition a finding')
        require(isinstance(finding.get('history'), list), 'Initial import history is missing')
        state = 'Open'
        for event in finding['history']:
            require(isinstance(event, dict) and event.get('from') == state and
                    event.get('to') in TRANSITIONS[state] and
                    isinstance(event.get('reason'), str) and bool(event['reason'].strip()) and
                    (event.get('date') is None or
                     (isinstance(event['date'], str) and
                      re.fullmatch(r'\d{4}-\d{2}-\d{2}', event['date']) is not None)),
                    'Imported finding contains invalid transition history')
            state = event['to']
        require(state == finding['status'],
                'Imported finding status is not supported by its history')

def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def safe_path(root, name):
    require(isinstance(name, str) and name and not Path(name).is_absolute(), 'Evidence path must be relative')
    path = (root / name).resolve()
    require(path.is_relative_to(root.resolve()), 'Evidence path escapes project')
    require(path.is_file(), f'Missing evidence file: {name}')
    return path


def read_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, f'Duplicate JSON key: {key}')
            result[key] = value
        return result
    return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=unique)


def trx_counts(path):
    tree = ET.parse(path)
    ns = {'t': 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010'}
    counters = tree.find('.//t:ResultSummary/t:Counters', ns)
    require(counters is not None, 'Missing TRX counters')
    counts = {k: int(counters.get(k, '0')) for k in ('total', 'executed', 'passed', 'failed', 'notExecuted')}
    cases = tree.findall('.//t:Results/t:UnitTestResult', ns)
    require(len(cases) == counts['total'], 'TRX result/counter mismatch')
    require(len({c.get('executionId') for c in cases}) == len(cases), 'Duplicate TRX executions')
    require(counts['executed'] == sum(c.get('outcome') not in ('NotExecuted', 'Pending') for c in cases),
            'TRX executed count mismatch')
    for outcome, key in [('Passed', 'passed'), ('Failed', 'failed'), ('NotExecuted', 'notExecuted')]:
        require(sum(c.get('outcome') == outcome for c in cases) == counts[key], 'TRX outcome mismatch')
    return counts, [c.get('testName', '') for c in cases if c.get('outcome') == 'Passed']


def validate_run(root, run):
    require(run.get('schema_version') == 1, 'Unknown run schema')
    uuid.UUID(run['run_id'])
    require(re.fullmatch(r'sha256:[a-f0-9]{64}', run.get('source_identity', '')) is not None and
            run.get('configuration') == 'Release', 'Run identity/configuration missing or invalid')
    require(run.get('evidence_kind') == 'executed-tooling', 'Run is not execution evidence')
    lanes = run.get('lanes', [])
    require(bool(lanes), 'Empty run')
    require(len({x['name'] for x in lanes}) == len(lanes), 'Duplicate lanes')
    for lane in lanes:
        require(lane['status'] in LANE_STATES, 'Unknown lane status')
        if lane['status'] != 'Passed':
            require(bool(lane.get('reason')), 'Nonpassing lane needs a reason')
            continue
        require(lane.get('exit_code') == 0, 'Passing lane has nonzero exit')
        require(bool(lane.get('stages')) and all(x['exit_code'] == 0 for x in lane['stages']), 'Passing lane stage failed')
        require(bool(run.get('runtime_versions', {}).get('dotnet')), 'Passing tests require resolved SDK version')
        require(bool(lane.get('results')), 'Passing lane has no results')
        if run.get('collect_coverage'):
            require(lane['name'] == 'fast', 'Unsupported coverage lane')
            measurements = lane.get('coverage', [])
            require({m['lane'] for m in measurements} == {'unit', 'integration'} and len(measurements) == 2,
                    'Passing coverage lane needs both measurements')
            spec = importlib.util.spec_from_file_location('coverage_contract', root / 'eng/coverage-contract.py')
            coverage = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(coverage)
            for measurement in measurements:
                folder = safe_path(root, measurement['directory'] + '/' + measurement['trx']).parent
                actual = coverage.validate_results(folder, measurement['lane'] + '.trx')
                require(actual == {k: v for k, v in measurement.items() if k not in ['lane', 'directory']},
                        'Coverage evidence content/hash mismatch')
        for result in lane['results']:
            path = safe_path(root, result['path'])
            require(digest(path) == result['sha256'], 'Result hash mismatch')
            counts, _ = trx_counts(path)
            require(counts == result['counts'], 'Recorded counts differ from TRX')
            require(counts['total'] > 0 and counts['executed'] == counts['total'] and
                    counts['passed'] == counts['total'] and counts['failed'] == counts['notExecuted'] == 0,
                    'Passed lane has zero discovery, failure, skip or incomplete execution')
    statuses = [x['status'] for x in lanes]
    expected = 'Failed' if 'Failed' in statuses else 'Blocked' if 'Blocked' in statuses else 'NotRun' if 'NotRun' in statuses else 'Passed'
    require(run.get('status') == expected, 'Aggregate outcome differs from lanes')


def regression_selectors(root, selectors):
    """Classify current source pointers; this never expands or executes native cases."""
    spec = importlib.util.spec_from_file_location('selector_source_index', root / 'eng/reconcile-source-inventory.py')
    index = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(index)
    methods = index.tests(root)
    declarations, owners = {}, {}
    for row in methods:
        if row['path'] not in declarations:
            source = index.mask_test_literals((root / row['path']).read_text())
            namespace = re.search(r'\bnamespace\s+([\w.]+)', source)
            scopes = []
            for cls in re.finditer(r'\bclass\s+(\w+)[^{;]*\{', source):
                depth, end = 1, cls.end()
                while end < len(source) and depth:
                    depth += (source[end]=='{') - (source[end]=='}')
                    end += 1
                require(depth == 0, 'Unbalanced regression class scope')
                scopes.append((cls.start(), end, cls[1]))
            declarations[row['path']] = (source, scopes, namespace[1] if namespace else '')
        source, scopes, namespace = declarations[row['path']]
        signature = re.search(r'\bpublic\s+(?:(?:async|static|virtual|override|sealed|new|unsafe)\s+)*[\w<>,?\[\].]+\s+' + re.escape(row['method']) + r'\s*\(', source)
        require(signature is not None, 'Regression method signature missing')
        offset = signature.start()
        enclosing = sorted((scope for scope in scopes if scope[0] <= offset < scope[1]), key=lambda scope: scope[0])
        require(bool(enclosing), 'Regression method has no supported class scope')
        owners[row['path'], row['method']] = {enclosing[-1][2], namespace + '.' + '+'.join(scope[2] for scope in enclosing)}
    result = []
    for selector in selectors:
        require(isinstance(selector, str) and bool(selector.strip()), 'Empty regression selector')
        if '/' in selector or selector.endswith(('.cs', '.mjs', '.py')):
            path = safe_path(root, selector)
            result.append(dict(selector=selector, kind='FileScope', paths=[path.relative_to(root.resolve()).as_posix()], native_case=False))
            continue
        declaration = selector.split('(', 1)[0]
        matches, classes = [], []
        for row in methods:
            class_names = owners[row['path'], row['method']]
            if declaration in class_names: classes.append(row['path'])
            if declaration == row['method'] or any(declaration == name + '.' + row['method'] for name in class_names):
                matches.append(row)
        if len(matches) == 1:
            result.append(dict(selector=selector, kind='MethodDeclaration', **matches[0],
                               native_case=False, theory_expansion_required=matches[0]['attribute']=='Theory'))
        elif matches:
            result.append(dict(selector=selector, kind='AmbiguousMethod', paths=sorted({row['path'] for row in matches}), native_case=False))
        elif classes:
            result.append(dict(selector=selector, kind='ClassScope', paths=sorted(set(classes)), native_case=False))
        else:
            result.append(dict(selector=selector, kind='Unresolved', paths=[], native_case=False))
    return result


def require_concrete_closure_selectors(root, selectors):
    require(bool(selectors), 'Closure has no regression selectors')
    classified = regression_selectors(root, selectors)
    require(all(row['kind'] == 'MethodDeclaration' for row in classified), 'Closure must resolve file/class/ambiguous/missing selectors to concrete current methods')
    require(all(not row['theory_expansion_required'] or '(' in row['selector'] and row['selector'].endswith(')') for row in classified),
            'Closure theory selectors require exact expanded native result names')
    # Native names are still matched verbatim by execution(); source location is no execution credit.


def execution(root, reference, required_cases=(), source_identity=None):
    path = safe_path(root, reference['path'])
    require(digest(path) == reference['sha256'], 'Evidence hash mismatch')
    run = read_json(path)
    validate_run(root, run)
    require(run['source_identity'] == source_identity, 'Evidence source identity differs from owning change')
    lane = next((x for x in run['lanes'] if x['name'] == reference['lane']), None)
    require(lane is not None and lane['status'] == 'Passed', 'Required lane did not pass')
    passed = []
    for result in lane['results']:
        _, names = trx_counts(safe_path(root, result['path']))
        passed.extend(names)
    require(all(case in passed for case in required_cases), 'Required exact regression case is absent')


PERFORMANCE_SOURCE_ALGORITHM = 'treehammock-performance-source-v1'


def performance_source_identity(root):
    """Fingerprint executable/setup/test/tooling inputs, excluding mutable documentation/evidence."""
    ignored = {'.git', '.docker', 'bin', 'obj', 'TestResults', '.artifacts', 'artifacts', '.correction-results', '__pycache__', 'node_modules'}
    total = hashlib.sha256()
    for path in sorted(root.rglob('*')):
        relative = path.relative_to(root)
        if relative.parts[0] == 'docs' or ignored.intersection(relative.parts):
            continue
        require(not path.is_symlink(), 'Linked performance source input')
        if path.is_file():
            total.update(relative.as_posix().encode() + b'\0' + hashlib.sha256(path.read_bytes()).digest())
    return 'sha256:' + total.hexdigest()


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def performance_reference(root, reference):
    require(isinstance(reference, dict) and set(reference) == {'path', 'sha256'}, 'Performance reference must contain path and sha256')
    require(isinstance(reference['sha256'], str) and re.fullmatch('[a-f0-9]{64}', reference['sha256']) is not None, 'Invalid performance reference hash')
    path = safe_path(root, reference['path'])
    relative = Path(reference['path'])
    require('..' not in relative.parts, 'Performance reference must be canonical')
    current = root
    for part in relative.parts:
        current = current / part
        require(not current.is_symlink(), 'Linked performance evidence')
    require(digest(path) == reference['sha256'], 'Performance reference content/hash mismatch')
    return read_json(path)


def validate_performance(root, measured):
    required = {'schema_version', 'kind', 'source_identity_algorithm', 'source_identity', 'baseline_source_identity',
                'workload', 'budget_approval', 'runtime_versions', 'profiles', 'outcome'}
    require(isinstance(measured, dict) and set(measured) == required, 'Incomplete/unknown structured performance receipt')
    require(type(measured['schema_version']) is int and measured['schema_version'] == 1 and measured['kind'] == 'resource-comparison', 'Unknown performance receipt contract')
    require(measured['source_identity_algorithm'] == PERFORMANCE_SOURCE_ALGORITHM, 'Unknown performance source identity algorithm')
    for key in ['source_identity', 'baseline_source_identity']:
        require(isinstance(measured[key], str) and re.fullmatch('sha256:[a-f0-9]{64}', measured[key]) is not None, 'Invalid measured source identity')
    require(measured['source_identity'] == performance_source_identity(root), 'Performance candidate source is stale')
    require(measured['outcome'] == 'Passed', 'Performance comparison did not pass')
    versions = measured['runtime_versions']
    require(isinstance(versions, dict) and set(versions) == {'dotnet', 'database', 'cache', 'os', 'architecture'}
            and all(isinstance(v, str) and bool(v.strip()) for v in versions.values()), 'Resolved structured runtime versions required')
    workload = performance_reference(root, measured['workload'])
    require(measured['workload']['path'] == 'eng/resource-workload.json', 'Performance workload must be the current reviewed workload')
    require(isinstance(workload, dict) and type(workload.get('schema_version')) is int and workload['schema_version'] == 1
            and isinstance(workload.get('workload_id'), str) and bool(workload['workload_id'].strip()), 'Invalid workload identity/schema')
    probe_spec = importlib.util.spec_from_file_location('performance_resource_probe', safe_path(root, 'eng/probe-resource-utilization.py'))
    probe = importlib.util.module_from_spec(probe_spec); probe_spec.loader.exec_module(probe)
    require(workload.get('scenarios') == list(probe.SCENARIOS), 'Complete current scenario set required')
    for key in ['concurrency', 'instances']:
        values = workload.get(key)
        require(isinstance(values, list) and bool(values) and all(type(v) is int and v > 0 for v in values)
                and len(set(values)) == len(values), 'Invalid/duplicate workload profile axis')
    require(type(workload.get('measured_requests_per_scenario')) is int and workload['measured_requests_per_scenario'] > 0, 'Reviewed sample count required')
    approval = performance_reference(root, measured['budget_approval'])
    approval_keys = {'schema_version', 'kind', 'status', 'approved_by', 'authorization_reference', 'workload_sha256', 'budgets'}
    require(isinstance(approval, dict) and set(approval) == approval_keys and type(approval['schema_version']) is int
            and approval['schema_version'] == 1 and approval['kind'] == 'resource-budget-approval' and approval['status'] == 'Approved', 'Explicit structured budget approval required')
    require(all(isinstance(approval[k], str) and bool(approval[k].strip()) for k in ['approved_by', 'authorization_reference']), 'Budget reviewer/authorization missing')
    require(workload.get('budget_status') == 'Approved' and workload.get('review_reference') == approval['authorization_reference']
            and approval['workload_sha256'] == measured['workload']['sha256'], 'Budget approval is not bound to the current workload')
    budgets = workload.get('budgets')
    metric_keys = {scenario + '.' + metric for scenario in probe.SCENARIOS for metric in probe.METRICS} | set(probe.STORAGE)
    require(isinstance(budgets, dict) and set(budgets) == metric_keys and all(probe.number(v) for v in budgets.values()), 'Every approved numeric maximum is required; unknown/count-only budgets rejected')
    require(canonical_json(approval['budgets']) == canonical_json(budgets), 'Approved numeric limits differ from workload')
    profiles = measured['profiles']
    expected_profiles = {(c, i) for c in workload['concurrency'] for i in workload['instances']}
    require(isinstance(profiles, list) and len(profiles) == len(expected_profiles), 'Every concurrency/instance profile requires separate captures')
    seen_profiles, seen_runs, seen_hashes, seen_paths = set(), set(), set(), set()
    for pair in profiles:
        require(isinstance(pair, dict) and set(pair) == {'baseline', 'candidate', 'comparison'}, 'Each profile needs baseline, candidate and comparator references')
        baseline = performance_reference(root, pair['baseline']); candidate = performance_reference(root, pair['candidate'])
        for name, capture, source in [('baseline', baseline, measured['baseline_source_identity']), ('candidate', candidate, measured['source_identity'])]:
            require(isinstance(capture, dict), 'Capture must be structured')
            probe.validate_capture(capture, workload)
            require(capture['run_id'] not in seen_runs and pair[name]['sha256'] not in seen_hashes
                    and pair[name]['path'] not in seen_paths, 'Baseline/candidate captures must be independent across all profiles')
            seen_runs.add(capture['run_id']); seen_hashes.add(pair[name]['sha256']); seen_paths.add(pair[name]['path'])
            require(capture['profile']['runtime'] == canonical_json(versions), 'Capture runtime versions differ from measured runtime')
            try:
                provenance = json.loads(capture['provenance'])
            except (ValueError, TypeError) as error:
                raise ValueError('Structured source-bound capture provenance required') from error
            require(isinstance(provenance, dict) and set(provenance) == {'kind', 'collector', 'source_identity', 'run_id'}
                    and provenance['kind'] == 'measured-resource-capture' and isinstance(provenance['collector'], str)
                    and bool(provenance['collector'].strip()) and provenance['source_identity'] == source
                    and provenance['run_id'] == capture['run_id'] and capture['provenance'] == canonical_json(provenance), 'Capture source/run/collector provenance mismatch')
        profile = (candidate['profile']['concurrency'], candidate['profile']['instances'])
        require(profile in expected_profiles and profile not in seen_profiles, 'Missing/duplicate measured profile')
        seen_profiles.add(profile)
        actual = probe.compare(baseline, candidate, workload)
        require(actual['status'] == 'Passed' and not actual['violations'], 'Measured resources exceed budgets or comparison is incomplete')
        actual['capture_sha256'] = {name: pair[name]['sha256'] for name in ['baseline', 'candidate']}
        recorded = performance_reference(root, pair['comparison'])
        require(canonical_json(recorded) == canonical_json(actual), 'Recorded comparator result does not match recomputed captures/maxima')
    require(seen_profiles == expected_profiles, 'Workload profile matrix is incomplete')
    return {'status': 'ValidResourceComparisonReceipt', 'profiles': len(seen_profiles), 'source_identity': measured['source_identity']}


def validate(root, previous=None):
    docs = root / 'docs/corrections'
    require(digest(docs / 'BASELINE_MANIFEST.json') == MANIFEST_SHA, 'Immutable baseline manifest changed')
    manifest = read_json(docs / 'BASELINE_MANIFEST.json')
    require(manifest['schema_version'] == 1 and manifest['source_archive_sha256'] == ARCHIVE_SHA, 'Baseline archive changed')
    require(manifest['source_file_count'] == 451, 'Baseline size changed')
    inventory = docs / 'FILE_REVIEW_INVENTORY.csv'
    require(digest(inventory) == manifest['inventory_sha256'], 'Original inventory changed')
    with inventory.open(encoding='utf-8', newline='') as stream:
        rows = list(csv.DictReader(stream))
    require(len(rows) == len({r['path'] for r in rows}) == 451, 'Lost/duplicate baseline inventory rows')
    require({r['path']: r['sha256'] for r in rows} == manifest['baseline_paths'], 'Baseline hashes lost')
    for row in rows:
        baseline_document(root, row['path'])  # Historical names may have reviewed documentation relocations.
    added = read_json(docs / 'ADDED_FILES.json')
    require(added['schema_version'] == 1 and not set(added['files']).intersection(manifest['baseline_paths']), 'Added-file catalog overlaps baseline')
    ignored = {'.git', '.docker', 'bin', 'obj', 'TestResults', '.correction-results', '.artifacts', 'artifacts', '__pycache__'}
    actual_added = {p.relative_to(root).as_posix(): digest(p) for p in root.rglob('*') if p.is_file()
                   and not ignored.intersection(p.relative_to(root).parts)
                   and p.relative_to(root).as_posix() not in manifest['baseline_paths']
                   and p.relative_to(root).as_posix() != 'docs/corrections/ADDED_FILES.json'}
    require(added['files'] == actual_added, 'Added-file catalog is missing, stale or has untracked files; refresh it after intentional edits')
    for name, expected in manifest['report_sha256'].items():
        require(digest(safe_path(docs, 'evidence/' + name)) == expected, f'Historical review changed: {name}')
    ledger_path = docs / 'evidence/Treehammock_Review_Ledger_Through_10I.json'
    require(digest(ledger_path) == manifest['ledger_sha256'], 'Historical ledger changed')
    original = {x['id']: x for x in read_json(ledger_path)['open_findings']}
    require(len(original) == 83 and set(original) == set(manifest['original_owners']), 'Original ownership incomplete')
    findings = read_json(docs / 'FINDING_CLOSURE.json')
    require(findings['schema_version'] == 1 and findings['source_archive_sha256'] == ARCHIVE_SHA, 'Unknown finding schema/baseline')
    current = {x['id']: x for x in findings['findings']}
    require(len(current) == len(findings['findings']) and set(original) <= set(current), 'Missing/duplicate finding IDs')
    for key, finding in current.items():
        require(finding['status'] in STATES, f'Unknown state: {key}')
        require(finding['owner'] in KNOWN_OWNERS, 'Unknown owner; add a scoped owner specification before assigning new work')
        require(finding['source_archive_sha256'] == ARCHIVE_SHA, 'Finding baseline changed')
        if key in original:
            require(finding['priority'] == original[key]['priority'] and finding['title'] == original[key]['title'], 'Original finding changed')
            require(finding['owner'] == manifest['original_owners'][key], 'Original owner changed without review import')
            require(finding['basis'] == original[key]['basis'], 'Original source observation basis changed')
            prefix = 'Treehammock_Review_' + original[key]['chunk'].replace('R', '', 1) + '_'
            original_refs = {'evidence/' + name for name in manifest['report_sha256'] if name.startswith(prefix) and name.endswith('.md')}
            require(original_refs <= set(finding['review_references']), 'Original review references lost')
        else:
            require(bool(finding.get('review_import')), 'New finding needs explicit review import')
            historical_review_path(docs, finding['review_import'])
        require(bool(finding['review_references']), 'Finding has no source review')
        for reference in finding['review_references']:
            historical_review_path(docs, reference)
        if finding['status'] == 'Closed':
            closure = finding.get('closure') or {}
            require(bool(closure.get('change_id')) and bool(finding['regression_cases']) and bool(finding['required_lanes']), 'Closure lacks change/cases/lanes')
            require_concrete_closure_selectors(root, finding['regression_cases'])
            refs = closure.get('evidence', [])
            require(set(finding['required_lanes']) <= {x['lane'] for x in refs}, 'Closure lacks required integration lanes')
            for reference in refs:
                execution(root, reference, finding['regression_cases'] if reference.get('regression') else (), closure['change_id'])
            require(any(x.get('regression') for x in refs), 'Closure lacks executed regression')
        if finding['status'] == 'Dispositioned':
            require(bool(finding.get('disposition', {}).get('rationale')) and bool(finding['disposition'].get('authorization_reference')), 'Disposition requires rationale and authorization')
        require(isinstance(finding['history'], list), 'History must be append-only list')
    gates = read_json(docs / 'REVIEW_GATES.json')
    require(gates['schema_version'] == 1 and gates['inventory_rows'] == 451, 'Gate schema/inventory mismatch')
    by_id = {g['id']: g for g in gates['gates']}
    require(len(by_id) == len(gates['gates']), 'Duplicate gate IDs')
    pending = [r for r in rows if 'pending full-file' in r['qualification']]
    require(gates['legacy_pending_rows'] == len(pending), 'Pending review count changed')
    require({'source:' + r['path'] for r in pending} | {'runtime', 'migration-recovery', 'performance', 'release', 'cor01-foundation'} <= set(by_id), 'Required review gates lost')
    for gate in by_id.values():
        if gate['id'].startswith('source:'):
            require(gate['kind'] == 'source' and gate['owner'] == 'COR23' and
                    gate['baseline_paths'] == [gate['id'].removeprefix('source:')], 'Source gate boundary changed')
        else:
            fixed = {'runtime': ('runtime', 'COR24'), 'migration-recovery': ('migration-recovery', 'COR02'),
                     'performance': ('performance', 'COR22'), 'release': ('release', 'COR24'), 'cor01-foundation': ('runtime', 'COR01')}
            if gate['id'] in fixed:
                require((gate['kind'], gate['owner']) == fixed[gate['id']], 'Required gate kind/owner changed')
        require(gate['status'] in {'Open', 'Passed'}, 'Unknown review gate state')
        if gate['status'] != 'Passed':
            continue
        require(bool(gate['evidence']), 'Passed gate lacks evidence')
        for ref in gate['evidence']:
            if gate['kind'] == 'source':
                review = read_json(safe_path(root, ref['path']))
                require(digest(safe_path(root, ref['path'])) == ref['sha256'], 'Source review hash mismatch')
                require(review.get('kind') == 'full-source-review' and bool(review.get('reviewer')) and bool(review.get('conclusion')), 'Source review incomplete')
                require(set(gate['baseline_paths']) <= set(review['file_sha256']), 'Source review lacks required paths')
                for path in gate['baseline_paths']:
                    require(digest(safe_path(root, path)) == review['file_sha256'][path], 'Source review is stale')
            elif gate['kind'] == 'performance':
                measured = read_json(safe_path(root, ref['path']))
                require(digest(safe_path(root, ref['path'])) == ref['sha256'], 'Measurement identity mismatch')
                validate_performance(root, measured)
            else:
                execution(root, ref, source_identity=ref['change_id'])
        if gate['id'] in {'runtime', 'cor01-foundation', 'migration-recovery'}:
            required = {'fast', 'sql', 'system'} if gate['id'] == 'runtime' else {'fast', 'sql-harness'} if gate['id'] == 'cor01-foundation' else {'sql'}
            require(required <= {ref.get('lane') for ref in gate['evidence']}, 'Gate lacks required runtime boundary lanes')
        if gate['id'] == 'release':
            require(all(f['status'] in {'Closed', 'Dispositioned'} for f in current.values()), 'Release has open findings')
            require(all(g['status'] == 'Passed' for k, g in by_id.items() if k != 'release'), 'Release has open review gates')
    if previous:
        old_manifest = read_json(previous / 'BASELINE_MANIFEST.json')
        require(old_manifest == manifest, 'Previous baseline manifest changed')
        old = read_json(previous / 'FINDING_CLOSURE.json')
        for item in old['findings']:
            require(item['id'] in current, 'Previous finding lost')
            new = current[item['id']]
            require(new['history'][:len(item['history'])] == item['history'], 'Evidence history rewritten')
            # A PR can record both implementation start and completion. Validate
            # every appended step instead of accepting a skipped state or only
            # looking at the final entry.
            state = item['status']
            for event in new['history'][len(item['history']):]:
                require(event.get('from') == state and event.get('to') in TRANSITIONS[state] and
                        bool(event.get('reason')), 'Invalid finding transition/history')
                state = event['to']
            require(state == new['status'], 'Transition history missing')
        old_gates = read_json(previous / 'REVIEW_GATES.json')
        require({g['id'] for g in old_gates['gates']} <= set(by_id), 'Previous review gate lost')
        for old_gate in old_gates['gates']:
            new_gate = by_id[old_gate['id']]
            require(new_gate['evidence'][:len(old_gate['evidence'])] == old_gate['evidence'], 'Review-gate history rewritten')
    return len(current), len(rows), sum(g['status'] == 'Open' for g in by_id.values())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--previous', type=Path, help='Previous docs/corrections snapshot for transition checks')
    parser.add_argument('--previous-revision', help='Git predecessor revision; absent correction data requires an all-open initial state')
    parser.add_argument('--initial-import-ledger-sha256', help='Explicitly pinned digest for historical ledgers imported after implementation; never permits closed findings or gates')
    parser.add_argument('--run', type=Path, help='Also validate an executed baseline run manifest')
    args = parser.parse_args()
    try:
        previous = args.previous
        temporary = None
        if args.previous_revision:
            require(re.fullmatch(r'(?:HEAD\^|[a-fA-F0-9]{40})', args.previous_revision) is not None, 'Invalid predecessor revision')
            revision = subprocess.run(['git', 'rev-parse', '--verify', args.previous_revision], cwd=args.root, capture_output=True, text=True)
            require(revision.returncode == 0, 'Predecessor revision is unavailable; fetch it before validating transitions')
            prior = subprocess.run(['git', 'show', f'{args.previous_revision}:docs/corrections/BASELINE_MANIFEST.json'], cwd=args.root, capture_output=True, text=True)
            if prior.returncode == 0:
                temporary = tempfile.TemporaryDirectory()
                previous = Path(temporary.name)
                for name in ['BASELINE_MANIFEST.json', 'FINDING_CLOSURE.json', 'REVIEW_GATES.json']:
                    value = subprocess.run(['git', 'show', f'{args.previous_revision}:docs/corrections/{name}'], cwd=args.root, capture_output=True, text=True)
                    require(value.returncode == 0, 'Previous correction snapshot is incomplete')
                    (previous / name).write_text(value.stdout, encoding='utf-8')
            else:
                verify_initial_import(args.root, args.initial_import_ledger_sha256)
        counts = validate(args.root.resolve(), previous)
        if temporary is not None:
            temporary.cleanup()
        if args.run:
            validate_run(args.root.resolve(), read_json(args.run))
        print(f'Evidence integrity passed: {counts[0]} findings, {counts[1]} baseline files, {counts[2]} open gates. No findings closed by this check.')
        return 0
    except (ValueError, KeyError, TypeError, OSError, ET.ParseError) as error:
        print(f'Evidence integrity failed: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
