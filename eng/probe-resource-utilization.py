#!/usr/bin/env python3
"""Compare captured baseline/candidate costs; missing evidence never becomes a pass."""
import argparse
import hashlib
import json
import math
from pathlib import Path

METRICS = ('duration_ms', 'db_commands', 'cache_writes', 'pool_wait_ms', 'lock_wait_ms', 'cpu_ms', 'allocated_bytes')
STORAGE = ('wal_bytes', 'storage_bytes', 'retained_rows', 'peak_working_set_bytes')
SCENARIOS = ('warm_auth', 'cold_auth', 'cache_down', 'reset_lookup', 'normalized_phone', 'deep_retention', 'account_delete')


def number(value):
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value) and value >= 0
    except OverflowError:
        return False


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lo = int(position)
    hi = min(lo + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (position - lo)


def validate_capture(capture, workload):
    if not isinstance(capture, dict) or set(capture) != {'workload_id', 'run_id', 'provenance', 'profile', 'requests', 'storage'}:
        raise ValueError('Capture fields must match the documented aggregate-only contract')
    if capture['workload_id'] != workload['workload_id'] or any(not isinstance(capture[k], str) or not capture[k].strip() for k in ('run_id', 'provenance')):
        raise ValueError('Capture needs matching workload identity and collection provenance')
    profile = capture['profile']
    fields = {'concurrency', 'instances', 'hardware', 'runtime', 'argon_policy', 'pool_limits', 'cache_tls_profile', 'fixture_seed', 'provider_profile'}
    if not isinstance(profile, dict) or set(profile) != fields:
        raise ValueError('Capture needs the complete workload profile')
    if type(profile['concurrency']) is not int or profile['concurrency'] not in workload.get('concurrency', []):
        raise ValueError('Concurrency profile does not match workload')
    if type(profile['instances']) is not int or profile['instances'] not in workload.get('instances', []):
        raise ValueError('Instance profile does not match workload')
    if any(not isinstance(profile[k], str) or not profile[k] for k in fields - {'concurrency', 'instances'}):
        raise ValueError('Capture profile controls are missing')
    requests = capture['requests']
    if not isinstance(requests, list) or not requests:
        raise ValueError('No captured requests')
    for row in requests:
        if not isinstance(row, dict) or set(row) != {'scenario', *METRICS} or row['scenario'] not in SCENARIOS:
            raise ValueError('Only documented scenario and numeric cost fields are accepted')
        if any(type(row[m]) is not int for m in ('db_commands', 'cache_writes', 'allocated_bytes')):
            raise ValueError('Command and allocation counts must be integers')
        if not all(number(row[m]) for m in METRICS):
            raise ValueError('Every request cost must be measured and nonnegative')
    if not isinstance(capture['storage'], dict) or set(capture['storage']) != set(STORAGE) or not all(number(capture['storage'][m]) for m in STORAGE):
        raise ValueError('Every storage/WAL observation must be measured')
    if any(not any(r['scenario'] == s for r in requests) for s in SCENARIOS):
        raise ValueError('Missing workload scenario')


def compare(baseline, candidate, workload):
    validate_capture(baseline, workload)
    validate_capture(candidate, workload)
    if baseline['profile'] != candidate['profile']:
        raise ValueError('Baseline and candidate profile controls differ')
    expected = workload.get('measured_requests_per_scenario')
    if type(expected) is not int or expected < 1:
        raise ValueError('Reviewed workload sample count is missing')
    if baseline['run_id'] == candidate['run_id']:
        raise ValueError('Baseline and candidate must be independent captures')
    result = {'status': 'PendingBudgetApproval', 'workload_id': workload['workload_id'], 'scenarios': {}, 'storage': {}, 'violations': []}
    budgets = workload.get('budgets')
    approved = workload.get('budget_status') == 'Approved' and isinstance(workload.get('review_reference'), str) and bool(workload['review_reference'].strip()) and isinstance(budgets, dict)
    complete = approved
    for scenario in SCENARIOS:
        a = [r for r in baseline['requests'] if r['scenario'] == scenario]
        b = [r for r in candidate['requests'] if r['scenario'] == scenario]
        if len(a) != len(b) or len(a) != expected:
            raise ValueError('Scenario sample counts differ')
        observations = {}
        for metric in METRICS:
            old = percentile([r[metric] for r in a], .95)
            new = percentile([r[metric] for r in b], .95)
            key = scenario + '.' + metric
            maximum = budgets.get(key) if approved else None
            if not number(maximum):
                maximum = None
                complete = False
            elif new > maximum:
                result['violations'].append(key)
            observations[metric] = {'baseline_p95': old, 'candidate_p95': new, 'delta': new - old,
                'maximum': maximum, 'samples': len(a)}
        result['scenarios'][scenario] = observations
    for metric in STORAGE:
        maximum = budgets.get(metric) if approved else None
        if not number(maximum):
            maximum = None
            complete = False
        elif candidate['storage'][metric] > maximum:
            result['violations'].append(metric)
        result['storage'][metric] = {'baseline': baseline['storage'][metric], 'candidate': candidate['storage'][metric], 'maximum': maximum}
    if approved:
        result['status'] = 'IncompleteBudgets' if not complete else 'Failed' if result['violations'] else 'Passed'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workload', type=Path, required=True)
    parser.add_argument('--baseline', type=Path)
    parser.add_argument('--candidate', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = {'status': 'Blocked', 'reason': 'Real baseline/candidate workload captures have not been supplied.'}
    if args.baseline and args.candidate:
        try:
            report = compare(json.loads(args.baseline.read_text()), json.loads(args.candidate.read_text()), json.loads(args.workload.read_text()))
        except (ValueError, KeyError, TypeError):
            report = {'status': 'InvalidEvidence', 'reason': 'Capture or budget contract is incomplete or invalid.'}
        report['capture_sha256'] = {name: hashlib.sha256(p.read_bytes()).hexdigest() for name, p in [('baseline', args.baseline), ('candidate', args.candidate)]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(report['status'])
    return 0 if report['status'] == 'Passed' else 2


if __name__ == '__main__':
    raise SystemExit(main())
