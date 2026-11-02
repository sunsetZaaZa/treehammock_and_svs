#!/usr/bin/env python3
"""Probe controlled loopback recovery fixtures; output redacted protocol/timing distributions.
Input: {"base_url":"http://127.0.0.1:PORT", "controlled_delivery":true,
"cohorts":[{"name":"eligible", "request":{"identifier":"fixture","deliveryChannel":"email"},
"verify":{"resetId":"issued UUID", "keyCode":"known-invalid"}}, ...]}.
Use independently seeded eligible/unknown/expired/canceled fixtures and pinned controlled delivery.
"""
import argparse
import bisect
import json
from pathlib import Path
import random
import statistics
import time
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from urllib.error import HTTPError

NAMES = {'eligible', 'unknown', 'expired', 'canceled'}

def shape(value):
    if isinstance(value, dict):
        return {k: ('opaque-present' if v else v) if k.lower() in {'resetid', 'nonce', 'continuation'} else shape(v) for k, v in value.items()}
    if isinstance(value, list): return [shape(v) for v in value]
    return value

def ks(a, b):
    a, b = sorted(a), sorted(b)
    return max(abs(bisect.bisect_right(a, x) / len(a) - bisect.bisect_right(b, x) / len(b)) for x in a + b)

def measure(base, endpoint, payload):
    started = time.monotonic()
    req = Request(base + '/account/password-reset/' + endpoint, json.dumps(payload).encode(), {'Content-Type': 'application/json'}, method='POST')
    try: response = urlopen(req, timeout=15)
    except HTTPError as error: response = error
    with response:
        result = response.status, shape(json.loads(response.read(100000)))
    return result, (time.monotonic() - started) * 1000

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixtures', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--samples', type=int, default=100)
    args = parser.parse_args()
    fixtures = json.loads(args.fixtures.read_text())
    url = fixtures['base_url'].rstrip('/'); target = urlsplit(url)
    if target.scheme != 'http' or target.hostname != '127.0.0.1' or target.path or not fixtures.get('controlled_delivery'):
        parser.error('Only explicit controlled-delivery loopback fixtures are supported')
    cohorts = fixtures['cohorts']
    if {c['name'] for c in cohorts} != NAMES or len(cohorts) != 4 or not 30 <= args.samples <= 1000:
        parser.error('Four independently seeded cohorts and 30–1000 samples are required')
    report = {'status': 'Failed', 'protocol': [], 'timing_ms': {}, 'comparisons': [],
              'qualification': 'Controlled host protocol/timing only. Live Turnstile qualification is separate.'}
    reference = None; valid = True
    for c in cohorts:
        for attempt in range(1, 7):
            observed, _ = measure(url, 'verify', c['verify'])
            if reference is None: reference = observed
            valid &= observed == reference and observed[0] == 401
            report['protocol'].append({'cohort': c['name'], 'attempt': attempt, 'same_401_protocol': observed == reference and observed[0] == 401})
    timings = {c['name']: [] for c in cohorts}; outward = None
    order = cohorts * args.samples; random.Random(14).shuffle(order)
    for c in order:
        observed, elapsed = measure(url, 'request', c['request'])
        if outward is None: outward = observed
        valid &= observed == outward and observed[0] == 202
        timings[c['name']].append(elapsed)
    for name, values in timings.items():
        report['timing_ms'][name] = {'samples': len(values), 'p50': statistics.median(values), 'p95': sorted(values)[int(.95 * (len(values) - 1))], 'max': max(values)}
    for name in sorted(NAMES - {'eligible'}):
        statistic = ks(timings['eligible'], timings[name]); limit = 1.63 * (2 / args.samples) ** .5
        median_gap = abs(statistics.median(timings['eligible']) - statistics.median(timings[name]))
        valid &= statistic <= limit and median_gap <= 25
        report['comparisons'].append({'cohort': name, 'ks': statistic, 'limit': limit, 'median_gap_ms': median_gap})
    report['status'] = 'Passed' if valid else 'Failed'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print('evidence: ' + str(args.output))
    return 0 if valid else 1
if __name__ == '__main__': raise SystemExit(main())
