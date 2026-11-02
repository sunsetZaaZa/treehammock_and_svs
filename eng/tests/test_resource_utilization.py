import copy
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('cor22', Path(__file__).resolve().parents[1] / 'probe-resource-utilization.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class ResourceEvidenceTests(unittest.TestCase):
    def fixtures(self):
        workload = {'concurrency': [1], 'instances': [1], 'measured_requests_per_scenario': 1, 'workload_id': 'owned', 'budget_status': 'Approved', 'review_reference': 'fixture-review',
            'budgets': {s + '.' + m: 5 for s in probe.SCENARIOS for m in probe.METRICS}}
        workload['budgets'].update({m: 5 for m in probe.STORAGE})
        capture = {'profile': {'concurrency': 1, 'instances': 1, **{k: 'fixture' for k in ('hardware', 'runtime', 'argon_policy', 'pool_limits', 'cache_tls_profile', 'fixture_seed', 'provider_profile')}}, 'workload_id': 'owned', 'run_id': 'baseline', 'provenance': 'synthetic test only',
            'requests': [dict(scenario=s, **{m: 1 for m in probe.METRICS}) for s in probe.SCENARIOS],
            'storage': {m: 1 for m in probe.STORAGE}}
        candidate = copy.deepcopy(capture)
        candidate['run_id'] = 'candidate'
        return capture, candidate, workload

    def test_percentile_interpolates_and_is_order_independent(self):
        self.assertEqual(probe.percentile([20, 0, 10], .95), 19)
        self.assertIsNone(probe.percentile([], .95))

    def test_missing_or_unreviewed_budgets_never_pass(self):
        a, b, w = self.fixtures()
        del w['budgets']['warm_auth.cache_writes']
        self.assertEqual(probe.compare(a, b, w)['status'], 'IncompleteBudgets')
        w['budget_status'] = 'Proposed'
        self.assertEqual(probe.compare(a, b, w)['status'], 'PendingBudgetApproval')

    def test_regression_fails_even_when_other_metrics_improve(self):
        a, b, w = self.fixtures()
        b['requests'][0]['pool_wait_ms'] = 6
        report = probe.compare(a, b, w)
        self.assertEqual(report['status'], 'Failed')
        self.assertEqual(report['violations'], ['warm_auth.pool_wait_ms'])

    def test_nan_negative_boolean_missing_or_sensitive_fields_are_rejected(self):
        for value in (float('nan'), float('inf'), -1, True, None):
            a, b, w = self.fixtures()
            b['requests'][0]['duration_ms'] = value
            with self.assertRaises(ValueError):
                probe.compare(a, b, w)
        a, b, w = self.fixtures()
        b['requests'][0]['access_token'] = 'do-not-report'
        with self.assertRaises(ValueError):
            probe.compare(a, b, w)

    def test_different_workloads_counts_or_same_capture_cannot_pass(self):
        for mutation in ('identity', 'count', 'run', 'profile'):
            a, b, w = self.fixtures()
            if mutation == 'identity':
                b['workload_id'] = 'different'
            elif mutation == 'count':
                b['requests'].append(copy.deepcopy(b['requests'][0]))
            elif mutation == 'profile':
                b['profile']['hardware'] = 'different'
            else:
                b['run_id'] = a['run_id']
            with self.assertRaises(ValueError):
                probe.compare(a, b, w)

    def test_complete_reviewed_fixture_has_comparable_costs(self):
        a, b, w = self.fixtures()
        self.assertEqual(probe.compare(a, b, w)['status'], 'Passed')


if __name__ == '__main__':
    unittest.main()
