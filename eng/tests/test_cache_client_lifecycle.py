"""Supplemental negative source witnesses; do not claim C# execution or cache/host qualification."""
import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('lifecycle', ROOT/'eng/check-cache-client-lifecycle.py')
lifecycle = importlib.util.module_from_spec(spec); spec.loader.exec_module(lifecycle)
class CacheClientLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)/'source'
        shutil.copytree(ROOT, self.root, ignore=shutil.ignore_patterns('.git','bin','obj','.artifacts','.correction-results','TestResults','__pycache__'))
    def tearDown(self): self.temp.cleanup()
    def reject(self, path, old, new):
        file = self.root/path; text = file.read_text(); self.assertIn(old, text); file.write_text(text.replace(old, new, 1))
        with self.assertRaises(ValueError): lifecycle.validate(self.root)
    def test_consistency_never_claims_native_execution(self): self.assertEqual('NotRun', lifecycle.validate(self.root)['qualification'])
    def test_options_must_be_snapshotted(self): self.reject(lifecycle.OWNER, '_settings = Snapshot(settings)', '_settings = settings')
    def test_start_burst_must_be_single_flight(self): self.reject(lifecycle.OWNER, 'if (!_borrowed && _worker is null)', 'if (!_borrowed)')
    def test_late_candidate_must_be_disposed(self): self.reject(lifecycle.OWNER, 'if (disposeCandidate) candidate.Dispose()', 'if (disposeCandidate) return')
    def test_borrowed_client_must_survive(self): self.reject(lifecycle.OWNER, 'if (!_borrowed) connection?.Dispose()', 'connection?.Dispose()')
    def test_retry_has_a_hard_ceiling(self): self.reject(lifecycle.OWNER, 'Math.Min(60000L,', 'Math.Min(long.MaxValue,')
    def test_retry_input_cannot_overflow(self): self.reject(lifecycle.OWNER, 'Math.Clamp(settings.reconnectRetryPolicy, 10u, 60000u)', 'settings.reconnectRetryPolicy')
    def test_disposal_is_idempotent(self): self.reject(lifecycle.OWNER, 'if (_disposal is not null) return new ValueTask(_disposal)', '')
    def test_host_stop_respects_its_wait_cancellation(self): self.reject(lifecycle.OWNER, 'drain.WaitAsync(cancellationToken)', 'drain')
    def test_disposed_slot_cannot_be_ready(self): self.reject(lifecycle.OWNER, '!_disposed && _connection?.IsConnected', '_connection?.IsConnected')
    def test_cleanup_cannot_hold_lifecycle_lock(self): self.reject(lifecycle.OWNER, '_stop.Cancel();', 'lock (_gate) { _stop.Cancel(); }')
    def test_health_cannot_start_an_independent_client(self): self.reject(lifecycle.HEALTH, '_ = await connection.Database.PingAsync()', '_ = ConnectionMultiplexer.Connect("localhost");\n            _ = await connection.Database.PingAsync()')
    def test_health_cannot_dispose_a_shared_client(self): self.reject(lifecycle.HEALTH, '_ = await connection.Database.PingAsync()', 'await connection.DisposeAsync();\n            _ = await connection.Database.PingAsync()')
    def test_production_active_consumer_must_share_its_role(self): self.reject(lifecycle.DI, 'Get(CacheProfile.ActiveSessions)', 'Get(CacheProfile.AbuseCounters)')
    def test_production_owner_must_have_a_host_disposal_owner(self): self.reject(lifecycle.DI, 'services.AddHostedService(provider => provider.GetRequiredService<CacheConnectionOwner>());', '')
    def test_real_cache_suite_must_be_collected(self): self.reject('eng/correction-baseline.py', '|FullyQualifiedName~Cor23NCacheOwnershipTests', '')
    def test_CI_must_check_lifecycle_contracts(self): self.reject('.github/workflows/treehammock-ci.yml', 'python3 eng/check-cache-client-lifecycle.py', 'true')
    def test_both_native_cache_products_must_be_in_CI(self): self.reject('.github/workflows/treehammock-ci.yml', 'cache-product: [redis, dragonfly]', 'cache-product: [redis]')
    def test_fixture_selection_is_closed_and_retains_unique_project_ownership(self):
        spec = importlib.util.spec_from_file_location('sqlfixture', self.root/'eng/correction-sql-fixture.py')
        fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
        redis = fixture.compose_command('owned-123', 'redis'); dragonfly = fixture.compose_command('owned-123', 'dragonfly')
        self.assertEqual(redis, dragonfly[:-2]); self.assertIn('owned-123', redis)
        self.assertTrue(dragonfly[-1].endswith('docker-compose.corrections.dragonfly.yml'))
        with self.assertRaises(ValueError): fixture.compose_command('owned-123', 'shared-custom')
if __name__ == '__main__': unittest.main()
