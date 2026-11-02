"""Source mutation witnesses only; do not claim C#/SQL/Dragonfly execution."""
import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('warmup',ROOT/'eng/check-session-cache-warmup.py')
warmup=importlib.util.module_from_spec(spec);spec.loader.exec_module(warmup)
class WarmupSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        paths=[warmup.WORKER,warmup.REPO,warmup.CACHE,warmup.SETTINGS,warmup.DI,
               'Rigging/Authentication/JsonWebTokenMiddleware.cs','eng/correction-baseline.py',
               '.github/workflows/treehammock-ci.yml','deploy/session-cache-warmup.env.example',
               'docker-compose.integration.yml','treehammock.Tests/Unit/SessionCacheWarmupTests.cs',
               'treehammock.Tests.SqlContracts/Integration/Database/SessionCacheWarmupSqlTests.cs']
        paths += [p.name for p in ROOT.glob('appsettings*.json')]
        for name in paths:
            p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/name,p)
    def tearDown(self):self.temp.cleanup()
    def reject(self,path,old,new):
        p=self.root/path;src=p.read_text();self.assertIn(old,src);p.write_text(src.replace(old,new,1))
        with self.assertRaises(ValueError):warmup.validate(self.root)
    def test_source_consistency_cannot_claim_native_execution(self):
        result=warmup.validate(self.root);self.assertEqual('NotRun',result['qualification']);self.assertEqual(0,result['native_cases_executed'])
    def test_existing_cache_entries_cannot_be_overwritten(self):self.reject(warmup.CACHE,'When.NotExists','When.Always')
    def test_batch_deadline_cannot_be_removed(self):self.reject(warmup.WORKER,'batch.CancelAfter','batch.Cancel')
    def test_run_duration_cannot_be_removed(self):self.reject(warmup.WORKER,'lifetime.CancelAfter','lifetime.Cancel')
    def test_retries_must_remain_paced_and_cancelable(self):self.reject(warmup.WORKER,'Task.Delay(TimeSpan.FromSeconds(_settings.IntervalSeconds), lifetime.Token)','Task.CompletedTask')
    def test_session_hard_expiry_caps_ttl(self):self.reject(warmup.WORKER,'session.EffectiveSessionExpiration < expiry','false')
    def test_entitlement_boundary_caps_ttl(self):self.reject(warmup.WORKER,'session.entitlements.NextBoundary','null')
    def test_stale_account_stamp_is_excluded(self):self.reject(warmup.REPO,'s.account_security_stamp = a.security_stamp','true')
    def test_query_must_remain_bounded(self):self.reject(warmup.REPO,'limit @limit','')
    def test_database_read_must_accept_cancellation(self):self.reject(warmup.REPO,'ReadAsync(cancellationToken)','ReadAsync()')
    def test_settings_must_be_startup_validated(self):self.reject(warmup.DI,'AddValidatedOptions<SessionCacheWarmupSettings>','AddOptions<SessionCacheWarmupSettings>')
    def test_request_time_authority_cannot_be_removed(self):self.reject('Rigging/Authentication/JsonWebTokenMiddleware.cs','else if (!await ValidateCachedSessionTrust(','else if (false && !await ValidateCachedSessionTrust(')
    def test_real_cache_tests_cannot_be_excluded(self):self.reject('eng/correction-baseline.py','|FullyQualifiedName~SessionCacheWarmupSqlTests','')
    def test_database_batch_bound_cannot_be_expanded(self):self.reject(warmup.SETTINGS,'[Range(1, 1000)]','[Range(1, 1000000)]')
if __name__=='__main__':unittest.main()
