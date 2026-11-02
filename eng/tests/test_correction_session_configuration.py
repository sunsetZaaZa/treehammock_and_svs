"""COR09 delivery/qualification wiring; no C# or SQL execution claim."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class SessionConfigurationArtifactTests(unittest.TestCase):
    def test_shipped_renewal_interval_is_within_access_and_family_lifetime(self):
        profiles = [json.loads((ROOT / name).read_text())['JWTSettings']
                    for name in ('appsettings.json', 'appsettings.Example.json')]
        for settings in profiles:
            access = sum(settings['RefreshTokenAlive' + unit + '_Short'] * scale
                         for unit, scale in [('Days', 86400), ('Hours', 3600), ('Minutes', 60)])
            hard = sum(settings['RefreshTokenAlive' + unit + '_DB'] * scale
                       for unit, scale in [('Days', 86400), ('Hours', 3600), ('Minutes', 60)])
            self.assertLessEqual(1, settings['MinimumRefreshIntervalSeconds'])
            self.assertLessEqual(settings['MinimumRefreshIntervalSeconds'], access)
            self.assertLessEqual(access, hard)
            self.assertNotIn('RefreshWindowMinutes', settings)
            self.assertNotIn('RefreshTokenGenRetries', settings)

    def test_authority_schedules_and_client_fixture_are_required_by_ci(self):
        selector = (ROOT / 'eng/correction-baseline.py').read_text()
        for case in ('Cor09SessionFamilyTests', 'Cor09RefreshHttpTests'):
            self.assertIn('FullyQualifiedName~' + case, selector)
        self.assertIn('node --test tests/client/session-protocol.test.mjs',
                      (ROOT / '.github/workflows/treehammock-ci.yml').read_text())

    def test_pending_proof_authority_and_cache_adapters_are_required(self):
        selector = (ROOT / 'eng/correction-baseline.py').read_text()
        for case in ('Cor10LoginProofTests', 'Cor10PendingProofCacheTests'):
            self.assertIn('FullyQualifiedName~' + case, selector)
        self.assertIn('FullyQualifiedName~Cor10PendingProofCacheTests',
                      (ROOT / 'eng/correction-counter-fixture.py').read_text())

    def test_pre_release_change_has_no_appended_migration(self):
        manifest = json.loads((ROOT / 'Rigging/Database/Migrations/manifest.json').read_text())
        self.assertEqual([entry['version'] for entry in manifest], list(range(1, 7)))
        self.assertEqual(len(list((ROOT / 'Rigging/Database/Migrations').glob('[0-9][0-9][0-9]_*.sql'))), 6)


if __name__ == '__main__':
    unittest.main()
