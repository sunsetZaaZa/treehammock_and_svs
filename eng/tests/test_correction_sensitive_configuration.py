"""Deployment configuration checks; these do not qualify C#/SQL execution."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class SensitiveConfigurationArtifactTests(unittest.TestCase):
    def test_shipped_request_budgets_allow_password_and_factor_completion(self):
        profiles = [json.loads((ROOT / name).read_text())['SensitiveActionSettings']
                    for name in ('appsettings.json', 'appsettings.Example.json')]
        self.assertEqual(profiles[0], profiles[1])
        for settings in profiles:
            self.assertGreaterEqual(settings['MaxRequestsPerSession'], settings['MaxPasswordAttempts'] + settings['MaxFactorAttempts'])
            self.assertGreaterEqual(settings['MaxRequestsPerAccount'], settings['MaxRequestsPerSession'])
            self.assertGreaterEqual(settings['MaxRequestsPerIp'], settings['MaxRequestsPerAccount'])
            self.assertLessEqual(settings['PasswordProofLeaseSeconds'], settings['AttemptWindowSeconds'])
            self.assertLessEqual(settings['ExpirationMinutes'] * 60, settings['AttemptWindowSeconds'])

    def test_new_native_authority_cases_are_mandatory_in_the_harness(self):
        self.assertIn('FullyQualifiedName~Cor08AttemptAndGrantTests', (ROOT / 'eng/correction-baseline.py').read_text())
        manifest = json.loads((ROOT / 'Rigging/Database/Migrations/manifest.json').read_text())
        self.assertEqual(manifest[-1]['version'], 6)
        self.assertEqual(manifest[-1]['name'], '006_atomic_attempts_and_sensitive_grants.sql')


if __name__ == '__main__':
    unittest.main()
