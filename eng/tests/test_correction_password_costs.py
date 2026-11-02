"""Configuration/artifact checks, separate from native application qualification."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class PasswordConfigurationArtifactTests(unittest.TestCase):
    def test_shipped_profiles_use_explicit_bytes_and_consistent_bounded_work(self):
        profiles = [json.loads((ROOT / name).read_text()) for name in ('appsettings.json', 'appsettings.Example.json')]
        for profile in profiles:
            login = profile['LoginSettings']
            self.assertNotIn('Argon2MemoryUsePer', login)
            self.assertEqual(login['Argon2MemoryBytes'], 64 * 1024 * 1024)
            self.assertEqual(login['Argon2Iterations'], 3)
            work = login['PasswordWork']
            self.assertGreaterEqual(work['MemoryBudgetBytes'], work['MaxEncodedMemoryBytes'])
            self.assertGreaterEqual(work['MaxEncodedMemoryBytes'], login['Argon2MemoryBytes'])
            self.assertGreaterEqual(work['CpuBudget'], work['MaxEncodedParallelism'])
            self.assertLessEqual(work['MaxActiveOperations'] * login['Argon2MemoryBytes'], work['MemoryBudgetBytes'])
            self.assertLessEqual(work['MaxQueuedOperations'], 8)
        self.assertEqual(profiles[0]['LoginSettings']['PasswordWork'], profiles[1]['LoginSettings']['PasswordWork'])

    def test_new_migration_retains_existing_epoch_and_public_sql_contracts(self):
        source = (ROOT / 'Rigging/Database/Migrations/005_password_cost_upgrade.sql').read_text()
        self.assertIn('security_stamp = p_stamp and hashed_password = p_old_hash', source)
        self.assertNotIn('set security_stamp', source)
        manifest = json.loads((ROOT / 'Rigging/Database/Migrations/manifest.json').read_text())
        self.assertEqual([entry['version'] for entry in manifest[:5]], [1, 2, 3, 4, 5])
