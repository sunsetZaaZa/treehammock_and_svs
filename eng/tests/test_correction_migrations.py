"""Mutation checks for immutable migration artifacts and generated baseline integrity."""
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('migration_baseline', ROOT / 'eng/generate-database-baseline.py')
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)


class MigrationArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        shutil.copytree(ROOT / 'Rigging/Database', self.root / 'Rigging/Database')
        overlay = self.root / generator.SVS_READ_SQL
        overlay.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / generator.SVS_READ_SQL, overlay)
        self.directory = self.root / 'Rigging/Database/Migrations'

    def tearDown(self):
        self.temp.cleanup()

    def test_both_baselines_match_the_ordered_bundle(self):
        expected = generator.generate(self.root)
        for name in ['000_canonical_database.sql', '000_treehammock_canonical_database.sql']:
            self.assertEqual((self.root / 'Rigging/Database/Baseline' / name).read_text(), expected)

    def test_predecessor_migration_cannot_be_rewritten_or_removed(self):
        current = json.loads((self.directory / 'manifest.json').read_text())
        for altered in [current[:1], [dict(current[0], sha256='0' * 64), current[1]]]:
            with self.assertRaisesRegex(ValueError, 'identity'):
                generator.validate_predecessor(current, altered)
        generator.validate_predecessor(current[:1], current)

    def test_migration_function_parameters_are_defined(self):
        import re
        script = (self.directory / '002_transaction_authority.sql').read_text()
        for function in generator.PATTERN.finditer(script):
            parameters = set(re.findall(r'\bp_\w+\b', function.group().split('as $$')[0]))
            referenced = set(re.findall(r'\bp_\w+\b', function.group()))
            self.assertFalse(referenced - parameters, function.group(1))

    def test_changed_migration_bytes_are_rejected(self):
        path = self.directory / '002_transaction_authority.sql'
        path.write_text(path.read_text() + '-- altered migration\n')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            generator.generate(self.root)

    def test_mutated_session_validator_sql_is_rejected(self):
        path = self.root / generator.SVS_READ_SQL
        path.write_bytes(path.read_bytes() + b'-- unaudited addition\n')
        with self.assertRaisesRegex(ValueError, 'SessionValidation SQL source checksum'):
            generator.generate(self.root)

    def test_reordered_or_gapped_versions_are_rejected(self):
        path = self.directory / 'manifest.json'
        value = json.loads(path.read_text())
        value.reverse()
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'sequence'):
            generator.generate(self.root)

    def test_manifest_cannot_read_outside_migration_directory(self):
        path = self.directory / 'manifest.json'
        value = json.loads(path.read_text())
        value[0]['name'] = '../Baseline/000_canonical_database.sql'
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'filename'):
            generator.generate(self.root)

    def test_public_result_contract_drift_is_rejected_even_with_updated_hash(self):
        import hashlib
        path = self.directory / '002_transaction_authority.sql'
        changed = path.read_text().replace('create or replace function complete_verify_account(\n    p_accountId uuid,',
                                          'create or replace function complete_verify_account(\n    p_accountId text,')
        path.write_text(changed)
        manifest = self.directory / 'manifest.json'
        value = json.loads(manifest.read_text())
        value[1]['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        manifest.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'contract changed'):
            generator.generate(self.root)


if __name__ == '__main__':
    unittest.main()
