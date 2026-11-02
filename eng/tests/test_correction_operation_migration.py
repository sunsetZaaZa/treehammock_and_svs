"""Qualify artifact generation for expand migrations, not PostgreSQL execution."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('operation_generator', ROOT/'eng/generate-database-baseline.py')
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)

class OperationMigrationGenerationTests(unittest.TestCase):
    def test_tables_precede_new_functions_and_routines_are_defined_once(self):
        sql = generator.generate(ROOT)
        self.assertLess(sql.index('CREATE TABLE security_operations'), sql.index('create or replace function lock_security_operation'))
        self.assertEqual(sql.count('create or replace function lock_security_operation('), 1)
        self.assertEqual(sql.count('create or replace function reconcile_security_operation('), 1)
        self.assertEqual(sql.count('create or replace function purge_security_operations('), 1)

    def test_unsupported_mutating_ddl_is_rejected_even_when_checksummed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(ROOT/'Rigging/Database', root/'Rigging/Database')
            overlay = root / generator.SVS_READ_SQL
            overlay.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / generator.SVS_READ_SQL, overlay)
            migrations = root/'Rigging/Database/Migrations'
            manifest = migrations/'manifest.json'
            entries = json.loads(manifest.read_text())
            script = migrations/'003_security_operations.sql'
            script.write_text(script.read_text() + '\nDROP TABLE accounts;\n')
            next(item for item in entries if item['name'] == script.name)['sha256'] = hashlib.sha256(script.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(entries))
            with self.assertRaisesRegex(ValueError, 'Unsupported'):
                generator.generate(root)

    def test_receipt_migration_cannot_be_rewritten_after_predecessor_recording(self):
        current = json.loads((ROOT/'Rigging/Database/Migrations/manifest.json').read_text())
        changed = [dict(item) for item in current]
        changed[-1]['sha256'] = '0'*64
        with self.assertRaisesRegex(ValueError, 'identity'):
            generator.validate_predecessor(current, changed)

if __name__ == '__main__':
    unittest.main()
