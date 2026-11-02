#!/usr/bin/env python3
"""Tooling regression tests. No .NET application, SQL or cache cases are executed."""
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("inventory", HERE / "collect-source-inventory.py")
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


class InventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.base = Path(cls.temp.name)
        cls.root = cls.base / "source"
        shutil.copytree(HERE.parents[1], cls.root, ignore=shutil.ignore_patterns("__pycache__"))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def collect(self, name="evidence"):
        return inventory.collect(self.root, self.base / name)

    def test_deterministic_and_preserves_all_baseline_bytes(self):
        first = self.collect("first")
        self.assertEqual(first["static_status"], "PASS")
        self.assertEqual(first["baseline_files"], 1042)
        self.collect("second")
        for path in (self.base / "first").iterdir():
            self.assertEqual(path.read_bytes(), (self.base / "second" / path.name).read_bytes())
        self.assertFalse(first["release_ready"])
        self.assertEqual(first["matrix"]["native_execution"], "NotRun")

    def test_changed_existing_file_fails(self):
        path = self.root / "Program.cs"
        old = path.read_bytes()
        try:
            path.write_bytes(old + b"\n// drift\n")
            report = self.collect()
            self.assertEqual(report["static_status"], "FAIL")
            self.assertIn("Program.cs", report["changed_baseline_files"])
        finally:
            path.write_bytes(old)

    def test_deleted_existing_file_fails(self):
        path = self.root / "Program.cs"
        old = path.read_bytes()
        try:
            path.unlink()
            self.assertIn("Program.cs", self.collect()["missing_baseline_files"])
        finally:
            path.write_bytes(old)

    def test_tampered_frozen_manifest_fails(self):
        path = self.root / "docs/session-validation/COR25_Q06_SOURCE_SHA256.json"
        old = path.read_bytes()
        try:
            path.write_bytes(old + b"\n")
            with self.assertRaisesRegex(ValueError, "manifest identity"):
                self.collect()
        finally:
            path.write_bytes(old)

    def test_unexpected_runtime_addition_fails(self):
        path = self.root / "Rigging/SvsUnexpected.cs"
        try:
            path.write_text("// accidental runtime source")
            self.assertIn("Rigging/SvsUnexpected.cs", self.collect()["unexpected_additions"])
        finally:
            path.unlink(missing_ok=True)

    def test_symlink_rejected(self):
        path = self.root / "eng/session-validation/escape"
        try:
            path.symlink_to(self.root / "Program.cs")
            with self.assertRaisesRegex(ValueError, "Symlink"):
                self.collect()
        finally:
            path.unlink(missing_ok=True)

    def test_output_inside_source_rejected(self):
        with self.assertRaisesRegex(ValueError, "outside source"):
            inventory.collect(self.root, self.root / "evidence")

    def test_sql_closure_includes_writes_locks_and_trigger_side_effects(self):
        audit = inventory.sql_audit((self.root / inventory.SQL_PATH).read_text())
        nodes = audit["routines"]
        self.assertFalse(audit["safe_for_readonly_role"])
        self.assertTrue(nodes["cor02_lock_account_authority"]["row_locks"])
        self.assertEqual(nodes["get_session"]["calls"], ["cor20_resolve_account"])
        self.assertIn({"operation": "update", "table": "accounts"}, nodes["cor20_resolve_account"]["writes"])
        self.assertIn({"operation": "update", "table": "sessions"}, nodes["cor20_resolve_account"]["writes"])
        self.assertIn("cor18_family_security_event", nodes["cor20_resolve_account"]["trigger_calls"])
        self.assertIn({"operation": "delete", "table": "delete_standby"}, nodes["cor18_retire_delete"]["writes"])
        self.assertEqual(len(nodes), 16)

    def test_missing_matrix_reference_rejected(self):
        matrix = json.loads((HERE / "session-decision-matrix.json").read_text())
        matrix["cases"][0]["references"] = ["does-not-exist.cs"]
        with self.assertRaisesRegex(ValueError, "Missing matrix reference"):
            inventory.validate_matrix(matrix, self.root)

    def test_no_fabricated_native_result(self):
        matrix = json.loads((HERE / "session-decision-matrix.json").read_text())
        matrix["cases"][0]["native_status"] = "PASS"
        with self.assertRaisesRegex(ValueError, "native fixture"):
            inventory.validate_matrix(matrix, self.root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
