"""Regression guards for active source layout, not native qualification."""
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
module_spec = importlib.util.spec_from_file_location('source_layout', ROOT / 'eng/verify-source-layout.py')
audit_module = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(audit_module)

class LayoutRegressionTests(unittest.TestCase):
    def test_current_source_graph_and_documentation_resolve(self):
        result = audit_module.audit(ROOT)
        self.assertEqual('PASS', result['status'], result['failures'])
        self.assertEqual(19, result['solutions']['treehammock.sln']['projects'])
        self.assertEqual(17, result['solutions']['treehammock.sln']['session_validation_projects'])
        self.assertGreater(result['relative_markdown_links_inspected'], 100)

    def test_missing_solution_never_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            result = audit_module.audit(Path(directory))
            self.assertEqual('FAIL', result['status'])
            self.assertTrue(any('missing solution' in finding for finding in result['failures']))

    def test_project_file_and_sql_resource_identity_are_verified(self):
        source = (ROOT / 'src/Treehammock.SessionValidation.Storage/Treehammock.SessionValidation.Storage.csproj').read_text()
        self.assertIn('inspect-validator-identity.sql', source)
        self.assertIn('LogicalName="svs05-inspect-identity.sql"', source)

if __name__ == '__main__':
    unittest.main()
