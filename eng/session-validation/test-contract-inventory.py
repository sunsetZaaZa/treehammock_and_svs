#!/usr/bin/env python3
"""Exercise fail-closed source checkpoint rules; not an authentication suite."""
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('checkpoint',HERE/'collect-contract-inventory.py')
checkpoint=importlib.util.module_from_spec(spec);spec.loader.exec_module(checkpoint)

class CheckpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.base=Path(cls.temp.name);cls.root=cls.base/'source'
        shutil.copytree(HERE.parents[1],cls.root,ignore=shutil.ignore_patterns('bin','obj','__pycache__','*.pyc'))
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def mutate(self,name,change):
        p=self.root/name;old=p.read_bytes()
        try:
            p.write_bytes(change(old))
            with self.assertRaises(AssertionError):checkpoint.collect(self.root,self.base/'evidence')
        finally:p.write_bytes(old)
    def test_checkpoint_is_deterministic(self):
        checkpoint.collect(self.root,self.base/'first');checkpoint.collect(self.root,self.base/'second')
        for p in (self.base/'first').iterdir():self.assertEqual(p.read_bytes(),(self.base/'second'/p.name).read_bytes())
    def test_authentication_source_drift_rejects(self):
        self.mutate('Rigging/Authentication/SessionProtocol.cs',lambda b:b+b'\n// drift\n')
    def test_existing_package_version_drift_rejects(self):
        self.mutate('Directory.Packages.props',lambda b:b.replace(b'Version="8.0.9"',b'Version="8.0.8"'))
    def test_missing_public_project_exclusion_rejects(self):
        self.mutate('treehammock.csproj',lambda b:b.replace(b'<Compile Remove="src/**;tests/**" />',b''))
    def test_frozen_predecessor_manifest_tampering_rejects(self):
        self.mutate('docs/session-validation/SVS-00_SOURCE_INVENTORY.json',lambda b:b+b'\n')

if __name__=='__main__':unittest.main(verbosity=2)
