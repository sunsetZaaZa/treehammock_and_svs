"""Package-integrity tests that do not require .NET or GitHub credentials."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'session_validation_artifacts.py'
spec = importlib.util.spec_from_file_location('svs_release_artifacts', SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
TAG = 'v1.3.0-rc.1'
SHA = '9' * 40

class ReleaseArtifactTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.published = self.root / 'published'
        service = self.published / 'service'
        service.mkdir(parents=True)
        (service / mod.DLL).write_bytes(b'FAKE-BUILT-API')
        (service / 'Treehammock.SessionValidation.Api.runtimeconfig.json').write_text(json.dumps({
            'runtimeOptions': {'frameworks': [{'name': 'Microsoft.NETCore.App', 'version': '10.0.0'},
                                               {'name': 'Microsoft.AspNetCore.App', 'version': '10.0.0'}]}}))
        for framework in ('net8.0', 'net10.0'):
            folder = self.published / 'client' / framework
            folder.mkdir(parents=True)
            for name in mod.CLIENT:
                (folder / name).write_bytes((framework + name).encode())
        self.output = self.root / 'out'

    def package(self):
        mod.package(type('A', (), dict(source=str(self.published), output=str(self.output), tag=TAG, sha=SHA))())
        return self.output / 'session-validation-release-manifest.json'

    def test_archive_has_service_and_client_both_targets(self):
        manifest = self.package()
        report = json.loads(manifest.read_text())
        self.assertFalse(report['production_approved'])
        self.assertTrue((self.output / report['archive']).is_file())
        self.assertIn('service/' + mod.DLL, report['files'])
        self.assertIn('client/net10.0/' + mod.CLIENT[0], report['files'])
        mod.verify(type('A', (), dict(manifest=str(manifest), tag=TAG, sha=SHA))())

    def test_rejects_archive_tampering(self):
        manifest = self.package()
        archive = self.output / json.loads(manifest.read_text())['archive']
        archive.write_bytes(archive.read_bytes() + b'edit')
        with self.assertRaises(mod.PackageError):
            mod.verify(type('A', (), dict(manifest=str(manifest), tag=TAG, sha=SHA))())

    def test_rejects_wrong_commit(self):
        manifest = self.package()
        with self.assertRaises(mod.PackageError):
            mod.verify(type('A', (), dict(manifest=str(manifest), tag=TAG, sha='a'*40))())

    def test_requires_built_client(self):
        (self.published / 'client/net8.0' / mod.CLIENT[0]).unlink()
        with self.assertRaises(mod.PackageError):
            self.package()

    def test_requires_net10_host(self):
        path = self.published / 'service/Treehammock.SessionValidation.Api.runtimeconfig.json'
        path.write_text(json.dumps({'runtimeOptions': {'framework': {'name': 'Microsoft.NETCore.App', 'version': '8.0.1'}}}))
        with self.assertRaises(mod.PackageError):
            self.package()

    def test_refuses_secrets(self):
        (self.published / 'service/password.pfx').write_text('not-a-real-key')
        with self.assertRaises(mod.PackageError):
            self.package()

    def test_refuses_repack_over_existing(self):
        self.package()
        with self.assertRaises(mod.PackageError):
            self.package()

if __name__ == '__main__':
    unittest.main()
