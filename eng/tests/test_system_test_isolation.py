"""Supplemental config/source mutation checks, never native qualification evidence."""
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('isolation', ROOT/'eng/check-system-test-isolation.py')
isolation = importlib.util.module_from_spec(spec); spec.loader.exec_module(isolation)

class SystemTestIsolationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)/'source'
        shutil.copytree(ROOT, self.root, ignore=shutil.ignore_patterns('.git','bin','obj','.artifacts','.correction-results','TestResults','__pycache__'))
    def tearDown(self): self.temp.cleanup()
    def replace(self, path, old, new):
        p = self.root/path; text = p.read_text(); self.assertIn(old, text); p.write_text(text.replace(old,new,1))
    def test_current_composition_and_profiles_remain_native_pending(self):
        result = isolation.validate(self.root); self.assertEqual(result['qualification'],'NotRun'); self.assertEqual(result['checked_default_profiles'],5)
    def test_generic_container_cannot_become_the_allowed_boundary(self):
        self.replace('Rigging/Hosting/SystemTestCapability.cs','EnvironmentName = "Testing"','EnvironmentName = "Container"')
        with self.assertRaises(ValueError): isolation.validate(self.root)
    def test_unconditional_capture_registration_is_rejected(self):
        self.replace('Rigging/DependencyInjection/TreehammockServiceCollectionExtensions.cs','if (systemTestCapability.CaptureEnabled)','services.AddSingleton<ISystemTestDeliveryCapture, SystemTestDeliveryCapture>();\n        if (systemTestCapability.CaptureEnabled)')
        with self.assertRaises(ValueError): isolation.validate(self.root)
    def test_removing_controller_isolation_is_rejected(self):
        self.replace('Rigging/Hosting/SystemTestControllerFeatureProvider.cs','feature.Controllers.Remove(type)','_ = type')
        with self.assertRaises(ValueError): isolation.validate(self.root)
    def test_deployable_defaults_cannot_enable_capture(self):
        p = self.root/'appsettings.Container.json'; settings = json.loads(p.read_text()); settings['SystemTestSettings']['Enabled'] = True; p.write_text(json.dumps(settings))
        with self.assertRaises(ValueError): isolation.validate(self.root)
    def test_test_harness_cannot_use_deployable_environment(self):
        self.replace('docker-compose.testing.yml','ASPNETCORE_ENVIRONMENT: Testing','ASPNETCORE_ENVIRONMENT: Container')
        with self.assertRaises(ValueError): isolation.validate(self.root)
    def test_proxy_test_runner_cannot_omit_explicit_test_overlay(self):
        self.replace('eng/docker-http-contracts-proxy.sh','-f docker-compose.testing.yml','-f docker-compose.api-proxy.yml')
        with self.assertRaises(ValueError): isolation.validate(self.root)
    def test_powershell_proxy_runner_cannot_omit_test_overlay(self):
        self.replace('eng/docker-http-contracts-proxy.ps1', "'-f', 'docker-compose.testing.yml'", "'-f', 'docker-compose.api-proxy.yml'")
        with self.assertRaises(ValueError): isolation.validate(self.root)
    def test_powershell_testing_overlay_must_follow_generic_proxy(self):
        self.replace('eng/docker-http-contracts-proxy.ps1', "'-f', 'docker-compose.api-proxy.yml', '-f', 'docker-compose.testing.yml'", "'-f', 'docker-compose.testing.yml', '-f', 'docker-compose.api-proxy.yml'")
        with self.assertRaises(ValueError): isolation.validate(self.root)
    def test_multiple_header_acceptance_is_rejected(self):
        self.replace('Rigging/Hosting/SystemTestCapability.cs','supplied.Count != 1','supplied.Count < 1')
        with self.assertRaises(ValueError): isolation.validate(self.root)

if __name__ == '__main__': unittest.main()
