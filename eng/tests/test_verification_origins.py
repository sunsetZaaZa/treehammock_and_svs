"""COR23G supplemental configuration/source mutations; not native link qualification."""
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('origins',ROOT/'eng/check-verification-origins.py');origins=importlib.util.module_from_spec(spec);spec.loader.exec_module(origins)
class VerificationOriginTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'source'
        shutil.copytree(ROOT,self.root,ignore=shutil.ignore_patterns('.git','bin','obj','.artifacts','.correction-results','TestResults','__pycache__'))
    def tearDown(self):self.temp.cleanup()
    def reject(self,path,old,new):
        p=self.root/path;s=p.read_text();self.assertIn(old,s);p.write_text(s.replace(old,new,1))
        with self.assertRaises(ValueError):origins.validate(self.root)
    def test_current_contract_remains_native_pending(self):self.assertEqual(origins.validate(self.root)['qualification'],'NotRun')
    def test_direct_TLS_origin_cannot_use_HTTP(self):self.reject('appsettings.LocalHttps.json','https://localhost:5001','http://localhost:5001')
    def test_proxy_origin_cannot_point_to_the_backend_port(self):self.reject('appsettings.ContainerReverseProxy.json','http://localhost:8080','http://localhost:5001')
    def test_generic_proxy_cannot_silently_inherit_localhost(self):self.reject('appsettings.ReverseProxy.json','"PublicOrigin": ""','"PublicOrigin": "https://localhost:5001"')
    def test_obsolete_per_flow_setting_cannot_reappear(self):self.reject('appsettings.json','"PublicOrigin": "https://localhost:5001"','"PublicOrigin": "https://localhost:5001", "AccountDeleteVerifyBaseUrl": "http://localhost:5000"')
    def test_payload_encoding_cannot_be_removed(self):self.reject('Rigging/Hosting/VerificationLinkBuilder.cs','Uri.EscapeDataString(payload)','payload')
    def test_credentials_cannot_be_accepted_in_origins(self):self.reject('Rigging/Hosting/VerificationLinkBuilder.cs','parsed.UserInfo.Length != 0','false')
    def test_normalized_dot_paths_cannot_bypass_origin_syntax(self):self.reject('Rigging/Hosting/VerificationLinkBuilder.cs','Regex.IsMatch(value','Regex.IsMatchElsewhere(value')
    def test_production_cannot_accept_HTTP_or_loopback(self):self.reject('Rigging/Hosting/VerificationLinkBuilder.cs','origin.Scheme == "https" && !loopback','true')
    def test_unknown_origin_keys_cannot_be_ignored(self):self.reject('Rigging/DependencyInjection/TreehammockServiceCollectionExtensions.cs','ErrorOnUnknownConfiguration = sectionName == "RegistrationSettings"','ErrorOnUnknownConfiguration = false')
    def test_compose_proxy_origin_cannot_be_internal_DNS(self):self.reject('docker-compose.api-proxy.yml','http://localhost:8080','http://api:5001')
    def test_host_runner_origin_cannot_be_omitted(self):self.reject('eng/docker-host-system-stack-tests.sh','export RegistrationSettings__PublicOrigin=http://localhost:8080','')
if __name__=='__main__':unittest.main()
