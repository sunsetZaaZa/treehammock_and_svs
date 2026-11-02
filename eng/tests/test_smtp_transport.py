"""COR23H source/config mutation witnesses; these do not execute MailKit/TLS."""
import importlib.util,shutil,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('smtp',ROOT/'eng/check-smtp-transport.py');smtp=importlib.util.module_from_spec(spec);spec.loader.exec_module(smtp)
class SmtpTransportTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'source';shutil.copytree(ROOT,self.root,ignore=shutil.ignore_patterns('.git','bin','obj','.artifacts','.correction-results','TestResults','__pycache__'))
    def tearDown(self):self.temp.cleanup()
    def reject(self,path,old,new):
        p=self.root/path;s=p.read_text();self.assertIn(old,s);p.write_text(s.replace(old,new,1))
        with self.assertRaises(ValueError):smtp.validate(self.root)
    def test_current_contract_remains_native_pending(self):self.assertEqual(smtp.validate(self.root)['qualification'],'NotRun')
    def test_shipped_profile_cannot_select_plaintext(self):self.reject('appsettings.Container.json','"TransportMode": "RequiredStartTls"','"TransportMode": "IsolatedPlaintext"')
    def test_testing_default_is_still_secure(self):self.reject('appsettings.Testing.json','"AllowIsolatedPlaintext": false','"AllowIsolatedPlaintext": true')
    def test_starttls_cannot_be_opportunistic(self):self.reject('Rigging/Delivery/SmtpTransportPolicy.cs','=> SecureSocketOptions.StartTls,','=> SecureSocketOptions.StartTlsWhenAvailable,')
    def test_implicit_tls_cannot_be_inferred_from_port(self):self.reject('Rigging/Delivery/SmtpTransportPolicy.cs','=> SecureSocketOptions.SslOnConnect,','=> SecureSocketOptions.Auto,')
    def test_plaintext_cannot_enable_in_container(self):self.reject('Rigging/Delivery/SmtpTransportPolicy.cs','environment == "Testing"','environment == "Container"')
    def test_plaintext_permission_cannot_be_implicit(self):self.reject('Rigging/Config/SMTPSettings.cs','!AllowIsolatedPlaintext','false')
    def test_loopback_destination_cannot_be_any_private_host(self):self.reject('Rigging/Config/SMTPSettings.cs','!IPAddress.IsLoopback(address)','false')
    def test_encryption_witness_cannot_be_removed(self):self.reject('Services/SMTPService.cs','!smtp.IsSecure','false')
    def test_certificate_revocation_cannot_be_disabled(self):self.reject('Rigging/Delivery/SmtpClientFactory.cs','CheckCertificateRevocation = true','CheckCertificateRevocation = false')
    def test_tls_floor_cannot_be_removed(self):self.reject('Rigging/Delivery/SmtpClientFactory.cs','SslProtocols.Tls12 | SslProtocols.Tls13','SslProtocols.None')
    def test_unknown_transport_keys_cannot_be_ignored(self):self.reject('Rigging/DependencyInjection/TreehammockServiceCollectionExtensions.cs','|| sectionName == "SMTPSettings"','')
    def test_raw_provider_exceptions_cannot_be_logged(self):self.reject('Services/SMTPService.cs','_logger.LogWarning(','_logger.LogWarning(ex,')
    def test_certificate_accept_all_callback_cannot_be_added(self):self.reject('Rigging/Delivery/SmtpClientFactory.cs','Timeout = 20000,','Timeout = 20000,\n        ServerCertificateValidationCallback = (_, _, _, _) => true,')
if __name__=='__main__':unittest.main()
