"""Supplemental source mutation witnesses; no native compression acceptance is claimed."""
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('body_boundary',ROOT/'eng/check-request-body-boundary.py')
body=importlib.util.module_from_spec(spec);spec.loader.exec_module(body)

class RequestBodyBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'source'
        shutil.copytree(ROOT,self.root,ignore=shutil.ignore_patterns('.git','bin','obj','.artifacts','.correction-results','TestResults','__pycache__'))
    def tearDown(self):self.temp.cleanup()
    def replace(self,path,old,new):
        p=self.root/path;text=p.read_text();self.assertIn(old,text);p.write_text(text.replace(old,new,1))
    def reject(self,path,old,new):
        self.replace(path,old,new)
        with self.assertRaises(ValueError):body.validate(self.root)
    def test_current_contract_stays_pending_native(self):self.assertEqual(body.validate(self.root)['qualification'],'NotRun')
    def test_decoder_cannot_follow_admission(self):
        p=self.root/'Program.cs';s=p.read_text();gate='app.UseMiddleware<RequestBodyMiddleware>();'
        p.write_text(s.replace(gate,'').replace('app.UseMiddleware<JsonWebTokenMiddleware>();',gate+'\napp.UseMiddleware<JsonWebTokenMiddleware>();'))
        with self.assertRaises(ValueError):body.validate(self.root)
    def test_encoded_limit_cannot_be_disabled(self):
        self.reject('Rigging/Hosting/RequestBodyMiddleware.cs','originalLength > limits.EncodedBytes','false')
    def test_chunked_probe_cannot_be_removed(self):
        self.reject('Rigging/Hosting/RequestBodyMiddleware.cs','length == encoded.Length','false')
    def test_expansion_buffer_cannot_be_unbounded(self):
        self.reject('Rigging/Hosting/RequestBodyMiddleware.cs','new byte[limits.DecodedBytes + 1]','new byte[int.MaxValue]')
    def test_unrelated_io_cannot_be_labeled_compression(self):
        self.reject('Rigging/Hosting/RequestBodyMiddleware.cs','catch (InvalidDataException)','catch (IOException)')
    def test_deadline_cannot_be_removed(self):
        self.reject('Rigging/Hosting/RequestBodyMiddleware.cs','deadline.CancelAfter(limits.ReadMilliseconds);','')
    def test_capacity_cannot_queue_without_limit(self):
        self.reject('Rigging/Hosting/RequestBodyPolicy.cs','_capacity.Wait(0)','_capacity.Wait(-1)')
    def test_capacity_must_be_released(self):
        self.reject('Rigging/Hosting/RequestBodyMiddleware.cs','if (entered) policy.Exit();','')
    def test_incomplete_deflate_cannot_be_clean_eof(self):
        self.reject('Rigging/Hosting/StrictRequestBodyDecoder.cs','Position == Length','false')
    def test_gzip_checksums_cannot_be_skipped(self):
        self.reject('Rigging/Hosting/StrictRequestBodyDecoder.cs','expectedCrc != Crc32','expectedCrc == Crc32')
    def test_brotli_requires_terminal_state(self):
        self.reject('Rigging/Hosting/StrictRequestBodyDecoder.cs','OperationStatus.Done','OperationStatus.NeedMoreData')
    def test_unknown_configuration_cannot_be_ignored(self):
        self.reject('Rigging/DependencyInjection/TreehammockServiceCollectionExtensions.cs','ErrorOnUnknownConfiguration = true','ErrorOnUnknownConfiguration = false')
    def test_shipped_budget_cannot_be_zero(self):
        self.reject('appsettings.json','"EncodedBytes": 262144','"EncodedBytes": 0')
if __name__=='__main__':unittest.main()
