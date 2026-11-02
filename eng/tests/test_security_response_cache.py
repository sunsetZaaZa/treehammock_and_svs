"""Supplemental source mutation witnesses, not native cache/privacy passes."""
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('privacy',ROOT/'eng/check-security-response-cache.py')
privacy=importlib.util.module_from_spec(spec);spec.loader.exec_module(privacy)

class SecurityResponseCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'source'
        shutil.copytree(ROOT,self.root,ignore=shutil.ignore_patterns('.git','bin','obj','.artifacts','.correction-results','TestResults','__pycache__'))
    def tearDown(self):self.temp.cleanup()
    def replace(self,path,old,new):
        p=self.root/path;text=p.read_text();self.assertIn(old,text);p.write_text(text.replace(old,new,1))
    def test_current_headers_order_and_boundary_remain_native_pending(self):
        report=privacy.validate(self.root);self.assertEqual(report['qualification'],'NotRun');self.assertEqual(report['public_production_opt_ins'],0)
    def test_no_cache_cannot_replace_no_store(self):
        self.replace('Rigging/Hosting/SecurityResponseCacheMiddleware.cs','response.Headers.CacheControl = "no-store";','response.Headers.CacheControl = "no-cache";')
        with self.assertRaises(ValueError):privacy.validate(self.root)
    def test_policy_cannot_follow_authentication_or_decoding(self):
        p=self.root/'Program.cs';s=p.read_text();gate='app.UseMiddleware<SecurityResponseCacheMiddleware>();';p.write_text(s.replace(gate,'').replace('app.MapControllers().WithMetadata(',gate+'\napp.MapControllers().WithMetadata('))
        with self.assertRaises(ValueError):privacy.validate(self.root)
    def test_removing_final_callback_reassertion_is_rejected(self):
        self.replace('Rigging/Hosting/SecurityResponseCacheMiddleware.cs','Apply((HttpResponse)state);','_ = state;')
        with self.assertRaises(ValueError):privacy.validate(self.root)
    def test_direct_credential_headers_retain_private_defense(self):
        self.replace('Rigging/Authentication/SessionProtocol.cs','treehammock.Rigging.Hosting.SecurityResponseCacheMiddleware.Apply(response);','')
        with self.assertRaises(ValueError):privacy.validate(self.root)
    def test_raw_exception_logging_is_rejected(self):
        self.replace('Rigging/Hosting/HttpExceptionFallbackMiddleware.cs','error.GetType().Name);','error.Message);')
        with self.assertRaises(ValueError):privacy.validate(self.root)
    def test_cancellation_cannot_turn_into_fallback_success(self):
        self.replace('Rigging/Hosting/HttpExceptionFallbackMiddleware.cs','when (context.RequestAborted.IsCancellationRequested) { throw; }','when (context.RequestAborted.IsCancellationRequested) { return; }')
        with self.assertRaises(ValueError):privacy.validate(self.root)

if __name__=='__main__':unittest.main()
