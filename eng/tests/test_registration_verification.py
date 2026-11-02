"""Source mutations and synthetic TRX rejection; never CLR/SQL qualification."""
import importlib.util,json,shutil,tempfile,unittest,xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
def module(name,file):
 spec=importlib.util.spec_from_file_location(name,ROOT/'eng'/file);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
guard=module('verification_guard','check-registration-verification.py');native=module('verification_native','test-registration-verification.py')
class VerificationSource(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'source with spaces'
  for relative in [guard.SYSTEM,guard.ASSERTION,guard.HTTP,guard.PROJECT]:
   path=self.root/relative;path.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/relative,path)
 def tearDown(self):self.temp.cleanup()
 def reject(self,old,new,path=guard.SYSTEM):
  p=self.root/path;text=p.read_text();self.assertIn(old,text);p.write_text(text.replace(old,new))
  with self.assertRaises(ValueError):guard.validate(self.root)
 def test_source_is_not_runtime_qualification(self):
  report=guard.validate(self.root);self.assertEqual(report['qualification'],'NotRun');self.assertEqual(report['http_facts'],10)
 def test_login_proof_cannot_be_removed(self):self.reject('await LoginAndReturnAccessToken(', 'await WeakLogin(')
 def test_protected_operation_cannot_be_removed(self):self.reject('using JsonDocument profile = await AuthenticatedGetJson(', 'using JsonDocument profile = await WeakGet(')
 def test_intended_identity_is_required(self):self.reject('GetProperty("emailAddress").GetString().ShouldBe(email);','')
 def test_verified_state_is_required(self):self.reject('GetProperty("verifyStatus").GetString().ShouldBe("SUCCESSFUL");','')
 def test_http_200_without_html_contract_is_rejected(self):self.reject('RegistrationVerificationAssertions.AssertSuccessPage(response, body,','WeakSuccess(response, body,')
 def test_registration_helper_cannot_create_a_hidden_session(self):self.reject('string token = await LatestDeliveryCode(client, \"email\", \"account_verify\", email, cancellationToken);', 'await LoginAndReturnAccessToken(client, email, password, cancellationToken);')
 def test_exact_page_cannot_be_replaced_with_marker(self):self.reject('body.ShouldBe(expectedHtml);','body.ShouldContain("Account verified");',guard.ASSERTION)
 def test_content_type_is_required(self):self.reject('(response.Content.Headers.ContentType?.MediaType).ShouldBe("text/html");','',guard.ASSERTION)
 def test_unavailable_completion_is_covered(self):self.reject('completion: null','completion: true',guard.HTTP)
 def test_rejected_completion_cannot_commit(self):self.reject('if (completion == true) _state[AccountId] = VerificationStatus.SUCCESSFUL;','_state[AccountId] = VerificationStatus.SUCCESSFUL;',guard.HTTP)
 def test_other_account_state_is_observed(self):self.reject('Observe(OtherAccountId).ShouldBe(VerificationStatus.SENT);','',guard.HTTP)
 def test_response_and_fixture_scopes_remain(self):self.reject('await using var fixture','var fixture',guard.HTTP)
 def test_system_links_shared_assertion(self):self.reject('RegistrationVerificationAssertions.cs','WeakAssertion.cs',guard.PROJECT)
 def test_missing_sdk_records_zero_native_cases(self):
  output=self.root/'native.json'
  with patch.object(native.shutil,'which',return_value=None):self.assertEqual(native.execute(output),2)
  report=json.loads(output.read_text());self.assertEqual(report['qualification'],'NotRun');self.assertEqual(report['cases'],[])

class VerificationReceipt(unittest.TestCase):
 def setUp(self):self.temp=tempfile.TemporaryDirectory();self.path=Path(self.temp.name)/'verification.trx';self.names={'Valid','Failure'}
 def tearDown(self):self.temp.cleanup()
 def write(self,outcome='Passed'):
  root=ET.Element('TestRun');definitions=ET.SubElement(root,'TestDefinitions');rows=ET.SubElement(root,'Results')
  for name in self.names:
   node=ET.SubElement(definitions,'UnitTest',id=name);ET.SubElement(node,'TestMethod',className='Tests.Cor23AERegistrationVerificationHttpTests',name=name);ET.SubElement(rows,'UnitTestResult',testId=name,executionId=name,outcome=outcome)
  summary=ET.SubElement(root,'ResultSummary');ET.SubElement(summary,'Counters',total='2',executed='2',passed='2',failed='0',notExecuted='0');ET.ElementTree(root).write(self.path)
 def test_complete_synthetic_receipt_validates_shape_only(self):self.write();self.assertEqual(native.results(self.path,self.names)['executions'],2)
 def test_missing_results_or_undiscovered_case_rejected(self):
  with self.assertRaises(ValueError):native.results(self.path,self.names)
  self.write()
  with self.assertRaises(ValueError):native.results(self.path,self.names|{'Absent'})
 def test_skips_and_failures_rejected(self):
  for outcome in ['Failed','NotExecuted']:
   self.write(outcome)
   with self.assertRaises(ValueError):native.results(self.path,self.names)
 def test_duplicate_execution_rejected(self):
  self.write();root=ET.parse(self.path);rows=root.find('Results');rows.append(ET.fromstring(ET.tostring(rows[0])));root.write(self.path)
  with self.assertRaises(ValueError):native.results(self.path,self.names)
 def test_false_counters_and_entity_declarations_rejected(self):
  self.write();self.path.write_text(self.path.read_text().replace('executed="2"','executed="0"'))
  with self.assertRaises(ValueError):native.results(self.path,self.names)
  self.write();self.path.write_text('<!DOCTYPE TestRun>'+self.path.read_text())
  with self.assertRaises(ValueError):native.results(self.path,self.names)
if __name__=='__main__':unittest.main()
