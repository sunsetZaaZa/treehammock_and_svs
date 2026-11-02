"""Source rejection and mutation/TRX orchestration. Never native assertion/HTTP qualification."""
import importlib.util,json,shutil,tempfile,unittest,xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,ROOT/'eng'/file);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
guard=module('account_guard','check-account-failure-envelopes.py');native=module('account_native','test-account-failure-envelopes.py')
class ContractSourceMutations(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'checkout with spaces'
  for name in [guard.HELPER,*guard.SUITES,guard.UNIT,'eng/test-account-failure-envelopes.py','Program.cs','Controllers/AccountControllerBase.cs']:
   path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/name,path)
 def tearDown(self):self.temp.cleanup()
 def reject(self,old,new,path=guard.HELPER):
  file=self.root/path;s=file.read_text();self.assertIn(old,s);file.write_text(s.replace(old,new))
  with self.assertRaises(ValueError):guard.validate(self.root)
 def test_current_source_does_not_claim_runtime_qualification(self):self.assertEqual(guard.validate(self.root)['qualification'],'NotRun')
 def test_status_only_branch_rejected(self):self.reject('Required(root, "success", JsonValueKind.False);','if (!root.TryGetProperty("success", out _)) return;')
 def test_transport_status_cannot_be_dropped(self):self.reject('((int)httpStatus).ShouldBe(statusCode);','')
 def test_missing_or_wrongly_typed_code_cannot_be_accepted(self):self.reject('Required(root, "code", JsonValueKind.String).GetString().ShouldBe(code);','')
 def test_object_map_compatibility_is_rejected(self):self.reject('Required(document.RootElement, "errors", JsonValueKind.Array)','Required(document.RootElement, "errors", JsonValueKind.Object)')
 def test_validation_of_all_errors_is_required(self):self.reject('foreach (JsonElement error in errors.EnumerateArray())','foreach (JsonElement error in errors.EnumerateArray().Take(1))')
 def test_nonempty_string_messages_are_required(self):self.reject('message.GetString().ShouldNotBeNullOrWhiteSpace();','')
 def test_exact_field_case_required(self):self.reject('StringComparison.Ordinal','StringComparison.OrdinalIgnoreCase')
 def test_null_data_and_errors_do_not_satisfy_omission(self):self.reject('root.TryGetProperty("errors", out _).ShouldBeFalse','root.TryGetProperty("errors", out _).ShouldBeTrue')
 def test_duplicate_property_check_required(self):self.reject('names.Distinct(StringComparer.Ordinal).Count().ShouldBe(names.Length','names.Length.ShouldBe(names.Length')
 def test_each_affected_http_suite_uses_the_shared_strict_assertion(self):
  for path in guard.SUITES:
   file=self.root/path;old=file.read_text();file.write_text(old.replace('AccountFailureAssertions.Failure(response, document,','LegacyFailure(document,'))
   with self.assertRaises(ValueError):guard.validate(self.root)
   file.write_text(old)
 def test_disposable_mutations_change_only_intended_anchor_and_restore_exact_bytes(self):
  for kind in ['framework-model-state','required-key-wrong-code','required-key-missing-code']:
   path,original=native.mutate(self.root,kind);self.assertNotEqual(path.read_bytes(),original)
   if kind.startswith('required-key'):
    self.assertIn('StatusCodes.Status428PreconditionRequired,',path.read_text());self.assertNotIn(native.KEY_BLOCK,path.read_text())
   else:self.assertNotIn(native.MODEL_BLOCK,path.read_text())
   path.write_bytes(original);self.assertEqual(path.read_bytes(),original)
 def test_nonunique_mutation_anchor_is_rejected(self):
  path=self.root/'Program.cs';path.write_text(path.read_text()+native.MODEL_BLOCK)
  with self.assertRaises(ValueError):native.mutate(self.root,'framework-model-state')
 def test_missing_sdk_executes_zero_native_cases(self):
  output=self.root/'report.json'
  with patch.object(native.shutil,'which',return_value=None):self.assertEqual(native.execute(output),2)
  report=json.loads(output.read_text());self.assertEqual(report['qualification'],'NotRun');self.assertEqual(report['cases'],[])

class NativeReceiptRejections(unittest.TestCase):
 def setUp(self):self.temp=tempfile.TemporaryDirectory();self.path=Path(self.temp.name)/'fresh.trx';self.inventory={'Suite':{'Case'}}
 def tearDown(self):self.temp.cleanup()
 def write(self,outcome='Passed',message='',**counters):
  root=ET.Element('TestRun');definitions=ET.SubElement(root,'TestDefinitions');test=ET.SubElement(definitions,'UnitTest',id='test');ET.SubElement(test,'TestMethod',className='Tests.Suite',name='Case');rows=ET.SubElement(root,'Results');row=ET.SubElement(rows,'UnitTestResult',testId='test',executionId='exec',outcome=outcome)
  if message:ET.SubElement(ET.SubElement(ET.SubElement(row,'Output'),'ErrorInfo'),'Message').text=message
  summary=ET.SubElement(root,'ResultSummary');values=dict(total='1',executed='1',passed='1' if outcome=='Passed' else '0',failed='1' if outcome=='Failed' else '0',notExecuted='0');values.update(counters);ET.SubElement(summary,'Counters',**values);ET.ElementTree(root).write(self.path)
 def test_positive_receipt_requires_fresh_complete_passed_discovery(self):self.write();self.assertEqual(native.results(self.path,self.inventory)['executions'],1)
 def test_zero_missing_and_incomplete_results_rejected(self):
  with self.assertRaises(ValueError):native.results(self.path,self.inventory)
  self.write();self.inventory['Suite'].add('Absent')
  with self.assertRaises(ValueError):native.results(self.path,self.inventory)
 def test_native_nonassertion_failure_does_not_kill_the_mutant(self):
  self.write('Failed','Build/runtime/configuration failure')
  with self.assertRaises(ValueError):native.results(self.path,self.inventory,'Case')
 def test_only_designated_strict_assertion_failure_kills_mutant(self):
  self.write('Failed','Shouldly.ShouldAssertException at AccountFailureAssertions.Failure');self.assertEqual(native.results(self.path,self.inventory,'Case')['failed_methods'],['Case'])
  with self.assertRaises(ValueError):native.results(self.path,self.inventory,'Other')
 def test_skipped_execution_and_wrong_counters_fail(self):
  self.write('NotExecuted')
  with self.assertRaises(ValueError):native.results(self.path,self.inventory)
  self.write(executed='0')
  with self.assertRaises(ValueError):native.results(self.path,self.inventory)
 def test_duplicate_execution_or_entity_declarations_rejected(self):
  self.write();tree=ET.parse(self.path);rows=tree.find('Results');rows.append(ET.fromstring(ET.tostring(rows[0])));tree.write(self.path)
  with self.assertRaises(ValueError):native.results(self.path,self.inventory)
  self.write();self.path.write_text('<!DOCTYPE TestRun>'+self.path.read_text())
  with self.assertRaises(ValueError):native.results(self.path,self.inventory)
if __name__=='__main__':unittest.main()
