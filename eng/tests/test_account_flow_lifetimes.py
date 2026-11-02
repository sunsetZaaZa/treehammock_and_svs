"""Source ownership and synthetic discovery checks; no CLR/host cleanup qualification."""
import importlib.util,json,shutil,tempfile,unittest,xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
def module(name,file):
 spec=importlib.util.spec_from_file_location(name,ROOT/'eng'/file);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
guard=module('flow_guard','check-account-flow-lifetimes.py');native=module('flow_native','test-account-flow-lifetimes.py')
class FlowOwnershipSource(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'source with spaces'
  for relative in [guard.FLOW,guard.PROBE]:
   path=self.root/relative;path.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/relative,path)
 def tearDown(self):self.temp.cleanup()
 def reject(self,old,new,path=guard.FLOW):
  p=self.root/path;text=p.read_text();self.assertIn(old,text);p.write_text(text.replace(old,new))
  with self.assertRaises(ValueError):guard.validate(self.root)
 def test_exact_source_scopes_are_not_runtime_qualification(self):
  report=guard.validate(self.root);self.assertEqual(report['qualification'],'NotRun');self.assertEqual(report['original_harness_scopes'],15);self.assertEqual(report['preserved_direct_factory_scopes'],12)
 def test_final_output_factory_scope_is_required(self):self.reject('using var lateLoginFactory = FlowFactory(', 'var lateLoginFactory = FlowFactory(')
 def test_one_unscoped_harness_is_rejected(self):self.reject('await using LoginTwoFactorHarness harness =','LoginTwoFactorHarness harness =')
 def test_direct_factory_scope_must_remain(self):self.reject('using var factory = FlowFactory','var factory = FlowFactory')
 def test_factory_async_disposal_must_be_delegated(self):self.reject('if (_factory is not null) await _factory.DisposeAsync();','')
 def test_disposal_operation_must_be_shared_by_repeated_callers(self):self.reject('_disposeTask ??= DisposeFactoryAsync()','DisposeFactoryAsync()')
 def test_helper_json_is_owned_before_assertions(self):self.reject('using JsonDocument loginJson = await ReadJson(login);','JsonDocument loginJson = await ReadJson(login);')
 def test_selection_json_cannot_escape_helper(self):self.reject('using JsonDocument selectedJson = await ReadJson(selected);','JsonDocument selectedJson = await ReadJson(selected);')
 def test_helper_cannot_return_disposable_document(self):self.reject('Task<LoginSelection> LoginAndAssertSelectionRequired','Task<JsonDocument> LoginAndAssertSelectionRequired')
 def test_successful_parallel_response_is_cleaned_even_after_other_failure(self):self.reject('if (request.IsCompletedSuccessfully) request.Result.Dispose();','')
 def test_di_registration_must_own_the_probe(self):self.reject('services.AddSingleton<IHostedService>(provider =>','services.AddSingleton<IHostedService>(probe =>',guard.PROBE)
 def test_stop_and_disposal_must_be_observed_not_inferred_from_time(self):self.reject('Stops.ShouldBe(1);','',guard.PROBE)
 def test_original_exception_identity_is_asserted(self):self.reject('observed.ShouldBeSameAs(original);','',guard.PROBE)
 def test_unstarted_factory_is_covered(self):self.reject('probe.Attachments.ShouldBe(0);','',guard.PROBE)
 def test_repetition_is_in_one_process_with_no_live_instances(self):self.reject('for (int iteration = 0; iteration < 12; iteration++)','for (int iteration = 0; iteration < 1; iteration++)',guard.PROBE)
 def test_missing_sdk_records_zero_native_cases(self):
  output=self.root/'native.json'
  with patch.object(native.shutil,'which',return_value=None):self.assertEqual(native.execute(output),2)
  report=json.loads(output.read_text());self.assertEqual(report['qualification'],'NotRun');self.assertEqual(report['cases'],[])

class FlowReceiptProof(unittest.TestCase):
 def setUp(self):self.temp=tempfile.TemporaryDirectory();self.path=Path(self.temp.name)/'flows.trx';self.names={'Flow','Probe'}
 def tearDown(self):self.temp.cleanup()
 def write(self,outcome='Passed'):
  root=ET.Element('TestRun');definitions=ET.SubElement(root,'TestDefinitions');rows=ET.SubElement(root,'Results')
  for name in self.names:
   node=ET.SubElement(definitions,'UnitTest',id=name);ET.SubElement(node,'TestMethod',className='Tests.AccountFlowRegressionTests',name=name);ET.SubElement(rows,'UnitTestResult',testId=name,executionId=name,outcome=outcome)
  summary=ET.SubElement(root,'ResultSummary');ET.SubElement(summary,'Counters',total='2',executed='2',passed='2',failed='0',notExecuted='0');ET.ElementTree(root).write(self.path)
 def test_fresh_complete_synthetic_results_only_validate_receipt_shape(self):self.write();self.assertEqual(native.results(self.path,self.names)['executions'],2)
 def test_missing_or_unexecuted_lifecycle_case_rejected(self):
  with self.assertRaises(ValueError):native.results(self.path,self.names)
  self.write()
  with self.assertRaises(ValueError):native.results(self.path,self.names|{'Absent'})
 def test_skips_and_failures_cannot_qualify_cleanup(self):
  for outcome in ['Failed','NotExecuted']:
   self.write(outcome)
   with self.assertRaises(ValueError):native.results(self.path,self.names)
 def test_duplicate_execution_rejected(self):
  self.write();root=ET.parse(self.path);rows=root.find('Results');rows.append(ET.fromstring(ET.tostring(rows[0])));root.write(self.path)
  with self.assertRaises(ValueError):native.results(self.path,self.names)
 def test_wrong_counter_and_entity_declaration_rejected(self):
  self.write();self.path.write_text(self.path.read_text().replace('executed="2"','executed="0"'))
  with self.assertRaises(ValueError):native.results(self.path,self.names)
  self.write();self.path.write_text('<!DOCTYPE TestRun>'+self.path.read_text())
  with self.assertRaises(ValueError):native.results(self.path,self.names)
if __name__=='__main__':unittest.main()
