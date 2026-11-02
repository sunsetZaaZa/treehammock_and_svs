"""Source mutations and synthetic native receipts; not CLR/PostgreSQL qualification."""
import importlib.util,json,shutil,tempfile,unittest,xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
def module(name,file):
 spec=importlib.util.spec_from_file_location(name,ROOT/'eng'/file);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
guard=module('replacement_guard','check-authenticator-replacement.py');native=module('replacement_native','test-authenticator-replacement.py')
class ReplacementSource(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'source with spaces'
  for relative in [guard.REPO,guard.HELPER,guard.SERVICE,guard.CONTROLLER,guard.TEST,'eng/correction-baseline.py','.github/workflows/treehammock-ci.yml']:
   path=self.root/relative;path.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/relative,path)
 def tearDown(self):self.temp.cleanup()
 def reject(self,old,new,path=guard.REPO):
  p=self.root/path;text=p.read_text();self.assertIn(old,text);p.write_text(text.replace(old,new))
  with self.assertRaises(ValueError):guard.validate(self.root)
 def test_source_requires_real_native_qualification(self):
  report=guard.validate(self.root);self.assertEqual(report['qualification'],'NotRun');self.assertEqual(report['expected_executions'],18)
 def test_three_argument_repository_comparison_is_rejected(self):self.reject(native.BOUND,native.UNBOUND)
 def test_omitting_only_version_is_rejected(self):self.reject(native.BOUND,native.BOUND.replace(', commandModel.ExpectedVersion)',' )'))
 def test_missing_grant_remains_fail_closed(self):self.reject('commandModel.Grant is null || commandModel.Grant.CanonicalTarget !=','commandModel.Grant.CanonicalTarget !=')
 def test_predecessor_sql_identity_is_preserved(self):self.reject('DbValue(commandModel.ExpectedEnrollmentId)','DBNull.Value')
 def test_predecessor_sql_version_is_preserved(self):self.reject('DbValue(commandModel.ExpectedVersion)','DBNull.Value')
 def test_fresh_null_defaults_are_preserved(self):self.reject('expectedEnrollmentId = null, long? expectedVersion = null','expectedEnrollmentId, long? expectedVersion',guard.HELPER)
 def test_controller_and_service_match_all_fields(self):self.reject('payload.provider, payload.expectedEnrollmentId, payload.expectedVersion','payload.provider',guard.CONTROLLER)
 def test_service_preserves_predecessor_in_repository_command(self):self.reject('protectedSecret.Context, command.ExpectedEnrollmentId, command.ExpectedVersion)','protectedSecret.Context)',guard.SERVICE)
 def test_enrollment_secret_context_remains_account_bound(self):self.reject('commandModel.Context.AccountId != commandModel.AccountId','false')
 def test_durable_state_and_grant_observers_are_required(self):self.reject('(await Snapshot(observer, a, ct)).ShouldBe(before);','',guard.TEST)
 def test_dependency_logging_stage_parameter_is_defined(self):self.reject('DependencyStage stage = DependencyStage.Acquire','',guard.REPO)
 def test_native_mutation_removes_exactly_predecessor_arguments_and_restores(self):
  path,original=native.mutate(self.root);mutated=path.read_text();self.assertIn(native.UNBOUND,mutated);self.assertNotIn(native.BOUND,mutated);path.write_bytes(original);self.assertEqual(guard.validate(self.root)['expected_executions'],18)
 def test_missing_sdk_records_zero_native_cases(self):
  output=self.root/'native.json'
  with patch.object(native.shutil,'which',return_value=None):self.assertEqual(native.execute(output),2)
  report=json.loads(output.read_text());self.assertEqual(report['qualification'],'NotRun');self.assertEqual(report['cases'],[]);self.assertEqual(report['discovered_native_methods'],[])
 def test_disposable_database_opt_in_is_required(self):
  with patch.object(native.shutil,'which',return_value='dotnet'),patch.dict(native.os.environ,{},clear=True):self.assertEqual(native.execute(self.root/'native.json'),2)
  self.assertEqual(json.loads((self.root/'native.json').read_text())['cases'],[])

class ReplacementReceipts(unittest.TestCase):
 def setUp(self):self.temp=tempfile.TemporaryDirectory();self.path=Path(self.temp.name)/'replacement.trx';self.inventory=native.expected(ROOT)
 def tearDown(self):self.temp.cleanup()
 def write(self,negative=False):
  inventory={native.TARGET:1} if negative else self.inventory
  root=ET.Element('TestRun');definitions=ET.SubElement(root,'TestDefinitions');rows=ET.SubElement(root,'Results')
  for method,count in inventory.items():
   for i in range(count):
    identity=method+'-'+str(i);node=ET.SubElement(definitions,'UnitTest',id=identity);ET.SubElement(node,'TestMethod',className='Tests.'+native.SUITE,name=method)
    row=ET.SubElement(rows,'UnitTestResult',testId=identity,executionId=identity,outcome='Failed' if negative else 'Passed')
    if negative:
     error=ET.SubElement(ET.SubElement(row,'Output'),'ErrorInfo');ET.SubElement(error,'Message').text='Shouldly.ShouldAssertException';ET.SubElement(error,'StackTrace').text=native.SUITE+'.<>c.<<'+native.TARGET+'>>'
  size=sum(inventory.values());ET.SubElement(ET.SubElement(root,'ResultSummary'),'Counters',total=str(size),executed=str(size),passed=str(0 if negative else size),failed=str(size if negative else 0),notExecuted='0');ET.ElementTree(root).write(self.path)
 def test_complete_synthetic_receipt_validates_shape_only(self):self.write();self.assertEqual(native.results(self.path,self.inventory)['executions'],18)
 def test_designated_failed_repository_mutation_is_required(self):self.write(True);self.assertEqual(native.results(self.path,{native.TARGET:1},True)['failed_methods'],[native.TARGET])
 def test_missing_trx_or_compile_error_cannot_qualify_mutation(self):
  with self.assertRaises(ValueError):native.results(self.path,{native.TARGET:1},True)
  self.path.write_text('compiler error')
  with self.assertRaises(ET.ParseError):native.results(self.path,{native.TARGET:1},True)
 def test_passing_mutant_is_rejected(self):
  self.write(True);s=self.path.read_text().replace('outcome="Failed"','outcome="Passed"').replace('passed="0"','passed="1"').replace('failed="1"','failed="0"');self.path.write_text(s)
  with self.assertRaises(ValueError):native.results(self.path,{native.TARGET:1},True)
 def test_wrong_failure_origin_is_rejected(self):
  self.write(True);self.path.write_text(self.path.read_text().replace('Shouldly.ShouldAssertException','DependencyUnavailableException'))
  with self.assertRaises(ValueError):native.results(self.path,{native.TARGET:1},True)
 def test_theory_variant_missing_is_rejected(self):
  self.write();root=ET.parse(self.path);root.find('Results').remove(root.find('Results')[-1]);root.write(self.path)
  with self.assertRaises(ValueError):native.results(self.path,self.inventory)
 def test_skipped_duplicate_and_entity_receipts_are_rejected(self):
  for kind in ['skip','duplicate','entity']:
   self.write()
   if kind=='skip':self.path.write_text(self.path.read_text().replace('outcome="Passed"','outcome="NotExecuted"',1))
   elif kind=='duplicate':root=ET.parse(self.path);rows=root.find('Results');rows.append(ET.fromstring(ET.tostring(rows[0])));root.write(self.path)
   else:self.path.write_text('<!DOCTYPE TestRun>'+self.path.read_text())
   with self.subTest(kind=kind),self.assertRaises(ValueError):native.results(self.path,self.inventory)
if __name__=='__main__':unittest.main()
