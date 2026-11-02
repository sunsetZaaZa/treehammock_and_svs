"""Integrated packet rejection and controlled process fixtures; not native release qualification."""
import copy,importlib.util,json,os,shutil,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('cor24',ROOT/'eng/verify-cross-feature-qualification.py');q=importlib.util.module_from_spec(spec);spec.loader.exec_module(q)
class QualificationMatrix(unittest.TestCase):
 def setUp(self):self.requirements=q.load_requirements(ROOT);self.catalog=q.catalog(ROOT);self.workload=q.read(ROOT/'eng/resource-workload.json')
 def test_complete_current_inventory_is_preserved(self):
  self.assertEqual((len(self.catalog['findings']),len(self.catalog['followups']),len(self.catalog['gates']),len(self.catalog['features'])),(84,32,186,45));self.assertEqual(self.catalog['original_inventory_rows'],451)
 def test_all_execution_and_acceptance_requirements_are_mandatory(self):self.assertEqual(len(self.requirements['required_stages']),24);self.assertEqual(len(self.requirements['required_acceptance']),12)
 def test_tooling_pass_cannot_close_native_or_release_obligations(self):
  stages=[dict(id=s['id'],kind=s['kind'],status='Succeeded',reason=None) for s in self.requirements['required_stages']]
  result=q.outcome(self.catalog,stages,self.requirements,self.workload);self.assertFalse(result['release_ready']);self.assertEqual(result['qualification'],'Blocked');self.assertTrue(any(b['kind']=='adjudication' for b in result['blockers']))
 def test_even_claimed_closed_gates_require_concrete_integrated_acceptance(self):
  inventory=copy.deepcopy(self.catalog)
  for f in inventory['findings']:f['implementation_status']='Closed'
  for g in inventory['gates']:g['status']='Passed'
  result=q.outcome(inventory,[],self.requirements,dict(budget_status='Approved',budgets={'x':1},review_reference='reviewed'))
  self.assertFalse(result['release_ready']);self.assertEqual(len([b for b in result['blockers'] if b['kind']=='acceptance']),12)
 def test_failed_command_is_not_masked_by_other_blockers(self):
  result=q.outcome(self.catalog,[dict(id='broken',kind='native',status='Failed',reason='actual failure')],self.requirements,self.workload);self.assertEqual(result['qualification'],'Failed')
 def test_proposed_budget_is_always_visible(self):self.assertTrue(any(b['id']=='approved-budgets' for b in q.blockers(self.catalog,[],self.requirements,self.workload)))
 def test_missing_sdk_records_all_mandatory_stages_without_any_child(self):
  folder=ROOT/'.correction-results'/('cor24-test-'+os.urandom(6).hex());before={p:q.sha(ROOT/'docs/corrections'/p) for p in ['FINDING_CLOSURE.json','REVIEW_GATES.json','SOURCE_FINDING_FOLLOWUPS.json']}
  try:
   with patch.object(q.shutil,'which',return_value=None):self.assertEqual(q.execute(folder,['registration-http']),2)
   packet=q.read(next(folder.glob('*/qualification.json')));self.assertEqual(len(packet['stages']),24);self.assertTrue(packet['ledger_unchanged']);self.assertFalse(packet['release_ready'])
   self.assertEqual(next(s for s in packet['stages'] if s['id']=='registration-http')['native_case_count'],0)
   self.assertTrue(all(s['status']=='NotRun' for s in packet['stages']))
   self.assertEqual(before,{p:q.sha(ROOT/'docs/corrections'/p) for p in before})
  finally:shutil.rmtree(folder,ignore_errors=True)
 def test_output_cannot_escape_dedicated_roots(self):
  with tempfile.TemporaryDirectory() as t,self.assertRaises(ValueError):q.execute(Path(t),['registration-http'])

class FeatureMatrixSummary(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
  self.path=self.root/'docs/release/RELEASE_FEATURE_MATRIX.md';self.path.parent.mkdir(parents=True)
  self.text=(ROOT/'docs/release/RELEASE_FEATURE_MATRIX.md').read_text();self.path.write_text(self.text)
  self.surface=q.read(ROOT/'docs/corrections/APPLICATION_SURFACE_INDEX.json')
  self.findings=q.read(ROOT/'docs/corrections/FINDING_CLOSURE.json')['findings'];self.gates=q.read(ROOT/'docs/corrections/REVIEW_GATES.json')['gates']
 def tearDown(self):self.temp.cleanup()
 def test_current_matrix_summary_agrees_with_authoritative_inventories(self):q.validate_feature_matrix(self.root,self.surface,self.findings,self.gates)
 def test_each_stale_missing_or_duplicated_summary_count_is_rejected(self):
  import re
  rows=re.findall(r'^\| (Findings|Review/release gates|Endpoints|Canonical SQL functions|Attributed source test methods|Feature rows) \| ([0-9]+) \|[^\n]*',self.text,re.M)
  self.assertEqual(len(rows),6)
  for label,count in rows:
   pattern=r'^\| '+re.escape(label)+r' \| '+count+r' \|[^\n]*'
   match=re.search(pattern,self.text,re.M)[0]
   for replacement in [match.replace('| '+count+' |','| '+str(int(count)+1)+' |'),'',match+'\n'+match]:
    self.path.write_text(self.text.replace(match,replacement,1))
    with self.subTest(label=label,replacement=replacement),self.assertRaises(ValueError):q.validate_feature_matrix(self.root,self.surface,self.findings,self.gates)
 def test_count_preserving_missing_warmup_row_is_rejected(self):
  next(f for f in self.surface['features'] if f['feature']==q.WARMUP_FEATURE)['feature']='Unreviewed replacement'
  with self.assertRaises(ValueError):q.validate_feature_matrix(self.root,self.surface,self.findings,self.gates)
 def test_warmup_requires_complete_located_source_config_guide_and_native_test_anchors(self):
  warmup=next(f for f in self.surface['features'] if f['feature']==q.WARMUP_FEATURE)
  for n in range(len(warmup['anchors'])):
   changed=copy.deepcopy(self.surface);row=next(f for f in changed['features'] if f['feature']==q.WARMUP_FEATURE);row['anchors'][n]['paths']=[]
   with self.subTest(anchor=n),self.assertRaises(ValueError):q.validate_feature_matrix(self.root,changed,self.findings,self.gates)
 def test_duplicate_feature_identity_or_qualified_warmup_is_rejected(self):
  changed=copy.deepcopy(self.surface);changed['features'][-1]=copy.deepcopy(changed['features'][0])
  with self.assertRaises(ValueError):q.validate_feature_matrix(self.root,changed,self.findings,self.gates)
  next(f for f in self.surface['features'] if f['feature']==q.WARMUP_FEATURE)['qualification']='Passed'
  with self.assertRaises(ValueError):q.validate_feature_matrix(self.root,self.surface,self.findings,self.gates)

class SourceAndReceipts(unittest.TestCase):
 def setUp(self):self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'source with spaces';self.root.mkdir();self.destination=Path(self.temp.name)/'public';self.destination.mkdir()
 def tearDown(self):self.temp.cleanup()
 def test_duplicate_json_key_is_rejected(self):
  p=self.root/'bad.json';p.write_text('{"status":"Passed","status":"Failed"}')
  with self.assertRaises(ValueError):q.read(p)
 def test_source_hash_ignores_only_generated_outputs(self):
  (self.root/'code.cs').write_text('candidate');before=q.source_identity(self.root);d=self.root/'.correction-results';d.mkdir();(d/'result.json').write_text('{}');self.assertEqual(before,q.source_identity(self.root));(self.root/'code.cs').write_text('mutation');self.assertNotEqual(before,q.source_identity(self.root))
 def test_linked_candidate_source_is_rejected(self):
  p=self.root/'target';p.write_text('candidate');(self.root/'linked').symlink_to(p)
  with self.assertRaises(ValueError):q.source_identity(self.root)
 def test_environment_secret_and_public_token_destinations_are_scrubbed(self):
  text='Password=very-private; payload=proof-value& accessToken="live-access" owner@example.test';value=q.redact(text,{'TEST_PASSWORD':'very-private'})
  for secret in ['very-private','proof-value','live-access','owner@example.test']:self.assertNotIn(secret,value)
 def test_stage_environment_does_not_reuse_outer_run_identity(self):
  clean=q.stage_environment({'TREEHAMMOCK_TEST_RUN_ACTIVE':'true','TREEHAMMOCK_TEST_RUN_TOKEN':'private','TREEHAMMOCK_PROCESS_GATE':'private','PATH':'caller','DOTNET_CLI_TELEMETRY_OPTOUT':'true'})
  self.assertEqual(clean,{'PATH':'caller','DOTNET_CLI_TELEMETRY_OPTOUT':'true'})
 def test_private_stage_environment_loader_preserves_caller_settings(self):
  spec=importlib.util.spec_from_file_location('stage',ROOT/'eng/stage-cross-feature-qualification.py');stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)
  p=self.root/'.docker/test-runs/run/cor24-stage-environment.json';p.parent.mkdir(parents=True);p.write_text('{"PATH":"caller"}');p.chmod(0o600)
  self.assertEqual(stage.load_environment(p),{'PATH':'caller'})
 def test_public_or_invalid_stage_environment_is_rejected(self):
  spec=importlib.util.spec_from_file_location('stage',ROOT/'eng/stage-cross-feature-qualification.py');stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)
  p=self.root/'public.json';p.write_text('{"PATH":"caller"}')
  with self.assertRaises(ValueError):stage.load_environment(p)
 def test_jwt_is_scrubbed(self):self.assertNotIn('eyJabc.abcdef.signature',q.redact('eyJabc.abcdef.signature',{}))
 def receipt(self,name,text):
  p=self.root/'.correction-results'/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text);return p
 def test_native_receipt_is_retained_with_both_hashes(self):
  p=self.receipt('run.json','{"qualification":"Partial","message":"accessToken=hidden-value"}');records=q.retain_receipts(self.root,self.destination,{})
  self.assertEqual(len(records),1);self.assertEqual(records[0]['original_sha256'],q.sha(p));public=self.destination/records[0]['path'];self.assertNotIn('hidden-value',public.read_text());self.assertNotEqual(records[0]['original_sha256'],records[0]['public_sha256'])
 def test_private_environment_and_ownership_receipts_are_excluded(self):
  self.receipt('ownership.json','{"qualification":"Passed","password":"private"}');self.receipt('environment.json','{"qualification":"Passed"}');self.assertEqual(q.retain_receipts(self.root,self.destination,{}),[])
 def test_embedded_keyring_is_not_exported(self):self.receipt('run.json','{"qualification":"Passed","hmacKeys":{"1":"private"}}');self.assertEqual(q.retain_receipts(self.root,self.destination,{}),[])
 def test_trx_entity_declaration_cannot_be_retained(self):
  self.receipt('tests.trx','<!DOCTYPE TestRun><TestRun/>')
  with self.assertRaises(ValueError):q.retain_receipts(self.root,self.destination,{})
 def test_linked_receipt_is_rejected(self):
  p=self.receipt('run.json','{"qualification":"Passed"}');(p.parent/'linked.json').symlink_to(p)
  with self.assertRaises(ValueError):q.retain_receipts(self.root,self.destination,{})
 def test_arbitrary_json_is_not_exported_as_native_evidence(self):self.receipt('untrusted.json','{"anything":"not a result"}');self.assertEqual(q.retain_receipts(self.root,self.destination,{}),[])
 def test_manifest_missing_stage_or_duplicate_id_is_rejected(self):
  folder=self.root/'eng';folder.mkdir();requirements=q.read(ROOT/'eng/cross-feature-qualification-requirements.json')
  for kind in ['missing','duplicate']:
   data=copy.deepcopy(requirements)
   if kind=='missing':data['required_stages'].pop()
   else:data['required_stages'][-1]['id']=data['required_stages'][0]['id']
   (folder/'cross-feature-qualification-requirements.json').write_text(json.dumps(data))
   with self.subTest(kind=kind),self.assertRaises(ValueError):q.load_requirements(self.root)
if __name__=='__main__':unittest.main()
