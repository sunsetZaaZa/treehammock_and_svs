#!/usr/bin/env python3
"""Source consistency only; this cannot qualify any COR24 application or release gate."""
import argparse,importlib.util,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def module(root):
 spec=importlib.util.spec_from_file_location('cor24_collector',root/'eng/verify-cross-feature-qualification.py');value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
def validate(root=ROOT):
 collector=module(root);requirements=collector.load_requirements(root);inventory=collector.catalog(root)
 source=(root/'eng/verify-cross-feature-qualification.py').read_text()
 for token in ['source_identity(checkout)==before','manager.stop(owned.Deadline(15))','process.wait(timeout=recipe[\'timeout_seconds\'])','Stage not selected; mandatory requirement remains unsatisfied','closure_updates_performed=False','deployment_performed=False','release_ready=False','Child returned a blocker/nonzero outcome','packet[\'ledger_unchanged\']','retain_receipts(checkout,directory','Missing executable prerequisites','COR22 workload budgets remain proposed/unreviewed']:
  collector.require(token in source,'Integrated evidence boundary missing: '+token)
 cases=collector.read(root/'eng/cross-feature-qualification-cases.json')
 collector.require(len(cases['cases'])==12 and cases['qualification']=='NotRun','Source cases cannot claim runtime qualification')
 for case in cases['cases']:
  collector.require((root/case['path']).is_file(),'Missing cross-feature source case')
  if case['method']:collector.require(case['method']+'(' in (root/case['path']).read_text(),'Missing cross-feature method: '+case['method'])
 collector.require('cor24-qualification' in (root/'.github/workflows/treehammock-ci.yml').read_text(),'Manual CI evidence lane required')
 return dict(status='SourceContractsConsistent',qualification='Blocked',findings=len(inventory['findings']),followups=len(inventory['followups']),gates=len(inventory['gates']),features=len(inventory['features']),stages=len(requirements['required_stages']),acceptance_obligations=len(requirements['required_acceptance']),release_ready=False)
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=ROOT);a=p.parse_args()
 try:print(json.dumps(validate(a.root)));return 0
 except (ValueError,OSError,KeyError):print('COR24 qualification source contract failed.');return 1
if __name__=='__main__':raise SystemExit(main())
