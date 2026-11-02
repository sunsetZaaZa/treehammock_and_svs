#!/usr/bin/env python3
"""Verify the documentation-only cache enablement revision; no runtime qualification."""
from pathlib import Path
import hashlib,json,subprocess,sys
ROOT=Path(__file__).resolve().parents[2]
MANIFEST='docs/session-validation/CACHE_ONLY_ENABLEMENT_SOURCE_INVENTORY.json'
IGNORE={'.git','bin','obj','__pycache__','TestResults'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 m=json.loads((ROOT/MANIFEST).read_text());before=m['baseline_files']
 actual={p.relative_to(ROOT).as_posix():sha(p) for p in sorted(ROOT.rglob('*')) if p.is_file() and not set(p.relative_to(ROOT).parts)&IGNORE and p.suffix!='.pyc' and p.relative_to(ROOT).as_posix()!=MANIFEST}
 assert actual==m['files'],'Source drift'
 changed=sorted(n for n in before.keys()&actual.keys() if before[n]!=actual[n]);added=sorted(actual.keys()-before.keys())
 assert not before.keys()-actual.keys() and changed==m['expected_modified'] and added==m['expected_added']
 assert all((n.startswith('docs/session-validation/') and n.endswith(('.md','.json','.txt','.py'))) or n=='deploy/session-validation/SVS06_CACHE_OPERATIONS.md' for n in changed)
 assert all(n.startswith('docs/session-validation/') or n=='eng/session-validation/verify-enablement-revision.py' for n in added)
 frozen=[n for n in before if not n.startswith('docs/session-validation/') and n!='deploy/session-validation/SVS06_CACHE_OPERATIONS.md']
 frozen += [n for n in before if 'SOURCE_INVENTORY.json' in n or n.endswith('_DELIVERY.md')]
 assert all(actual[n]==before[n] for n in frozen),'Runtime or historical evidence changed'
 d=ROOT/'docs/session-validation';g=d/'design';t=json.loads((d/'SVS_PR_TRACKER.json').read_text())
 assert t==json.loads((g/'docs/SVS_PR_TRACKER.json').read_text())
 assert [p['status'] for p in t['prs']]==m['previous_statuses'] and {p['id']:p.get('depends_on',[]) for p in t['prs']}==m['previous_dependencies']
 assert t['open_findings']==m['previous_open_findings'] and t['next_pr']=='SVS-07'
 assert t['cache_only_enablement_pr']=='SVS-11' and t['prs'][11]['must_deliver_production_enablement']
 assert t['prs'][11]['code_audit_projects']==['SVS','TreeHammock']
 assert (d/'CACHE_ONLY_ENABLEMENT_PLAN.md').read_bytes()==(g/'docs/18_CACHE_ONLY_ENABLEMENT.md').read_bytes()
 req=json.loads((d/'CACHE_ONLY_ENABLEMENT_REQUIREMENTS.json').read_text());assert len(req['requirements'])==8 and req['actual_audit_status']=='Planned in SVS-11/THS-12'
 assert not req['runtime_native_qualification_flag_required'] and not req['runtime_change_in_this_revision']
 for line in (g/'SHA256_MANIFEST.txt').read_text().splitlines():h,n=line.split('  ',1);assert sha(g/n)==h
 r=subprocess.run([sys.executable,str(g/'tools/verify_design_package.py')],capture_output=True,text=True);assert not r.returncode,r.stdout+r.stderr
 print(json.dumps(dict(status='PASS',scope='Documentation/source preservation only; no C# or native execution',source_files=len(actual)+1,parent='SVS-06',source_paths_modified=len(changed),source_paths_added=len(added)+1,runtime_source_unchanged=True,previous_pr_statuses_dependencies_findings_preserved=True,code_enablement_pr='SVS-11',treehammock_integration_pr='THS-12',runtime_tests_executed_this_revision=0,native_tests_executed_this_revision=0,release_ready=False),indent=2))
if __name__=='__main__':main()
