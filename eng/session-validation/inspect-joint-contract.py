#!/usr/bin/env python3
"""Exact source/policy/schema reconciliation. Offline checks are not native acceptance."""
from pathlib import Path
import argparse,hashlib,json,zipfile
R=Path(__file__).resolve().parents[2]
def digest(b):return hashlib.sha256(b).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--peer-archive',type=Path,required=True);a=p.parse_args()
 m=json.loads((R/'docs/session-validation/SVS10_PEER_PINS.json').read_text());assert digest(a.peer_archive.read_bytes())==m['peer_archive_sha256']
 with zipfile.ZipFile(a.peer_archive) as z:
  assert z.testzip() is None and len(z.namelist())==len(set(z.namelist()))
  seal=json.loads(z.read('PACKAGE_SHA256.json'));assert set(z.namelist())==set(seal)|{'PACKAGE_SHA256.json'}
  for n,h in seal.items():assert digest(z.read(n))==h,n
  prefix='source/treehammock-main/'
  for n,h in m['peer_files'].items():assert digest(z.read(prefix+n))==h,n
  snapshots=R/'tests/Treehammock.SessionValidation.HostTests/PeerSource';s=json.loads((snapshots/'SOURCE_PINS.json').read_text())
  assert s['peer_archive_sha256']==m['peer_archive_sha256']
  for n,h in s['files'].items():assert digest((snapshots/n).read_bytes())==h==digest(z.read(prefix+n)),n
  for n,x in m['shared_files'].items():assert digest((R/n).read_bytes())==x['svs10_sha256'] and digest(z.read(prefix+n))==x['peer_sha256'],n
  reader='src/Treehammock.SessionValidation.Storage/CoherentSessionCacheReader.cs'
  local=(R/reader).read_text();delta='    // SVS-08 read-only hint query retained; never grants admission.\n    public bool IsCurrentEpoch(Guid epoch)=>epoch!=Guid.Empty && Capture()?.Space.Epoch==epoch;\n'
  assert local.count(delta)==1 and local.replace(delta,'').encode()==z.read(prefix+reader)
  assert (R/'deploy/session-validation/conformance/authority-transition.lua').read_bytes()==z.read(prefix+'Rigging/Cache/Authority/authority-transition.lua')
  assert (R/'deploy/session-validation/treehammock-validator-policy.json').read_bytes()==z.read(prefix+'deploy/authority/THS10_DATABASE_POLICY.json')
  assert (R/'contracts/coherent-cache-v1.schema.json').read_bytes()==z.read(prefix+'contracts/coherent-cache-v1.schema.json')
 previous=json.loads((R/'docs/session-validation/SVS-09_SOURCE_INVENTORY.json').read_text())['files']
 for n in ['NpgsqlSnapshotExecutor.cs','YsqlSessionAuthority.cs','ValidatorDatabaseIdentity.cs']:
  path='src/Treehammock.SessionValidation.Storage/'+n;assert digest((R/path).read_bytes())==previous[path],path
 for path in ['src/Treehammock.SessionValidation.Api','src/Treehammock.SessionValidation.Client']:
  for f in (R/path).glob('*.cs'):assert '.Admit(' not in f.read_text(),'Production admission belongs to SVS11'
 assert digest((R/'Directory.Packages.props').read_bytes())==previous['Directory.Packages.props']
 assert all(digest((R/n).read_bytes())==h for n,h in previous.items() if n.endswith('.lock.json'))
 print(json.dumps(dict(status='PASS',peer='THS-12B',peer_source_files=len(m['peer_files']),compiled_exact_peer_files=len(s['files']),shared_files_reviewed=len(m['shared_files']),policy_and_cache_schema='Exact byte match',validator_adapters='Preserved',production_admission='Unadmitted until SVS11 runtime agent',native_executions=0,release_ready=False),indent=2))
if __name__=='__main__':main()
