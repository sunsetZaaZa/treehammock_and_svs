#!/usr/bin/env python3
"""Lifecycle wiring guard; real Docker/SDK/Windows execution is separate."""
import argparse,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def require(value,message):
 if not value:raise ValueError(message)
def validate(root):
 helper=(root/'eng/test-ownership.py').read_text();process=(root/'eng/test-process.py').read_text()
 for token in ['on_created(run)','on_created=prepared','class Deadline:','class RunLock:','class Lifecycle:',"self.run['processes'].append(record)","write(gate,dict(owner=self.run['id'],token=self.run['token']))","retain=primary!=0 and retain=='true'","status='RetainedDebug'","processes.identity(run['pid'])!=run['pid_identity']","discard_retained",'process-cleanup','inputs=False']:
  require(token in helper,'Missing lifecycle ownership/budget boundary: '+token)
 require(helper.index("write(manifest(self.run),self.run)")<helper.index('write(gate,dict('),'Child released before receipt commit')
 require(helper.index('write(folder/\'ownership.json\',run)')<helper.index('snapshot(root,'),'Manifest must precede acquisition')
 for token in ['def identity(pid):','def windows_job():','0x2000','prctl(36,1','pidfd_send_signal','Process launch was not committed',"status='Stopped'","request['role']=='host-api'"]:
  require(token in process,'Missing process containment: '+token)
 bash=(root/'eng/docker-host-system-stack-tests.sh').read_text();ps=(root/'eng/docker-host-system-stack-tests.ps1').read_text()
 require(bash.index('trap cleanup EXIT')<bash.index('"${compose[@]}" up'),'Bash cleanup installed after Compose')
 require(ps.index('$primaryFailure = $null\ntry {')<ps.index("-Stage 'docker-compose-2'"),'PowerShell cleanup installed after Compose')
 for source in [bash,ps]:require('api-start' in source and 'api-stop' in source,'Host API bypasses ownership')
 require('api_pid=' not in bash and 'Start-Process' not in ps,'Host process escapes supervisor')
 require('exit "$test_code"' in bash,'Bash native test code is lost')
 return dict(status='SourceContractsConsistent',qualification='NotRun',scope='Acquisition receipts, gated containment, shared cleanup deadline and exact abandoned recovery')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=ROOT);a=p.parse_args()
 try:print(json.dumps(validate(a.root),indent=2))
 except (OSError,ValueError) as e:print(str(e));raise SystemExit(1)
