#!/usr/bin/env python3
"""COR23Y source/wiring guard; native isolation and cancellation remain separate."""
import argparse,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
LANES=['docker-unit-tests','docker-sql-contracts','docker-http-contracts-direct','docker-http-contracts-proxy','docker-system-stack-tests','docker-host-system-stack-tests','docker-all-tests']
def require(value,message):
 if not value:raise ValueError(message)
def validate(root):
 helper=(root/'eng/test-ownership.py').read_text()
 for token in ["pin_context(run,startup_deadline);child=run_environment(run,environment)","uuid.uuid4()","project='treehammock-test-'","snapshot(root,Path(run['checkout']))","secrets.compare_digest(token,run['token'])","--env-file","validate_graph(run,graph","label='+OWNER+'='+run['id']","actual.get(k)==v","COMPOSE_DISABLE_ENV_FILE='true'","lease.acquire()","lease.release()","run['ci_identity']!=identity","require(not alive(run['pid'])","if clean['status']=='Failed' and primary==0"]:require(token in helper,'Ownership/cleanup boundary missing: '+token)
 require('prune' not in helper and "'down'" not in helper,'Cleanup must be label-verified, never default-project teardown')
 for lane in LANES:
  for extension in ['sh','ps1']:
   source=(root/'eng'/f'{lane}.{extension}').read_text()
   require('test-ownership.'+extension in source,'Lane bypasses ownership coordinator')
   require(('treehammock_owned_test '+lane if extension=='sh' else "Enter-TreehammockOwnedTest -Lane '"+lane+"'") in source,'Lane omits run inheritance')
   require('down --volumes' not in source and "'down', '--volumes'" not in source and 'prune' not in source,'Test must never reset a shared project')
   if lane not in ['docker-unit-tests','docker-all-tests']:
    require(('docker compose -p "$COMPOSE_PROJECT_NAME"' if extension=='sh' else "'-p', $env:COMPOSE_PROJECT_NAME") in source,'Compose operation omits explicit project')
    require('TREEHAMMOCK_TEST_OWNERSHIP_OVERRIDE' in source,'Compose operation omits owned override')
   if lane=='docker-host-system-stack-tests':require('TREEHAMMOCK_TEST_HOST_LOG_ROOT' in source and '.artifacts/system-host-api' not in source,'Host artifacts must be isolated')
   if lane=='docker-unit-tests':require('io.treehammock.fixture.owner=' in source and 'TREEHAMMOCK_TEST_UNIT_IMAGE' in source,'Unit image must be unique and owned')
 value=json.loads((root/'eng/test-ownership-compose.json').read_text());require(set(value)=={'container','host'},'Modes must not merge unrelated services')
 require(set(value['host']['services'])=={'postgres','dragonfly','haproxy-host'},'Host graph differs')
 for path in [*(root/'.github/workflows').glob('*.yml'),*(root/'.gitlab/ci/pipelines').glob('*.yml')]:
  source=path.read_text()
  require(not re.search(r'docker compose[^\n]*(?:down --volumes|logs --no-color)',source),'CI must use exact owned manifests')
  require(not re.search(r'      - name:[^\n]+\n        if: always\(\)\n\n      - name:',source),'Empty CI step')
  if 'docker-system-stack-tests.sh' in source or 'docker-host-system-stack-tests.sh' in source:require('python3 eng/test-ownership.py cleanup-ci' in source,'System CI safety cleanup must preserve run/job identity')
 return dict(status='SourceContractsConsistent',qualification='NotRun',lanes=len(LANES),scope='Fresh project/checkouts, authenticated inheritance, namespace/labels/lease/CI wiring')
if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=ROOT);args=parser.parse_args()
 try:print(json.dumps(validate(args.root),indent=2))
 except (ValueError,OSError,KeyError) as error:print(str(error));raise SystemExit(1)
