#!/usr/bin/env python3
"""Actual Docker sentinel/concurrent cancellation matrix; controlled waiting lane is explicit."""
import argparse,importlib.util,json,os
from pathlib import Path
import shutil,signal,subprocess,tempfile,time,uuid
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('ownership',ROOT/'eng/test-ownership.py');owned=importlib.util.module_from_spec(spec);spec.loader.exec_module(owned)
def execute(output,full_stack=False):
 report=dict(schema_version=1,qualification='NotRun',cases=[],cleanup=[],pending=['Actual supported Desktop/Linux and PowerShell/Windows host lane lease, state and cancellation','Partial-startup/process-tree/cleanup deadline qualification remains COR23Z/AA/AB','Integrated lane/result qualification remains COR24'])
 output.parent.mkdir(parents=True,exist_ok=True)
 def save():output.write_text(json.dumps(report,indent=2)+'\n')
 if not shutil.which('docker') or not shutil.which('bash'):
  report['reason']='Docker/Compose and Bash required; zero native cases executed';save();return 2
 identity='treehammock-cor23y-sentinel-'+uuid.uuid4().hex;volume=identity+'-volume';network=identity+'-network';container=identity+'-container';created=[];processes=[];primary=0
 def command(args,expected=0,timeout=120):
  result=subprocess.run(['docker',*args],capture_output=True,text=True,timeout=timeout)
  if expected is not None:owned.require(result.returncode==expected,'Native stage failed')
  return result
 def case(name):report['cases'].append(dict(case=name,status='Passed'))
 with tempfile.TemporaryDirectory(prefix='treehammock-cor23y-native-') as temporary:
  root=Path(temporary)/'source';owned.snapshot(ROOT,root)
  try:
   command(['info']);command(['volume','create',volume]);created.append(('volume',volume));command(['network','create',network]);created.append(('network',network))
   command(['run','--detach','--name',container,'--network',network,'--mount','type=volume,src='+volume+',dst=/state','alpine:3.20','sh','-c','echo developer-sentinel >/state/marker; sleep 3600']);created.append(('container',container))
   # Keep two actual Compose state graphs alive through an intentionally waiting
   # private lane body. This qualifies the real coordinator/labels/cancellation,
   # not the actual application proof stage substituted by this waiting fixture.
   entry=root/'eng/docker-http-contracts-direct.sh';original=entry.read_bytes()
   entry.write_text('''#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
source ./eng/test-ownership.sh
treehammock_owned_test docker-http-contracts-direct "$@"
source ./eng/fixture-isolation.sh
treehammock_initialize_fixture container
docker compose -p "$COMPOSE_PROJECT_NAME" -f docker-compose.integration.yml -f docker-compose.ci-system.yml -f "$TREEHAMMOCK_TEST_OWNERSHIP_OVERRIDE" up --detach --wait --wait-timeout 180 postgres dragonfly
touch "$TREEHAMMOCK_TEST_ARTIFACT_ROOT/started"
trap 'exit 143' TERM
trap 'exit 130' INT
while true; do sleep 1; done
''');entry.chmod(0o755)
   for _ in range(2):
    log=tempfile.TemporaryFile();process=subprocess.Popen(['bash',str(entry)],cwd=root,stdout=log,stderr=subprocess.STDOUT,start_new_session=True);processes.append((process,log))
   deadline=time.monotonic()+900
   while len(list((root/'artifacts/test-runs').glob('*/started')))<2:
    owned.require(all(p.poll() is None for p,_ in processes),'Waiting native fixture exited early')
    if time.monotonic()>deadline:raise ValueError('Native startup deadline')
    time.sleep(.2)
   manifests=sorted((root/'.docker/test-runs').glob('*/ownership.json'));runs=[json.loads(path.read_text()) for path in manifests];owned.require(len(runs)==2,'Expected exactly two concurrent owned projects')
   for run in runs:owned.validate_run(run,owned.manifest(run));owned.validate_graph(run,json.loads(owned.docker(run,owned.compose(run)+['config','--format','json']).stdout))
   owned.require(runs[0]['project']!=runs[1]['project'] and Path(runs[0]['credential_file']).read_text()!=Path(runs[1]['credential_file']).read_text(),'Runs reused identities or keys');case('actual-concurrent-rendered-project-key-and-volume-isolation')
   def state(run,index,write=False):
    values=dict(line.split('=',1) for line in Path(run['credential_file']).read_text().splitlines());base=owned.compose(run)
    sql="CREATE TABLE cor23y_owned_marker(value text); INSERT INTO cor23y_owned_marker VALUES ('run-"+str(index)+"');" if write else 'SELECT value FROM cor23y_owned_marker;'
    query=owned.docker(run,base+['exec','-T','--env','PGPASSWORD='+values['TREEHAMMOCK_FIXTURE_DB_PASSWORD'],'postgres','psql','-h','127.0.0.1','-U','treehammock','-d','treehammock','-t','-A','-c',sql])
    args=['set','cor23y:owned-marker','run-'+str(index)] if write else ['get','cor23y:owned-marker']
    cache=owned.docker(run,base+['exec','-T','--env','REDISCLI_AUTH='+values['TREEHAMMOCK_FIXTURE_CACHE_PASSWORD'],'dragonfly','redis-cli','--raw',*args])
    if not write:owned.require(query.stdout.strip()=='run-'+str(index) and cache.stdout.strip()=='run-'+str(index),'Sibling state changed')
   for index,run in enumerate(runs):state(run,index,True);state(run,index)
   case('actual-independent-postgres-and-cache-state')
   processes[0][0].terminate();owned.require(processes[0][0].wait(timeout=120)==143,'Cancellation outcome changed')
   completed=[json.loads(path.read_text()) for path in manifests];alive=[run for run in completed if run['status']=='Running'];owned.require(len(alive)==1 and processes[1][0].poll() is None,'Cancellation affected sibling run')
   sibling=alive[0];index=next(i for i,run in enumerate(runs) if run['id']==sibling['id']);state(sibling,index)
   marker=command(['exec',container,'cat','/state/marker']).stdout.strip();owned.require(marker=='developer-sentinel','Developer state was changed');command(['volume','inspect',volume]);command(['network','inspect',network]);case('actual-cancellation-preserves-sibling-and-developer-sentinel')
   processes[1][0].terminate();owned.require(processes[1][0].wait(timeout=120)==143,'Second cancellation outcome changed')
   for run in runs:
    remain=command(['ps','--all','--quiet','--filter','label='+owned.OWNER+'='+run['id']]).stdout.strip();owned.require(not remain,'Owned containers retained unexpectedly')
    for kind in ['volume','network']:owned.require(not command([kind,'ls','--quiet','--filter','label='+owned.OWNER+'='+run['id']]).stdout.strip(),'Owned state retained unexpectedly')
   case('actual-owned-cleanup-removes-only-labeled-test-resources')
   entry.write_bytes(original)
   if full_stack:
    actual=subprocess.run(['bash',str(root/'eng/docker-all-tests.sh')],cwd=root,capture_output=True,text=True,timeout=3600);owned.require(actual.returncode==0,'Actual all-tests runner failed');case('actual-unmodified-container-all-tests-runner')
   else:report['pending'].append('Unmodified full container runner: rerun with --full-stack')
   report['qualification']='Partial';report['reason']='Actual local Docker ownership cases passed; supported host and complete application/lifecycle matrix remains required'
  except (OSError,ValueError,KeyError,subprocess.SubprocessError):primary=1;report.update(qualification='Failed',reason='Native ownership qualification failed; no controlled adapter success inferred')
  finally:
   for process,log in processes:
    if process.poll() is None:
     process.terminate()
     try:process.wait(timeout=120)
     except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=10);primary=1
    log.close()
   for path in (root/'.docker/test-runs').glob('*/ownership.json'):
    try:
     run=json.loads(path.read_text());result=owned.cleanup(run);report['cleanup'].append(dict(run_id=run['id'],status=result['status']));primary|=result['status']!='Passed'
    except (OSError,ValueError,KeyError,subprocess.SubprocessError):primary=1
   for kind,name in reversed(created):
    try:
     args=['rm','--force',name] if kind=='container' else [kind,'rm',name];result=command(args,expected=None);report['cleanup'].append(dict(resource='owned native '+kind,status='Passed' if result.returncode==0 else 'Failed'));primary|=result.returncode!=0
    except (OSError,subprocess.SubprocessError):primary=1
   if primary:report['qualification']='Failed'
   save()
 return primary or 2
if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,default=ROOT/'.correction-results/cor23y-ownership.json');parser.add_argument('--full-stack',action='store_true');args=parser.parse_args();raise SystemExit(execute(args.output.resolve(),args.full_stack))
