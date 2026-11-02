#!/usr/bin/env python3
"""Real partial Compose acquisition and real SDK process-tree qualification; no adapters."""
import argparse,importlib.util,json,os,shutil,subprocess,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('owned',ROOT/'eng/test-ownership.py');owned=importlib.util.module_from_spec(spec);spec.loader.exec_module(owned)
def execute(output):
 report=dict(pr='COR23Z',qualification='NotRun',cases=[],pending=['Full application host acquisition/readiness/test failure matrix on supported Linux/Windows PowerShell and Docker Desktop hosts.','Windows job/ACL/break/force-termination and daemon restart/hung deletion recovery.'],reason='');code=2
 def save():output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(report,indent=2)+'\n')
 docker=shutil.which('docker');sdk=shutil.which('dotnet');bash=shutil.which('bash')
 if not all([docker,sdk,bash]):report['reason']='Real Docker, .NET SDK and Bash are required; zero cases executed';save();return code
 with tempfile.TemporaryDirectory(prefix='cor23z-native-') as temporary:
  root=Path(temporary)/'source';owned.snapshot(ROOT,root);manager=None;process=None
  try:
   subprocess.run([docker,'info'],check=True,capture_output=True,timeout=15)
   entry=root/'eng/docker-http-contracts-direct.sh';entry.write_text('''#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source eng/test-ownership.sh
treehammock_owned_test docker-http-contracts-direct "$@"
source eng/fixture-isolation.sh
treehammock_initialize_fixture container
docker compose -p "$COMPOSE_PROJECT_NAME" -f docker-compose.integration.yml -f docker-compose.ci-system.yml -f "$TREEHAMMOCK_TEST_OWNERSHIP_OVERRIDE" up --detach --wait --wait-timeout 120 postgres
# An initiating failure after real partial acquisition must still clean that state.
exit 47
''');entry.chmod(0o755)
   result=subprocess.run([bash,str(entry)],cwd=root,capture_output=True,timeout=900);owned.require(result.returncode==47,'Partial-start failure changed')
   run=json.loads(next((root/'.docker/test-runs').glob('*/ownership.json')).read_text());outcome=json.loads((Path(run['artifacts'])/'run.json').read_text());owned.require(outcome['cleanup']=='Passed','Partial-start cleanup failed')
   for args in [['ps','--all','--quiet'],['volume','ls','--quiet'],['network','ls','--quiet']]:owned.require(not owned.docker(run,args+['--filter','label='+owned.OWNER+'='+run['id']]).stdout.strip(),'Partial resources remain')
   report['cases'].append(dict(case='real-compose-partial-acquisition-preserves-47-and-cleans-owned-state',status='Passed'))
   project=Path(temporary)/'sdk';project.mkdir();(project/'Probe.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework><ImplicitUsings>enable</ImplicitUsings></PropertyGroup></Project>');(project/'Program.cs').write_text((ROOT/'eng/tests/fixtures/process-lifecycle/LifecycleProbe.cs.txt').read_text());(project/'NuGet.Config').write_text('<configuration><packageSources><clear /></packageSources></configuration>')
   subprocess.run([sdk,'build',str(project/'Probe.csproj'),'-c','Release','--nologo'],check=True,capture_output=True,timeout=120)
   run=owned.create_run(root,'docker-host-system-stack-tests',dict(os.environ));run['status']='Running';owned.write(owned.manifest(run),run);manager=owned.Lifecycle(run);receipt=Path(run['artifacts'])/'sdk.pid'
   process=manager.launch('host-api',[sdk,'run','--project',str(project/'Probe.csproj'),'-c','Release','--no-build','--no-restore','--',str(receipt)],owned.run_environment(run,os.environ))
   deadline=time.monotonic()+30
   while not Path(str(receipt)+'.child').exists():
    owned.require(process.poll() is None and time.monotonic()<deadline,'SDK tree never started');time.sleep(.05)
   pids=[int(receipt.read_text()),int(Path(str(receipt)+'.child').read_text())]
   owned.require(not manager.stop(owned.Deadline(15)),'SDK tree teardown failed');owned.require(all(owned.processes.identity(pid) is None for pid in pids),'SDK descendants still alive')
   report['cases'].append(dict(case='real-dotnet-run-parent-and-application-child-tree-stop',status='Passed'));report.update(qualification='Partial',reason='Real local Compose/SDK cases passed; full supported-host/application matrix pending');code=2
  except (OSError,ValueError,KeyError,subprocess.SubprocessError):report.update(qualification='Failed',reason='Real lifecycle stage failed');code=1
  finally:
   if manager:
    try:
     if manager.stop(owned.Deadline(15)):code=1;report['qualification']='Failed'
    except (OSError,ValueError,subprocess.SubprocessError):code=1;report['qualification']='Failed'
   for path in (root/'.docker/test-runs').glob('*/ownership.json'):
    try:
     if owned.cleanup(json.loads(path.read_text()))['status']!='Passed':code=1;report['qualification']='Failed'
    except (OSError,ValueError,KeyError,subprocess.SubprocessError):code=1;report['qualification']='Failed'
   save()
 return code
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,default=ROOT/'.correction-results/cor23z-lifecycle.json');a=p.parse_args();raise SystemExit(execute(a.output.resolve()))
