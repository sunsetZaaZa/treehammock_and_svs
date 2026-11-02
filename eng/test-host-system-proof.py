#!/usr/bin/env python3
"""Real Docker/.NET host identity, full System TRX and fault scenarios; no adapters."""
import argparse,http.server,importlib.util,json,os,shutil,signal,subprocess,tempfile,threading,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('owned',ROOT/'eng/test-ownership.py');owned=importlib.util.module_from_spec(spec);spec.loader.exec_module(owned)
def execute(output):
 report=dict(pr='COR23AA',qualification='NotRun',cases=[],pending=['Native Windows/PowerShell/Desktop matrix, supported host prerequisites (COR23AB), final integrated release evidence (COR24).'],reason='');code=2
 def save():output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(report,indent=2)+'\n')
 if not all(shutil.which(name) for name in ['docker','dotnet','bash']) or os.name=='nt':report['reason']='Native Linux Docker/.NET/Bash required; zero cases executed';save();return code
 class Sentinel(http.server.BaseHTTPRequestHandler):
  def log_message(self,*args):pass
  def do_GET(self):
   data=b'{"status":"ready"}';self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
 with tempfile.TemporaryDirectory(prefix='cor23aa-native-') as folder:
  parent=Path(folder);active=None
  def root(name):
   value=parent/name;owned.snapshot(ROOT,value);return value
  def run(value,expect_success=False,kill_phase=None):
   nonlocal active
   log=tempfile.TemporaryFile();active=subprocess.Popen(['bash',str(value/'eng/docker-host-system-stack-tests.sh')],cwd=value,stdout=log,stderr=subprocess.STDOUT,env=dict(os.environ,TREEHAMMOCK_HOST_STARTUP_TIMEOUT_SECONDS='900'))
   deadline=time.monotonic()+1800;sent=False
   while active.poll() is None:
    if time.monotonic()>deadline:raise ValueError('Native host proof deadline')
    if kill_phase and not sent:
     for path in (value/'.docker/test-runs').glob('*/ownership.json'):
      manifest=json.loads(path.read_text());api=next((record for record in manifest['processes'] if record['role']=='host-api'),None)
      if api is None:continue
      state=json.loads(Path(api['state']).read_text())
      if state.get('status')!='Running':continue
      tests_running=False
      if kill_phase=='tests':
       wrapper=next(record for record in manifest['processes'] if record['role']=='wrapper')
       for pid in owned.descendants_of(wrapper['pid']):
        record=owned.processes.linux_records().get(pid)
        if record:
         try:argv=(Path('/proc')/str(record[0])/'cmdline').read_bytes()
         except OSError:continue
         if b'test\0treehammock.Tests.System/' in argv:tests_running=True
      if kill_phase=='readiness' or tests_running:
       owned.require(owned.verified_signal(state['pid'],state['identity'],signal.SIGTERM),'Native owned API identity changed');sent=True
    time.sleep(.03)
   result=active.returncode;log.close();active=None
   owned.require(result==0 if expect_success else result!=0,'Wrong native host result')
   if kill_phase:owned.require(sent,'Native API exit injection never reached its actual phase')
   runpath=next((value/'.docker/test-runs').glob('*/ownership.json'));manifest=json.loads(runpath.read_text());outcome=json.loads((Path(manifest['artifacts'])/'run.json').read_text());owned.require(outcome['cleanup']=='Passed','Native host cleanup failed')
   if expect_success:
    proof=json.loads((Path(manifest['artifacts'])/'host/proof.json').read_text());owned.require(proof['status']=='Passed' and proof['identity']['assembly_sha256']==manifest['host_artifact']['assembly_sha256'],'Native assembled/loaded/endpoint/result identity failed')
  try:
   subprocess.run(['docker','info'],check=True,capture_output=True,timeout=15)
   run(root('positive'),True);report['cases'].append(dict(case='unmodified-real-dll-proxy-backing-state-and-complete-System-TRX',status='Passed'))
   sentinel=http.server.ThreadingHTTPServer(('127.0.0.1',8080),Sentinel);thread=threading.Thread(target=sentinel.serve_forever,daemon=True);thread.start()
   try:run(root('old-listener'));owned.require(sentinel.server_address[1]==8080,'Old listener changed');report['cases'].append(dict(case='healthy-old-loopback-listener-preserved-and-rejected',status='Passed'))
   finally:sentinel.shutdown();sentinel.server_close();thread.join(timeout=2)
   sentinel=http.server.ThreadingHTTPServer(('127.0.0.1',0),Sentinel);thread=threading.Thread(target=sentinel.serve_forever,daemon=True);thread.start()
   try:
    value=root('wrong-proxy');config=value/'deploy/haproxy/haproxy.host-system.cfg';config.write_text(config.read_text().replace('127.0.0.1:5001','127.0.0.1:'+str(sentinel.server_address[1])));run(value);report['cases'].append(dict(case='real-haproxy-wrong-target-cannot-prove-launched-dotnet-application',status='Passed'))
   finally:sentinel.shutdown();sentinel.server_close();thread.join(timeout=2)
   value=root('startup-exception');settings=value/'appsettings.Testing.json';data=json.loads(settings.read_text()) if settings.exists() else {};data['HostSystemTestProof']={'Unsupported':'reject'};settings.write_text(json.dumps(data));run(value);report['cases'].append(dict(case='real-application-startup-exception-fails-proof',status='Passed'))
   for phase in ['readiness','tests']:
    run(root('exit-'+phase),kill_phase=phase);report['cases'].append(dict(case='actual-launched-api-exit-during-'+phase+'-fails-proof',status='Passed'))
   report.update(qualification='Partial',reason='Real local Linux host cases passed; supported-host/Windows/Desktop/integrated qualification pending');code=2
  except (OSError,ValueError,KeyError,subprocess.SubprocessError):report.update(qualification='Failed',reason='Real host qualification failed; controlled success was not substituted');code=1
  finally:
   if active:
    active.terminate()
    try:active.wait(timeout=60)
    except subprocess.TimeoutExpired:active.kill();active.wait(timeout=5)
   for path in parent.glob('*/.docker/test-runs/*/ownership.json'):
    try:
     value=json.loads(path.read_text())
     if owned.recover(Path(value['source']),value['id'],os.environ)!=0:code=1;report['qualification']='Failed'
    except (OSError,ValueError,KeyError,subprocess.SubprocessError):code=1;report['qualification']='Failed'
   save()
 return code
if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,default=ROOT/'.correction-results/cor23aa-host.json');args=parser.parse_args();raise SystemExit(execute(args.output.resolve()))
