#!/usr/bin/env python3
"""Create disposable test ownership, stage private inputs and remove only labeled resources."""
import argparse,datetime,hashlib,importlib.util,json,os
from pathlib import Path
import re,secrets,shutil,signal,socket,subprocess,sys,time,uuid,threading,socketserver
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('fixture_settings',ROOT/'eng/fixture-isolation.py');fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
OWNER='io.treehammock.fixture.owner';PROJECT='io.treehammock.fixture.project';ROLE='io.treehammock.fixture.role'
process_spec=importlib.util.spec_from_file_location('owned_process',ROOT/'eng/test-process.py');processes=importlib.util.module_from_spec(process_spec);process_spec.loader.exec_module(processes)
host_spec=importlib.util.spec_from_file_location('host_proof',ROOT/'eng/host-system-proof.py');hostproof=importlib.util.module_from_spec(host_spec);host_spec.loader.exec_module(hostproof)
prerequisite_spec=importlib.util.spec_from_file_location('host_prerequisites',ROOT/'eng/host-prerequisites.py');prerequisites=importlib.util.module_from_spec(prerequisite_spec);prerequisite_spec.loader.exec_module(prerequisites)
LANES=['docker-unit-tests','docker-sql-contracts','docker-http-contracts-direct','docker-http-contracts-proxy','docker-system-stack-tests','docker-host-system-stack-tests','docker-all-tests']
IGNORE={'.git','.docker','bin','obj','node_modules','artifacts','.artifacts','.correction-results','TestResults','__pycache__'}
def require(value,message):
    if not value:raise ValueError(message)
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def write(path,value):
    require(not fixture.linked(path),'Linked ownership output rejected')
    temporary=path.with_name(path.name+'.'+secrets.token_hex(8)+'.tmp')
    descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:
        with os.fdopen(descriptor,'w') as stream:json.dump(value,stream,indent=2);stream.write('\n')
        temporary.replace(path)
    finally:temporary.unlink(missing_ok=True)
def ci_identity(environment):
    if environment.get('GITHUB_ACTIONS')=='true':
        parts=[environment.get(k,'') for k in ['GITHUB_REPOSITORY','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_JOB']]
        require(all(parts),'Incomplete GitHub job identity');return 'github:'+':'.join(parts)
    if environment.get('GITLAB_CI')=='true':
        parts=[environment.get(k,'') for k in ['CI_PROJECT_ID','CI_PIPELINE_ID','CI_JOB_ID']]
        require(all(parts),'Incomplete GitLab job identity');return 'gitlab:'+':'.join(parts)
    return None
def labels(run):return {OWNER:run['id'],PROJECT:run['project'],ROLE:'disposable-test'}
def snapshot(source,target):
    def ignored(directory,names):return [name for name in names if name in IGNORE]
    # A source link must never redirect writable test outputs to the developer tree.
    for directory,dirs,names in os.walk(source,followlinks=False):
        dirs[:]=[name for name in dirs if name not in IGNORE]
        for name in dirs+names:require(not (Path(directory)/name).is_symlink(),'Source links require explicit fixture support')
    shutil.copytree(source,target,ignore=ignored)
    for script in (target/'eng').glob('*.sh'):script.chmod(script.stat().st_mode|0o111)
def create_run(root,lane,environment,on_created=None):
    require(lane in LANES,'Unknown test lane')
    identity=str(uuid.uuid4());project='treehammock-test-'+identity.replace('-','')
    parent=root/'.docker/test-runs'
    for path in [root/'.docker',parent]:
        require(not fixture.linked(path),'Linked run storage rejected');path.mkdir(mode=0o700,parents=True,exist_ok=True)
        if os.name!='nt':require(path.stat().st_uid==os.getuid(),'Foreign run storage');path.chmod(0o700)
    folder=parent/identity;folder.mkdir(mode=0o700);fixture.private_windows(folder,True,environment)
    artifacts=root/'artifacts/test-runs'/identity
    for path in [root/'artifacts',root/'artifacts/test-runs']:
        require(not fixture.linked(path),'Linked result storage rejected');path.mkdir(parents=True,exist_ok=True)
    artifacts.mkdir(mode=0o700)
    selected=environment.get('TREEHAMMOCK_DOCKER_SELECTED') or environment.get('TREEHAMMOCK_DOCKER_CLI') or 'docker'
    selected=shutil.which(selected,path=environment.get('PATH')) or selected
    run=dict(docker_cli=selected,schema_version=2,id=identity,project=project,token=secrets.token_hex(32),source=str(root.resolve()),checkout=str((folder/'checkout').resolve()),artifacts=str(artifacts.resolve()),lane=lane,pid=os.getpid(),ci_identity=ci_identity(environment),created_at=now(),status='Preparing',pid_identity=processes.identity(os.getpid()),processes=[],docker_environment={k:environment[k] for k in ['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_CONFIG','TREEHAMMOCK_DOCKER_CLI','TREEHAMMOCK_DOCKER_SELECTED'] if k in environment})
    run.update(credential_file=str(folder/'checkout/.docker/fixtures'/project/'compose.env'),override=str(folder/'ownership.compose.json'),images_override=str(folder/'images.compose.yml'))
    write(folder/'ownership.json',run)
    if on_created:on_created(run)
    try:
        snapshot(root,Path(run['checkout']))
        env=dict(environment,COMPOSE_PROJECT_NAME=project)
        credential=fixture.ensure(Path(run['checkout']),env,'container')
        run['credential_file']=str(credential);run['override']=str(folder/'ownership.compose.json');run['images_override']=str(folder/'images.compose.yml')
        value=json.loads((Path(run['checkout'])/'eng/test-ownership-compose.json').read_text())['host' if lane=='docker-host-system-stack-tests' else 'container']
        for service in value['services'].values():service['labels']=labels(run)
        for name in ['api','sql-contract-tests']:
            if name in value['services']:value['services'][name]['build']={'labels':labels(run)}
        for item in value['volumes'].values():item['labels']=labels(run)
        for item in value['networks'].values():item['labels']=labels(run)
        for name in ['http-contract-tests-direct','http-contract-tests-proxy','system-tests']:
            if name not in value['services']:continue
            value['services'][name]['volumes']=[{'type':'bind','source':str(artifacts/'compose-proof'),'target':'/reports'}]
        if 'sql-contract-tests' in value['services']:
            value['services']['sql-contract-tests']['environment']={'TREEHAMMOCK_TEST_RESULTS_DIRECTORY':'/results'}
            value['services']['sql-contract-tests']['volumes']=[{'type':'bind','source':str(artifacts/'sql'),'target':'/results'}]
        for directory in ['compose-proof','sql','host','unit','docker-logs']:(artifacts/directory).mkdir()
        write(Path(run['override']),value);run['status']='Owned';write(folder/'ownership.json',run)
    except BaseException:
        run['status']='PreparationFailed'
        try:write(folder/'ownership.json',run)
        except OSError:pass
        raise
    return run
def manifest(run):return Path(run['checkout']).parent/'ownership.json'
def validate_run(run,path,root=None,token=None,inputs=True):
    require(run.get('schema_version')==2 and run.get('lane') in LANES,'Invalid ownership manifest')
    require(isinstance(run.get('pid'),int) and run['pid']>0 and isinstance(run.get('pid_identity'),str) and run['pid_identity'],'Invalid coordinator birth identity')
    identity=str(uuid.UUID(run['id']));require(identity==run['id'],'Noncanonical run identity')
    require(run['project']=='treehammock-test-'+identity.replace('-',''),'Unexpected project identity')
    source=Path(run['source']);expected=source/'.docker/test-runs'/identity
    require(path==expected/'ownership.json' and Path(run['checkout'])==expected/'checkout' and Path(run['artifacts'])==source/'artifacts/test-runs'/identity,'Ownership path mismatch')
    for parent in [source/'.docker',source/'.docker/test-runs',expected,path]:require(not fixture.linked(parent),'Linked ownership storage rejected')
    if os.name!='nt':require(path.stat().st_uid==os.getuid() and path.stat().st_mode&0o077==0,'Manifest must be private and owned')
    if root:require(root.resolve()==Path(run['checkout']).resolve(),'Caller is outside owned checkout')
    if token is not None:require(bool(token) and secrets.compare_digest(token,run['token']),'Ownership capability mismatch')
    require(run.get('override')==str(expected/'ownership.compose.json') and run.get('images_override')==str(expected/'images.compose.yml'),'Override path mismatch')
    require(run.get('credential_file')==str(expected/'checkout/.docker/fixtures'/run['project']/'compose.env'),'Credential path mismatch')
    for name in ['override','credential_file']:
        if not inputs:continue
        require(not fixture.linked(Path(run[name])) and Path(run[name]).is_file(),'Missing or linked owned settings')
    return run
def joined(root,environment,lane):
    require(environment.get('TREEHAMMOCK_TEST_RUN_ACTIVE')=='true','No active owned test run')
    path=Path(environment.get('TREEHAMMOCK_TEST_RUN_MANIFEST',''));run=json.loads(path.read_text())
    validate_run(run,path,root,environment.get('TREEHAMMOCK_TEST_RUN_TOKEN',''))
    require(run['status']=='Running' and lane in LANES,'Inactive run cannot be joined')
    require(lane==run['lane'] or run['lane']=='docker-all-tests' and lane in LANES[:5],'Unrelated lane cannot reuse this run')
    expected=run_environment(run,{})
    for name in ['COMPOSE_PROJECT_NAME','TREEHAMMOCK_TEST_RUN_ID','TREEHAMMOCK_TEST_OWNERSHIP_OVERRIDE','TREEHAMMOCK_DOCKER_COMPOSE_IMAGE_OVERRIDE_FILE','TREEHAMMOCK_TEST_ARTIFACT_ROOT','TREEHAMMOCK_TEST_UNIT_IMAGE']:
        require(environment.get(name)==expected[name],'Owned environment identity mismatch')
    for name in ['TREEHAMMOCK_DOCKER_SELECTED','TREEHAMMOCK_DOCKER_CLI']:
        require(environment.get(name)==run['docker_cli'],'Docker executable changed inside owned run')
    for name in ['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_CONFIG']:
        require(environment.get(name)==run['docker_environment'].get(name),'Daemon context changed inside owned run')
    return run
def run_environment(run,environment):
    child=dict(environment);child.update(run['docker_environment'])
    for name in ['COMPOSE_FILE','COMPOSE_PROFILES','COMPOSE_ENV_FILES','COMPOSE_PROJECT_DIRECTORY','TREEHAMMOCK_PUBLIC_ORIGIN']:child.pop(name,None)
    child.update(TREEHAMMOCK_DOCKER_SELECTED=run['docker_cli'],TREEHAMMOCK_DOCKER_CLI=run['docker_cli'],COMPOSE_PROJECT_NAME=run['project'],COMPOSE_DISABLE_ENV_FILE='true',TREEHAMMOCK_TEST_RUN_ACTIVE='true',TREEHAMMOCK_TEST_RUN_MANIFEST=str(manifest(run)),TREEHAMMOCK_TEST_RUN_TOKEN=run['token'],TREEHAMMOCK_TEST_RUN_ID=run['id'],TREEHAMMOCK_TEST_OWNERSHIP_OVERRIDE=run['override'],TREEHAMMOCK_DOCKER_COMPOSE_IMAGE_OVERRIDE_FILE=run['images_override'],TREEHAMMOCK_TEST_ARTIFACT_ROOT=run['artifacts'],TREEHAMMOCK_TEST_UNIT_IMAGE=run['project']+'-unit:owned',TREEHAMMOCK_TEST_HOST_LOG_ROOT=run['artifacts']+'/host')
    return child
def arguments(lane,args):
    # Project/files, service selection, mounts, environment and image tags are owned.
    if lane=='docker-unit-tests':
        values={'--configuration':{'Release','Debug','Sandbox'},'--progress':{'auto','plain','tty'},'-Configuration':{'Release','Debug','Sandbox'},'-Progress':{'auto','plain','tty'}}
        index=0
        while index<len(args):
            value=args[index]
            if value in ('--no-cache','-NoCache'):index+=1;continue
            require(value in values and index+1<len(args) and args[index+1] in values[value],'Unsupported unit fixture argument');index+=2
    else:require(not args,'Owned Compose/all-test lanes do not accept arbitrary CLI overrides')
def docker(run,args,expected=0,timeout=60):
    environment=run_environment(run,os.environ);cli=environment.get('TREEHAMMOCK_DOCKER_SELECTED') or environment.get('TREEHAMMOCK_DOCKER_CLI') or 'docker'
    result=subprocess.run([cli,*args],env=environment,cwd=run['checkout'] if Path(run['checkout']).is_dir() else run['source'],capture_output=True,text=True,timeout=timeout)
    if expected is not None:require(result.returncode==expected,'Owned Docker command failed')
    return result
def pin_context(run,deadline=None):
    # Freeze the effective default as well as explicit caller daemon selectors.
    if not run['docker_environment'].get('DOCKER_HOST') and not run['docker_environment'].get('DOCKER_CONTEXT'):
        name=docker(run,['context','show'],timeout=deadline.left() if deadline else 60).stdout.strip()
        require(bool(name) and '\n' not in name and '\r' not in name,'Invalid effective Docker context')
        run['docker_environment']['DOCKER_CONTEXT']=name
        write(manifest(run),run)
def compose(run,host=False):
    base=['compose','-p',run['project'],'--env-file',run['credential_file']]
    names=['docker-compose.local-system.yml'] if host else ['docker-compose.integration.yml','docker-compose.api-proxy.yml','docker-compose.testing.yml','docker-compose.ci-system.yml']
    for name in names:base+=['-f',str(Path(run['checkout'])/name)]
    base+=['-f',run['override']]
    for profile in (['host-system'] if host else ['proxy','sql','http','http-proxy','system']):base+=['--profile',profile]
    return base

def validate_graph(run,value,host=False):
    require(value.get('name')==run['project'],'Rendered project identity changed')
    expected=labels(run)
    for kind in ['services','volumes','networks']:
        for name,item in value.get(kind,{}).items():
            require(not item.get('external'),'External test resource rejected')
            require(all(item.get('labels',{}).get(k)==v for k,v in expected.items()),'Resource lacks the exact ownership labels')
            if kind=='services':
                require(not item.get('container_name'),'Custom container name rejected')
                require(item.get('network_mode') in (None,'host') and (not item.get('network_mode') or host and name=='haproxy-host'),'Unowned network namespace rejected')
                for port in item.get('ports',[]):require(host and port.get('host_ip')=='127.0.0.1','Unexpected host publication')
            else:require(item.get('name','').startswith(run['project']+'_'),'Resource name is outside owned project')
    return value
class HostLease:
    def __init__(self,environment=None):self.stream=None;self.environment=environment
    def acquire(self):
        path=Path(tempfile_directory())/'treehammock-host-fixture.lease'
        require(not fixture.linked(path),'Linked host lease rejected')
        descriptor=os.open(path,os.O_RDWR|os.O_CREAT,0o600)
        self.stream=os.fdopen(descriptor,'r+b')
        try:
            fixture.private_windows(path,False,self.environment)
            if os.name=='nt':
                import msvcrt
                if path.stat().st_size==0:self.stream.write(b'0');self.stream.flush()
                self.stream.seek(0);msvcrt.locking(descriptor,msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                require(path.stat().st_uid==os.getuid() and path.stat().st_mode&0o077==0,'Foreign/public host lease rejected')
                fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
            for port in [5432,6379,5001,8080]:
                with socket.socket() as probe:
                    # POSIX permits TIME_WAIT reuse while still rejecting a live
                    # listening socket. Windows reuse can steal a listener: never use it.
                    if os.name!='nt':probe.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                    probe.bind(('127.0.0.1',port))
        except BaseException:self.release();raise
    def release(self):
        if self.stream:self.stream.close();self.stream=None
    # OS releases the lease on process exit; never unlink a lock another run uses.
def tempfile_directory():
    # A per-run TMPDIR must not split the fixed-port lease between checkouts.
    if os.name=='nt':
        folder=Path(os.environ.get('PROGRAMDATA','C:/ProgramData'))/'Treehammock'
        require(not fixture.linked(folder),'Linked global host lease directory rejected');folder.mkdir(exist_ok=True)
        return str(folder)
    return '/tmp'
def redactions(run):
    values=[run['token']]
    if run.get('host_artifact',{}).get('challenge'):values.append(run['host_artifact']['challenge'])
    if Path(run['credential_file']).exists():values += list(dict(line.split('=',1) for line in Path(run['credential_file']).read_text().splitlines()).values())
    return values
def redact(text,values):
    for value in values:
        if value:text=text.replace(value,'[REDACTED]')
    return text
class Deadline:
    def __init__(self,seconds):self.end=time.monotonic()+seconds
    def left(self,maximum=60):
        value=min(maximum,self.end-time.monotonic())
        if value<=0:raise TimeoutError('Owned cleanup budget exhausted')
        return value
def budget(environment):
    value=int(environment.get('TREEHAMMOCK_TEST_CLEANUP_TIMEOUT_SECONDS','45'))
    require(1<=value<=120,'Cleanup budget must be 1 to 120 seconds');return value

def cleanup(run,deadline=None,retain=False):
    validate_run(run,manifest(run),inputs=False);deadline=deadline or Deadline(45);diagnostics=Deadline(min(3,deadline.left()/4));failures=[];removed=[]
    if retain:
        result=dict(status='RetainedDebug',removed=[],failures=[],retained=True)
        write(Path(run['artifacts'])/'cleanup.json',result);return result
    kinds=[('container',['ps','--all','--quiet'],['rm','--force']),('volume',['volume','ls','--quiet'],['volume','rm']),('network',['network','ls','--quiet'],['network','rm']),('image',['image','ls','--quiet'],['image','rm'])]
    def bounded(args,expected=0,maximum=10):return docker(run,args,expected,deadline.left(maximum))
    for kind,list_args,remove_args in kinds:
        try:names=bounded(list_args+['--filter','label='+OWNER+'='+run['id']]).stdout.split()
        except (OSError,ValueError,subprocess.SubprocessError):failures.append(kind+'-inventory');continue
        for name in dict.fromkeys(names):
            try:
                args=['image','inspect',name] if kind=='image' else [kind,'inspect',name] if kind in ('network','volume') else ['inspect',name]
                record=json.loads(bounded(args).stdout)[0];actual=record.get('Config',{}).get('Labels',{}) if kind in ('container','image') else record.get('Labels',{})
                require(isinstance(actual,dict) and all(actual.get(k)==v for k,v in labels(run).items()),'Refusing resource with different ownership')
                if kind in ('volume','network'):require(record['Name'].startswith(run['project']+'_'),'Unowned resource name')
                if kind=='container':require(actual.get('com.docker.compose.project') in (None,run['project']),'Compose project mismatch')
                if kind=='container':
                    try:
                        logs=bounded(['logs','--tail','100',name],expected=None,maximum=diagnostics.left(2))
                        filename=hashlib.sha256(name.encode()).hexdigest()[:16]+'.log'
                        folder=Path(run['artifacts'])/'docker-logs';folder.mkdir(exist_ok=True)
                        (folder/filename).write_text(redact((logs.stdout+logs.stderr)[-65536:],redactions(run)))
                    except (OSError,ValueError,subprocess.SubprocessError):pass
                bounded(remove_args+[name]);removed.append(dict(kind=kind,resource=name))
            except (OSError,ValueError,KeyError,IndexError,subprocess.SubprocessError):failures.append(kind+'-removal')
    result=dict(status='Failed' if failures else 'Passed',removed=removed,failures=failures,budget_exhausted=time.monotonic()>=deadline.end)
    write(Path(run['artifacts'])/'cleanup.json',result);return result

def report(run,primary,clean):
    result=dict(schema_version=1,run_id=run['id'],project=run['project'],lane=run['lane'],ci_identity=run['ci_identity'],created_at=run['created_at'],completed_at=now(),exit_code=primary,status='Passed' if primary==0 else 'Failed',cleanup=clean['status'],ownership='Disposable',qualification='RunnerOutcomeOnly: expected native discovery remains the lane contract')
    if run['lane']=='docker-unit-tests':
        result['unit_image']=run_environment(run,{})['TREEHAMMOCK_TEST_UNIT_IMAGE']
    write(Path(run['artifacts'])/'run.json',result)
class RunLock:
    def __init__(self,run):self.run=run;self.stream=None
    def acquire(self):
        path=manifest(self.run).parent/'ownership.lock';require(not fixture.linked(path),'Linked recovery lease')
        self.stream=open(path,'a+b')
        if os.name=='nt':
            import msvcrt
            if path.stat().st_size==0:self.stream.write(b'0');self.stream.flush()
            self.stream.seek(0);msvcrt.locking(self.stream.fileno(),msvcrt.LK_NBLCK,1)
        else:
            import fcntl
            path.chmod(0o600);fcntl.flock(self.stream.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
    def release(self):
        if self.stream:self.stream.close();self.stream=None

def descendants_of(pid):return processes.descendants(pid)

def verified_signal(pid,birth,number):
    if not birth or processes.identity(pid)!=birth:return False
    if sys.platform.startswith('linux') and hasattr(os,'pidfd_open') and hasattr(signal,'pidfd_send_signal'):
        descriptor=os.pidfd_open(pid)
        try:
            if processes.identity(pid)!=birth:return False
            signal.pidfd_send_signal(descriptor,number);return True
        finally:os.close(descriptor)
    os.kill(pid,number);return True

def stop_record(record,deadline,process=None):
    pid=record['pid'];birth=record.get('identity');current=processes.identity(pid)
    state=Path(record['state'])
    if process is not None and process.poll() is not None or current is None or current!=birth:
        # A reused PID is never a cleanup target. A missing supervisor can leave
        # orphan descendants, so only its committed stopped receipt proves cleanup.
        try:done=json.loads(state.read_text()).get('status')=='Stopped'
        except (OSError,ValueError):done=False
        return done or not Path(record.get('gate',str(state)+'.missing-gate')).exists() and json.loads(state.read_text()).get('status') in ['Starting','Ready']
    require(birth,'No strong process identity for abandoned recovery')
    try:
        if os.name=='nt':
            if process is not None:
                try:process.send_signal(signal.CTRL_BREAK_EVENT)
                except OSError:pass  # A console-free host still has its kill-on-close job.
        else:verified_signal(pid,birth,signal.SIGTERM)
        until=time.monotonic()+min(6,deadline.left()/3)
        while time.monotonic()<until:
            if process is not None and process.poll() is not None or processes.identity(pid)!=birth:
                return json.loads(state.read_text()).get('status')=='Stopped' or not Path(record['gate']).exists() and json.loads(state.read_text()).get('status') in ['Starting','Ready']
            time.sleep(.03)
        if processes.identity(pid)!=birth:return json.loads(state.read_text()).get('status')=='Stopped' or not Path(record['gate']).exists() and json.loads(state.read_text()).get('status') in ['Starting','Ready']
        if os.name=='nt':
            processes.terminate_windows(pid,birth)
        else:
            for child in descendants_of(pid):
                try:verified_signal(child,processes.identity(child),signal.SIGKILL)
                except ProcessLookupError:pass
            # Leave the subreaper alive to reap children and commit its stopped
            # receipt. If it cannot finish within budget, recovery retains ownership.
        if process is not None:process.wait(timeout=deadline.left(2))
        else:
            until=time.monotonic()+deadline.left(2)
            while processes.identity(pid)==birth and time.monotonic()<until:time.sleep(.03)
        done=processes.identity(pid)!=birth or process is not None and process.poll() is not None
        if done and os.name=='nt':write(state,dict(status='Stopped',forced=True))
        return done and (os.name=='nt' or json.loads(state.read_text()).get('status')=='Stopped')
    except ProcessLookupError:return True

class Lifecycle:
    write=staticmethod(write);manifest=staticmethod(manifest);fixture=fixture;processes=processes
    def __init__(self,run,startup_deadline=None):self.run=run;self.children=[];self.lock=threading.RLock();self.closing=False;self.server=None;self.thread=None;self.log_threads=[];self.proof=hostproof.HostProof(self,startup_deadline or Deadline(600)) if run['lane']=='docker-host-system-stack-tests' else None
    def launch(self,role,command,environment):
        with self.lock:
            require(not self.closing,'Run cleanup already started')
            folder=manifest(self.run).parent;identifier=uuid.uuid4().hex
            request=folder/(identifier+'.request.json');gate=folder/(identifier+'.release.json');state=folder/(identifier+'.state.json')
            write(request,dict(role=role,command=command));write(state,dict(status='Starting'))
            env=dict(environment,TREEHAMMOCK_PROCESS_LANE=self.run['lane'],TREEHAMMOCK_PROCESS_REQUEST=str(request),TREEHAMMOCK_PROCESS_GATE=str(gate),TREEHAMMOCK_PROCESS_STATE=str(state))
            options=dict(cwd=self.run['checkout'],env=env,start_new_session=os.name!='nt',creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name=='nt' else 0,stdin=subprocess.DEVNULL)
            options.update(stdout=subprocess.PIPE,stderr=subprocess.PIPE if role=='host-api' else subprocess.STDOUT)
            process=subprocess.Popen([sys.executable,str(Path(self.run['checkout'])/'eng/test-process.py')],**options)
            if role=='host-api':
                for stream,name in [(process.stdout,'api.out.log'),(process.stderr,'api.err.log')]:
                    thread=threading.Thread(target=pump_stream,args=(stream,self.run,Path(self.run['artifacts'])/'host'/name,False),daemon=True);thread.start();self.log_threads.append(thread)
            record=dict(role=role,pid=process.pid,identity=processes.identity(process.pid),state=str(state),request=str(request),gate=str(gate))
            self.children.append((process,record));self.run['processes'].append(record)
            require(record['identity'],'Cannot establish strong supervisor identity')
            write(manifest(self.run),self.run)
            until=min(time.monotonic()+10,self.proof.deadline.end) if self.proof and not self.proof.ready else time.monotonic()+10
            while json.loads(state.read_text()).get('status')!='Ready':
                require(not self.closing and process.poll() is None and time.monotonic()<until,'Supervisor containment did not become ready')
                time.sleep(.02)
            require(not self.closing,'Cleanup started before launch commit')
            write(gate,dict(owner=self.run['id'],token=self.run['token']))
            return process
    def start_broker(self):
        owner=self
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    self.request.settimeout(3);data=b''
                    while not data.endswith(b'\n'):
                        chunk=self.request.recv(4096)
                        if not chunk:raise ValueError('Incomplete control request')
                        data+=chunk;require(len(data)<=131072,'Control request too large')
                    message=json.loads(data);require(secrets.compare_digest(message.get('token',''),owner.run['token']),'Invalid process capability')
                    with owner.lock:
                        require(not owner.closing,'Run cleanup started')
                        api=next(((p,r) for p,r in owner.children if r['role']=='host-api'),None)
                        operation=message.get('operation')
                        if operation=='api-start':
                            require(owner.run['lane']=='docker-host-system-stack-tests','API broker only belongs to host lane')
                            if api is None:
                                env=message['environment'];require(isinstance(env,dict) and all(isinstance(k,str) and isinstance(v,str) and len(v)<=8192 for k,v in env.items()),'Invalid API environment')
                                joined(Path(owner.run['checkout']),env,owner.run['lane'])
                                executable=shutil.which('dotnet',path=env.get('PATH'));require(executable,'Host SDK missing')
                                env,assembly=owner.proof.prepare(env)
                                process=owner.launch('host-api',[executable,str(assembly),'--urls','http://127.0.0.1:5001'],env)
                                api=next((p,r) for p,r in owner.children if p is process)
                            response=dict(exit_code=0,pid=api[0].pid)
                        elif operation=='api-status':
                            if api is None:response=dict(exit_code=1)
                            else:
                                value=json.loads(Path(api[1]['state']).read_text());code=value.get('exit_code',1) or 1
                                response=dict(exit_code=0 if value['status'] in ['Starting','Ready','Running'] else code)
                        elif operation=='api-ready':
                            failure=owner.proof.tick();response=dict(exit_code=failure or (0 if owner.proof.ready else 75))
                        elif operation=='api-proof':response=dict(exit_code=owner.proof.finish())
                        elif operation=='api-stop':
                            owner.proof.stop_requested=True
                            response=dict(exit_code=0 if api is None or stop_record(api[1],Deadline(8),api[0]) else 1)
                        else:raise ValueError('Unknown control operation')
                    self.request.sendall((json.dumps(response)+'\n').encode())
                except (OSError,ValueError,KeyError,subprocess.SubprocessError):
                    try:self.request.sendall(b'{"exit_code":1}\n')
                    except OSError:pass
        self.server=socketserver.ThreadingTCPServer(('127.0.0.1',0),Handler);self.server.daemon_threads=True
        self.thread=threading.Thread(target=lambda:self.server.serve_forever(poll_interval=.05),daemon=True);self.thread.start()
        return str(self.server.server_address[1])
    def stop(self,deadline):
        self.closing=True;failures=[]
        if not self.lock.acquire(timeout=max(0,deadline.end-time.monotonic())):return ['process-control-busy']
        try:children=list(self.children)
        finally:self.lock.release()
        for process,record in reversed(children):
            try:
                if not stop_record(record,deadline,process):failures.append(record['role'])
                elif process.poll() is None:process.wait(timeout=deadline.left(.5))
            except (OSError,ValueError,subprocess.SubprocessError):failures.append(record['role'])
        if self.server:
            self.server.shutdown();self.server.server_close();self.thread.join(timeout=min(1,max(0,deadline.end-time.monotonic())))
        for thread in self.log_threads:thread.join(timeout=min(.1,max(0,deadline.end-time.monotonic())))
        return failures

def api_control(operation):
    run=joined(ROOT,os.environ,'docker-host-system-stack-tests')
    message=dict(token=run['token'],operation=operation)
    if operation=='api-start':message['environment']=dict(os.environ)
    while True:
        with socket.create_connection(('127.0.0.1',int(os.environ['TREEHAMMOCK_TEST_PROCESS_BROKER_PORT'])),timeout=12) as connection:
            connection.sendall((json.dumps(message)+'\n').encode());value=b''
            while not value.endswith(b'\n'):
                chunk=connection.recv(4096);require(chunk,'Process control ended early');value+=chunk;require(len(value)<=16384,'Process response too large')
            response=json.loads(value)
        if operation=='api-ready' and response['exit_code']==75:time.sleep(.05);continue
        if operation=='api-start' and response['exit_code']==0:print(response['pid'])
        return response['exit_code']

def pump_output(process,run):
    pump_stream(process.stdout,run,Path(run['artifacts'])/'runner.log',True)

def pump_stream(stream,run,path,echo):
    values=redactions(run);limit=1048576;pending=b'';written=0
    try:
        with path.open('w') as log:
            while True:
                data=stream.read(4096)
                if not data:break
                pending+=data
                while b'\n' in pending or len(pending)>65536:
                    line,separator,rest=pending.partition(b'\n')
                    if not separator:
                        safe_pending=redact(pending.decode(errors='replace'),values)
                        overlap=max([len(value) for value in values]+[1]);cut=len(safe_pending)-overlap
                        line=safe_pending[:cut].encode();rest=safe_pending[cut:].encode()
                    pending=rest;safe=redact((line+(b'\n' if separator else b'')).decode(errors='replace'),values)
                    if written<limit:
                        output=safe[:limit-written];log.write(output);written+=len(output)
                        if echo:print(output,end='',flush=True)
            if pending and written<limit:log.write(redact(pending.decode(errors='replace'),values)[:limit-written])
    except (OSError,ValueError):run['output_failed']=True
    finally:stream.close()

def execute(root,lane,entry,shell,args,environment):
    arguments(lane,args);require(Path(entry).name in (lane+'.sh',lane+'.ps1'),'Entry does not match lane')
    startup_deadline=Deadline(hostproof.startup_seconds(environment)) if lane=='docker-host-system-stack-tests' else None
    cleanup_seconds=budget(environment);retain=environment.get('TREEHAMMOCK_TEST_RETAIN_FAILED_RESOURCES','false');require(retain in ['true','false'],'Invalid retained-debug setting')
    if lane=='docker-host-system-stack-tests':
        try:environment=prerequisites.check(root,entry,shell,environment,startup_deadline)
        except prerequisites.Failure as error:
            print(str(error),file=sys.stderr);return error.code
    run=None;lease=HostLease(environment);lock=None;lifecycle=None;primary=0;clean={'status':'NotRequired'};process=None;previous={};cancelled=0;pump=None
    def interrupted(number,frame):
        nonlocal cancelled
        cancelled=cancelled or 128+number
    def prepared(value):
        nonlocal run,lock
        run=value;lock=RunLock(run);lock.acquire()
    for number in [signal.SIGINT,signal.SIGTERM,*([signal.SIGBREAK] if os.name=='nt' else [])]:previous[number]=signal.signal(number,interrupted)
    try:
        create_run(root,lane,environment,on_created=prepared)
        if cancelled:raise InterruptedError('Acquisition interrupted')
        pin_context(run,startup_deadline);child=run_environment(run,environment)
        if lane=='docker-host-system-stack-tests':
            require(not child.get('WSL_DISTRO_NAME') and not child.get('WSL_INTEROP'),'Fixed-port host lease requires native host')
            fixture.check_host('host',child);lease.acquire()
        run['status']='Running';write(manifest(run),run);lifecycle=Lifecycle(run,startup_deadline)
        if lane=='docker-host-system-stack-tests':child['TREEHAMMOCK_TEST_PROCESS_BROKER_PORT']=lifecycle.start_broker()
        if lane!='docker-unit-tests':
            graph=json.loads(docker(run,compose(run,lane=='docker-host-system-stack-tests')+['config','--format','json'],timeout=startup_deadline.left() if startup_deadline else 60).stdout);validate_graph(run,graph,lane=='docker-host-system-stack-tests')
            write(Path(run['artifacts'])/'rendered-ownership.json',dict(project=run['project'],labels=labels(run),services=sorted(graph['services']),volumes=sorted(graph.get('volumes',{})),networks=sorted(graph.get('networks',{}))))
        command=[shell,str(Path(run['checkout'])/'eng'/Path(entry).name),*args]
        if entry.endswith('.ps1'):command=[shell,'-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',str(Path(run['checkout'])/'eng'/Path(entry).name),*args]
        if startup_deadline:startup_deadline.left()
        if cancelled:raise InterruptedError('Startup interrupted')
        process=lifecycle.launch('wrapper',command,child);pump=threading.Thread(target=pump_output,args=(process,run),daemon=True);pump.start()
        while process.poll() is None and not cancelled:
            if lifecycle.proof:
                failure=lifecycle.proof.tick()
                if failure:primary=failure;break
            time.sleep(.03)
        if cancelled:primary=cancelled
        elif not primary:
            code=process.returncode;primary=128-code if code<0 else code
            if primary==0 and lifecycle.proof and (not lifecycle.proof.completed or lifecycle.proof.failure_code):primary=lifecycle.proof.failure_code or 1
    except (OSError,ValueError,KeyError,subprocess.SubprocessError):primary=primary or cancelled or (124 if startup_deadline and time.monotonic()>=startup_deadline.end else 2)
    finally:
        deadline=Deadline(cleanup_seconds)
        if run is not None:
            try:process_failures=lifecycle.stop(deadline) if lifecycle else []
            except (OSError,ValueError,KeyError,subprocess.SubprocessError):process_failures=['process-cleanup']
            if pump:pump.join(timeout=min(1,max(0,deadline.end-time.monotonic())))
            try:clean=cleanup(run,deadline,retain=primary!=0 and retain=='true')
            except (OSError,ValueError,KeyError,subprocess.SubprocessError):clean=dict(status='Failed',failures=['cleanup-diagnostics'])
            run['retained_resources']=bool(clean.get('retained'))
            if process_failures:clean['status']='Failed';clean['process_failures']=process_failures
            if clean['status']=='Failed' and primary==0:primary=1
            if run.get('output_failed') and primary==0:primary=1
            lease.release();run['status']='Completed' if clean['status']=='Passed' else clean['status'];run['exit_code']=primary
            try:write(manifest(run),run);report(run,primary,clean)
            except (OSError,ValueError,KeyError):
                primary=primary or 1;run['status']='DiagnosticsFailed';run['exit_code']=primary
                try:write(manifest(run),run)
                except (OSError,ValueError):pass
                print('Owned run diagnostics could not be saved; initiating failure retained.',file=sys.stderr)
        lease.release()
        if lock:lock.release()
        for number,handler in previous.items():signal.signal(number,handler)
    if run:print('Owned test run '+run['id']+'; results: '+run['artifacts'])
    return primary

def alive(pid):
    try:os.kill(pid,0);return True
    except ProcessLookupError:return False
    except PermissionError:return True
def recover(root,run_id,environment,discard_retained=False):
    require(str(uuid.UUID(run_id))==run_id,'Noncanonical recovery identity')
    path=root/'.docker/test-runs'/run_id/'ownership.json';run=json.loads(path.read_text());validate_run(run,path,inputs=False)
    require(run['source']==str(root.resolve()),'Recovery source differs')
    lock=RunLock(run)
    try:
        lock.acquire()
        require(not alive(run['pid']) or run.get('pid_identity') and processes.identity(run['pid'])!=run['pid_identity'],'Active coordinator still owns this run')
        require(not (run['status']=='RetainedDebug' or run.get('retained_resources')) or discard_retained,'Retained debug state requires explicit discard')
        deadline=Deadline(budget(environment));failures=[]
        for record in reversed(run.get('processes',[])):
            require(record.get('role') in ['wrapper','host-api'] and isinstance(record.get('pid'),int) and record['pid']>0 and bool(record.get('identity')),'Invalid process receipt')
            name=Path(record['state']).name
            require(re.fullmatch(r'[0-9a-f]{32}\.state\.json',name),'Invalid receipt identity')
            for key,suffix in [('state','.state.json'),('request','.request.json'),('gate','.release.json')]:
                require(Path(record[key])==path.parent/(name.removesuffix('.state.json')+suffix) and not fixture.linked(Path(record[key])),'Unowned process receipt')
            try:
                if not stop_record(record,deadline):failures.append(record['role'])
            except (OSError,ValueError,subprocess.SubprocessError):failures.append(record['role'])
        result=cleanup(run,deadline)
        if failures:result['status']='Failed';result['process_failures']=failures
        write(Path(run['artifacts'])/'recovery.json',dict(run_id=run_id,status=result['status'],process_failures=failures))
        run['recovery_status']=result['status'];write(path,run)
        return 0 if result['status']=='Passed' else 1
    finally:lock.release()
def cleanup_ci(root,environment):
    identity=ci_identity(environment);require(identity,'CI cleanup requires exact current job identity');failed=False
    for path in sorted((root/'.docker/test-runs').glob('*/ownership.json')):
        try:
            run=json.loads(path.read_text());validate_run(run,path,inputs=False)
            if run['source']!=str(root.resolve()) or run['ci_identity']!=identity:continue
            require(not alive(run['pid']) or run.get('pid_identity') and processes.identity(run['pid'])!=run['pid_identity'],'Active coordinator still owns this run')
            failed|=recover(root,run['id'],environment)!=0
        except (OSError,ValueError,KeyError,subprocess.SubprocessError):failed=True
    return 1 if failed else 0

def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
    run=sub.add_parser('run');run.add_argument('--lane',choices=LANES,required=True);run.add_argument('--entry',required=True);run.add_argument('--shell',required=True);run.add_argument('args',nargs=argparse.REMAINDER)
    verify=sub.add_parser('verify');verify.add_argument('--lane',choices=LANES,required=True);verify.add_argument('args',nargs=argparse.REMAINDER)
    sub.add_parser('cleanup-ci')
    for operation in ['api-start','api-status','api-stop','api-ready','api-proof']:sub.add_parser(operation)
    recovery=sub.add_parser('recover');recovery.add_argument('--run',required=True);recovery.add_argument('--discard-retained',action='store_true')
    args=parser.parse_args()
    try:
        if args.command=='verify':
            arguments(args.lane,args.args[1:] if args.args[:1]==['--'] else args.args);joined(ROOT,os.environ,args.lane);return 0
        if args.command=='cleanup-ci':return cleanup_ci(ROOT,os.environ)
        if args.command=='recover':return recover(ROOT,args.run,os.environ,args.discard_retained)
        if args.command.startswith('api-'):return api_control(args.command)
        return execute(ROOT,args.lane,args.entry,args.shell,args.args[1:] if args.args[:1]==['--'] else args.args,dict(os.environ))
    except (OSError,ValueError,KeyError,subprocess.SubprocessError):print('Owned fixture prerequisites or ownership validation failed.',file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
