#!/usr/bin/env python3
"""Host assembly/process/HTTP identity and fresh System results. No native success inferred."""
from contextlib import closing
import hashlib,http.client,json,os,re,secrets,socket,threading,time,uuid
from pathlib import Path
import xml.etree.ElementTree as ET
DIRECT='http://127.0.0.1:5001';PROXY='http://127.0.0.1:8080'
DEPENDENCIES={'postgresql','dragonfly_active_sessions','dragonfly_two_factor_sessions','dragonfly_abuse_counters'}
class ProofError(ValueError):pass
class Unavailable(OSError):pass
def require(value,message):
    if not value:raise ProofError(message)
def canonical(value):return isinstance(value,str) and str(uuid.UUID(value))==value
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def startup_seconds(environment):
    value=int(environment.get('TREEHAMMOCK_HOST_STARTUP_TIMEOUT_SECONDS','600'));require(1<=value<=1800,'Host startup budget must be 1 to 1800 seconds');return value
def expected_tests(root):
    index=json.loads((root/'docs/corrections/APPLICATION_SURFACE_INDEX.json').read_text())
    # The System project links the shared BuildIdentityProbe Fact too.
    paths={'treehammock.Tests/Infrastructure/BuildIdentity.cs'}
    rows=[row for row in index['attributed_test_methods'] if row['path'].startswith('treehammock.Tests.System/') or row['path'] in paths]
    require(rows and all(row['attribute']=='Fact' for row in rows),'Unsupported System discovery contract')
    names=[row['method'] for row in rows];require(len(names)==len(set(names)),'Ambiguous System method inventory');return set(names)
def validate_trx(path,expected):
    data=path.read_bytes();require(len(data)<=4000000 and b'<!DOCTYPE' not in data.upper() and b'<!ENTITY' not in data.upper(),'Unbounded or external TRX declarations')
    root=ET.fromstring(data);ns={'t':'http://microsoft.com/schemas/VisualStudio/TeamTest/2010'}
    counts=root.findall('.//t:Counters',ns);require(len(counts)==1,'Missing/ambiguous TRX counters');counts=counts[0].attrib
    require(all(int(counts.get(k,-1))==len(expected) for k in ['total','executed','passed']) and all(int(counts.get(k,-1))==0 for k in ['failed','notExecuted']),'Incomplete System test discovery/results')
    rows=root.findall('.//t:UnitTestResult',ns);require(len(rows)==len(expected) and all(row.get('outcome')=='Passed' for row in rows),'Failed/missing System results')
    ids=[row.get('executionId') for row in rows];require(all(ids) and len(set(ids))==len(ids),'Duplicate/missing System executions')
    names=[row.get('testName','').split('(')[0].split('.')[-1] for row in rows]
    require(set(names)==expected and len(set(names))==len(names),'Wrong System test inventory')
    return dict(executed_tests=len(rows),result_sha256=hashlib.sha256(data).hexdigest())

def fetch(url,path,key,timeout):
    # Literal loopback only: ignore ambient HTTP proxy/DNS; never redirect or echo bodies.
    require(url in [DIRECT,PROXY],'Unowned proof endpoint')
    port=5001 if url==DIRECT else 8080
    end=time.monotonic()+timeout
    with closing(http.client.HTTPConnection('127.0.0.1',port,timeout=timeout)) as connection:
        connection.connect();transport=connection.sock
        def abort():
            try:transport.shutdown(socket.SHUT_RDWR)
            except OSError:pass
        timer=threading.Timer(max(.001,end-time.monotonic()),abort);timer.daemon=True;timer.start()
        try:
            return receive(connection,path,key,end)
        finally:timer.cancel()

def receive(connection,path,key,end):
    connection.request('GET',path,headers={'X-System-Test-Key':key,'Cache-Control':'no-store','Connection':'close'})
    response=connection.getresponse()
    try:
        if response.status in [502,503,504]:raise Unavailable('Owned endpoint not ready')
        require(response.status==200,'Owned endpoint rejected identity/health')
        data=response.read(16385);require(len(data)<=16384,'Oversized identity/health response')
        require(time.monotonic()<end,'HTTP proof exceeded its attempt budget')
        value=json.loads(data);require(isinstance(value,dict),'Invalid identity/health response');return value
    finally:response.close()

class HostProof:
    def __init__(self,owner,deadline):
        self.owner=owner;self.run=owner.run;self.deadline=deadline;self.lock=threading.RLock();self.artifact=None;self.ready=False;self.completed=False;self.stop_requested=False;self.failure_code=0;self.next_probe=0;self.process_birth=None;self.runtime=None;self.last_contact=None
    def fail(self,code,stage):
        if not self.failure_code:
            self.failure_code=code or 1;self.run['host_proof_failure']=stage
            self.owner.write(self.owner.manifest(self.run),self.run)
        return self.failure_code
    def prepare(self,environment):
        with self.lock:
            require(self.artifact is None,'Host API already has a launch identity')
            run_id=environment.get('TREEHAMMOCK_BUILD_RUN_ID');require(canonical(run_id) and environment.get('TREEHAMMOCK_BUILD_CONFIGURATION')=='Release','Invalid host build identity')
            root=Path(self.run['checkout']);app=root/'bin/Release/net8.0/treehammock.dll';tests=root/'treehammock.Tests.System/bin/Release/net8.0/treehammock.Tests.System.dll';copy=tests.parent/'treehammock.dll'
            for binary,name in [(app,'treehammock'),(tests,'treehammock.Tests.System')]:
                require(not self.owner.fixture.linked(binary) and binary.is_file(),'Missing/linked current host binary')
                marker=binary.with_name(binary.name+'.proof-id');require(not self.owner.fixture.linked(marker) and marker.read_text().strip()==run_id+'|Release|'+name+'|net8.0','Host output belongs to another build')
            require(not self.owner.fixture.linked(copy) and sha(copy)==sha(app),'System tests reference a different application binary')
            require(environment.get('TREEHAMMOCK_SYSTEM_BASE_URL')==PROXY,'System test target differs from verified proxy')
            key=dict(line.split('=',1) for line in Path(self.run['credential_file']).read_text().splitlines())['TREEHAMMOCK_FIXTURE_TEST_KEY']
            require(environment.get('SystemTestSettings__TestKey')==key and environment.get('SystemTestSettings__Enabled')=='true' and environment.get('SystemTestSettings__EnableTestInspectionEndpoints')=='true' and environment.get('ASPNETCORE_ENVIRONMENT')=='Testing' and environment.get('DOTNET_ENVIRONMENT')=='Testing','Host proof requires the owned Testing capability')
            challenge=secrets.token_hex(32)
            self.artifact=dict(run_id=self.run['id'],build_run_id=run_id,configuration='Release',assembly_sha256=sha(app),test_sha256=sha(tests),assembly=str(app),tests=str(tests),challenge=challenge)
            self.run['host_artifact']=self.artifact;self.key=key
            for path in [Path(self.run['artifacts'])/'host/treehammock-system-host-tests.trx',tests.parent/'treehammock.Tests.System.identity.json']:
                require(not self.owner.fixture.linked(path) and not path.exists(),'Host proof cannot reuse existing result receipts')
            self.owner.write(self.owner.manifest(self.run),self.run)
            child=dict(environment,ASPNETCORE_CONTENTROOT=self.run['checkout'],ASPNETCORE_URLS=DIRECT)
            for name,value in [('RunId',self.run['id']),('BuildRunId',run_id),('AssemblySha256',self.artifact['assembly_sha256']),('Challenge',challenge)]:child['HostSystemTestProof__'+name]=value
            return child,app
    def actor(self):
        api=next(((p,r) for p,r in self.owner.children if r['role']=='host-api'),None)
        if api is None:return None
        process,record=api
        if process.poll() is not None or self.owner.processes.identity(record['pid'])!=record['identity']:raise ProofError('Owned API supervisor exited')
        value=json.loads(Path(record['state']).read_text());status=value.get('status')
        if status in ['Starting','Ready']:return None
        if status!='Running':
            self.fail(value.get('exit_code') or 1,'api-exited');raise ProofError('Owned API exited')
        birth=self.owner.processes.identity(value['pid'])
        if birth is None:raise Unavailable('Awaiting supervised API exit outcome')
        require(birth==value.get('identity'),'Owned API process changed')
        if self.process_birth is not None:require((value['pid'],birth)==self.process_birth,'Owned API process was replaced')
        self.process_birth=(value['pid'],birth);return value['pid']
    def inspect(self):
        pid=self.actor()
        if pid is None:raise Unavailable('Owned API has not started')
        values=[]
        for url in [DIRECT,PROXY]:
            timeout=min(.5,max(.001,self.deadline.end-time.monotonic())) if not self.ready else .5
            value=fetch(url,'/__system-test/identity',self.key,timeout)
            for name in ['run_id','build_run_id','configuration','assembly_sha256','challenge']:require(value.get(name)==self.artifact[name],'Host identity mismatch')
            require(type(value.get('process_id')) is int and value['process_id']==pid and canonical(value.get('mvid')),'Host process/module mismatch')
            values.append(value)
        require(values[0]==values[1],'Proxy reaches another application')
        if self.runtime is not None:require(values[0]==self.runtime,'Running host identity changed')
        for url in [DIRECT,PROXY]:
            health=fetch(url,'/health/ready',self.key,min(.5,max(.001,self.deadline.end-time.monotonic())) if not self.ready else .5)
            require(health.get('status')=='ready','Invalid owned readiness status')
            dependencies=health.get('dependencies',[]);require(isinstance(dependencies,list) and {row.get('name') for row in dependencies if isinstance(row,dict) and row.get('status')=='healthy'}>=DEPENDENCIES,'Backing state is not healthy')
        require(self.actor()==pid,'API exited during identity probes')
        self.runtime=values[0];self.last_contact=time.monotonic()
    def tick(self):
        with self.lock:
            if self.failure_code:return self.failure_code
            if self.stop_requested:return 0
            if not self.ready and time.monotonic()>=self.deadline.end:return self.fail(124,'startup-budget')
            if self.artifact is None:return 0
            try:
                self.actor()
                if time.monotonic()<self.next_probe:return 0
                self.next_probe=time.monotonic()+.5;self.inspect()
                if not self.ready:
                    require(time.monotonic()<self.deadline.end,'Startup proof arrived after deadline')
                    self.ready=True;self.run['host_runtime']={k:v for k,v in self.runtime.items() if k!='challenge'}
                    self.owner.write(self.owner.manifest(self.run),self.run)
                    self.owner.write(Path(self.run['artifacts'])/'host/identity.json',dict(status='Ready',direct=DIRECT,proxy=PROXY,identity=self.run['host_runtime']))
            except (ConnectionError,TimeoutError,Unavailable):
                if not self.ready and time.monotonic()>=self.deadline.end:return self.fail(124,'startup-budget')
                if self.ready and self.last_contact is not None and time.monotonic()-self.last_contact>=2:return self.fail(1,'endpoint-unavailable')
            except (OSError,ValueError,KeyError,TypeError,http.client.HTTPException):return self.fail(self.failure_code or (124 if not self.ready and time.monotonic()>=self.deadline.end else 1),'identity-or-process')
            return self.failure_code
    def finish(self):
        with self.lock:
            require(self.ready and not self.failure_code and not self.stop_requested,'Host tests ran without current readiness')
            self.inspect();root=Path(self.run['checkout']);tests=Path(self.artifact['tests']);app=Path(self.artifact['assembly'])
            require(sha(tests)==self.artifact['test_sha256'] and sha(app)==self.artifact['assembly_sha256'],'Host binaries changed during tests')
            receipt=tests.parent/'treehammock.Tests.System.identity.json';trx=Path(self.run['artifacts'])/'host/treehammock-system-host-tests.trx'
            for path in [receipt,trx]:require(not self.owner.fixture.linked(path) and path.is_file(),'Fresh host proof output missing')
            identity=json.loads(receipt.read_text());require(identity.get('run_id')==self.artifact['build_run_id'] and identity.get('configuration')=='Release','System assemblies came from a different build')
            binaries=identity.get('assemblies',[]);require(len(binaries)==2,'Incomplete loaded assembly identity')
            byname={row['name']:row for row in binaries};require(set(byname)=={'treehammock','treehammock.Tests.System'},'Unexpected loaded assemblies')
            for name,path in [('treehammock',tests.parent/'treehammock.dll'),('treehammock.Tests.System',tests)]:
                row=byname[name];require(Path(row['path'])==path and row['sha256']==sha(path) and canonical(row['mvid']),'Wrong loaded System assembly')
            require(byname['treehammock']['mvid']==self.runtime['mvid'],'Tested application module differs from the launched module')
            result=validate_trx(trx,expected_tests(root));self.inspect()
            self.owner.write(Path(self.run['artifacts'])/'host/proof.json',dict(status='Passed',run_id=self.run['id'],build_run_id=self.artifact['build_run_id'],identity=self.run['host_runtime'],**result))
            self.completed=True;return 0
