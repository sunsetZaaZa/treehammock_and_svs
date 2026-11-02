"""Actual Node HTTP deadlines and shell/controlled-command lanes; no SDK substitution claim."""
import importlib.util,json,os
from pathlib import Path
import shutil,socket,subprocess,sys,tempfile,threading,time,unittest
import uuid,xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parents[2]
NODE=shutil.which('node')
spec=importlib.util.spec_from_file_location('compose_guard',ROOT/'eng/check-compose-proof.py');guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard)

@unittest.skipUnless(NODE,'Node runtime unavailable')
class HttpLaneTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.folder=Path(self.temp.name);self.collection=self.folder/'collection';shutil.copytree(ROOT/'tests/http/bruno/treehammock',self.collection)
        self.server=socket.socket();self.server.bind(('127.0.0.1',0));self.server.listen();self.server.settimeout(.1);self.base='http://127.0.0.1:'+str(self.server.getsockname()[1]);self.closed=threading.Event();self.connections=[];self.mode='ready'
        def serve():
            while not self.closed.is_set():
                try:
                    connection,_=self.server.accept();self.connections.append(connection)
                    if self.mode=='ready':connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}');connection.close()
                    elif self.mode=='unready':connection.sendall(b'HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');connection.close()
                    elif self.mode=='partial':connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nx')
                except (socket.timeout,OSError):pass
        self.thread=threading.Thread(target=serve);self.thread.start()
        binary=self.folder/'bin';binary.mkdir();self.trace=self.folder/'calls.jsonl'
        npm=binary/'npm';npm.write_text('#!'+sys.executable+'''\nimport json,os,pathlib,sys
with open(os.environ['TRACE'],'a') as f:f.write(json.dumps(['npm',*sys.argv[1:]])+'\\n')
if os.environ.get('FAIL_INSTALL'):sys.exit(47)
prefix=pathlib.Path(sys.argv[sys.argv.index('--prefix')+1]);tool=prefix/'node_modules/.bin/bru';tool.parent.mkdir(parents=True)
tool.write_text('#!'+sys.executable+'\\n'+os.environ['BRU_PROGRAM']);tool.chmod(0o755)
''');npm.chmod(0o755)
        self.env=dict(os.environ,PATH=str(binary)+os.pathsep+os.environ['PATH'],TRACE=str(self.trace),TREEHAMMOCK_BASE_URL=self.base,TREEHAMMOCK_COMPOSE_READY_TIMEOUT_MS='350',TREEHAMMOCK_COMPOSE_ATTEMPT_TIMEOUT_MS='100')
        names=['live endpoint returns HTTP 200','live endpoint reports live status','ready endpoint returns HTTP 200','ready endpoint reports ready status']
        self.data=[dict(summary=dict(failedRequests=0,failedTests=0,failedAssertions=0,skippedRequests=0),results=[dict(testResults=[dict(description=n,status='pass') for n in names])])]
        self.env['BRU_PROGRAM']='''import json,os,pathlib,sys
with open(os.environ['TRACE'],'a') as f:f.write(json.dumps(['bru',*sys.argv[1:]])+'\\n')
if os.environ.get('FAIL_TESTS'):sys.exit(53)
if not os.environ.get('NO_REPORT'):pathlib.Path(sys.argv[sys.argv.index('--reporter-json')+1]).write_text(os.environ['REPORT'])
'''
        self.env['REPORT']=json.dumps(self.data);self.reports=self.folder/'reports'
    def tearDown(self):
        self.closed.set();self.thread.join(timeout=2);self.server.close()
        for connection in self.connections:
            try:connection.close()
            except OSError:pass
        self.temp.cleanup()
    def invoke(self):
        start=time.monotonic();result=subprocess.run([NODE,str(ROOT/'eng/compose-http-proof.mjs'),'direct',str(self.collection),str(self.reports)],env=self.env,capture_output=True,text=True,timeout=8)
        self.assertLess(time.monotonic()-start,3);states=[json.loads(p.read_text()) for p in self.reports.glob('*/run.json')];return result,states[-1]
    def test_success_requires_expected_fresh_executed_tests(self):
        result,state=self.invoke();self.assertEqual(result.returncode,0);self.assertEqual(state['status'],'Passed');self.assertTrue(list(self.reports.glob('*/proof.json')))
    def test_hung_no_header_response_hits_total_deadline(self):
        self.mode='hung';result,state=self.invoke();self.assertEqual(result.returncode,2);self.assertEqual(state['stage'],'readiness');self.assertFalse(self.trace.exists())
    def test_partial_body_with_200_cannot_hang_or_report_ready(self):
        self.mode='partial';result,state=self.invoke();self.assertEqual(result.returncode,2);self.assertEqual(state['stage'],'readiness')
    def test_readiness_failure_stops_before_install(self):
        self.mode='unready';result,state=self.invoke();self.assertEqual(result.returncode,2);self.assertFalse(self.trace.exists())
    def test_install_exit_survives_and_stops_tests(self):
        self.env['FAIL_INSTALL']='true';result,state=self.invoke();self.assertEqual(result.returncode,47);self.assertEqual(state['exit_code'],47);self.assertEqual(state['stage'],'install');self.assertEqual(len(self.trace.read_text().splitlines()),1)
    def test_failed_tests_retain_exit_before_validation(self):
        self.env['FAIL_TESTS']='true';result,state=self.invoke();self.assertEqual(result.returncode,53);self.assertEqual(state['stage'],'tests');self.assertFalse(list(self.reports.glob('*/proof.json')))
    def test_collection_validation_stops_before_readiness_or_install(self):
        (self.collection/'bruno.json').unlink();result,state=self.invoke();self.assertEqual(result.returncode,2);self.assertEqual(state['stage'],'collection');self.assertFalse(self.trace.exists())
    def test_missing_report_cannot_reuse_stale_success(self):
        self.assertEqual(self.invoke()[0].returncode,0);self.env['NO_REPORT']='true';result,state=self.invoke();self.assertEqual(result.returncode,2);self.assertEqual(state['stage'],'result-validation');self.assertEqual(len(list(self.reports.glob('*/run.json'))),2)
    def test_zero_discovery_rejected(self):
        self.env['REPORT']='[]';self.assertEqual(self.invoke()[0].returncode,2)
    def test_skipped_failed_duplicate_or_wrong_tests_rejected(self):
        for change in ['skip','fail','duplicate','wrong']:
            data=json.loads(json.dumps(self.data));tests=data[0]['results'][0]['testResults']
            if change=='duplicate':tests[1]=tests[0]
            elif change=='wrong':tests[0]['description']='wrong method'
            else:tests[0]['status']=change
            self.env['REPORT']=json.dumps(data)
            with self.subTest(change=change):self.assertEqual(self.invoke()[0].returncode,2)
    def test_hidden_request_failure_rejected(self):
        self.data[0]['summary']['failedRequests']=1;self.env['REPORT']=json.dumps(self.data);self.assertEqual(self.invoke()[0].returncode,2)
    def test_invalid_deadline_configuration_rejected(self):
        self.env['TREEHAMMOCK_COMPOSE_READY_TIMEOUT_MS']='0';self.assertEqual(self.invoke()[0].returncode,2);self.assertFalse(self.trace.exists())

class SystemShellStages(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'source';(self.root/'eng/ComposeProofProbe').mkdir(parents=True)
        for name in ['compose-system-proof.sh','build-identity.sh']:shutil.copy2(ROOT/'eng'/name,self.root/'eng'/name)
        for p in (ROOT/'eng/ComposeProofProbe').iterdir():shutil.copy2(p,self.root/'eng/ComposeProofProbe'/p.name)
        self.bin=Path(self.temp.name)/'bin';self.bin.mkdir();self.trace=Path(self.temp.name)/'trace.jsonl';self.reports=Path(self.temp.name)/'reports'
        tool=self.bin/'dotnet';tool.write_text('#!'+sys.executable+'''\nimport json,os,pathlib,sys
args=sys.argv[1:];stage=('readiness' if '--ready' in args else 'validation' if '--trx' in args else args[0])
with open(os.environ['TRACE'],'a') as f:f.write(json.dumps(stage)+'\\n')
if stage==os.environ.get('FAIL_STAGE'):sys.exit(47)
if stage=='validation':print('{"status":"Passed","kind":"controlled SDK response, not native TRX proof"}')
''');tool.chmod(0o755)
        scratch=Path(self.temp.name)/'scratch';scratch.mkdir()
        self.env=dict(os.environ,PATH=str(self.bin)+os.pathsep+os.environ['PATH'],TRACE=str(self.trace),TMPDIR=str(scratch),TREEHAMMOCK_SYSTEM_BASE_URL='http://owned-fixture',TREEHAMMOCK_COMPOSE_REPORT_ROOT=str(self.reports))
    def tearDown(self):self.temp.cleanup()
    def invoke(self):return subprocess.run(['bash',str(self.root/'eng/compose-system-proof.sh')],cwd=self.root,env=self.env,capture_output=True,text=True,timeout=10)
    def test_readiness_restore_build_test_and_validation_failures_stop_later_work(self):
        order=['publish','readiness','restore','build','test','validation']
        for failed in order:
            self.trace.unlink(missing_ok=True);self.env['FAIL_STAGE']=failed
            with self.subTest(stage=failed):
                result=self.invoke();self.assertEqual(result.returncode,47);self.assertEqual([json.loads(x) for x in self.trace.read_text().splitlines()],order[:order.index(failed)+1])
    def test_failed_restore_survives_owned_tool_cleanup_failure(self):
        rm=self.bin/'rm';rm.write_text('#!/bin/sh\nexit 63\n');rm.chmod(0o755);self.env['FAIL_STAGE']='restore'
        self.assertEqual(self.invoke().returncode,47)
    def test_shell_success_is_supplemental_control_flow_only(self):self.assertEqual(self.invoke().returncode,0)

class ComposeWiringTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'source';shutil.copytree(ROOT,self.root,ignore=shutil.ignore_patterns('.git','.docker','bin','obj','artifacts','.artifacts','.correction-results','TestResults','__pycache__'))
    def tearDown(self):self.temp.cleanup()
    def reject(self,file,before,after):
        p=self.root/file;s=p.read_text();self.assertIn(before,s);p.write_text(s.replace(before,after,1))
        with self.assertRaises(ValueError):guard.validate(self.root)
    def test_consistency_is_not_native_qualification(self):self.assertEqual(guard.validate(self.root)['qualification'],'NotRun')
    def test_inline_http_shell_cannot_bypass_proof(self):self.reject('docker-compose.integration.yml','/work/eng/compose-http-proof.mjs','/work/old-proof.mjs')
    def test_system_shell_must_be_fail_fast(self):self.reject('eng/compose-system-proof.sh','set -euo pipefail','set -u')
    def test_fresh_system_results_required(self):self.reject('eng/compose-system-proof.sh','mkdir "$lane_run"','mkdir -p "$lane_run"')
    def test_native_expected_discovery_required(self):self.reject('eng/ComposeProofProbe/Program.cs','observed.SetEquals(expected)','true')
    def test_http_active_request_must_be_aborted(self):self.reject('eng/compose-http-proof.mjs','request?.destroy()','void request')


def current_system_inventory():
    index=json.loads((ROOT/'docs/corrections/APPLICATION_SURFACE_INDEX.json').read_text())
    project=ROOT/'treehammock.Tests.System/treehammock.Tests.System.csproj'
    linked={(project.parent/item.attrib['Include'].replace('\\','/')).resolve().relative_to(ROOT).as_posix()
            for item in ET.parse(project).findall('.//Compile') if 'Include' in item.attrib}
    rows=[row for row in index['attributed_test_methods']
          if row['path'].startswith('treehammock.Tests.System/') or row['path'] in linked]
    return rows,linked


def system_fixture_trx(rows):
    ns='http://microsoft.com/schemas/VisualStudio/TeamTest/2010'
    root=ET.Element('TestRun',xmlns=ns);results=ET.SubElement(root,'Results')
    for row in rows:ET.SubElement(results,'UnitTestResult',row)
    summary=ET.SubElement(root,'ResultSummary')
    ET.SubElement(summary,'Counters',total=str(len(rows)),executed=str(len(rows)),passed=str(len(rows)),failed='0',notExecuted='0')
    return ET.tostring(root,encoding='utf-8')


class SystemInventoryTests(unittest.TestCase):
    """Current compile/index consistency and synthetic host-validator checks, not System execution."""
    def test_all_current_compiled_attributed_sources_include_linked_identity(self):
        spec=importlib.util.spec_from_file_location('host_inventory',ROOT/'eng/host-system-proof.py')
        host=importlib.util.module_from_spec(spec);spec.loader.exec_module(host)
        rows,linked=current_system_inventory()
        self.assertIn('treehammock.Tests/Infrastructure/BuildIdentity.cs',linked)
        self.assertTrue(rows and all(row['attribute']=='Fact' for row in rows))
        names=[row['method'] for row in rows]
        self.assertEqual(len(names),len(set(names)))
        self.assertEqual(set(names),host.expected_tests(ROOT))
        self.assertIn('Loaded_test_and_application_share_the_requested_configuration',names)
        # Source witness supplements the actual compiled probe tests below.
        probe=(ROOT/'eng/ComposeProofProbe/Program.cs').read_text()
        for path in {row['path'] for row in rows if row['path'] in linked}:
            self.assertIn('== "'+path+'"',probe)
    def test_full_current_host_trx_oracle_includes_shared_fact_and_rejects_bad_rows(self):
        spec=importlib.util.spec_from_file_location('host_trx',ROOT/'eng/host-system-proof.py')
        host=importlib.util.module_from_spec(spec);spec.loader.exec_module(host)
        expected=host.expected_tests(ROOT)
        valid=[dict(testName=name,executionId=str(uuid.uuid4()),outcome='Passed') for name in sorted(expected)]
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'synthetic.trx';path.write_bytes(system_fixture_trx(valid))
            self.assertEqual(host.validate_trx(path,expected)['executed_tests'],len(expected))
            for kind in ['missing-shared','missing-system','duplicate','failed','skipped','unrelated','duplicate-id','missing-id']:
                rows=json.loads(json.dumps(valid))
                if kind=='missing-shared':rows=[row for row in rows if row['testName']!='Loaded_test_and_application_share_the_requested_configuration']
                elif kind=='missing-system':rows=[row for row in rows if row['testName']== 'Loaded_test_and_application_share_the_requested_configuration']
                elif kind=='duplicate':rows.append(dict(rows[0]))
                elif kind in ['failed','skipped']:rows[0]['outcome']='Failed' if kind=='failed' else 'NotExecuted'
                elif kind=='unrelated':rows[0]['testName']='unrelated'
                elif kind=='duplicate-id':rows[0]['executionId']=rows[1]['executionId']
                elif kind=='missing-id':rows[0].pop('executionId')
                path.write_bytes(system_fixture_trx(rows))
                with self.subTest(kind=kind),self.assertRaises(ValueError):host.validate_trx(path,expected)


@unittest.skipUnless(shutil.which('dotnet'),'.NET SDK unavailable; compiled Compose TRX validator regression NotRun')
class NativeComposeTrxValidatorTests(unittest.TestCase):
    """Run the actual package-free C# validator on synthetic TRX; not native application qualification."""
    @classmethod
    def setUpClass(cls):
        cls.tool=tempfile.TemporaryDirectory();cls.addClassCleanup(cls.tool.cleanup)
        root=Path(cls.tool.name);source=root/'source'
        shutil.copytree(ROOT/'eng/ComposeProofProbe',source)
        (source/'NuGet.Config').write_text('<configuration><packageSources><clear /></packageSources></configuration>')
        child=subprocess.run(['dotnet','publish',str(source/'ComposeProofProbe.csproj'),'--configuration','Release',
            '--output',str(root/'probe'),'-p:NuGetAudit=false'],capture_output=True,text=True,timeout=120)
        if child.returncode:raise AssertionError('Actual Compose probe build failed: '+child.stdout+child.stderr)
        cls.binary=root/'probe/ComposeProofProbe.dll'
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.folder=Path(self.temp.name)
        rows,_=current_system_inventory();self.inventory={'attributed_test_methods':rows}
        self.names=[row['method'] for row in rows]
        self.results=[dict(testName=name,executionId=str(uuid.uuid4()),outcome='Passed') for name in self.names]
    def invoke(self,results=None):
        index=self.folder/'index.json';index.write_text(json.dumps(self.inventory))
        trx=self.folder/'synthetic.trx';trx.write_bytes(system_fixture_trx(self.results if results is None else results))
        return subprocess.run(['dotnet',str(self.binary),'--trx',str(trx),str(index),str(uuid.uuid4())],
            capture_output=True,text=True,timeout=10)
    def test_actual_probe_accepts_complete_system_and_linked_fact_results(self):
        result=self.invoke();self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['executed_tests'],len(self.names))
    def test_actual_probe_rejects_incomplete_or_wrong_results_and_unsupported_inventory(self):
        for kind in ['missing-shared','missing-system','duplicate','failed','skipped','unrelated','duplicate-id','missing-id','zero']:
            rows=json.loads(json.dumps(self.results))
            if kind=='missing-shared':rows=[row for row in rows if row['testName']!='Loaded_test_and_application_share_the_requested_configuration']
            elif kind=='missing-system':rows=[row for row in rows if row['testName']=='Loaded_test_and_application_share_the_requested_configuration']
            elif kind=='duplicate':rows.append(dict(rows[0]))
            elif kind in ['failed','skipped']:rows[0]['outcome']='Failed' if kind=='failed' else 'NotExecuted'
            elif kind=='unrelated':rows[0]['testName']='unrelated'
            elif kind=='duplicate-id':rows[0]['executionId']=rows[1]['executionId']
            elif kind=='missing-id':rows[0].pop('executionId')
            elif kind=='zero':rows=[]
            with self.subTest(kind=kind):self.assertEqual(self.invoke(rows).returncode,2)
        self.inventory['attributed_test_methods'].append(dict(self.inventory['attributed_test_methods'][0]))
        self.assertEqual(self.invoke().returncode,2)
        self.inventory['attributed_test_methods'].pop()
        self.inventory['attributed_test_methods'][0]['attribute']='Theory'
        self.assertEqual(self.invoke().returncode,2)
