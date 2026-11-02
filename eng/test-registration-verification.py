#!/usr/bin/env python3
"""Actual Release registration HTTP regressions; full SQL/proxy System qualification is separate."""
import argparse,hashlib,importlib.util,json,os,re,shutil,signal,subprocess,sys,tempfile,threading,xml.etree.ElementTree as ET
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
PROJECT='treehammock.Tests/treehammock.Tests.csproj'
FLOW='treehammock.Tests/Integration/RegistrationVerificationHttpTests.cs'
def require(value,message):
    if not value:raise ValueError(message)
def expected(root):
    names=set()
    names.update(re.findall(r'\[Fact\]\s*public (?:async Task|void) (\w+)\(', (root/FLOW).read_text()))
    require(len(names)==10,'Complete registration verification discovery inventory changed; review expected cases')
    return names

def results(path,names):
    require(path.is_file(),'Fresh registration-verification TRX missing')
    raw=path.read_text();require('<!DOCTYPE' not in raw and '<!ENTITY' not in raw,'TRX entities rejected')
    root=ET.fromstring(raw);definitions={};observed=set();ids=set()
    for node in root.iter():
        if node.tag.rsplit('}',1)[-1]!='UnitTest':continue
        method=next((value for value in node.iter() if value.tag.rsplit('}',1)[-1]=='TestMethod'),None)
        require(method is not None,'Missing verification test identity')
        require(method.attrib['className'].split(',')[0].endswith('.Cor23AERegistrationVerificationHttpTests'),'Unexpected test class')
        require(node.attrib['id'] not in definitions,'Duplicate verification definition')
        definitions[node.attrib['id']]=method.attrib['name'].split('(')[0]
    rows=[node for node in root.iter() if node.tag.rsplit('}',1)[-1]=='UnitTestResult']
    for row in rows:
        method=definitions.get(row.attrib.get('testId'));execution=row.attrib.get('executionId')
        require(method in names and method not in observed and execution and execution not in ids,'Unknown/duplicate registration-verification execution')
        require(row.attrib.get('outcome')=='Passed','Failed/skipped/unexecuted registration verification HTTP case')
        observed.add(method);ids.add(execution)
    require(observed==names and len(rows)==len(names),'Complete verification discovery required')
    counters=next((node for node in root.iter() if node.tag.rsplit('}',1)[-1]=='Counters'),None);require(counters is not None,'TRX counters missing')
    require(all(int(counters.attrib[name])==len(names) for name in ['total','executed','passed']) and int(counters.attrib['failed'])==0 and int(counters.attrib.get('notExecuted','0'))==0,'Verification TRX counters disagree')
    return dict(executions=len(rows),methods=sorted(observed),sha256=hashlib.sha256(path.read_bytes()).hexdigest())

def execute(output):
    output=output.resolve();output.parent.mkdir(parents=True,exist_ok=True)
    report=dict(pr='COR23AE',qualification='NotRun',cases=[],expected_source_methods=sorted(expected(ROOT)),discovered_native_methods=[],reason='Native .NET SDK unavailable; zero cases executed',scope='Actual Release Program/MVC verification pages and isolated in-memory repository state; not full SQL/proxy System qualification')
    def save():output.write_text(json.dumps(report,indent=2)+'\n')
    save();sdk=shutil.which('dotnet')
    if not sdk:return 2
    if sys.platform not in ['linux','win32']:report['reason']='Native Linux/Windows containment required; zero cases executed';save();return 2
    spec=importlib.util.spec_from_file_location('flow_ownership',ROOT/'eng/test-ownership.py');owned=importlib.util.module_from_spec(spec);spec.loader.exec_module(owned)
    code=1
    try:
        with tempfile.TemporaryDirectory(prefix='cor23ae native space ') as temporary:
            source=Path(temporary)/'source with spaces';owned.snapshot(ROOT,source);names=expected(source)
            # Create a unique fresh public result directory; a previous run is never reused.
            evidence=output.parent/(output.stem+'-'+os.urandom(8).hex());evidence.mkdir()
            environment=dict(os.environ,DOTNET_CLI_TELEMETRY_OPTOUT='true',DOTNET_SKIP_FIRST_TIME_EXPERIENCE='true',DOTNET_CLI_HOME=str(Path(temporary)/'dotnet-home'))
            run=owned.create_run(source,'docker-unit-tests',environment);run['status']='Running';owned.write(owned.manifest(run),run);environment=owned.run_environment(run,environment)
            def interrupted(number,frame):raise KeyboardInterrupt()
            previous={number:signal.signal(number,interrupted) for number in [signal.SIGINT,signal.SIGTERM]}
            def command(arguments):
                manager=owned.Lifecycle(run);drain=None
                def discard(stream):
                    try:
                        while stream.read(65536):pass
                    finally:stream.close()
                try:
                    process=manager.launch('wrapper',[sdk,*arguments],environment);drain=threading.Thread(target=discard,args=(process.stdout,),daemon=True);drain.start()
                    return process.wait(timeout=900)
                finally:
                    clean=manager.stop(owned.Deadline(15))
                    if drain:drain.join(timeout=1)
                    require(not clean,'Native owned process cleanup failed')
            try:
                require(command(['restore',PROJECT,'--locked-mode'])==0,'Locked native restore failed')
                # Execute the actual HTTP and assertion regressions with fresh results.
                for iteration in range(1):
                    destination=evidence/('complete-suite-'+str(iteration+1));destination.mkdir()
                    require(command(['test',PROJECT,'-c','Release','--no-restore','--filter','FullyQualifiedName~Cor23AERegistrationVerificationHttpTests','--logger','trx;LogFileName=verification.trx','--results-directory',str(destination)])==0,'Native registration verification failed')
                    proof=results(destination/'verification.trx',names);report['discovered_native_methods']=proof['methods'];report['cases'].append(dict(case=destination.name,status='Passed',**proof));save()
                report.update(qualification='Partial',reason='Actual HTTP fixture and negative success assertions passed; complete registration System stack and COR24 remain pending');code=0
            finally:
                for number,handler in previous.items():signal.signal(number,handler)
    except KeyboardInterrupt:report.update(qualification='Interrupted',reason='Native verification interrupted; process cleanup applied');code=130
    except (OSError,ValueError,KeyError,ET.ParseError,subprocess.SubprocessError):report.update(qualification='Failed',reason='Actual restore/build/discovery/HTTP/assertion/cleanup failed; no synthetic pass substituted')
    save();return code

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();return execute(args.output)
if __name__=='__main__':raise SystemExit(main())
