#!/usr/bin/env python3
"""Actual Release account HTTP suites and disposable schema/code mutations; no CLR emulator."""
import argparse,hashlib,importlib.util,json,os,re,shutil,signal,subprocess,sys,tempfile,threading,time,xml.etree.ElementTree as ET
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
PROJECT='treehammock.Tests/treehammock.Tests.csproj'
SUITES=['ApiValidationEnvelopeTests','AccountAdjustIntegrationTests','Cor23ACAccountFailureAssertionTests']
MODEL_TARGET='Malformed_json_returns_standard_validation_envelope'
KEY_TARGET='Authenticated_adjust_missing_required_idempotency_key_returns_precondition_required'
MODEL_BLOCK='''        .ConfigureApiBehaviorOptions(options =>
        {
            options.InvalidModelStateResponseFactory = context => ApiResponses.InvalidModelState(context.ModelState);
        })'''
KEY_BLOCK='''                StatusCodes.Status428PreconditionRequired,
                AuthenticatedMutationIdempotencyConstants.MissingRequiredKeyCode)'''
IGNORE={'.git','.docker','bin','obj','artifacts','.artifacts','.correction-results','TestResults','__pycache__','node_modules'}
def require(value,message):
    if not value:raise ValueError(message)
def mutate(root,kind):
    if kind=='framework-model-state':path=root/'Program.cs';before=MODEL_BLOCK;after=''
    else:
        require(kind in ['required-key-wrong-code','required-key-missing-code'],'Unknown mutation')
        path=root/'Controllers/AccountControllerBase.cs';before=KEY_BLOCK
        after='                StatusCodes.Status428PreconditionRequired,\n                '+('"COR23AC_WRONG_CODE")' if kind=='required-key-wrong-code' else 'null!)')
    original=path.read_bytes();text=original.decode();require(text.count(before)==1,'Mutation anchor is not unique');path.write_text(text.replace(before,after));return path,original

def expected(root):
    result={}
    for name in SUITES:
        group='Unit' if name.endswith('AssertionTests') else 'Integration'
        text=(root/f'treehammock.Tests/{group}/{name}.cs').read_text()
        # Theory expansions are validated through unique executions and nonzero per-method results.
        methods=re.findall(r'\[(?:Fact|Theory)\][\s\S]*?public (?:async )?(?:Task|void) (\w+)\(',text)
        result[name]=set(methods);require(bool(methods),'Suite discovery inventory is empty')
    return result

def results(path,inventory,negative=None):
    require(path.is_file(),'Fresh TRX missing')
    raw=path.read_text();require('<!DOCTYPE' not in raw and '<!ENTITY' not in raw,'TRX entities are invalid')
    root=ET.fromstring(raw);records=[n for n in root.iter() if n.tag.rsplit('}',1)[-1]=='UnitTestResult']
    require(bool(records),'Zero tests executed')
    definitions={}
    for node in root.iter():
        if node.tag.rsplit('}',1)[-1]!='UnitTest':continue
        method=next((x for x in node.iter() if x.tag.rsplit('}',1)[-1]=='TestMethod'),None)
        require(method is not None,'Test method identity missing');definitions[node.attrib['id']]=(method.attrib['className'].split(',')[0].split('.')[-1],method.attrib['name'])
    observed={name:set() for name in inventory};failures=[];ids=set();outcomes=[];method_counts={}
    for row in records:
        require(row.attrib.get('executionId') and row.attrib['executionId'] not in ids,'Duplicate execution receipt');ids.add(row.attrib['executionId'])
        require(row.attrib.get('testId') in definitions,'Unknown test identity');suite,method=definitions[row.attrib['testId']]
        # VSTest may use the theory display name in TestMethod.name; keep the exact base method.
        method=method.split('(')[0]
        require(suite in inventory and method in inventory[suite],'Unexpected test discovered')
        method_counts[(suite,method)]=method_counts.get((suite,method),0)+1
        observed[suite].add(method);outcome=row.attrib.get('outcome');outcomes.append(outcome)
        require(outcome in ['Passed','Failed'],'Skipped/unexecuted HTTP case')
        if outcome=='Failed':
            message=' '.join((x.text or '') for x in row.iter() if x.tag.rsplit('}',1)[-1] in ['Message','StackTrace'])
            require('Shouldly.ShouldAssertException' in message and 'AccountFailureAssertions.Failure' in message,'Failure is not the strict contract assertion')
            failures.append(method)
    require(observed==inventory,'Suite discovery is incomplete')
    for method,count in [('Authenticated_adjust_blank_or_email_plus_valid_field_returns_validation_failed',2),('Empty_malformed_or_wrong_media_type_body_is_rejected',3),('Status_only_missing_wrongly_typed_and_malformed_validation_shapes_are_rejected',40)]:
        if any(method in names for names in inventory.values()):require(sum(value for (suite,name),value in method_counts.items() if name==method)==count,'Theory expansion is incomplete')
    counters=next((n for n in root.iter() if n.tag.rsplit('}',1)[-1]=='Counters'),None);require(counters is not None,'TRX counters missing')
    require(int(counters.attrib['total'])==len(records) and int(counters.attrib['executed'])==len(records) and int(counters.attrib.get('notExecuted','0'))==0,'Incomplete TRX counters')
    require(int(counters.attrib['passed'])==outcomes.count('Passed') and int(counters.attrib['failed'])==outcomes.count('Failed'),'TRX outcome counters differ')
    if negative:require(negative in failures,'Designated schema/code mutation escaped its HTTP test')
    else:require(not failures,'Current application failed exact contracts')
    return dict(executions=len(records),methods=sum(len(v) for v in observed.values()),failed_methods=sorted(set(failures)),sha256=hashlib.sha256(path.read_bytes()).hexdigest())

def execute(output):
    report=dict(pr='COR23AC',qualification='NotRun',cases=[],reason='Native .NET SDK unavailable; zero cases executed',scope='Actual Release CLR/ASP.NET host, current account HTTP suites and assertion unit fixtures; mocked domain/cache authority, not SQL/Docker/provider qualification')
    output=output.resolve();output.parent.mkdir(parents=True,exist_ok=True)
    def save():output.write_text(json.dumps(report,indent=2)+'\n')
    sdk=shutil.which('dotnet')
    if not sdk:save();return 2
    if sys.platform not in ['linux','win32']:report['reason']='Native Linux/Windows process containment required; zero cases executed';save();return 2
    spec=importlib.util.spec_from_file_location('envelope_ownership',ROOT/'eng/test-ownership.py');owned=importlib.util.module_from_spec(spec);spec.loader.exec_module(owned)
    code=1
    with tempfile.TemporaryDirectory(prefix='cor23ac native space ') as temporary:
        source=Path(temporary)/'source with spaces';shutil.copytree(ROOT,source,ignore=shutil.ignore_patterns(*IGNORE));inventory=expected(source)
        evidence=output.parent/(output.stem+'-evidence');evidence.mkdir(exist_ok=False)
        environment=dict(os.environ,DOTNET_CLI_TELEMETRY_OPTOUT='true',DOTNET_SKIP_FIRST_TIME_EXPERIENCE='true',DOTNET_CLI_HOME=str(Path(temporary)/'dotnet-home'))
        run=owned.create_run(source,'docker-unit-tests',environment);root=Path(run['checkout']);run['status']='Running';owned.write(owned.manifest(run),run);environment=owned.run_environment(run,environment)
        def interrupted(number,frame):raise KeyboardInterrupt()
        previous={number:signal.signal(number,interrupted) for number in [signal.SIGINT,signal.SIGTERM]}
        def command(argv,timeout=900):
            manager=owned.Lifecycle(run);process=None;drain=None
            def discard(stream):
                try:
                    while stream.read(65536):pass
                finally:stream.close()
            try:
                process=manager.launch('wrapper',[sdk,*argv],environment)
                drain=threading.Thread(target=discard,args=(process.stdout,),daemon=True);drain.start()
                return subprocess.CompletedProcess([sdk,*argv],process.wait(timeout=timeout))
            finally:
                clean=manager.stop(owned.Deadline(15))
                if drain:drain.join(timeout=1)
                require(not clean,'Owned native process cleanup failed')
        def test(name,negative=None):
            destination=evidence/name;destination.mkdir()
            selected='|'.join('FullyQualifiedName~'+suite for suite in SUITES)
            result=command(['test',PROJECT,'-c','Release','--no-restore','--filter',selected,'--logger','trx;LogFileName=contracts.trx','--results-directory',str(destination)])
            require(result.returncode==(1 if negative else 0),'Native command returned an unexpected code')
            proof=results(destination/'contracts.trx',inventory,negative)
            report['cases'].append(dict(case=name,status='Passed',expected_failure=negative is not None,**proof));save()
        changed=None;original=None
        try:
            require(command(['restore',PROJECT,'--locked-mode']).returncode==0,'Locked native restore failed')
            test('current-contracts')
            for kind,target in [('framework-model-state',MODEL_TARGET),('required-key-wrong-code',KEY_TARGET),('required-key-missing-code',KEY_TARGET)]:
                changed,original=mutate(root,kind)
                try:test(kind,target)
                finally:changed.write_bytes(original);changed=None
                test('restored-'+kind)
            report.update(qualification='Partial',reason='Actual host/strict assertions/mutations passed; supported-host and integrated COR24 qualification remains pending');code=0
        except KeyboardInterrupt:report.update(qualification='Interrupted',reason='Native verification interrupted; owned process cleanup and private source restoration applied');code=130
        except (OSError,ValueError,KeyError,ET.ParseError,subprocess.SubprocessError):report.update(qualification='Failed',reason='Native restore/build/discovery/HTTP/schema mutation or restoration failed; no controlled success substituted')
        finally:
            if changed:changed.write_bytes(original)
            for number,handler in previous.items():signal.signal(number,handler)
    save();return code

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();return execute(args.output)
if __name__=='__main__':raise SystemExit(main())
