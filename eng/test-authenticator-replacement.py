#!/usr/bin/env python3
"""Actual Release/PostgreSQL replacement proof and failing predecessor-omission mutation."""
import argparse,hashlib,importlib.util,json,os,re,shutil,signal,subprocess,sys,tempfile,threading,xml.etree.ElementTree as ET
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
PROJECT='treehammock.Tests.SqlContracts/treehammock.Tests.SqlContracts.csproj'
SUITE='Cor23AFAuthenticatorReplacementTests'
TEST='treehammock.Tests.SqlContracts/Integration/Database/AuthenticatorReplacementTests.cs'
REPO='Repos/AuthenticatorAppEnrollmentRepo.cs'
TARGET='Actual_repository_replacement_with_predecessor_bound_grant_commits'
BOUND='SensitiveActionTargets.AuthenticatorSetup(commandModel.AuthId, commandModel.Required, commandModel.TotpProviderType, commandModel.ExpectedEnrollmentId, commandModel.ExpectedVersion)'
UNBOUND='SensitiveActionTargets.AuthenticatorSetup(commandModel.AuthId, commandModel.Required, commandModel.TotpProviderType)'
def require(value,message):
    if not value:raise ValueError(message)
def expected(root):
    source=(root/TEST).read_text();methods=re.findall(r'\[(?:Fact|Theory)\][\s\S]*?public (?:async )?(?:Task|void) (\w+)\(',source)
    require(len(methods)==6 and len(set(methods))==6,'Complete replacement source inventory changed')
    require(source.count('[InlineData(')==13,'Review all thirteen denial variants')
    return {method:13 if method=='Stale_or_mismatched_target_preserves_original_setup' else 1 for method in methods}
def mutate(root):
    path=root/REPO;original=path.read_bytes();source=original.decode()
    require(source.count(BOUND)==1,'Repository predecessor mutation anchor must be unique')
    path.write_text(source.replace(BOUND,UNBOUND));return path,original

def results(path,inventory,negative=False):
    require(path.is_file(),'Fresh native replacement TRX missing')
    raw=path.read_text();require('<!DOCTYPE' not in raw and '<!ENTITY' not in raw,'TRX entities rejected')
    root=ET.fromstring(raw);definitions={};counts={name:0 for name in inventory};ids=set();outcomes=[];failed=[]
    for node in root.iter():
        if node.tag.rsplit('}',1)[-1]!='UnitTest':continue
        method=next((n for n in node.iter() if n.tag.rsplit('}',1)[-1]=='TestMethod'),None)
        require(method is not None and method.attrib['className'].split(',')[0].endswith('.'+SUITE),'Actual repository test identity required')
        require(node.attrib['id'] not in definitions,'Duplicate definition')
        definitions[node.attrib['id']]=method.attrib['name'].split('(')[0]
    rows=[n for n in root.iter() if n.tag.rsplit('}',1)[-1]=='UnitTestResult']
    for row in rows:
        method=definitions.get(row.attrib.get('testId'));execution=row.attrib.get('executionId');outcome=row.attrib.get('outcome')
        require(method in counts and execution and execution not in ids,'Unknown/duplicate replacement execution')
        ids.add(execution);counts[method]+=1;outcomes.append(outcome)
        require(outcome in ['Passed','Failed'],'Skipped/unexecuted replacement case')
        if outcome=='Failed':
            message=' '.join((n.text or '') for n in row.iter() if n.tag.rsplit('}',1)[-1] in ['Message','StackTrace'])
            require(negative and method==TARGET and 'Shouldly.ShouldAssertException' in message and SUITE in message and TARGET in message,'Failure must be the designated actual replacement assertion')
            failed.append(method)
    require(counts==inventory and len(rows)==sum(inventory.values()),'Full exact method/theory discovery required')
    counters=next((n for n in root.iter() if n.tag.rsplit('}',1)[-1]=='Counters'),None);require(counters is not None,'TRX counters missing')
    require(int(counters.attrib['total'])==len(rows) and int(counters.attrib['executed'])==len(rows) and int(counters.attrib.get('notExecuted','0'))==0,'Incomplete execution counters')
    require(int(counters.attrib['passed'])==outcomes.count('Passed') and int(counters.attrib['failed'])==outcomes.count('Failed'),'Outcome counters disagree')
    require(failed==[TARGET] if negative else not failed,'Repository mutation escaped its expected failed replacement assertion')
    return dict(executions=len(rows),methods=sorted(counts),failed_methods=failed,sha256=hashlib.sha256(path.read_bytes()).hexdigest())

def execute(output):
    output=output.resolve();output.parent.mkdir(parents=True,exist_ok=True)
    report=dict(pr='COR23AF',qualification='NotRun',cases=[],discovered_native_methods=[],expected_source_methods=expected(ROOT),reason='Native .NET SDK unavailable; zero cases executed',scope='Actual production service/repository, real PostgreSQL grant consumption and independent durable-state observer; completed password/factor attestation remains an explicit COR16 fixture substitute')
    def save():output.write_text(json.dumps(report,indent=2)+'\n')
    save();sdk=shutil.which('dotnet')
    if not sdk:return 2
    if os.environ.get('TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS','').lower() not in ['true','1'] or not os.environ.get('TREEHAMMOCK_DB_CONTRACT_CONNECTION','').strip():
        report['reason']='Explicit disposable PostgreSQL opt-in and connection required; use the owned correction fixture';save();return 2
    if sys.platform not in ['linux','win32']:report['reason']='Native Linux/Windows process containment required';save();return 2
    spec=importlib.util.spec_from_file_location('replacement_ownership',ROOT/'eng/test-ownership.py');owned=importlib.util.module_from_spec(spec);spec.loader.exec_module(owned)
    code=1;changed=None;original=None
    try:
        with tempfile.TemporaryDirectory(prefix='cor23af native space ') as temporary:
            source=Path(temporary)/'source with spaces';owned.snapshot(ROOT,source);inventory=expected(source)
            evidence=output.parent/(output.stem+'-'+os.urandom(8).hex());evidence.mkdir()
            environment=dict(os.environ,DOTNET_CLI_TELEMETRY_OPTOUT='true',DOTNET_SKIP_FIRST_TIME_EXPERIENCE='true',DOTNET_CLI_HOME=str(Path(temporary)/'dotnet-home'))
            run=owned.create_run(source,'docker-unit-tests',environment);run['status']='Running';owned.write(owned.manifest(run),run);environment=owned.run_environment(run,environment)
            report['postgres_image_id']=environment.get('TREEHAMMOCK_CORRECTION_DB_IMAGE_ID');report['owned_fixture_project']=environment.get('TREEHAMMOCK_CORRECTION_PROJECT')
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
            def test(name,negative=False):
                destination=evidence/name;destination.mkdir()
                selected='FullyQualifiedName~'+SUITE+('.'+TARGET if negative else '')
                exit_code=command(['test',PROJECT,'-c','Release','--no-restore','--filter',selected,'--logger','trx;LogFileName=replacement.trx','--results-directory',str(destination)])
                require(exit_code==(1 if negative else 0),'Native exit code disagrees with actual mutation outcome')
                proof=results(destination/'replacement.trx',{TARGET:1} if negative else inventory,negative)
                report['cases'].append(dict(case=name,status='Passed',expected_failure=negative,**proof));report['discovered_native_methods']=sorted(set(report['discovered_native_methods'])|set(proof['methods']));save()
            try:
                require(command(['restore',PROJECT,'--locked-mode','-p:Configuration=Release'])==0,'Locked native restore failed')
                test('current-repository-service')
                changed,original=mutate(source)
                try:test('omitted-predecessor-negative-control',True)
                finally:changed.write_bytes(original);changed=None
                test('restored-repository-service')
                report.update(qualification='Partial',reason='Actual repository/service, eighteen positive/denial cases and designated failing mutation passed; integrated COR24 qualification remains pending');code=0
            finally:
                if changed:changed.write_bytes(original);changed=None
                for number,handler in previous.items():signal.signal(number,handler)
    except KeyboardInterrupt:report.update(qualification='Interrupted',reason='Native replacement interrupted; private source restoration and process cleanup applied');code=130
    except (OSError,ValueError,KeyError,ET.ParseError,subprocess.SubprocessError):report.update(qualification='Failed',reason='Actual native restore/build/discovery/repository/service/SQL/mutation/cleanup failed; no source witness substituted')
    save();return code

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();return execute(args.output)
if __name__=='__main__':raise SystemExit(main())
