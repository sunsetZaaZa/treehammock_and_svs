#!/usr/bin/env python3
"""Collect a fresh source-bound COR24 packet; never change findings/gates or claim release readiness."""
import argparse,datetime,hashlib,importlib.util,json,os,platform,re,shutil,signal,subprocess,sys,tempfile,threading,uuid,xml.etree.ElementTree as ET
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
IGNORE={'.git','.docker','bin','obj','TestResults','.artifacts','artifacts','.correction-results','__pycache__','node_modules'}
def require(value,message):
    if not value:raise ValueError(message)
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def read(path):
    def unique(pairs):
        result={}
        for key,value in pairs:require(key not in result,'Duplicate evidence JSON key');result[key]=value
        return result
    return json.loads(path.read_text(),object_pairs_hook=unique)
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def source_identity(root):
    total=hashlib.sha256()
    for path in sorted(root.rglob('*')):
        if not path.is_file() or IGNORE.intersection(path.relative_to(root).parts):continue
        require(not path.is_symlink(),'Linked source input rejected')
        total.update(path.relative_to(root).as_posix().encode()+b'\0'+hashlib.sha256(path.read_bytes()).digest())
    return 'sha256:'+total.hexdigest()
def load_requirements(root):
    data=read(root/'eng/cross-feature-qualification-requirements.json');require(data['schema_version']==1 and data['pr']=='COR24','Unknown requirements')
    ids=[s['id'] for s in data['required_stages']];require(len(ids)==len(set(ids)) and len(ids)==24,'Complete mandatory stage inventory required')
    require(len(data['required_acceptance'])==12 and len({s['id'] for s in data['required_acceptance']})==12,'Complete acceptance inventory required')
    for stage in data['required_stages']:
        require(re.fullmatch('[a-z0-9-]+',stage['id']) and stage['kind'] in ['source','tooling','client','native'],'Invalid stage identity')
        require(1<=stage['timeout_seconds']<=7200 and stage['command'] and isinstance(stage['tools'],list),'Bounded stage recipe required')
        for token in stage['command']:
            require(isinstance(token,str) and '\0' not in token and '\n' not in token,'Invalid argv')
            if token.startswith('eng/') or token.startswith('tests/'):require((root/token).exists() and (root/token).resolve().is_relative_to(root.resolve()),'Missing/escaped stage source: '+token)
    return data

WARMUP_FEATURE='Database-backed Dragonfly session warmup'
def validate_feature_matrix(root,surface,findings,gates):
    """Current source counts/anchors only; historical inventories are not rewritten."""
    counts={'Findings':len(findings),'Review/release gates':len(gates),'Endpoints':len(surface['endpoints']),
        'Canonical SQL functions':len(surface['sql_functions']),'Attributed source test methods':len(surface['attributed_test_methods']),
        'Feature rows':len(surface['features'])}
    text=(root/'docs/release/RELEASE_FEATURE_MATRIX.md').read_text()
    rows=re.findall(r'^\| (Findings|Review/release gates|Endpoints|Canonical SQL functions|Attributed source test methods|Feature rows) \| ([0-9]+) \|',text,re.M)
    require(len(rows)==len(counts) and {name:int(count) for name,count in rows}==counts,'Current feature-matrix counts differ from authoritative ledgers/source index')
    features=surface['features']
    require(len(features)==45 and len({(f['area'],f['feature']) for f in features})==45,'Advertised feature inventory changed; review COR24 matrix')
    warmup=[f for f in features if f['feature']==WARMUP_FEATURE]
    require(len(warmup)==1,'Existing warmup must have exactly one explicit feature row')
    expected={'Services/SessionCacheWarmupWorker.cs','Repos/SessionCacheWarmupRepo.cs','Rigging/Config/SessionCacheWarmupSettings.cs',
        'docs/deployment/SESSION_CACHE_WARMUP.md','treehammock.Tests/Unit/SessionCacheWarmupTests.cs',
        'treehammock.Tests.SqlContracts/Integration/Database/SessionCacheWarmupSqlTests.cs'}
    located={a['anchor'] for a in warmup[0]['anchors'] if a['anchor'] in a['paths']}
    require(expected<=located,'Existing warmup source/config/guide/native test anchors are incomplete')
    require(warmup[0]['qualification']=='PendingIntegratedQualification','Warmup source row cannot assert native qualification')

def catalog(root):
    findings=read(root/'docs/corrections/FINDING_CLOSURE.json')['findings'];followups=read(root/'docs/corrections/SOURCE_FINDING_FOLLOWUPS.json')['followups']
    gates=read(root/'docs/corrections/REVIEW_GATES.json')['gates'];surface=read(root/'docs/corrections/APPLICATION_SURFACE_INDEX.json');mapping=read(root/'docs/corrections/SOURCE_RECONCILIATION.json')
    require(len(findings)==84 and len({f['id'] for f in findings})==84,'All imported finding IDs required')
    require(len(followups)==32 and len(gates)==186,'All owner followups and gates required')
    validate_feature_matrix(root,surface,findings,gates);features=surface['features']
    return dict(findings=[dict(id=f['id'],owner=f['owner'],implementation_status=f['status'],required_lanes=f['required_lanes'],regression_cases=f['regression_cases'],closure_present=f['closure'] is not None) for f in findings],
        followups=[dict(pr=f['pr'],finding=f['finding'],implementation_status=f.get('implementation_status'),qualification=f['qualification']) for f in followups],
        gates=[dict(id=g['id'],kind=g['kind'],owner=g['owner'],status=g['status']) for g in gates],
        features=features,source_files=[dict(path=p.relative_to(root).as_posix(),sha256=sha(p)) for p in sorted(root.rglob('*')) if p.is_file() and not IGNORE.intersection(p.relative_to(root).parts)],
        original_inventory_rows=mapping['original_inventory_rows'],endpoints=len(surface['endpoints']),sql_functions=len(surface['sql_functions']))

def redact(text,environment):
    for name,value in environment.items():
        if re.search('password|secret|token|connection|fixture_.*key',name,re.I) and len(value)>=4:text=text.replace(value,'[REDACTED]')
    text=re.sub(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+','[REDACTED-JWT]',text)
    names=r'password|pwd|secret|access.?token|refresh.?token|twoFactorAccessToken|setupId|manualEntryKey|sensitive.?action.?token|recovery.?key|payload'
    text=re.sub(r'(?i)((?:'+names+r')["\']?\s*[=:]\s*["\']?)[^\s;"\'<>&,]+',r'\1[REDACTED]',text)
    text=re.sub(r'[A-Za-z0-9_.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}','[REDACTED-DESTINATION]',text)
    return text



def stage_environment(parent):
    # The supervisor keeps its own gated run identity; stage fixtures must own fresh identities.
    result=dict(parent)
    for name in list(result):
        if name.startswith(('TREEHAMMOCK_PROCESS_','TREEHAMMOCK_TEST_RUN_')):result.pop(name)
    return result

def retain_receipts(checkout,destination,environment):
    receipts=[]
    for base in [checkout/'.correction-results',checkout/'artifacts/test-runs']:
        if not base.exists():continue
        for original in sorted(base.rglob('*')):
            if not original.is_file() or original.suffix not in ['.json','.trx']:continue
            if original.is_symlink():raise ValueError('Linked receipt rejected')
            if re.search('ownership|credential|environment|authfile|private|secret',original.name,re.I):continue
            raw=original.read_text()
            if original.suffix=='.trx':
                require('<!DOCTYPE' not in raw and '<!ENTITY' not in raw,'Receipt entities rejected');ET.fromstring(raw)
            else:
                data=read(original)
                if not isinstance(data,dict) or not any(key in data for key in ['qualification','lanes','build_run_id','source_identity','proof','image_id']):continue
                if re.search(r'"(?:password|hmacKeys|protectionKeys|encryptionKeys|connectionString)"\s*:',raw,re.I):continue
            relative=original.relative_to(checkout);target=destination/'receipts'/relative
            target.parent.mkdir(parents=True,exist_ok=True);target.write_text(redact(raw,environment))
            receipts.append(dict(path=target.relative_to(destination).as_posix(),original_sha256=sha(original),public_sha256=sha(target),sanitized=True))
    return receipts

def blockers(snapshot,stages,requirements,workload):
    result=[]
    for item in snapshot['findings']:
        if item['implementation_status'] not in ['Closed','Dispositioned']:result.append(dict(kind='finding',id=item['id'],reason='Executable owner closure/disposition pending'))
    for item in snapshot['gates']:
        if item['status']!='Passed':result.append(dict(kind='gate',id=item['id'],reason='Current review/qualification evidence pending'))
    for item in stages:
        if item['status']!='Succeeded':result.append(dict(kind='stage',id=item['id'],reason=item['reason']))
        elif item['kind']=='native':result.append(dict(kind='adjudication',id=item['id'],reason='Command completion is not integrated closure; review fresh native receipts and scoped acceptance'))
    # These require concrete owner/runtime/operator artifacts, never an empty or inferred pass.
    result.extend(dict(kind='acceptance',id=item['id'],reason=item['requirement']) for item in requirements['required_acceptance'])
    if workload.get('budget_status')!='Approved' or not workload.get('budgets') or not workload.get('review_reference'):
        result.append(dict(kind='performance',id='approved-budgets',reason='COR22 workload budgets remain proposed/unreviewed'))
    return result

def outcome(snapshot,stages,requirements,workload):
    missing=blockers(snapshot,stages,requirements,workload)
    failed=any(row['status']=='Failed' for row in stages)
    return dict(qualification='Failed' if failed else 'Blocked' if missing else 'ReadyForReview',release_ready=False,
        deployment_performed=False,closure_updates_performed=False,blockers=missing)

def execute(output,select=None,include_tooling=True):
    requirements=load_requirements(ROOT);snapshot=catalog(ROOT);before=source_identity(ROOT)
    output=output.resolve();require(output.is_relative_to(ROOT/'.correction-results') or output.is_relative_to(ROOT/'.artifacts'),'Evidence must be under the dedicated output roots')
    output.mkdir(parents=True,exist_ok=True);run_id=str(uuid.uuid4());directory=output/run_id;directory.mkdir(mode=0o700)
    packet=dict(schema_version=1,pr='COR24',run_id=run_id,started_at=now(),source_identity=before,platform=platform.platform(),
        requirements_sha256=sha(ROOT/'eng/cross-feature-qualification-requirements.json'),catalog=snapshot,stages=[],qualification='Running',release_ready=False,
        expected_native_execution_counts='Source inventory only; zero executions are inferred',deployment_performed=False,closure_updates_performed=False)
    ledger_hashes={name:sha(ROOT/'docs/corrections'/name) for name in ['FINDING_CLOSURE.json','REVIEW_GATES.json','SOURCE_FINDING_FOLLOWUPS.json']}
    packet['ledger_sha256']=ledger_hashes;path=directory/'qualification.json'
    def save():path.write_text(json.dumps(packet,indent=2)+'\n')
    packet['stages']=[dict(id=s['id'],kind=s['kind'],status='NotRun',exit_code=None,reason='Stage not reached',native_case_count=0 if s['kind']=='native' else None) for s in requirements['required_stages']]
    save();selected=set(select) if select else None;known={s['id'] for s in requirements['required_stages']}
    require(selected is None or selected<=known,'Unknown selected stage')
    spec=importlib.util.spec_from_file_location('cor24_owned',ROOT/'eng/test-ownership.py');owned=importlib.util.module_from_spec(spec);spec.loader.exec_module(owned)
    previous={}
    def interrupted(number,frame):raise KeyboardInterrupt()
    try:
        for number in [signal.SIGINT,signal.SIGTERM]:previous[number]=signal.signal(number,interrupted)
        with tempfile.TemporaryDirectory(prefix='cor24 locked source ') as temporary:
            checkout=Path(temporary)/'source with spaces';owned.snapshot(ROOT,checkout)
            require(source_identity(checkout)==before,'Private checkout differs from candidate source')
            # ZIP checkouts do not necessarily preserve the Git executable bit; apply it only privately.
            for script in (checkout/'eng').glob('*.sh'):script.chmod(script.stat().st_mode|0o100)
            for recipe in requirements['required_stages']:
                row=next(value for value in packet['stages'] if value['id']==recipe['id']);row.update(started_at=now(),reason=None)
                folder=directory/recipe['id'];folder.mkdir()
                command=[value.replace('{python}',sys.executable).replace('{evidence}',str(folder)) for value in recipe['command']]
                row['command']=command
                missing=[tool for tool in recipe['tools'] if not shutil.which(tool)]
                if selected is not None and recipe['id'] not in selected:row['reason']='Stage not selected; mandatory requirement remains unsatisfied'
                elif recipe['kind']=='tooling' and not include_tooling:row['reason']='Full tooling suite omitted explicitly; requirement remains unsatisfied'
                elif sys.platform not in recipe['platforms']:row['reason']='This stage requires another supported native platform'
                elif missing:row['reason']='Missing executable prerequisites: '+', '.join(missing)
                else:
                    run=owned.create_run(checkout,'docker-unit-tests',dict(os.environ));run['status']='Running';owned.write(owned.manifest(run),run)
                    caller_environment=stage_environment(os.environ)
                    environment=owned.run_environment(run,dict(os.environ));manager=owned.Lifecycle(run);drain=None;captured=bytearray()
                    private_environment=owned.manifest(run).parent/'cor24-stage-environment.json'
                    private_environment.write_text(json.dumps(caller_environment));private_environment.chmod(0o600)
                    contained_command=[sys.executable,str(Path(run['checkout'])/'eng/stage-cross-feature-qualification.py'),str(private_environment),*command]
                    def collect(stream):
                        try:
                            while True:
                                chunk=stream.read(65536)
                                if not chunk:break
                                captured.extend(chunk)
                                if len(captured)>1024*1024:del captured[:-1024*1024]
                        finally:stream.close()
                    try:
                        process=manager.launch('wrapper',contained_command,environment)
                        drain=threading.Thread(target=collect,args=(process.stdout,),daemon=True);drain.start()
                        row['exit_code']=process.wait(timeout=recipe['timeout_seconds'])
                        row['status']='Succeeded' if row['exit_code']==0 else 'Blocked' if row['exit_code'] in [2,127] else 'Failed'
                        row['reason']=None if row['exit_code']==0 else 'Child returned a blocker/nonzero outcome; inspect sanitized log and native receipts'
                        # Executed does not mean qualified; counts stay unknown pending native receipt adjudication.
                        if recipe['kind']=='native':row['native_case_count']=None
                    except subprocess.TimeoutExpired:row.update(status='Failed',exit_code=124,reason='Bounded stage deadline exceeded; owned cleanup applied')
                    except OSError:row.update(status='Failed',exit_code=127,reason='Actual child could not start')
                    finally:
                        cleanup=manager.stop(owned.Deadline(15));row['cleanup_status']='Failed' if cleanup else 'Succeeded'
                        if drain:drain.join(timeout=2)
                        if cleanup:row.update(status='Failed',reason='Owned child tree cleanup failed')
                        log=folder/'stage.log';log.write_text(redact(captured.decode('utf-8',errors='replace'),environment));row['log']=dict(path=str(log.relative_to(directory)),sha256=sha(log),bounded_bytes=log.stat().st_size)
                    if recipe['id']=='python-tooling' and row['status']=='Succeeded':
                        match=re.search(r'Ran (\d+) tests .*\n\nOK',log.read_text());require(match is not None,'Tooling execution has no complete passed result');row['tooling_tests']=int(match[1])
                row['completed_at']=now();save()
            packet['retained_receipts']=retain_receipts(checkout,directory,dict(os.environ))
            require(source_identity(ROOT)==before,'Candidate source changed during qualification')
            require(all(sha(ROOT/'docs/corrections'/name)==value for name,value in ledger_hashes.items()),'Qualification may not promote/change ledger or gates')
            packet.update(outcome(snapshot,packet['stages'],requirements,read(ROOT/'eng/resource-workload.json')))
    except KeyboardInterrupt:packet.update(qualification='Interrupted',release_ready=False,reason='Interrupted; bounded owned child cleanup applied')
    except (OSError,ValueError,KeyError,subprocess.SubprocessError):packet.update(qualification='Failed',release_ready=False,reason='Actual source/stage/evidence/cleanup integrity failed')
    finally:
        for number,handler in previous.items():signal.signal(number,handler)
        packet['completed_at']=now();packet['ledger_unchanged']=all(sha(ROOT/'docs/corrections'/name)==value for name,value in ledger_hashes.items());save()
    print(json.dumps(dict(qualification=packet['qualification'],release_ready=False,report=str(path))))
    return 1 if packet['qualification'] in ['Failed','Interrupted'] else 2

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,default=ROOT/'.correction-results/cor24');parser.add_argument('--stage',action='append');parser.add_argument('--omit-tooling',action='store_true');args=parser.parse_args();return execute(args.output,args.stage,not args.omit_tooling)
if __name__=='__main__':raise SystemExit(main())
