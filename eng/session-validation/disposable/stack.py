#!/usr/bin/env python3
"""SVS-15 owned disposable stack. A failed/missing native target never becomes Passed."""
import argparse,hashlib,json,os,re,shutil,sys,tempfile,time,zipfile
from pathlib import Path
from common import ROOT,PEER_SHA256,Refused,require,run,save,sha,images
import fixture
COMPOSE=ROOT/'deploy/session-validation/compose.integration.yaml'
def check_topology(value):
    expected=set(fixture.SERVICES);require(set(value['services'])==expected,'SERVICE_INVENTORY_DRIFT')
    networks=value['networks'];require(set(networks)=={'data','validation','control','ingress','mail'} and all(n.get('internal') is True and not n.get('external') for n in networks.values()),'PRIVATE_NETWORK_REQUIRED')
    for name,s in value['services'].items():
        require(not set(s).intersection({'ports','network_mode','privileged','devices','pid','ipc','container_name','extends','env_file'}),'HOST_BOUNDARY_REFUSED')
        require(s.get('read_only') is True and s.get('cap_drop')==['ALL'] and s.get('security_opt')==['no-new-privileges:true'] and s.get('logging')=={'driver':'none'},'PROCESS_BOUNDARY_REQUIRED')
        require(s['pids_limit']<=512 and 0<float(s['cpus'])<=2 and s['mem_limit'] in {'128m','256m','512m','768m','3g'},'RESOURCE_BUDGET_REFUSED')
        for volume in s['volumes']:
            require(volume['type']=='bind' and volume['source'].startswith('${SVS15_STATE') and volume['target'].startswith(('/run/fixture','/capture','/session','/apps/treehammock/appsettings.')),'MOUNT_SCOPE_REFUSED')
        if name.startswith('caller-'):
            require(set(s['networks'])=={'validation','ingress'},'CALLER_DATA_NETWORK_REFUSED')
            require(all('/operator' not in v['source'] and '/writer' not in v['source'] and '/svs-' not in v['source'] for v in s['volumes']),'CALLER_SECRET_MOUNT_REFUSED')
        if name.startswith('svs-'):require(set(s['networks'])=={'data','validation','control'},'SVS_NETWORK_DRIFT')
    require(set(value['services']['yugabyte']['networks'])=={'data'},'DATABASE_NETWORK_DRIFT')
    require(all(set(value['services'][n]['networks'])=={'data'} for n in ['cache-old','cache-new']),'CACHE_NETWORK_DRIFT')
    return dict(services=len(expected),private_networks=len(networks),callers=2,svs_replicas=2,auth_event_brokers=0)
def source_check():
    sys.path.insert(0,str(ROOT/'eng/session-validation/ci'));import policy
    return policy.check_source(ROOT)
def extract_peer(archive,destination):
    require(sha(archive)==PEER_SHA256,'THS12C_ARCHIVE_MISMATCH')
    with zipfile.ZipFile(archive) as z:
        require(z.testzip() is None,'THS12C_ARCHIVE_CRC')
        prefix='source/treehammock-main/'
        for n in z.namelist():
            if not n.startswith(prefix) or n.endswith('/'):continue
            rel=Path(n[len(prefix):]);require(not rel.is_absolute() and '..' not in rel.parts,'PEER_ARCHIVE_PATH_REFUSED');p=destination/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(z.read(n))
    require((destination/'treehammock.csproj').is_file(),'PEER_SOURCE_MISSING')
class Stack:
    def __init__(self,state,project,environment):self.state=state;self.project=project;self.env=environment
    def compose(self,*args,data=None,timeout=180):return run(['docker','compose','--project-name',self.project,'--file',COMPOSE,*args],data=data,env=self.env,timeout=timeout)
    def sql(self,sql,database='treehammock'):
        # Only the owned container's loopback provisioning rule permits trust.
        return self.compose('exec','-T','yugabyte','/home/yugabyte/postgres/bin/ysqlsh','-X','-q','-v','ON_ERROR_STOP=1',f'host=127.0.0.1 port=5433 user=yugabyte dbname={database} sslmode=verify-full sslrootcert=/run/fixture/sql-ca.pem',data=sql.encode())
    def operator(self,*args,timeout=180):return self.compose('run','--rm','--no-deps','-T','operator',*args,timeout=timeout)
    def controller(self,action):return self.operator('dotnet','/apps/treehammock/treehammock.dll','fleet-control','/run/fixture/controller.json',action,timeout=200)
    def await_sql(self):
        end=time.monotonic()+120
        while time.monotonic()<end:
            try:self.sql('select 1;','yugabyte');return
            except Refused:time.sleep(1)
        raise Refused('YSQL_STARTUP_TIMEOUT')
def provision(stack,peer,phase,v):
    roles=fixture.rolemap(phase);retired=list(fixture.rolemap('old')[k] for k in ['App','Coordinator','Validator','Refiller','Maintenance']) if phase=='new' else []
    variables={'app_role':roles['App'],'coordinator_role':roles['Coordinator'],'validator_role':roles['Validator'],'refiller_role':roles['Refiller'],'maintenance_role':roles['Maintenance'],'owner_role':roles['Owner'],'validator_read_role':roles['ValidatorRead'],'write_schema':'public','retired_roles':json.dumps(retired,separators=(',',':'))}
    script='\n'.join("\\set "+k+" '"+value+"'" for k,value in variables.items())+'\n'+(peer/'deploy/authority/THS10_PROVISION.sql').read_text()
    stack.sql(script)
    script='\n'.join('alter role '+roles[k]+" login password '"+v['passwords'][phase][k]+"';" for k in ['App','Coordinator','Validator','Refiller','Maintenance'])
    stack.sql(script)
def permission_probes(stack,v):
    roles=fixture.rolemap('new')
    for kind in ['Validator','Refiller']:
        role=roles[kind];password=v['passwords']['new'][kind]
        # Reconnect with each actual runtime login; never SET ROLE from an admin.
        sql="\\connect 'host=172.29.90.20 port=5433 dbname=treehammock user="+role+' password='+password+" sslmode=verify-full sslrootcert=/run/fixture/sql-ca.pem'\n"
        sql+="do $probe$ begin if current_user <> '"+role+"' or session_user <> current_user then raise exception 'wrong probe identity';end if;end;$probe$;\n"
        for command in ['update public.sessions set generation=generation where false','select hashed_password from public.accounts limit 0','create temporary table fixture_privilege_escape(i integer)','set role '+roles['App']]:
            sql+="do $probe$ begin begin execute '"+command+"';raise exception 'forbidden permission succeeded' using errcode='P7501';exception when insufficient_privilege then null;end;end;$probe$;\n"
        stack.sql(sql)
    return ['actual-validator-role-negative-permissions','actual-refiller-role-negative-permissions']
def verify_docker(environment):
    require(not environment.get('DOCKER_HOST') or environment['DOCKER_HOST'].startswith('unix://'),'LOCAL_DOCKER_REQUIRED')
    context=json.loads(run(['docker','context','inspect'],env=environment));require(len(context)==1 and context[0]['Endpoints']['docker']['Host'].startswith('unix://'),'LOCAL_DOCKER_REQUIRED')
    info=json.loads(run(['docker','info','--format','{{json .}}'],env=environment));require(info.get('OSType')=='linux' and info.get('Architecture') in ['x86_64','amd64'],'LINUX_X64_DOCKER_REQUIRED')
def native(archive,lock,output):
    source_check();topology=check_topology(json.loads(COMPOSE.read_text()));require(sha(archive)==PEER_SHA256,'THS12C_ARCHIVE_MISMATCH')
    environment={k:v for k,v in os.environ.items() if not k.startswith(('COMPOSE_','SVS15_'))};verify_docker(environment)
    for k in ['toolchain','yugabyte','dragonfly']:run(['docker','image','inspect',lock[k]],env=environment)
    output=output.resolve();require(not output.exists(),'FRESH_EVIDENCE_PATH_REQUIRED');output.mkdir(parents=True,mode=0o700)
    project='svs15-'+os.urandom(8).hex();result=dict(pr='SVS-15',status='Failed',native_execution='Started',cases=[],grant_rights=False,release_ready=False,images=lock,peer_sha256=PEER_SHA256,topology=topology)
    stack=None;image=None;cleanup=False
    temporary=tempfile.mkdtemp(prefix='svs15-owned-')
    try:
        temp=Path(temporary);state=temp/'state';context=temp/'context';context.mkdir();peer=context/'peer';extract_peer(archive,peer)
        shutil.copytree(ROOT,context/'current',ignore=shutil.ignore_patterns('.git','bin','obj','__pycache__','docs','artifacts','TestResults'))
        shutil.copytree(Path(__file__).parent,context/'driver',ignore=shutil.ignore_patterns('__pycache__'))
        fixture.create(state,peer,lock)
        environment.update(SVS15_PROJECT=project,SVS15_STATE=str(state),SVS15_USER=f'{os.getuid() or 1654}:{os.getgid() or 1654}',SVS15_DBUSER=f'{os.getuid() or 1654}:{os.getgid() or 1654}',SVS15_UID=str(os.getuid() or 1654),SVS15_GID=str(os.getgid() or 1654),SVS15_YUGABYTE_IMAGE=lock['yugabyte'],SVS15_DRAGONFLY_IMAGE=lock['dragonfly'],SVS15_APP_IMAGE=project+':local')
        stack=Stack(state,project,environment)
        try:
            run(['docker','build','--pull=false','--build-arg','SVS15_TOOLCHAIN_IMAGE='+lock['toolchain'],'--file',ROOT/'deploy/session-validation/disposable/Dockerfile','--tag',project+':local',context],env=environment,timeout=900)
            image=run(['docker','image','inspect','--format','{{.Id}}',project+':local'],env=environment).decode().strip();require(re.fullmatch(r'sha256:[a-f0-9]{64}',image),'BUILT_IMAGE_ID_REQUIRED');environment['SVS15_APP_IMAGE']=image;result['built_image']=image
            stack.compose('up','-d','--no-build','yugabyte','cache-old','smtp');stack.await_sql()
            v=json.loads((state/'private.json').read_text())
            stack.sql("alter role yugabyte password '"+v['sqlAdmin']+"';create database treehammock;",'yugabyte')
            stack.sql("do $isolate$ declare d record;begin for d in select datname from pg_database where datallowconn loop execute format('revoke all on database %I from public',d.datname);end loop;end;$isolate$;",'yugabyte')
            stack.sql((peer/'Rigging/Database/Baseline/000_canonical_database.sql').read_text())
            for p in sorted((peer/'Rigging/Database/Current').glob('*.sql')):
                if not p.name.startswith('070_'):stack.sql(p.read_text())
            provision(stack,peer,'old',v)
            old=json.loads(stack.operator('python3','/driver/native.py','cache-old'));fixture.configure(state,peer,'old',old)
            stack.controller('bootstrap');stack.compose('up','-d','--no-build','writer','svs-1','svs-2')
            # A missing peer fails the real controller. Never prune membership or
            # restore a retired identity on failure. No retry of stateful commands.
            stack.operator('python3','/driver/native.py','ready');stack.controller('isolate');result['cases'].append('complete-three-peer-isolation-and-credential-rejection')
            stack.compose('stop','writer','svs-1','svs-2');provision(stack,peer,'new',v)
            stack.compose('up','-d','--no-build','cache-new');new=json.loads(stack.operator('python3','/driver/native.py','cache-new'));require(new['run_id']!=old['run_id'],'FRESH_PRIMARY_REQUIRED')
            fixture.configure(state,peer,'new',new);stack.compose('up','-d','--no-build','--force-recreate','writer','svs-1','svs-2','caller-1','caller-2')
            stack.operator('python3','/driver/native.py','ready');stack.controller('admit-coherent');result['cases'].append('rotated-identities-fresh-primary-coherent-admission')
            result['cases']+=permission_probes(stack,v)
            for caller in ['caller-1','caller-2']:stack.compose('exec','-T',caller,'dotnet','/apps/caller/Treehammock.SessionValidation.DisposableCaller.dll','--deny-data-network')
            result['cases'].append('both-callers-data-and-controller-network-denied')
            flows=json.loads(stack.operator('python3','/driver/native.py','flows'));require(flows['status']=='Passed' and len(flows['cases'])==6,'NATIVE_CASE_INVENTORY_REFUSED');result['cases']+=flows['cases']
            stack.compose('pause','yugabyte')
            try:
                outage=json.loads(stack.operator('python3','/driver/native.py','outage'));require(outage['status']=='Passed' and len(outage['cases'])==1,'CACHE_OUTAGE_CASE_REFUSED');result['cases']+=outage['cases']
            finally:stack.compose('unpause','yugabyte')
            source_check();result.update(status='Passed',native_execution='Passed')
        except Exception as error:
            result['failure']=str(error) if isinstance(error,Refused) else 'STACK_EXECUTION_FAILED'
        finally:
            try:
                stack.compose('down','--volumes','--remove-orphans','--timeout','15');cleanup=True
                if image:run(['docker','image','rm',project+':local'],env=environment)
            except Refused:result.update(status='Failed',failure='OWNED_STACK_CLEANUP_FAILED')
            result['cleanup_complete']=cleanup
            if not cleanup:result['retained_private_workspace']=str(temp)
            save(output/'NATIVE_VALIDATION.json',result)
    finally:
        if cleanup or stack is None:shutil.rmtree(temporary)
    require(result['status']=='Passed' and cleanup,'NATIVE_STACK_NOT_PASSED');return result
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('mode',choices=['check','run']);parser.add_argument('--peer',type=Path);parser.add_argument('--images',type=Path);parser.add_argument('--output',type=Path);args=parser.parse_args()
    if args.mode=='check':
        pinned=source_check();topology=check_topology(json.loads(COMPOSE.read_text()));print(json.dumps(dict(pr='SVS-15',status='SourceChecksPassed',pinned_files=pinned,topology=topology,native_execution='NotRun',grant_rights=False,release_ready=False)));return
    require(args.peer is not None and args.images is not None and args.output is not None,'RUN_INPUTS_REQUIRED');value=native(args.peer.resolve(),images(args.images),args.output);print(json.dumps(dict(status=value['status'],native_cases=len(value['cases']),grant_rights=False,release_ready=False)))
if __name__=='__main__':
    try:main()
    except Exception as error:print(str(error) if isinstance(error,Refused) else 'DISPOSABLE_STACK_REFUSED',file=sys.stderr);sys.exit(1)
