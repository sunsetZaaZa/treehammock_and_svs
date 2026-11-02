#!/usr/bin/env python3
"""Actual disposable Compose/Bruno/SDK proof; no native success substitute."""
import argparse,json,os
from pathlib import Path
import shutil,subprocess,tempfile,uuid
ROOT=Path(__file__).resolve().parents[1]
IGNORE=shutil.ignore_patterns('.git','.docker','bin','obj','artifacts','.artifacts','.correction-results','TestResults','__pycache__','node_modules')
def execute(output):
    report=dict(schema_version=1,qualification='NotRun',cases=[],cleanup=dict(status='NotRequired'),scope='Actual container lanes; hosted scheduling and host-process identity remain separate')
    output.parent.mkdir(parents=True,exist_ok=True)
    if not shutil.which('docker'):
        report['reason']='Docker/Compose and real SDK/Node/Bruno container resources required';output.write_text(json.dumps(report,indent=2)+'\n');return 2
    project='treehammock-cor23w-'+str(uuid.uuid4());configuration=None;primary=0;fixture_env=dict(os.environ,COMPOSE_PROJECT_NAME=project)
    def command(args,expected=0,timeout=1800):
        result=subprocess.run(['docker',*args],capture_output=True,text=True,timeout=timeout,env=fixture_env)
        if expected is not None and result.returncode!=expected:raise RuntimeError('Native Compose stage returned unexpected status')
        return result
    with tempfile.TemporaryDirectory(prefix='treehammock-cor23w-native-') as temporary:
        root=Path(temporary)/'source';shutil.copytree(ROOT,root,ignore=IGNORE)
        for script in (root/'eng').glob('*.sh'):script.chmod(script.stat().st_mode | 0o111)
        (root/'artifacts/compose-proof').mkdir(parents=True)
        try:
            import importlib.util
            spec=importlib.util.spec_from_file_location('fixture_settings',root/'eng/fixture-isolation.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            file=module.ensure(root,fixture_env,'container');fixture_env.update(dict(line.split('=',1) for line in file.read_text().splitlines()))
            info=json.loads(command(['info','--format','{{json .}}']).stdout)
            if info['OSType']!='linux':raise RuntimeError('Linux container daemon required')
            args=['compose','-p',project]
            for name in ['docker-compose.integration.yml','docker-compose.api-proxy.yml','docker-compose.testing.yml','docker-compose.ci-system.yml']:args+=['-f',str(root/name)]
            for profile in ['proxy','http','http-proxy','system']:args+=['--profile',profile]
            value=json.loads(command(args+['config','--format','json']).stdout)
            # Private qualification fixture only: omit host publications without
            # changing the shared source's COR23X/Y lifecycle/network contracts.
            secret=str(uuid.uuid4());password=str(uuid.uuid4())
            for service in value['services'].values():service.pop('ports',None)
            value['services']['postgres']['environment']['POSTGRES_PASSWORD']=password
            value['services']['api']['environment'].update(DatabaseSettings__password=password,SystemTestSettings__TestKey=secret)
            value['services']['system-tests']['environment']['TREEHAMMOCK_SYSTEM_TEST_KEY']=secret
            for service in ['system-tests','http-contract-tests-direct','http-contract-tests-proxy']:
                value['services'][service]['environment'].update(TREEHAMMOCK_COMPOSE_READY_TIMEOUT_MS='60000',TREEHAMMOCK_COMPOSE_ATTEMPT_TIMEOUT_MS='2000')
            value['services']['hung']={'image':'node:22-alpine','command':['node','-e',"require('http').createServer(()=>{}).listen(8088,'0.0.0.0')"]}
            configuration=root/'native-compose.json';configuration.write_text(json.dumps(value))
            compose=['compose','-p',project,'-f',str(configuration)]
            command(compose+['up','--detach','--build','api','haproxy','hung'])
            for service in ['http-contract-tests-direct','http-contract-tests-proxy','system-tests']:
                command(compose+['run','--rm',service]);report['cases'].append(dict(case='actual-success',service=service,status='Passed'))
            original_node=(root/'eng/compose-http-proof.mjs').read_text();original_system=(root/'eng/compose-system-proof.sh').read_text()
            def negative(service,label,expected=2,environment=None):
                extras=[]
                for name,val in (environment or {}).items():extras+=['--env',name+'='+val]
                command(compose+['run','--rm',*extras,service],expected=expected)
                report['cases'].append(dict(case=label,service=service,status='Passed',observed_exit=expected))
            for service,variable in [('http-contract-tests-direct','TREEHAMMOCK_BASE_URL'),('system-tests','TREEHAMMOCK_SYSTEM_BASE_URL')]:
                negative(service,'actual-hung-readiness',environment={variable:'http://hung:8088','TREEHAMMOCK_COMPOSE_READY_TIMEOUT_MS':'400','TREEHAMMOCK_COMPOSE_ATTEMPT_TIMEOUT_MS':'100'})
            node=root/'eng/compose-http-proof.mjs'
            node.write_text(original_node.replace("command('npm',['install'","command('sh',['-c','exit 47','install'",1))
            negative('http-contract-tests-direct','actual-install-failure',47);node.write_text(original_node)
            collection=root/'tests/http/bruno/treehammock/bruno.json';saved=collection.read_bytes();collection.unlink()
            try:negative('http-contract-tests-direct','actual-missing-collection')
            finally:collection.write_bytes(saved)
            system=root/'eng/compose-system-proof.sh'
            for prefix,label in [('dotnet restore treehammock.Tests.System/','restore'),('dotnet build treehammock.Tests.System/','build'),('dotnet test treehammock.Tests.System/','tests')]:
                lines=original_system.splitlines();lines=["bash -c 'exit 47'" if line.startswith(prefix) else line for line in lines];system.write_text('\n'.join(lines)+'\n')
                negative('system-tests','actual-'+label+'-failure',47);system.write_text(original_system)
            lines=original_system.splitlines();lines=['true # private missing-result mutation' if line.startswith('dotnet test treehammock.Tests.System/') else line for line in lines]
            system.write_text('\n'.join(lines)+'\n');negative('system-tests','actual-missing-fresh-trx');system.write_text(original_system)
            report['qualification']='Passed'
        except (RuntimeError,OSError,ValueError,KeyError,subprocess.SubprocessError):
            primary=1;report.update(qualification='Failed',reason='Actual Compose/Bruno/SDK qualification failed; no native pass inferred')
        finally:
            if configuration:
                try:
                    result=command(['compose','-p',project,'-f',str(configuration),'down','--volumes','--remove-orphans','--rmi','local'],expected=None,timeout=60)
                    report['cleanup']=dict(status='Passed' if result.returncode==0 else 'Failed',project=project)
                    if result.returncode:primary=1;report['qualification']='Failed'
                except (RuntimeError,OSError,subprocess.SubprocessError):primary=1;report['qualification']='Failed';report['cleanup']=dict(status='Failed',project=project)
            output.write_text(json.dumps(report,indent=2)+'\n')
    return primary
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,default=ROOT/'.correction-results/cor23w-compose.json');args=parser.parse_args();raise SystemExit(execute(args.output.resolve()))
