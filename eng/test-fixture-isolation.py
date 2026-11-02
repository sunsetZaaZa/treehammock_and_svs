#!/usr/bin/env python3
"""Owned COR23X Docker/render/auth/peer matrix. External host qualification stays explicit."""
import argparse,importlib.util,itertools,json,os
from pathlib import Path
import shutil,socket,subprocess,tempfile,time,uuid
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('fixture_settings',ROOT/'eng/fixture-isolation.py');settings=importlib.util.module_from_spec(spec);spec.loader.exec_module(settings)
def execute(output,host_route=False):
    report=dict(schema_version=1,qualification='NotRun',cases=[],cleanup=[],pending=['External unrelated IPv4/IPv6/L2 peer denial on each supported Engine/Desktop host','Authenticated SSH tunnel success and denial from another lab host','Existing host application runner and simultaneous host-port collision qualification (COR23Y/AA/AB)'])
    output.parent.mkdir(parents=True,exist_ok=True)
    def save():output.write_text(json.dumps(report,indent=2)+'\n')
    if not shutil.which('docker'):
        report['reason']='Docker/Compose unavailable; zero native cases executed';save();return 2
    projects=[];peer='treehammock-cor23x-peer-'+str(uuid.uuid4());peer_created=False;primary=0
    def command(args,environment=None,expected=0,timeout=1800):
        result=subprocess.run(['docker',*args],capture_output=True,text=True,env=environment,timeout=timeout)
        if expected is not None and result.returncode!=expected:raise ValueError('Native fixture stage failed; captured output is private')
        return result
    def passed(name,**values):report['cases'].append(dict(case=name,status='Passed',**values))
    def node(network,url,key=None,expected=None):
        script="""const http=require('http');const request=http.get(process.env.PROBE_URL,{headers:process.env.PROBE_KEY?{'X-System-Test-Key':process.env.PROBE_KEY}:{}},r=>{r.resume();process.exit(r.statusCode===Number(process.env.PROBE_EXPECTED)?0:3)});request.setTimeout(2000,()=>request.destroy());request.on('error',()=>process.exit(process.env.PROBE_EXPECTED==='denied'?0:4));setTimeout(()=>process.exit(process.env.PROBE_EXPECTED==='denied'?0:5),3000);"""
        args=['run','--rm','--network',network,'--env','PROBE_URL='+url,'--env','PROBE_EXPECTED='+str(expected)]
        if key:args+=['--env','PROBE_KEY='+key]
        command(args+['node:22-alpine','node','-e',script],timeout=30)
    with tempfile.TemporaryDirectory(prefix='treehammock-cor23x-native-') as temporary:
        root=Path(temporary)/'source';shutil.copytree(ROOT,root,ignore=shutil.ignore_patterns('.git','.docker','bin','obj','artifacts','.artifacts','.correction-results','TestResults','__pycache__','node_modules'))
        try:
            settings.check_host('published',os.environ)
            command(['info']);command(['network','create',peer],timeout=30);peer_created=True
            for index in range(2):
                project='treehammock-cor23x-'+str(uuid.uuid4());env=dict(os.environ,COMPOSE_PROJECT_NAME=project)
                file=settings.ensure(root,env);env.update(dict(line.split('=',1) for line in file.read_text().splitlines()))
                compose=['compose','-p',project,'-f',str(root/'docker-compose.integration.yml'),'-f',str(root/'docker-compose.api-proxy.yml'),'-f',str(root/'docker-compose.testing.yml'),'--profile','proxy']
                projects.append((compose,env,project))
                overlays=['docker-compose.host-access.yml','docker-compose.proxy-access.yml','docker-compose.api-direct.yml']
                for count in range(4):
                    for selected in itertools.combinations(overlays,count):
                        arguments=compose[:]
                        for name in selected:arguments+=['-f',str(root/name)]
                        value=json.loads(command(arguments+['config','--format','json'],env).stdout)
                        ports=[port for service in value['services'].values() for port in service.get('ports',[])]
                        if not selected:settings.require(not ports,'Default profiles published a port')
                        settings.require(all(port.get('host_ip')=='127.0.0.1' for port in ports),'Merged wildcard/IPv6 publication')
                        passed('rendered-profile-union',project_index=index,overlays=list(selected),published_ports=[dict(host_ip=p['host_ip'],target=p['target'],published=p.get('published')) for p in ports])
                command(compose+['up','--detach','--build','--wait','--wait-timeout','180','api','haproxy'],env)
                network=project+'_default'
                command(compose+['exec','-T','--env','PGPASSWORD='+env['TREEHAMMOCK_FIXTURE_DB_PASSWORD'],'postgres','psql','-h','127.0.0.1','-U','treehammock','-d','treehammock','-c','SELECT 1'],env,timeout=30)
                wrong=command(compose+['exec','-T','--env','PGPASSWORD=wrong','postgres','psql','-h','127.0.0.1','-U','treehammock','-d','treehammock','-c','SELECT 1'],env,expected=None,timeout=30);settings.require(wrong.returncode!=0,'Wrong SQL password accepted')
                cache=command(compose+['exec','-T','--env','REDISCLI_AUTH='+env['TREEHAMMOCK_FIXTURE_CACHE_PASSWORD'],'dragonfly','redis-cli','ping'],env,timeout=30);settings.require(cache.stdout.strip()=='PONG','Cache password unusable')
                wrong=command(compose+['exec','-T','--env','REDISCLI_AUTH=wrong','dragonfly','redis-cli','ping'],env,expected=None,timeout=30);settings.require('PONG' not in wrong.stdout,'Wrong cache credential accepted')
                passed('state-password-acceptance-and-denial',project_index=index)
                # Readiness is retryable; capability responses are exact and not retried into success.
                deadline=time.monotonic()+90
                while True:
                    try:node(network,'http://api:5001/health/ready',expected=200);break
                    except (ValueError,subprocess.SubprocessError):
                        if time.monotonic()>=deadline:raise
                        time.sleep(.5)
                path='http://haproxy:8080/__system-test/deliveries/latest'
                for key in [None,'wrong',env['TREEHAMMOCK_FIXTURE_TEST_KEY']]:node(network,path,key,401 if key!=env['TREEHAMMOCK_FIXTURE_TEST_KEY'] else 400)
                passed('actual-per-project-inspection-key',project_index=index)
                container=command(compose+['ps','--quiet','api'],env).stdout.strip()
                info=json.loads(command(['inspect',container]).stdout)[0];settings.require(not info['HostConfig'].get('PortBindings'),'Default API published a host port')
                address=info['NetworkSettings']['Networks'][network]['IPAddress'];node(peer,'http://'+address+':5001/health/ready',expected='denied');passed('unrelated-bridge-peer-denied',project_index=index)
            first,second=projects[0][1],projects[1][1]
            settings.require(all(first[key]!=second[key] for key in settings.KEYS),'Parallel project keys were reused')
            node(projects[1][2]+'_default','http://api:5001/__system-test/deliveries/latest',first['TREEHAMMOCK_FIXTURE_TEST_KEY'],401);passed('parallel-project-state-network-and-key-separation')
            compose,env,_=projects[0]
            # A privileged Testing overlay carried into Production must fail startup.
            production=root/'production-denial.json';production.write_text(json.dumps({'services':{'api':{'environment':{'DOTNET_ENVIRONMENT':'Production','ASPNETCORE_ENVIRONMENT':'Production'}}}}))
            attempt=command(compose+['-f',str(production),'up','--detach','--wait','--wait-timeout','45','api'],env,expected=None,timeout=90)
            settings.require(attempt.returncode!=0,'Production accepted privileged fixture configuration')
            logs=command(compose+['logs','--no-color','api'],env).stdout
            settings.require('Test capabilities require the dedicated Testing environment.' in logs,'Production failure did not prove capability rejection');passed('production-rejects-testing-capabilities')
            # Real restricted host publications use OS-selected ephemeral ports in this owned fixture.
            state=root/'published-state.json';state.write_text(json.dumps({'services':{'postgres':{'ports':[{'target':5432,'published':'0','host_ip':'127.0.0.1'}]},'dragonfly':{'ports':[{'target':6379,'published':'0','host_ip':'127.0.0.1'}]}}}))
            command(compose+['-f',str(state),'up','--detach','--wait','postgres','dragonfly'],env)
            for service,port in [('postgres',5432),('dragonfly',6379)]:
                container=command(compose+['ps','--quiet',service],env).stdout.strip();info=json.loads(command(['inspect',container]).stdout)[0]
                bindings=info['NetworkSettings']['Ports'][str(port)+'/tcp'];settings.require(bindings and all(b['HostIp']=='127.0.0.1' for b in bindings),'Runtime port binding escaped loopback')
                with socket.create_connection(('127.0.0.1',int(bindings[0]['HostPort'])),timeout=3):pass
            passed('actual-loopback-state-publications-and-local-usability')
            if host_route:
                settings.check_host('host',os.environ)
                from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
                import threading,urllib.request
                class Handler(BaseHTTPRequestHandler):
                    def do_GET(self):self.send_response(200);self.end_headers()
                    def log_message(self,*args):pass
                server=ThreadingHTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever);thread.start()
                with socket.socket() as probe:probe.bind(('127.0.0.1',0));proxy_port=probe.getsockname()[1]
                cfg=root/'host-probe.cfg';cfg.write_text((root/'deploy/haproxy/haproxy.host-system.cfg').read_text().replace('127.0.0.1:8080','127.0.0.1:'+str(proxy_port)).replace('127.0.0.1:5001','127.0.0.1:'+str(server.server_port)))
                name='treehammock-cor23x-host-'+str(uuid.uuid4())
                try:
                    command(['run','--detach','--name',name,'--network','host','--volume',str(cfg)+':/usr/local/etc/haproxy/haproxy.cfg:ro','haproxy:latest'],timeout=120)
                    deadline=time.monotonic()+15
                    while True:
                        try:
                            with urllib.request.urlopen('http://127.0.0.1:'+str(proxy_port)+'/health/ready',timeout=2) as response:settings.require(response.status==200,'Host route unavailable')
                            break
                        except OSError:
                            if time.monotonic()>=deadline:raise
                            time.sleep(.2)
                    passed('actual-loopback-proxy-to-owned-host-backend')
                finally:
                    try:
                        removal=command(['rm','--force',name],expected=None,timeout=30);settings.require(removal.returncode==0,'Owned host proxy cleanup failed')
                    finally:server.shutdown();thread.join(timeout=5);server.server_close()
            else:report['pending'].append('Host route: rerun with --host-route on Engine/Linux or opted-in Desktop')
            report['qualification']='Partial';report['reason']='Local native cases passed; external peer/SSH/supported-host matrix still required'
        except (OSError,ValueError,KeyError,subprocess.SubprocessError):
            primary=1;report.update(qualification='Failed',reason='Native isolation stage failed; no source or simulated native pass inferred')
        finally:
            for compose,env,project in reversed(projects):
                try:result=command(compose+['down','--volumes','--remove-orphans','--rmi','local'],env,expected=None,timeout=60);ok=result.returncode==0
                except (OSError,subprocess.SubprocessError):ok=False
                report['cleanup'].append(dict(project=project,status='Passed' if ok else 'Failed'))
                if not ok:primary=1;report['qualification']='Failed'
            if peer_created:
                try:ok=command(['network','rm',peer],expected=None,timeout=30).returncode==0
                except (OSError,subprocess.SubprocessError):ok=False
                report['cleanup'].append(dict(resource='owned peer network',status='Passed' if ok else 'Failed'))
                if not ok:primary=1;report['qualification']='Failed'
            save()
    return primary or 2
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,default=ROOT/'.correction-results/cor23x-isolation.json');parser.add_argument('--host-route',action='store_true');args=parser.parse_args();raise SystemExit(execute(args.output.resolve(),args.host_route))
