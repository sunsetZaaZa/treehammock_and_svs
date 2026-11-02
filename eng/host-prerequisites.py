#!/usr/bin/env python3
"""Read-only host-lane checks. No fixture, credential, process broker or Docker acquisition."""
import csv,io,json,os,re,shutil,subprocess,sys
from pathlib import Path

class Failure(ValueError):
    def __init__(self,stage,code=2):
        super().__init__('Host prerequisite failed: '+stage)
        self.code=code

def executable(name,environment,stage):
    selected=shutil.which(name,path=environment.get('PATH'))
    if not selected:raise Failure(stage+' executable unavailable',127)
    return str(Path(selected).resolve())

def check(root,entry,shell,environment,deadline):
    env=dict(environment)
    if sys.version_info<(3,10):raise Failure('Python 3.10 or newer required')
    if sys.platform not in ('linux','win32') or env.get('WSL_INTEROP') or env.get('WSL_DISTRO_NAME'):
        raise Failure('supported native Linux or Windows host required; use the container lane')
    if sys.platform=='linux':
        if not hasattr(os,'pidfd_open'):raise Failure('Linux PID handles unavailable')
        try:handle=os.pidfd_open(os.getpid());os.close(handle)
        except OSError:raise Failure('Linux kernel PID handles unavailable') from None
    shell=executable(shell,env,'selected shell')
    def command(stage,argv,command_environment=None):
        try:result=subprocess.run(argv,cwd=root,env=env if command_environment is None else command_environment,capture_output=True,text=True,timeout=deadline.left())
        except (subprocess.TimeoutExpired,ValueError):raise Failure(stage+' exceeded startup budget',124) from None
        except OSError:raise Failure(stage+' executable unavailable',127) from None
        if result.returncode:raise Failure(stage,128-result.returncode if result.returncode<0 else result.returncode)
        return result.stdout.strip()
    if entry.endswith('.ps1'):
        version=command('selected PowerShell host',[shell,'-NoLogo','-NoProfile','-NonInteractive','-Command',"$PSVersionTable | Select-Object PSEdition,@{n='Major';e={$_.PSVersion.Major}},@{n='Minor';e={$_.PSVersion.Minor}} | ConvertTo-Json -Compress"])
        try:value=json.loads(version);major=int(value['Major']);minor=int(value['Minor']);edition=value['PSEdition']
        except (ValueError,TypeError,KeyError):raise Failure('selected PowerShell returned invalid version') from None
        if not (edition=='Core' and major>=7 or sys.platform=='win32' and edition=='Desktop' and (major,minor)>=(5,1)):
            raise Failure('PowerShell 7+ or Windows PowerShell 5.1 required')
        env['TREEHAMMOCK_POWERSHELL_HOST']=shell
        audit=[shell,'-NoLogo','-NoProfile','-NonInteractive']
        if sys.platform=='win32':audit+=['-ExecutionPolicy','Bypass']
        audit+=['-File',str(root/'eng/check-locks.ps1')]
    else:
        if sys.platform!='linux':raise Failure('Bash host lane requires native Linux; use PowerShell on Windows')
        major=command('selected Bash host',[shell,'-c','printf "%s" "$BASH_VERSINFO"'])
        if not major.isdigit() or int(major)<4:raise Failure('Bash 4 or newer required')
        for tool in ('find','sort','grep'):executable(tool,env,'lock audit '+tool)
        audit=[shell,str(root/'eng/check-locks.sh')]
    docker=executable(env.get('TREEHAMMOCK_DOCKER_SELECTED') or env.get('TREEHAMMOCK_DOCKER_CLI') or 'docker',env,'Docker')
    sdk=executable('dotnet',env,'.NET')
    env['TREEHAMMOCK_DOCKER_SELECTED']=docker
    env['TREEHAMMOCK_DOCKER_CLI']=docker
    if not env.get('DOCKER_HOST') and not env.get('DOCKER_CONTEXT'):
        name=command('Docker context',[docker,'context','show'])
        if not name or '\n' in name or '\r' in name:raise Failure('invalid Docker context')
        env['DOCKER_CONTEXT']=name
    version=command('Docker Engine',[docker,'version','--format','{{.Server.Version}}'])
    if not re.match(r'^(\d+)\.',version) or int(version.split('.')[0])<28:raise Failure('Docker Engine 28+ required')
    endpoint=command('Docker endpoint',[docker,'context','inspect','--format','{{.Endpoints.docker.Host}}'])
    endpoint=endpoint if env.get('DOCKER_CONTEXT') else env.get('DOCKER_HOST') or endpoint
    if not endpoint.startswith(('unix://','npipe://')):raise Failure('local Docker daemon required')
    raw_info=command('Docker daemon',[docker,'info','--format','{{json .}}'])
    try:info=json.loads(raw_info)
    except ValueError:raise Failure('invalid Docker daemon response') from None
    if not isinstance(info,dict) or info.get('OSType')!='linux':raise Failure('Linux containers required')
    if (sys.platform=='win32' or 'desktop' in info.get('OperatingSystem','').lower()) and env.get('TREEHAMMOCK_HOST_NETWORKING_CONFIRMED')!='true':
        raise Failure('Docker Desktop host networking requires explicit TREEHAMMOCK_HOST_NETWORKING_CONFIRMED=true')
    compose=command('Docker Compose',[docker,'compose','version','--short']).lstrip('v')
    if not re.match(r'^2\.',compose):raise Failure('Docker Compose v2 required')
    sdks=command('.NET SDK',[sdk,'--list-sdks'])
    if not any(re.match(r'^(\d+)\.',line) and int(line.split('.')[0])>=8 for line in sdks.splitlines()):raise Failure('.NET SDK 8+ required')
    runtimes=command('.NET runtime',[sdk,'--list-runtimes'])
    for runtime in ('Microsoft.NETCore.App','Microsoft.AspNetCore.App'):
        if not re.search(r'^'+re.escape(runtime)+r' 8\.',runtimes,re.M):raise Failure(runtime+' 8.x required')
    if sys.platform=='win32':
        owner=executable('whoami',env,'Windows ACL owner')
        identity=command('Windows ACL owner',[owner,'/user','/fo','csv','/nh'])
        try:sid=next(csv.reader(io.StringIO(identity)))[1]
        except (StopIteration,IndexError):raise Failure('Windows owner SID unavailable') from None
        if not re.fullmatch(r'S-1-[0-9-]+',sid):raise Failure('Windows owner SID invalid')
    for name in ('docker-compose.local-system.yml','eng/test-ownership-compose.json','deploy/haproxy/haproxy.host-system.cfg','treehammock.csproj','treehammock.Tests.System/treehammock.Tests.System.csproj','Rigging/Database/Baseline/000_treehammock_canonical_database.sql'):
        if not (root/name).is_file():raise Failure('required host configuration missing: '+name)
    try:
        value=json.loads((root/'eng/test-ownership-compose.json').read_text())
        if not all(name in value['host']['services'] for name in ('postgres','dragonfly','haproxy-host')):raise ValueError()
    except (ValueError,KeyError,TypeError):raise Failure('invalid host ownership configuration') from None
    render=command('host Compose configuration',[docker,'compose','-f',str(root/'docker-compose.local-system.yml'),'--profile','host-system','config','--format','json'],dict(env,TREEHAMMOCK_FIXTURE_DB_PASSWORD='preflight-placeholder',TREEHAMMOCK_FIXTURE_CACHE_PASSWORD='preflight-placeholder'))
    try:
        graph=json.loads(render)
        if not all(name in graph['services'] for name in ('postgres','dragonfly','haproxy-host')):raise ValueError()
    except (ValueError,KeyError,TypeError):raise Failure('invalid host Compose configuration') from None
    # A child of the exact selected shell keeps check-locks' exit scoped to the audit.
    command('host lock audit',audit)
    try:deadline.left()
    except ValueError:raise Failure('startup budget expired',124) from None
    return env
