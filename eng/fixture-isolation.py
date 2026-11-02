#!/usr/bin/env python3
"""Project-scoped fixture credentials and restricted-host prerequisites."""
import argparse,base64,json,os
from pathlib import Path
import re,secrets,shutil,stat,subprocess,sys,time
ROOT=Path(__file__).resolve().parents[1]
KEYS={'TREEHAMMOCK_FIXTURE_DB_PASSWORD','TREEHAMMOCK_FIXTURE_CACHE_PASSWORD','TREEHAMMOCK_FIXTURE_TEST_KEY','TREEHAMMOCK_FIXTURE_OUTBOX_KEY','TREEHAMMOCK_FIXTURE_OPERATION_KEY'}
def require(value,message):
    if not value:raise ValueError(message)
def check_host(mode,environment):
    if mode=='container':return
    require(mode in ('published','host','remote'),'Unknown fixture access mode')
    if mode=='remote':require(environment.get('TREEHAMMOCK_REMOTE_LAB_ACCESS')=='true','Remote lab access requires explicit opt-in and an authenticated SSH tunnel')
    cli=environment.get('TREEHAMMOCK_DOCKER_SELECTED') or environment.get('TREEHAMMOCK_DOCKER_CLI') or 'docker'
    result=subprocess.run([cli,'version','--format','{{.Server.Version}}'],capture_output=True,text=True,timeout=15,env=dict(os.environ,**environment))
    require(result.returncode==0 and re.match(r'^(\d+)\.',result.stdout) and int(result.stdout.split('.')[0])>=28,'Published fixtures require Docker Engine 28 or newer')
    context=subprocess.run([cli,'context','inspect','--format','{{.Endpoints.docker.Host}}'],capture_output=True,text=True,timeout=15,env=dict(os.environ,**environment))
    endpoint=context.stdout.strip() if environment.get('DOCKER_CONTEXT') else environment.get('DOCKER_HOST') or context.stdout.strip()
    require(context.returncode==0 and endpoint.startswith(('unix://','npipe://')),'Published fixtures require a local daemon')
    if mode=='host':
        info=subprocess.run([cli,'info','--format','{{json .}}'],capture_output=True,text=True,timeout=15,env=dict(os.environ,**environment))
        value=json.loads(info.stdout);require(info.returncode==0 and value['OSType']=='linux','Host lane requires Linux containers')
        if 'desktop' in value.get('OperatingSystem','').lower() or sys.platform!='linux':require(environment.get('TREEHAMMOCK_HOST_NETWORKING_CONFIRMED')=='true','Desktop host networking must be explicitly enabled and confirmed')
def linked(path):
    try:attributes=path.lstat()
    except FileNotFoundError:return False
    return path.is_symlink() or bool(getattr(attributes,'st_file_attributes',0)&getattr(stat,'FILE_ATTRIBUTE_REPARSE_POINT',0))
def private_windows(path,directory,environment=None):
    if os.name!='nt':return
    environment=dict(os.environ if environment is None else environment)
    selected=environment.get('TREEHAMMOCK_POWERSHELL_HOST')
    if selected:
        host=shutil.which(selected,path=environment.get('PATH'))
    else:
        host=shutil.which('pwsh.exe',path=environment.get('PATH')) or shutil.which('powershell.exe',path=environment.get('PATH'))
    require(bool(host),'Selected PowerShell ACL host unavailable')
    import csv,io
    identity=subprocess.run(['whoami','/user','/fo','csv','/nh'],capture_output=True,text=True,timeout=10)
    require(identity.returncode==0,'Cannot identify fixture file owner');sid=next(csv.reader(io.StringIO(identity.stdout)))[1]
    if directory:
        script="$ErrorActionPreference='Stop';$sid=[System.Security.Principal.SecurityIdentifier]::new($env:TREEHAMMOCK_ACL_SID);$acl=[System.Security.AccessControl.DirectorySecurity]::new();$acl.SetOwner($sid);$acl.SetAccessRuleProtection($true,$false);foreach($identity in @($sid,[System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'))){$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))};Set-Acl -LiteralPath $env:TREEHAMMOCK_ACL_PATH -AclObject $acl"
    else:
        script="$ErrorActionPreference='Stop';$sid=[System.Security.Principal.SecurityIdentifier]::new($env:TREEHAMMOCK_ACL_SID);$acl=[System.Security.AccessControl.FileSecurity]::new();$acl.SetOwner($sid);$acl.SetAccessRuleProtection($true,$false);foreach($identity in @($sid,[System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'))){$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($identity,'FullControl','Allow'))};Set-Acl -LiteralPath $env:TREEHAMMOCK_ACL_PATH -AclObject $acl"
    result=subprocess.run([host,'-NoProfile','-NonInteractive','-Command',script],env=dict(environment,TREEHAMMOCK_ACL_PATH=str(path),TREEHAMMOCK_ACL_SID=sid),capture_output=True,text=True,timeout=10)
    require(result.returncode==0,'Cannot restrict fixture ACL')

def ensure(root,environment,mode='container'):
    check_host(mode,environment)
    project=environment.get('COMPOSE_PROJECT_NAME') or re.sub(r'[^a-z0-9_-]','',root.name.lower())
    require(re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,62}',project),'Invalid fixture project identity')
    folder=root/'.docker/fixtures'/project
    # Never follow a user/sibling link into unrelated credential storage.
    for parent in [root/'.docker',root/'.docker/fixtures',folder]:
        require(not linked(parent),'Linked fixture storage rejected');parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        if os.name!='nt':
            require(parent.stat().st_uid==os.getuid(),'Fixture directory belongs to another user')
            # Only this explicitly owned fixture tree is restricted.
            parent.chmod(0o700)
    private_windows(folder,True,environment)
    file=folder/'compose.env';require(not linked(file),'Linked fixture credential file rejected')
    if not file.exists():
        lock=folder/'initializing'
        try:lock.mkdir(mode=0o700)
        except FileExistsError:
            deadline=time.monotonic()+5
            while not file.exists() and time.monotonic()<deadline:time.sleep(.05)
            require(file.exists(),'Fixture initialization incomplete; inspect owned directory before retry')
        else:
            temporary=None
            try:
                values={name:(base64.b64encode(secrets.token_bytes(32)).decode() if name.endswith('_KEY') and name not in ('TREEHAMMOCK_FIXTURE_TEST_KEY',) else secrets.token_hex(32)) for name in sorted(KEYS)}
                temporary=folder/('credentials-'+secrets.token_hex(8)+'.tmp')
                descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                with os.fdopen(descriptor,'w') as stream:stream.write(''.join(k+'='+v+'\n' for k,v in values.items()))
                temporary.replace(file)
            finally:
                if temporary is not None:temporary.unlink(missing_ok=True)
                lock.rmdir()
    require(file.is_file() and file.stat().st_nlink==1,'Missing or multiply linked fixture credentials')
    private_windows(file,False,environment)
    lines=file.read_text().splitlines();values=dict(line.split('=',1) for line in lines)
    require(len(lines)==len(KEYS) and set(values)==KEYS,'Invalid fixture credential inventory')
    for name,value in values.items():
        if name in ('TREEHAMMOCK_FIXTURE_OUTBOX_KEY','TREEHAMMOCK_FIXTURE_OPERATION_KEY'):require(len(base64.b64decode(value,validate=True))==32,'Invalid fixture crypto key')
        else:require(re.fullmatch(r'[a-f0-9]{64}',value),'Invalid fixture credential')
    if os.name!='nt':require(file.stat().st_uid==os.getuid() and file.stat().st_mode & 0o077==0,'Fixture credential permissions must be private')
    return file

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--mode',choices=['container','published','host','remote'],default='container');args=p.parse_args()
    try:print(ensure(ROOT,os.environ,args.mode));return 0
    except (OSError,ValueError,subprocess.SubprocessError):print('Fixture settings or restricted-host prerequisites failed.',file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
