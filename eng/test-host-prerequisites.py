#!/usr/bin/env python3
"""Actual selected PowerShell version/lock-audit checks with controlled Docker/SDK replies."""
import argparse,importlib.util,json,os,shutil,subprocess,sys,tempfile
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'eng/tests'))
from test_host_prerequisites import HostPrerequisites,pre,owned

def run(host):
    cases=[];fixture=HostPrerequisites();fixture.setUp()
    try:
        real_run=subprocess.run;real_which=shutil.which
        env=dict(fixture.env,TREEHAMMOCK_HOST_NETWORKING_CONFIRMED='true')
        def resolve(name,**kwargs):
            if name==host:return real_which(name,**kwargs)
            return '/controlled/'+name
        def invoke(argv,**kwargs):
            if argv[0]==host:return real_run(argv,**kwargs)
            return fixture.response(argv,**kwargs)
        with patch.object(pre.shutil,'which',side_effect=resolve),patch.object(pre.subprocess,'run',side_effect=invoke):
            selected=pre.check(fixture.root,'docker-host-system-stack-tests.ps1',host,env,owned.Deadline(30))
            assert selected['TREEHAMMOCK_POWERSHELL_HOST']==host
            cases.append(dict(name='selected_native_host_and_real_lock_audit_in_space_checkout',status='Passed'))
            (fixture.root/'eng/check-locks.ps1').write_text('exit 47\n')
            try:pre.check(fixture.root,'docker-host-system-stack-tests.ps1',host,env,owned.Deadline(30))
            except pre.Failure as error:assert error.code==47
            else:raise AssertionError('Native lock failure accepted')
            assert not (fixture.root/'.docker').exists() and not (fixture.root/'artifacts').exists()
            cases.append(dict(name='native_child_47_retained_before_acquisition',status='Passed'))
        if os.name=='nt':
            # Real CMD, actual selected host and Python; deliberately missing Docker.
            launch_env=dict(os.environ,TREEHAMMOCK_POWERSHELL_HOST=host,TREEHAMMOCK_DOCKER_CLI=str(fixture.root/'absent docker.exe'))
            def cmd(environment,arguments=()):
                command='cmd.exe /d /s /c "'+subprocess.list2cmdline([str(fixture.root/'eng/docker-host-system-stack-tests.cmd'),*arguments])+'"'
                return real_run(command,cwd=fixture.root,env=environment,capture_output=True,text=True,timeout=30)
            result=cmd(launch_env)
            assert result.returncode==127 and not (fixture.root/'.docker').exists()
            cases.append(dict(name='real_cmd_forwards_selected_host_127_without_acquisition',status='Passed'))
            receipt=fixture.root/'selected host receipt.json'
            (fixture.root/'eng/docker-host-system-stack-tests.ps1').write_text("param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Rest)\n@{host=[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName;args=@($Rest)} | ConvertTo-Json -Compress | Set-Content -LiteralPath $env:TREEHAMMOCK_HOST_RECEIPT\nexit 47\n")
            launch_env['TREEHAMMOCK_HOST_RECEIPT']=str(receipt)
            result=cmd(launch_env,['argument with spaces','second argument'])
            assert result.returncode==47
            value=json.loads(receipt.read_text(encoding='utf-8-sig'))
            assert os.path.normcase(value['host'])==os.path.normcase(host) and value['args']==['argument with spaces','second argument']
            cases.append(dict(name='real_cmd_keeps_selected_host_space_arguments_and_exit_47',status='Passed'))
            launch_env['TREEHAMMOCK_POWERSHELL_HOST']=str(fixture.root/'missing host.exe')
            assert cmd(launch_env).returncode==127
            cases.append(dict(name='real_cmd_explicit_missing_host_never_falls_back',status='Passed'))
    finally:fixture.tearDown()
    return cases

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--host');parser.add_argument('--require-native',action='store_true');args=parser.parse_args()
    host=args.host or os.environ.get('TREEHAMMOCK_POWERSHELL_HOST') or shutil.which('pwsh') or (shutil.which('powershell.exe') if os.name=='nt' else None)
    host=str(Path(shutil.which(host) or host).resolve()) if host else None
    value=dict(status='NotRun',qualification='NotRun',cases=[],reason='Actual supported PowerShell unavailable',scope='Actual PowerShell version and lock child, Windows CMD if available; controlled Docker/SDK replies, not native application qualification')
    code=2 if args.require_native and not host else 0
    if host:
        try:value.update(status='Passed',qualification='Partial',cases=run(host),reason='Native selected-host checks only; full Docker/.NET/Windows matrix remains required')
        except (AssertionError,OSError,ValueError,subprocess.SubprocessError):value.update(status='Failed',reason='Native selected-host check failed');code=1
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(value,indent=2)+'\n');print(value['status']);return code
if __name__=='__main__':raise SystemExit(main())
