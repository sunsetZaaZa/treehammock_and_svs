#!/usr/bin/env python3
"""Source consistency only; executable preflight and native host tests are separate."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def validate(root=ROOT):
    ownership=(root/'eng/test-ownership.py').read_text();host=(root/'eng/docker-host-system-stack-tests.ps1').read_text();acl=(root/'eng/fixture-isolation.py').read_text();cmd=(root/'eng/docker-host-system-stack-tests.cmd').read_text()
    assert ownership.index('environment=prerequisites.check(')<ownership.index('create_run(root,lane,environment,on_created=prepared)')
    assert "-FilePath 'powershell.exe'" not in host
    assert '-FilePath $selectedHost -Arguments $lockArguments' in host
    assert '[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName' in host
    assert "[host,'-NoProfile'" in acl and "TREEHAMMOCK_POWERSHELL_HOST" in acl
    assert 'if defined TREEHAMMOCK_POWERSHELL_HOST' in cmd and 'exit /b %ERRORLEVEL%' in cmd
    return dict(status='SourceConsistent',qualification='NotRun')
if __name__=='__main__':print(json.dumps(validate()))
