#!/usr/bin/env python3
"""Run the combined SVS/Backup scoped suite; invoke with a .NET 10 SDK selected."""
import argparse,os,subprocess
from pathlib import Path
root=Path(__file__).resolve().parents[2];backup=root.parent/'contact-backup'
a=argparse.ArgumentParser();a.add_argument('--dotnet',default='dotnet');a.add_argument('--evidence',type=Path,required=True);v=a.parse_args()
if not (backup/'ContactBackup.slnx').is_file():raise SystemExit('Verified sibling Backup source required')
v.evidence.mkdir(parents=True,exist_ok=True);env=dict(os.environ,DOTNET_PROCESSOR_COUNT='4',MSBUILDDISABLENODEREUSE='1')
def run(args,name):
 with (v.evidence/name).open('w') as f:subprocess.run([v.dotnet,*map(str,args)],cwd=root.parent.parent,env=env,stdout=f,stderr=subprocess.STDOUT,check=True)
p=root/'tests/Treehammock.SessionValidation.HostTests/Treehammock.SessionValidation.HostTests.csproj'
run(['restore',p,'--locked-mode','--disable-parallel','-m:1','-p:NuGetAudit=false'],'restore.log');run(['build',p,'--no-restore','-m:1'],'build.log');run([p.parent/'bin/Debug/net10.0/Treehammock.SessionValidation.HostTests.dll','-xml',v.evidence.resolve()/'host-tests.xml'],'host-tests.log')
run(['restore',backup/'ContactBackup.slnx','--locked-mode','--disable-parallel','-m:1','-p:NuGetAudit=false'],'backup-restore.log');run(['build',backup/'ContactBackup.slnx','--no-restore','-m:1'],'backup-build.log')
for project in sorted((backup/'tests').glob('Backup.*.Tests')):run([project/'bin/Debug/net10.0'/f'{project.name}.dll'],project.name+'.log')
print('Scoped combined suite passed; native/physical acceptance NotRun.')
