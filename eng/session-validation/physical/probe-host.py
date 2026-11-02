#!/usr/bin/env python3
"""Read-only Linux process/cgroup snapshot; never changes sysctls or host state."""
import argparse,json,os,platform,re,sys
from pathlib import Path
class Refused(RuntimeError):pass
def require(value,code):
    if not value:raise Refused(code)
def read(path,limit=1048576):
    with Path(path).open() as f:value=f.read(limit+1)
    require(len(value)<=limit,'PROBE_FILE_BOUND');return value
def inspect(pid,uid,proc=Path('/proc'),cgroups=Path('/sys/fs/cgroup')):
    require(type(pid) is int and pid>0 and type(uid) is int and uid>=1000,'OWNED_PROCESS_REQUIRED');directory=proc/str(pid);status=dict(line.split(':',1) for line in read(directory/'status').splitlines() if ':' in line)
    require(set(int(x) for x in status['Uid'].split())=={uid} and status['NoNewPrivs'].strip()=='1' and int(status['CapEff'].strip(),16)==0,'PROCESS_IDENTITY_OR_CAPABILITY_REFUSED')
    limits=read(directory/'limits');core=re.search(r'^Max core file size\s+(\S+)\s+(\S+)',limits,re.M);fds=re.search(r'^Max open files\s+(\S+)\s+(\S+)',limits,re.M)
    require(core is not None and core.group(1,2)==('0','0') and fds is not None and fds[1].isdigit() and fds[2].isdigit() and int(fds[1])<=4096 and int(fds[2])<=4096,'PROCESS_RESOURCE_LIMIT_REFUSED')
    entries=list((directory/'fd').iterdir());require(len(entries)<=4096,'OPEN_FD_BUDGET_REFUSED')
    group=read(directory/'cgroup');match=re.fullmatch(r'0::(/[^\n]*)\n?',group);require(match is not None,'CGROUP_V2_REQUIRED');relative=Path(match[1]);require('..' not in relative.parts,'CGROUP_PATH_REFUSED');base=cgroups/str(relative).lstrip('/')
    require(read(base/'memory.swap.max',128).strip()=='0','SWAP_BUDGET_REFUSED')
    memory=read(base/'memory.max',128).strip();pids=read(base/'pids.max',128).strip();cpu=read(base/'cpu.max',128).split()
    require(memory.isdigit() and 0<int(memory)<=768*1024*1024 and pids.isdigit() and 0<int(pids)<=256 and len(cpu)==2 and all(x.isdigit() for x in cpu) and int(cpu[1])>0 and 0<int(cpu[0])<=2*int(cpu[1]),'CGROUP_CEILING_REFUSED')
    return dict(status='ScopedProcessLimitsPassed',open_fds=len(entries),fd_limit=int(fds[2]),memory_max_bytes=int(memory),pids_max=int(pids),cpu_quota_cores=round(int(cpu[0])/int(cpu[1]),3),kernel=platform.release(),network_firewall='NotRun',tls_alpn='NotRun',key_ownership='NotRun',full_physical_qualification='NotRun',grant_rights=False,release_ready=False)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--pid',type=int,required=True);p.add_argument('--uid',type=int,required=True);a=p.parse_args();print(json.dumps(inspect(a.pid,a.uid)))
if __name__=='__main__':
    try:main()
    except Exception as e:print(json.dumps(dict(status='Refused',code=str(e) if isinstance(e,Refused) else 'HOST_PROBE_FAILED')));sys.exit(1)
