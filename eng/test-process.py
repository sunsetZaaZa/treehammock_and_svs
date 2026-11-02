#!/usr/bin/env python3
"""Owned process supervisor: launch gate, Linux subreaper or Windows kill-on-close job."""
import ctypes,json,os
from pathlib import Path
import signal,subprocess,sys,time

def linux_records():
    """Resolve namespace PIDs even when /proc is mounted from an outer namespace."""
    namespace=os.readlink('/proc/self/ns/pid');records={}
    for path in Path('/proc').glob('[0-9]*'):
        try:
            if os.readlink(path/'ns/pid')!=namespace:continue
            values=dict(line.split(':',1) for line in (path/'status').read_text().splitlines() if ':' in line)
            pid=int(values['NSpid'].split()[-1]);fields=(path/'stat').read_text().rsplit(')',1)[1].split()
            records[pid]=(int(path.name),int(fields[1]),fields[19],fields[0])
        except (OSError,KeyError,ValueError,IndexError):continue
    return records

def identity(pid):
    if sys.platform.startswith('linux'):
        try:
            # Direct /proc/PID is only authoritative inside the caller namespace.
            path=Path('/proc')/str(pid);namespace=os.readlink('/proc/self/ns/pid')
            try:
                values=dict(line.split(':',1) for line in (path/'status').read_text().splitlines() if ':' in line)
                direct=int(values['NSpid'].split()[-1])==pid and os.readlink(path/'ns/pid')==namespace
            except (OSError,ValueError,KeyError):direct=False
            if direct:
                fields=(path/'stat').read_text().rsplit(')',1)[1].split()
                if fields[0]=='Z':return None
                start=fields[19]
            else:
                record=linux_records().get(pid)
                if record is None or record[3]=='Z':return None
                start=record[2]
            return 'linux:'+Path('/proc/sys/kernel/random/boot_id').read_text().strip()+':'+namespace+':'+start
        except (OSError,IndexError):return None
    if os.name=='nt':
        from ctypes import wintypes as w
        api=ctypes.WinDLL('kernel32',use_last_error=True);api.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];api.OpenProcess.restype=w.HANDLE
        handle=api.OpenProcess(0x1000,False,pid)
        if not handle:return None
        try:
            created=w.FILETIME();exit_time=w.FILETIME();kernel=w.FILETIME();user=w.FILETIME()
            api.GetProcessTimes.argtypes=[w.HANDLE,ctypes.POINTER(w.FILETIME),ctypes.POINTER(w.FILETIME),ctypes.POINTER(w.FILETIME),ctypes.POINTER(w.FILETIME)]
            if not api.GetProcessTimes(handle,ctypes.byref(created),ctypes.byref(exit_time),ctypes.byref(kernel),ctypes.byref(user)):return None
            return 'windows:'+str((created.dwHighDateTime<<32)|created.dwLowDateTime)
        finally:api.CloseHandle.argtypes=[w.HANDLE];api.CloseHandle(handle)
    return None

def terminate_windows(pid,birth):
    from ctypes import wintypes as w
    api=ctypes.WinDLL('kernel32',use_last_error=True);api.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];api.OpenProcess.restype=w.HANDLE
    handle=api.OpenProcess(0x1001,False,pid)
    if not handle:raise OSError('Cannot open owned supervisor')
    try:
        created=w.FILETIME();other=[w.FILETIME() for _ in range(3)]
        api.GetProcessTimes.argtypes=[w.HANDLE,*([ctypes.POINTER(w.FILETIME)]*4)]
        if not api.GetProcessTimes(handle,ctypes.byref(created),*(ctypes.byref(value) for value in other)):raise OSError('Cannot inspect owned supervisor')
        actual='windows:'+str((created.dwHighDateTime<<32)|created.dwLowDateTime)
        if actual!=birth:raise ValueError('Supervisor identity changed')
        api.TerminateProcess.argtypes=[w.HANDLE,w.UINT]
        if not api.TerminateProcess(handle,143):raise OSError('Cannot terminate owned supervisor')
    finally:api.CloseHandle.argtypes=[w.HANDLE];api.CloseHandle(handle)

def windows_job():
    from ctypes import wintypes as w
    class Basic(ctypes.Structure):
        _fields_=[('ProcessTime',ctypes.c_int64),('JobTime',ctypes.c_int64),('Flags',w.DWORD),('MinWorkingSet',ctypes.c_size_t),('MaxWorkingSet',ctypes.c_size_t),('ActiveProcesses',w.DWORD),('Affinity',ctypes.c_size_t),('Priority',w.DWORD),('Scheduling',w.DWORD)]
    class IO(ctypes.Structure):_fields_=[(name,ctypes.c_uint64) for name in ['ReadOperations','WriteOperations','OtherOperations','ReadBytes','WriteBytes','OtherBytes']]
    class Extended(ctypes.Structure):_fields_=[('Basic',Basic),('IO',IO),('ProcessMemory',ctypes.c_size_t),('JobMemory',ctypes.c_size_t),('PeakProcessMemory',ctypes.c_size_t),('PeakJobMemory',ctypes.c_size_t)]
    api=ctypes.WinDLL('kernel32',use_last_error=True);api.CreateJobObjectW.argtypes=[ctypes.c_void_p,w.LPCWSTR];api.CreateJobObjectW.restype=w.HANDLE
    handle=api.CreateJobObjectW(None,None)
    if not handle:raise OSError('Job creation failed')
    limits=Extended();limits.Basic.Flags=0x2000
    api.SetInformationJobObject.argtypes=[w.HANDLE,ctypes.c_int,ctypes.c_void_p,w.DWORD];api.AssignProcessToJobObject.argtypes=[w.HANDLE,w.HANDLE];api.GetCurrentProcess.restype=w.HANDLE
    if not api.SetInformationJobObject(handle,9,ctypes.byref(limits),ctypes.sizeof(limits)) or not api.AssignProcessToJobObject(handle,api.GetCurrentProcess()):
        api.CloseHandle.argtypes=[w.HANDLE];api.CloseHandle(handle);raise OSError('Owned job assignment failed')
    # Keep the handle alive until supervisor exit; closing it kills this job tree.
    return handle

def descendants(root_pid=None):
    if not sys.platform.startswith('linux'):return []
    records=linux_records();local={record[0]:pid for pid,record in records.items()}
    parents={pid:local.get(record[1]) for pid,record in records.items()}
    result=[];current={os.getpid() if root_pid is None else root_pid}
    while current:
        current={pid for pid,parent in parents.items() if parent in current and pid not in result};result+=list(current)
    return result

def signal_descendants(number):
    for pid in descendants():
        try:
            if hasattr(os,'pidfd_open') and hasattr(signal,'pidfd_send_signal'):
                birth=identity(pid);descriptor=os.pidfd_open(pid)
                try:
                    if birth and identity(pid)==birth and pid in descendants():signal.pidfd_send_signal(descriptor,number)
                finally:os.close(descriptor)
            else:os.kill(pid,number)
        except ProcessLookupError:pass

def drain_children():
    if os.name=='nt':return
    while True:
        try:
            pid,_=os.waitpid(-1,os.WNOHANG)
            if pid==0:return
        except ChildProcessError:return

def main():
    # Imported lazily to avoid an ownership/supervisor import cycle.
    import importlib.util
    root=Path(__file__).resolve().parents[1]
    spec=importlib.util.spec_from_file_location('ownership',root/'eng/test-ownership.py');owned=importlib.util.module_from_spec(spec);spec.loader.exec_module(owned)
    run=owned.joined(root,os.environ,os.environ['TREEHAMMOCK_PROCESS_LANE']);folder=owned.manifest(run).parent
    request_path=Path(os.environ['TREEHAMMOCK_PROCESS_REQUEST']);gate=Path(os.environ['TREEHAMMOCK_PROCESS_GATE']);state=Path(os.environ['TREEHAMMOCK_PROCESS_STATE'])
    for path in [request_path,gate,state]:owned.require(path.parent==folder and not owned.fixture.linked(path),'Unowned process record')
    request=json.loads(request_path.read_text());owned.require(request['role'] in ['wrapper','host-api'],'Unsupported child role')
    stopped=False;child=None;job=None
    def stop(number,frame):
        nonlocal stopped
        stopped=True
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    if os.name=='nt':signal.signal(signal.SIGBREAK,stop)
    try:
        if os.name=='nt':job=windows_job();containment='windows-job'
        elif sys.platform.startswith('linux'):
            libc=ctypes.CDLL(None,use_errno=True)
            if not hasattr(os,'pidfd_open') or not hasattr(signal,'pidfd_send_signal'):raise OSError('PID handles required for safe Linux cleanup')
            descriptor=os.pidfd_open(os.getpid());os.close(descriptor)
            if libc.prctl(36,1,0,0,0)!=0:raise OSError('Subreaper setup failed')
            containment='linux-subreaper'
        else:raise OSError('Owned process containment requires Linux or Windows')
        owned.write(state,dict(status='Ready',containment=containment))
        deadline=time.monotonic()+10
        while not gate.exists() and not stopped:
            if time.monotonic()>=deadline:raise OSError('Process launch was not committed')
            time.sleep(.02)
        if stopped:
            owned.write(state,dict(status='Stopped',exit_code=143))
            return 143
        with gate.open() as stream:permit=json.load(stream)
        owned.require(permit=={'owner':run['id'],'token':run['token']},'Invalid launch permit')
        child=subprocess.Popen(request['command'],cwd=run['checkout'],env=os.environ)
        owned.write(state,dict(status='Running',pid=child.pid,identity=identity(child.pid),containment=containment))
        while not stopped and child.poll() is None:time.sleep(.02)
        code=child.poll()
        if request['role']=='host-api' and not stopped:
            owned.write(state,dict(status='Exited',pid=child.pid,identity=identity(child.pid),exit_code=code,containment=containment))
            # Keep the tree's supervisor/identity alive for safe later cleanup.
            while not stopped:time.sleep(.02)
        deadline=time.monotonic()+4
        while time.monotonic()<deadline:
            if sys.platform.startswith('linux'):signal_descendants(signal.SIGTERM)
            elif child.poll() is None:child.terminate()
            if child.poll() is not None:
                drain_children()
                if not descendants():break
            time.sleep(.05)
        if sys.platform.startswith('linux'):
            signal_descendants(signal.SIGKILL)
            until=time.monotonic()+1
            while descendants() and time.monotonic()<until:signal_descendants(signal.SIGKILL);drain_children();time.sleep(.02)
        elif child.poll() is None:child.kill()
        try:child.wait(timeout=1)
        except subprocess.TimeoutExpired:return 1
        if sys.platform.startswith('linux') and descendants():raise OSError('Owned descendants remain')
        owned.write(state,dict(status='Stopped',exit_code=code if code is not None else 143,containment=containment))
        return (128-code if code is not None and code<0 else code) if code is not None else 143
    except (OSError,ValueError,KeyError,subprocess.SubprocessError):
        if sys.platform.startswith('linux') and child is not None:
            try:
                signal_descendants(signal.SIGKILL)
                child.wait(timeout=1)
                until=time.monotonic()+1
                while descendants() and time.monotonic()<until:signal_descendants(signal.SIGKILL);drain_children();time.sleep(.02)
            except (OSError,subprocess.SubprocessError):pass
        try:owned.write(state,dict(status='Failed',exit_code=127))
        except OSError:pass
        return 127
if __name__=='__main__':raise SystemExit(main())
