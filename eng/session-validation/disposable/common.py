"""Private disposable-fixture operations; never interpolate target output in errors."""
import hashlib,json,os,re,socket,ssl,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
PEER_SHA256='364de19c8a5c65d82e79bbb22f745effeb59281d97a2dd10ae4b8e1d3a5d41b0'
class Refused(RuntimeError): pass
def require(value,code):
    if not value: raise Refused(code)
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def save(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,indent=2)+'\n');path.chmod(0o600)
def run(args,*,data=None,cwd=None,env=None,timeout=180):
    try:r=subprocess.run([str(x) for x in args],input=data,capture_output=True,cwd=cwd,env=env,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired): raise Refused('PROCESS_UNAVAILABLE_OR_TIMED_OUT') from None
    require(r.returncode==0,'CHILD_PROCESS_FAILED');return r.stdout
def images(path):
    p=Path(path);require(p.is_file() and p.stat().st_size<8192,'IMAGE_LOCK_REQUIRED');v=json.loads(p.read_text())
    require(set(v)=={'toolchain','yugabyte','dragonfly','dragonflyVersion'},'IMAGE_LOCK_FIELDS')
    for k in ['toolchain','yugabyte','dragonfly']:
        require(re.fullmatch(r'[a-zA-Z0-9._:/-]+@sha256:[a-f0-9]{64}',v[k]) is not None,'IMMUTABLE_IMAGE_REQUIRED')
    require(re.fullmatch(r'[A-Za-z0-9._+-]{1,64}',v['dragonflyVersion']) is not None and 'REPLACE' not in v['dragonflyVersion'],'EXACT_DRAGONFLY_VERSION_REQUIRED');return v
class Resp:
    def __init__(self,host,user,secret,root,tlsname):
        context=ssl.create_default_context(cafile=str(root));context.minimum_version=ssl.TLSVersion.TLSv1_2
        self.socket=context.wrap_socket(socket.create_connection((host,6379),timeout=3),server_hostname=tlsname);self.file=self.socket.makefile('rb')
        self.command('AUTH',user,secret)
    def command(self,*args):
        args=[str(x).encode() for x in args];self.socket.sendall(b'*%d\r\n'%len(args)+b''.join(b'$%d\r\n'%len(x)+x+b'\r\n' for x in args));return self.read()
    def read(self):
        line=self.file.readline(65537);require(line.endswith(b'\r\n'),'CACHE_REPLY_REFUSED');kind=line[:1];data=line[1:-2]
        if kind==b'-': raise Refused('CACHE_COMMAND_REFUSED')
        if kind==b'+': return data.decode()
        if kind==b':': return int(data)
        size=int(data);require(-1<=size<=1048576,'CACHE_REPLY_BOUND')
        if kind==b'$':
            if size==-1:return None
            value=self.file.read(size);require(self.file.read(2)==b'\r\n','CACHE_REPLY_REFUSED');return value.decode()
        require(kind==b'*' and size<=256,'CACHE_REPLY_REFUSED');return [self.read() for _ in range(max(size,0))]
    def close(self): self.file.close();self.socket.close()
