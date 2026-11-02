#!/usr/bin/env python3
"""Bounded exported-output scan. Emit rule codes/counts, never file names or bytes."""
import argparse,base64,gzip,hashlib,io,json,os,re,stat,sys,tarfile,zipfile
from pathlib import Path
from urllib.parse import quote
class Refused(RuntimeError):pass
def require(value,code):
    if not value:raise Refused(code)
class Scanner:
    def __init__(self,canaries=(),maximum=64*1024*1024,members=2048,depth=4):
        self.maximum=maximum;self.remaining=maximum;self.limit=members;self.depth=depth;self.files=0;self.findings=set();self.variants=set()
        for value in canaries:
            require(isinstance(value,str) and 8<=len(value)<=4096,'CANARY_INPUT_REFUSED');raw=value.encode()
            self.variants.update([raw,base64.b64encode(raw),base64.urlsafe_b64encode(raw).rstrip(b'='),raw.hex().encode(),raw.hex().upper().encode(),quote(value,safe='').encode()])
    def inspect(self,data,name='',level=0):
        require(level<=self.depth,'ARCHIVE_DEPTH_REFUSED');self.files+=1;self.remaining-=len(data);require(self.files<=self.limit and self.remaining>=0,'SCAN_BUDGET_EXHAUSTED')
        if any(x in data for x in self.variants):self.findings.add('SECRET_CANARY')
        if re.search(rb'-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY)-----',data):self.findings.add('PRIVATE_KEY')
        if re.search(rb'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}',data):self.findings.add('CREDENTIAL_TOKEN')
        if re.search(rb'(?i)(?:authorization\s*:\s*bearer\s+|(?:password|pwd|client_secret|api_key)["\']?\s*[:=]\s*["\']?)[A-Za-z0-9_+/=-]{8,}',data):self.findings.add('CREDENTIAL_ASSIGNMENT')
        if name.lower().endswith(('.pfx','.p12','.dmp','.core')) or re.fullmatch(r'core(?:\.\d+)?',Path(name).name):self.findings.add('PRIVATE_OR_DUMP_ARTIFACT')
        if data.startswith(b'\x7fELF') and len(data)>18:
            endian='little' if data[5]==1 else 'big'
            if int.from_bytes(data[16:18],endian)==4:self.findings.add('CORE_DUMP')
        if data.startswith(b'PK\x03\x04'):
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    require(len(z.infolist())<=self.limit-self.files,'ARCHIVE_MEMBER_BUDGET')
                    for member in z.infolist():
                        if member.is_dir():continue
                        require(not member.flag_bits&1 and member.file_size<=self.remaining,'ARCHIVE_ENTRY_REFUSED')
                        require(not stat.S_ISLNK(member.external_attr>>16),'ARCHIVE_SYMLINK_REFUSED');self.inspect(z.read(member),member.filename,level+1)
            except (zipfile.BadZipFile,RuntimeError) as e:
                if isinstance(e,Refused):raise
                raise Refused('ARCHIVE_INVALID') from None
        elif data.startswith(b'\x1f\x8b'):
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(data)) as g:expanded=g.read(self.remaining+1)
                require(len(expanded)<=self.remaining,'EXPANSION_BUDGET_EXHAUSTED');self.inspect(expanded,name.removesuffix('.gz'),level+1)
            except (OSError,EOFError):raise Refused('ARCHIVE_INVALID') from None
        elif len(data)>262 and data[257:262]==b'ustar':
            try:
                with tarfile.open(fileobj=io.BytesIO(data),mode='r:') as tar:
                    for member in tar:
                        if member.isdir():continue
                        require(member.isfile() and member.size<=self.remaining,'TAR_ENTRY_REFUSED');self.inspect(tar.extractfile(member).read(),member.name,level+1)
            except tarfile.TarError:raise Refused('ARCHIVE_INVALID') from None
    def path(self,path):
        path=Path(path);require(not path.is_symlink(),'SYMLINK_REFUSED')
        if path.is_dir():
            for p in sorted(path.iterdir()):self.path(p)
        else:
            require(path.is_file() and path.stat().st_size<=self.remaining,'FILE_BUDGET_REFUSED');self.inspect(path.read_bytes(),path.name)
    def result(self):return dict(status='Refused' if self.findings else 'Passed',files_scanned=self.files,rules=sorted(self.findings),native_execution='NotRun',grant_rights=False,release_ready=False)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('paths',type=Path,nargs='+');p.add_argument('--canaries',type=Path);a=p.parse_args();canaries=[]
    if a.canaries:
        require(a.canaries.is_file() and not a.canaries.is_symlink() and a.canaries.stat().st_mode&0o077==0 and a.canaries.stat().st_size<=65536,'PRIVATE_CANARY_FILE_REQUIRED');canaries=json.loads(a.canaries.read_text());require(isinstance(canaries,list) and len(canaries)<=64,'CANARY_INPUT_REFUSED')
    scanner=Scanner(canaries)
    for path in a.paths:scanner.path(path)
    print(json.dumps(scanner.result()));return 1 if scanner.findings else 0
if __name__=='__main__':
    try:sys.exit(main())
    except Exception as error:print(json.dumps(dict(status='Refused',code=str(error) if isinstance(error,Refused) else 'SCAN_FAILED')));sys.exit(1)
