#!/usr/bin/env python3
"""Inspect explicit owned key files without reading or printing secret bytes/paths."""
import argparse,json,os,stat,sys
from pathlib import Path
class Refused(RuntimeError):pass
def audit(value):
    if not isinstance(value,dict) or set(value)!={'version','items'} or value['version']!=1 or not 1<=len(value['items'])<=128:raise Refused('INVENTORY_REQUIRED')
    seen=set();count=0
    for item in value['items']:
        if set(item)!={'service','purpose','path','owner_uid'} or item['purpose'] not in {'server','caller','controller','offline-ca','signing'}:raise Refused('KEY_CLASSIFICATION_REQUIRED')
        if not isinstance(item['service'],str) or not item['service'] or not isinstance(item['owner_uid'],int) or item['owner_uid']<0:raise Refused('OWNED_IDENTITY_REQUIRED')
        if item['service'].startswith('caller') and item['purpose']!='caller':raise Refused('CALLER_SIGNING_OR_SERVER_KEY_REFUSED')
        p=Path(item['path'])
        if not p.is_absolute() or '..' in p.parts or any(x.is_symlink() for x in [p,*p.parents]):raise Refused('KEY_PATH_REFUSED')
        info=p.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=item['owner_uid'] or info.st_mode&0o777!=0o600:raise Refused('PRIVATE_KEY_OWNER_OR_MODE')
        identity=(info.st_dev,info.st_ino)
        if identity in seen:raise Refused('SHARED_PRIVATE_FILE_REFUSED')
        seen.add(identity);count+=1
    return dict(status='Passed',private_files=count,scope='path-owner-mode-and-mount-inventory-only',native_execution='NotRun',grant_rights=False,release_ready=False)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('inventory',type=Path);a=p.parse_args()
    if not a.inventory.is_file() or a.inventory.stat().st_size>65536:raise Refused('INVENTORY_REQUIRED')
    print(json.dumps(audit(json.loads(a.inventory.read_text()))))
if __name__=='__main__':
    try:main()
    except Exception as e:print(json.dumps(dict(status='Refused',code=str(e) if isinstance(e,Refused) else 'KEY_INVENTORY_FAILED')));sys.exit(1)
