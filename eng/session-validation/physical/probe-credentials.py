#!/usr/bin/env python3
"""Inspect explicitly inventoried systemd runtime credentials without reading bytes."""
import argparse,json,os,stat,sys
from pathlib import Path
class Refused(RuntimeError):pass
def audit(value):
    if not isinstance(value,dict) or set(value)!={'version','items'} or value['version']!=1 or not isinstance(value['items'],list) or not 1<=len(value['items'])<=128:raise Refused('INVENTORY_REQUIRED')
    seen=set()
    for item in value['items']:
        if not isinstance(item,dict) or set(item)!={'path','owner_uid'} or type(item['owner_uid']) is not int or item['owner_uid']<1000:raise Refused('SERVICE_IDENTITY_REQUIRED')
        p=Path(item['path'])
        if not p.is_absolute() or '..' in p.parts or any(x.is_symlink() for x in [p,*p.parents]):raise Refused('CREDENTIAL_PATH_REFUSED')
        info=p.stat();identity=(info.st_dev,info.st_ino)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=item['owner_uid'] or stat.S_IMODE(info.st_mode)!=0o400 or info.st_nlink!=1 or identity in seen:raise Refused('RUNTIME_CREDENTIAL_OWNER_MODE_OR_SHARING_REFUSED')
        seen.add(identity)
    return dict(status='ScopedCredentialMetadataPassed',files=len(seen),scope='Explicit runtime file metadata only; no secret bytes read',other_process_access='NotRun',full_physical_qualification='NotRun',grant_rights=False,release_ready=False)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('inventory',type=Path);a=p.parse_args()
    if not a.inventory.is_file() or a.inventory.is_symlink() or a.inventory.stat().st_size>32768:raise Refused('INVENTORY_REQUIRED')
    print(json.dumps(audit(json.loads(a.inventory.read_text()))))
if __name__=='__main__':
    try:main()
    except Exception as e:print(json.dumps(dict(status='Refused',code=str(e) if isinstance(e,Refused) else 'CREDENTIAL_PROBE_FAILED')));sys.exit(1)
