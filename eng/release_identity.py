#!/usr/bin/env python3
"""Canonical release values shared by preflight, builders and promotion checks."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

class ReleaseError(ValueError):
    pass

def require(condition, message):
    if not condition: raise ReleaseError(message)

def canonical(tag, sha):
    require(isinstance(tag,str) and len(tag)<=128, 'Invalid release tag')
    match=re.fullmatch(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?',tag)
    require(match is not None, 'Noncanonical release tag')
    require(all(int(x)<=65534 for x in match.groups()[:3]), 'Assembly version component out of range')
    if match[4]:
        require(all(not (part.isdigit() and len(part)>1 and part[0]=='0') for part in match[4].split('.')), 'Noncanonical prerelease')
    require(isinstance(sha,str) and re.fullmatch(r'[0-9a-f]{40}',sha), 'Invalid source SHA')
    base='.'.join(match.groups()[:3]);version=tag[1:]
    return dict(tag=tag,version=version,base_version=base,assembly_version=base+'.0',
                informational_version=version+'+sha.'+sha,source_sha=sha,is_prerelease=bool(match[4]))

def run(arguments, *, cwd=None, input=None, optional=False, timeout=300, env=None):
    result=subprocess.run(arguments,cwd=cwd,input=input,capture_output=True,text=True,timeout=timeout,env=env)
    if result.returncode and not optional: raise ReleaseError('Release command failed: '+arguments[0])
    return result

def source_check(root, expected):
    require(run(['git','rev-parse','--verify','HEAD^{commit}'],cwd=root).stdout.strip()==expected, 'Checkout SHA differs from release source')
    # Byte comparison tolerates CI chmod, but never content differences/extra code.
    tracked=run(['git','ls-files','-z'],cwd=root).stdout.split('\0')
    for name in filter(None,tracked):
        path=root/name
        require(path.is_file() and not path.is_symlink(), 'Tracked source is missing or linked')
        original=subprocess.run(['git','show','HEAD:'+name],cwd=root,capture_output=True,timeout=30)
        require(original.returncode==0 and path.read_bytes()==original.stdout, 'Tracked source content differs from commit')
    extra=run(['git','ls-files','--others','--exclude-standard','-z'],cwd=root).stdout
    require(not extra, 'Untracked source cannot enter release context')

def gitlab_preflight(environment, root):
    identity=canonical(environment.get('CI_COMMIT_TAG',''),environment.get('CI_COMMIT_SHA',''))
    source_check(root,identity['source_sha'])
    package=environment.get('RELEASE_PACKAGE_NAME','treehammock-api')
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}',package), 'Invalid package name')
    flags={}
    for name in ['PUBLISH_GITLAB_REGISTRY','PUBLISH_SELF_HOSTED_REGISTRY','PUBLISH_DOCKERHUB','PUBLISH_AWS_ECR','PUSH_LATEST_FOR_STABLE']:
        value=environment.get(name,'true' if name=='PUSH_LATEST_FOR_STABLE' else 'false')
        require(value in ['true','false'],'Invalid publication flag');flags[name]=value
    return dict(RELEASE_TAG=identity['tag'],RELEASE_VERSION=identity['version'],RELEASE_BASE_VERSION=identity['base_version'],
                RELEASE_ASSEMBLY_VERSION=identity['assembly_version'],RELEASE_SOURCE_SHA=identity['source_sha'],
                RELEASE_PACKAGE_VERSION=identity['tag'],RELEASE_ARCHIVE=package+'-'+identity['tag']+'.tar.gz',
                RELEASE_CHECKSUM=package+'-'+identity['tag']+'.sha256',**flags)

def main():
    try:
        require(sys.argv[1:]==['gitlab-preflight'], 'Unsupported identity operation')
        values=gitlab_preflight(os.environ,Path(__file__).resolve().parents[1])
        output=Path('artifacts/release-intent.env');output.parent.mkdir(parents=True,exist_ok=True)
        output.write_text(''.join(k+'='+v+'\n' for k,v in values.items()))
        return 0
    except (ReleaseError,OSError,subprocess.SubprocessError):
        print('Release identity validation failed.',file=sys.stderr);return 2

if __name__=='__main__':raise SystemExit(main())
