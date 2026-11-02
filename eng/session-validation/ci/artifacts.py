#!/usr/bin/env python3
"""Validation artifacts and detached Ed25519 signatures, separate from app release."""
import argparse,gzip,hashlib,io,json,os,re,subprocess,sys,tarfile
from pathlib import Path
from policy import Refused,require,scan,sha,check_source,source_fingerprint

def encode(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def bundle(root,directory,summary,provenance,secrets=()):
    require(not directory.exists(),'PUBLIC_OUTPUT_ALREADY_EXISTS');directory.mkdir(parents=True)
    require(summary['total_test_executions']>0 and summary['native_cases_executed']==0 and summary['grant_rights'] is False and summary['release_ready'] is False,'SUMMARY_REFUSED')
    payload={};assemblies={}
    projects=[('treehammock','net8.0',root),*[(f'Treehammock.SessionValidation.{n}','net10.0',root/'src'/f'Treehammock.SessionValidation.{n}') for n in ['Api','Core','Storage','Client','Contracts']]]
    for name,framework,project in projects:
        source=project/'bin/Release'/framework/(name+'.dll');require(source.is_file(),'COMPILED_ASSEMBLY_MISSING')
        data=source.read_bytes()
        for secret in secrets:
            if len(secret)>=4:require(secret.encode() not in data,'SECRET_IN_BINARY')
        assemblies[f'{framework}/{name}.dll']=dict(sha256=hashlib.sha256(data).hexdigest(),bytes=len(data))
    payload['assembly-hashes.json']=encode(assemblies)
    payload['summary.json']=encode(summary);payload['provenance.json']=encode(provenance)
    for data in payload.values():scan(data,secrets)
    with (directory/'payload.tar.gz').open('wb') as output:
        with gzip.GzipFile(fileobj=output,mode='wb',mtime=0,filename='') as compressed:
            with tarfile.open(fileobj=compressed,mode='w') as tar:
                for name,data in sorted(payload.items()):
                    item=tarfile.TarInfo(name);item.size=len(data);item.mode=0o644;item.mtime=0;tar.addfile(item,io.BytesIO(data))
    (directory/'summary.json').write_bytes(payload['summary.json']);(directory/'provenance.json').write_bytes(payload['provenance.json'])
    manifest=dict(schema='svs-validation-artifact.v1',commit=provenance['commit'],source_sha256=provenance['source_sha256'],purpose='Validation evidence and own assembly hashes; not a deployable release',files={n:sha(directory/n) for n in ['payload.tar.gz','summary.json','provenance.json']},payload_files={n:hashlib.sha256(data).hexdigest() for n,data in sorted(payload.items())},native_execution='NotRun',grant_rights=False,release_ready=False)
    (directory/'manifest.json').write_bytes(encode(manifest));verify(directory,provenance['commit']);return manifest

def verify(directory,commit):
    m=json.loads((directory/'manifest.json').read_bytes());require(m['schema']=='svs-validation-artifact.v1' and m['commit']==commit,'ARTIFACT_COMMIT_MISMATCH')
    require(m['native_execution']=='NotRun' and m['grant_rights'] is False and m['release_ready'] is False,'ARTIFACT_ACCEPTANCE_ESCALATION')
    require(set(m['files'])=={'payload.tar.gz','summary.json','provenance.json'},'ARTIFACT_FILE_SET')
    for name,digest in m['files'].items():require((directory/name).is_file() and sha(directory/name)==digest,'ARTIFACT_HASH_MISMATCH')
    summary=json.loads((directory/'summary.json').read_bytes());provenance=json.loads((directory/'provenance.json').read_bytes())
    require(summary['native_cases_executed']==0 and summary['grant_rights'] is False and summary['release_ready'] is False and summary['total_test_executions']>0,'ARTIFACT_SUMMARY_REFUSED')
    require(provenance['commit']==commit and provenance['source_sha256']==m['source_sha256'],'ARTIFACT_PROVENANCE_MISMATCH')
    with tarfile.open(directory/'payload.tar.gz','r:gz') as tar:
        members=tar.getmembers();require(len(members)==len(m['payload_files']) and len({x.name for x in members})==len(members),'PAYLOAD_DUPLICATES')
        for item in members:
            require(item.isfile() and item.name in m['payload_files'] and '..' not in Path(item.name).parts and not Path(item.name).is_absolute(),'PAYLOAD_PATH_REFUSED')
            data=tar.extractfile(item).read();require(hashlib.sha256(data).hexdigest()==m['payload_files'][item.name],'PAYLOAD_HASH_MISMATCH');scan(data)
    return m

def signing_context(env):
    require(env.get('GITLAB_CI')=='true' and env.get('CI_COMMIT_REF_PROTECTED')=='true' and env.get('CI_COMMIT_TAG') and env.get('SVS14_SIGN_ARTIFACTS')=='true','PROTECTED_TAG_REQUIRED')
    commit=env.get('CI_COMMIT_SHA','');require(re.fullmatch('[a-f0-9]{40}|[a-f0-9]{64}',commit) is not None,'COMMIT_REQUIRED');return commit

def sign(directory,env=os.environ):
    commit=signing_context(env);m=verify(directory,commit);check_source()
    require(m['source_sha256']==source_fingerprint(),'SIGNING_SOURCE_MISMATCH')
    require(subprocess.check_output(['git','rev-parse','HEAD'],cwd=__import__('policy').ROOT,text=True).strip()==commit,'SIGNING_CHECKOUT_MISMATCH')
    private=Path(env.get('SVS14_SIGNING_KEY_FILE',''));require(private.is_file() and private.stat().st_mode&0o077==0,'PRIVATE_SIGNING_KEY_PERMISSIONS')
    fingerprint=env.get('SVS14_SIGNING_PUBLIC_SHA256','');require(re.fullmatch('[a-f0-9]{64}',fingerprint) is not None,'PUBLIC_KEY_PIN_REQUIRED')
    def command(args):
        r=subprocess.run(['openssl',*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20);require(r.returncode==0,'SIGNATURE_OPERATION_FAILED');return r.stdout
    public=command(['pkey','-in',str(private),'-pubout']);require(hashlib.sha256(public).hexdigest()==fingerprint,'PUBLIC_KEY_PIN_MISMATCH')
    output=directory/'signing-public.pem';output.write_bytes(public)
    # ed25519 rejects an RSA/EC key for this explicit algorithm check.
    text=command(['pkey','-pubin','-in',str(output),'-text','-noout']);require(b'ED25519' in text.upper(),'ED25519_KEY_REQUIRED')
    signature=directory/'manifest.ed25519'
    command(['pkeyutl','-sign','-rawin','-inkey',str(private),'-in',str(directory/'manifest.json'),'-out',str(signature)])
    command(['pkeyutl','-verify','-rawin','-pubin','-inkey',str(output),'-in',str(directory/'manifest.json'),'-sigfile',str(signature)])
    scan(signature.read_bytes(),[private.read_text()]);return 'SignedValidationArtifactOnly'
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('action',choices=['sign','verify']);p.add_argument('--directory',required=True,type=Path);p.add_argument('--commit');a=p.parse_args()
    try:print(sign(a.directory) if a.action=='sign' else verify(a.directory,a.commit)['schema'])
    except Exception as e:print(str(e) if isinstance(e,Refused) else 'ARTIFACT_OPERATION_FAILED',file=sys.stderr);sys.exit(1)
