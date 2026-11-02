#!/usr/bin/env python3
"""SVS-14 fail-closed source/CI policy. Messages never interpolate source contents."""
import base64,hashlib,json,os,re,sys,zipfile
from pathlib import Path
import yaml
ROOT=Path(__file__).resolve().parents[3]
class Refused(RuntimeError):pass
def require(condition,code):
    if not condition:raise Refused(code)
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def pins(root=ROOT):return json.loads((root/'eng/session-validation/ci/source-pins.json').read_text())
def check_test_locks(root,p):
    reviews=p.get('reviewed_test_locks',{})
    if not reviews:return {}
    name='tests/Treehammock.SessionValidation.HostTests/packages.lock.json'
    require(set(reviews)=={name},'TEST_LOCK_SCOPE')
    r=reviews[name];bp='eng/session-validation/ci/baselines/host.packages.lock.json'
    require(r['pr']=='SVS-20' and r['baseline_path']==bp and r['baseline_sha256']==p['files'][name] and sha(root/bp)==p['files'][name],'TEST_LOCK_HISTORY')
    old=json.loads((root/bp).read_text());new=json.loads((root/name).read_text());extra={'backup.api','backup.application','backup.domain','backup.identity','backup.persistence','backup.cachewarm','backup.security','contactbackup.email'}
    require(old.keys()==new.keys() and old['version']==new['version'] and old['dependencies'].keys()==new['dependencies'].keys(),'TEST_LOCK_FORMAT')
    for framework,entries in old['dependencies'].items():
        current=new['dependencies'][framework]
        require(set(current)-set(entries)==extra and all(current.get(k)==v for k,v in entries.items()),'TEST_PACKAGE_DRIFT')
        for key in extra:
            item=current[key]
            require(set(item)<= {'type','dependencies'} and item['type']=='Project' and all(k.lower() in extra|{'treehammock.sessionvalidation.client'} and v=='[1.0.0, )' for k,v in item.get('dependencies',{}).items()),'TEST_PROJECT_ONLY')
    require(sha(root/name)==r['sha256'],'TEST_LOCK_DIGEST')
    return {name:r['sha256']}
def check_source(root=ROOT):
    p=pins(root)
    require(not set(p['files']).intersection(p.get('reviewed_additions',{})),'PIN_OVERRIDE_REFUSED')
    require(all(n.startswith('deploy/session-validation/') for n in p.get('reviewed_additions',{})),'ADDITION_SCOPE_REFUSED')
    changes=p.get('reviewed_runtime_changes',{});additions=p.get('reviewed_runtime_additions',{})
    require(not set(additions).intersection(p['files']),'RUNTIME_ADDITION_OVERRIDE')
    expected_files=dict(p['files']);expected_files.update(check_test_locks(root,p))
    for name,review in changes.items():
        require(name in p['files'] and name.startswith('src/Treehammock.SessionValidation.Api/') and '..' not in Path(name).parts and review['baseline_sha256']==p['files'][name] and review['pr'] in {'SVS-17','SVS-19'} and bool(review['reason']),'RUNTIME_REVIEW_REQUIRED')
        expected_files[name]=review['sha256']
    require(all(n.startswith('src/Treehammock.SessionValidation.Api/') and '..' not in Path(n).parts for n in additions),'RUNTIME_ADDITION_SCOPE')
    expected_files.update(additions);expected_files.update(p.get('reviewed_additions',{}))
    for name,digest in expected_files.items():require((root/name).is_file() and sha(root/name)==digest,'SOURCE_OR_LOCK_DRIFT')
    # Existing child pipelines are sealed; root dispatcher may only add this lane.
    parent=yaml.safe_load((root/'.gitlab-ci.yml').read_text())
    require(parent.pop('trigger-session-validation-pipeline',None) is not None,'MISSING_SVS_DISPATCH')
    rule={'if':'$RUN_SVS_PIPELINE == "true"'}
    require(parent['workflow']['rules'].count(rule)==1,'SVS_WORKFLOW_DRIFT');parent['workflow']['rules'].remove(rule)
    require(parent==p['parent_pipeline'],'BASELINE_PIPELINE_WEAKENED')
    # Refuse unreviewed additions to production/policy roots, as well as changes.
    protected=('src/','Controllers/','DataLayer/','Entities/','Models/','Repos/','Rigging/','RiggingSupport/','Services/','deploy/session-validation/')
    allowed='deploy/session-validation/ci/'
    actual={x.relative_to(root).as_posix() for x in root.rglob('*') if x.is_file() and not {'bin','obj','.git','__pycache__'}.intersection(x.parts) and x.relative_to(root).as_posix().startswith(protected) and not x.relative_to(root).as_posix().startswith(allowed)}
    expected={n for n in expected_files if n.startswith(protected) and not n.startswith(allowed)}
    require(actual==expected,'PRODUCTION_OR_POLICY_ADDITION')
    child=yaml.safe_load((root/'.gitlab/ci/pipelines/session-validation.yml').read_text())
    require(child['default']['cache']==[],'SHARED_CACHE_REFUSED')
    require(child['default']['image']['name']=='$SVS14_CI_IMAGE','IMAGE_POLICY_DRIFT')
    for job in ['svs14-policy','svs14-validation','svs14-signature']:
        require('allow_failure' not in child[job] and child[job]['timeout'] in {'5 minutes','40 minutes'},'JOB_POLICY_DRIFT')
    require(child['svs14-validation']['artifacts']['access']=='maintainer','ARTIFACT_ACCESS_DRIFT')
    require(child['svs14-signature']['rules']==[{'if':'$CI_COMMIT_REF_PROTECTED == "true" && $CI_COMMIT_TAG && $SVS14_SIGN_ARTIFACTS == "true"'},{'when':'never'}],'SIGNING_RULE_DRIFT')
    return len(p['files'])
def source_fingerprint(root=ROOT):
    files={p.relative_to(root).as_posix():sha(p) for p in root.rglob('*') if p.is_file() and not {'.git','bin','obj','__pycache__','artifacts','TestResults'}.intersection(p.relative_to(root).parts) and not p.relative_to(root).as_posix().startswith('docs/')}
    return hashlib.sha256((json.dumps(files,sort_keys=True,separators=(',',':'))+'\n').encode()).hexdigest()
def check_image(value):require(re.fullmatch(r'[a-zA-Z0-9._:/-]+@sha256:[a-f0-9]{64}',value or '') is not None,'PINNED_IMAGE_REQUIRED')
def check_archive(path,digest):
    require(path.is_file() and sha(path)==digest,'INPUT_ARCHIVE_REFUSED')
    with zipfile.ZipFile(path) as z:require(z.testzip() is None,'INPUT_ARCHIVE_CRC')
def scan(data,secrets=()):
    # Bytes only; only refusal codes are emitted. Synthetic JWT test fixtures must
    # stay in private scratch and are deliberately excluded from public artifacts.
    for secret in secrets:
        if len(secret)>=4:require(secret.encode() not in data,'SECRET_IN_OUTPUT')
    require(re.search(rb'-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY)-----',data) is None,'PRIVATE_KEY_IN_OUTPUT')
    require(re.search(rb'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}',data) is None,'TOKEN_IN_OUTPUT')
    require(re.search(rb'(?i)(?:password|client_secret|api_key)\s*[=:]\s*["\']?[^\s"\';,}]{4,}',data) is None,'CREDENTIAL_IN_OUTPUT')
def verify_packages(root,packages,content_hashes=None):
    expected={}
    for lock in root.rglob('packages.lock.json'):
        if {'bin','obj','.git'}.intersection(lock.parts):continue
        for target in json.loads(lock.read_text())['dependencies'].values():
            for name,entry in target.items():
                if entry.get('type')=='Project':continue
                if 'resolved' in entry and 'contentHash' in entry:
                    key=(name.lower(),entry['resolved'].lower());value=entry['contentHash']
                    require(key not in expected or expected[key]==value,'LOCK_HASH_CONFLICT');expected[key]=value
    used={}
    for asset in root.rglob('project.assets.json'):
        if '.git' in asset.parts:continue
        a=json.loads(asset.read_text())
        for target in a['targets'].values():
            for name,entry in target.items():
                if entry.get('type')!='package':continue
                package,version=name.lower().rsplit('/',1);key=(package,version)
                require(key in expected,'UNLOCKED_PACKAGE')
                used.setdefault(key,set())
                for kind in ['compile','runtime','native','runtimeTargets','build','buildMultiTargeting','buildTransitive','contentFiles']:
                    used[key].update(entry.get(kind,{}))
    require(bool(used),'NO_RESTORED_PACKAGES')
    for (package,version),files in used.items():
        folder=packages/package/version;archive=folder/f'{package}.{version}.nupkg'
        require(archive.is_file(),'PACKAGE_ARCHIVE_MISSING')
        require(zipfile.is_zipfile(archive),'PACKAGE_ARCHIVE_INVALID')
        with zipfile.ZipFile(archive) as z:
            if '.signature.p7s' in z.namelist():
                require(content_hashes is not None and str(archive) in content_hashes,'SIGNED_PACKAGE_VERIFIER_REQUIRED')
                digest=content_hashes[str(archive)]
            else:digest=base64.b64encode(hashlib.sha512(archive.read_bytes()).digest()).decode()
            require(digest==expected[(package,version)],'PACKAGE_HASH_MISMATCH')
            for name in files:
                if name.endswith('/_._'):continue
                require('..' not in Path(name).parts and not Path(name).is_absolute(),'PACKAGE_PATH_REFUSED')
                require((folder/name).is_file() and (folder/name).read_bytes()==z.read(name),'EXPANDED_PACKAGE_TAMPER')
    return len(used)
if __name__=='__main__':
    try:
        require(sys.argv[1:]==['check'],'USAGE');count=check_source()
        if os.environ.get('GITLAB_CI')=='true':check_image(os.environ.get('SVS14_CI_IMAGE'))
        print(json.dumps(dict(status='Passed',pinned_files=count,native_execution='NotRun',grant_rights=False,release_ready=False)))
    except Exception as e:print(str(e) if isinstance(e,Refused) else 'POLICY_CHECK_FAILED',file=sys.stderr);sys.exit(1)
