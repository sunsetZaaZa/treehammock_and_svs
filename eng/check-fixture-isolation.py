#!/usr/bin/env python3
"""COR23X supplemental wiring guard; rendered/native isolation remains required."""
import argparse,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
WRAPPERS=['docker-infra-up','docker-postgres-up','docker-dragonfly-up','docker-api-direct-up','docker-api-proxy-up','docker-api-proxy-scale','docker-all-runtime-up','docker-sql-contracts','docker-http-contracts-direct','docker-http-contracts-proxy','docker-system-stack-tests','docker-host-system-stack-tests','docker-down']
def require(value,message):
    if not value:raise ValueError(message)
def validate(root):
    base=(root/'docker-compose.integration.yml').read_text()
    require(not re.search(r'^\s+ports:',base,re.M),'Default stack must have no host publications')
    require('enable_ipv6: false' in base and 'gateway_mode_ipv4: nat' in base,'Fixture bridge routing must remain explicit')
    for path in root.glob('docker-compose*.yml'):
        active=False
        for line in path.read_text().splitlines():
            if re.match(r'^\s+ports:',line):
                active=True
                if '[' in line:require('127.0.0.1:' in line and not re.search(r'["\'][0-9]+:',line),'Only literal loopback publication is allowed')
            elif active and re.match(r'^\s+- ',line):require('127.0.0.1:' in line,'Only literal loopback publication is allowed')
            elif line.strip():active=False
    for name in ['DB_PASSWORD','CACHE_PASSWORD','OUTBOX_KEY','OPERATION_KEY']:
        require('${TREEHAMMOCK_FIXTURE_'+name+':?' in base,'Generated fixture setting must be mandatory: '+name)
    require(base.count('BundleSettings__password: ${TREEHAMMOCK_FIXTURE_CACHE_PASSWORD:?')==3,'All cache clients must authenticate')
    for name in ['integration','local-system']:
        text=(root/('docker-compose.'+name+'.yml')).read_text()
        require('--requirepass' in text and 'REDISCLI_AUTH=$$FIXTURE_CACHE_PASSWORD' in text,'Cache auth and health credentials must agree')
    for name,field in [('testing','SystemTestSettings__TestKey'),('ci-system','TREEHAMMOCK_SYSTEM_TEST_KEY')]:
        require(field+': ${TREEHAMMOCK_FIXTURE_TEST_KEY:?' in (root/('docker-compose.'+name+'.yml')).read_text(),'Test key producers/consumers must share project settings')
    local=(root/'docker-compose.local-system.yml').read_text();host=(root/'deploy/haproxy/haproxy.host-system.cfg').read_text()
    require('network_mode: host' in local and 'extra_hosts:' not in local and 'bind 127.0.0.1:8080' in host and '127.0.0.1:5001' in host,'Host proxy must use the restricted loopback route')
    for stem in WRAPPERS:
        for ext in ['sh','ps1']:
            script=(root/'eng'/f'{stem}.{ext}').read_text()
            require('fixture-isolation.'+ext in script,'Compose wrapper must initialize project settings: '+stem)
            if ext=='ps1':require(script.index(". (Join-Path $PSScriptRoot 'fixture-isolation.ps1')")<script.index('Invoke-TreehammockRunner -Stage'),'Restore function must outlive runner body scope')
            if stem=='docker-host-system-stack-tests':require('127.0.0.1:5001' in script and '0.0.0.0:5001' not in script,'Host API must bind loopback')
            if stem in ['docker-sql-contracts','docker-http-contracts-direct','docker-http-contracts-proxy','docker-system-stack-tests']:
                require('docker-compose.host-access.yml' not in script and 'docker-compose.proxy-access.yml' not in script,'Container proof must not select host publications')
    helper=(root/'eng/fixture-isolation.py').read_text()
    for token in [">=28","'TREEHAMMOCK_REMOTE_LAB_ACCESS'","'TREEHAMMOCK_HOST_NETWORKING_CONFIRMED'",'secrets.token_bytes(32)','secrets.token_hex(32)',"lock.mkdir",'0o600','FILE_ATTRIBUTE_REPARSE_POINT']:
        require(token in helper,'Credential/preflight boundary absent: '+token)
    require('Restore-TreehammockFixtureEnvironment -Owner $Stage' in (root/'eng/native-command.ps1').read_text(),'Owning PowerShell runner must restore fixture environment')
    for path in ['eng/check-correction-evidence.py','eng/reconcile-source-inventory.py','eng/update-correction-file-inventory.py','eng/correction-baseline.py','.dockerignore']:
        require('.docker' in (root/path).read_text(),'Private credential storage must be excluded: '+path)
    return dict(status='SourceContractsConsistent',qualification='NotRun',scope='Project settings, restricted profiles and wrapper wiring; native peer/auth/lifecycle acceptance is separate')
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=ROOT);args=parser.parse_args()
    try:print(json.dumps(validate(args.root),indent=2))
    except (OSError,ValueError) as error:print(str(error));raise SystemExit(1)
