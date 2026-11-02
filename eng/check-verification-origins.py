#!/usr/bin/env python3
"""COR23G profile/source checks; native URI, HTTP/TLS/proxy and SQL qualification remains required."""
import argparse
import json
import re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
PROFILES={'appsettings.json':'https://localhost:5001','appsettings.Example.json':'https://localhost:5001','appsettings.LocalHttps.json':'https://localhost:5001','appsettings.Container.json':'http://localhost:5001','appsettings.ContainerReverseProxy.json':'http://localhost:8080','appsettings.ReverseProxy.json':'','appsettings.Testing.json':'http://localhost:5001','appsettings.Development.json':'https://localhost:5001'}
OLD=['AccountVerificationBaseUrl','AccountEmailChangeVerificationBaseUrl','AccountDeleteVerifyBaseUrl']
def require(valid,message):
    if not valid: raise ValueError(message)

def validate(root):
    read=lambda p:(root/p).read_text()
    for name,origin in PROFILES.items():
        obj=json.loads(read(name));section=obj['RegistrationSettings'];require(section['PublicOrigin']==origin,'Public origin/profile mismatch: '+name)
        require(not any(key in section for key in OLD),'Obsolete per-flow setting: '+name)
        if name not in ['appsettings.json','appsettings.Example.json','appsettings.Development.json','appsettings.ReverseProxy.json']:
            host=obj['HostingSettings'];require(host['Port']==5001,'Profile listener mismatch')
            if name=='appsettings.LocalHttps.json':require(host['UseHttps'],'LocalHttps requires HTTPS')
    settings=read('Rigging/Config/RegistrationSettings.cs')
    require('[Required] public string? PublicOrigin' in settings and 'VerificationLinkBuilder.TryOrigin(PublicOrigin' in settings,'Require/validate canonical origin')
    require(not any(key in settings for key in OLD),'No legacy origin aliases')
    builder=read('Rigging/Hosting/VerificationLinkBuilder.cs')
    for token in ['private readonly Uri _origin;','value.Length > 2048','Regex.IsMatch(value','parsed.UserInfo.Length != 0','parsed.Query.Length != 0','parsed.Fragment.Length != 0','parsed.AbsolutePath != "/"','Uri.EscapeDataString(payload)','new Uri(_origin, route','origin.Scheme == "https" && !loopback','"Development" or "Testing" or "Container" or "ContainerReverseProxy"']:
        require(token in builder,'Canonical link policy lacks '+token)
    require(not any(token in builder for token in ['HttpContext','Request.Headers','X-Forwarded-Host']) or all(token not in re.sub(r'//[^\n]*','',builder) for token in ['HttpContext','Request.Headers','X-Forwarded-Host']),'Never choose authority from request metadata')
    for route in ['/account/verifyaccount','/account/adjust/email/verify','/account/wipeout/verify']:require(route in builder,'Fixed verification route absent: '+route)
    service=read('Services/AccountService.cs');require('BuildUrl(' not in service and not any(key in service for key in OLD),'Consolidate route builders; no relative fallback')
    for call in ['_verificationLinks.Registration(verifyKey)','_verificationLinks.EmailChange(verifyKey)','_verificationLinks.Delete(deleteToken)']:require(call in service,'Real producer must use canonical builder')
    registration=read('Rigging/DependencyInjection/TreehammockServiceCollectionExtensions.cs')
    require('VerificationLinkBuilder.AllowedForEnvironment(settings.PublicOrigin, environment?.EnvironmentName)' in registration and 'ErrorOnUnknownConfiguration = sectionName == "RegistrationSettings"' in registration and 'new VerificationLinkBuilder(provider.GetRequiredService<IOptions<RegistrationSettings>>().Value.PublicOrigin)' in registration,'Validate startup/environment and freeze one DI builder')
    env=lambda file:{'RegistrationSettings__PublicOrigin':re.search(r'^      RegistrationSettings__PublicOrigin: ([^\n]+)$',read(file),re.M).group(1)}
    require(env('docker-compose.integration.yml')['RegistrationSettings__PublicOrigin']=='${TREEHAMMOCK_PUBLIC_ORIGIN:-http://localhost:5001}','Direct Compose public authority')
    require(env('docker-compose.api-proxy.yml')['RegistrationSettings__PublicOrigin']=='${TREEHAMMOCK_PUBLIC_ORIGIN:-http://localhost:8080}','Proxy Compose public authority')
    require('export RegistrationSettings__PublicOrigin=http://localhost:8080' in read('eng/docker-host-system-stack-tests.sh'),'Bash host edge authority')
    require("$env:RegistrationSettings__PublicOrigin = 'http://localhost:8080'" in read('eng/docker-host-system-stack-tests.ps1') and "'RegistrationSettings__PublicOrigin'," in read('eng/docker-host-system-stack-tests.ps1'),'PowerShell declares/restores host edge authority')
    for name,method in [('treehammock.Tests/Integration/VerificationLinkHttpTests.cs','Owned_public_listener_and_proxy_follow_captured_links'),('treehammock.Tests/Unit/PublicOriginTests.cs','Invalid_Production_origin_stops_host_start'),('treehammock.Tests.SqlContracts/Integration/Database/RegistrationAndUnlockTests.cs','Cor23G_registration_and_resend_URL_payloads'),('treehammock.Tests.SqlContracts/Integration/Database/EmailChangeTests.cs','Cor23G_encrypted_email_change_URL'),('treehammock.Tests.SqlContracts/Integration/Database/DeleteAuthorityTests.cs','Cor23G_encrypted_delete_URL')]:require(method in read(name),'Native regression missing: '+method)
    launch=json.loads(read('Properties/launchSettings.json'))
    for name,expected in [('http','http://localhost:5001'),('https','https://localhost:5001'),('IIS Express','https://localhost:'+str(launch['iisSettings']['iisExpress']['sslPort']))]:
        lane=launch['profiles'][name];require(lane['environmentVariables']['RegistrationSettings__PublicOrigin']==expected,'Launch profile public authority: '+name)
        if name!='IIS Express':require(lane['applicationUrl']==expected,'Launch/browser listener: '+name)
    require('RegistrationSettings__PublicOrigin=https://api.example.com'  in read('README.md'),'Document deployment input')
    return dict(status='SourceContractsConsistent',qualification='NotRun',shipped_profiles=len(PROFILES),canonical_origin_properties=1,production='explicit non-loopback HTTPS',native_required=['fast','sql-harness','sql','system','COR24 public/proxy/TLS qualification'])

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=ROOT);args=parser.parse_args()
    try:print(json.dumps(validate(args.root),indent=2));return 0
    except (ValueError,OSError,KeyError) as error:print(str(error));return 1
if __name__=='__main__':raise SystemExit(main())
