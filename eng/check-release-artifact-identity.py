#!/usr/bin/env python3
"""Release identity/promotion wiring checks; never native artifact qualification."""
import argparse
import json
from pathlib import Path
import xml.etree.ElementTree as ET
import yaml

ROOT=Path(__file__).resolve().parents[1]
def require(condition,message):
    if not condition:raise ValueError(message)
def validate(root):
    props=(root/'Directory.Build.props').read_text();targets=(root/'Directory.Build.targets').read_text();docker=(root/'Dockerfile').read_text()
    for value in ['<Version>$(TreehammockReleaseVersion)</Version>','<PackageVersion>$(TreehammockReleaseVersion)</PackageVersion>','<AssemblyVersion>$(TreehammockReleaseBaseVersion).0</AssemblyVersion>',
                  '<FileVersion>$(TreehammockReleaseBaseVersion).0</FileVersion>','<InformationalVersion>$(TreehammockReleaseVersion)+sha.$(TreehammockReleaseSourceSha)</InformationalVersion>',
                  '<IncludeSourceRevisionInInformationalVersion>false</IncludeSourceRevisionInInformationalVersion>','TreehammockReleasePackageVersion','TreehammockReleaseSourceSha']:
        require(value in props,'Release property/metadata missing: '+value)
    require('ValidateTreehammockReleaseIdentity' in targets and 'Release base/version mismatch.' in targets,'Missing release identity build checks')
    require('FROM unit-test AS publish' in docker,'Candidate build must include unit target')
    publish=docker.split('FROM unit-test AS publish',1)[1].split('\nFROM ',1)[0]
    require('cat /tmp/treehammock-build-id' in publish and 'TREEHAMMOCK_BUILD_CONFIGURATION="$BUILD_CONFIGURATION"' in publish,'No-build publish does not reuse compilation identity/configuration')
    for property in ['Tag','Version','BaseVersion','SourceSha']:
        require(docker.count('-p:TreehammockRelease'+property+'=')==4,'Restore/build/no-build test/publish identity differs')
    for label in ['org.opencontainers.image.version','org.opencontainers.image.revision','io.treehammock.build.run-id']:
        require(label in docker,'Missing OCI identity label')
    require(any(x.get('Remove')=='eng\\ReleaseArtifactProbe\\**' for x in ET.parse(root/'treehammock.csproj').findall('ItemGroup/Compile')),'Artifact probe entered application compile glob')
    require('artifacts' in (root/'.dockerignore').read_text(),'Candidate can seed source context')
    for name,policy in [('treehammock-release.yml','bootstrap'),('treehammock-versioned-release.yml','versioned')]:
        workflow=yaml.safe_load((root/'.github/workflows'/name).read_text());jobs=workflow['jobs']
        require(workflow['env']['RELEASE_POLICY']==policy,'GitHub release policy boundary changed')
        require(workflow['permissions']=={'contents':'read'},'Workflow acquired write defaults')
        for job in jobs.values():
            for step in job['steps']:require('${{' not in step.get('run',''),'Context expression entered release shell')
        package=jobs['release-package-api'];build=[s for s in package['steps'] if 'release_artifacts.py build' in s.get('run','')]
        require(len(build)==1 and build[0]['env']['RELEASE_SOURCE_SHA']=='${{ needs.release-preflight.outputs.checkout_ref }}','Candidate source uses trigger/mutable ref')
        require('release_artifacts.py build' not in str(jobs['release-ghcr-image']),'Publisher rebuilds candidate')
        require('Download tested candidate' in str(jobs['release-ghcr-image']),'Publisher lacks tested OCI input')
        publisher=next(s for s in jobs['release-ghcr-image']['steps'] if s.get('name')=='Promote tested GHCR digest')
        require(publisher['env']['RELEASE_SOURCE_SHA']=='${{ needs.release-preflight.outputs.checkout_ref }}','Image SHA uses trigger rather than checkout')
        require('release_artifacts.py verify' in str(jobs['create-github-release']) and 'github-summary' in str(jobs['create-github-release']),'Source release skips manifest/outcomes verification')
    gitlab=yaml.safe_load((root/'.gitlab/ci/pipelines/release.yml').read_text())
    require('python3 eng/release_identity.py gitlab-preflight' in gitlab['release-preflight']['script'],'GitLab preflight bypasses canonical identity')
    require('python3 eng/release_artifacts.py build --output artifacts/release' in gitlab['release-package-api']['script'],'GitLab archive bypasses tested candidate')
    gates={'release-dotnet-unit-gate','release-dotnet-integration-gate','release-dotnet-sql-gate','release-docker-direct-gate','release-docker-proxy-gate','release-docker-system-gate'}
    require(gates<=set(gitlab['release-package-api']['needs']),'Candidate bypasses release gates')
    for name in ['release-container-gitlab-registry','release-container-self-hosted-registry','release-container-dockerhub','release-container-aws-ecr']:
        require('release-package-api' in gitlab[name]['needs'] and 'services' not in gitlab[name],'Registry job does not consume one candidate')
        require(gitlab[name]['artifacts']['when']=='always','Registry failure loses outcome artifact')
    require(gitlab['release-publication-summary']['when']=='always' and 'release-publication-summary' in gitlab['release-upload-assets']['needs'],'Partial publication cannot produce honest summary')
    wrapper=(root/'eng/release-container-publish.sh').read_text()
    require('release_artifacts.py promote' in wrapper and 'docker build' not in wrapper and 'CI_COMMIT_SHORT_SHA' not in wrapper,'Publisher rebuild/trigger fallback returned')
    return dict(status='SourceContractsConsistent',qualification='NotRun',github_policies=2,registries=5)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=ROOT);args=p.parse_args()
    try:print(json.dumps(validate(args.root),indent=2));return 0
    except (ValueError,KeyError,OSError,ET.ParseError,yaml.YAMLError) as error:print(str(error));return 1
if __name__=='__main__':raise SystemExit(main())
