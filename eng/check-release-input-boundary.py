#!/usr/bin/env python3
"""Check release workflow data/code and token scope contracts; not hosted proof."""
import argparse
import json
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_document(workflow):
    require(workflow['permissions'] == {'contents': 'read'}, 'Workflow token must default to contents read only')
    jobs = workflow['jobs']
    expected_jobs = {
        'release-preflight', 'release-dotnet-unit-gate', 'release-dotnet-integration-gate',
        'release-dotnet-sql-gate', 'release-docker-direct-gate',
        'release-docker-proxy-gate', 'release-docker-system-gate',
        'release-package-api', 'release-package-svs', 'release-ghcr-image',
        'create-github-release',
    }
    require(set(jobs) == expected_jobs, 'Release job inventory changed; review token scopes')
    for name, job in jobs.items():
        expected = {'contents': 'read'}
        if name == 'create-github-release':
            expected = {'contents': 'write'}
        elif name == 'release-ghcr-image':
            expected['packages'] = 'write'
        require(job.get('permissions') == expected, 'Unexpected job token privileges: ' + name)
        for step in job['steps']:
            require('${{' not in step.get('run', ''), 'Context expression enters shell code: ' + name)
            if step.get('uses', '').startswith('actions/checkout@'):
                checkout = step['with']
                require(checkout.get('persist-credentials') is (name == 'release-preflight'), 'Checkout credential persistence differs from policy')
                if name != 'release-preflight':
                    require(checkout['ref'] == '${{ needs.release-preflight.outputs.checkout_ref }}', 'Consumer must check out resolved commit')
            if name != 'release-preflight':
                require(not any('inputs.' in str(value) for value in step.get('env', {}).values()), 'Publish/build step reparses raw dispatch inputs')
        if name != 'release-preflight':
            require('inputs.' not in job.get('if', ''), 'Job condition reparses raw dispatch inputs')
            require("needs.release-preflight.outputs.should_release == 'true'" in job.get('if', ''), 'Consumer bypasses metadata policy gate')
    preflight = jobs['release-preflight']
    checkouts = [s for s in preflight['steps'] if s.get('uses', '').startswith('actions/checkout@')]
    require(len(checkouts) == 1 and checkouts[0]['with']['ref'] == 'main' and checkouts[0]['with']['fetch-depth'] == 0, 'Preflight must use trusted main and complete history')
    steps = [s for s in preflight['steps'] if s.get('id') == 'release-meta']
    require(len(steps) == 1, 'Missing unique metadata resolver')
    step = steps[0]
    require(step['run'] == 'python3 eng/release-metadata.py', 'Metadata must execute trusted helper')
    for suffix in ['RELEASE_TAG', 'TARGET_REF', 'CREATE_RELEASE', 'PUBLISH_GHCR']:
        require(step['env']['INPUT_' + suffix] == '${{ inputs.' + suffix.lower() + ' }}', 'Dispatch input must enter environment as data')
    require(step['env']['GH_TOKEN'] == '${{ secrets.GITHUB_TOKEN }}', 'Read-only metadata token wiring missing')
    for output in ['checkout_ref', 'create_release', 'publish_ghcr', 'should_release']:
        require(preflight['outputs'][output] == '${{ steps.release-meta.outputs.' + output + ' }}', 'Validated output missing')
    require("needs.release-preflight.outputs.publish_ghcr == 'true'" in jobs['release-ghcr-image']['if'], 'Image publishing must use validated flag')
    require("needs.release-preflight.outputs.create_release == 'true'" in jobs['create-github-release']['if'], 'Release publishing must use validated flag')
    svs = jobs['release-package-svs']
    require(svs['needs'] == 'release-preflight', 'SVS must depend on preflight')
    svs_steps = '\n'.join(str(s.get('run', '')) for s in svs['steps'])
    require('eng/session-validation-release.sh test' in svs_steps and
            'eng/session-validation-release.sh publish' in svs_steps and
            'eng/session_validation_artifacts.py package' in svs_steps and
            'eng/session_validation_artifacts.py verify' in svs_steps,
            'SVS release package must build, test, package and verify')
    release = jobs['create-github-release']
    require('release-package-svs' in release['needs'], 'Publishing must wait for SVS archive')
    require("needs.release-package-svs.result == 'success'" in release['if'], 'SVS failure must prevent release publication')
    upload = '\n'.join(str(s.get('run', '')) for s in release['steps'])
    require('artifacts/session-validation/release/*.tar.gz' in upload and
            'artifacts/session-validation/release/*.sha256' in upload and
            'artifacts/session-validation/release/session-validation-release-manifest.json' in upload,
            'GitHub Release must attach SVS archive, checksum and manifest')
    return dict(status='SourceContractsConsistent', qualification='NotRun', jobs=len(jobs), write_jobs=2)


def validate(root):
    return validate_document(yaml.safe_load((root / '.github/workflows/treehammock-release.yml').read_text()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        print(json.dumps(validate(args.root), indent=2))
        return 0
    except (KeyError, ValueError, OSError, yaml.YAMLError) as error:
        print(str(error))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
