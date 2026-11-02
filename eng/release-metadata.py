#!/usr/bin/env python3
"""Read release inputs as data and emit validated bootstrap release outputs.

This helper performs only Git reads/fetches and GitHub GET requests. It cannot
publish. Hosted dispatch authorization and token enforcement need qualification.
"""
import os
from pathlib import Path
import re
import subprocess
import sys
from release_identity import canonical, ReleaseError


class MetadataError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise MetadataError(message)


def boolean(value, name):
    require(value in ('true', 'false'), 'Invalid ' + name)
    return value


def inputs(environment):
    event = environment.get('GITHUB_EVENT_NAME', '')
    require(event in ('push', 'workflow_dispatch'), 'Unsupported release event')
    require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', environment.get('GITHUB_REPOSITORY', '')), 'Invalid repository')
    require(re.fullmatch(r'[0-9a-f]{40}', environment.get('GITHUB_SHA', '')), 'Invalid trigger commit')
    package = environment.get('RELEASE_PACKAGE_NAME', 'treehammock-api')
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', package), 'Invalid package name')
    policy = environment.get('RELEASE_POLICY', 'bootstrap')
    require(policy in ('bootstrap', 'versioned'), 'Invalid release policy')
    if event == 'push':
        if policy == 'versioned':
            require(environment.get('GITHUB_REF', '').startswith('refs/tags/'), 'Versioned push requires a tag')
            tag, target = environment['GITHUB_REF'][len('refs/tags/'):], environment['GITHUB_SHA']
        else:
            tag, target = 'v1.0.0', None
        create = 'true'
        publish = boolean(environment.get('PUBLISH_GHCR', '') or 'false', 'publish_ghcr')
    else:
        tag = environment.get('INPUT_RELEASE_TAG', '')
        target = environment.get('INPUT_TARGET_REF', '')
        create = boolean(environment.get('INPUT_CREATE_RELEASE', ''), 'create_release')
        publish = boolean(environment.get('INPUT_PUBLISH_GHCR', ''), 'publish_ghcr')
        require(0 < len(target) <= 255 and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]*', target), 'Invalid target reference')
        # Only names and SHAs, never Git revision expressions, options or paths.
        require('..' not in target and '//' not in target and not target.endswith(('/', '.')), 'Invalid target reference')
        require(all(part and not part.startswith('.') and not part.endswith('.lock') for part in target.split('/')), 'Invalid target reference')
        if target.startswith('refs/'):
            require(target.startswith(('refs/heads/', 'refs/tags/', 'refs/remotes/origin/')), 'Unsupported reference namespace')
    require(0 < len(tag) <= 128 and re.fullmatch(r'v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?', tag), 'Invalid release tag')
    require(environment.get('GITHUB_OUTPUT'), 'Missing output file')
    return event, tag, target, create, publish, package


def command(arguments, *, optional=False):
    # No shell, no evaluated input and no command/stderr/token logging.
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=90)
    if result.returncode and not optional:
        raise MetadataError('Release metadata command failed: ' + arguments[0])
    return result


def commit(reference, *, optional=False):
    result = command(['git', 'rev-parse', '--verify', '--end-of-options', reference + '^{commit}'], optional=optional)
    if result.returncode:
        return None
    sha = result.stdout.strip()
    require(re.fullmatch(r'[0-9a-f]{40}', sha), 'Invalid resolved commit')
    return sha


def resolve_target(target):
    if target.startswith('refs/') or re.fullmatch(r'[0-9a-fA-F]{40}', target):
        return commit(target)
    # Checkout fetches remote branches, which need not exist as local branches.
    # Reject ambiguous names rather than choosing a different branch/tag silently.
    candidates = ['refs/heads/' + target, 'refs/tags/' + target, 'refs/remotes/origin/' + target]
    if re.fullmatch(r'[0-9a-fA-F]{7,39}', target):
        candidates.append(target)
    resolved = {sha for ref in candidates if (sha := commit(ref, optional=True)) is not None}
    require(len(resolved) == 1, 'Target reference is missing or ambiguous')
    return resolved.pop()


def github_exists(endpoint):
    result = command(['gh', 'api', '--include', '--method', 'GET', endpoint], optional=True)
    statuses = re.findall(r'^HTTP/\S+ (\d{3})(?:\s|$)', result.stdout, re.M)
    require(len(statuses) == 1, 'GitHub lookup did not return an unambiguous HTTP status')
    status = int(statuses[0])
    if result.returncode == 0 and 200 <= status < 300:
        return True
    if result.returncode != 0 and status == 404:
        return False
    raise MetadataError('GitHub release lookup failed')


def metadata(environment):
    event, tag, target, create, publish, package = inputs(environment)
    canonical(tag, environment['GITHUB_SHA'])
    # All input syntax/boolean/output checks precede any external command.
    if target is not None:
        command(['git', 'check-ref-format', 'refs/heads/' + target])
    command(['git', 'fetch', '--no-tags', '--prune', 'origin', '+refs/heads/main:refs/remotes/origin/main'])
    main = 'refs/remotes/origin/main'
    root = command(['git', 'rev-list', '--first-parent', '--max-parents=0', main]).stdout.strip()
    require(re.fullmatch(r'[0-9a-f]{40}', root), 'Invalid initial main commit')
    # Require a real commit object, and carry only this immutable SHA downstream.
    require(commit(root) == root, 'Initial main commit identity mismatch')
    requested = resolve_target(target) if target is not None else None
    should_release, reason = 'true', ''
    policy = environment.get('RELEASE_POLICY', 'bootstrap')
    checkout = requested if policy == 'versioned' else root
    if policy == 'versioned':
        require(command(['git', 'merge-base', '--is-ancestor', checkout, main], optional=True).returncode == 0, 'Versioned source must be on main history')
        if github_exists('repos/' + environment['GITHUB_REPOSITORY'] + '/releases/tags/' + tag):
            should_release, reason = 'false', 'GitHub Release already exists.'
        elif github_exists('repos/' + environment['GITHUB_REPOSITORY'] + '/git/ref/tags/' + tag):
            command(['git', 'fetch', '--no-tags', 'origin', 'refs/tags/' + tag + ':refs/tags/' + tag])
            require(commit('refs/tags/' + tag) == checkout, 'Existing version tag targets another source')
    elif tag != 'v1.0.0':
        should_release, reason = 'false', 'Release workflow is pinned to v1.0.0 only.'
    elif event == 'push' and environment.get('GITHUB_REF') != 'refs/heads/main':
        should_release, reason = 'false', 'Release v1.0.0 only runs from pushes to main.'
    elif event == 'push' and environment['GITHUB_SHA'] != root:
        should_release, reason = 'false', 'Release v1.0.0 only runs from the initial commit to main.'
    elif event == 'workflow_dispatch' and requested != root:
        should_release, reason = 'false', 'Manual v1.0.0 release must target the initial commit to main.'
    elif github_exists('repos/' + environment['GITHUB_REPOSITORY'] + '/releases/tags/' + tag):
        should_release, reason = 'false', 'GitHub Release already exists.'
    elif github_exists('repos/' + environment['GITHUB_REPOSITORY'] + '/git/ref/tags/' + tag):
        should_release, reason = 'false', 'Git tag already exists.'
    identity = canonical(tag, checkout)
    version = identity['version']
    base = identity['base_version']
    return dict(release_tag=tag, release_version=version, release_base_version=base,
                release_assembly_version=base + '.0', release_archive=package + '-' + tag + '.tar.gz',
                release_checksum=package + '-' + tag + '.sha256', checkout_ref=checkout,
                is_prerelease='true' if '-' in version else 'false',
                release_mode='versioned' if policy == 'versioned' else ('bootstrap' if event == 'push' else 'manual'),
                should_release=should_release, skip_reason=reason,
                create_release=create, publish_ghcr=publish,
                release_source_sha=checkout, release_informational_version=identity['informational_version'])


def main():
    try:
        values = metadata(os.environ)
        # Atomic logical output: validation/resolution/API failure emits no outputs.
        require(all('\n' not in value and '\r' not in value for value in values.values()), 'Invalid output value')
        with Path(os.environ['GITHUB_OUTPUT']).open('a', encoding='utf-8') as output:
            output.write(''.join(key + '=' + value + '\n' for key, value in values.items()))
        if values['should_release'] != 'true':
            print('Skipping release: ' + values['skip_reason'])
        return 0
    except (MetadataError, ReleaseError, OSError, subprocess.SubprocessError):
        print('Release metadata validation or read-only lookup failed.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
