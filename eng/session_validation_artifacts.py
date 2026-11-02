#!/usr/bin/env python3
"""Bundle and verify a release's framework-dependent SVS host and client DLLs.

Only an actually published net10 host and built net8/net10 client can be packaged.
This tool does not grant production security/native qualification.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile
import gzip

BASE = Path(__file__).resolve().parents[1]
EXAMPLES = (
    ('deploy/session-validation/README.md', 'docs/deployment.md'),
    ('deploy/session-validation/host.example.json', 'examples/host.example.json'),
    ('deploy/session-validation/client.example.json', 'examples/client.example.json'),
    ('LICENSE', 'LICENSE'),
)
PREFIX = 'session-validation'
DLL = 'Treehammock.SessionValidation.Api.dll'
CLIENT = ('Treehammock.SessionValidation.Client.dll', 'Treehammock.SessionValidation.Contracts.dll')

class PackageError(Exception):
    pass

def require(ok, msg):
    if not ok:
        raise PackageError(msg)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def canonical(tag, sha):
    require(isinstance(tag, str) and re.fullmatch(r'v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)?', tag), 'Invalid release tag')
    require(isinstance(sha, str) and re.fullmatch('[0-9a-f]{40}', sha), 'Invalid source SHA')

def get_published_files(source):
    service = source / 'service'
    require(service.is_dir() and not service.is_symlink(), 'Missing SVS published host')
    require((service / DLL).is_file(), 'Missing compiled SVS host DLL')
    config_path = service / 'Treehammock.SessionValidation.Api.runtimeconfig.json'
    require(config_path.is_file(), 'Missing .NET 10 runtime config')
    config = json.loads(config_path.read_text())
    frameworks = config.get('runtimeOptions', {}).get('frameworks', [])
    single = config.get('runtimeOptions', {}).get('framework')
    if single:
        frameworks.append(single)
    require(any(f.get('name') == 'Microsoft.NETCore.App' and str(f.get('version', '')).startswith('10.') for f in frameworks), 'Not a .NET 10 service')
    blobs = {}
    for file in sorted(service.rglob('*')):
        require(not file.is_symlink(), 'Symlinked publish output prohibited')
        if not file.is_file():
            continue
        rel = file.relative_to(service).as_posix()
        require(not re.search(r'(?i)(\.pem$|\.pfx$|\.key$|\.env$|secrets|credentials|private[-_]?key)', rel), 'Secret-like file in publish output')
        blobs['service/' + rel] = file.read_bytes()
    for framework in ('net8.0', 'net10.0'):
        for name in CLIENT:
            file = source / 'client' / framework / name
            require(file.is_file() and not file.is_symlink(), 'Missing SVS client/contract ' + framework + '/' + name)
            blobs['client/' + framework + '/' + name] = file.read_bytes()
    for src, dest in EXAMPLES:
        p = BASE / src
        require(p.is_file() and not p.is_symlink(), 'Missing source documentation: ' + src)
        blobs[dest] = p.read_bytes()
    instructions = (
        'SessionValidation deployment bundle\n'
        '===================================\n'
        'service/: framework-dependent .NET 10 SessionValidation gRPC host.\n'
        'Requires the .NET 10 ASP.NET Core runtime on the deployment host.\n'
        'Run only on private HTTP/2 with configured mTLS and permitted validator credentials.\n'
        'examples/: templates only; never deploy with example credentials or sample trust roots.\n'
        'client/: built net8.0/net10.0 client and wire-contract DLLs for reference.\n'
        'Client DLLs are not self-contained NuGet packages; restore their NuGet dependencies\n'
        'from the matching source project before integrating.\n'
        'Native Yugabyte/Dragonfly and independent security/physical testing are NOT\n'
        'satisfied by the managed CI lane. This artifact is NOT production-approved.\n'
    )
    blobs['README.txt'] = instructions.encode()
    return blobs

def create_archive(path, files):
    # reproducible tar.gz: path order, no host ownership or timestamps
    buffer = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', fileobj=buffer, mtime=0, compresslevel=9) as compressed:
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as archive:
            for name, data in sorted(files.items()):
                member = tarfile.TarInfo(PREFIX + '/' + name)
                member.uid = member.gid = 0
                member.uname = member.gname = ''
                member.mtime = 0
                member.mode = 0o644
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
    path.write_bytes(buffer.getvalue())

def inspect_archive(path):
    files = {}
    with tarfile.open(path, 'r:gz') as archive:
        for item in archive:
            name = PurePosixPath(item.name)
            require(item.isfile() and not item.issym() and not item.islnk(), 'Unexpected archive entry')
            require(not name.is_absolute() and '..' not in name.parts and len(name.parts) >= 2 and name.parts[0] == PREFIX, 'Unsafe archive path')
            key = '/'.join(name.parts[1:])
            require(key not in files, 'Duplicate archive member')
            files[key] = archive.extractfile(item).read()
    return files

def package(args):
    canonical(args.tag, args.sha)
    source = Path(args.source)
    target = Path(args.output)
    target.mkdir(parents=True, exist_ok=True)
    archive_name = f'session-validation-{args.tag}.tar.gz'
    path = target / archive_name
    manifest_path = target / 'session-validation-release-manifest.json'
    checksum_path = target / f'session-validation-{args.tag}.sha256'
    require(not any(x.exists() for x in (path, manifest_path, checksum_path)), 'Refusing to replace existing release files')
    blobs = get_published_files(source)
    manifest = {
        'schema_version': 1,
        'service': 'SessionValidation',
        'release_tag': args.tag,
        'source_sha': args.sha,
        'target_framework': 'net10.0',
        'deployment': 'private-grpc-framework-dependent',
        'production_approved': False,
        'qualification': 'Managed tests only; native and security review remain separate',
        'archive': archive_name,
        'files': {k: digest(v) for k,v in sorted(blobs.items())},
    }
    create_archive(path, blobs)
    manifest['archive_sha256'] = digest(path.read_bytes())
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    checksum_path.write_text(manifest['archive_sha256'] + '  ' + archive_name + '\n')
    verify(argparse.Namespace(manifest=str(manifest_path), tag=args.tag, sha=args.sha))
    print('SessionValidation artifact verified: ' + archive_name)

def verify(args):
    path = Path(args.manifest)
    manifest = json.loads(path.read_text())
    require(manifest.get('schema_version') == 1 and manifest.get('service') == 'SessionValidation', 'Unexpected artifact manifest')
    tag = manifest.get('release_tag'); sha = manifest.get('source_sha')
    canonical(tag, sha)
    if args.tag:
        require(tag == args.tag, 'Mismatched release tag')
    if args.sha:
        require(sha == args.sha, 'Mismatched source SHA')
    require(manifest.get('target_framework') == 'net10.0' and manifest.get('production_approved') is False, 'Invalid release qualification metadata')
    archive_name = f'session-validation-{tag}.tar.gz'
    require(manifest.get('archive') == archive_name, 'Release archive name differs')
    data = (path.parent / archive_name).read_bytes()
    require(digest(data) == manifest.get('archive_sha256'), 'Release archive SHA mismatch')
    require((path.parent / f'session-validation-{tag}.sha256').read_text() == f'{digest(data)}  {archive_name}\n', 'Checksum sidecar mismatch')
    files = inspect_archive(path.parent / archive_name)
    require(set(files) == set(manifest.get('files', {})), 'Archive file inventory mismatch')
    require(all(digest(files[k]) == v for k,v in manifest['files'].items()), 'Archive member hash mismatch')
    require('service/' + DLL in files and 'service/Treehammock.SessionValidation.Api.runtimeconfig.json' in files, 'Missing service host')
    for framework in ('net8.0', 'net10.0'):
        for dll in CLIENT:
            require('client/' + framework + '/' + dll in files, 'Missing client binary')
    print(f'Verified {len(files)} SessionValidation release files for {tag}')

def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='command', required=True)
    pack = sub.add_parser('package')
    pack.add_argument('--source', required=True)
    pack.add_argument('--output', required=True)
    pack.add_argument('--tag', required=True)
    pack.add_argument('--sha', required=True)
    check = sub.add_parser('verify')
    check.add_argument('--manifest', required=True)
    check.add_argument('--tag')
    check.add_argument('--sha')
    args = parser.parse_args()
    try:
        package(args) if args.command == 'package' else verify(args)
        return 0
    except (PackageError, OSError, KeyError, ValueError, tarfile.TarError) as exc:
        print(f'SessionValidation packaging rejected: {exc}', file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
