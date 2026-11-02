#!/usr/bin/env python3
"""Generate/verify committed bindings with the centrally pinned Grpc.Tools compiler."""
import argparse
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import xml.etree.ElementTree as ET

root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--verify', action='store_true')
parser.add_argument('--tools-root', type=Path, help='Restored grpc.tools package directory')
args = parser.parse_args()
version = next(e.attrib['Version'] for e in ET.parse(root/'Directory.Packages.props').iter('PackageVersion') if e.attrib['Include']=='Grpc.Tools')
package = args.tools_root or Path(os.environ.get('NUGET_PACKAGES', str(Path.home()/'.nuget/packages')))/'grpc.tools'/version
system = platform.system()
arch = {'x86_64':'x64','amd64':'x64','aarch64':'arm64','arm64':'arm64'}.get(platform.machine().lower(), platform.machine().lower())
os_name = {'Linux':'linux','Darwin':'macosx','Windows':'windows'}.get(system)
tools = package/'tools'/f'{os_name}_{arch}'
extension = '.exe' if system=='Windows' else ''
compiler = tools/('protoc'+extension)
plugin = tools/('grpc_csharp_plugin'+extension)
if not compiler.is_file() or not plugin.is_file():
    raise SystemExit('Pinned compiler unavailable. Restore the Contracts project and/or pass --tools-root; this platform must be supported by Grpc.Tools.')
for path in [compiler, plugin]:
    if system!='Windows':path.chmod(path.stat().st_mode | 0o100)
destination = root/'src/Treehammock.SessionValidation.Contracts/Generated'
with tempfile.TemporaryDirectory() as temp:
    out=Path(temp)
    subprocess.run([str(compiler), '--proto_path='+str(root/'contracts'), '--csharp_out='+str(out),
                    '--grpc_out='+str(out), '--plugin=protoc-gen-grpc='+str(plugin),
                    'session-validation-v1.proto'], check=True)
    generated=sorted(p.name for p in out.glob('*.cs'))
    if len(generated)!=2:raise SystemExit('Unexpected generated binding set')
    if args.verify:
        if generated != sorted(p.name for p in destination.glob('*.cs')) or any((out/n).read_bytes()!=(destination/n).read_bytes() for n in generated):
            raise SystemExit('Committed bindings differ from pinned compiler output')
    else:
        destination.mkdir(parents=True, exist_ok=True)
        for n in generated:(destination/n).write_bytes((out/n).read_bytes())
print(('Verified' if args.verify else 'Generated')+' pinned C# protobuf/gRPC bindings ('+version+')')
