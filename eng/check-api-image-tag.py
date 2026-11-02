#!/usr/bin/env python3
"""Supplemental output/base variable wiring; not PowerShell execution."""
import argparse
import json
from pathlib import Path
import re
ROOT=Path(__file__).resolve().parents[1]
def validate(root):
    text=(root/'eng/docker-api-image.ps1').read_text()
    def require(condition,message):
        if not condition:raise ValueError(message)
    require('Set-Variable -Name outputImage -Value $Image -Option ReadOnly' in text,'Caller output tag is not captured read-only')
    loops=re.findall(r'foreach\s*\(\$(\w+)\s+in\s+\$requiredImages\)',text,re.I)
    require(loops==['baseImage'] and loops[0].lower() not in ('image','outputimage'),'Base loop overwrites the output tag')
    require("@('pull', $baseImage)" in text and "'-t', $outputImage" in text,'Pull/build references are not separate')
    require('$outputImage -eq $sdkImage -or $outputImage -eq $runtimeImage' in text,'Known output/base collision is not rejected')
    for value in ['TREEHAMMOCK_DOTNET_SDK_IMAGE','TREEHAMMOCK_DOTNET_RUNTIME_IMAGE','DOTNET_SDK_IMAGE=$sdkImage','DOTNET_RUNTIME_IMAGE=$runtimeImage',
                  'BUILD_CONFIGURATION=$Configuration','TREEHAMMOCK_BUILD_RUN_ID=$env:TREEHAMMOCK_BUILD_RUN_ID',"'--target', 'api'","'--progress', $Progress","$buildArgs += '--no-cache'","$buildArgs += '.'"]:
        require(value in text,'Wrapper forwarding missing: '+value)
    require("Invoke-TreehammockRunner -Stage 'docker-api-image'" in text and "Invoke-TreehammockNative -Stage 'docker-build' -FilePath 'docker' -Arguments $buildArgs" in text,'Native failure boundary missing')
    require(text.rstrip().endswith("Invoke-TreehammockNative -Stage 'docker-build' -FilePath 'docker' -Arguments $buildArgs\n}"),'Later command can mask the native build result')
    return dict(status='SourceContractsConsistent',qualification='NotRun')
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=ROOT);args=p.parse_args()
    try:print(json.dumps(validate(args.root),indent=2));return 0
    except (ValueError,OSError) as error:print(str(error));return 1
if __name__=='__main__':raise SystemExit(main())
