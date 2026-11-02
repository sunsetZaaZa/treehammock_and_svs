#!/usr/bin/env python3
"""Compose prerequisite/result wiring; source consistency is not native proof."""
import argparse,json
from pathlib import Path
import yaml
ROOT=Path(__file__).resolve().parents[1]
def validate(root):
    def require(value,message):
        if not value:raise ValueError(message)
    compose=yaml.safe_load((root/'docker-compose.integration.yml').read_text())['services']
    for lane,name in [('direct','http-contract-tests-direct'),('proxy','http-contract-tests-proxy')]:
        require(compose[name]['command']==['node','/work/eng/compose-http-proof.mjs',lane,'/work/tests/http/bruno/treehammock','/reports'],'HTTP lane bypasses shared proof runner')
        require('./artifacts/compose-proof:/reports' in compose[name]['volumes'],'HTTP reports cannot reach CI')
    system=yaml.safe_load((root/'docker-compose.ci-system.yml').read_text())['services']['system-tests']
    require(system['command']==['bash','./eng/compose-system-proof.sh'] and './artifacts/compose-proof:/reports' in system['volumes'],'System lane bypasses fresh proof')
    node=(root/'eng/compose-http-proof.mjs').read_text();shell=(root/'eng/compose-system-proof.sh').read_text();probe=(root/'eng/ComposeProofProbe/Program.cs').read_text()
    for token in ['request?.destroy()','performance.now()<deadline','Math.min(attempt,left)','--reporter-json','fs.mkdirSync(folder)','validateReport(report,expected)',"result.status!==0","state('Failed')"]:require(token in node,'HTTP deadline/freshness/failure contract missing')
    for token in ['set -euo pipefail','trap finish EXIT','stage="readiness"','stage="restore"','stage="build"','stage="tests"','stage="result-validation"','--results-directory "$lane_run/results"','mkdir "$lane_run"','exit "$primary"']:require(token in shell,'System stage/exit/freshness boundary missing')
    require(shell.index('stage="readiness"')<shell.index('stage="restore"')<shell.index('stage="tests"')<shell.index('stage="result-validation"'),'System prerequisite order differs')
    for token in ['CancellationTokenSource deadline','HttpClient','MaxResponseContentBufferSize = 65536','DtdProcessing.Prohibit','observed.SetEquals(expected)','results.Length != expected.Count']:require(token in probe,'Native readiness/result validation missing')
    require('eng\\ComposeProofProbe\\**' in (root/'treehammock.csproj').read_text(),'Probe entered application compile glob')
    return dict(status='SourceContractsConsistent',qualification='NotRun',lanes=3)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=ROOT);args=p.parse_args()
    try:print(json.dumps(validate(args.root),indent=2));return 0
    except (ValueError,OSError,KeyError,yaml.YAMLError) as error:print(str(error));return 1
if __name__=='__main__':raise SystemExit(main())
