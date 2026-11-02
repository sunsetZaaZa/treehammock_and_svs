#!/usr/bin/env python3
"""Source audit for the explicit SVS-01-C01 correction; historical PR snapshots stay frozen."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PREDECESSOR = 'b9432c2bd44e159595e570ee76db3e662cbaae2818231ba9e838afb81f3d1252'
CHANGES = {
    'Controllers/AccountControllerBase.RepositoryGuards.cs', 'Controllers/AccountTwoFactorController.cs',
    'Services/PasswordResetService.cs', 'Services/SMTPService.cs',
    'docs/session-validation/SVS_PR_TRACKER.json',
    'treehammock.Tests/Infrastructure/PublicHttpFixture.cs',
    'treehammock.Tests/Infrastructure/TestConfiguration.cs',
    'treehammock.Tests/Unit/AccountControllerAuthenticateTests.cs',
    'treehammock.Tests/Unit/AccountControllerSafeRepoWrapperTests.cs',
    'treehammock.Tests/Unit/DeleteAuthorityTests.cs',
    'treehammock.Tests/Unit/CacheWriteTests.cs',
    'treehammock.Tests/Unit/AuthoritativeBudgetTests.cs',
    'treehammock.Tests/Unit/DependencyInjectionRegistrationTests.cs',
    'treehammock.Tests/Unit/PasswordResetRequestOrchestrationTests.cs',
    'treehammock.Tests/Unit/SessionCacheWarmupTests.cs'
}
ADDITIONS = {
    'Controllers/AccountControllerBase.SensitiveActions.cs',
    'treehammock.Tests/Unit/BuildCorrectionRegressionTests.cs',
    'docs/session-validation/SVS-01_SOURCE_INVENTORY.json',
    'docs/session-validation/BUILD_CORRECTION.md',
    'eng/session-validation/collect-build-correction.py'
}
spec = importlib.util.spec_from_file_location('source_inventory', ROOT/'eng/session-validation/collect-source-inventory.py')
inventory = importlib.util.module_from_spec(spec); spec.loader.exec_module(inventory)


def collect(root, output):
    root=root.resolve();output=output.resolve()
    if root==output or root in output.parents:raise ValueError('Output must be outside the source tree')
    frozen=(root/'docs/session-validation/SVS-01_SOURCE_INVENTORY.json').read_bytes()
    if hashlib.sha256(frozen).hexdigest()!=PREDECESSOR:raise ValueError('Predecessor inventory changed')
    previous=json.loads(frozen);current=inventory.source_inventory(root)
    missing=sorted(set(previous)-set(current));added=sorted(set(current)-set(previous))
    changed=sorted(n for n in previous if n in current and previous[n]!=current[n])
    if set(changed)!=CHANGES or set(added)!=ADDITIONS or missing:raise ValueError('Source differs from the reviewed correction paths')
    # Contract library, protobuf, SDK selection, package pins and SQL must remain byte-identical.
    immutable=[n for n in previous if n.startswith(('src/','tests/','contracts/','Rigging/Database/')) or
               n in {'treehammock.csproj','Directory.Packages.props','global.json','packages.lock.json'}]
    if any(previous[n]!=current[n] for n in immutable):raise ValueError('Unexpected SVS/build/dependency/SQL change')
    output.mkdir(parents=True,exist_ok=True)
    inventory.write_json(output/'SOURCE_INVENTORY.json',current)
    report={'correction':'SVS-01-C01','static_status':'PASS','predecessor_inventory_sha256':PREDECESSOR,
            'candidate_inventory_sha256':inventory.sha(inventory.encoded(current)),
            'source_files':len(current),'unchanged_predecessor_files':len(previous)-len(changed),
            'changed_files':changed,'added_files':added,'deleted_files':missing,
            'svs_contract_source_unchanged':True,'sql_and_dependency_pins_unchanged':True,
            'runtime_checks':'See separate VALIDATION.json; hashes alone do not prove behavior',
            'next_pr':'SVS-02','release_ready':False}
    inventory.write_json(output/'BASELINE_CHECK.json',report)
    print(json.dumps({k:report[k] for k in ['correction','static_status','source_files','unchanged_predecessor_files']}))
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    try:collect(ROOT,args.output)
    except (ValueError,OSError) as error:raise SystemExit('Build correction inventory failed: '+str(error))
