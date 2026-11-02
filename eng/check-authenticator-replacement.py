#!/usr/bin/env python3
"""Source guard only; actual repository/PostgreSQL mutation evidence is mandatory."""
import argparse,importlib.util,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
REPO='Repos/AuthenticatorAppEnrollmentRepo.cs'
HELPER='Rigging/Security/SensitiveActionTargets.cs'
SERVICE='Services/AuthenticatorAppProvisioningService.cs'
CONTROLLER='Controllers/AccountTwoFactorController.cs'
TEST='treehammock.Tests.SqlContracts/Integration/Database/AuthenticatorReplacementTests.cs'
BOUND='SensitiveActionTargets.AuthenticatorSetup(commandModel.AuthId, commandModel.Required, commandModel.TotpProviderType, commandModel.ExpectedEnrollmentId, commandModel.ExpectedVersion)'
def require(value,message):
    if not value:raise ValueError(message)
def validate(root=ROOT):
    repo=(root/REPO).read_text();helper=(root/HELPER).read_text();service=(root/SERVICE).read_text();controller=(root/CONTROLLER).read_text();test=(root/TEST).read_text()
    require(repo.count(BOUND)==1,'Repository must bind both expected predecessor fields')
    for token in ['commandModel.Grant is null || commandModel.Grant.CanonicalTarget !=','"@expectedRequestId", NpgsqlDbType.Uuid','DbValue(commandModel.ExpectedEnrollmentId)','"@expectedVersion", NpgsqlDbType.Bigint','DbValue(commandModel.ExpectedVersion)','commandModel.Grant.SessionHash','commandModel.Grant.TokenHash','commandModel.Grant.TargetHash','commandModel.Context.AccountId != commandModel.AccountId','DependencyStage stage = DependencyStage.Acquire','LogRepositoryFailure(exception, procedure, scope, stage: stage);']:
        require(token in repo,'Repository binding/context/dependency boundary missing: '+token)
    require('expectedEnrollmentId = null, long? expectedVersion = null' in helper and 'required, (int)provider, expectedEnrollmentId, expectedVersion' in helper,'Canonical five-element target and fresh nulls required')
    require('AuthenticatorSetup(command.Label, command.Required, command.ProviderType, command.ExpectedEnrollmentId, command.ExpectedVersion)' in service and 'protectedSecret.Context, command.ExpectedEnrollmentId, command.ExpectedVersion)' in service,'Service must preserve predecessor shape into command')
    require('AuthenticatorSetup(payload!.label, payload.required, payload.provider, payload.expectedEnrollmentId, payload.expectedVersion)' in controller,'Controller target differs from repository/service')
    for token in ['Actual_repository_replacement_with_predecessor_bound_grant_commits','Actual_service_and_repository_agree_on_fresh_and_replacement_targets','Stale_or_mismatched_target_preserves_original_setup','Canonical_targets_preserve_five_fields_and_label_normalization','new AuthenticatorAppEnrollmentRepo(storage','new AuthenticatorAppSetupService(repo','Cor16EnrollmentSql.SeedGrant','var observer = await f.OpenConnectionAsync();','(await Snapshot(observer, a, ct)).ShouldBe(before);','await AssertConsumed(observer, grant, false, ct);','protector.Unprotect(stored)','await using var storage','"other-predecessor"','"stale-identity"','"stale-version"','"label"','"required"','"provider"','"missing"','"session"','"purpose"','"account"']:
        require(token in test,'Actual repository/state/negative fixture missing: '+token)
    spec=importlib.util.spec_from_file_location('replacement_native_inventory',ROOT/'eng/test-authenticator-replacement.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native);inventory=native.expected(root)
    require('Cor23AFAuthenticatorReplacementTests' in (root/'eng/correction-baseline.py').read_text(),'Owned foundation must execute actual repository suite')
    require('--authenticator-replacement' in (root/'.github/workflows/treehammock-ci.yml').read_text(),'Required CI native mutation fixture missing')
    return dict(status='SourceContractsConsistent',qualification='NotRun',methods=len(inventory),expected_executions=sum(inventory.values()),native='Actual service/repository, independent PostgreSQL observer and failing three-argument mutation required')
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=ROOT);args=parser.parse_args()
    try:print(json.dumps(validate(args.root)));return 0
    except (OSError,ValueError):print('Authenticator replacement source contract failed.');return 1
if __name__=='__main__':raise SystemExit(main())
