# COR23B additional current-source review

Review date: 2026-10-08. Basis: current source inspection; C# and repository/runtime behavior are inferred, not executed. This is an explicit new review import; the frozen R06/R10 reports and original 83 findings remain unchanged.

## R23B-01 — Repository target comparison omits authenticator predecessor identity and version

Priority P2; owner COR23AF; state Open. `AuthenticatorAppEnrollmentRepo.BeginAuthenticatorAppSetupAsync` compares the grant target with the three-argument AuthenticatorSetup call. The controller and service pass the expected enrollment ID and version. The helper serializes five array elements and defaults the last two to null. For a non-null predecessor the upstream target differs from the repository target, so a valid replacement is denied before SQL. This defect blocks actual repository replacement qualification even after COR23B repairs the SQL predicate. It does not change R06-02's frozen observation or one-finding scope.

Source identities observed at import:

- `Repos/AuthenticatorAppEnrollmentRepo.cs`: `5df3ee8e9c3006664b3e921c064e275ad6f73394a6eddf29df0e1c543777bc61`
- `Rigging/Security/SensitiveActionTargets.cs`: `2c90d27fdd1572837777e725895179191f2717e5cc3e9b4f74b770c6bfa81fb8`
- `Controllers/AccountTwoFactorController.cs`: `d8f677c8f879fbc91170423b85435da80b3d2b7a1c6156332942a180d1d1e218`
- `Services/AuthenticatorAppProvisioningService.cs`: `879a6dc5ec8dfbea8afe4e560f65e017edb24b00268d09f178785d2cb2bc08f1`

## Detailed corrective PR — COR23AF

**Title:** Bind authenticator replacement grant targets consistently through the repository.

**Owns:** R23B-01 only. **Depends on:** COR08, COR16, COR23B and COR23. **Coordinates with:** COR23C actual reader qualification; COR24 runtime qualification.

**Files:** Repos/AuthenticatorAppEnrollmentRepo.cs; Rigging/Security/SensitiveActionTargets.cs; focused actual repository and service regression cases. Inspect Controllers/AccountTwoFactorController.cs and Services/AuthenticatorAppProvisioningService.cs as the current upstream target contract.

**Implementation:** Build the repository's canonical target with the command's expected predecessor enrollment ID and version, matching the controller and service. Preserve grant validation, expected identity/version SQL arguments, fresh setup null predecessor behavior, account/session/purpose binding and fail-closed mismatches. Use the current typed target helper; do not accept a target made for a different predecessor or omit predecessor binding to permit replacement.

**Regression cases:** A fresh setup with null predecessor succeeds. A grant-bound replacement carrying the current predecessor ID/version reaches actual PostgreSQL and commits the new encrypted enrollment. A stale identity/version, changed label/required/provider, missing grant or target made for a different predecessor is denied with retained state. The actual repository negative control that removes the two predecessor arguments must fail the valid replacement case, not merely compile or trip a lexical witness. The service/controller and repository must agree on canonical target shape.

**Acceptance:** Compile and execute the production repository/service path using real PostgreSQL, grant consumption, enrollment-bound v2 material and an independent durable-state observer. Publish exact passing cases and failing mutation evidence, retaining all native prerequisites and original gates. Source comparison alone cannot close this finding. Review result readers under the existing COR23C scope, without moving its ownership here.

**Schema policy:** Direct current pre-1.0 contract edits; no upgrade, compatibility or backfill strategy. No schema change is expected. Record append-only implementation/qualification history and keep old unbound entry points denied.
