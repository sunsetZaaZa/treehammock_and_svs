# COR23AF — predecessor-bound authenticator replacement grants

Owner: R23B-01 only. Baseline: completed COR23AE. Status: FixedPendingQualification; actual repository/service/PostgreSQL and native mutation execution remain NotRun.

Build the repository's canonical authenticator setup target with ExpectedEnrollmentId and ExpectedVersion, matching the unchanged controller and service. Fresh setup still serializes null/null. Preserve label normalization, required/provider binding, grant presence, account/stamp/session/purpose/target checks, expected predecessor SQL parameters and enrollment-bound v2 material. No unbound target bypass or alternate entry point is added.

The same repository's logging helper referenced an undefined stage and lacked the named stage parameter used by its callers. Add that private dependency-stage parameter and pass the rollback stage through, so the touched repository's failure reporting can compile and preserve its observed phase. No reader conversion or SQL change is part of this correction; COR23C retains result-reader ownership.

The new actual SQL suite defines six methods/eighteen executions: canonical five-field/normalization contract; fresh null-predecessor commit; real repository replacement; thirteen stale/mismatched/missing grant or authority variants; real provisioning service plus repository fresh/replacement flow; verified-enrollment retention. A separate connection observes committed row identity, setup UUID/version, encrypted v2 envelope, persisted associated-data parameters, decryptable secret and grant consumption. Conflict/invalid-authority denials retain the original row and do not consume the grant. Existing SQL consumes an authorized grant before the already-attached return; the verified-enrollment case preserves that contract.

Completed password/factor attestation is the explicit existing COR16 fixture substitute. The canonical target is hashed with the real typed HMAC helper into the fixture grant/proof records. Production provisioning, repository operations, PostgreSQL authorization/consumption, encryption and independent observers are real in the authored native tests. The controller target shape is inspected unchanged; full controller/System behavior remains part of integrated qualification.

The owned SQL/cache fixture can select the new native runner. It executes the full suite, removes exactly the two predecessor arguments in a disposable private checkout, requires the designated valid replacement Fact to fail at its real Shouldly assertion, restores source and reruns the complete suite. A compile error, absent/skipped TRX, wrong failure or passing mutant cannot qualify the negative control. Existing ownership contains SDK/test-host processes and removes only the fixture's resources. CI requires current repository cases and the actual mutation runner for Redis and Dragonfly. See [qualification contract](../testing/AUTHENTICATOR_REPLACEMENT.md).

The transition rejection tests now initialize an explicit Open record only in their private fixtures, rather than assuming the project still has an Open finding. Production ledger/history remain intact.

Only R23B-01/COR23AF advance. Other 83 findings/31 followups, all 76 protected SQL/lock/original evidence/gate files and the imported additional review remain unchanged. Ledger: 84 FixedPendingQualification / 0 Open; all 186 release gates Open. The typed target helper, controller, service, encryption and repository readers remain unchanged. Refresh the existing COR23C consumer inventory for intentional source changes. No schema, package, endpoint, migration or compatibility system change.

Next: COR24, integrated native/release qualification after prerequisites and per-owner runtime evidence are available.
