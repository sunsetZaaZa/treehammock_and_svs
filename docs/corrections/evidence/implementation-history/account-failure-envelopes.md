# COR23AC — strict account failure-envelope assertions

Owner: R10E-01 only. Baseline: completed COR23AB. Status: FixedPendingQualification; actual compiled HTTP/assertion/mutation qualification remains NotRun.

Replace status-only and object-map validation compatibility in ApiValidationEnvelopeTests and AccountAdjustIntegrationTests with one test-only strict helper. Require actual HTTP/envelope status, false success, exact typed code, complete validation error/message arrays, exact field names and explicitly declared route data. Preserve current null-property omission, successful result checks and stale-trust AppStatus. Distinguish model and controller validation; do not introduce production compatibility exceptions.

Add compiled adversarial assertions covering status-only, missing/wrongly typed properties, incorrect status/code, malformed validation rows/messages, duplicates, null/data/error differences, transport mismatch and empty/malformed/wrong-media-type bodies. Author a required real .NET Release mutation runner: current HTTP suites pass, default framework model-state body must fail despite 400, required-key wrong/omitted code must fail despite 428, and restored suites pass after each private mutation. Require actual designated assertion failures and fresh complete discovery/TRX/theory counts. Reuse Z owned process containment and restore exact private bytes; the user checkout's production files stay unchanged.

Python tooling executes source rejection, mutation isolation/restoration and receipt validation against synthetic records; it does not execute C# or qualify HTTP. The actual native runner records zero cases/NotRun without the SDK. See [account failure contracts](../testing/ACCOUNT_FAILURE_ENVELOPES.md).

Only R10E-01/COR23AC advance. Other 83 findings and 31 followups, SQL/locks/original evidence and all 186 Open release gates remain unchanged. Ledger: 81 FixedPendingQualification / 3 Open. No schema migration, production API change or legacy compatibility system. Native integrated qualification remains COR24.

Next: COR23AD, deterministic disposal of two-factor application factories.
