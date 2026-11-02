# Treehammock review R10E — large authentication suites and HTTP assertions

Reviewed 2026-10-03 against the unchanged uploaded source. This is a source review and correction-plan addendum, with no application or test-code changes.

R10E adds **one P2 finding**, bringing the cumulative ledger to **81 open findings: 18 P1 and 63 P2**. None is closed. Four selected suites received complete source inspection; the Authenticate authorization filter also received a complete cross-check and its earlier inventory qualification was updated. **40 R10-assigned files and three partial R06 SQL test files remain.** This is not a global outstanding-file count: earlier source evidence and legacy inventory qualifiers still require reconciliation, and some earlier suites were indexed or inspected only in slices. No chunk is runtime-qualified.

## Scope and validation

| Fully inspected suite | Source lines | Fact methods | Theory methods | InlineData rows | MemberData source rows |
|---|---:|---:|---:|---:|---:|
| Unit/AccountControllerAuthenticateTests.cs | 1,879 | 54 | 7 | 8 | 13 |
| Unit/JsonWebTokenMiddlewareTests.cs | 1,600 | 37 | 1 | 4 | 0 |
| Integration/ApiValidationEnvelopeTests.cs | 405 | 16 | 0 | 0 | 0 |
| Integration/AccountAdjustIntegrationTests.cs | 355 | 6 | 1 | 2 | 0 |
| **Total** | **4,239** | **113** | **9** | **14** | **13** |

Paths are relative to treehammock.Tests. The source contains **122 attributed methods**. Three MemberData references use providers with 13 explicit yield rows. These are source counts, not runtime discovery, execution or passing-test counts.

The review cross-checked the complete Authenticate filter, ApiResponse model and allowing idempotency fixture, plus model-state response registration and relevant response/timeout/rotation slices. AccountFlowRegressionTests received a strict-envelope-helper cross-check; AccountEndpointContractTests received targeted searches. Those two large suites remain deferred for full review. Release matrices received targeted claim checks and remain scheduled for full documentation review.

Both original runners were attempted with Release and locked restore: `eng/dotnet-unit-tests.sh` and `eng/dotnet-integration-tests.sh`. Both exited **127** at the missing SDK, before restore/build/discovery/test. There was no C# execution, TestServer request, real PostgreSQL/cache operation or performance measurement. PowerShell, Docker, PostgreSQL tools and redis-server are also unavailable.

The evidence builder verified all **451 source files** against the upload, cataloged every selected attributed method and source data provider, and checked 16 source assertions. Nonconforming JSON examples below are branch-derived witnesses, not executed C# reproductions or responses observed from the application.

## R10E-01 — Failure-envelope tests accept a different response contract

**Priority: P2. Correction owner: COR23AC.**

ApiValidationEnvelopeTests.AssertFailureEnvelope at lines 357–369 checks success, statusCode and code only when a success property exists. Otherwise it accepts a matching `status` and returns without checking the expected error code. AccountAdjustIntegrationTests repeats the same branch at 321–333. Validation error helpers also accept object maps as well as the expected array records.

The production contract is more specific. ApiResponse requires success, statusCode and code and represents errors as a list of field/messages records. Program at line 44 explicitly installs ApiResponses.InvalidModelState for framework validation. The Authenticate filter returns ApiResponses.Unauthorized for unauthenticated protected requests. These inspected account responses are intended to use the envelope; the documented direct health-response exception does not apply.

For example, a 400 response with this body can satisfy the failure helper and the password-field assertion without satisfying the intended envelope:

```json
{"status":400,"errors":{"password":["invalid"]}}
```

Likewise, the adjustment test for a missing required idempotency key can accept an HTTP 428 body of `{"status":428}` through its failure helper, without checking the required error code. These conclusions follow from the source branches; they were not executed here.

**Impact.** These particular HTTP tests can continue to pass if validation falls back to a framework-style response or an account error loses its envelope/code. Their names and assertions then overstate protection of the wire contract clients depend on. This is an assertion defect, not a newly established production response bug. Other suites contain strict envelope checks—AccountFlowRegressionTests at 1496–1501 is one example—so this review does not claim the entire release suite would necessarily pass such a regression.

**Correction.** Remove the permissive fallback from the affected account-contract assertions and require the agreed JSON schema, expected status and expected code. Require field/messages array records for these validation responses. Share a strict assertion helper where appropriate. Keep any deliberate compatibility or direct-payload exception in a separately named test with an explicit route/contract scope; do not let it weaken every account failure check.

This is independent of COR23E's no-store/privacy correction and of the application's existing authentication/storage defects. Those concerns are not recounted as new findings here.

## Useful coverage and its actual limits

| Suite | Behavior checked in source | Qualification still required |
|---|---|---|
| Login action | Identifier shape/selection, verification disclosure after password checks, lockout handling, failure persistence errors, initial session creation and rollback, database-first rotation, cache degradation, preauth selection state and factor availability. | Actions run through AccountControllerHarness with substitute JWT/cache/repos/services. Argument assertions do not establish durable ownership, atomic counters, stamp races or actual cryptographic admission. |
| JWT middleware | Real middleware invocation checks cache hit/miss/stale payload, database-trust outcomes, authoritative access/hard/cutoff horizons, refresh caps, cache degradation and timeout denial. | JWT validation and storage are substitutes. This suite establishes dispatch/context/header decisions for supplied outcomes, not signature correctness or real database/cache consistency. |
| Validation HTTP | Actual host/client test code covers empty/malformed/model/runtime-invalid input and unauthenticated protected routes. | Requests were not run here. The permissive assertion branches weaken schema proof. HTTPS base addresses on TestServer do not qualify real TLS/proxy/listeners. |
| Adjustment HTTP | Username success/duplicate, email pending verification, invalid input, missing required key and stale cached trust outcomes. | Factory substitutes cache/JWT/session/account/service and installs the allowing replay fixture. It does not establish real profile mutation, fresh proof or durable replay behavior. |

Several contracts should be preserved during correction. Successful durable login/refresh remains usable after cache writes or old-cache deletion fail; these tests correctly avoid compensating away a committed session merely because cache cleanup failed. The database-trust tests also require authoritative horizons and stamps before granting context. They do not demonstrate that stale cache alone authenticates a revoked session.

The login suite has an explicit sequence assertion at 679–724 for database rotation, new cache publication and old-cache revocation. Its abuse-policy case at 1627–1664, however, asserts receipt of increments and lookup without checking their relative order despite “before account lookup” in the name. Denial tests do assert that lookup does not occur after an IP throttle. Extend the successful-admission ordering case under COR05/COR08; this narrow limitation does not create a second finding.

The middleware metadata rehydration assertion at 1182–1185 repeats the same premium-feature predicate. That redundancy is a minor test cleanup, not a new correctness/performance defect or proof of missing security behavior.

## Existing findings that require assertion changes

**Transient outages — COR03.** Middleware tests at 1428–1489 currently expect CLIENT_CLEAR_ACCESS_TOKEN when database lookup/trust validation times out. These preserve the already recorded AUTH-10 outage-as-invalid-credentials behavior. Revise them with the chosen corrected transient-error contract. Protected actions must remain denied, while response controls must stop instructing permanent credential erasure merely because authority was temporarily unavailable. Keep separate tests for an actual missing/revoked session.

**Refresh winner/loser — COR09.** The failed-rotation, old-session-mismatch and exception cases at 779–899 expect clear-token responses. A single supplied mismatch cannot distinguish logout from another concurrent refresh winning. AUTH-01 requires a controlled competing-request schedule and client-state assertions. Reconcile existing expectations with the corrected policy rather than allowing the old assertions to dictate the fix.

**Timeout outcome — COR04.** The four timeout tests at 1393–1525 use unresolved TaskCompletionSource operations and 10 ms timeout settings. They exercise waiting-path decisions, but do not complete a delayed rotation, observe a commit after the response, or prove cancellation at the storage boundary. Add late-success, late-failure, cancellation and lost-response schedules tied to actual authority. No flakiness or latency result is claimed from source alone.

**Counters and lockout — COR05/COR08.** Direct tests correctly assert persistence error responses and no session creation on failure. Sequential expected values such as SetLoginFailures(account, 2) cannot qualify concurrent failure increments or atomic lockout transitions. Revise repository-facing expectations if the durable operation changes, preserving public behavior while proving no lost failures and the intended reset-versus-failure order.

**Two-factor authority — COR10.** Pending-session tests preserve distinct preauth tokens, selection state, available verified methods and no premature active session. They also check pointer replacement before previous pending-cache revocation. Keep those contracts while adding real current-challenge/stamp/expiry schedules; successful mocked BeginTwoFactorSession does not prove fresh challenge authority.

**Adjustment proof/replay — COR17/COR06.** The allowing replay fixture is stronger than the direct harness's NotApplied default: it rejects missing required keys, uses the production key normalizer and creates a reservation for valid keys. Completion is a no-op and there is no shared reservation/result storage. It therefore supplies key admission, not cache-backed replay exclusion, ownership or response recovery. Current email-adjustment tests use no fresh sensitive proof and a substituted account service. Add actual proof/replay qualification when those corrections land, and retain focused HTTP response checks.

## Detailed PR specification — COR23AC

**Problem and result.** Account failure-contract tests accept responses missing the contract they claim to enforce. A corrected test lane must fail when success/statusCode/code disappear or validation errors change shape, while preserving successful checks of the currently intended responses.

**Primary files.** treehammock.Tests/Integration/ApiValidationEnvelopeTests.cs and AccountAdjustIntegrationTests.cs. Add a shared test-only HTTP assertion helper under Infrastructure if useful, then reconcile equivalent helpers in other suites during their full review. ApiResponse, ApiResponses, Program and the authorization filter define the reference behavior; a production change is not required solely to fix this finding.

**Implementation.** Require a JSON object with correctly typed success, statusCode and code; assert false, the expected HTTP/envelope status and exact expected error code. Check the expected account validation error array, field names and nonempty string message lists. Preserve route-specific data/result assertions and agree null/omission behavior for optional data/errors rather than silently allowing unrelated schemas. Remove the status-only branch and object-map validation compatibility from these account assertions. Name any intentionally supported alternative contract explicitly and limit it to its intended endpoints.

**Executable acceptance.** Run both affected HTTP suites in the actual host. Missing/malformed body, invalid identifiers/password/country/factor fields, protected-route denial, adjustment validation/duplicate/stale trust and required-key 428 must retain exact envelopes. In a disposable mutation run, replace model-state envelope registration with the framework default and require the relevant HTTP tests to fail for schema/code differences even when status remains 400. Also make a required-key denial omit or alter its code while retaining 428 and require that test to fail. Restore the production path and prove the same cases pass. Retain discovery and results under COR01/COR24; source text assertions alone cannot close this finding.

**Dependencies.** The schema correction can be implemented against the current behavior without waiting for every domain fix. Final execution requires a working SDK/restore lane and configuration consistent with COR23L; later security/privacy changes must update expected responses deliberately. Coordinate the eventual shared helper with R10F, whose full suites remain unreviewed here. This PR owns R10E-01 only; related domain findings retain their earlier owners.

**Migration/rollback.** Test-only change; no schema migration or public API change. Reverting assertions would restore the verification hole. Any proposed production compatibility exception must be documented as an explicit supported contract and tested separately before it can replace the current expectation.

## Integrated closure and remaining review

Existing domain PRs should carry the revised behavior tests above alongside real SQL/cache schedules, with COR24 retaining cross-instance and lost-response evidence. Measure production password cost, refresh contention, database work on cache hits and acquisition/fault latency under COR01/COR22/COR24. Reduced test hash parameters, fake storage and ten-millisecond fixture settings are not production capacity evidence.

R10F should fully inspect AccountFlowRegressionTests and AccountEndpointContractTests. Startup, repository/cache/system suites, dependency binaries, release/SQL matrices, examples and the large HTML inventory still require their scheduled passes. Reconcile older per-file evidence with qualification markers before declaring global source completion: some earlier complete-source descriptions retain legacy pending qualifiers, and earlier indexed/partial suites must actually be inspected in full. The Authenticate filter row is now explicitly complete from this chunk; other rows are not upgraded merely because their names were searched.

The cumulative bundle includes earlier reports/evidence, this report and source catalog, both blocked runner attempts, the updated 81-finding ledger and Through_10E file inventory. Original design/PR planning documents remain unchanged; this report adds COR23AC and refines existing acceptance criteria. No feature-complete, security-approved or performance-qualified release claim is made.
