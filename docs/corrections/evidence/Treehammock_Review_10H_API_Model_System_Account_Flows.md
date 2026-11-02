# Treehammock review R10H — API/model contracts and system account flows

Reviewed 2026-10-03. Source review and correction-plan addendum only; no application or test code changed.

This chunk completes **10 files, 1,653 lines and 70,657 bytes**, including the full system account-flow suite. It adds **one P2 finding**, R10H-01, owned by **COR23AE**: the system registration-verification success check accepts a failure page with HTTP 200. The cumulative ledger now contains **83 open findings: 18 P1 and 65 P2**. None are closed.

The system suite exercises real HTTP, issued credentials and captured deliveries when executed against its configured stack. It therefore has a different boundary from the substituted in-process flow suite. It has not been executed in this review, and its happy-path coverage does not close the existing concurrency, authority, replay, provider or performance findings.

## Complete source scope

| File | Lines | Bytes | Source test attributes |
| --- | ---: | ---: | --- |
| `treehammock.Tests/Unit/GreenfieldApiNegativeContractTests.cs` | 79 | 2,806 | 2 Facts, 1 Theory |
| `treehammock.Tests/Unit/ModelValidationConsistencyTests.cs` | 116 | 4,110 | 7 Facts, 1 Theory |
| `treehammock.Tests/Unit/TreehammockLicenseTests.cs` | 61 | 1,979 | 2 Facts |
| `treehammock.Tests/Unit/TreehammockRenameCompletionTests.cs` | 124 | 3,867 | 2 Facts |
| `treehammock.Tests.SqlContracts/GlobalUsings.cs` | 1 | 20 | Support |
| `treehammock.Tests.SqlContracts/Properties/AssemblyInfo.cs` | 8 | 477 | Assembly execution policy |
| `treehammock.Tests.System/AssemblyInfo.cs` | 3 | 80 | Assembly execution policy |
| `treehammock.Tests.System/GlobalUsings.cs` | 1 | 20 | Support |
| `treehammock.Tests.System/Support/TreehammockEnvironment.cs` | 15 | 363 | Environment helper |
| `treehammock.Tests.System/SystemStackAccountFlowTests.cs` | 1,245 | 56,935 | 22 Facts plus local TOTP helper |
| Total | **1,653** | **70,657** | **35 Facts, 2 Theories** |

The two theories have eight InlineData rows. These are source counts, not runtime-discovered or passed tests. Five files contain test classes and five are support/assembly files. All test methods and data attributes are cataloged in the evidence JSON.

Two previously pending source files also received complete cross-checks: `Controllers/AccountControllerBase.RegistrationHelpers.cs` (52 lines) and `Rigging/Authentication/TwoFactorChallengeCodeUtility.cs` (42 lines). Their inventory qualifications now record complete source inspection with runtime pending. Registration-controller actions, existing direct verification tests and model/configuration references were cross-checked in the stated slices; their earlier qualifications are retained.

The original 451-file tree remains byte-for-byte identical to the uploaded archive, SHA-256 `229ef2275f1caeff3a6a40186e678f7440a90fd54add2e0ba8de0fd6c645758f`.

## R10H-01 — registration verification system success check accepts failure pages

**Priority: P2. Correction owner: COR23AE. Status: open.**

`Registration_verify_succeeds_through_haproxy` at system-suite lines 23–31 calls `RegisterAndVerify` and then ends. The helper at lines 509–522 checks signup success, obtains the captured verification token, sends the verification GET and checks only `HttpStatusCode.OK`. It does not read the HTML outcome, confirm persisted verification or prove a subsequent authenticated operation.

The actual `VerifyAccountCreation` action returns unsuccessful HTML when the token is unknown, invalid, denied or when `AccountPassedVerification` returns false/null. Its completed/failure selection at controller lines 254–268 uses the same `AccountVerificationContent` helper as the successful path. That helper returns `Content(html, "text/html", Encoding.UTF8)` without setting a failure status. The controller advertises HTTP 200 for the HTML endpoint. Existing direct controller cases distinguish successful and unsuccessful content, including a completion-failure test; the system helper does not.

The framework's current official [ContentResult executor](https://source.dot.net/Microsoft.AspNetCore.Mvc.Core/Infrastructure/ContentResultExecutor.cs.html) changes response status only when a result supplies one. The current [default response feature](https://source.dot.net/Microsoft.AspNetCore.Http/Features/HttpResponseFeature.cs.html) initializes status to 200. These sources corroborate the response mechanism; they are illustrative current source, not execution of the project's pinned framework. Runtime qualification remains pending.

A source-derived witness is therefore:

| Verification result | HTTP status | HTML body | Durable verification | Current system assertion |
| --- | ---: | --- | --- | --- |
| Completion false/null | 200 | `<html><body><h1>Account verification failed</h1></body></html>` fallback | Not established as successful | Accepts status and the dedicated test ends |

The witness was not served or executed. It shows that the test assertion cannot distinguish a production failure response from successful verification. A runtime regression in completing verification could therefore coexist with this particular green system test. This does not assert that real verification currently fails.

The deletion flow also checks a verification GET only by HTTP status, but subsequently requires finalization success and rejects future login and the old access token. Those later checks give that overall flow stronger outcome evidence. Do not describe all HTML verification flows as equivalent to the registration false positive.

This finding is distinct from R10E-01/COR23AC: R10E concerns malformed JSON failure-envelope fallback; R10H concerns semantic success and persisted account state behind an intentional HTML response contract. Neither finding requires changing the public endpoint's status policy simply to make tests pass.

## System flow coverage and limits

The suite contains 22 system Facts covering registration, login without factors, invalid password, email/SMS/authenticator enrollment, advertised verified methods, four login factor paths, wrong factor proof, five reset combinations, deletion, unlock, factor removal and two legacy API denials.

| Area | Useful assertions in source | Existing qualification to complete |
| --- | --- | --- |
| Real HTTP/capture boundary | HttpClient requests against configured base URL, real issued credentials, purpose/channel/destination delivery lookup | Owned artifact/process/state identity and actual execution; COR01, COR23AA, COR24 |
| Login | Expected status/code, nonblank active token | Use issued token on a protected route; real refresh/revoke races and stable session ID; COR09, COR24 |
| Two-factor | Selection, next required factor, final token; real TOTP calculation in test helper | No intermediate active authority, token-purpose denial, stale replacement/expiry and replay schedules; COR10, COR15, COR24 |
| Reset | Request/verify/select/proof/finalize, completion code/status; one case tests old/new password login | Deny old active sessions and wrong-purpose tokens; complete authority lineage and competing schedules; COR13, COR24 |
| Deletion | Successful finalize; later login and prior-token view denied | Durable deletion/cascade/audit state, current destructive proof, budget continuity and stamp races; COR18, COR24 |
| Unlock | Failed passwords reach lockout; captured unlock token enables login | Atomic budgets, changed-lockout epoch/stamp schedules and durable one-time consumption; COR08, COR11, COR24 |
| Factor removal | Authenticator removed; SMS login retained; reset menus exclude authenticator | Fresh/current proof, stale pending reset invalidation and concurrent factor mutation; COR13, COR16, COR24 |
| Legacy denial | Removed login route returns 404; authenticator reset delivery rejected with validation errors | Complete executed route/DTO inventory and strict error schema; COR23AC, COR24 |

Most users are created through the privileged verified-account seed endpoint rather than signup/verification. This is a reasonable fixture for isolating later flows, but does not qualify public registration or delivery of the initial verification. Keep at least one full public registration flow with authoritative outcome assertions.

The system stack uses PostgreSQL, a Redis-compatible cache and HAProxy, with system SMTP/SMS capture providers. It does not validate real external SMTP TLS, Twilio/AWS submission, real mailbox/handset receipt or provider ambiguity. Its Compose/host settings raise shared-IP delivery/reset ceilings to 100 and set reset request cooldown to zero. These settings support repeated happy paths; they do not qualify production abuse thresholds. The prior provider, startup capability isolation and abuse findings remain open.

Both SQL and system assemblies disable framework test parallelization. That avoids ordinary concurrent test execution within each assembly. It does not isolate two processes/jobs/stacks or serialize application requests deliberately launched inside a test. The capture clear operation deletes all captured deliveries in its backing table; per-run storage ownership still belongs to COR23X/COR23Y. Unique emails help avoid account collisions, while purpose/destination-only latest capture selection is not proof of exact request/challenge lineage.

## Acceptance refinements without new finding counts

**Replay — COR06/COR24.** `AddAuthenticatedMutationHeaders` generates a new GUID-based key every time. It satisfies key admission for these happy paths, not persisted retries or response loss. Add scenarios that retain one key across first request, retry and changed-body/operation/account attempts; assert one mutation, stored response and ownership/expiry behavior. Keep real coordination enabled.

**Fresh factor proof — COR16.** Email/SMS setup currently sends access token plus mutation key and no sensitive-action grant. Authenticator enrollment and factor removal do request a grant. Adapt email/SMS helpers to the corrected purpose/target-bound fresh proof contract and retain explicit denial tests for session-only setup. Successful execution of the old helper would not close the existing session-only enrollment finding.

**TOTP metadata/replay — COR15/COR24.** Enrollment reads returned digits/period/algorithm with defaults and verifies a previous time step to avoid immediate replay. Follow-up login/reset paths discard those parameters and hard-code 6 digits, 30 seconds and SHA1. `AuthenticatorEnrollment` retains only the secret and rotated token. Preserve exact returned/persisted enrollment parameters in the fixture; require valid metadata and reject unknown algorithms/base32 characters rather than silently falling back or skipping characters. Qualify nondefault supported parameters and repeated enrollment/login/reset proofs with independent vectors and controlled time. The existing COR15 parameter-drift finding remains the owner of production behavior; these are fixture acceptance refinements.

**Deterministic negative proof — COR24.** The wrong email-code case submits `000000` without comparing it with the generated challenge. The production generator selects from zero through the numeric range and zero formats to `000000`; the chosen negative value can therefore be correct. Select a same-shape code guaranteed different from the captured challenge. Do not quantify observed flaky runs: none were executed. This small test reliability observation is recorded under integrated test qualification, not a separate P2 finding.

**Readiness and run identity — COR23W/COR23AA.** The readiness helper computes a 90-second wall-clock deadline but sends each GET with only the caller token. It supplies no linked remaining-budget cancellation, and CreateClient leaves default HttpClient timeout and redirect behavior. A single request can run beyond the loop's declared deadline; successful redirection also needs target validation. Use a monotonic aggregate budget to cancel each request and delay, reject unexpected readiness redirects/targets, and verify owned process/build/backing-state identity. Qualify unresponsive endpoint, slow response, clock movement, early process exit and wrong target using isolated fixtures. This strengthens existing bounded-proof owners rather than duplicating them.

**Envelope/schema/privacy — COR23AC/COR23E/COR24.** PostJson checks HTTP status and parses JSON; individual callers assert varying subsets of the envelope. Consolidate strict application success/status/code/error schema checks without applying application-envelope requirements to explicitly different test-only/HTML/health contracts. Enum set readers currently remove unknown values (`-1`) and deduplicate; require rejection of unknown values and enforce the intended raw cardinality rather than allowing unexpected entries to disappear. Model tests labeled as omitting token hashes must also verify serialized profile/session response privacy and credential response no-store behavior.

**Proof-loop progress — COR13/COR24.** Reset proof helper loops until `canChangePassword`, following response-required methods with no explicit maximum or progress assertion. Bound it by the selected configuration's expected proofs and reject repeated/no-progress state. Require that cases advertised as two-factor reset actually entered the expected factor path; then verify final durable password/session state. The deletion case already has useful post-request denial checks and should retain them.

**Denial/privacy claims — COR14/COR24.** The invalid-login test exercises a wrong password for a known seeded account and checks failure fields. Its name alone does not prove indistinguishable known/unknown account responses or timing. Add the required comparison cases under the existing privacy policy and declared measurement budget, without inferring a new oracle from an unexecuted test.

## API/model, naming and assembly checks

Greenfield API tests inspect route attributes on a hard-coded list of account controller types and inspect reset DTO property names; they also call the delivery-channel support helper. These are useful reflection/helper contracts, not complete runtime route discovery. Preserve them alongside real legacy-denial requests and an executed endpoint inventory that discovers all registered controller types under COR01/COR24.

Model tests intentionally allow short values at the DataAnnotations stage so configured runtime minimums remain authoritative. They reject sentinel country/factor values and absent login identifiers and check default session-management DTO values. They do not demonstrate runtime configuration enforcement, model-binding envelopes or serialized secret omission. Keep the distinct validation stages and supplement them through executed boundary and wire-contract cases.

License tests check MIT text fragments and shared project metadata. Rename tests scan selected text extensions and names, excluding build/VCS/result directories. These establish source hygiene when executed; they do not qualify third-party binary provenance, packaged notices or behavior. Remaining dependency binary review remains scheduled. No legal conclusion is made from the metadata assertions.

Assembly policies are explicit and environment lookup falls back for absent/whitespace values while retaining supplied nonblank values. Use resolved per-run configuration rather than treating default system key/base URL as deployment qualification. The environment helper is read completely; it has no storage or account authority of its own.

## Detailed corrective PR — COR23AE

**Title:** Prove successful registration verification in the system lane.

**Owns:** R10H-01 only. Can land independently of production corrections; coordinate with COR11 verification state and COR23G public origins, and include results in COR01/COR24 qualification.

**Files:** `treehammock.Tests.System/SystemStackAccountFlowTests.cs`; focused HTTP verification regression cases in the existing test project. Reuse configured verification templates and existing isolated persistence fixtures. A general production status-code change or new public inspection endpoint is unnecessary.

**Implementation:** After verification, assert the intended successful HTML outcome/content type using the controlled fixture contract. In the dedicated registration scenario, independently prove the account is verified by successful normal login and a protected operation, or an existing isolated durable-state query. Keep registration helpers usable in unlock/other scenarios without introducing hidden session side effects. A pure rendering marker cannot substitute for committed account state, and a status assertion cannot substitute for either. Preserve specified already-verified, expired, invalid and unavailable behaviors.

**Regression cases:** Known valid token and committed success; invalid token; expired token; completion rejected/failed; failed outcome HTML with HTTP 200. Force completion failure through an isolated integration fixture without adding a production fault-injection route. The unsuccessful HTTP-200 case must fail the success assertion, and durable verification must remain uncommitted. Confirm legitimate already-verified behavior is handled according to its contract. Keep fixtures/captured delivery owned by the run and close all HTTP/JSON scopes.

**Acceptance:** The complete dedicated registration system case succeeds only after actual committed verification. A failure page with 200 is rejected; durable state and later authorized behavior agree. Execute the corrected real stack path and publish discovered test/results evidence; the source-derived witness alone does not close this finding.

**Migration/rollback:** Test-only correction needs no schema or deployment migration. Rollback restores weak qualification and reopens the finding. Production verification migrations remain governed by their existing owners.

## Validation and remaining scope

The evidence builder verifies source/archive parity, ten-file metadata, all source test attributes, sixteen fixture/assertion observations and the failure-page witness. These are source checks; no C# or HTTP execution is simulated.

| Original runner attempted | Exit | Result |
| --- | ---: | --- |
| `bash eng/dotnet-unit-tests.sh --configuration Release --locked-restore` | 127 | .NET SDK absent; stopped before restore/build/discovery/test |
| `bash eng/dotnet-integration-tests.sh --configuration Release --locked-restore` | 127 | .NET SDK absent; stopped before restore/build/discovery/test |
| `bash eng/docker-system-stack-tests.sh` | 1 | Docker selection helper found no reachable Docker CLI; stopped before stack startup/test |

No test was compiled/discovered/executed, no system HTTP request or real SQL/cache contract ran, and no performance benchmark was measured. Nothing is qualified as feature-complete or release-ready by this source pass.

The Through_10H inventory records ten R10 files and two prior source files as inspected, runtime-pending. **13 R10-assigned files remain**, plus the three partially reviewed R06 SQL-contract suites. The R10 remainder is not a global outstanding-file count: earlier R01–R05 legacy qualification rows and indexed/partial suites need individual reconciliation before a whole-project completion claim.

Next is **R10I: complete the three partial R06 SQL-contract suites**, followed by remaining release/API/SQL documentation, observability/HTTP configuration and dependency binary qualification. Runtime/performance qualification remains a required later stage.

The cumulative bundle retains prior reports/evidence and updates the ledger/inventory through R10H. Original design and detailed PR-plan Word documents remain unchanged; this report adds COR23AE and acceptance refinements for the existing owners.
