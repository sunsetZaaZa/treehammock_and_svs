# Treehammock review R10D — authentication/controller test contracts

Reviewed 2026-10-03 against the unchanged upload. This is a **source review and correction-plan addendum**, with no application changes.

R10D establishes **no new independent finding**. The cumulative ledger remains **80 open findings: 18 P1 and 62 P2**; none is closed. The 13 selected files received complete source inspection. **44 R10-assigned files and three partially reviewed R06 SQL test files remain.** R10 and the overall project review are still incomplete, and no chunk is runtime-qualified.

The selected tests provide useful evidence of action-level response contracts, dependency calls, JWT claims and authorization intent. Their mock and framework boundaries must remain explicit when judging whether the corrected project is feature complete. Qualification requirements below extend existing owners; they do not count normal unit-test isolation as a new production defect.

## Scope and evidence

The scope is 2,501 source lines in nine test classes and four support/global files. The companion JSON records exact paths, hashes, method names, attribute lines and data rows.

| Fully inspected file under treehammock.Tests | Fact methods | Theory methods | InlineData rows |
|---|---:|---:|---:|
| Unit/AccountControllerApiShapeTests.cs | 6 | 0 | 0 |
| Unit/AccountControllerArchitectureTests.cs | 4 | 1 | 6 |
| Unit/AccountControllerAuthorizationMetadataTests.cs | 2 | 7 | 67 |
| Unit/AccountControllerLogoffTests.cs | 15 | 0 | 0 |
| Unit/ControllerAuthorizationIntentTests.cs | 3 | 3 | 17 |
| Unit/ApiResponsesTests.cs | 12 | 0 | 0 |
| Unit/AuthenticateResponseTests.cs | 2 | 0 | 0 |
| Unit/CredentialLookupResultTests.cs | 3 | 1 | 2 |
| Unit/JsonWebTokenUtilityTests.cs | 15 | 0 | 0 |
| GlobalUsings.cs | — | — | — |
| Infrastructure/AccountControllerHarness.cs | — | — | — |
| Infrastructure/TestConfiguration.cs | — | — | — |
| Infrastructure/TreehammockWebApplicationFactory.cs | — | — | — |
| **Source attribute totals** | **62** | **12** | **92** |

These are **74 attributed methods identified in source**, not an xUnit discovery result or a passing-test count. The 92 rows belong to the theories and are not additional methods.

The real JsonWebTokenUtility implementation was cross-checked in full. Session-controller replay/logout branches, middleware database-trust calls and selected HTTP integration fixtures were consulted in slices. Large AccountControllerAuthenticateTests, JsonWebTokenMiddlewareTests and AccountFlowRegressionTests remain scheduled for full review; searching their names does not complete that review.

The original unit lane was attempted with `bash eng/dotnet-unit-tests.sh --configuration Release --locked-restore`. It exited **127** at the missing SDK, before restore, build, discovery or execution. dotnet, PowerShell, Docker, PostgreSQL tools and redis-server are unavailable. No C# test, HTTP request, real storage contract or performance benchmark ran. The evidence builder completed archive parity for all **451 source files**, the attribute catalog and 14 static source assertions. Those assertions are review evidence, not application tests.

## What the inspected tests establish

| Surface | Useful checks present | Boundary of that evidence |
|---|---|---|
| Login action response shape | Direct authentication calls check negative 400/401/423/500 envelopes; lookup errors must not charge counters or create sessions. | JWT, cache, repositories and services are substitutes; MVC routing, filters, binding and wire serialization do not execute. |
| Session actions | Fifteen logout/session tests check repository arguments, current versus noncurrent cleanup, missing context, stamp failure, invalid input and response summaries. | Mock repository success does not establish SQL ownership predicates, atomic stamp checks or real revocation across instances. |
| Authorization intent and API metadata | Reflection checks authorization/idempotency intent and advertised status codes; architecture tests constrain controller split/discovery structure. | Handwritten endpoint lists are scoped policy assertions, not an exhaustive runtime route inventory or proof that a filter executes. |
| Envelopes and credential states | ApiResponses checks helpers and model-state conversion; credential lookup checks result-state invariants. AuthenticateResponse tests use actual Newtonsoft serialization. | Helper objects and model serialization do not establish every production formatter/header path or actual database failure classification. |
| JWT utility | Actual utility calls check signed compact tokens, claim allowlist, jti/iat, random token identity, matching key/purpose, supplied expiration and missing jti. Log-reason/privacy checks also inspect constants/source. | They do not establish the full middleware/storage chain. Negative signature/issuer/algorithm and exact lifetime-boundary qualification still need reconciliation with the deferred suites. |

The logout cache-cleanup-warning case deserves preservation: a successful durable logout followed by cache cleanup failure returns success with a warning. That is compatible with the current authority model. The middleware consults `ValidateCachedSessionTrust` with token hash, account ID, session stamp and account stamp. It would be incorrect to infer that a remaining cache entry automatically bypasses durable revocation. Actual subsequent-request behavior remains a COR03/COR09 qualification obligation.

JWT lifetime also requires the correct model. The utility disables the embedded lifetime validator, then checks the supplied session expiration and refresh window. This review does not classify an absent JWT exp claim as a new expiration bug. Tests should qualify that authoritative horizon and the database binding, including the intended behavior exactly at expiration.

## Harness and factory boundaries

**Direct controller harness.** AccountControllerHarness freezes substitute repositories, cache, JWT, two-factor and account services. At lines 52–61, sensitive-action validation succeeds for any command and idempotency begin returns NotApplied; completion is a no-op. At lines 122–138, abuse admission returns allowed with count one. At 168–201 it constructs the controller directly with DefaultHttpContext. At 204–225 it puts a fabricated authenticated session and token hash into context items.

These defaults make isolated action tests practical. They do not authenticate a bearer token, run authorization filters, enforce fresh proof, reserve a replay key or test an actual failure budget. A successful sensitive mutation in this harness therefore cannot be used as evidence that the security gate succeeds or rejects the right requests. Keep action tests, and introduce explicit gate-oriented fixtures for those claims.

The harness hashes fixture passwords with one iteration and memory setting 8192. Reduced test work is intentional test setup; it does not qualify production password cost or repair R02-15/COR07's memory-unit issue. Production work-factor, compatibility and capacity evidence must use the corrected production parameters.

**In-process factory.** TreehammockWebApplicationFactory sets Testing, clears configuration sources and selects example/testing JSON or an in-memory settings dictionary. Dependency replacement is an optional caller callback, not a default complete replacement of external services. Callers must declare which implementations remain real and prevent accidental contact with nonfixture services.

A TestServer request can exercise application middleware, filters, binding and serialization, subject to caller substitutions. Merely obtaining a client or binding options does not prove real listener startup, TLS/HAProxy behavior, PostgreSQL/cache readiness or multiple-instance behavior. The factory currently does not supply that proof.

TestConfiguration enables Twilio routing without a Twilio settings section. This is a fixture implication of the already recorded **R08-05/COR23L** startup-validation defect. Repair the configuration-validation contract and its fixture together; do not invent a second finding for the same missing prerequisite validation.

There is already targeted HTTP idempotency coverage elsewhere: AccountFlowRegressionTests at 1153–1200 checks 428 for a required mutation lacking a key and success for optional current logout. JWT/cache/repository dependencies are substituted in those cases. This prevents the stronger, unsupported assertion that all pipeline replay-key coverage is absent. The rest of that file remains deferred.

## Deduplicated correction obligations

| Existing owner | Acceptance clarification from R10D |
|---|---|
| COR01 / COR24 | Label fixture boundaries, retain real discovery/results, reconcile runtime action descriptors with declared endpoint policies, and distinguish source checks from executed closure evidence. |
| COR03 / COR04 | Exercise dependency outage versus invalid credentials, bounded acquisition, cancellation and late database completion using real adapters. Direct-action status assertions cannot close these findings. |
| COR09 | Prove revocation after cache cleanup failure, refresh winner/loser response consistency and stable management identifiers using committed SQL state and later authenticated requests. |
| COR05 / COR06 | Exercise real counter atomicity and request-bound replay, owner/expiry races, safe replay payload recovery and required/optional HTTP key behavior. |
| COR07 / COR08 / COR10 | Measure corrected production password parameters; qualify concurrent failure budgets and current two-factor challenge authority. |
| COR16 / COR17 | Test fresh sensitive-action proof through the actual gate, including wrong purpose, stamp, account/session binding and expiration; denied requests must not mutate state. |
| COR23D / COR23E / COR23L | Check production isolation of test capabilities, credential-response privacy/no-store behavior, enabled-provider startup validation and valid fixture configuration. |

No COR23AC defect owner is added. These requirements preserve primary ownership from earlier chunks, and no finding is closed by a mock-based or source-only check.

## Detailed PR-plan acceptance addendum

### COR01/COR24 — expose fixture boundaries and qualification evidence

**Change.** Give direct-action, in-process HTTP and real-state fixtures explicit purposes. Retain a convenient permissive direct-action setup, but require gate-oriented fixtures to select real security services or configure explicit denial/admission expectations. Record the dependency substitution map for each HTTP fixture. Use isolated destinations and fail on unexpected external service access in lanes intended to run without those services.

**Files.** AccountControllerHarness, TreehammockWebApplicationFactory, TestConfiguration, their callers, the test inventory, runner/result collection and final qualification manifest.

**Acceptance.** For each mandatory lane, retain discovered/executed/pass/fail/skip counts, target commit, configuration and environment. Fail on zero discovery, unexpected skips or missing results after the existing runner fixes. Classify source/reflection assertions explicitly. Every advertised feature and open finding must point to the appropriate executed evidence; a single aggregate green count is insufficient.

**Dependencies and delivery.** Start the boundary/catalog work under COR01 now; final evidence gates belong to COR24 after domain fixes and COR23Q/R/S/W runner corrections. Changes are confined to test infrastructure and documentation, with no database migration. Preserve existing unit tests while strengthening the qualification lane. Implementation and execution are future work, not completed by this review.

### COR24 — qualify HTTP authentication and policy enforcement

**Change.** Enumerate MVC action descriptors in a built test host and reconcile every route/verb with public, active-session, preauthentication, sensitive-action and replay-key policies. Explicitly exclude disabled production test routes under COR23D. Keep reflection tests as fast policy checks, then issue real HTTP requests through the application pipeline with actual JWT validation and relevant security services.

**Required cases.** Missing/malformed/tampered credentials; wrong signature key, issuer and token purpose; malformed or missing required claims; unsupported token shapes/algorithms under the chosen policy; current versus expired/refreshable authoritative horizon. Freeze the supplied time for just-before/exactly-at/just-after checks. Assert both response/header contract and absence of protected side effects. Cover wrong account/session/stamp bindings, missing/expired sensitive proof, required-key 428 and optional current logout. Verify credential responses and errors satisfy COR23E's agreed privacy contract.

**Acceptance.** The route matrix must fail when a newly discovered action lacks a disposition. Removing a production security gate must cause the corresponding denial test to fail. Do not manufacture a failing token-exp assertion inconsistent with the durable-session design. Reconcile these cases with the full suites in R10E before treating any as a missing project-wide regression.

**Dependencies.** COR03/09/10/16/17, COR06 and COR23D/E. TestServer proves the application pipeline; direct/proxy listener and multi-instance lanes remain separate COR24 requirements. No new finding owner or application behavior change is implied by this validation specification.

### Existing domain PRs plus COR24 — qualify durable session and replay schedules

**Change.** Attach real PostgreSQL/Redis-compatible schedules to the existing owners. Use barriers or controlled fault hooks around acquisition, commit and response delivery rather than timing-only sleeps. Make each test own its database rows/cache namespace and retain safe state evidence without tokens or signing secrets.

**Required schedules.** Cache-hit authorization after durable logout with failed cache removal; refresh versus logout and competing refresh; timeout before commit followed by late completion; stale versus current two-factor challenge; concurrent password failures; replay reservation expiry and replacement owner completion; same key with changed request content; duplicate retry after successful commit with lost response. Assert durable rows, cache state, counter TTLs and subsequent requests, including another API instance where required.

**Acceptance.** Prove the corrected invariant and public response contract, including no erasure of a concurrent refresh winner and no permanent-credential classification for a transient outage. For logout-all and revoke-owned-session, use a second account as a negative control and prove all relevant stamp/ownership predicates at the committed mutation. Keep the cache-cleanup-warning action test, then demonstrate that subsequent requests are denied by durable authority. Run each supported cache implementation/version; compatibility is an execution result, not inferred from a Redis-shaped API.

**Performance.** Measure production password capacity, acquisition/fault latency, refresh/logout contention and database work on cache-hit requests against COR01 budgets. Record concurrency, workload, resource limits and latency/error distributions under COR22/COR24. Unit-fixture hash settings and mocked storage cannot support performance claims.

**Dependencies and rollback.** Closure evidence ships with COR03/04/05/06/07/08/09/10 and related fixes, then participates in COR24. Disposable test-state cleanup must follow COR23Y/Z ownership rules. Validation work does not alter production schema or rollback policy; each underlying domain PR retains its own migration and rollback plan.

## Remaining review and completion limits

R10E should inspect the large login/middleware regression suites and remaining HTTP endpoint contracts in full. Remaining repository/cache tests, the three partial SQL files, real system-flow sources, dependency binaries, documentation, examples and inventories still require their scheduled source passes. Full-source inspection and runtime qualification are separate gates; neither feature completeness nor performance approval follows from R10D.

The cumulative bundle retains earlier reports/evidence and replaces the current ledger/inventory with their Through_10D versions. Original planning documents remain unchanged; this report is the correction-plan acceptance addendum.

## Primary framework references

Microsoft's [controller testing guidance](https://learn.microsoft.com/en-us/aspnet/core/mvc/controllers/testing?view=aspnetcore-10.0) distinguishes action-unit tests from routing, filters and binding. Its [ASP.NET Core integration-testing guidance](https://learn.microsoft.com/en-us/aspnet/core/test/integration-tests?view=aspnetcore-8.0) describes WebApplicationFactory/TestServer and caller service replacement. These support the fixture-boundary interpretation; repository conclusions above come from inspected project source.
