# Treehammock review R10F — account flows and endpoint contracts

Reviewed 2026-10-03. Review and correction-plan addendum only; no application or test code changed.

This chunk completes source inspection of two account test suites, including their fixtures, HTTP assertions, direct controller checks and cleanup paths. It adds **one P2 finding**, R10F-01, owned by **COR23AD**. The cumulative ledger now contains **82 open findings: 18 P1 and 64 P2**. None are closed. Mock isolation and incomplete runtime coverage are recorded as qualification boundaries and acceptance refinements for existing PRs, rather than new independent defects.

## Scope and baseline

| Complete source inspection | Lines | Bytes | Source test methods | Evidence boundary |
| --- | ---: | ---: | ---: | --- |
| `treehammock.Tests/Integration/AccountFlowRegressionTests.cs` | 1,837 | 86,257 | 27 Facts | TestServer HTTP orchestration, substituted persistence, token and proof dependencies |
| `treehammock.Tests/Unit/AccountEndpointContractTests.cs` | 1,135 | 58,068 | 58 Facts | 57 direct controller cases; one source-string check |
| Total | **2,972** | **144,325** | **85 Facts** | Source catalog only; no runtime discovery |

There are no Theory/data-driven methods in these two suites. Method names and source locations are cataloged in the evidence JSON. Attribute counts do not establish test discovery, successful execution or release coverage.

The original 451-file tree remains byte-for-byte identical to the uploaded archive, SHA-256 `229ef2275f1caeff3a6a40186e678f7440a90fd54add2e0ba8de0fd6c645758f`. Focused cross-checks of the shared factory, allowing idempotency fixture and pinned MVC Testing/TestHost package declaration retain their prior qualifications. Neither targeted searches nor package metadata are treated as a new full-file audit.

## R10F-01 — two-factor flow harness does not dispose its application factories

**Priority: P2. Owner: COR23AD. Status: open.**

Fifteen flow tests allocate `LoginTwoFactorHarness harness = BuildLoginTwoFactorHarness(...)`. The builder creates a fresh application factory at lines 1354–1364. Tests create and dispose an `HttpClient` from `harness.Factory`, but the harness itself has no disposal scope or teardown owner. Its class at lines 1613–1738 implements neither `IDisposable` nor `IAsyncDisposable`; `Factory` is an owned property at line 1671. The outer test class supplies no xUnit fixture/lifetime teardown, and the suite never disposes those factories. The other twelve flow tests correctly scope their directly created factories with `using`.

Disposing the client does not dispose the factory that owns the in-process application. ASP.NET Core 8 integration-test guidance assigns TestServer cleanup to disposal of `WebApplicationFactory` and requires disposal of developer-created disposable objects. Reference: [Microsoft integration testing — disposal of objects](https://learn.microsoft.com/en-us/aspnet/core/test/integration-tests?view=aspnetcore-8.0#disposal-of-objects). This harness is not a registered xUnit-owned class fixture.

The consequence established here is missing deterministic host/server/service-provider teardown after these tests, including assertion failures. Repeated test hosts can accumulate resources or leave services active beyond the test that owns them. No live resource growth, socket leak, interference, timing regression or out-of-memory failure was measured. Current [official factory source](https://source.dot.net/Microsoft.AspNetCore.Mvc.Testing/WebApplicationFactory.cs.html) illustrates explicit server disposal and host stopping in `DisposeAsync`; it also has a finalizer. It is not the pinned 8.0.27 implementation, so this review does not claim a version-specific finalizer or binary audit. The ownership finding follows the fixture source and .NET 8 disposal contract.

The evidence JSON lists all fifteen allocation sites and the twelve already scoped factories. This is a fixture lifecycle defect, not a newly discovered production authentication defect.

## What the suites establish, and what remains unqualified

The flow suite covers creation/model validation, sequential password login, two-factor selection and promotion, rejected legacy routes/request shapes, delivery channel selection, expiration denial, factor removal, activation, unlock, deletion, required mutation keys and optional current-session logout. The endpoint suite checks input validation, username/email normalization, typed failure mapping, profile projection, deletion stages, client-clear behavior and missing/invalid/replayed idempotency outcomes.

Several checks are particularly useful and should survive corrections: no delivery before choosing a two-factor configuration; rejection of out-of-order proof; no active access token or active-cache entry after only the first factor in a two-factor configuration; pending-session denial following factor removal; no profile mutation on replay/admission failure; and strict success/status/code assertions in HTTP flow helpers.

| Area | Actual source evidence | Qualification still required under existing PRs |
| --- | --- | --- |
| HTTP envelope and routing | Flow tests send requests through the in-process pipeline and inspect JSON envelopes; direct endpoint tests extract action objects | Executed pipeline/route inventory, runtime discovery and shared strict schema validation; COR23AC, COR24 |
| Password login | Sequential HTTP calls use successful credential snapshots from a substitute | Durable multiple-session behavior, real rotation/authority and configured hash cost; COR07, COR09, COR24 |
| Two-factor promotion | Controller orchestration checks selected configuration, proof order and absence of intermediate active token | Real JWT purpose/signature, TOTP verification/replay, current challenge authority and transactional promotion; COR10, COR15, COR24 |
| Expiration/cache | Mutable session deadlines are adjusted in stored objects; cache dictionaries return the same references | Cache serialization, actual TTL expiration/renewal and stale snapshot/race behavior; COR03, COR10, COR24 |
| Factor removal | Fake repository updates eligible methods and invalidates a fake pending pointer | Current account authority, real fresh sensitive proof, persisted factor summary and concurrency; COR10, COR13, COR16, COR24 |
| Concurrent removal | `Task.WhenAll` issues two requests; `Interlocked.Increment` in the substitute predetermines one success and one not-configured response | Controlled overlapping SQL operations, exact persisted winner/loser state and lock order; COR16, COR24 |
| Mutation keys/replay | FlowFactory installs the allowing service; endpoint tests preset begin outcomes | Real reservation ownership, expiry, request binding, completion and response recovery; COR06, COR24 |
| Activation/unlock delivery | Tests capture generated code/token passed to repository substitutes and then verify it | Durable transaction authority and delivery capture with correct recipient/body; existing lifecycle/delivery PRs, COR19, COR24 |
| Deletion | Preset service outcomes drive request/verify/finalize and active-cache removal | Actual deletion/cascades, durable budgets, authority invalidation and post-commit access denial; COR18, COR24 |
| Safe profile | Direct case checks a supplied safe-profile object is returned | Serialized response privacy and credential-response cache policy; COR23E, COR24 |
| Public verification token bound | One Fact searches concatenated controller source for the 512-character guard and unsuccessful-content return | HTTP boundary cases and no repository lookup on oversized input; COR24 |

`FlowFactory` always replaces the abuse store with an allowing store and authenticated-mutation idempotency with `AllowingAuthenticatedMutationIdempotencyService` at lines 1401–1408. The latter does enforce required keys and production key normalization, but its completion has no storage. The missing-key 428 flow is useful HTTP admission evidence, not actual cache-backed idempotency qualification.

The login harness replaces repositories, JWT generation/validation, delivery, sensitive-action proof and authenticator verification. Authenticator verification returns success for any supplied code; it does not calculate TOTP or enforce replay. Sensitive proof is accepted by a substitute. Cache substitutes at lines 1772–1836 ignore `expire` and return mutable object references; `AdjustExpiration` only tests presence. These choices support isolated orchestration tests. They do not prove that production cache entries expire, that serialized state survives process boundaries, or that real proofs are valid.

The endpoint completed-replay example uses `client-key-12345`, which is **16 characters**, meeting the fixture's minimum. No invalid-key finding is raised for that example. Its begin substitute accepts any request and returns a completed result without a preceding persisted first call; consequently the test proves controller replay mapping and skipped mutation, rather than request binding or durable replay. The deletion token-mismatch example likewise presets a failure result; it does not execute a real second-account ownership attempt.

## Correction-plan acceptance refinements

These requirements strengthen existing owners without increasing their finding counts or changing their production design.

**COR06 — request-bound replay.** Keep focused direct mapping/admission cases. Add executed HTTP cases using the actual coordination service with a valid key, a first successful request and a retry, then the same key with a changed body/operation/account. Assert reservation ownership, no duplicate mutation, equivalent safe response and the specified mismatch policy. Include 15/16/128/129-character boundaries, concurrent admission, reservation expiry, owner replacement and response loss. The allowing fixture's no-op completion must not be used to close those criteria.

**COR10 — pending two-factor authority.** Preserve all configuration/proof-order and no-intermediate-token assertions. Add real SQL/cache cases for current challenge hash/version, account stamp/policy, challenge and session deadlines, replaced/removed factor state, serialized cache round trips and TTL. Force stale-cache versus authoritative replacement and removal schedules. Assert the current durable state and cache outcome, not only the HTTP status.

**COR15/COR16 — authenticator and fresh proof.** Use the real TOTP verifier with known enrollment/time and independent vectors; reject malformed, wrong, expired and already consumed proofs under the corrected persisted parameter contract. Require real purpose/target/current-authority grants for sensitive factor changes and assert no mutation/delivery on denial. Add SQL barriers around removal versus removal, verification and security-stamp changes; inspect retained factors, cleared secret columns, summaries and invalidated pending authority. `Task.WhenAll` against a predetermined substitute is retained as HTTP mapping coverage, not a SQL race qualification.

**COR17/COR18 — identity change and deletion.** Adapt HTTP flows to the corrected fresh-proof/confirmation contract. For deletion, persist a request for one account and attempt use from another; test old authority after reset, logout-all, email/factor/stamp changes. After accepted finalization inspect account/cascade/audit state and verify prior sessions cannot authorize another operation. Keep typed result-mapping unit cases, while proving rejection through real guarded repository commands and HTTP.

**COR19 and existing delivery/lifecycle PRs.** Activation flow tests must adopt the trusted grant contract and inspect committed grant/activation state. Capture the delivery actually emitted by the qualified isolated provider and check recipient, purpose and matching generated verifier; a repository argument alone is not delivery proof. Execute redemption/disable/stamp races through the real transaction. Unlock/reset flows need equivalent current-authority and delivery evidence under their existing owners.

**COR23AC/COR23E/COR24 — contract/privacy qualification.** Reuse the flow helper's mandatory `success`, `statusCode` and `code` requirements when consolidating envelope checks. Add exact validation-error schema checks as specified in R10E. Exercise public token limits with real requests and assert no lookup on oversize denial; source-string presence does not establish execution order. Verify safe profile fields and absence of credential/proof material in serialized wire responses, and retain the credential-response no-store contract. Record distinct direct-controller, HTTP, real-storage and system coverage in runtime result manifests.

## Detailed corrective PR — COR23AD

**Title:** Dispose owned two-factor flow factories after each test.

**Problem/result:** Fifteen tests leave their factory-owned application lifetime without explicit teardown. The PR makes each helper-owned factory stop and dispose when its owning test finishes or exits exceptionally.

**Files:** `treehammock.Tests/Integration/AccountFlowRegressionTests.cs`; add a focused lifecycle test/support probe only if needed to verify host stop/disposal. Shared factory changes are unnecessary unless the selected ownership API needs a reusable fixture helper. No application endpoints, schema, authentication behavior or delivery policy changes are part of this PR.

**Implementation:** Give `LoginTwoFactorHarness` explicit ownership via `IAsyncDisposable` delegating to its factory and change all fifteen test allocations to `await using`. A scoped factory in every caller is an acceptable alternative if equally explicit. Keep client scopes inside the owner lifetime; stop/dispose the host once after requests complete. Make creation/cleanup exception-safe. Existing twelve scoped factory cases must retain correct ownership. Also close JSON document lifetimes in helper call sites that currently discard returned documents; prefer helpers returning only needed values or explicit caller scopes. Keep these cleanup changes in the same PR rather than creating an additional finding.

**Validation:** Execute the complete account-flow suite on the pinned SDK/package graph. Use a disposable DI service/hosted-service probe to observe normal host shutdown and disposal, including an intentional exception after host start that is caught by the lifecycle test. Assert disposal happens exactly once and the original exception remains observable. Cover a harness whose factory never starts. Repeat the focused lifecycle cases in one process to detect undisposed probe instances; no timing or memory threshold alone substitutes for observing ownership cleanup. Confirm all existing flow assertions continue to pass and that no later test accesses a disposed factory.

**Acceptance:** Every owned factory has a test/fixture teardown owner; host/server/provider cleanup is observed after normal and exceptional exits; no shared host is accidentally disposed by an individual request. Publish the discovered tests and outcomes. Static `await using` presence alone does not close the runtime cleanup criterion.

**Dependencies/order:** Can land independently of production corrections; COR01 supplies result evidence and COR24 includes it in integrated qualification. Do not delay cleanup until all authentication PRs are implemented. No migration or deployment sequencing is needed. Rollback changes test lifetime only and reopens this finding if teardown is removed.

## Validation, inventory and next chunk

The Python evidence builder verifies archive/source parity, two-suite metadata, source Fact catalog, fifteen missing owner scopes versus twelve existing factory scopes, and fifteen specific source observations. These are static evidence checks, not replacements for the application tests.

Both original Release/locked-restore test runners were attempted:

| Runner | Exit | Qualification |
| --- | ---: | --- |
| `bash eng/dotnet-unit-tests.sh --configuration Release --locked-restore` | 127 | SDK absent; no restore/build/discovery/test |
| `bash eng/dotnet-integration-tests.sh --configuration Release --locked-restore` | 127 | SDK absent; no restore/build/discovery/test |

No TestServer request, host teardown probe, PostgreSQL/Redis-compatible test or performance benchmark ran. Source inspection does not establish feature completeness, security approval or measured performance.

The Through_10F inventory records both suites as source-inspected and runtime-pending. **38 files remain in the R10-assigned inventory**, and three earlier R06 SQL-contract suites still need their full review. This is not the global outstanding-file count: earlier R01–R05 rows include legacy pending qualifications and some indexed/partial suites. Reconcile their individual evidence before claiming every project file has been fully reviewed.

Next is **R10G: startup/hosting configuration and repository/cache contract suites**. Continue the three partial SQL suites, release/API/SQL documentation, remaining system flows/support, observability configuration and dependency binary qualification in subsequent bounded chunks. Runtime/performance qualification remains a separate required stage.

The cumulative bundle retains previous review reports/evidence and replaces its current ledger/inventory with the Through_10F versions. Original design and detailed PR-plan Word documents remain unchanged; this report adds COR23AD and the acceptance refinements above.
