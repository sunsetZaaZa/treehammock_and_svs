# Treehammock review 09 — Health, abuse controls, observability and replay

Reviewed 2026-10-03 against the unchanged uploaded source. This is a source review and correction-plan addendum; no application fixes were made.

**Four new P2 findings. Cumulative: 68 open findings, comprising 18 P1 and 50 P2.** All 30 files assigned to R09 received complete source inspection, including ten C# test/support files and two Bruno health examples. No finding is closed. Next is **R10 — tests, dependencies, build, deployment, operations and documentation**.

## Scope and evidence limits

Reviewed health endpoints/dependency service, abuse contracts/settings/counter implementation, delivery admission and login counter keys, operational telemetry, authenticated mutation replay, system-test endpoints/delivery capture, assigned tests and health request examples. Cross-checks cover dependency injection, storage connection acquisition, cache configuration, login/public-token callers, SQL state and authenticator setup replay. Full assigned-file inspection and focused cross-chunk inspection are separately recorded in the inventory.

The unit runner exited **127 before restore/build/test**, because the .NET SDK is absent. Docker, PostgreSQL tools and Redis server are also absent. No fault injection, real cache/SQL concurrency test, MeterListener assertion, host shutdown test, load test or benchmark ran. Expected effects below are source-derived and require runtime confirmation. The archive hash, exact source file set and all 451 file hashes match the upload. Source-pass completion does not establish release readiness or feature completeness.

## Findings

| ID | Priority | Defect | Correction owner |
|---|---|---|---|
| R09-01 | P2 | The conditional PostgreSQL counter fallback is an unconditional allow decision for Redis-only policies. | COR23M |
| R09-02 | P2 | Health cache initialization can create competing, unowned connections; shutdown has no disposal owner. | COR23N |
| R09-03 | P2 | Readiness lacks an aggregate deadline and cancellation does not cover acquisition/connect/PING. | COR23O |
| R09-04 | P2 | Cooldown metrics count observations as starts, and policy denial can be recorded twice. | COR23P |

### R09-01 — A configuration flag substitutes for an authoritative fallback

**Evidence.** `Rigging/Abuse/DragonflyAbuseCounterStore.cs` 198–234 sets AllowWhenCounterStoreUnavailable solely by comparing the global CounterFailureMode to AllowWhenPostgreSqlAuthoritativeStateExists. On failure, IncrementAsync returns Allowed=true/CurrentCount=0 and GetCooldownAsync returns Active=false. Neither the counter request nor this store checks that PostgreSQL holds and enforces the equivalent policy. `Rigging/Config/AbuseControlSettings.cs` accepts this enum; the default is FailClosed. DragonflyAbuseCounterStoreTests explicitly expect an allow result under the alternative mode without any PostgreSQL authority fixture.

`Services/DeliveryAbuseThrottleService.cs` 71–113 uses those results directly for admission, checking channel cooldown and account/destination/IP counters. No equivalent durable hourly delivery quota is consulted on this path. Login admission likewise includes a Redis IP counter (`Controllers/AccountControllerBase.LoginHelpers.cs` 181–215); the existing database account lockout is not an equivalent cross-account IP limit. SQL proof-attempt limits in other flows do not establish authority for these policies.

**Inferred impact.** With this nondefault mode enabled, cache outage/timeout disables affected limits even while PostgreSQL is unavailable or has no equivalent counter. Delivery can proceed and cross-account login requests can evade their configured IP limit. Existing durable per-proof/account limits still apply where implemented; this finding does not claim that every protection disappears. Default FailClosed is safe with respect to this specific bypass. Missing per-policy fallback verification is independent of AUTH-06's non-atomic increment/expiry.

**Correction.** Return a typed unavailable result from the store. Decide fallback at the policy owner, using an explicit policy capability and an actual durable admission operation enforcing the same subject, scope, window and threshold. A successful database connection or existence of an account is insufficient. Redis-only policies must fail closed unless a separately specified safe degraded mode is intentionally accepted. A failed durable fallback must not become allowed. Validate unsupported fallback configurations at startup and document availability behavior.

**Required regression.** Enumerate all enabled policy/dimension combinations. Interrupt Redis with PostgreSQL both up and down; prove delivery account/destination/IP quotas and login IP admission remain enforced or return a sanitized dependency-unavailable result. For supported durable fallback, use multiple instances and real transactions to test the exact threshold/window and race with cache recovery. Assert no provider/hash invocation after denial. Keep an explicit default-mode test and verify an unavailable decision cannot be confused with a consumed proof attempt.

### R09-02 — Health cache clients have no exclusive lifecycle owner

**Evidence.** `Rigging/Health/HealthDependencyService.cs` 43–62 constructs three separate Lazy<IConnectionMultiplexer> instances using PublicationOnly. Each factory performs ConnectionMultiplexer.Connect. The singleton registration is at `Rigging/DependencyInjection/TreehammockServiceCollectionExtensions.cs` 77. The service implements neither IDisposable nor IAsyncDisposable and does not dispose unpublished factory results.

The [Microsoft LazyThreadSafetyMode contract](https://learn.microsoft.com/en-us/dotnet/api/system.threading.lazythreadsafetymode?view=net-8.0) permits all competing PublicationOnly initializers to run and discards losing values. The [StackExchange.Redis usage contract](https://stackexchange.github.io/StackExchange.Redis/Basics.html) describes a reusable, thread-safe multiplexer with an explicit disposable lifetime. Discarding a factory result is not deterministic resource disposal.

**Inferred impact.** Concurrent first readiness/dependency requests can create more live cache clients than the three intended ones, without retaining an owner for the losers. The winning clients also lack explicit host-shutdown cleanup. This can waste connections/background resources, especially under repeated host construction or startup probe bursts. Exact socket counts and retention duration have not been measured. Once successful initialization has completed, this code does not create a fresh connection on every probe; that would overstate the defect.

**Correction.** Give each logical cache client one DI/host lifecycle owner and expose its health through an explicit interface, or use bounded, separately owned diagnostic clients. Initialize asynchronously with one shared initialization task; do not let a request token permanently cancel the host-owned client. Handle failed initialization/retry deliberately, including bounded retry/backoff, rather than replacing PublicationOnly with an exception-caching Lazy that can remain broken forever. Dispose every created client exactly once at shutdown; a health service must not dispose a borrowed application client.

**Required regression.** Barrier concurrent cold probes at the connection factory and count creations/disposals. A successful startup creates only the intended clients; failed startup followed by recovery is retryable without accumulating abandoned clients. Exercise repeated host start/stop and assert all owned clients close. Measure cache connected-client counts, process handles and retained memory under startup bursts and recovery. Include a test proving health and request-serving clients use the intended lifecycle owner.

### R09-03 — Probe cancellation and the total deadline omit dependency work

**Evidence.** `HealthDependencyService.cs` 65–75 awaits four probes sequentially without a total probe budget. PostgreSQL acquisition at 83 calls StorageContext.CreateConnection without a token; the two-second CommandTimeout at 86 applies only after acquisition. `Rigging/Database/StorageContext.cs` 25–28 calls OpenConnectionAsync without supplying cancellation. Redis access at 122 performs synchronous lazy connection initialization; PingAsync at 124 has no application cancellation/deadline wrapper. Request cancellation is checked only after the ping at 125. There is no early cancellation check before starting dependency work.

**Inferred impact.** Readiness can exceed the apparent two-second SQL command budget by pool/connect waits and sequential cache connect/command budgets. An abandoned readiness request can continue dependency work until driver limits complete it. Repeated anonymous probes can amplify outage load because no shared in-flight probe or bounded sampling is used. Driver connection/command timeouts exist; this finding claims missing application-wide bounds, not an infinite wait. AUTH-11 already owns synchronous lazy initialization in request-serving cache paths; this finding adds the distinct readiness path, PostgreSQL acquisition and aggregate probe contract.

**Correction.** Define validated total/per-dependency probe budgets, pass cancellation through database acquisition and command execution, and bound awaits of shared Redis initialization/PING. Check cancellation before starting new work. Explicitly separate a caller ceasing to wait from terminating host-owned initialization or a Redis operation already submitted; observe late completions and bound underlying work/concurrency. Use single-flight probes or short-lived cached reports with an explicit staleness limit to prevent probe multiplication. Bounded parallel checks may avoid cumulative latency, but concurrency and resource limits must still hold. Liveness remains dependency-free at its controller action.

**Required regression.** Delay pool acquisition, database connect/command, Redis initialization and each PING separately. Verify canceled callers return promptly, no new dependency operation starts for a pre-canceled request, total elapsed time respects the configured budget plus declared scheduling tolerance, and abandoned operations do not accumulate. Outage/recovery tests must show sanitized unhealthy reports within budget, bounded concurrent probes and recovery within the stated freshness interval. Measure p95/p99 duration, thread-pool queues and pool wait under repeated probes. HealthControllerTests currently substitute the dependency service; SystemStackHealthTests check healthy responses and do not qualify these failure paths.

### R09-04 — Metrics do not distinguish cooldown creation from observation

**Evidence.** `Rigging/Observability/AbuseOperationalTelemetry.cs` 152–168 calls RecordCooldownStarted whenever RecordPolicyDenied receives FailureCooldownActive. Thus every rejection while an existing cooldown is active increments the starts counter. `DragonflyAbuseCounterStore.cs` 98–103 also records a start after attempting SET NX; 236–253 ignores the returned creation flag, so multiple threshold-crossing requests can each count a start when only one wins. Denial at store line 61/99 is additionally recorded by public-token policy mapping in `Controllers/AccountControllerBase.LoginHelpers.cs` 304–313. Store and policy reason labels can differ, but a single denied counter check still generates multiple policy-decision observations without a layer distinction.

**Inferred impact.** Increased traffic against one existing cooldown appears as many new cooldowns. Dashboards/alerts based on starts or aggregated denial counts can misrepresent incident magnitude and policy effectiveness. This is an observability correctness defect; it does not itself grant access. Existing telemetry tests verify names, label names and log templates, without observing live measurement counts.

**Correction.** Return the actual cooldown transition result from the atomic counter operation and emit a start only when the cooldown is created. Record subsequent blocked attempts in their own observation metric. Assign one owner to each decision metric or explicitly distinguish counter decisions from final policy/request outcomes. Keep feature-specific throttle metrics if useful, with documented counting units so operators do not sum overlapping series as independent requests. Use bounded reason values and sanitization for both logs and metrics.

**Required regression.** Use MeterListener to observe actual values/tags. One real cooldown creation increments starts exactly once; repeated blocked requests leave it unchanged. Concurrent SET-NX contenders produce one start, and expiry/recreation produces the next start. Assert one decision at each documented layer and no accidental duplicate final policy outcome. Verify failure/reset paths and dashboard query expectations, including actual tag values and absence of proof/identifier material. Run the transition case against real Redis/Dragonfly as well as deterministic fakes.

## Existing findings strengthened, without duplicate IDs

| Existing owner | Additional closure requirement from R09 |
|---|---|
| AUTH-06 / COR05 | Increment/window expiry remain separate; cooldown creation and reset need atomic/fenced semantics. Race successful reset against new failures so it cannot erase newer state. Expiration must recover after interruption. |
| AUTH-07 / COR06 | Completion still uses local owner comparison followed by unconditional SET. Exercise lease expiry, competing reservation, late completion, eviction and crash after database commit. Durable mutation outcomes remain necessary. |
| AUTH-08 / COR06 | Authenticator setup replay returns success and supported apps but omits setupId, otpauthUri, manualEntryKey, issuer/account parameters and expiry (`AccountTwoFactorController.cs` 100–107 versus 157–173). A lost first response therefore cannot recover the enrollment payload using the same key. Define a bounded encrypted, authority-bound recovery envelope or an explicit safe recovery protocol; do not put raw secrets in ordinary Redis replay values. Test byte/semantic-equivalent replay and authority revocation, alongside different-body conflicts. |
| AUTH-11 / COR03 | Request cache stores still connect synchronously outside wait wrappers; R09-02/03 specify the separate health owner and probe budget. Async caller timeout must not imply that underlying Redis work was canceled. |
| R07-01 / COR23D | System-test endpoints/capture remain flag/key guarded rather than intrinsically isolated. They create verified accounts and retain plaintext proof captures. Keep test credentials, database, endpoints and providers physically/operationally isolated; no new duplicate exposure finding. |
| R08-04 / COR23K | Delivery still uses channel-wide provider failure cooldown. R09-01's dependency fallback and R09-04's transition telemetry must compose with the corrected provider-scoped circuit policy. |

## Positive checks and qualification gaps

| Surface | Source result / required follow-up |
|---|---|
| Health response | Anonymous live/ready/dependencies routes exist; readiness returns 503 when a reported dependency is unhealthy. Fixed dependency/reason codes avoid leaking connection strings. Liveness action makes no dependency calls. Authentication middleware precedes actions, so test the deployed probe request shape as well. |
| Readiness meaning | SELECT 1 and Redis PING establish basic connectivity, not schema version, write/required-command permissions or healthy request-serving clients. GetDatabase correctly uses configured DefaultDatabase; no wrong-database finding was added. Specify required versus degradable dependencies and production readiness capabilities before adding intrusive probes. |
| Abuse defaults | Policies default enabled and counter failure defaults closed. Nested settings have range validation. Account IDs and hashed identifier/IP keys keep raw values out of cache key strings. Unknown-IP requests deliberately share a budget; verify proxy/IP normalization with the hosting lane. |
| Counter behavior | Sequential tests cover normal threshold and failure-mode decisions. They cannot qualify atomicity, multiple instances, interrupted expiration or actual durable fallback. Per-command wait budgets do not establish a total multi-gate admission deadline. |
| Replay | Namespaced account/method/route/key reservations, required-key validation and in-progress conflict exist. Completed state is status/code only, cache TTL-limited and lacks content fingerprint; existing findings remain open. Canceled waits and Redis work already submitted need explicit outcome semantics in COR03/04/06. |
| Telemetry safety | Label-name allowlist, normalized values and bounded enum feature/dimension names exist. A label-name test does not prove bounded/safe label values. Edge metric emitters are declared; an active edge integration is not established by these R09 paths. Exporter/dashboard/deployment integration remains R10. |
| Test support | Seed/capture queries use SQL parameters, owned command/connection scopes and scalar execution. In-process schema semaphore avoids repeated setup per instance. Cross-instance first-use DDL, explicit capture retention, consistent indexed normalization and tie-breaking need fixture qualification. DeliveryCaptureConnection is declared but capture uses the ordinary StorageContext; make fixture configuration/isolation unambiguous under COR23D. |
| Test limits | Assigned unit tests use substitutes/source assertions; the system health test checks a healthy stack. Its retry loop needs a per-request timeout/cancellation so a single HTTP call cannot overrun the nominal overall wait. Real outage, recovery and shutdown scenarios remain required. |

Under COR22, measure probe duration/concurrency, owned cache clients, pool wait, request admission latency during outages, cooldown transitions versus blocked attempts, replay recovery and fixture storage growth. No throughput/latency target is reported as achieved.

## Detailed correction-plan addendum

The original correction design/PR plan covered 52 findings; prior review addenda supplied COR23A–L. Add COR23M–P below, scheduling them with their prerequisites. These are review-derived PR specifications, not opened or implemented PRs. The trusted-grant activation decision is unchanged. Original Word planning artifacts have not been rewritten.

### COR23M — Enforce per-policy authoritative fallback

- **Owns:** R09-01. **Depends on:** COR03 typed dependency outcomes and COR05 atomic budgets; coordinate delivery admission with COR12 and login with COR08.
- **Files:** abuse contracts/settings/store, every admission policy caller, durable budget schema/repositories where fallback is supported, startup validation and real outage/concurrency tests.
- **Implementation:** policy/dimension capability catalog, explicit unavailable outcome, equivalent durable admission before allow, startup rejection for unsupported fallback configuration. Specify FailClosed and safe degraded behavior per policy. Preserve durable proof/account limits and count infrastructure failure separately.
- **Acceptance:** Redis failure cannot permit a policy lacking its equivalent enforced durable limit; PostgreSQL failure cannot turn a fallback into allow. Real multi-instance threshold/window matrix passes and denied delivery/hash work is not invoked.
- **Migration/rollback:** deploy durable schema and owner paths before enabling fallback. Existing alternative-mode deployments should use FailClosed until their policy matrix is supported. Version fallback semantics; rollback must retain enforced budgets or disable unsupported modes, never silently reopen admission.

### COR23N — Give cache health clients a single owner

- **Owns:** R09-02. **Depends on:** COR03 lifecycle/client abstraction; coordinate COR23O probe isolation.
- **Files:** HealthDependencyService, cache client ownership/factories and DI, host lifecycle tests and cache connection diagnostics.
- **Implementation:** one asynchronous shared initializer per logical owned client, explicit bounded retry/backoff after failure, exact ownership/disposal contract for borrowed versus dedicated clients. Remove PublicationOnly creation of disposable resources.
- **Acceptance:** simultaneous first probes create only the intended clients; initialization failure recovers; host shutdown disposes all owned clients exactly once. Repeated starts and startup bursts show bounded connected-client/handle counts.
- **Migration/rollback:** no data migration; roll client composition coherently and distinguish old/new client names during qualification. Avoid shared-client double disposal. Rollback to racing unowned initialization reopens the finding.

### COR23O — Bound readiness work and isolate probe lifetimes

- **Owns:** R09-03. **Depends on:** COR03 cancellation-aware acquisition, COR23N owner initialization; coordinate deployment probe thresholds with R10/COR23 and measurements with COR22.
- **Files:** health settings/validation/service/controllers, StorageContext acquisition interface, cache probe adapters, host/system fault tests and deployment probe documentation.
- **Implementation:** validated total/per-dependency budgets, early cancellation, database acquisition/command propagation, bounded waiting on Redis work, late-completion observation and concurrency controls. Use single-flight/sampling with explicit report age. Document connectivity/capability and required/degradable dependency policy; retain cheap liveness.
- **Acceptance:** controlled hangs and pre-canceled requests pass the phase matrix above. Outage probes finish within the declared budget/tolerance without unbounded residual work; recovery and freshness bounds hold under concurrent probes and pool pressure.
- **Migration/rollback:** tune application budgets below deployment readiness deadlines using measurements. Publish staleness/cancellation semantics. No schema change for basic probes; capability probes require safe namespacing/cleanup if introduced. Rollback cannot discard all bounds or hide unhealthy state in stale success.

### COR23P — Make operational counts represent real transitions

- **Owns:** R09-04. **Depends on:** COR05 atomic cooldown transition result; coordinate COR23K circuit classification and COR22 telemetry/dashboard definitions.
- **Files:** abuse counter decision/transition models/store, AbuseOperationalTelemetry and policy callers, dashboard/query documentation, MeterListener and real-cache concurrency tests.
- **Implementation:** cooldown-created flag emitted by the actual atomic state transition, separate blocked-attempt metric, explicit counting owner/layer, bounded tag catalog and tests observing values. Remove implicit start recording from generic denied observations.
- **Acceptance:** one start per real transition, no start on repeat denial or losing SET-NX contender, one outcome per documented layer and no sensitive tag material. Dashboard queries use the new counting contract and pass synthetic series scenarios.
- **Migration/rollback:** version/rename metrics when changing semantics; update dashboards/alerts with rollout to avoid mixing definitions. Do not rename persisted cache keys solely for telemetry. Preserve old dashboards temporarily only with a clear compatibility period; reverting inflated metrics reopens correctness concerns.

## Evidence and next chunk

The cumulative bundle contains R01–R09 reports/static evidence, reproducible structural builders, blocked validation attempts and the latest 451-file inventory/68-finding ledger. R09 evidence checks source/archive parity, the relevant fallback/lifecycle/deadline/metric/replay structures, assigned test catalogs and correction ownership. These checks validate review evidence, not application correctness or performance.

R10 has 155 assigned files and also retains three partially reviewed R06 SQL-test files: BooleanProcedureContractTests, PasswordResetProcedureContractTests and PasswordResetRepositorySqlIntegrationTests. Its scope is broad and may need subchunks; track explicit file coverage rather than declaring all remaining aspects complete after one pass. Review dependency/build/test tooling, integration/system qualification, deployment/edge configuration, operations/retention and documentation contracts. Feature completion requires implementation or explicit disposition of findings, real state/fault/concurrency tests and measured budgets.
