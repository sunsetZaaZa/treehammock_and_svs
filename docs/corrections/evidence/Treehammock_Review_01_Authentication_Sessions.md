# Treehammock review 01 — Authentication and session management

Reviewed on October 3, 2026. Input: `treehammock-main.zip`.

Archive SHA-256: `229ef2275f1caeff3a6a40186e678f7440a90fd54add2e0ba8de0fd6c645758f`.

## Assessment

The PostgreSQL-authoritative session design has useful protections, but the current authentication/session implementation needs corrections before it should be considered qualified. This review identified five high-priority issues and seven medium-priority issues, plus performance and operational follow-ups. Findings below are grounded in source paths and concrete execution schedules. They have not been reproduced against a running .NET/PostgreSQL/Dragonfly stack in this environment.

The uploaded project is unchanged. This deliverable is a review, not an implementation or deployment. There are 451 regular files in the extracted project. The accompanying inventory assigns every file to a future review chunk; assignment does not mean that the file has passed review.

### Scope and verification limits

This pass traced password login, active-token validation, refresh, logout, logout-all, session listing/revocation, pending login 2FA selection/challenge/proof/promotion, reauthentication, cache access, abuse counters, and idempotency. Relevant PostgreSQL functions, repository methods, configuration, and selected tests were inspected. Registration, complete enrollment/removal workflows, recovery, reset, deletion, activation, hosting, and providers require their dedicated passes.

The project targets ASP.NET Core/.NET 8 and uses Npgsql and StackExchange.Redis. No `dotnet`, `docker`, `psql`, or `redis-server` executable is available here. Running `bash eng/validate.sh --configuration Release --locked-restore` stopped at `dotnet: command not found`. No build, application test suite, real SQL contract suite, HTTP test, load test, or query-plan benchmark passed during this review. Static findings and test-source inspection must not be described as runtime test results.

## Architecture actually present

| Component | Current behavior |
|---|---|
| Password login | Looks up credentials in PostgreSQL, verifies an encoded Argon2id hash, applies account and cache-backed abuse policies, then creates/rotates an active session or begins pending 2FA. |
| Access token | Signed compact JWT using a per-session random key held by the server. Includes issuer, web key, purpose, token ID, and issued-at metadata. Expiration is enforced through server-side session state rather than a JWT `exp` claim. |
| PostgreSQL | Durable account/session state, account/session security stamps, expiration and cutoff, single-session ownership, pending 2FA markers/challenge records, sensitive-action tokens, password-reset state. |
| Dragonfly/Redis-compatible cache | Active-session JSON, pending login 2FA JSON, abuse counters, cooldowns, and authenticated-mutation idempotency reservations/results. |
| Active cache hit | PostgreSQL trust validation precedes JWT validation; a successful request rewrites the cache entry. |
| Active cache miss/failure | PostgreSQL session lookup followed by JWT validation and best-effort cache hydration. |
| Pending login 2FA | Requires cached pending-session content. PostgreSQL validates the pending marker and persists challenges, but the delivered-code verification path uses cached challenge content. This is a materially different authority model from active sessions. |
| Password-reset session service | Despite its cache-shaped interface and location, `PasswordResetSessionService` persists pending reset sessions in PostgreSQL, not Redis. |
| Session policy | One active session per account is explicitly documented. A second password login replacing an earlier session is intentional; this review does not label that behavior a multi-session bug. |

### Protections worth retaining

- Active authentication requires an exact token-hash lookup, signature/issuer/purpose validation, and authoritative account/session state. A signed token alone does not authenticate.
- Cached active sessions are checked against both session and account security stamps. Stale Redis entries after committed logout or account-stamp rotation should be rejected on subsequent authentication.
- Cache hydration failure after successful session creation/rotation does not undo a valid PostgreSQL session.
- Active session creation, rotation, and final 2FA promotion take account-scoped PostgreSQL locks. Final promotion persists the active session and clears the pending marker in one transaction.
- Delivered-code hashes are compared in constant time. Local authenticator verification uses a durable accepted-step marker; this is stronger than a cache-only replay guard.
- SQL calls use typed parameters; function identifiers are validated. Credential lookups have case-insensitive email/username indexes.

These are source observations, not a complete proof that every mutation and failure boundary preserves the protections.

## Prioritized findings

Priority: P1 means an important authentication, security, or availability defect to address first. P2 means an actionable correctness or reliability defect. Confidence refers to source evidence, not a completed integration reproduction.

| ID | Priority | Finding |
|---|---|---|
| AUTH-01 | P1 | Concurrent refresh can return a new token on one request and tell another request to erase it. |
| AUTH-02 | P1 | Middleware timeout stops waiting but does not cancel database rotation or determine its eventual outcome. |
| AUTH-03 | P1 | Delivered 2FA proof can use a stale cached challenge after a newer challenge is committed. |
| AUTH-04 | P1 | Password-failure counters and lockout transitions are not atomic. |
| AUTH-05 | P1 | Reauthentication has no password-attempt throttle or durable failure budget. |
| AUTH-06 | P2 | Abuse-counter increment and initial expiration are separate cache commands. |
| AUTH-07 | P2 | Idempotency completion checks ownership and overwrites the reservation in separate commands. |
| AUTH-08 | P2 | Idempotency keys do not bind to request content. |
| AUTH-09 | P2 | Token refresh changes the session-management ID, invalidating a previously listed revoke target. |
| AUTH-10 | P2 | Temporary PostgreSQL failure is handled as permanent credential invalidation. |
| AUTH-11 | P2 | Synchronous lazy cache connection establishment falls outside the advertised async timeout. |
| AUTH-12 | P2 | PostgreSQL connection strings interpolate unescaped configuration values. |

### AUTH-01 — Concurrent refresh invalidates the client session

**Evidence:** `Rigging/Authentication/JsonWebTokenMiddleware.cs:118–144, 410–485`; SQL `rotate_active_session` at `Rigging/Database/Baseline/000_treehammock_canonical_database.sql:2602`.

Two requests with the same token can both validate the old session and enter the refresh window. Both generate a different replacement token. PostgreSQL correctly allows only one old-token rotation; the other sees an old-session mismatch. The winner returns a new `AccessToken`. The loser remains unauthenticated and emits `CLIENT_CLEAR_ACCESS_TOKEN`. A client processing the losing response after the winning response can erase the new token. Requests that arrive just after rotation with the old token also enter the clear-token path.

This is a client-visible consequence of otherwise useful database serialization. No client code was supplied to establish a compensating protocol.

**Repair:** Define a coordinated refresh protocol across instances and clients. A safe implementation needs either an explicit refresh operation with client request coordination or a narrowly bounded, authoritative refresh-family/replay mechanism. It must distinguish legitimate parallel rotation from logout, account-stamp invalidation, and expired credentials. Do not simply accept expired old tokens or hand out arbitrary replacement tokens based on an old cache hit.

**Required test:** Barrier two real requests after old-session validation; permit one rotation; process responses in both orders. Also submit an old-token request immediately after the winner commits. Verify that the client can keep a valid session and that logout still prevents reuse.

### AUTH-02 — Timed-out database work can still rotate the session

**Evidence:** `JsonWebTokenMiddleware.cs:379–400, 449–461`; `Repos/SessionRepo.cs:201–262`; `Rigging/Database/StorageContext.cs:24–27`.

`WithTimeout` races an already-started task against `Task.Delay`, then returns a fallback value. Session repository interfaces and these Npgsql calls do not receive cancellation tokens. If account locking or database work outlasts the middleware budget, the middleware reports failed refresh and tells the client to clear its token, while the repository task can later commit the replacement session. The old token is then expired and the replacement token was never delivered.

Read operations left running after timeout also retain database/pool resources longer than the apparent request budget. Redis writes may likewise complete after the wrapper stops waiting; active-session trust checks limit the security effect of stale active cache data, but do not solve the work/resource problem.

**Repair:** Propagate request/deadline cancellation through connection acquisition, execution, and transaction handling. Set real database-side execution/lock budgets. Mutation cancellation alone cannot establish whether a commit happened; introduce a durable operation identity and outcome-reconciliation strategy for unknown commit outcomes. Observe eventual failures of abandoned tasks.

**Required test:** Hold an account row lock beyond the configured fallback timeout, release it, then inspect database state after the HTTP response. Simulate response loss after commit separately. Verify a recoverable outcome and bounded pool occupancy.

### AUTH-03 — PostgreSQL does not validate the challenge being proved

**Evidence:** `Controllers/AccountControllerBase.TwoFactorHelpers.cs:203–319, 724–815, 818–898` (especially line 881); SQL `is_pending_twofactor_session_current`, `record_twofactor_challenge_issued`, and `promote_twofactor_new_login`/`promote_twofactor_rotation_login`.

The pending-session check confirms account stamp, pending token identity, and pending-session expiration. It does not compare challenge hash/version, selected configuration, or completed-proof state. Email/SMS verification compares the submitted hash against `session.challengeCodeHash` loaded from Redis. Final promotion confirms a live pending marker but does not atomically establish that this exact current challenge was accepted and that all required proofs were completed.

Concrete race: verification A loads challenge X; request B commits a replacement challenge Y; A verifies X from its snapshot and proceeds to promotion. The current PostgreSQL challenge is Y, yet no database operation rejects proof of X. Whole-object `When.Always` cache writes can also overwrite newer selection/progress with an earlier request's snapshot. Existing PostgreSQL attempt accounting does not close this success-path race.

**Repair:** Give pending state/challenges an authoritative version. Verify and consume delivered proof in PostgreSQL against the current hash/version, expiration, configuration, expected method, and attempt budget. Persist proof advancement atomically and require durable completion before promotion. Cache updates should be version-conditional projections of committed state. Apply the same state-version guard around accepted TOTP proof while retaining the durable replay marker.

**Required tests:** Barrier an old-proof request against challenge replacement; interleave successful proof, failed proof, and progress-cache writes; race two configuration selections; simulate loss of the new cache write. A superseded code and stale progress must never complete login.

### AUTH-04 — Concurrent wrong passwords lose failure increments

**Evidence:** `AccountControllerBase.LoginHelpers.cs:373–400`; SQL `set_account_login_failures:1379–1391`, `set_account_lockout:1352–1364`, and `remove_account_lockout:1366–1377`.

Each request reads the current failure count, increments its private copy, and sends an absolute value back to SQL. If two requests read zero, both write one; two attempts are recorded as one. A slow older request can overwrite a newer count with a smaller value. Choosing the threshold transition in application code also separates counting from lockout. An expired-lockout cleanup based on an earlier read can clear a subsequently renewed lockout because removal is unconditional by account ID.

The cache abuse policy mitigates guessing under normal operation, but it does not make the durable counter correct. This matters particularly when abuse controls are disabled or the configured counter-failure mode permits requests to proceed.

**Repair:** One PostgreSQL operation should atomically increment the durable count, decide the threshold/lockout, and return the current outcome. Bind mutations to the credential/account version verified by the request. Clear only the lockout version/expiration actually observed, and handle successful-password reset under the same concurrency policy.

**Required test:** Submit a batch of wrong-password attempts concurrently, inspect the persisted count and lockout, then interleave a successful login and an expired-lockout cleanup with new failures. Counts must not move backward because of stale requests.

### AUTH-05 — Reauthentication bypasses login attempt controls

**Evidence:** `Controllers/AccountSessionController.cs:77–125`; `Services/SensitiveActionTokenService.cs:74–154`; SQL `get_account_reauthentication_credentials`.

An authenticated request to `/account/reauthenticate` loads the password hash and performs Argon2id verification. A failed password returns without applying login abuse controls, a dedicated reauthentication budget, or a durable failure/lockout transition. The credential lookup does not fetch/enforce `unlock_when` either.

Someone holding a stolen active token can make repeated password guesses through this endpoint even when the login endpoint's password-attempt policy would block them. A user with their own valid session can also repeatedly trigger expensive password verification. Expiration/rotation caps the lifetime of an individual token; it is not an attempt budget.

**Repair:** Add a separate account/session/IP reauthentication attempt policy before hash verification, with authoritative failed-attempt accounting and appropriate behavior during counter outages. Keep successful issue and sensitive-action token binding intact. Include a bounded Argon2 concurrency budget.

**Required test:** Repeated and parallel wrong reauthentication passwords must trigger the configured rejection without invoking the hasher after the limit. Cover account lockout and counter outage explicitly.

### AUTH-06 — Failed expiration can leave an immortal counter

**Evidence:** `Rigging/Abuse/DragonflyAbuseCounterStore.cs:72–84`.

`INCR` runs first; only a result of one causes `EXPIRE`. If the process stops or the expiration command fails after the increment, the counter remains without a TTL. Later increments return values above one, so they never repair expiration. Once the count reaches the limit, the account/identifier/IP can remain blocked beyond the intended window. Cooldown expiration does not reset this immortal counter.

**Repair:** Use an atomic server-side operation to increment and establish/repair the window TTL. Preserve bounded execution and Dragonfly compatibility. Redis Lua supports atomic execution; verify the chosen script on the exact deployed compatible-cache version rather than assuming newer Redis-only commands exist.

**Required test:** Against real Dragonfly, interrupt the client between the logical increment/expiry steps and start with a TTL-less counter. Verify that all counters recover an expiration and the window eventually resets.

### AUTH-07 — Idempotency completion has a reservation ownership race

**Evidence:** `Rigging/Replay/AuthenticatedMutationIdempotency.cs:247–278`.

`CompleteAsync` reads the reservation, compares its token locally, then performs unconditional `SET`. If reservation A expires after the read and another request reserves B before the write, A overwrites B's reservation with A's completed result. Slow/stalled requests can outlive the configured 600–900 second lease. Owner tokens protect completion only if the comparison and write are atomic.

**Repair:** Compare reservation token and write completion/TTL in one atomic cache operation. Decide how to renew or fence operations that outlive their lease. State-changing operations still need database transaction/replay protection where duplicate execution is harmful.

**Required test:** Pause completion A after its read, expire A, reserve B, resume A. B's reservation must remain intact and A must not complete it.

### AUTH-08 — Same idempotency key with a different body can claim a false result

**Evidence:** `AuthenticatedMutationIdempotency.cs:33–39, 191–195, 290–298`; `AccountSessionController.cs:326–353`; `AccountTwoFactorController.cs:620–640`.

The reservation key includes account, method, route, and client key, but no request fingerprint. The stored result contains only status/code. Reusing a key for a different session target or removal method returns the earlier result without executing the new action. Removal replay builds the response with the new `payload.method`, so it can report success for a method that the first request did not remove.

**Repair:** Persist a canonical request fingerprint with the reservation/result; reject a different request under the same key. Store sufficient result data to replay the original response accurately. Include relevant session/security version semantics in the replay contract. Document that logout credentials being invalidated can prevent a later retry from reaching the controller replay path.

**Required test:** Reuse one key for two different `sessionId` values and for two factor-removal methods. The second request must receive a conflict and must not be reported as successfully applied.

### AUTH-09 — Refresh changes the identity used by session revoke

**Evidence:** SQL `sessions.session_id:80`; `rotate_active_session:2602–2737`; `revoke_session_for_account:3342`; `Entities/Session.cs`.

Refresh inserts a new session row without preserving `session_id`, so its default generates a new UUID. The entity/repository rotation contract does not carry this ID. Session revoke targets the listed UUID and ignores expired rows. Therefore: list session S, allow an automatic token refresh to create T, then revoke S. The result can be `SESSION_ALREADY_MISSING_OR_STALE`, while T remains usable. The user's intention to end the listed logical login session is not fulfilled.

**Repair:** Use a stable logical session/family ID across automatic token refresh. Keep token identity separate from session-management identity. A schema using one session row plus rotated token records may fit better than copying a unique session ID into several historical rows. Define separately whether a fresh password login starts a new logical session.

**Required test:** List the session, refresh its token, revoke the original listed ID, then try the refreshed token. It must be rejected.

### AUTH-10 — A database outage tells clients to discard valid credentials

**Evidence:** `JsonWebTokenMiddleware.cs:75–87, 176–184, 319–376`; `SessionRepo.GetSession` returning null on repository failure.

A database lookup timeout/exception is collapsed into no session; a cached-session trust timeout is collapsed into failed trust. Both emit `CLIENT_CLEAR_ACCESS_TOKEN`. A temporary PostgreSQL interruption can therefore cause clients to delete tokens for otherwise valid persisted sessions. Signature validation alone should still never authenticate during an outage, but failing closed does not require instructing permanent credential deletion.

**Repair:** Carry distinct results for missing/revoked/expired credentials and dependency failure. On dependency failure, deny protected operations with a retriable service-unavailable result while preserving the client's token. Only definitive authoritative invalidation should request token deletion. Avoid deleting a good cache entry solely because a trust-check dependency timed out.

**Required test:** Interrupt PostgreSQL during cached trust validation and cache-miss fallback. The operation must fail closed without the clear-token instruction; it should recover when PostgreSQL returns.

### AUTH-11 — Cold cache connection work bypasses the wrapper deadline

**Evidence:** `Rigging/Cache/ActiveUserCacheService.cs:34–50, 70–78`; corresponding lazy connections in `TwoFactorSessionService`, `DragonflyAbuseCounterStore`, and `DragonflyAuthenticatedMutationIdempotencyService`.

The first async operation evaluates a `Lazy<IConnectionMultiplexer>` and synchronously calls `ConnectionMultiplexer.Connect`. This runs before the async call yields and before middleware receives the task to race against its timeout. Cold/unreachable cache establishment can therefore block request threads beyond the 250 ms middleware budget. Other callers can wait on the same lazy initialization. If initialization throws, the standard lazy instance retains that exception; the class does not replace it to retry creation.

**Repair:** Initialize asynchronous, lifecycle-owned shared cache connections outside request hot paths and define initialization retry/readiness behavior. Confirm that each cache lane can share a connection where its endpoint/security configuration matches; use explicit database selection rather than relying on a single default database if sharing.

**Required test:** Start the host with an unreachable cache, submit concurrent first requests, then restore the cache. Verify latency bounds, thread usage, fallback, and recovery without process restart.

### AUTH-12 — Configuration values are not escaped in the PostgreSQL connection string

**Evidence:** `Rigging/Database/StorageContext.cs:18–21`.

The connection string is assembled by interpolating host/database/username/password into semicolon-separated text. Valid secret values containing semicolons or other connection-string syntax can be parsed as additional settings or fail parsing. This is a deployment correctness defect; it is not an SQL injection claim about HTTP inputs.

**Repair:** Construct settings with `NpgsqlConnectionStringBuilder` properties. Expose explicit deployment settings for port, verified TLS/certificates, connect/command/lock deadlines, pool limits, and application name as needed. The cache configuration similarly lacks an explicit TLS configuration surface. Assess transport settings against the intended network topology in the hosting/deployment pass.

**Required test:** Build and parse configuration with passwords containing semicolons, quotes, equals signs, and spaces; values must round-trip exactly. Test required TLS/certificate behavior against the deployment profile.

## Performance and operational follow-ups

### PERF-01 — Successful authentication performs redundant cache writes

Every successful non-refresh token request awaits cache read, PostgreSQL trust validation or lookup, JWT validation, and a full JSON `SET` with TTL. Cached trust validation also opens an explicit database transaction for a stable read. The cache does not remove PostgreSQL from the authenticated request path, and every valid cache hit is written again. These are observable code costs, not measured throughput results.

Preserve authoritative invalidation while avoiding unnecessary cache rewrites on unchanged hits. Hydrate on misses and update on actual state changes. Evaluate whether simple stable reads need explicit client transactions. Benchmark this approach against a single indexed PostgreSQL session read; keep Redis if measured latency/resource gains justify its additional calls and complexity.

### PERF-02 — Session history and stale pending rows have no retention runner

Rotations create new rows and expire old rows; normal runtime does not delete expired session history. References explicitly reserve hard deletion for future cleanup jobs. Expired pending login 2FA rows are generally removed on another login, promotion, or stamp rotation, rather than by an observed scheduled cleanup. No scheduled session-retention worker was found in this archive. Separate password-reset/email-change/delete cleanup functions exist, but do not establish a session retention policy.

Specify bounded batched cleanup and audit retention, preserve whatever history is required, avoid disrupting active session families, and validate the indexes at realistic history depth. Old session rows contain signing-key material, so decide how long that material is actually needed rather than retaining it by accident.

### PERF-03 — Infrastructure owners are not disposed by their wrapper classes

`StorageContext` creates an `NpgsqlDataSource` but does not implement a disposal contract. The cache/counter/idempotency services similarly own multiplexers without disposing them. `await using` around repository connections/readers is useful and is already present; it does not dispose these longer-lived owners. This is primarily a host shutdown/restart/test-host lifecycle issue, not evidence of a new connection pool per request.

Register directly disposable shared infrastructure objects with dependency injection or implement explicit ownership/disposal in the wrappers. Verify repeated host creation and teardown does not retain background resources.

### PERF-04 — Password hashing needs load qualification and a concurrency budget

Login and reauthentication invoke synchronous Argon2id verification on request execution paths. The default hash-creation memory setting is 65,536 KiB; actual verification resource cost follows the stored encoded hash parameters. Per-account/IP attempt limits do not cap aggregate concurrent hashes across many accounts. Measure peak concurrent hashes, memory, thread-pool queueing, CPU, and overload rejection. Use bounded concurrency with a bounded wait; moving hashing into unbounded `Task.Run` work would not solve the resource limit.

### Lifecycle behaviors that need explicit product confirmation

- Defaults are 15-minute access lifetime, 10-minute refresh window, three automatic refreshes, and seven-day hard session lifetime. With continuous activity and refresh near the start of each window, refreshes can occur around minutes 5, 10, and 15; the limit then causes authentication rejection around minute 20, even while the last token has unexpired access time. A seven-day stored hard limit does not mean the user stays signed in seven days. The existing middleware test intentionally expects this rejection. Treat the intended renewal/idle policy as a design decision before changing it.
- Expired access tokens are not refreshed after their access deadline. Cached and uncached paths enforce it. Idle gaps can require password login well before the hard database lifetime.
- Pending login 2FA cannot be reconstructed after a cache loss despite its PostgreSQL rows. Failure is closed, but cache restart can force users to restart login. Decide whether this availability behavior is acceptable or make pending-state retrieval authoritative.
- Application timestamps are captured before awaited work, and SQL uses `now()`, which is transaction-start time. Expiration/cutoff boundaries under long lock waits require tests with the post-wait wall clock. Use a fresh authorization timestamp where required; do not globally replace every SQL timestamp without considering consistency.
- The token is not a conventional independently validated expiring JWT. Document the server-state requirement for consumers. An algorithm allowlist and structural token checks are useful defense-in-depth, but this review does not claim an algorithm-substitution bypass: the exact stored token hash materially constrains that attack.

## Tests inspected and missing verification

| Existing suite/source | Useful existing coverage observed | What this pass still needs |
|---|---|---|
| `JsonWebTokenMiddlewareTests` | Cache trust failures, cutoff/expiration, PostgreSQL fallback, refresh success/failure, cache timeout/hydration outcomes. | Parallel refresh responses, real delayed-commit outcomes, database outage classification, cold connection initialization, stable session identity. |
| `AccountControllerAuthenticateTests` | Login branches, persistence failures, lockout and pending 2FA behavior. | Real concurrent failed-password accounting and stale cleanup/success races. |
| `SessionConcurrencyProcedureContractTests` | Two connections prove direct `set_session` calls serialize on the account row; then query active-session state. | Real refresh, revoke-after-refresh, logout/rotation interleavings, and client response behavior. |
| `TwoFactorSelectionEndpointTests` / `TwoFactorAuthenticationPromotionTests` | Selection, ordered combo proofs, authenticator proof path, promotion before cache write, fail-closed failures. | Superseded-code success path, configuration/proof version fencing, stale whole-object writes, durable completion verification. |
| `DragonflyAbuseCounterStoreTests` | Mocked increment, expiry, cooldown, outage policy. | Real atomic TTL behavior and recovery from TTL-less counters. |
| `AuthenticatedMutationIdempotencyTests` | Key construction/normalization and missing-key behavior; source-contract assertions. | Real reservation ownership races, different-body reuse, lease expiry, accurate replay response. |
| `SensitiveActionTokenServiceTests` | Token issue/validation and failed password outcomes. | Reauthentication throttling, durable budgets, outage and CPU overload behavior. |

These are inspected test sources. They were not executed. Mocked status returns and string-presence assertions cannot validate PostgreSQL lock schedules or real cache atomicity.

### Runtime qualification matrix

Run unit and in-process tests, real SQL contracts, and real direct/proxy stack HTTP tests after repairs. Add controlled fault/concurrency tests before relying on load results. Test cold/warm caches, cache unavailable/slow/restarting, PostgreSQL unavailable/slow/lock-blocked, multiple API instances, concurrent login/refresh/logout, and delayed responses. Measure p50/p95/p99 request latency, Redis command count, database transaction duration, account-lock waits, pool wait/occupancy, hash concurrency/memory, and database history growth. No throughput number or deployment-safe load threshold is asserted here.

## Suggested repair order

| Work item | Scope | Acceptance gate |
|---|---|---|
| AUTH-FIX-1 | Atomic password failures, guarded lockout cleanup, reauthentication budgets. | Concurrent attempts have correct durable accounting; hasher stops after budget exhaustion. |
| AUTH-FIX-2 | Versioned authoritative pending 2FA proofs/progress and promotion guard. | Old challenges and stale cache snapshots cannot complete login. |
| AUTH-FIX-3 | Refresh-family/session identity and concurrent request protocol. | Parallel refresh preserves usable client state; old listed session ID still revokes that login. |
| AUTH-FIX-4 | Real deadlines/cancellation, unknown-commit reconciliation, dependency status separation. | Late database operations do not create unrecoverable hidden rotations; outages fail closed without credential deletion. |
| AUTH-FIX-5 | Atomic cache counters, idempotency completion fencing, request fingerprint/replay data. | Fault schedules preserve TTL, reservation ownership, and accurate request-bound results. |
| AUTH-FIX-6 | Connection builder, asynchronous cache ownership, disposal, cache-write reduction, retention. | Startup/shutdown/failure tests pass; benchmark shows bounded resource usage and measured latency. |

These are review recommendations, not completed PRs. Runtime qualification remains required.

## Whole-project review ledger

The accompanying `Treehammock_File_Review_Inventory.csv` lists all 451 files, their SHA-256, assigned chunk, and review status. Cross-cutting files remain pending full-file review even when selected functions were inspected here.

| Chunk | Focus | State / completion condition |
|---|---|---|
| R01 | Core password authentication, JWT, active/pending login session lifecycle. | This source review delivered; all findings open; runtime qualification pending. |
| R02 | Registration, verification, password reset, unlock/recovery. | Next source-review chunk. Trace public token use, delivery, enumeration, cancellation, reset promotion/session invalidation, and recovery locks end to end. |
| R03 | Factor setup/removal, TOTP cryptography/provisioning/replay, sensitive actions. | Selected boundaries inspected in R01; complete lifecycle and crypto review pending. |
| R04 | Profile/username/email changes and account deletion. | Pending. Check ownership, uniqueness, stale-state/version races, token consumption, and deletion retention. |
| R05 | Activation workflows. | Pending. Check authenticated ownership, expiry, duplicates, delivery and disable/verify races. |
| R06 | Complete PostgreSQL schema/repositories and storage performance. | Session functions inspected in R01; complete function/schema/constraints/locking/index/query-plan/disposal audit pending. |
| R07 | HTTP pipeline, models, response contracts, validation, hosting and proxy trust. | Authentication filter/transport inspected in R01; complete API/transport/request-limit/error review pending. |
| R08 | Email/SMS/AWS/Twilio providers, templates and external calls. | Pending. Check delivery correctness, destinations, secrets, retry/idempotency, cancellation, timeouts, and encoding. |
| R09 | Shared abuse policies, telemetry, health and system-test surfaces. | Counter/idempotency primitives inspected in R01; full policies/metrics/readiness/test-surface exposure pending. |
| R10 | Build/dependencies, deployment/CI/tooling, complete test and documentation audit. | Pending. Validate reproducibility, deployment security, feature-matrix claims, every test lane, and supply-chain/version choices. |

At the end of each chunk, update this ledger with inspected files/functions, open finding IDs, required reproductions, changes if separately requested, and completed test evidence. After R10, reconcile every inventory row and every open finding; finish with cross-feature concurrency/fault/load qualification. No file should be called reviewed solely because it is assigned to a chunk.

## Supporting primary documentation

Checked during this review; source-code findings above are independent of documentation search snippets.

- [Npgsql basic usage and data-source pooling](https://www.npgsql.org/doc/basic-usage.html): data sources own connection pools; disposing connections returns them to the pool.
- [Npgsql connection-string settings](https://www.npgsql.org/doc/connection-string-parameters.html): explicit connection/command/cancellation budgets and transport/pool settings are distinct concerns.
- [PostgreSQL 16 date/time functions](https://www.postgresql.org/docs/16/functions-datetime.html): transaction-start timestamps differ from wall-clock timestamps during an executing statement.
- [Redis Lua execution](https://redis.io/docs/latest/develop/programmability/eval-intro/): scripts execute atomically; the project should verify script compatibility against its selected Dragonfly version.

The performance proposals are inferences from the observed call paths. They require measurements and integration tests before being described as improvements achieved.

### Inventory reconciliation

All 451 source files are mapped. Chunk counts: R01 = 65, R02 = 60, R03 = 28, R04 = 9, R05 = 12, R06 = 19, R07 = 54, R08 = 19, R09 = 30, R10 = 155. 53 files have explicit R01 inspection notes; these do not constitute full-file qualification. The two SQL baseline copies have identical executable content and differ only in the first branding comment.
