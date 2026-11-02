# Treehammock review 02 — Registration, verification, password reset, and recovery

Reviewed October 3, 2026. Input: `treehammock-main.zip`, SHA-256 `229ef2275f1caeff3a6a40186e678f7440a90fd54add2e0ba8de0fd6c645758f`.

## Assessment and limits

This source pass identified **15 actionable findings: six P1 and nine P2**. The most consequential issues are weak default password-hash cost, unrestricted signup hashing, replacement tokens invalidating delivered tokens before delivery is allowed, non-atomic unlock validation, stale password-reset proof updates, and reset-session revocation bypass after removing the last additional factor. The uploaded source is unchanged. No finding is marked fixed or runtime-qualified.

The pass traced the four public flows through controllers, services, repository calls, PostgreSQL procedures, state models, settings, delivery seams, and selected test assertions. It also followed factor removal only far enough to establish its effect on reset authorization; full enrollment/removal is R03. SQL locations below refer to `Rigging/Database/Baseline/000_canonical_database.sql`; the second baseline contains the same executable SQL.

There is no .NET SDK, Docker, PostgreSQL client/server, or Redis server executable in this workspace. R01's validation command stopped at `dotnet: command not found`; that blocker remains. No build, application tests, SQL integration tests, HTTP reproduction, query plans, or load benchmarks ran successfully. Concurrency schedules below are source-grounded inferences requiring real database tests. Structural evidence checks establish what the source contains, not application behavior under execution.

## Flow and authority

| Flow | Authority and current sequence |
|---|---|
| Signup | Validate inputs; hash password; insert account and token hash; start verification in a second transaction; check delivery throttle; send email. |
| Verification resend | Expire prior token rows and insert a replacement; then check delivery throttle and send. |
| Account verification | Cache-backed token/IP budget; SQL lookup; application expiry/hash check; separate SQL completion. |
| Unlock request | SQL lookup of locked account and verified destination; generate random token; cancel prior tokens and create replacement; delivery throttle/send; cancel replacement on failure. |
| Unlock verification | Token/IP budget; SQL token/status/expiry/account-binding reads; then token and account updates. |
| Password-reset request | Identifier/IP/account abuse budgets and durable daily/cooldown counters; SQL eligibility; create replacement reset; deliver code; cancel replacement on failure. |
| Reset bootstrap proof | SQL lookup; verify HMAC code; issue deterministic HMAC reset access token; advertise current eligible additional methods. |
| Reset additional proof | PostgreSQL pending session, accessed through a cache-shaped interface; read state, verify proof, then overwrite pending state with an upsert. |
| Password promotion | Application proof gate; Argon2id hash; SQL locks and checks reset/account; update password/stamp, cut off sessions, consume reset, revoke pending reset sessions. |

`PasswordResetSessionService` uses PostgreSQL, not Redis. Its `expire` and Redis `CommandFlags` arguments are ignored; absolute expiration resides in the SQL row. Redis-compatible storage supplies abuse counters. Giving reset state durable storage is useful, but durability alone does not make read/check/write transitions atomic.

Protections to retain include random 256-bit account-verification/unlock tokens stored as hashes; cryptographically generated reset digits; peppered HMAC reset-code hashes and constant-time comparison; reset/account binding; durable failed-attempt increments; a unique active reset per account; promotion consumption and security-stamp rotation in one transaction; and authoritative session cutoff. Bootstrap proof is excluded from the additional-factor menu, and combined paths enforce their proof order. These are source observations rather than a blanket security qualification.

## Findings

P1 denotes an important security or availability defect to address first. P2 denotes actionable correctness, reliability, or operational work. Confidence is high in the identified source behavior; integration impact and frequency remain unmeasured.

| ID | Priority | Finding |
|---|---|---|
| R02-01 | P1 | Public signup performs expensive password hashing before any signup abuse gate. |
| R02-15 | P1 | Default password-hash memory is passed in bytes, implying only 64 KiB. |
| R02-02 | P1 | Token replacement invalidates delivered tokens before delivery admission. |
| R02-03 | P1 | Unlock can clear a newer lockout using an earlier account/token snapshot. |
| R02-04 | P1 | Stale reset proof writes can replace a newer challenge or undo session revocation. |
| R02-05 | P1 | Removing the last additional factor allows a revoked reset session to be bypassed. |
| R02-06 | P2 | Password promotion does not atomically validate the completed reset proof session. |
| R02-07 | P2 | Reset creation and promotion acquire account/reset locks in opposite orders. |
| R02-08 | P2 | Expiration is not consistently enforced at the authoritative mutation point. |
| R02-09 | P2 | Concurrent duplicate signup returns a generic failure instead of the duplicate contract. |
| R02-10 | P2 | Concurrent verification resends can leave multiple usable verification tokens. |
| R02-11 | P2 | Infrastructure failure is reported and charged as missing/incorrect reset proof. |
| R02-12 | P2 | The fifth invalid bootstrap proof can reveal whether a reset request was real. |
| R02-13 | P2 | CAPTCHA configuration is disconnected from the actual request count and proof flow. |
| R02-14 | P2 | Reset cleanup exists but is not scheduled; reset events have no bounded retention. |

### R02-01 — Public signup hashing has no admission limit

**Evidence:** `Controllers/AccountRegistrationController.cs`, `AccountSetup`; `Services/AccountService.cs:103–189`; `Services/AccountService.cs`, `TrySendEmailWithDeliveryThrottle`; `appsettings.json`, `LoginSettings.Argon2MemoryUsePer`.

Every syntactically valid public signup reaches Argon2id before the account lookup/insert and before any delivery throttle. Even a repeatedly submitted existing email incurs the hash. No signup request/IP/identifier admission budget or aggregate hash-work limiter was found in this path. Delivery limits protect outbound messages after this resource expenditure. Unique-address submissions can also create undelivered, unverified account rows. Per-request memory, CPU, and achievable attack throughput are unmeasured. R02-15's weak default does not establish a safe resource bound, and correcting the hash cost makes early admission and aggregate limits more urgent.

**Repair:** Apply public signup budgets before hashing and database mutation. Bound concurrent password-hash work across the host, with explicit rejection behavior and capacity measurements. Add a defined retention/recovery policy for abandoned unverified accounts. Keep account-existence behavior deliberate.

**Required validation:** Flood valid duplicate and distinct signup inputs through real HTTP while delivery is denied. Establish a bound on active hashes, memory, queue depth, pool use, and database growth.

### R02-02 — Destructive replacement precedes delivery admission

**Evidence:** `AccountService.cs:199–230`; SQL `resend_verify_account:638–690`; `AccountRecoveryService.cs`, `StartRecovery` and `TryDeliverUnlockToken`; SQL `start_unlock_account:4528–4606`; `PasswordResetService.cs:305–374`; SQL `create_password_reset_request:5090–5134`.

Verification resend first expires the user's delivered link and commits a new token. A denied delivery throttle then returns pending without emailing that token. Public unlock start similarly cancels prior unlock tokens before admission; on denial it cancels the replacement too. An unauthenticated caller who knows the email/identifier can repeat these operations and prevent a recipient from completing the legitimate flow. The start paths have no request admission budget before the destructive rotation. Password reset has stronger up-front request budgets, but an admitted request can still cancel its predecessor and then fail the separate delivery gate, leaving no delivered usable replacement.

**Repair:** Reject throttled requests before changing current token state. Define delivery/replacement semantics with a durable outbox or equivalent retry protocol, and maintain a usable recovery route after provider failure. Do not hold a database transaction open across a network send. Give verification resend/unlock start their own account/identifier/IP request budgets and cooldowns.

**Required validation:** Start with a delivered valid token, exhaust delivery limits, submit another request, and verify that denial preserves the previous usable token. Repeat for provider failure, retry, concurrent replacement, and response loss.

### R02-03 — Unlock binding is checked without protecting the mutation

**Evidence:** SQL `verify_unlock_account:4646–4727`, `start_unlock_account`, `cancel_unlock_account`; `Repos/AccountRecoveryRepo.cs`.

Unlock reads the recovery status and account security stamp/`unlock_when` without row locks, checks the saved lockout binding, then updates the token and clears `accounts.unlock_when` by account ID alone. A concurrent lockout update or stamp rotation can commit after the check and before the account update. The old valid token can then clear the newer lockout. Cancellation can likewise commit between token read and completion, yet completion overwrites its status. Two consumers can both pass the initial status check and report completion.

**Repair:** Serialize all unlock start/cancel/verify transitions with the account and current token, in a consistent lock order. Validate binding after acquiring the relevant locks and use conditional updates that include current status, stamp, lockout identity, and expiry. Require one successful consumption.

**Required validation:** Barrier verification after its binding read; commit a newer lockout, stamp rotation, or token cancellation; release verification and require rejection. Two parallel consumes must have one winner.

### R02-04 — Reset proof upsert accepts stale state and resurrects revoked rows

**Evidence:** `PasswordResetService.cs:434–611, 613–768, 1086–1110`; SQL `upsert_pending_password_reset_session:5248–5401`; `PasswordResetSessionService.cs`.

Proof verification reads a pending session and checks its challenge in application memory. Its later SQL upsert locks the parent reset but overwrites the pending row without an expected version, challenge identity, current state, or revocation predicate. `ON CONFLICT` explicitly clears `revoked_at` and `revoked_reason`. Thus A can read a valid old SMS challenge, B can replace it, and A can verify the old code and overwrite B's row as completed. A stale write can also undo a session-only revocation while the parent reset remains active. Parent cancellation/consumption is guarded and is not claimed to be bypassed.

Selection always constructs a fresh session; repeated selection also erases progress and resets challenge counters. The stored `nextChallengeAllowedAt` is not consulted by this orchestration path. Delivery throttling does not make the state replacement safe.

**Repair:** Replace generic upsert with explicit SQL transition commands using expected session/challenge versions and monotonic state rules. Revocation must be terminal for that session identity. Issue/reselect/resend must preserve budgets and enforce cooldowns against authoritative current state.

**Required validation:** Barrier an old correct proof after session read, replace the challenge or revoke the session, then release the write. Require stale rejection, intact newer state, and no resurrection. Cover delayed failed-proof writes overwriting completed state too.

### R02-05 — Removing the last additional factor bypasses reset revocation

**Evidence:** `PasswordResetService.cs:908–978`, especially `availableConfigurations.Count == 0`; `PasswordResetTwoFactorConfigurationResolver.cs`; SQL `remove_twofactor_method:3842–4035`, `revoke_pending_password_reset_sessions_for_account:5436–5481`, and `promote_password_reset`.

Consider an account with verified email and only an authenticator as an additional reset factor. An email bootstrap code yields a reset access token and an authenticator-required pending session. Factor removal revokes that pending session, but does not cancel its parent reset or rotate the account stamp. Subsequent finalize recomputes available configurations: email is excluded as the bootstrap method, and no authenticator remains. The zero-configuration early return skips the revoked-session lookup entirely. SQL promotion sees an active, stamp-matching reset and can change the password without the originally required authenticator proof.

This is a sequential path, distinct from R02-04's stale writes. Existing removal tests retain another additional factor, so they do not cover this boundary. Allowing a newly requested reset under a new factor policy is a separate design choice; the old revoked session should not silently gain authorization.

**Repair:** Cancel/invalidate the parent reset when factor changes revoke its authorization, and bind reset authorization to a factor-policy version or initial proof requirement. The zero-factor path must still reject explicitly revoked authorization. Enforce this in promotion too.

**Required validation:** Email plus authenticator only; verify bootstrap, select authenticator, remove it, then finalize with the old access token and separately with the old bootstrap code. Both old authorization paths must fail. Repeat with SMS as the only additional factor.

### R02-06 — Completed reset proof is outside the password transaction

**Evidence:** `PasswordResetService.cs:823–845, 908–1030`; `Repos/PasswordResetRepo.cs:125–142, 533–600`; SQL `promote_password_reset:5679–5823`.

The application reads a completed pending session, then hashes the new password and calls promotion. Promotion has no reset-session hash/version argument and never checks selected configuration, completed methods, session expiry, or session revocation. Reselection, revocation, or expiration between the proof gate and promotion therefore does not necessarily prevent the password change. SQL's reset/account stamp checks are useful but do not represent the proof-session state.

**Repair:** Make final promotion consume a specific, current, unrevoked, unexpired authorization session/version under the same transaction as the password mutation. Explicitly support resets that legitimately require no additional factor without weakening session revocation semantics.

**Required validation:** Pause after the gate, then reselect/revoke/expire the session before promotion. Require rejection and unchanged password. Retain the two-finalizer one-winner test.

### R02-07 — Opposite lock order creates a reset deadlock

**Evidence:** SQL `create_password_reset_request:5025–5030, 5090–5095`; `promote_password_reset:5701–5705, 5752–5757`; `PasswordResetRepo.cs` exception handlers.

Creation locks account A then updates old reset R. Promotion locks R then locks A. If both take their first lock, each waits for the other. PostgreSQL aborts one transaction to break the cycle. The repository logs and returns null without targeted deadlock retry; a valid finalize can become a generic failure, or replacement creation can be silently suppressed under the generic accepted response. This is an availability issue; transaction rollback protects integrity.

**Repair:** Establish and use one lock order across creation, promotion, factor removal, cancellation, and cleanup. Add bounded retries only for identified retryable transaction failures and preserve operation identity/outcome semantics.

**Required validation:** Use two real SQL connections with barriers after the first locks, run creation and promotion concurrently, and verify controlled outcomes without the lock cycle. Two calls to the same fake method do not test this schedule.

### R02-08 — Expiry checks can age before authoritative completion

**Evidence:** `AccountRegistrationController.cs:243–268`; SQL `complete_verify_account:710–737`; `PasswordResetService.cs:980–1007`; SQL `promote_password_reset:5701–5757`; `verify_unlock_account` uses `now()`.

Account verification checks expiry in the controller, then completes in another transaction whose function checks status but not expiry. A pre-expiry request delayed before completion can verify afterward; the controller also accepts equality because it uses `moment > expiresAt`. Reset promotion checks against an application timestamp captured before connection/lock waits, and checks expiry before waiting for its account lock. A long wait can therefore consume an expired reset. PostgreSQL `now()` is transaction-start time, so using it does not by itself solve long lock-wait boundaries.

**Repair:** Define one expiry boundary (`expires_at > current time`) and recheck against the authoritative clock after relevant locks, immediately before mutation. Keep audit timestamps distinct from authorization time. Avoid holding locks during hashing or delivery.

**Required validation:** Block each completion around expiry and verify rejection after the boundary; include exact equality, application/database clock skew, and transaction/row-lock waits.

### R02-09 — Duplicate signup races lose their API result

**Evidence:** SQL `setup_account_email:493–550`, `setup_account_both:553–616`; unique lower(email)/lower(username)/web-key indexes at SQL `34–42`; `AccountRepo.cs:450–514`; `AccountService.cs:157–175`.

Two signups can both pass pre-insert existence checks. Unique indexes correctly prevent duplicate accounts, but the loser raises `unique_violation`; these setup functions do not map that conflict to their duplicate outcome. The repository returns generic failure, so the service/controller produces an internal error rather than the documented duplicate-email/username result. The same pattern undermines intended rare GUID/web-key retry handling.

**Repair:** Map constraint conflicts at the transactional insert boundary to stable outcomes, distinguishing email, username, account ID, and web key. Preserve transaction rollback for genuinely unexpected failures.

**Required validation:** Concurrent duplicate email and username submissions with barriers before inserts; one success and a deterministic duplicate result, without a generic server failure.

### R02-10 — Concurrent resends can create multiple active links

**Evidence:** SQL `resend_verify_account:638–690`; account-verification schema/indexes at SQL `47–58, 75–76`; `complete_verify_account`.

Resend reads the account without locking it, expires currently visible rows, then inserts a new row. Two overlapping resends can both run the expiration step before seeing the other's new row, then each insert a usable token. Only token-hash uniqueness exists; there is no one-active-verification-per-account constraint. Either link can subsequently complete, contrary to the intended replacement of earlier links.

**Repair:** Serialize token issuance per account and enforce a defined current-token identity/invariant. Combine this with R02-02's delivery admission so serialization does not merely make denied requests reliably invalidate good links.

**Required validation:** Concurrent resends against real SQL; after both commit, only the authorized current token should complete. Include verify-versus-resend.

### R02-11 — Backend faults consume the user's proof budget

**Evidence:** `PasswordResetTotpService.cs`, enrollment lookup/unprotect/step-marker exception handling; `PasswordResetService.cs:699–740, 1580–1608`; `PasswordResetRepo.cs:410–478, 658–702`; `PasswordResetSessionService.cs`.

TOTP enrollment/secret/marker failures return `Verified=false` with diagnostic codes. Orchestration treats all false results as an incorrect proof, persists a failed challenge, and registers a durable reset failed attempt. A transient infrastructure fault can consequently cancel a valid reset after the attempt limit. Pending-session SQL failure is also collapsed to null, then reported as expired/not complete; bootstrap lookup failure becomes invalid proof. Cancellation is swallowed by broad repository exception handlers, and the reset-session wrapper passes `CancellationToken.None`.

**Repair:** Use typed outcomes for invalid proof, absent/revoked state, backend unavailability, and cancellation. Fail closed with a retryable service-unavailable response for backend faults without charging the invalid-proof budget. Propagate deadlines through connection acquisition and execution; reconcile uncertain mutation outcomes.

**Required validation:** Inject enrollment lookup, decryption, replay-marker, and pending-session database faults independently. No password change; correct service-unavailable outcome; unchanged invalid-proof count and authorization; bounded work on disconnect.

### R02-12 — Generic request responses leak through later proof attempts

**Evidence:** `PasswordResetService.cs:212–374, 376–432, 1580–1608`; SQL `get_password_reset_request_for_finalize`, `register_password_reset_failed_attempt:5588–5677`; supplied `MaxAttempts=5` and reset token-verification abuse limit of five.

Request returns a random public reset ID for both eligible and unknown accounts, but only the eligible account gets a real row. An unauthenticated caller can request a reset for a target and submit five intentionally incorrect codes for the returned ID. Under the supplied limits, the fifth request is still admitted by the abuse budget. A real reset's fifth failed proof returns `PASSWORD_RESET_ATTEMPTS_EXCEEDED`/429; a nonexistent reset continues to return invalid proof/401. This reveals whether an eligible reset was created without possession of the delivered code, and cancels that reset. Cancellation/expiry lookup states and synchronous delivery timing offer related distinction surfaces.

**Repair:** Preserve non-enumeration across the entire unauthenticated flow, including exhaustion and nonexistent IDs. Use a consistent outward invalid-proof/throttling protocol while retaining authoritative internal cancellation. Queue delivery to reduce synchronous timing differences. Successful possession proof may legitimately reveal account-specific next steps.

**Required validation:** Compare eligible and unknown accounts across attempts one through six using actual default limits, then expired/canceled states and provider latency. No distinguishing unauthorized code/status sequence.

### R02-13 — CAPTCHA enablement does not implement the advertised threshold

**Evidence:** `PasswordResetService.cs:295`; `PasswordResetAbuseProtectionServices.cs`, `ShouldRequireCaptcha`; `PasswordResetSettings.cs`; `PasswordResetAbuseProtectionTests.cs:85–102`.

Orchestration always calls `ShouldRequireCaptcha(1)`. Enabling CAPTCHA with the supplied threshold of three therefore never reaches the threshold. Setting the threshold to one suppresses every eligible reset request, and there is no CAPTCHA token/verification/resume path. The policy unit test passes a count of three directly; it does not establish that orchestration supplies a real count.

**Repair:** Either remove/reject unsupported CAPTCHA enablement at startup, or wire an actual authoritative request count and verified CAPTCHA continuation. Do not silently disable recovery through a configurable stub.

**Required validation:** Enabled policy at thresholds one and three through the public request path; enforce advertised behavior and retain a working verified continuation.

### R02-14 — Cleanup is callable but has no production caller

**Evidence:** `PasswordResetRepo.cs:905–1009`; SQL `cleanup_password_reset_rate_limits:4968–4990`, `cleanup_expired_password_reset_requests:5825–5864`; reset-event schema at SQL `413–428`; repository-wide caller search.

Cleanup functions and repository methods exist, but no production service/job invokes them in the supplied project. Tests call them directly. Without an external operator job, reset requests, pending sessions, and rate-limit keys accumulate. `password_reset_events` has no foreign key with cascading removal and neither cleanup deletes it; request cleanup alone leaves the events indefinitely. Each session upsert appends an event, so repeated selection magnifies this growth.

**Repair:** Define retention and schedule bounded cleanup with telemetry, retry/error handling, and appropriate indexes. Cover independent event retention and abandoned verification/recovery state. Confirm any external scheduler before treating an operational deployment as corrected.

**Required validation:** Seed aged terminal rows/events, run the actual scheduled path, retain active authorization, delete expected history, and measure batch time, WAL, locks, and table/index growth.

### R02-15 — Default password-hash cost uses the wrong scale

**Evidence:** `appsettings.json` and `appsettings.Example.json`, `LoginSettings.Argon2MemoryUsePer=65536`; `Argon2idPasswordHashCodec.cs:9–20`; `AccountService.cs:105`; `PasswordResetPasswordMaterialService.cs:40–43`; `Directory.Packages.props`, Geralt 4.1.0; [Geralt password-hashing API documentation](https://www.geralt.xyz/password-hashing).

The codec passes this integer directly to Geralt `Argon2id.ComputeHash`. The official API documents that argument in bytes. The supplied configuration therefore implies 65,536 bytes, or 64 KiB, instead of 65,536 KiB/64 MiB. Geralt's documented minimum recommendation is 64 MiB. The configured iteration count of three does not correct the memory scale. All newly created signup/reset hashes using this configuration inherit the weak cost, materially reducing the intended resistance to offline guessing if password hashes are exposed. Actual deployment overrides were not supplied.

This conclusion combines the source call with the official API contract; the encoded output from the project's pinned Geralt version has not been executed here. Startup validation currently accepts any positive memory integer, so it does not catch cost below the library's security recommendation or clarify units. Existing passwords remain verifiable because encoded hashes carry their own cost.

**Repair:** Name/document this setting in bytes, require an appropriate minimum, and use a measured cost such as 67,108,864 bytes if adopting the documented 64 MiB target. Add aggregate hashing limits before increasing it. Rehash existing low-cost hashes after successful login using the codec's actual encoded parameters and a deliberate migration policy; changing defaults alone does not strengthen stored hashes.

**Required validation:** Generate signup and reset hashes with Geralt 4.1.0, decode their PHC memory parameter, and require the chosen security cost. The current direct-byte interpretation predicts `m=64` KiB; a 64 MiB setting should encode `m=65536`. Verify old-hash login, upgraded-hash login, and controlled rehash behavior, then benchmark concurrency and capacity.

## Performance and API follow-ups

- Reset request on an eligible account can perform four separate durable operations before creation: IP rate limit, account lookup, account rate limit, destination rate limit; creation is another transaction. Redis budgets and provider calls add more latency. Reset proof and finalization each load reset/account/factor state again. Measure actual command count and p95/p99 latency before batching the necessary SQL reads/writes.
- Repository reads generally use explicit begin/commit transactions for one function call. Validate whether the extra round trips serve a needed consistency guarantee. Connection acquisition does not take the request cancellation token in these calls.
- Verification resend and unlock start need admission limits before SQL work. Reset verify/proof/finalize budgets are scoped to reset ID, without the supplied IP/user-agent feeding an additional pre-lookup gate. Random valid reset IDs can create many cache keys and database lookups without exhausting any one budget. Add global/IP capacity protection and measure key cardinality; per-reset security budgets should remain.
- SQL reset identifier lookup uses account predicates OR a correlated factor lookup with several `regexp_replace` phone predicates. Stored normalized phone identity and suitable indexes may be needed at scale. R06 will require real plans and cardinalities; no full-scan cost is asserted without them.
- The selection API accepts `destination`, but service selection ignores it and SQL chooses the preferred verified SMS destination. Either define that single-destination contract or validate/select the requested destination. Review complete factor modeling in R03 before changing this interface.
- Reset's supplied two-minute lifetime is short relative to email/SMS delivery plus combined-factor entry. Delivery remains synchronous. Measure remaining usable lifetime, late provider completion, and cancellation cleanup, then choose explicit timing/retry policy.
- Factor menus currently offer single-method alternatives even when multiple factors exist. Tests explicitly expect these menus. Whether reset may use any additional factor or must honor an enrolled required combination is a policy decision for R03, not an asserted bug in this pass.
- Relative verification URLs are allowed when the configured origin is blank. Verify absolute HTTPS origin, trusted proxy handling, log/referrer protection, and response cache policy in hosting/HTTP chunks. Provider/template encoding and external send reliability receive the R08 pass.

## Validation evidence and missing tests

Existing source includes controller/input tests, token randomness/hash checks, abuse-policy/key tests, delivery-failure handling, state-model progression, SQL schema-string assertions, a fake-backed end-to-end harness, and real PostgreSQL contract tests. Real SQL tests cover lifecycle, cancellation, promotion/session invalidation, TOTP replay, durable pending-session rehydration, and rate limits. These were inspected selectively, not run.

`PasswordResetEndToEndRegressionTests` uses an in-memory repository with `lock (_sync)` for promotion and custom gates. Its two-promoter and two-creator tests exercise same-operation races; they cannot demonstrate PostgreSQL lock ordering between different operations. Its removal scenarios leave another factor, omitting the zero-additional-factor case. Several repository/schema tests assert names/source text rather than execute transitions. They are useful wiring checks but do not qualify the schedules identified here.

First regression work should exercise R02-03/04/05/06/07 on the real PostgreSQL baseline. Follow with expiry/delivery ordering, fifth-attempt non-enumeration, duplicate signup, and resource bounds. Run the project's required validation script once the SDK and SQL/Dragonfly services are available. Record builds, test results, lock schedules, and measured latencies separately from this static pass.

Supporting official references, consulted October 3, 2026:

- [PostgreSQL 16 locking](https://www.postgresql.org/docs/16/explicit-locking.html): ordinary reads do not lock account state against writers; consistent acquisition order prevents lock cycles; detected deadlocks abort a participant.
- [PostgreSQL 16 time functions](https://www.postgresql.org/docs/16/functions-datetime.html): `now()` tracks transaction start, while `clock_timestamp()` supplies current wall-clock time.
- [OWASP forgot-password guidance](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html): consistent public behavior, abuse controls, and expiring single-use recovery authorization.
- [Geralt password hashing](https://www.geralt.xyz/password-hashing): `ComputeHash` memory is specified in bytes; the documentation recommends at least 64 MiB and stores cost in the encoded hash. The project's pinned-version runtime output remains to be checked.

The findings themselves derive from this uploaded source. These references explain the underlying transaction and recovery principles; they do not establish a runtime reproduction.

## Cumulative review ledger

R01's AUTH-01 through AUTH-12 remain open. R02 adds R02-01 through R02-15, all open. Total: **27 findings, eleven P1 and sixteen P2**. R02-15 also applies to the shared password-hash codec used by the authentication reviewed in R01; it is recorded once in R02. Performance observations and design decisions are tracked separately and are not added to this finding count. No source fixes have been applied.

| Chunk | Scope | Status |
|---|---|---|
| R01 | Authentication and session lifecycle | Source pass recorded; 12 findings open; runtime qualification pending. |
| R02 | Registration, verification, reset, unlock | Source pass recorded; 15 findings open; runtime qualification pending. |
| R03 | Complete factor enrollment/removal, TOTP crypto/replay, sensitive actions | Next. |
| R04 | Profile, email change, deletion | Pending. |
| R05 | Activation | Pending. |
| R06 | PostgreSQL schema, repositories, concurrency, performance | Pending. |
| R07 | HTTP pipeline, models, hosting, proxies | Pending. |
| R08 | Providers and templates | Pending. |
| R09 | Abuse, telemetry, health, test surfaces | Pending. |
| R10 | Build, dependencies, deployment, CI, documentation | Pending. |

The bundle contains both reports, the cumulative 451-file inventory, evidence, and the validation blocker. File assignment is not review approval. R02 inventory notes distinguish traced production paths from selectively inspected test sources and deferred provider/runtime qualification.
