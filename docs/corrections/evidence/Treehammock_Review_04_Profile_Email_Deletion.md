# Treehammock review 04 — Profile, email changes, and account deletion

Reviewed 2026-10-03. Original archive: `treehammock-main.zip`, SHA-256 `229ef2275f1caeff3a6a40186e678f7440a90fd54add2e0ba8de0fd6c645758f`.

## Result and qualification boundary

This chunk adds **9 open findings: 2 P1 and 7 P2**. The cumulative ledger now contains **46 open findings: 16 P1 and 30 P2**. P1 means resolve before production security qualification. P2 means a concrete correctness, reliability, or operational weakness for the review backlog. These are review priorities, not measured exploit scores.

The principal risks are recovery-email changes authorized by an active session alone and deletion's non-atomic security-stamp check. Profile ownership and credential exclusion are sound in the inspected source. Email completion also has useful safeguards: a conditional account-stamp update, session invalidation, and removal of the old email factor. The surrounding admission, lifecycle, and concurrency behavior needs correction.

**This is a source review.** No .NET build, unit/controller test, PostgreSQL reproduction, cache/HTTP system test, or performance benchmark ran. The environment still lacks `dotnet`, Docker, PostgreSQL/`psql`, and a Redis server. The earlier validation attempt remains blocked by `dotnet: command not found`. Structural assertions in the evidence script are source checks only. All 451 source files remain unchanged; no fixes are included.

Scope: the full profile and deletion controllers; username/profile and email-change/deletion repository slices; relevant account-service, validation, configuration, schema, and template content; twelve PostgreSQL functions; and selected test assertions. Nine files are assigned to R04 in the original inventory, with additional cross-chunk files inspected as recorded in the cumulative CSV. A scope assignment or selected test inspection is not whole-file approval or runtime qualification. SMTP implementation/rendering, complete database tuning, hosting, and whole-suite quality retain their later review chunks.

## Flow and authority map

| Operation | Authorization and durable transition | Main boundary |
| --- | --- | --- |
| `GET /account/view` | Authenticated account ID/stamp → `view_account` → limited profile DTO | No caller-selected ownership ID; safe profile fields |
| `POST /account/adjust`, username | Active session + required idempotency key → `edit_account_username` | Final username update predicates on the supplied stamp; uniqueness enforced |
| `POST /account/adjust`, email | Active session + required idempotency key → pending hashed-token request → delivery to proposed address | No fresh password/factor grant; previous request is overwritten before delivery |
| `GET /account/adjust/email/verify` | Public opaque token + cache token/IP budget → SQL completion | Changes address, rotates stamp, deletes verified email factor, and expires sessions |
| `POST /account/wipeout` | Active session + required idempotency key → delete standby row → email delivery | Optional passphrase is a newly chosen deletion secret, not account-password reauthentication |
| `GET /account/wipeout/verify` | Public opaque token + cache token/IP budget → standby `verified = true` | Does not itself delete the account |
| `POST /account/wipeout/finalize` | Active session + required idempotency key + cache account/token budget → SQL prepare → optional local passphrase verify → SQL commit in one repository transaction | Standby row locked through prepare/commit; account-stamp check is not held through deletion |

## New findings

| ID | Priority | Finding |
| --- | --- | --- |
| R04-01 | P1 | Recovery-email changes require no fresh password or existing-factor proof. |
| R04-02 | P1 | Final deletion can remove an account after its checked security stamp changes. |
| R04-03 | P2 | Pending deletion proofs survive account security-stamp and email changes. |
| R04-04 | P2 | Email completion and account deletion can deadlock through opposite lock order. |
| R04-05 | P2 | Failed-delivery cleanup erases the durable deletion-request cooldown and count. |
| R04-06 | P2 | Concurrent first deletion requests bypass the cooldown and overwrite the initial count. |
| R04-07 | P2 | Expired email-change reservations still block other accounts from requesting the address. |
| R04-08 | P2 | A concurrent address claim turns email completion into a generic server error. |
| R04-09 | P2 | Email verification GET performs the account change and session revocation immediately. |

### R04-01 — A session can change the account's recovery identity

**Evidence.** [AccountProfileController.cs](sandbox:/workspace/scratch/78b7f387c802/source/treehammock-main/Controllers/AccountProfileController.cs), `ModifyAccount` (line 80), authenticates, requires idempotency, and calls `RequestEmailChange` when an email field is supplied. Neither that action nor the account-service request path verifies the current password, an existing factor, or a sensitive-action grant. [AccountEdit.cs](sandbox:/workspace/scratch/78b7f387c802/source/treehammock-main/Models/Account/AccountEdit.cs) has email/username fields only. Delivery goes to the proposed new address. `VerifyEmailChange` is public and invokes the final mutation with the emailed token.

**Source-derived scenario.** An attacker holding a stolen valid session requests an address they control, receives its token, and completes the change without knowing the current password. Completion rotates the stamp and expires the legitimate user's sessions. For accounts with no additional factor, the ordinary public password-reset flow can then use the new address. For an email-only 2FA account, completion removes that old email factor, leaving no additional factor. This provides a plausible takeover chain; it is not an executed exploit, and accounts retaining SMS/authenticator proof may have an additional reset barrier.

The new-mailbox token proves access to the destination, not authorization by the current account owner. An idempotency key does not supply that authorization. The inspected path also sends no alert/confirmation to the previous address.

**Change.** Require a fresh, purpose-bound authorization before creating the email-change request: current-password proof for the agreed non-MFA policy and existing-factor proof where required for MFA accounts. Bind the approved change to its account generation and intended address. Define notification/recovery behavior through the previous trusted address. Apply the existing reauthentication throttle fix (AUTH-05) when extending sensitive grants; do not merely add another unthrottled password endpoint.

**Qualification.** Add HTTP tests for a valid session without fresh proof, wrong-purpose/destination grants, no-factor and email-only accounts, and retained-authenticator accounts. The stolen-session scenario must fail before pending state/delivery. Prove that legitimate proof plus destination confirmation succeeds and that old sessions remain unusable after commit. OWASP recommends reauthentication for email changes and provides different MFA/non-MFA email-change processes. This finding applies that guidance to the source; it does not infer an unstated project policy. [OWASP authentication guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#changing-a-users-registered-email-address).

### R04-02 — Deletion's stamp check is detached from the destructive write

**Evidence.** [Canonical SQL](sandbox:/workspace/scratch/78b7f387c802/source/treehammock-main/Rigging/Database/Baseline/000_canonical_database.sql), `commit_account_delete_finalize` (line 2494), reads the account without a row lock and checks `account_record.security_stamp`. It then locks/validates the standby row and eventually executes `DELETE FROM accounts ... WHERE account_id = p_accountId`, without a stamp predicate or a check that the account still has the checked generation. `prepare_account_delete_finalize` also leaves its account read unlocked. [AccountRepo.cs](sandbox:/workspace/scratch/78b7f387c802/source/treehammock-main/Repos/AccountRepo.cs), `FinalizeAccountDelete`, does keep prepare and commit in one transaction, but that does not lock the earlier account read.

**Source-derived interleaving.** Deletion A's commit function reads stamp S and validates it. Password reset or logout-all B commits stamp S′ while A retains its standby row lock. A's unconditional delete then removes the account with stamp S′. The destructive operation can therefore finish after the credentials used to authorize it were invalidated. B's reset/logout-all paths do not need the standby lock for their stamp update. This schedule has not been run against PostgreSQL.

**Change.** Make account authorization and deletion atomic: lock and validate the current account using a common account-first order, keep the relevant authority stable until deletion, and make the final delete conditional on the expected state. Require an affected row before recording/returning success. Revalidate live-session authority if immediate in-flight logout revocation is part of the contract. Changing only the controller check does not close the database race.

**Qualification.** With deterministic two-connection synchronization, stop A after its commit-time account read, rotate the stamp in B, resume A, and assert rejection with the account/data intact and no committed success audit. Exercise password reset and logout-all separately. Include the success path and stamp change before prepare. Sequential stale-stamp tests cover neither this race nor its final write.

### R04-03 — Old deletion proof can be combined with a new account generation

**Evidence.** The `delete_standby` schema (SQL line 450) stores account ID, token hash, optional passphrase hash, expiration, verification, and budgets, but no originating account security stamp or trusted-email identity. Request processing checks the caller's current stamp and then stores no such binding. Token verification uses the hash alone. Prepare/commit check the current caller's stamp against the current account, not against the generation that issued the deletion proof. Password reset, logout-all, and email completion do not revoke or remove standby rows.

**Sequential scenario.** Issue and verify deletion token T under S; rotate to S′ or change the registered email; authenticate under S′; finalize with T and S′. The old request remains eligible until token expiry, provided its optional deletion passphrase is satisfied. Verification can also occur after the stamp/email change. The former mailbox's proof can therefore authorize deletion of the changed account when combined with a current valid session.

**Impact boundary.** A token alone still cannot finalize deletion: the endpoint requires current authentication and the optional passphrase remains enforced. This is a missing proof-lifecycle binding, not an anonymous-deletion claim. The newly chosen deletion passphrase is not the current account password.

**Change.** Record the authorization generation on the standby request and enforce it at verification/finalization, or explicitly revoke pending destructive proofs on the relevant account-security changes. Define which ordinary refreshes should preserve a proof and which credential/recovery changes must invalidate it. Make restart/recovery explicit to the user.

**Qualification.** Test deletion tokens across password reset, logout-all, authenticator enrollment stamp rotation, and email change, with a fresh authenticated session. Assert invalidation for the agreed security events and continued eligibility only for approved lifecycle transitions. This is separate from R04-02's in-flight race.

### R04-04 — Email completion locks the request before the account, deletion does the reverse

**Evidence.** `complete_account_email_change` (SQL line 2111) locks its pending request first, then updates the account. The final account delete acquires the account's delete lock and cascades into `account_email_change_requests` through its `ON DELETE CASCADE` foreign key. The standby lock held by the repository does not remove this account/request inversion.

**Source-derived cycle.** Email completion A holds request E and waits to update account U; deletion B holds U and waits to cascade-delete E. PostgreSQL can detect the cycle and abort one transaction. Repository catch/rollback handling produces a generic failure. This is a contention/availability problem; an exception rollback does not commit a partial email change or partial deletion.

**Change.** Use a common account → request/proof order for email change, deletion, and related mutations. Looking up the account ID from a token can be a non-locking locator step, followed by locking/revalidation in the standard order. Review cascade and event writes in the same lock graph. Keep retry bounded and operation-aware after correcting avoidable inversion.

**Qualification.** Reproduce completion versus deletion with two connections and explicit barriers around the relevant locks. Check SQLSTATE `40P01`, final state, retry response, and audit consistency. Extend the shared factor lock-order work in R03-06, because email completion/deletion also touch or cascade into factor rows. [PostgreSQL locking guidance](https://www.postgresql.org/docs/16/explicit-locking.html#LOCKING-DEADLOCKS).

### R04-05 — Delivery failure removes the deletion rate-limit state

**Evidence.** `request_account_delete` (line 2220) stores `requested_count`, `last_requested_at`, and `next_request_allowed_at` in the standby row. [AccountService.cs](sandbox:/workspace/scratch/78b7f387c802/source/treehammock-main/Services/AccountService.cs), `RequestAccountDelete` (line 313), calls `CancelAccountDeleteRequest` when delivery is denied or fails. `cancel_account_delete_request` (line 2348) deletes the complete standby row. The next new request sees no durable cooldown/count.

**Scenario.** Request deletion with one idempotency key; fail or deny delivery; successful cleanup deletes standby; immediately request again with another key. The configured 15-minute SQL cooldown and eight-request/24-hour budget start fresh instead of enforcing continuity. Cache account/destination/IP delivery budgets and provider-failure cooldown still exist; this finding does not claim unrestricted email delivery.

**Change.** Keep rate-limit state independent of cancellable token/proof state, or preserve a durable request-admission tombstone through cleanup/expiry. Decide whether unsuccessful delivery counts as a request and encode that policy consistently. Avoid letting cleanup silently reset the budget. Preserve exact-token cancellation so an older failed send cannot cancel a newer request.

**Qualification.** Simulate denied delivery, provider false/exception, and successful cleanup. Submit fresh idempotency keys immediately and assert that the SQL request budget remains intact. Test cache recovery/eviction too: the durable policy should not depend on a separate cache budget being present.

### R04-06 — Locking an existing standby row does not serialize initial admission

**Evidence.** `request_account_delete` reads the account without `FOR UPDATE`, selects any existing standby row `FOR UPDATE`, checks budgets, and then inserts with `ON CONFLICT (account_id) DO UPDATE` using the precomputed `next_requested_count`. When no row exists, that select locks no row.

**Source-derived schedule.** Two first requests A and B both observe no standby row. Both pass admission with count 1. A inserts/commits; B's insert conflicts and updates A's row with its own token and count 1, without rechecking A's cooldown/count. Both can return pending success and send different tokens, although only the final token survives. The primary key prevents duplicate rows, but does not enforce the advertised admission policy.

**Change.** Serialize admission through a stable account/rate-limit row lock, or an atomic admission statement that evaluates and updates the current budget under the conflict path. Use the common lock order. Preserve the existing row's current count/cooldown when re-evaluating rather than writing a stale computed value.

**Qualification.** Begin with no standby row, start two independent SQL requests behind a barrier, and assert only the admitted request succeeds while the other reports the limit. Verify one delivery, the resulting count, and the surviving token. Then test concurrent replacements of an existing row and cleanup racing admission.

### R04-07 — Expiry does not release an email reservation

**Evidence.** The request table has a unique index on `lower(new_email_address)` covering expired and live rows alike. `request_account_email_change` rejects another account's matching pending address without checking its expiration or stamp validity. Expired rows are removed only by verification of their old token, owner replacement/deletion, or the explicit purge function. A source search finds purge wrappers and tests, but no scheduled production caller in the archive.

**Scenario.** Account A leaves an email-change request unused until it expires. Account B later tries to change to that address. The request still returns `ACCOUNT_ADJUST_DUPLICATE_EMAIL` although no current account owns it and the reservation token is unusable. Without another action or cleanup, the rejection can persist indefinitely. A request whose account stamp has changed can also reserve an address until cleared, even though completion rejects that old proof.

**Change.** Retire unusable reservations safely during admission or through an enforced bounded lifecycle, with uniqueness and concurrency preserved. Make expiration determine eligibility rather than relying only on eventual housekeeping. PostgreSQL cannot use a moving `now()` condition as an ordinary immutable index predicate; an atomic reservation lifecycle is needed. The missing scheduler belongs to the shared retention work under R02-14; this ID records its concrete address-availability consequence and admission predicate.

**Qualification.** Insert expired and stale-generation reservations and attempt a competing account's request. Assert that unusable reservations cannot block a valid claim and that two genuinely live claims still have one winner. Include purge/admission races and verify the winner's token and address association.

### R04-08 — A race around the final email unique index changes the error contract

**Evidence.** `complete_account_email_change` checks whether another account owns the proposed address before updating the account. The unique account-email index is authoritative, but this function has no `unique_violation` handler. The repository catches the resulting exception, rolls back, and returns null; the controller maps null to `ACCOUNT_ADJUST_FAILED`/500. The normal duplicate path returns `ACCOUNT_ADJUST_DUPLICATE_EMAIL`, currently mapped to 400 by the project's adjustment contract.

**Source-derived schedule.** A completion sees the address free; a concurrent signup/account claim B inserts it and commits; A's account update violates uniqueness. Signup's insert does not reserve against `account_email_change_requests`. The database correctly prevents duplicate ownership; the bug is the generic server failure and inconsistent result/recovery behavior.

**Change.** Map the specific relevant unique constraint to the documented duplicate-address result, with a deliberate pending-request cleanup/retry policy. Retain transaction rollback and avoid treating every unique violation as an email conflict. Do not weaken the unique index or introduce an application-only check.

**Qualification.** Pause after A's duplicate lookup, commit B's claim, resume A, and assert the documented conflict response, unchanged A email/stamp/sessions, and consistent request cleanup. Keep the existing sequential already-claimed-address test: it exercises only the earlier check, not index rejection under contention.

### R04-09 — Retrieving a verification link performs the sensitive change

**Evidence.** `VerifyEmailChange` has `[AllowAnonymous]` and `[HttpGet("adjust/email/verify")]`. Its successful GET calls the committing SQL function immediately. The emailed URL points directly to that route. There is no read-only confirmation landing step before address replacement, account-stamp rotation, email-factor removal, and session expiry.

**Impact.** A process that fetches the valid URL for scanning, link checking, or preview can perform the change before the owner deliberately confirms. This is a source-derived risk; no actual mailbox scanner or preview system was tested. It requires possession of the valid opaque link and is not evidence that an arbitrary third party can guess it. Deletion verification GET also changes proof state, but still requires authenticated POST finalization and does not delete on GET.

**Change.** Use GET for a read-only confirmation page/preview and a deliberate POST for consumption and mutation. Preserve the token, authorization-generation, expiry, and replay guards. Protect confirmation pages/tokens from referrer/log/cache leakage as part of R07/R08; disabling response caching alone does not make a mutating GET safe.

**Qualification.** Fetch the emailed link repeatedly without submitting confirmation and assert no account/factor/session change. Then submit an explicit valid confirmation and assert one committed result. Test preview/scanner-like requests and duplicates. RFC 9110 defines GET as safe and explicitly discusses why automated retrieval and prefetching must not trigger unsafe actions. [RFC 9110 §9.2.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.1).

## Positive source findings

- **Ownership:** profile, username change, deletion request, and deletion finalization use the authenticated session's account ID/stamp. Their request DTOs do not expose ownership IDs. Finalization binds the deletion token to that account, so a different account's token is rejected.
- **Profile output:** `AccountProfile` returns email, username, creation time, verification/country/features, and factor summaries. It omits password hashes, salts/nonces, web keys, refresh tokens, and protected TOTP secrets. The repository maps a limited return shape rather than returning its internal account entity.
- **Username write:** SQL normalizes/limits the value, enforces case-insensitive uniqueness, predicates the final write on the supplied stamp, checks `FOUND`, and handles a unique violation. A stale account read therefore does not produce the destructive race seen in deletion.
- **Email completion:** the final account update predicates on the request's recorded account stamp and checks `FOUND`. It rotates that stamp, expires sessions in SQL, and deletes the old verified email factor so it cannot silently follow the new destination. These mutations share a repository transaction.
- **Token handling:** email-change/deletion tokens use cryptographic random generation and hash-only database storage. Lookup parameters are typed. Public token/IP budgets run before verification calls; deletion finalization has cache account/token admission and durable failure/lockout checks.
- **Deletion sequencing:** the repository holds its standby lock across prepare, optional local passphrase verification, and commit. A concurrent token/passphrase replacement cannot normally change the locked standby row between prepare and commit. The finalization success path deletes the account inside the same transaction as its success audit.
- **Data lifecycle:** account-owned authentication/session/factor/activation/proof tables have foreign-key cascades in the baseline. Password-reset events detach their account reference; deletion events intentionally retain the account UUID without a foreign key. Cache removal is best effort after SQL success; authoritative session checks must continue to reject a deleted account even if a cache entry remains.
- **Request validation:** profile adjustment permits exactly one email/username field and caps sizes. Verification/finalization tokens and optional passphrases are bounded. Empty-body deletion is intentional and produces the one-time-email workflow, not immediate account deletion.

These are source observations, not passed tests or evidence of deployed behavior.

## Earlier findings and shared invariants

| Existing ID | R04 extension; no duplicate count |
| --- | --- |
| AUTH-07 / AUTH-08 | Adjustment, deletion request, and deletion finalize inherit shared idempotency reservation/content-binding flaws. A replayed key can also conceal a changed input. |
| AUTH-02 | The inspected account-service/repository operations lack request-cancellation plumbing. A caller timing out does not establish whether the database mutation committed. Preserve this in operation-recovery testing. |
| AUTH-05 | Fresh email-change proof should reuse a repaired, throttled authorization mechanism. |
| R02-02 | Email/deletion request replacement commits before delivery admission. A failed replacement can invalidate a previously delivered token, then remove the replacement on cleanup. Exact-token cleanup protects newer different tokens, but does not restore the previous proof. |
| R02-08 | SQL `now()` is fixed at transaction start. Deletion keeps a transaction open through optional password hashing; both commit-time expiry checks still use that old instant. Long lock waits can also outlive expiry. Include these paths in the authoritative post-wait deadline fix. |
| R02-14 | Neither email/delete purge has a scheduled production caller in the archive. Deletion audit records can grow on every limited request, failed verification, or repeated successful verification; no bounded audit-retention job is present. |
| R02-15 | Optional deletion passphrases use the existing Argon2id codec/cost units. Raising the configured cost must include admission and lock-duration review. |
| R03-02 | Email completion removes verified email factors but retains pending factor setups. Those rows lack their originating account-stamp binding. Reusing pre-change pending factor proof under a fresh session must be covered by the enrollment-generation fix, beyond the original in-flight verification race. |
| R03-06 | Email completion/deletion also contend with factor writes/cascades; include them in the common account-first lock graph. |

`now()` semantics were checked against the primary PostgreSQL documentation. Use actual decision-time checks under the required locks where expiry is meant to be a hard deadline; merely switching an earlier timestamp variable does not make that decision current. [PostgreSQL date/time functions](https://www.postgresql.org/docs/16/functions-datetime.html#FUNCTIONS-DATETIME-CURRENT).

## Performance and recovery observations

No timings, query plans, memory costs, or load limits were measured. The following are concrete implementation costs and qualification tasks, not claimed benchmark results.

1. **Hash before deletion-request admission.** `RequestAccountDelete` hashes a supplied passphrase before its SQL cooldown/window check. A request later rejected by SQL still pays the password-hash cost. Add a cheap bounded admission stage before hashing while retaining authoritative atomic SQL admission. After fixing R02-15, measure this path using the intended stronger cost.
2. **Hash inside a locked deletion transaction.** Prepare holds the standby row lock and a database connection while local passphrase verification runs. This preserves proof consistency, but increases lock duration and pool occupancy. Measure before changing it. If hashing moves outside the transaction, use a version/hash predicate and revalidate every required proof/authority at commit; otherwise a replacement race can be introduced.
3. **Round trips.** Profile reads use an explicit transaction around one SQL function. Finalization has prepare, local hash work, commit-function execution, and transaction commit. Under R06, measure query/round-trip and pool-wait costs rather than optimizing away necessary mutation locks.
4. **Cascades and history.** Deletion cost depends on all account-owned rows, including old sessions, pending proofs, activations, and historical factors. Check foreign-key indexes and delete plans at realistic history sizes. Audit rows remain after account deletion; document the retention policy and measure storage growth. This is not a legal-compliance conclusion.
5. **Request-window semantics.** Deletion's count compares the most recent request time to the window, rather than tracking a separate window-start timestamp. Eight requests spread over more than a day can remain accumulated until a sufficiently long idle period. Decide whether that idle-reset policy is intended before changing it; this review does not assume a fixed-window contract that the project never explicitly defines.
6. **Commit and lost response.** Successful deletion invalidates the account used to authenticate a retry; middleware runs before idempotency replay. Email completion also invalidates old sessions and consumes its token. Define user-visible recovery for lost responses without returning secrets or weakening revocation. The current delete success path does clear the client token, but a response lost before the client sees that header needs a documented outcome path.
7. **Same-field concurrent edits.** Username updates are last-writer-wins for the same account generation. No profile revision/ETag is present. This is a policy choice, not classified as a lost-update bug absent a stronger editing contract. Separate-field accidental overwrite is constrained by the one-field adjustment API.

## Test evidence and missing qualification

| Surface | Inspected test-source evidence | Needed qualification |
| --- | --- | --- |
| `AccountEndpointContractTests` | Adjustment validation, ownership/stamp/status mapping, limited profile, public token errors/throttles, deletion workflows, clear-token header, idempotency entry points | Fresh email-change authorization, no mutation on GET, lost responses, state changes during final mutation |
| `AccountServiceSetupTests` | Hash-only tokens, new-address delivery, exact-token cleanup on false/exception, optional deletion secret, raw passphrase forwarded for local hash verification, purge wrappers | Failed-delivery budget persistence, pre-hash admission, generation-bound pending proof, actual provider/cache fault combinations |
| `RepositoryContractTests` / repo contract tests | Selected SQL-text, function-name, parameter, type, and mapping assertions | Text containing a stamp check/lock does not prove the final destructive write is protected |
| Deferred `BooleanProcedureContractTests` | Selected sequential profile/username/email request-cancel-conflict/purge and deletion request-cooldown-verify-cross-account-passphrase-lockout-finalize-purge assertions | Two-connection R04-02/04/06/08 schedules, expired reservation admission, security-generation invalidation |
| `AccountFlowRegressionTests` | Deletion request → verify → finalize HTTP flow, service/session substitutes and cache removal | This HTTP wiring test substitutes the account service and cannot qualify SQL locking or cascades |
| `SystemStackAccountFlowTests` | Existing deletion flow through HAProxy with delivery capture and future-login rejection assertions | Run the actual stack; add stale-cache, lost-response, generation-change, concurrent claim, and failure-recovery cases |

**All suites above were inspected, not executed.** In the deferred SQL test, direct calls to the commit function pass a trusted boolean for passphrase satisfaction; those calls exercise SQL state, not the repository's actual Argon2id verification. Add repository-level proof checks as well. System coverage exists and must not be described as absent merely because this environment cannot run it.

Suggested qualification order when tools are available:

1. Run the project's standard validation script and the relevant unit/controller/service suites.
2. Use a disposable PostgreSQL database and enable the deferred contract lane. Add deterministic two-connection schedules, with explicit lock barriers rather than flaky delay-based races.
3. Exercise the email/deletion HTTP flows with real SQL and stubbed delivery, including security-stamp changes, old proof reuse, delivery failures, GET previews, and lost responses.
4. Run the existing system stack with PostgreSQL and the Redis-compatible cache. Retain a stale cached session after deletion/email change and prove authoritative rejection on each instance.
5. Measure p50/p95/p99 latency, hashing time, pool and row-lock waits, deadlocks, round trips, provider sends, cascade row counts, and audit growth at realistic account-history sizes. Verify both successful and throttled paths.

## Next chunk

**R05: activation lifecycle and feature/entitlement changes**, including code issuance/delivery, activation timing, duplicate/concurrent use, expiration, feature propagation to sessions/cache, and their SQL/test contracts.

Continue afterward with R06 all repositories/SQL/performance; R07 HTTP/models/hosting/proxies; R08 providers/templates; R09 abuse/telemetry/health/tests; R10 build/dependencies/deployment/CI/docs. Cross-chunk observations do not mark those areas complete.

The bundle contains R01–R04 reports, the cumulative 451-file inventory, the 46-finding ledger, per-chunk structural evidence, the R04 evidence builder, and the original blocked validation record. All reports remain review artifacts; no project source edits or runtime sign-off are included.

Primary references: [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), [PostgreSQL 16 explicit locking](https://www.postgresql.org/docs/16/explicit-locking.html), [PostgreSQL date/time semantics](https://www.postgresql.org/docs/16/functions-datetime.html), and [RFC 9110 HTTP semantics](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.1). External guidance supports the recommendations; it is not evidence of a passed project test.
