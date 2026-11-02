# Treehammock review 05 — Activation lifecycle and entitlement boundaries

Reviewed 2026-10-03. Review only; no application source changed.

## Result and qualification

This chunk adds **six P2 findings**, bringing the cumulative ledger to **52 open findings: 16 P1 and 36 P2**. The most consequential defects are the unconditional activation-consumption update and the disable path excluding the verified state. These affect lifecycle correctness today; this review does not claim that they currently grant paid features or cause a financial loss.

The current implementation provides an authenticated email-code workflow. It does **not** implement an authoritative entitlement change: verification updates an activation row and returns its requested feature set, without changing account features, database session features, or cached session features. The intended relationship between activations and entitlements must therefore be defined before this area can be qualified as a complete feature-management system. That product boundary is recorded separately from the six confirmed source defects.

The .NET SDK, Docker, PostgreSQL client/server, and Redis server are unavailable in this workspace. No build, .NET test, database concurrency reproduction, real provider delivery, cache/system suite, or performance benchmark ran. Findings are based on inspected source and source-derived schedules. The evidence builder checks structural facts, matching SQL functions in both baselines, and source integrity; it is not a substitute for runtime validation.

Source: the uploaded `treehammock-main.zip`, SHA-256 `229ef2275f1caeff3a6a40186e678f7440a90fd54add2e0ba8de0fd6c645758f`. All **451 source files** are compared byte-for-byte by hash against the upload, with the exact file set checked. These statements describe the supplied project, not a running deployment.

## Scope and evidence map

All 12 files assigned to R05 received a source pass. Cross-cutting repository, SQL, enum, delivery, session, documentation, and test slices were inspected without claiming those future chunks are complete.

| Surface | Inspection |
|---|---|
| `Controllers/ActivationsController.cs` | All routes, authentication context, validation, idempotency, response construction, and code/status mappings |
| `Services/ActivationService.cs` | Creation, random code, term calculation, delivery admission/cleanup, verification budgets, and disable orchestration |
| `Services/ActivationAbuseProtectionServices.cs` | Account keys and normalized email/IP fingerprints |
| `Repos/ActivationRepo.cs` | All four function calls, parameter types, transaction/error paths, result decoding, and log scopes |
| `Models/Activation/*.cs`, activation DTOs/entity/status enum | Complete source contract |
| Both canonical SQL baselines | Activation table/index and `place_activation`, `cancel_activation_request`, `disable_activation`, `verify_activation`; credential/session/profile feature-read slices |
| `FeatureSet` and `ApplicationLayer` enums | Tier, term, and repeat definitions |
| Delivery policy and configuration | Shared admission service, activation verify defaults, delivery limits, local HAProxy request path |
| Existing tests | Activation API/source contracts, service tests, SQL contract test, selected delivery denial and HTTP regression tests; inspected, never executed |

Primary source links: [ActivationsController.cs](sandbox:/workspace/scratch/78b7f387c802/source/treehammock-main/Controllers/ActivationsController.cs), [ActivationService.cs](sandbox:/workspace/scratch/78b7f387c802/source/treehammock-main/Services/ActivationService.cs), [ActivationRepo.cs](sandbox:/workspace/scratch/78b7f387c802/source/treehammock-main/Repos/ActivationRepo.cs), [000_canonical_database.sql](sandbox:/workspace/scratch/78b7f387c802/source/treehammock-main/Rigging/Database/Baseline/000_canonical_database.sql).

## Current behavior

| Operation | Preconditions and durable effect | Cache/provider effect |
|---|---|---|
| POST `/activations/place` | Authenticated session; required idempotency key; bounded email and defined tier/term/repeat; SQL checks account stamp and current account email; inserts an independent status-3 row with raw backend-generated code | Delivery admission occurs after SQL commit. Email sends the code. A denied/failed delivery attempts another transaction to mark that exact pending code status 5 |
| POST `/activations/verify` | Authenticated session; bounded email/code; SQL checks current stamp/email, reads a status-1/3 row, then sets status 4 by activation ID and returns tier/expiration/term/repeat | Account, email, and IP verification counters checked before SQL; reset on success. No endpoint idempotency reservation, feature update, or session/cache feature refresh |
| POST `/activations/disable` | Authenticated session; required idempotency key; SQL checks current stamp/email and disrupts current status-1/3 rows for the account | No provider call; no account/session feature or cache mutation |

Statuses are `REQUEST=1`, `PENDING=3`, `WENT_THRU=4`, `DISRUPTED=5`. The verification response returns the term **enum value**, not an elapsed-day count; `recycle` is stored/read internally but absent from the HTTP details response. Disable targets all qualifying rows for the authenticated account, not a caller-supplied activation ID.

## New findings

P1 means high priority; P2 means medium priority. No new P1 is assigned because the supplied activation flow does not itself apply entitlements. The following source defects are independently actionable.

| ID | Priority | Finding |
|---|---|---|
| R05-01 | P2 | Activation verification can succeed twice or overwrite a concurrent cancellation/disable. |
| R05-02 | P2 | Disable never revokes an already verified activation. |
| R05-03 | P2 | Activation mutations can commit after the checked account security stamp changes. |
| R05-04 | P2 | Service expiration calculations disagree with the stored calendar term. |
| R05-05 | P2 | Delivery-denied creation still inserts retained activation rows without a request admission budget. |
| R05-06 | P2 | Activation delivery admission failures lose their reason and return generic HTTP 500. |

### R05-01 — Consumption does not guard the selected state

**Evidence.** `verify_activation` selects the row at SQL lines 6154–6173 with `status in (1, 3)`, but does not lock it. Its update at 6209–6211 is only:

```sql
update activations a
   set status = 4
 where a.activation_id = v_activation_id;
```

It does not repeat the accepted status, expiration, or other admission conditions, and does not check `FOUND`/affected rows before returning `ACTIVATION_VERIFIED`. `cancel_activation_request` and `disable_activation` mutate that same row. SQL documentation in the project explicitly requires replay to be blocked or yield an already-finalized/missing result.

**Source-derived duplicate schedule.** A and B both read pending row X. A updates X to 4 and commits. B's update by ID still matches X and also returns success. An ordinary sequential retry sees status 4 and fails; that does not prove concurrent single-use behavior.

**Source-derived disable schedule.** A reads X while it is pending, using the earlier request time. B disables X, changes it to status 5, clamps its expiration, and commits. A's unconditional update changes X back to 4 and returns the earlier selected expiration and feature set. Failed-delivery cancellation can lose the same race when the code is otherwise known. The issue is a violated state transition; a cache front brake cannot make the SQL consumption atomic.

At ordinary Read Committed isolation, PostgreSQL reevaluates the **actual update predicate** after a concurrent update. Here that predicate is only the activation ID, so it cannot reject the changed status. This schedule is an inference from source and database semantics, not an executed reproduction. See the primary [PostgreSQL transaction-isolation documentation](https://www.postgresql.org/docs/16/transaction-iso.html).

**Correction direction.** Serialize the account boundary first, then either lock and validate the activation or perform a conditional transition with `UPDATE ... RETURNING`. Include accepted status and authoritative time in the transition and return success only for the row actually consumed. Do not simply add a late activation lock while ignoring account-lock ordering.

**Validation needed.** Two-connection tests with barriers around selection/mutation: verify/verify returns at most one success; verify/disable preserves a valid serial outcome; verify/cancel never resurrects a disrupted row. A test-only locking/barrier harness can force the interleaving without timing-dependent sleeps. No production race-test hooks were added in this review.

### R05-02 — Verified rows cannot be disabled

**Evidence.** Verification writes `WENT_THRU=4`. Both current and expired branches of `disable_activation` filter `status in (1, 3)` at 6064, 6076, and 6083. Status 4 is absent. `ActivationService.DisableActivation` passes status 5; it does not provide a second path for a verified row.

**Trigger and result.** Place and successfully verify an unexpired activation. Then disable with the correct account stamp and email. If no other eligible pending/request row exists, the function returns `ACTIVATION_NOT_FOUND`; the verified row remains status 4 with its prior expiration. If another pending row exists, disabling that row can return success while the verified row remains untouched.

**Impact.** The advertised disable/unsubscribe surface cannot revoke the normal completed lifecycle state. This is distinct from R05-01: it fails without concurrency. There is no supplied downstream entitlement consumer whose continued access can be measured, so this finding does not assert a current paid-access bypass.

**Correction direction.** Define whether status 4 means an active grant, a consumed receipt, or a handoff to another system. If active, disable must transition it and revoke any authoritative grant. If a receipt, provide an explicit grant-revocation path and name/document disable as cancellation of pending requests. Update the response contract so callers can tell what was actually revoked.

**Validation needed.** Sequential place → verify → disable, mixed pending/verified rows, repeated disable, and expired verified rows. Assert row states and effective permissions, not only an HTTP success code.

### R05-03 — Stamp checks are separate from the mutation

**Evidence.** All four activation functions perform unlocked `exists` account checks before inserting/updating activations. There is no account `FOR UPDATE/SHARE` lock or final mutation predicate that serializes with stamp rotation. `ActivationRepo` begins an ordinary transaction without explicitly selecting stronger isolation. Its functions validate a stale stamp presented at entry, but do not preserve that condition through the write.

**Source-derived schedule.** A passes the last account-stamp/email check with S. B resets the password, changes the email, or logs out all sessions and commits S′. A then inserts, consumes, cancels, or disables activation state using its previously accepted S. The functions can report success after the account boundary changed. The activation foreign key only establishes account existence; it is not a check that the security stamp is still S.

**Impact and limits.** An in-flight request can cross the intended account-wide invalidation boundary. This is an activation-specific mutation defect; it does not imply that an arbitrary account can be selected by the caller, or that a newly arriving stale session passes middleware. The source rejects the wrong account email and a sequentially stale stamp. These checks need to be atomic with the mutation.

**Correction direction.** Acquire the account row in a mode that conflicts with stamp updates, validate stamp/email under that lock, and follow a common account → activation lock order. Keep the validation and mutation in one transaction. If using serializable isolation instead, define bounded whole-operation retries and external-delivery behavior before adopting it.

**Validation needed.** A barrier-driven stamp rotation between the last check and activation write must produce a legitimate serial outcome. Cover email rotation and logout-all as well as reset, plus delete-versus-activation lock ordering. Existing sequential stale-stamp tests do not exercise this condition.

### R05-04 — The stored term and effective expiration disagree

**Evidence.** `ActivationService.ResolveCloseOff` at 295–308 converts monthly terms to **31 days**, quarterly to 91, half-year to 182, three-quarter-year to 273, year to 365, and indefinite to 36,500 days. `place_activation` at 5930–5942 stores calendar intervals of one/three/six/nine months, one year, or 100 years respectively. The supplied `p_closeOff` becomes `off_at`; SQL never reconciles it with the stored term. Verification and disable use `off_at`.

**Concrete mismatch.** For a monthly activation created at `2026-02-01T00:00:00Z`, the service's 31-day expiration is `2026-03-04T00:00:00Z`; the stored one-month term ends March 1 in UTC. A yearly activation beginning on `2024-01-01T00:00:00Z` expires on December 31 under a 365-day calculation rather than January 1, 2025 under a one-year term. These examples are calendar arithmetic observations, not a run of the C# service or PostgreSQL.

**Impact.** Clients and future entitlement consumers cannot derive one consistent expiration from the persisted term. Calendar billing/retention interpretations can differ by days. `MONTHFIRST` and `MONTHLAST` are also treated exactly like `MONTHLY`; their names alone are insufficient to define the intended boundary policy.

**Correction direction.** Choose one contract: fixed elapsed-day products with matching stored durations, or calendar terms using an explicit calendar/time-zone policy and one authoritative calculation. Define first/last-month behavior and the meaning of indefinite separately. Noda Time distinguishes elapsed `Duration` from calendar `Period`; see its [core-concepts documentation](https://www.nodatime.org/3.3.x/userguide/concepts).

**Validation needed.** Table-driven service + real SQL checks for February, leap years, month ends, quarter lengths, and any chosen time-zone/DST policy. Compare stored term, returned off time, and actual eligibility at the boundary. This differs from the earlier decision-time expiration finding R02-08.

### R05-05 — Denied delivery still grows durable activation state

**Evidence.** Creation commits `_activationRepo.PlaceActivation` at service lines 108–131 before delivery admission at 133/321–329. SQL inserts a new row for each generated code; its only activation secondary index is the global unique code index. There is no per-account creation cooldown, request budget, pending-row cap, or replacement policy. Cancellation changes status and clamps expiration; it **retains** the row. Activation verification limits apply only to verify. Required idempotency keys prevent reuse of a key from being a normal fresh mutation, but an authenticated caller can use distinct valid keys.

**Trigger.** Use a valid current session, matching account email, and distinct valid idempotency keys. After the configured delivery budget is exhausted, each additional place call still inserts a pending row, checks delivery admission, and normally marks that row disrupted in a second transaction. The email provider is suppressed; database writes and retained rows continue. A provider cooldown or cache-store admission failure has the same ordering. No live request/load loop ran.

**Impact.** Delivery rate limiting does not bound activation creation writes, retained storage, or connection use. The supplied schema has no account/status index for the bulk account disable scan or account deletion cascade. As rows accumulate, these paths have an avoidable scan risk. This is a source/index-shape risk; no actual execution plan, latency, throughput, or storage growth measurement is claimed.

**Correction direction.** Introduce an explicit creation admission policy before durable insertion, plus a transactionally enforced account-level bound to protect multiple instances. Define pending request replacement/multiplicity. Bound retention of terminal rows and keep any required audit history separately. Evaluate an index beginning with account ID, with status/time columns or a suitable partial predicate based on real query plans; do not add an index solely from an unmeasured guess.

**Validation needed.** After the creation budget is exhausted, fresh keys must not cause an unbounded sequence of new rows. Test across multiple app instances, with provider and cache failures, and verify atomic limits under concurrency. On realistic data, capture `EXPLAIN (ANALYZE, BUFFERS)` for disable, account cascade, and retention operations and measure database round trips before/after admission changes.

**Deduplication.** R02-14 already records unscheduled cleanup/retention concerns. This new finding is specifically the absence of activation **creation admission before durable writes**, including the accumulating denial path; missing retention is supporting impact/remediation, not another new finding. Unlike the earlier token-replacement finding R02-02, a new activation does not invalidate a previously issued activation code by replacing its row.

### R05-06 — Admission reasons are converted to delivery failure and HTTP 500

**Evidence.** `TrySendActivationCode` obtains an `AbuseDecision` but returns only `false` when denied at 325–329. Creation then returns `ACTIVATION_EMAIL_DELIVERY_FAILED` after successful cancellation, or `ACTIVATION_CLEANUP_FAILED`. The controller maps both to 500 at 440. It never receives the original delivery throttle/cache-unavailable reason or retry delay. This happens before any provider send, so it is not evidence of an SMTP failure.

**Trigger and result.** Exhaust an email delivery budget and call place. The shared delivery service can return `DELIVERY_THROTTLE_EXCEEDED`, but activation returns a delivery-failed server error. A cache-store unavailable/timeout admission decision similarly loses its distinction instead of reaching the existing 503 mappings. A true provider failure is collapsed into the same branch.

**Impact.** Clients cannot distinguish expected throttling from temporary infrastructure trouble or delivery failure, and may repeatedly retry with fresh keys while R05-05 grows durable state. Operational server-error rates become misleading. The existing selected delivery-denial unit test asserts `EmailDeliveryFailedCode`, so it currently codifies this conversion rather than detecting it.

**Correction direction.** Return a typed delivery outcome containing the admission reason and retry information. Map ordinary admission denial to the documented throttle contract, cache admission unavailability to 503, and actual provider failure separately. Preserve an explicit cleanup-failed result when compensation genuinely fails. Changing only the controller mapping cannot recover a reason already discarded in the service.

**Validation needed.** Service/controller cases for account/destination/IP throttle, provider cooldown, cache unavailable/timeout, SMTP false/exception, and failed compensation. Verify reason/status/retry metadata and whether state was created; do not infer provider failure from a denied send.

## Entitlement and policy boundaries — unresolved, not counted as new defects

### Feature updates are absent

Verification's only success write is status 4 on `activations`. Searches across the supplied SQL and C# found no activation trigger, worker, outbound entitlement handoff, or code that applies `activations.feature_set` to `accounts.features` or `sessions.features`. Neither the activation service nor controller receives an active-session cache service. Profile reads `account_record.features`; password login reads account features; session loading and cache reconstruction copy the database session's features. These are existing independent values, not values recalculated from successful activations.

Consequently, a response with `featureSet=premium` means the code workflow returned its stored request, not that the authenticated account or its session acquired premium permissions. If these endpoints are deliberately just a code/receipt workflow, document that explicitly. If they are meant to activate product entitlements, the integration is missing and must be designed. This review does not manufacture a billing, provider, or grant policy that the project does not state.

Before applying features, the server also needs an authorization rule. `featureSet`, term, and recycle are selected by the ordinary authenticated caller; current validation checks enum membership, not payment, administrator/provider authority, eligible upgrades, or a signed grant. SQL limits delivery to the current account email, which proves a destination relationship but does not authorize a particular product tier. Automatically copying the returned tier into account features would expose every defined tier to self-selection under the existing API.

A complete entitlement contract needs a trusted grant source, precedence/overlap rules, effective start/end, renewal/repeat meaning, revocation, and a cache/session invalidation or version strategy. Test that profile, login, existing database sessions, refreshed tokens, and cache-hit authentication agree after upgrade, downgrade, disable, and expiry. Existing account-stamp trust checks do not by themselves define an entitlement version change.

### Other decisions retained for later review

| Boundary | Observed fact | Decision/check needed |
|---|---|---|
| Pending proof lineage | Activation rows have no originating stamp or issuing email; verification checks the account's current stamp/current email | Decide whether codes issued before reset/logout-all/email rotation remain usable with a new valid session; if not, bind origin or revoke rows on rotation |
| Repeat/start scheduling | Repeat is stored and read, but no renewal implementation was found; HTTP creation always supplies null delayed start | Define whether these are metadata or executable lifecycle promises; do not claim renewal is implemented merely because the enum is valid |
| Start of term | `off_at` is calculated when place is invoked, before delivery and verification | Decide whether request, delivery, verified redemption, or a trusted grant start begins the term |
| Lost verify response | Successful verify consumes status 3 → 4; later sequential retry returns missing rather than restoring details; no verify idempotency receipt | Define safe recovery for a lost success response; retain single-use protection and do not blindly make replays successful |
| Shared IP counters | Success resets the activation IP budget as well as account/email budgets | Review cross-account abuse-budget semantics in R09; resetting a shared aggregate is different from resetting a challenge-local counter |
| Raw activation codes | Backend random code is persisted as text, including terminal rows; project SQL documentation expressly permits user-facing activation codes | Define whether a hashed verifier can serve the protocol and how terminal proof material is retained; no new secret-storage finding assigned solely against that explicit contract |

`delayed_start` is not consulted by verification, but the HTTP service always writes null; this is not reported as a current public-API start-date bypass. SQL's `p_upperLimit` only checks for a zero limit and then returns at most one row; the supplied service always calls position 0/limit 1, so generalized pagination semantics are not a new current endpoint finding.

## Properties that held in the inspected source

- All three activation routes are authenticated POST endpoints. Account ID/stamp come from the authenticated context, not from a client-supplied account ID.
- SQL confines code lookup and disable to that account and requires the supplied email to match its current email. A code for a different account is not accepted by the inspected predicate.
- The backend generates 18 random bytes and uses URL-safe Base64, yielding a 24-character code with 144 random bits. Clients cannot provide a creation code. Guessing risk is additionally front-braked by configured account/email/IP verification counters.
- Controller and service reject undefined tier/term/repeat values; SQL additionally rejects undefined term/repeat ranges. Email and code inputs are trimmed and bounded. Values are bound as SQL parameters, including `TimestampTz` for instants and `Smallint` for enums.
- Failed provider delivery normally compensates only the exact pending account/code; it does not cancel an unrelated replacement code by account ID alone.
- Sequentially stale account stamps return an explicit authentication result. Expired pending rows and wrong codes have distinct controlled outcomes. These contracts do not establish concurrency safety.
- Normal sequential verification consumes the pending code, and subsequent sequential lookup excludes status 4. The defect is the missing atomic transition under concurrency, not total absence of consumption.
- Delivery admission receives the account ID, unlike the setup delivery omission recorded in R03-08. Provider sends are suppressed when delivery admission is denied.
- Tier/expiry details are returned only after successful repository verification. Creation responses and idempotency replay bodies do not expose the emailed activation code.

## Existing test evidence and gaps

| Test source | What the inspected assertions cover | What they do not establish |
|---|---|---|
| `ActivationApiContractTests.cs` | Source strings for POST/API shape, generated-code contract, status mappings, duration validation, bounded inputs | Actual HTTP auth enforcement, real SQL outcomes, concurrency, entitlement changes |
| `ActivationServiceTests.cs` | Mock repository code persistence/email, failed delivery compensation, code details, stale stamp mapping, expired/wrong code mapping, safe abuse keys, denial before verify repository, success counter reset, invalid duration rejection | Real account/code ownership predicates, SQL single-use, verify/disable lifecycle, calendar agreement, multi-instance creation limits |
| `ActivationProcedureContractTests.cs` | Declared real database test seeds an account, places a pending code, rejects sequential stale stamp/invalid duration, wrong code, and expired pending code | It contains no successful real SQL verification, disable/cancel success, concurrent interleaving, or post-activation account/session feature assertion |
| Selected `DeliveryAbuseThrottleApplicationTests.cs` | Mock denial suppresses SMTP and returns `EmailDeliveryFailedCode` | Correct reason/status mapping or bounded durable denial-path writes |
| Selected `AccountFlowRegressionTests.cs` | HTTP place/verify wiring with substituted activation/session repositories and captured email code | Real database transition, real Redis trust, revocation, or changed features |
| Selected `RepositoryContractTests.cs` | Repository source has explicit result/code decoding | Real parameter transport, transaction execution, or the underlying invariants |

None of these tests ran here. The absence of an assertion in these selected tests does not imply no other test in the repository can exercise related code; the evidence catalog and inventory specify inspected boundaries. No full project test or runtime qualification is asserted.

## Earlier findings extended, without duplicate IDs

| Existing ID | R05 connection |
|---|---|
| AUTH-02 | Activation repository methods also omit cancellation-token propagation; abandonment/timeouts do not settle the eventual durable outcome |
| AUTH-06 | Activation verification and delivery use the shared abuse-counter implementation; its increment/initial-expiry atomicity issue remains relevant |
| AUTH-07 / AUTH-08 | Required place/disable idempotency uses the same ownership-completion race and lacks request-body binding |
| R02-08 | Verify selects against a service-supplied moment before cache checks/database work and does not recheck actual wall-clock expiration in its final update |
| R02-14 | Activation terminal-row retention adds another maintenance concern; R05-05 separately identifies the write-admission flaw |

The activation flow inserts independent code rows, so it does not reproduce R02-02's replacement of an already delivered token. Old-stamp proof lineage is a policy boundary above; it was not added to the new-finding count as a speculative duplicate of prior proof-lifecycle concerns.

## Correction order and runtime qualification

1. Define verified versus active versus receipt states and the entitlement authority. Correct atomic verification, account serialization, and disable behavior together with a consistent lock order (R05-01–03).
2. Add creation admission and typed delivery outcomes, keeping compensation and external side effects explicit (R05-05–06).
3. Unify time/term semantics and document start, repeat, and first/last-month behavior (R05-04).
4. Run existing tests in a .NET/PostgreSQL/cache environment, then add the invariant/concurrency cases listed above. Capture query plans and connection/provider/cache timings on a realistic workload. No performance target is assumed without measurement.

The runtime pass should check account/stamp/email ownership, single consumption, disable after verification, invalidation interleavings, storage bounds under delivery denial, reason/status mapping, calendar boundaries, and entitlement agreement if a grant system is intended. Tests should assert resulting durable state and effective permission, not mirror implementation strings.

## Cumulative review status and next chunk

| Chunk | Source review | Runtime qualification | Open findings |
|---|---|---|---|
| R01 Authentication/sessions | Recorded | Pending | 12: 5 P1, 7 P2 |
| R02 Registration/reset/recovery | Recorded | Pending | 15: 6 P1, 9 P2 |
| R03 2FA/TOTP/sensitive actions | Recorded | Pending | 10: 3 P1, 7 P2 |
| R04 Profile/email/delete | Recorded | Pending | 9: 2 P1, 7 P2 |
| R05 Activation/entitlement boundaries | Recorded | Pending | 6: 0 P1, 6 P2 |
| R06–R10 | Still pending; selected cross-cutting slices only | Pending | Not yet assessed |

**Next: R06 — remaining repositories and PostgreSQL correctness/performance.** Focus on function/repository contract alignment, transaction/reader lifetimes, concurrency and lock order, indexes/query plans, connection use, error typing, cleanup/retention, and database constraints. Keep earlier root causes under their original IDs when they recur.

The cumulative bundle contains the five reports, the latest inventory/ledger, source evidence files, the original blocked validation record, and this chunk's reproducible evidence builder. It contains no application fixes or copy of the source archive. Reports use local source links while that source remains available; the bundle retains paths, line anchors, and structural evidence for later review.
