# Treehammock review R10I — complete SQL-contract suite inspection

Reviewed 2026-10-03. This chunk completes the full-source review of the three SQL-contract test files left partially inspected in R06. It adds no distinct numbered finding: the observations below strengthen existing correction PR acceptance criteria. The cumulative ledger remains **83 open findings: 18 P1 and 65 P2**. No finding is closed by this source review.

The three files contain **4,865 lines / 251,233 bytes and 19 `[Fact]` methods**. These are source counts, not runtime discovery or passing tests. All 451 project files remain byte-identical to the uploaded archive (SHA256 `229ef2275f1caeff3a6a40186e678f7440a90fd54add2e0ba8de0fd6c645758f`). No application, test or SQL source was changed.

## Scope and evidence

| File under `treehammock.Tests.SqlContracts/Integration/Database/` | Full source lines | Fact methods | Review disposition |
| --- | ---: | ---: | --- |
| `BooleanProcedureContractTests.cs` | 2,936 | 9 | Entire setup, test bodies, assertions, readers and helpers inspected |
| `PasswordResetProcedureContractTests.cs` | 671 | 3 | Entire lifecycle, TOTP and rate-limit tests plus readers inspected |
| `PasswordResetRepositorySqlIntegrationTests.cs` | 1,258 | 7 | Entire actual-repository/service tests, substitutes and storage lifecycle inspected |

The review cross-checked the canonical baseline's reset create/promote/upsert and TOTP function bodies; selected finalize lookup slices; actual `PasswordResetRepo` promotion/upsert mapping and transaction bodies; complete `StorageContext`, SQL opt-in settings, SQL project and original shell runners. Earlier complete-source qualifications for these supporting files remain in place. This chunk does not claim a fresh full read of the entire SQL baseline or all repository methods.

Source references use the original archive's line numbers. `BooleanProcedureContractTests.cs` was read in contiguous ranges 1–240, 241–620, 621–1020, 1021–1440, 1441–1860, 1861–2300, 2301–2700 and 2701–2936. `PasswordResetProcedureContractTests.cs` was read 1–330 and 331–671; the repository suite 1–310, 311–650, 651–970 and 971–1258. The evidence JSON includes SHA256/byte counts and every source test method.

## What the assertions actually cover

The Boolean suite checks real SQL calls when executed, using a GUID-named schema per test and the canonical baseline. Its large first test checks view/credential values, security stamps, session creation/rotation and trust, account lockout, pending two-factor pointers, email-change outcomes, deletion limits, persisted state and audit counts. The remaining tests check cutoff propagation, registration verification, trust statuses, challenge issue compensation, selection snapshots, stamp rotation, logout/revoke and email/SMS setup replacement/replay.

The reset procedure suite checks one active request per account, replacement/cancellation, failed-attempt exhaustion, password/security-stamp/session effects, TOTP step progression and SQL request rate limiting/cleanup. It supplies controlled timestamps to the rate-limit functions, which makes those sequential boundary cases useful.

The repository suite uses actual `PasswordResetRepo`, `SessionRepo`, `PasswordResetTotpRepo`, `PasswordResetSessionService` and selected `PasswordResetService` paths against the isolated SQL schema when executed. It checks actual persisted request/session data and fresh service instances rehydrating SMS/authenticator progress. Readers in the inspected actual repository promotion/upsert bodies explicitly dispose before commit; this supports the distinction already made in R06 between these repositories and the activation reader-lifetime defect.

These suites are stronger than tests that inspect SQL strings alone. However, their inspected calls are sequential. The selected source contains no competing request schedule (`Task.WhenAll`/`Task.Run`), SQL lock barrier or deliberate two-connection race. The repository fixture has a setup connection plus pooled repository connections; the existence of multiple connections does not turn sequential calls into a concurrency reproduction. The separate previously reviewed `SessionConcurrencyProcedureContractTests.cs` is outside the selected scope; this report does not claim the entire project lacks concurrency tests.

## Acceptance refinements for existing corrections

### Reset promotion and actual factor removal — COR13 / COR16

The terminal-reset repository test at lines 733–860 creates a reset, saves a pending session, and promotes the password. Its `SavePendingSession` helper at lines 1075–1098 selects `SMS_AND_AUTHENTICATOR_APP` and starts a challenge. It never records completed SMS/authenticator proof. The test nevertheless expects promotion success and a `PASSWORD_RESET_COMPLETED` revocation reason.

The procedure lifecycle test at lines 10–249 and repository promotion test at lines 30–180 also invoke promotion directly without a completed durable authorization. These are useful transaction/effect checks for the present function, but cannot be retained as security acceptance for the corrected COR13 contract. The canonical `promote_password_reset` at lines 5679–5823 validates the reset and account stamp, then changes password/stamp and terminal state; it accepts no reset access-token hash or expected authorization version and never requires a completed proof record. This is the existing R02-06/COR13 finding, not a newly counted defect.

The same terminal test's method-removal section invokes `revoke_pending_password_reset_sessions_for_account` directly with the text `TWO_FACTOR_METHOD_REMOVED`. It never removes the SMS/authenticator factor or invokes the production factor-removal path. The resulting revocation reason proves this helper's effect if executed; it cannot prove that actual removal invalidates the parent reset authorization, prevents rebootstrap with the old token, or avoids the existing last-factor bypass.

**Required correction:** COR13 must consume the exact completed, current, unexpired durable authorization in the password transaction, including the legitimate no-additional-factor path. Replace incomplete-promotion positives with negative authorization cases. Keep separate completed-proof positives that still assert password material, account stamp, request consumption, old-session denial and exactly one completion event. COR16 must exercise real factor removal and its integration with COR13. Direct revocation-helper tests may remain as narrowly named helper contracts.

**Required schedules:** Pause after the service reads completed authorization, then revoke/expire/replace it before promotion; compete two finalizers; remove the last factor and deny finalize/rebootstrap using the old request/token; submit stale success/failure after a newer challenge; race replacement with promotion using two isolated connections and a bounded barrier. Assert rollback/no partial password, proof progress, budget reset or success audit. A source check that the word `atomic` appears in a test name is not closure.

The reset upsert's conflict branch at lines 5373–5394 overwrites proof/attempt/challenge fields and clears `revoked_at`/`revoked_reason`. Existing R02-04/COR13 owns the stale-writer problem. Keep the useful rehydration assertions, but add competing-version tests that prove terminal revocation and monotonic progress survive stale writers.

### Stamp checks and challenge replacement — COR09 / COR10 / COR16

The test named `Two_factor_pending_and_finalization_require_current_account_security_stamp_and_rotation_clears_pending_pointer` at Boolean lines 2239–2320 seeds an account pointer but never creates an authoritative `pending_two_factor_sessions` row. Its supposed current-stamp case already returns false. A later false result with a wrong/stale stamp therefore does not establish that a real otherwise-valid pending session was rejected because its stamp changed.

Construct the real current pending row using the production begin transition, demonstrate its valid baseline, then mutate the stamp and assert the expected rejection and preserved terminal state. Retain the current account-pointer cleanup assertion. Qualify replaced challenge versus proof/cancel schedules under COR10; add session refresh versus logout/revoke under COR09. The existing sequential trust/cutoff/logout checks should remain.

The setup test at lines 2540–2750 begins SMS twice, checks one pending row and the replacement destination, verifies the correct replacement code and rejects replay. Its “stale method” branch checks email even though the setup calls used SMS. Preserve that not-found case, but add proof with the first SMS code against the replaced SMS setup and the actual cross-method replacement schedule. Coordinate setup verification versus stamp rotation/removal and prove no success response for an unpersisted challenge under COR16.

### Registration/delivery and deletion budgets — COR11 / COR12 / COR18 / COR22

The registration test at lines 1714–1833 explicitly expects both the original verification key and the resend key to remain readable before completion. It proves the current sequential behavior when executed, not an admitted-delivery replacement policy. Update the positive/negative assertions alongside COR11/COR12 so only the intended delivered artifact is usable according to the correction's documented transition. Add actual duplicate signup/resend contention and delivery denied/unavailable/compensation cases. Do not label this source-only evidence as a reproduced resend race.

The Boolean suite contains useful deletion/email durable-state and audit checks. Its expired deletion replacement section at lines 1177–1228 forces an expired row while cooldown is still future, requests replacement, and expects `requested_count == 1`. This encodes present behavior; it is not proof of continuous abuse budgets across terminal-artifact replacement. Cancellation and purge checks likewise mainly assert artifact absence and events. COR18/COR22 must preserve approved request/attempt windows across cancellation, expiry, purge and failed delivery, with independent durable budget state where required. Retain final account absence, old-session trust denial and audit checks.

### TOTP, transport and cache boundaries — COR15 / COR24

The procedure TOTP test at lines 260–361 checks missing then verified enrollment and sequential same/older/newer steps. It does not test each advertised rejection branch: unverified, revoked, expired, wrong provider, missing secret material and cross-account enrollment. The repository test at lines 189–269 verifies ciphertext/nonce/tag byte mapping and one replay. Its deliberately short fixture bytes are mapping data, not evidence that real protection/decryption succeeds.

The service runtime factory at lines 962–1005 substitutes a fixed TOTP verifier, fixed password material factory, in-memory captured delivery and an always-allow abuse counter, with cache-backed reset abuse disabled and raised SQL request ceilings. Consequently the three-runtime rehydration case proves SQL-backed service/session persistence if executed; it does not prove real TOTP verification/replay, password hashing, provider delivery, Redis/Valkey behavior or production abuse budgets. No cache connection is exercised by these selected suites.

Keep these focused fixtures. Add COR15 cases using real encrypted enrollments, immutable persisted algorithm/digits/period, independent vectors, expiry and simultaneous replay. COR24 must qualify the real delivery/crypto/cache adapters and process restart against shared state. The existing system suite can participate once its R10H acceptance refinements are implemented; these substitutes should not be silently described as a full system test.

### SQL schemas, exceptions and clocks — COR02 / COR03 / COR22 / COR24

The duplicate-active-reset assertion at procedure lines 86–104 accepts any `PostgresException`. It checks no SQLSTATE or constraint name, so an unrelated PostgreSQL error could satisfy that local negative assertion. Require the intended unique-constraint result and prove the first request remains intact. Other tests in the same file can still fail independently; this observation does not assert the whole suite will pass on arbitrary SQL breakage.

Status readers generally require a first row and read positional fields, without proving exactly one row or exact result schema/types. The Boolean nullable string helper at lines 2826–2830 returns `result as string`, which turns unexpected non-string values into null. `QueryAccountViewAsync` also defaults optional columns when absent. Add exact schema/cardinality/type checks to the declared SQL contract, reject incorrect nullable field types, and retain explicit zero-row semantics only where the function permits them. This strengthens COR02/COR24 rather than adding a general SQL injection or production mapping finding.

The repository tests use `SearchPathStorageContext`: its override pool is disposed, but its base constructor also creates `_databaseInstance`, which the fixture never uses or disposes. R06 already records this ownership gap under COR03/COR22. A search-path command failure after opening a connection also needs local cleanup before the connection is returned. Own/dispose actual pools and failed-acquisition connections; prove repeated fixture/host lifecycle returns resources to the declared baseline. No connection leak count or performance regression was measured here.

Two repository cases use the fixed instant `1_900_000_000` for future expiration while `create_password_reset_request` uses database `now()` as creation time. They are not clock-independent and will eventually become invalid as the real database date moves beyond the fixed expiry. Obtain a coherent database/app clock baseline or inject time through an intentionally supported fixture seam; do not add a public production clock override. The rate-limit test's explicit timestamps are meaningful because those functions accept their comparison time. Bound requests, lock waits and owned cleanup; preserve original test failure alongside cleanup failure.

## Detailed correction-plan addendum

No new COR23 sub-PR is introduced. The following work extends existing owners; original Word design/PR documents remain unchanged and this addendum travels in the cumulative bundle.

| Owner and dependencies | Concrete file scope | Required implementation/tests | Completion gate |
| --- | --- | --- | --- |
| COR02 / COR24; existing DB contract foundation | Three selected suites; SQL reader helpers; SQL result/constraint manifest | Strict row/type/cardinality and exact named unique violation; compatible baseline/upgrade result schemas | Executed PostgreSQL contracts for each installed function version; unrelated SQL error fails the uniqueness test |
| COR04 / COR13; lock/order and reset transition foundation | Canonical baseline and migration; `PasswordResetRepo`; `PasswordResetService`; selected reset suites; shared SQL barrier fixture | Account-first consistent lock schedule; exact completed authorization/version consumed with password/stamp update; reject incomplete/stale/expired/revoked proof; compete create/promote and two finalizers | One authorized effect; no deadlock-dependent success or stale write; rejection leaves password/session/audit invariant intact |
| COR09 / COR10; session/proof authority foundations | Boolean suite and pending/session repositories/functions | Start genuinely valid pending state before stamp negatives; barrier refresh/logout/revoke and challenge issue/proof/cancel | Durable authority and state determine result; current valid setup passes and stale setup is specifically rejected |
| COR11 / COR12; delivery admission | Registration Boolean test; registration/delivery functions/services and existing delivery fixtures | Align old/new token assertions with admitted delivery; duplicate signup/resend and cancellation/unavailable schedules | User retains the intended valid delivered artifact; no multiple unintended tokens or success on failed state mutation |
| COR13 / COR16; fresh proof and factor policy | Terminal/reset rehydration tests; actual factor removal repository/service/controller; reset SQL | Invoke actual factor removal; reject old finalize and rebootstrap, including last-factor removal; preserve helper-only revocation tests separately | Old proof stays invalid through menu changes and stale writes; legitimate newly authorized reset completes |
| COR15 / COR24; secret/parameter migration | Procedure/repository TOTP tests; production TOTP verifier/protection; existing system fixtures | Negative enrollment matrix, real protection and metadata-aware independent TOTP vectors, simultaneous same-step proof | Real crypto and SQL replay authority agree; mapping fixtures remain clearly scoped |
| COR18 / COR22; durable budgets/retention | Boolean deletion/email tests; deletion/email/cleanup services/functions | Continuity across cancel/expiry/purge/delivery failure; exact expiry and bounded retention; representative query/load evidence | Artifact cleanup never resets forbidden budgets; declared work/latency/storage limits are measured |
| COR03 / COR22 / COR24; owned resources and qualification | `StorageContext`; SQL fixture subclass/helpers; owned runner lifecycle | Dispose actual/base pools, close failed search-path connection, coherent time and bounded work/cleanup | Repeated runs return owned resources to baseline; no fixed-future expiration dependency |

Each implementation PR must enable its domain regression cases in the appropriate mandatory lane when its fix lands. Keep negative reproductions isolated before a production fix rather than deliberately breaking default CI. Runtime manifests must record discovered/executed tests, SDK/database/cache versions, fresh versus upgraded schema, run ownership and actual outcomes. Existing source names/counts cannot fill those fields.

## Validation and remaining review

The evidence builder passed archive/source parity for all 451 files, selected metadata/catalog checks and **19 source observations**. These checks reproduce the report's source claims; they do not compile C#, execute SQL or establish concurrency/performance results.

Original runner attempts:

| Original command | Outcome |
| --- | --- |
| `bash eng/sql-contracts.sh --configuration Release --locked-restore` | Exit 2: real SQL opt-in/database prerequisites are not configured |
| `bash eng/docker-sql-contracts.sh` | Exit 1: no reachable Docker CLI, before Compose startup |

No synthetic opt-in or database credential was supplied to bypass prerequisites. Tool availability separately confirms .NET SDK, Docker, PowerShell, PostgreSQL and Redis executables are absent. No restore/build/test discovery, HTTP request, PostgreSQL/cache execution, concurrency reproduction or benchmark occurred. Source review completion remains separate from runtime qualification.

All three earlier R06 partial SQL suites are now fully source-reviewed. **13 R10-assigned files remain**: README; release/API/password-reset feature matrices; SQL-contract matrix; test guide and large HTML inventory; Grafana dashboard; Bruno collection/environments; CityHash configuration/binary qualification. Next chunk R10J addresses the documentation and test-inventory claims, followed by configuration/binary scope and global per-file evidence reconciliation.

Those 13 paths are not the project's global outstanding count. Older R01–R05 legacy “pending full-file review” dispositions and indexed/slice-only tests still need explicit reconciliation against their actual evidence. None should be upgraded merely because the file was named in a search result. The full review and runtime/performance release gates remain open.

Companion artifacts: `Treehammock_Review_10I_Static_Evidence.json`, `Treehammock_Review_10I_Validation_Attempt.txt`, `build_review_10i_evidence.py`, `Treehammock_Review_Ledger_Through_10I.json` and `Treehammock_File_Review_Inventory_Through_10I.csv`.
