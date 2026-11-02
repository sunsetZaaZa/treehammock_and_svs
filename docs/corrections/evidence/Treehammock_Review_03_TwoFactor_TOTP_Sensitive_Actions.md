# Treehammock review 03 — Two-factor enrollment, TOTP, and sensitive actions

Reviewed 2026-10-03. Source: `treehammock-main.zip`, SHA-256 `229ef2275f1caeff3a6a40186e678f7440a90fd54add2e0ba8de0fd6c645758f`.

## Result and limits

This chunk adds **10 open findings: 3 P1 and 7 P2**. Together with R01 and R02, the ledger contains **37 open findings: 14 P1 and 23 P2**. P1 means address before production security qualification; P2 means a concrete correctness, reliability, or operational weakness to address in the review backlog. These priorities are review judgments, not measured exploit severity scores.

The strongest implementation is authenticator setup completion: one PostgreSQL transaction locks the account, old session, and pending enrollment; verifies their relationships; records the accepted TOTP step; rotates the account security stamp; expires existing sessions; and inserts the replacement session. Email/SMS enrollment lacks equivalent authorization and locking discipline.

This is a **source review, not a runtime security sign-off**. The environment has no `dotnet`, Docker, PostgreSQL/`psql`, or Redis server. No build, .NET suite, real SQL concurrency reproduction, HTTP test, or performance benchmark was executed. The earlier validation attempt remains blocked by `dotnet: command not found`. The evidence script checks source structure and archive integrity only. All 451 source files remain unchanged.

Production flows reviewed here include email/SMS setup and verification, authenticator setup/verification/cancellation, local TOTP verification for login, shared replay marking with password reset, method removal, and password reauthentication/sensitive-action grants. The R03 inventory assigns 28 files to this area; additional controller, repository, SQL, configuration, delivery, and test slices cross chunk boundaries. Assignment is a scope map, not an approval of a file. The CSV records what was actually inspected. Other controller methods, complete SQL tuning, providers, deployment, and whole-suite quality remain in their scheduled chunks.

## New findings

| ID | Priority | Finding |
| --- | --- | --- |
| R03-01 | P1 | Email/SMS factor enrollment trusts the active session without fresh sensitive-action proof. |
| R03-02 | P1 | Email/SMS verification can persist a factor after the account security stamp changes. |
| R03-03 | P1 | Default configuration ships a published TOTP encryption key that passes startup validation. |
| R03-04 | P2 | TOTP encryption has no key identifier or supported rotation path for existing enrollments. |
| R03-05 | P2 | Existing TOTP enrollments depend on mutable global algorithm, digits, and period settings. |
| R03-06 | P2 | Email/SMS verification and account-first factor mutations acquire locks in opposite orders. |
| R03-07 | P2 | Concurrent setup replacement can return success and deliver a code that was never persisted. |
| R03-08 | P2 | Setup delivery omits the account ID and bypasses the per-account delivery budget. |
| R03-09 | P2 | A TOTP enrollment lookup outage is charged as an invalid login proof. |
| R03-10 | P2 | Replacing pending authenticator setup with email/SMS retains abandoned TOTP secret material. |

### R03-01 — Fresh proof is missing on the email/SMS enrollment path

**Evidence.** [AccountTwoFactorController.cs](sandbox:/workspace/scratch/78b7f387c802/source/treehammock-main/Controllers/AccountTwoFactorController.cs), `SetupTwoFactorMethod` (line 379), authenticates and requires idempotency, then persists a challenge and sends it. It never calls `ValidateSensitiveActionToken`. Verification likewise requires the session and delivered code. By comparison, `StartAuthenticatorAppSetup` consumes a sensitive-action grant, and method removal consumes a purpose-specific removal grant. [SensitiveActionPurpose.cs](sandbox:/workspace/scratch/78b7f387c802/source/treehammock-main/RiggingSupport/Enum/SensitiveActionPurpose.cs) defines no email/SMS enrollment purpose.

**Failure scenario.** Someone holding a stolen active session can begin SMS enrollment with a phone they control and submit its delivered code, without knowing the account password or proving possession of an existing factor. When no SMS factor is already verified, the single-factor index does not prevent this. `resolve_available_twofactor_configurations` exposes standalone SMS when it is verified, including alongside an existing authenticator. This grants the attacker a factor under their control; it does not by itself prove that password login can be bypassed. Email setup is correctly bound to the account email, so the attacker-controlled-destination scenario specifically concerns SMS.

**Change.** Apply a consistent fresh-proof policy to factor addition. Require a purpose-bound grant before creating or replacing a pending enrollment; where an existing factor is configured, define and enforce the required existing-factor proof. An idempotency key is not a proof of identity. Keep first-factor enrollment usable with an explicit password reauthentication policy.

**Qualification.** Add HTTP tests proving that a valid session alone cannot enroll SMS, the wrong-purpose grant is rejected, and an approved grant plus destination proof can enroll. Include the existing-authenticator/add-SMS case. OWASP's factor-change guidance advises existing-factor reauthentication and warns against relying solely on an active session; this finding is the review's application of that guidance to this code, not a claim that the project currently promises that policy. [OWASP MFA guidance](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html#changing-mfa-factors).

### R03-02 — The security-stamp check does not guard the final factor write

**Evidence.** [Canonical SQL](sandbox:/workspace/scratch/78b7f387c802/source/treehammock-main/Rigging/Database/Baseline/000_canonical_database.sql), `verify_twofactor_setup` (line 3691), reads the account without `FOR UPDATE`, checks the supplied stamp, then locks the pending factor and sets `verified = true`. Its later `UPDATE accounts ... WHERE security_stamp = p_accountSecurityStamp` does not check the affected-row count. The function still returns `TWO_FACTOR_SETUP_VERIFIED`. The factor table has no enrollment-account-stamp field that makes the first update conditional on the current stamp.

**Source-derived interleaving, not an executed reproduction:** request A reads stamp S; password reset B commits stamp S′; A verifies its pending factor and writes `verified = true`; A's account update affects zero rows, but the function returns success and the repository commits. `promote_password_reset` changes the account stamp and session cutoffs without deleting pending factor-enrollment rows, so it supplies a concrete stamp-changing counterpart.

**Impact.** An enrollment authorized under invalidated account credentials can become durable after reset. The account's factor summary can also disagree with its verified factor rows. This is a distinct mutation from R02's reset-proof races.

**Change.** Lock and validate the account before the factor, using the same account-first lock order as authenticator completion/removal. Make every required write conditional on the current authorized state, and fail/roll back if an expected update affects no row. Bind pending enrollment to the authorization generation if it must survive requests safely.

**Qualification.** Use two PostgreSQL connections with deterministic synchronization to pause verification after its initial read, commit password reset, resume verification, and assert rejection with no verified factor or summary change. Also exercise a stale request arriving after reset. An ordinary sequential stale-stamp test does not cover this schedule.

### R03-03 — A public sample key is the runnable default

**Evidence.** [appsettings.json](sandbox:/workspace/scratch/78b7f387c802/source/treehammock-main/appsettings.json) (line 294) and [appsettings.Example.json](sandbox:/workspace/scratch/78b7f387c802/source/treehammock-main/appsettings.Example.json) contain the same fixed Base64 TOTP protection key. [TotpSettings.cs](sandbox:/workspace/scratch/78b7f387c802/source/treehammock-main/Rigging/Config/TotpSettings.cs), `Validate`/`TryDecodeProtectionKey`, checks encoding and 32-byte length only. Startup's validated options accept that known value. The protector uses the resulting bytes directly for AES-GCM.

**Impact and condition.** Any deployment that retains this default encrypts TOTP seeds under a key available with the source. A readable database dump plus that key permits seed recovery and future code generation. This is a confirmed unsafe default, **not evidence that the live deployment uses it, that a database was exposed, or that a production key was compromised**. A securely overridden key avoids this particular risk.

**Change.** Require a deployment-specific secret outside checked-in runnable defaults, reject the known sample key outside an explicitly isolated development/test configuration, and document generation and secret injection. Check the actual deployed value privately. If seeds were protected under the published value, assess exposure and migrate/re-enroll as appropriate; merely changing configuration prevents the old ciphertext from decrypting (R03-04).

**Qualification.** Assert that production startup fails for absent/invalid/known-sample keys and succeeds with an independently generated key. Confirm separate environments do not share the same key, without logging or exporting it. Do not use a key-format test as a deployment-secret check.

### R03-04 — Key rotation strands existing encrypted seeds

**Evidence.** [TotpSecretProtectionService.cs](sandbox:/workspace/scratch/78b7f387c802/source/treehammock-main/Services/TotpSecretProtectionService.cs), `ProtectedTotpSecret` and `TotpSecretProtector` (line 16 onward), stores ciphertext, nonce, tag, and format version `1`. There is one configured `SecretProtectionKey`, no key ID or decrypting key ring, and `Unprotect` always uses the current configured key. No enrollment re-encryption path appears in the reviewed setup/removal and repository contracts.

**Failure scenario.** Encrypt an enrollment under key K1, change the configured key to K2, restart, and submit a correct TOTP code. Decryption fails authentication before code verification. The stored format version does not identify K1. Rolling back configuration preserves availability but is not a supported rotation process.

**Change.** Add a key ID separate from the ciphertext-format version, support decrypting retained keys while encrypting under the active key, and provide a resumable migration with verification before retiring old keys. Define recovery if a key is lost. Keep deployments consistent during a rolling change.

**Qualification.** Test old and new seeds across rotation, partially migrated data, rollback, missing keys, and rolling application instances. Tampered data must continue to fail closed. Do not disable GCM authentication to make migration pass.

### R03-05 — Runtime TOTP defaults rewrite the meaning of old enrollments

**Evidence.** [TotpCodeVerifier.cs](sandbox:/workspace/scratch/78b7f387c802/source/treehammock-main/Services/TotpCodeVerifier.cs), `Verify` (line 48), uses the current `TotpSettings.Digits`, `PeriodSeconds`, and `HashAlgorithm` for every enrollment. Provisioning communicates those settings in the URI, but the factor schema and `VerifiedTotpEnrollmentRecord` do not persist those parameters. The durable `totp_last_used_step` also has no period/algorithm generation attached.

**Impact.** Changing a valid global setting can make existing client-generated codes fail. Changing the period also changes the units of the stored replay counter; some period changes can leave its old value ahead of the new counter for a long time. Startup permits these settings, so the resulting outage need not be a configuration-validation failure.

**Change.** Persist immutable parameters with each enrollment and verify/replay-track using those parameters. Use global settings for new provisioning only. Alternatively, explicitly freeze the parameters for the lifetime of all existing enrollments and reject incompatible changes until a planned migration is performed.

**Qualification.** Provision under one set of parameters, change defaults, and assert that existing enrollments still work while new enrollments use the new settings. Test period changes in both directions and replay behavior. RFC 6238 requires the prover and verifier to share the time step and describes provisioning of those parameters. [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238).

### R03-06 — Factor mutation lock order permits deadlocks

**Evidence.** `verify_twofactor_setup` first locks the pending factor, then updates the account. `remove_twofactor_method` (SQL line 3842) and `begin_authenticator_app_setup` (line 4036) lock the account before updating/deleting/locking factor rows. Authenticator completion also follows account-first locking.

**Source-derived schedule.** Email/SMS verification A holds the factor lock; an account-first mutation B holds the account lock and waits on that factor; A waits to update the account. This creates a cycle. PostgreSQL can abort a participant; the email/SMS function's `WHEN OTHERS` maps the error to generic setup failure. This is an availability/retry problem, not a claim of committed partial writes after a PostgreSQL exception.

**Change.** Establish one account → session, where needed → factor lock order for related mutations. Add bounded retry only after fixing avoidable inversion and preserving idempotent results. Avoid holding transactions open while calling external delivery providers.

**Qualification.** Reproduce verification versus authenticator-start/removal with separate connections and controlled barriers. Capture SQLSTATE `40P01`, final state, and response behavior. PostgreSQL documents consistent lock ordering as a deadlock prevention measure. [PostgreSQL 16 locking](https://www.postgresql.org/docs/16/explicit-locking.html#LOCKING-DEADLOCKS).

### R03-07 — Setup can promise a challenge after a zero-row update

**Evidence.** `begin_twofactor_setup` (SQL line 3475) selects the pending row's index without `FOR UPDATE`. Its replacement update later requires `verified = false AND revoked_at IS NULL`, but never checks `ROW_COUNT`. It returns `TWO_FACTOR_SETUP_PENDING` regardless. The controller sends the newly generated code after a successful result.

**Source-derived schedule.** A replacement request selects pending row i; B verifies row i and commits; A's guarded update affects zero rows because i is now verified; A returns pending success and sends its code. That new code was never stored. This differs from a duplicate-insert race, which the unique index catches.

**Change.** Serialize setup replacement with verification using the common account-first order, re-evaluate eligibility under lock, and require an actual insert/update before returning pending. Return an explicit already-configured/conflict result when the target changed.

**Qualification.** Pause replacement after the index lookup, complete verification, resume replacement, and assert no misleading pending response or delivery. Inspect stored hashes and row counts. Keep existing sequential replace/replay tests.

### R03-08 — Setup delivery drops the account dimension

**Evidence.** [AccountControllerBase.TwoFactorHelpers.cs](sandbox:/workspace/scratch/78b7f387c802/source/treehammock-main/Controllers/AccountControllerBase.TwoFactorHelpers.cs), `SendTwoFactorSetupChallenge` (line 60), calls `_twoFactorService.SetupEmail(emailAddress, codeKey)` and `SetupSMS(smsDestination, codeKey)` without an account ID. [TwoFactorAuthenticateService.cs](sandbox:/workspace/scratch/78b7f387c802/source/treehammock-main/Services/TwoFactorAuthenticateService.cs) forwards the optional `accountId` into the delivery-throttle request. [DeliveryAbuseThrottleService.cs](sandbox:/workspace/scratch/78b7f387c802/source/treehammock-main/Services/DeliveryAbuseThrottleService.cs), `BuildDeliveryCounterLimits`, creates the account counter only for a supplied nonempty ID.

**Impact.** Setup has destination and IP budgets, but its configured account budget is absent. For SMS, the same account can change destinations and source IPs to evade that missing dimension, increasing provider cost and message abuse. Unique pending enrollment constrains database state, not how many messages are sent. This is not a claim that all delivery throttles are disabled.

**Change.** Pass the authenticated account ID through the helper to both setup-delivery calls. Preserve the other dimensions and avoid recording raw destinations in telemetry. Address the late-admission replacement issue under existing R02-02 as part of this change.

**Qualification.** Observe throttle requests and real counter keys for both channels. With a low account limit, vary SMS destinations/IPs and assert denial once the account budget is exhausted. Use different idempotency keys to test genuine new requests.

### R03-09 — Enrollment lookup failures debit the user's proof budget

**Evidence.** [AuthenticatorAppEnrollmentRepo.cs](sandbox:/workspace/scratch/78b7f387c802/source/treehammock-main/Repos/AuthenticatorAppEnrollmentRepo.cs), `GetVerifiedTotpEnrollmentForAccountAsync`, catches repository exceptions and returns null. [AuthenticatorAppLoginService.cs](sandbox:/workspace/scratch/78b7f387c802/source/treehammock-main/Services/AuthenticatorAppLoginService.cs), `VerifyForLoginAsync`, returns `EnrollmentUnavailableCode` for null lookup or an exception. In the controller helper, `IsAuthenticatorAppLoginServerFailure` recognizes `SecretUnavailableCode` and `StepMarkFailedCode` only. `EnrollmentUnavailableCode` therefore reaches `RecordTwoFactorFailure`, which records a durable failed attempt.

**Failure scenario.** A transient lookup failure occurs, then the durable failure write succeeds after database recovery. A valid submitted code is counted as incorrect without being checked. Repeated intermittent faults can exhaust a pending login's attempt budget. A complete outage may also prevent the failure write; debit is not guaranteed in every outage.

**Change.** Distinguish no eligible enrollment from a storage/cancellation failure in repository results. Treat infrastructure failure as retryable server failure without charging incorrect-proof counters. Preserve fail-closed authorization. Do not classify every absent factor as a server fault without deciding its contract.

**Qualification.** Fault only the lookup while allowing failure persistence; assert a retryable response and unchanged invalid-proof budget. Separately assert that a genuinely wrong TOTP code increments the budget, a missing enrollment is denied, and cancellation stays cancellation. R02-11 tracks the analogous reset-side failure taxonomy; this ID records the separate login implementation.

### R03-10 — Cross-method replacement leaves a protected seed behind

**Evidence.** `begin_authenticator_app_setup` can create a protected seed in the single pending factor row. `begin_twofactor_setup` intentionally reuses any pending row, regardless of its previous method. Its email/SMS replacement update changes method/contact/token fields but does not null `totp_secret_ciphertext`, nonce, tag, version, provider type, or last-used-step. Email/SMS verification likewise does not clear those fields. Removal wipes TOTP fields only when `p_method = 3`.

**Failure scenario.** Start authenticator setup; replace it with SMS or email setup; verify that factor. The abandoned encrypted authenticator seed remains attached to a verified delivery-factor row with no expiration. Later email/SMS removal also retains it. Current verified-TOTP lookup filters to method 3, so **this does not make the abandoned seed an accepted authenticator**. It is unnecessary sensitive-data retention and an inconsistent row contract.

**Change.** On cross-method replacement, clear every field owned by the previous method. Add schema invariants for allowed method/secret combinations where practical, and migrate existing mismatched rows. Use a bounded cleanup policy for abandoned/expired pending secrets.

**Qualification.** Exercise authenticator → SMS and authenticator → email replacement, verification, and removal against PostgreSQL. Assert all TOTP columns are null on delivery-factor rows. Also assert verified authenticator data survives unrelated method removal and is wiped on authenticator removal.

## Existing findings extended by this chunk

These remain under their original IDs; the counts do not duplicate them.

| Existing ID | Additional R03 evidence or required qualification |
| --- | --- |
| AUTH-03 | Final delivered login proof still relies on cached challenge state; TOTP's replay marker does not repair the email/SMS challenge-generation race. |
| AUTH-05 | Sensitive-action issuance verifies a password without an attempt budget. Adding grants to SMS setup must include this fix. |
| AUTH-07 / AUTH-08 | Setup and removal use the shared idempotency service and inherit reservation-ownership/content-binding problems. |
| AUTH-02 | Several sensitive-action/account repository methods have no cancellation parameter; authenticator methods catch all exceptions, including cancellation, into null. Timeout/commit ambiguity needs operation-level qualification. |
| R02-02 | Email/SMS setup persists replacement before delivery admission and attempts cancellation on delivery failure; a denied or failed delivery can destroy the previous pending setup, including a pending authenticator setup. |
| R02-05 | Removing the last additional factor still has the reset-proof bypass identified in R02. Removing a factor is not qualified until that reset interaction is fixed. |
| R02-08 | Setup completion and token consumption use application-supplied timestamps captured before lock waits. Include post-wait expiry enforcement in the common deadline fix. |
| R02-14 | Expired pending authenticator secrets have no scheduled cleanup in the reviewed production lifecycle. Broaden retention work beyond reset records. |
| R02-15 | Sensitive-action reauthentication and user-secret hashing share the Argon2id codec/cost units already flagged. Do not count it again or treat the configured number as a measured memory cost. |

## Positive source findings and boundaries

- TOTP secret generation uses cryptographic randomness, and Base32/URI construction follows the standard manual-entry/`otpauth` structure. Provisioning returns client seed material intentionally; SQL receives the protected seed and setup-ID hash.
- AES-GCM uses a 32-byte key, random 12-byte nonce, 16-byte tag, and format-associated data. It rejects unsupported versions and malformed bundles. Successful local verification paths clear the decrypted byte array. This is source assurance, not a certification of deployment key handling.
- Code verification uses a 64-bit moving counter, HMAC SHA-1/SHA-256/SHA-512, dynamic truncation, fixed-length comparison, and a bounded skew window. With the default skew of one, at most three candidate steps are checked. Tests include one independent RFC SHA-1 vector; many other tests generate expected codes using the production implementation, so their independence is limited.
- PostgreSQL `mark_totp_step_used` locks the enrollment row and only accepts a strictly newer step. Login and reset use this shared marker. Concurrent use of the same accepted step therefore has a durable single-winner guard. This does not prove the larger authentication transaction is atomic.
- Authenticator completion checks the old access-token hash and account stamp under locks and rotates security state in SQL before best-effort cache work. A cache-write failure cannot undo a committed enrollment; a lost token response remains a recovery concern.
- Sensitive-action tokens are random opaque tokens, stored as hashes, with a short lifetime and account/stamp/session-hash/purpose fields. Consumption locks the token row and records `consumed_on`, providing a single-use primitive. SQL issuance/validation receives parameters rather than interpolated user input.
- Email setup resolves and checks the account's email rather than allowing arbitrary destinations. Revocation-aware unique indexes constrain one active verified enrollment per method and one active pending enrollment per account. Managed TOTP providers are rejected pending an actual provider contract.

## Design and reliability questions retained without new finding counts

**TOTP proof and login promotion are separate commits.** A valid TOTP step can be consumed, then login promotion/cache progression can fail. Retrying that same code fails the replay check and can consume an incorrect-proof attempt. This fail-closed behavior preserves one-time use but makes recovery brittle. Test failures between marking and promotion. If recoverable retries are required, persist an operation-bound proof receipt or atomically combine the relevant proof and promotion state; never simply roll back the global replay marker and permit unrestricted reuse. RFC 6238 requires rejection of repeated successfully validated OTPs.

**Secret-safe idempotency has a recovery tradeoff.** Source tests explicitly prohibit replaying setup IDs/manual keys/URIs/access tokens. A lost setup response therefore yields a sanitized replay success without provisioning material. A lost authenticator-verify response is harder: the old token is invalid after stamp rotation, and authentication happens before idempotency lookup, so that token cannot reach replay. Keep secrets out of generic idempotency records, but document an explicit restart/re-login/recovery response instead of implying that the sanitized response restores the result. This is not a request to weaken the current secret-safe cache rule.

**Session binding is a comparison, not a live-session check.** `validate_sensitive_action_token` locks the token row and compares stored fields to caller-supplied fields; it does not read the current account or bound session. The controller separately authenticates before consumption, and mutation functions check stamps separately. Decide whether a request authenticated before logout/refresh is allowed to finish afterward. If immediate revocation of in-flight sensitive actions is required, bind grant consumption to current session authority in the mutation transaction and test that exact schedule. Ordinary later requests remain subject to the authentication middleware; this review does not claim that an unauthenticated caller can spend a grant.

**Ciphertexts are not bound to their enrollment row.** The AAD is a fixed format string, not account/enrollment identity. A complete valid encrypted bundle can be copied between rows without GCM detecting a row substitution. Exploitation requires suitable database write capability and a broader threat-model assessment; it is not evidence of a remote API bypass. Consider binding future formats to immutable account/enrollment identity when designing key rotation, with migration for existing records.

**Factor policy needs an explicit contract.** Available configurations include standalone email/SMS/authenticator choices even when other factors are configured. The persisted `required` field does not make all such factors mandatory. Existing tests expect standalone alternatives after removal, so this is treated as the current choice policy, not silently labeled a multi-factor bypass. Document the meaning of `required` and whether adding a weaker factor is permitted to create an alternative login/reset path.

## Performance review for this chunk

No latency, throughput, allocations, or query plans were measured. Local TOTP/HMAC/AES work is bounded and is unlikely to dominate the network-bound paths at current seed sizes; that is an inference to confirm under load. The default skew permits three comparisons, not an unbounded scan. Keep those bounds when extending provider support.

Repository enrollment lookups open an explicit transaction even for read-only SQL functions, introducing begin/commit round trips. Authenticator verification commonly does lookup → local decrypt/verify → a separate mutation transaction. Sensitive reauthentication similarly does credential lookup → password hash verification → token issuance. Review round-trip costs and connection-pool occupancy in R06; optimize after measuring without weakening the required mutation locks.

Method mutations count factor rows and derive configurations. The active set is bounded by uniqueness, but revoked history and pending secrets need retention/migration policies. SQL often scans per-account history for the next smallint index. Do not infer constant cost from the three active factor types. Measure realistic historical account sizes and inspect supporting indexes in R06.

Correctness issues R03-06 and R03-07 can create retries, wasted deliveries, and tail-latency spikes. R03-08 allows avoidable provider spend. Prioritize those ahead of micro-optimizing a handful of HMAC calls. Factor-removal transactions also write reset-session/event state; test lock duration with large account history. Keep SMTP/SMS outside database transactions.

## Test coverage inspected and remaining qualification

| Test surface | Source evidence inspected | Missing qualification for this review |
| --- | --- | --- |
| `TotpCodeVerifierTests` | Current/past/out-of-window, shape, used-step rejection, one RFC SHA-1 vector | Full independent RFC SHA-1/256/512 vectors, future-skew boundaries, digits/period changes, concurrent replay |
| `TotpSecretProtectionServiceTests` | Round trip, ciphertext tamper, unknown version, invalid key format | Nonce/tag tamper and wrong key, rotation/migration, row binding, deployment sample-key rejection |
| `AuthenticatorAppProvisioningServiceTests` | Encoding/URI, protected storage/hash-only setup ID, duplicate/provider rejection, cancellation, invalid proof, completion command | Real SQL mutation atomicity, lock waits, expiry after waits, cross-method replacement, lost responses |
| `AuthenticatorAppLoginVerifierTests` | Valid/wrong proof, missing/provider enrollment, replay-marker rejection with repository substitutes | Distinguish repository outage/cancellation, actual concurrent step marking, promotion failure after accepted step |
| `SensitiveActionTokenServiceTests` | Correct/wrong password and unverified-account issuance with substitutes | Wrong account/stamp/session/purpose, single-winner consume, expiry after waits, live-session revocation, issuance throttling |
| `TotpHardeningRegressionTests` and enrollment SQL contract tests | Text assertions for sensitive grants, secret-safe idempotency, shared marker, atomic rotation, log exclusions | Text presence does not prove SQL locking semantics, runtime behavior, multiline/structured log privacy, or network failure recovery |
| Removal/email-binding/enrollment-limit tests | Selected controller/substitute and SQL-text assertions | Last-factor reset interaction, real concurrent enrollment/removal, abandoned-secret cleanup |
| Deferred `BooleanProcedureContractTests` | Sequential pending replacement, wrong-code attempts, successful verification, replay denial | Two-connection interleavings R03-02/06/07 and new enrollment/grant contracts |

All of the above are test-source observations. No listed suite was executed. Broader SQL reset tests touch shared replay data, but are not substitutes for the actual authenticator repository/login path under contention. Referenced TOTP design documents in release matrices are not all present in this archive; current source/tests take precedence, with documentation completeness reserved for R10.

Suggested qualification sequence once runtime tools exist:

1. Run the project validation script and relevant unit/controller tests; correct any build/configuration failures first.
2. Run the deferred PostgreSQL contracts with their opt-in flag and a disposable database. Extend them with deterministic, two-connection tests for the schedules above.
3. Exercise authenticated HTTP enrollment/removal, lost responses, cache outage after SQL commit, and per-account delivery budgets with stubbed external providers.
4. Run the existing system stack against PostgreSQL and the Redis-compatible cache, including cross-instance replay and revocation. Confirm outage responses do not exhaust user proof budgets.
5. Measure p50/p95/p99, query/round-trip counts, pool waits, lock waits, deadlocks, delivery volume, and failed-operation recovery for both ordinary and high-history accounts. Set budgets based on actual results.

## Next chunk and cumulative artifacts

**R04 is account profile reads/updates, email-change lifecycle, and account deletion.** It should reuse the account-stamp, pending-proof, lock-order, and session-revocation invariants established by R01–R03. Then continue R05 activation; R06 complete repositories/SQL/performance; R07 HTTP/models/hosting/proxies; R08 providers/templates; R09 abuse/telemetry/health/tests; R10 dependencies/build/deployment/CI/docs. Cross-chunk observations do not mark those areas complete.

The accompanying bundle contains R01–R03 reports, the cumulative 451-file inventory and open-finding ledger, this chunk's structural evidence/test-method catalog, the earlier evidence, and the original blocked validation record. No fixes or source changes are included.

Primary references used to validate the review's reasoning: [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238), [OWASP MFA Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html), [PostgreSQL 16 explicit locking](https://www.postgresql.org/docs/16/explicit-locking.html), and [Microsoft .NET 8 AesGcm API](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesgcm?view=net-8.0). They support the algorithm/locking/security guidance, not claims that this project's runtime tests passed.
