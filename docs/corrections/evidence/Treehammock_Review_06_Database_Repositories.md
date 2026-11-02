# Treehammock review 06 — PostgreSQL and repositories

Reviewed 2026-10-03. Review only; application source unchanged.

## Result and qualification

This chunk adds **three findings: one P1 and two P2**. The cumulative ledger now contains **55 open findings: 17 P1 and 38 P2**. The new defects concern activation transaction completion, ambiguous SQL identifiers in conditional branches, and exhaustion of retained factor identities. Previously reported authority, race, deadlock, cleanup, and connection-string issues remain open and are not counted again.

The production database/repository source pass is complete. Runtime qualification is blocked: this workspace has no .NET SDK, Docker, PostgreSQL client/server, or Redis server. `bash eng/sql-contracts.sh --locked-restore`, supplied with the required opt-in and a disposable local connection placeholder, exits 127 at `dotnet --info`. It never connects to a database. No build, application test, database reproduction, query plan, or performance benchmark ran. Static evidence below establishes source structure; behavioral consequences are inferences requiring the specified runtime regressions.

Source is the uploaded `treehammock-main.zip`, SHA-256 `229ef2275f1caeff3a6a40186e678f7440a90fd54add2e0ba8de0fd6c645758f`. The evidence builder verifies the exact set and hashes of all **451 source files**. The two canonical SQL files differ only in their first project-name comment; their remaining bodies are identical. The second is verified by complete comparison, not represented as an independent implementation.

## Inspection coverage

All 19 files assigned to R06 have explicit dispositions. **16 received a complete source pass or identical-baseline verification; three large test files received targeted coverage inspection.** Their remaining full-source test audit is explicitly carried to R10. This does not claim complete test-suite review or a qualified release.

| Surface | Disposition |
|---|---|
| All ten `Repos/*.cs` files | Complete source inspection: function selection, positional parameters and database types, reader/transaction lifetime, result decoding, nullable failure contracts, logging and cancellation boundaries |
| `StorageContext.cs` | Complete source; shared data-source construction, connection acquisition, disposal and cancellation ownership; singleton DI registration consulted |
| Both canonical baselines | Entire canonical baseline inspected: tables, keys, checks, indexes, all function bodies, state changes, lock acquisition and cascades; second baseline compared in full, with only a project-name header difference |
| `ActivationProcedureContractTests.cs` | Complete source: sequential direct SQL calls; bypasses the actual activation repository; no disable call or successful verification transition asserted |
| `SessionConcurrencyProcedureContractTests.cs` | Complete source: two physical connections, blocked second creation, first commit, final active-session count and trust checks |
| `SqlContractSettings.cs` | Complete source: explicit disposable-database opt-in; tests throw if prerequisites are missing |
| `BooleanProcedureContractTests.cs` | Test-method catalog, opt-in/setup, and complete email/SMS setup replacement/verification regression inspected; other test bodies remain for R10 |
| `PasswordResetProcedureContractTests.cs` | Test-method catalog and initial lifecycle/schema-constraint slice inspected; remaining bodies carried to R10 |
| `PasswordResetRepositorySqlIntegrationTests.cs` | Test-method catalog; initial actual-repository/session lifecycle slice; selected schema setup/runtime factory, fake dependency and custom StorageContext slices; remaining bodies carried to R10 |
| Cross-cutting sources | Selected callers, pinned Npgsql lock entry, DI registration, authenticator SQL source-string tests, SQL runner, existing correction plan and earlier reports |

Primary code: [ActivationRepo.cs](sandbox:/workspace/scratch/78b7f387c802/source/treehammock-main/Repos/ActivationRepo.cs), [AuthenticatorAppEnrollmentRepo.cs](sandbox:/workspace/scratch/78b7f387c802/source/treehammock-main/Repos/AuthenticatorAppEnrollmentRepo.cs), [AccountRepo.cs](sandbox:/workspace/scratch/78b7f387c802/source/treehammock-main/Repos/AccountRepo.cs), [SessionRepo.cs](sandbox:/workspace/scratch/78b7f387c802/source/treehammock-main/Repos/SessionRepo.cs), [000_canonical_database.sql](sandbox:/workspace/scratch/78b7f387c802/source/treehammock-main/Rigging/Database/Baseline/000_canonical_database.sql), [StorageContext.cs](sandbox:/workspace/scratch/78b7f387c802/source/treehammock-main/Rigging/Database/StorageContext.cs).

Paths and line numbers below are relative to the supplied repository, so evidence remains locatable after extracting the review bundle. No fixes are included.

## New findings

| ID | Priority | Finding | Correction owner |
|---|---|---|---|
| R06-01 | P1 | All four activation repository methods commit with their reader still open. | COR23A |
| R06-02 | P2 | Authenticator replacement and activation-disable fallback contain identifiers ambiguous with output variables. | COR23B |
| R06-03 | P2 | Retained revoked factors consume a smallint identity range and can permanently prevent new enrollment. | COR23C |

### R06-01 — Activation readers outlive the commit attempt

**Evidence.** `Repos/ActivationRepo.cs` executes a reader, decodes one row, then commits before leaving the `await using` reader scope:

| Method | Reader / decode / commit lines |
|---|---|
| `PlaceActivation` | 106–108 |
| `CancelActivationRequest` | 148–150 |
| `DisableActivation` | 194–196 |
| `VerifyActivation` | 242–244 |

The decoder helpers at 265–296 perform a single `ReadAsync` and return; neither closes the reader. `await using` ensures eventual disposal, but disposal at scope exit occurs **after** the commit call. Other inspected repositories explicitly dispose their readers before committing, including `SessionRepo.GetSession` and the actual reset repositories.

**Inferred impact.** Npgsql treats a connection with an active reader as busy, and documents `NpgsqlOperationInProgressException` for an operation on an already-busy connection. The expected consequence here is rejection of `CommitAsync`, unwinding/disposal of the reader, and the catch path rolling back, logging and returning null. A successful SQL function row therefore does not establish a committed activation operation through the real repository. Creation would fail before ordinary code delivery; verification, disable and cancellation would also fail through these paths. This is a high-priority feature blocker, independent of whether activations currently grant entitlements. See the primary [Npgsql busy-connection contract](https://www.npgsql.org/doc/api/Npgsql.NpgsqlOperationInProgressException.html).

`packages.lock.json` pins Npgsql 8.0.9. A reproduction against that exact package is still required: the current API documentation supports the busy-connection rule, but is not a version-pinned execution trace. Attempts to retrieve the pinned upstream source were unavailable. This review does not claim a reproduced exception or observed provider behavior.

**Coverage gap.** The existing activation SQL test invokes functions directly, with reader disposal in its query helper; it never constructs `ActivationRepo`. HTTP/service tests using a substituted repository likewise cannot validate real reader lifetime. The bug can therefore coexist with passing direct SQL and mocked HTTP tests.

**Correction.** Materialize the result inside a nested reader scope, leave that scope, then commit. Apply it to every activation method, including false/no-row results. Keep decoding failures inside rollback handling. Do not replace the reader with an unchecked scalar that drops the multi-column status contract.

**Required regression.** Use the real repository and pinned Npgsql against disposable PostgreSQL. Assert successful placement, cancellation, disable and verification; independently query durable state from a second connection. Also assert false statuses, missing rows, and decoding/SQL failures, with no committed partial mutation and no leaked busy connector.

**Amendment to R05.** R05 described the intended SQL lifecycle and its races. This finding adds a repository blocker that can mask those behaviors. The earlier six findings remain valid source defects in their SQL/service paths, and must be tested after this blocker is fixed. R05's behavioral tables must not be read as evidence that real repository commits already succeed.

### R06-02 — Conditional SQL branches collide with output variables

**Evidence.** Both baselines contain these references:

1. `begin_authenticator_app_setup`, SQL 4036–4084, declares `RETURNS TABLE(... two_factor_index smallint, expiration ...)` at 4049. Its replacement update at **4075** uses `where ... and two_factor_index = target_index ...` without qualifying `two_factor_index`. That name can refer to either the table column or the function's implicit output variable.
2. `disable_activation`, SQL 6020–6091, declares output `status` at 6027. After its current-row update finds nothing, the fallback query at **6071–6077** uses `and status in (1, 3)` without a table alias. The earlier update correctly uses `a.status`, but the fallback does not.

Neither function declares a conflict preference; no project setting overriding it was found. With PostgreSQL's default `plpgsql.variable_conflict=error`, these references are ambiguous. SQL inside a conditional branch is analyzed when reached, so loading the baseline or running another branch does not validate them. This conclusion is inferred from the source and the primary [PostgreSQL PL/pgSQL implementation documentation](https://www.postgresql.org/docs/16/plpgsql-implementation.html), sections 43.11.1–43.11.2.

**Inferred impact.** First authenticator setup can take the insert branch; repeating setup while a pending authenticator, email or SMS setup exists takes the update branch and returns `AUTHENTICATOR_SETUP_FAILED` through its broad exception handler. It cannot complete the advertised replacement. For an existing account with matching stamp/email, disabling with no current qualifying activation reaches the ambiguous fallback and raises a database error instead of a reliable expired/not-found result. It reaches the expression even when there are no activation rows. R06-01 independently masks repository outcomes until repaired.

**Coverage gap.** There is an actual SQL replacement test for email/SMS `begin_twofactor_setup`, whose predicate is qualified; it does not exercise `begin_authenticator_app_setup`. The inspected authenticator unit tests assert strings/function names rather than executing these branches. The dedicated SQL test project contains no call to `begin_authenticator_app_setup` or `disable_activation`.

**Correction.** Alias the updated/queried tables and qualify column reads in both functions. Keep input and local naming distinct from output names. Do not globally change variable resolution to hide the problem; choosing variables can also change predicate meaning. Update both baseline copies or their authoritative generation path together.

**Required regression.** Under the default conflict setting: create a pending authenticator, replace it; replace pending email/SMS with an authenticator; disable a current activation, an expired activation, and an account with no activation. Assert exact status and stored row/secret lineage after each call. Add branch coverage for the remaining table-returning functions as a release gate; successful baseline creation alone is insufficient.

### R06-03 — Factor history exhausts the enrollment identity range

**Evidence.** `two_factor_authentications.two_factor_index` is a **smallint** at SQL 141, part of the primary key at 169. Both creation functions allocate from the maximum of **all historical rows** for the account:

```sql
select (coalesce(max(t.two_factor_index), -1) + 1)::smallint
```

See `begin_twofactor_setup` at 3572–3576 and `begin_authenticator_app_setup` at 4070–4071. The removal path at 3900–3916 marks verified factors revoked and retains their rows; its later deletion removes only unrevoked pending rows. Revoked SMS/authenticator history therefore continues to raise the maximum. No retention/reallocation path for that history was found. Email-change-specific deletion is not a general solution for retained SMS/authenticator history.

**Inferred impact.** With no replaceable pending row and a retained row at index 32767, the next allocation tries to cast 32768 to smallint and cannot succeed. Even an account with zero active factors cannot attach a new one. The first generated index is 0, so monotonically retained allocations have 32,768 nonnegative slots. This is a long-lived capacity defect, not a claim of likely immediate exhaustion or a public exploit. Repository models/readers also use C# `short`, so widening only the table would leave contracts inconsistent.

**Correction.** Use a durable, non-reused enrollment identity with a suitable range, such as UUID/bigint, through the database, functions, repository DTOs and TOTP replay references. Keep factor display/order indices separate. Define history retention, but do not recycle cryptographic/replay identities merely to work around exhaustion. If identity participates in secret protection, migrate its binding without making existing secrets undecryptable. Coordinate this with the existing TOTP envelope and policy migration.

**Required regression.** Seed a valid revoked SMS/authenticator history row at index 32767 with no active/pending factor; execute each new-enrollment function. The existing implementation is expected to fail. After the change, assert successful fresh identity allocation, uniqueness under simultaneous enrollment, usable old enrollment migration, unchanged replay protection, and correct terminal-history retention. This avoids requiring tens of thousands of slow setup cycles in a regression.

## Existing findings reinforced without new ledger entries

| Existing ID | R06 evidence / closure consequence |
|---|---|
| AUTH-02 | Many repositories cannot receive request cancellation; even token-aware repositories acquire their connection through tokenless `StorageContext.CreateConnection`. A timeout response is not evidence of rollback. Preserve durable outcome reconciliation. |
| AUTH-04 / R02-03 | Absolute failure writes and unconditional unlock/reset of lockout fields remain in SQL; fix transitions atomically under current authority. |
| AUTH-09 | Session rotation inserts a fresh row/default session ID. Stable device-session identity remains an open correction. |
| AUTH-10 / R02-11 / R03-09 | Nullable results still conflate missing data and infrastructure errors in parts of the repository contract. Typed dependency failures must reach caller policy. |
| AUTH-12 | Connection settings still interpolate directly into a connection string. Use a structured builder and explicit resource ownership. |
| R02-04 / R02-06 | Generic reset-session upsert and reset promotion still lack the exact monotonic durable-proof authority required by the correction design. |
| R02-07 / R03-06 / R04-04 | Account/request/factor lock-order mismatches remain. Repositories span multiple commands and some hashes run under transactions; a single function's local lock list is not a complete transaction graph. |
| R02-08 | Time values sampled before lock waits, including transaction-time `now()`, still require an explicit time contract and deadline regressions. |
| R02-14 / R04-07 / R05-05 | Retention/scheduling remains necessary; narrow live indexes do not bound retained history. |
| R03-02 / R03-07 / R04-02 / R05-01–03 | Several final updates still rely on previously read authority or ignore affected-row outcomes. Row locks/CAS predicates must cover the final mutation and external effects. |

The baseline header explicitly describes an **undeployed greenfield project**. The absence of an upgrade migration is not added as a deployment defect. The correction program should still establish a single authoritative schema path and migration testing before changing persistent identity/security state. No deployed database was inspected.

## Performance and resource observations — measurements still required

These are follow-up tasks for COR03/COR22, not additional numbered defects or measured performance claims.

| Surface | Source observation | Required evidence / proposed change |
|---|---|---|
| Account deletion / revoked reset history | SQL 349–393: reset-session `account_id` FK cascades on account deletion, but its account-leading index includes only `revoked_at is null`. It cannot cover all revoked child rows. Activations also lack an account index, already recorded under R05-05. | Capture cascade trigger time and plans at deep mixed live/revoked history. Evaluate an unconditional account-leading index and overlap/write cost; preserve bounded cleanup. |
| Reset identifier lookup | The account query combines lowercased email/username with a factor-phone `EXISTS` and runtime phone normalization. Ordinary email/username indexes do not prove a cheap absent-phone lookup. | EXPLAIN with buffers for positive/negative email, username and phone distributions; introduce normalized/indexed phone lookup only with proven normalization and ambiguity policy. |
| Read-only repository operations | Many single read calls still explicitly begin/commit transactions. Cache trust requests add durable checks rather than eliminate DB cost. | Measure command counts, pool waits and latency. Remove unnecessary transaction framing only for reads with unchanged consistency semantics; retain required lock lifetimes. |
| Data-source lifetime | DI registers `StorageContext` as singleton. It builds its own NpgsqlDataSource but exposes no disposal interface. The reset-test subclass builds and disposes a separate source; base ownership remains unchanged. | Let DI own/dispose the actual shared pool. Test repeated host lifecycle and connection acquisition failure/cancellation. No per-request pool creation was found. |
| Factor history | `MAX` allocation and some factor scans include terminal history. Revoked factors are retained; identity exhaustion is separately R06-03. | Declare retention and query budgets; measure cold/deep-history lookup and enrollment. Avoid unsafe identity reuse. |
| Session byte decoding | `SessionRepo.GetSession`, 82–84, reads a configured-length refresh buffer without validating actual stored length; other byte readers materialize the stored length. | R07 configuration/compatibility pass should check persisted credential size changes and malformed row behavior; define exact stored-byte decoding and version migration before changing settings. No authentication bypass is asserted. |
| Constraints and indexes | PK/unique checks cover core hashes, per-method verified factors, one pending setup and one active reset request. Checks alone do not encode all authorization transitions. | Test constraints and state-machine invariants separately. Measure redundant indexes, write amplification, dead tuples, vacuum and expiry-driven retention before tuning. |

PostgreSQL does not automatically index referencing FK columns, and deleting parent rows requires finding matching child rows. These observations follow the schema and the primary [PostgreSQL constraints documentation](https://www.postgresql.org/docs/16/ddl-constraints.html), section 5.4.5; they are not benchmark results. Shared pooling/disposal and per-command round trips are described in the primary [Npgsql basic usage documentation](https://www.npgsql.org/doc/basic-usage.html).

## Correction-plan addendum

The delivered design/PR plan covered 52 findings. It must now include these **three explicit owners**, in addition to its existing mapping. No finding is closed by this review. The previously chosen **trusted-grant activation authority** remains the target: server authorization selects the tier; email code proves redemption. The additions repair infrastructure/contracts underneath that design, without restoring caller authority over paid tiers.

Per COR23's existing instruction to create scoped COR23A onward PRs, insert the following work **when its prerequisites are ready**, rather than waiting until the end of the numbered program. These are review-derived specifications, not implemented PRs.

### COR23A — Close activation readers before completing transactions

- **Owns:** R06-01 only. **Depends on:** COR01; coordinate repository lifetime/result contracts with COR03. **Gates:** real activation qualification in COR19–21 and COR24.
- **Files:** `Repos/ActivationRepo.cs`; dedicated actual-repository tests in the SQL contract project. Avoid unrelated SQL state-machine edits in this PR.
- **Implementation:** nested reader scopes for all four methods; materialize the full result; commit afterward; preserve rollback on read/SQL errors and typed dependency failures if COR03 has introduced them.
- **Acceptance:** real pinned-Npgsql tests verify the returned result and committed state from another connection for all four operations, including false/no-row/failure cases. Source-string tests alone cannot close it.
- **Migration/rollback:** no schema migration. Rollback restores the defect; do not roll back into a release that relies on functional activation writes. Re-run existing activation tests after rebasing into the trusted-grant workflow.

### COR23B — Remove output-variable ambiguity and execute SQL branches

- **Owns:** R06-02 only. **Depends on:** COR01 and COR02's authoritative SQL delivery path. **Gates:** COR16's authenticator replacement and COR19's activation lifecycle qualification.
- **Files:** both baselines or the schema generation/migration source; `begin_authenticator_app_setup`, `disable_activation`; executable SQL branch regressions.
- **Implementation:** alias table column references in ambiguous branches; check other table-returning functions for the same pattern; preserve status result types and intended predicates. Keep the default PostgreSQL conflict setting.
- **Acceptance:** all listed branch scenarios run under the supported PostgreSQL version/default setting. Assert exact status and durable state, including retained original setup on failed input and replacement of pending secret material on success.
- **Migration/rollback:** function replacements with unchanged signatures can be staged atomically. Schema parity check remains required. A rollback that reinstates ambiguous branches reopens this finding.

### COR23C — Separate enrollment identity from the small display index

- **Owns:** R06-03 only. **Depends on:** COR01/COR02 and coordination with COR15's identity-bound TOTP envelope migration. **Gates:** final enrollment/replay contract in COR16 and COR24.
- **Files:** factor schema/allocator functions; enrollment and reset-TOTP repositories/records/readers; TOTP replay APIs and secret-binding logic; fixtures and migration tests. Inventory all `short TwoFactorIndex` consumers before choosing UUID/bigint.
- **Implementation:** durable new identity, widened/updated function parameters and result types, backfilled stable mapping for existing rows, explicit history policy, fresh identity per enrollment. Reject cross-enrollment replay and preserve secret decryptability. Keep API display ordering separate.
- **Acceptance:** boundary seed succeeds after migration; normal enrollment, replacement, removal and re-enrollment work; concurrent creation stays unique; old secrets and replay markers survive the migration; retired enrollments cannot regain authority.
- **Migration/rollback:** prefer additive identity and a validated dual-read/backfill stage if any existing data must survive. Reverting to smallint allocation is unsafe after new identities exist. For a confirmed disposable greenfield environment, rebuild may be simpler, but deployment/data disposition must be established before selecting that path.

COR22 additionally owns the unmeasured query/index/pool observations above. COR23 must reconcile this report and the three partial test-source dispositions. COR24 requires all findings closed or explicitly dispositioned with runtime evidence and measured budgets; reaching 55 items in a ledger is not feature completion.

## Evidence and next chunk

The cumulative bundle contains R01–R06 reports, latest 451-file inventory and 55-finding ledger, static evidence, evidence builders and blocked validation logs. The R06 builder checks source hashes, both-baseline parity, the reader/commit pattern, ambiguous branch structure, history allocation/revocation, index/ownership observations, test method catalogs, finding ownership and report links. These are structural assertions, not PostgreSQL/Npgsql execution tests.

Next is **R07: HTTP boundaries, hosting, dependency injection, configuration and shared request/response contracts**, following the mapped inventory. The three targeted SQL-test files remain explicitly queued for their complete source audit in R10; performance and database/concurrency closure remain runtime gates.
