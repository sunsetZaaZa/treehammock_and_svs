# Treehammock review R10G — startup, hosting, repository and cache contracts

Reviewed 2026-10-03. Source review and correction-plan addendum only; no application or test code changed.

This chunk completes **15 test suites: 4,009 lines, 202,693 bytes and 136 attributed test methods**. It also completes a fresh source cross-check of the shared cache serializer and both session-cache services. **No new independent findings** are added, and none are closed. The cumulative ledger remains **82 open findings: 18 P1 and 64 P2**.

The suites provide useful configuration, mapping, serialization, failure-mapping and structural checks. This review strengthens existing PR acceptance criteria where those checks do not establish real listener, transaction, cache or concurrency behavior. Ordinary dependency substitution is not counted as a defect.

## Complete source scope

All Unit paths below are under `treehammock.Tests/Unit/`; the startup suite is under `treehammock.Tests/Integration/`.

| Suite | Lines | Facts | Theories | Principal boundary |
| --- | ---: | ---: | ---: | --- |
| StartupConfigurationTests.cs | 408 | 6 | 6 | In-process startup, options binding/validation and one reflection check |
| HostingProfileConfigurationTests.cs | 127 | 5 | 1 | Actual example/profile JSON and option validation |
| HostingSettingsTests.cs | 114 | 4 | 1 | Options binding/validation and forwarded-header option construction |
| HostingStartupContractTests.cs | 75 | 4 | 0 | Source/file-presence assertions |
| LaunchSettingsJsonTests.cs | 40 | 1 | 0 | Strict JSON parsing and profile object shape |
| TreehammockEnvironmentContractTests.cs | 54 | 2 | 0 | Script source/environment naming and removed-file checks |
| AccountControllerSafeRepoWrapperTests.cs | 322 | 9 | 0 | Direct controller calls with throwing repository substitutes |
| AccountRepoBooleanContractTests.cs | 125 | 0 | 4 | Boolean conversion and command-builder helper tests |
| AccountRepoMappingTests.cs | 244 | 6 | 1 | Real credential mapping/constructor and malformed-material checks |
| RepositoryContractTests.cs | 755 | 26 | 0 | Source, reflection, constants and helper contracts |
| RepositoryFailureBoundaryTests.cs | 271 | 8 | 1 | Real repository entry points with connection acquisition replaced by a throw; logging helper/source checks |
| SessionRepoBooleanContractTests.cs | 93 | 2 | 3 | Command builder, typed status mapping, reflection and result records |
| SessionSqlConcurrencyContractTests.cs | 79 | 2 | 0 | Function-scoped SQL regex/text ordering |
| CacheJsonSettingsTests.cs | 602 | 18 | 1 | Real serialization/model behavior and cache service calls with substituted Redis interfaces |
| AccountServiceSetupTests.cs | 700 | 24 | 1 | Actual service/hasher with repository and SMTP substitutes |
| Total | **4,009** | **117** | **19** | **136 source methods; no runtime discovery** |

There are 164 InlineData rows and two MemberData references with 18 literal TheoryData rows in source. These describe source inputs, not a runtime-discovered or passed test count. The evidence JSON records each method, attribute location and data source.

Additional source files completed in this pass:

| File | Lines | Bytes | Qualification |
| --- | ---: | ---: | --- |
| `Rigging/Cache/CacheJsonSettings.cs` | 37 | 1,016 | Complete source cross-check; C# execution pending |
| `Rigging/Cache/ActiveUserCacheService.cs` | 122 | 4,469 | Complete source cross-check; real cache qualification pending |
| `Rigging/Cache/TwoFactorSessionService.cs` | 122 | 4,553 | Complete source cross-check; real cache qualification pending |

`HostingConfigurator`, `RepositoryCommands` and the shared web factory were fully cross-checked with their prior qualifications retained. `AccountRepo`, `Program` and dependency injection were inspected in relevant slices only; no new full-file pass is claimed for those slices.

The original 451-file project remains byte-for-byte identical to the uploaded archive, SHA-256 `229ef2275f1caeff3a6a40186e678f7440a90fd54add2e0ba8de0fd6c645758f`.

## Startup and hosting evidence

`App_starts_with_example_local_config` creates a scoped application factory and client. The shared factory forces the **Testing** environment, clears configuration sources, and loads example plus Testing overlays. This checks the isolated startup contract; it does not start the advertised LocalHttps Kestrel listener, load a deployment certificate, test external dependencies or validate a production environment. Provider/client disposal is explicit in these suites; the separate R10F harness ownership finding remains open.

The missing-section theory covers 13 sections. Production dependency injection registers 17 validated option sections. The missing-section inputs omit `LoginSettings`, `RegistrationSettings`, `SensitiveActionSettings` and `EmailTemplateSettings`. Other tests validate some values in these areas, including zero registration token periods; they do not replace missing-section cases. This is an acceptance refinement under COR01/COR24, not a new production startup defect: the registration helper itself uses section existence, object validation and `ValidateOnStart`.

Hosting profile tests bind real JSON overlays and construct `HostingSettings`. Forwarded-header unit cases check enabled header kinds, forward limit and configured trust lists, including clearing lists for trust-all mode. They do not send trusted/untrusted proxy requests or observe effective client IP/scheme. The ContainerReverseProxy trust-all assertion must remain tied to its isolated deployment assumptions; it does not prove safe public exposure. Existing COR23X addresses stack listener exposure, and COR24 qualifies the deployed trust boundary.

The source tests confirm hosting profile files, configuration key names and Program call sites. Strict launch JSON parsing is useful, but neither file presence nor key presence proves listener ownership, certificate readiness, effective pipeline order or verified public link origin. Keep the actual profile binding tests and supplement them with executed hosting/proxy cases under COR23G/COR24.

Startup fixtures also assert enabled provider flags and accept SMS routing aliases. R08-05/COR23L remains open: routing aliases and flags do not establish required Twilio credentials/sender transport settings. R03-03/COR15 likewise remains open: decoding a 32-byte TOTP protection key does not establish deployment-specific secret safety. Production secret rejection and isolated test capability gating need explicit environment cases under COR15/COR23D.

## Repository and SQL evidence

The boolean suites invoke real conversion helpers and `RepositoryCommands.BuildFunctionSelect`. They check expected SQL strings, typed statuses and invalid function identifiers. They do not construct every repository command, validate live parameter types/order against installed PostgreSQL functions or prove all result branches commit. Keep these fast helper tests and add actual repository contracts under COR02/COR24. Extend identifier tests to unsafe parameter identifiers and empty/no-argument combinations where the helper contract permits them; do not infer a SQL injection finding from missing negative test cases.

Credential mapping tests check values, crypto material dimensions, null refresh state, cutoff and required account security stamp. The test named `rejects_wrong_salt_siv_or_nonce_length` supplies only an invalid salt length. Add separate SIV and nonce cases, plus real reader/result-schema cases, under COR07/COR24. Variable-length password hash material is an intentional positive test and is not classified as an invalid-length production bug.

`RepositoryFailureBoundaryTests` constructs actual repositories but overrides `CreateConnection` to throw before a connection is returned. This establishes the intended controlled acquisition-failure mapping. The setup case even passes a null Account because acquisition is expected to fail first. It does not validate post-open execution, read/decode, commit, rollback, cancellation, pool reuse or eventual transaction outcomes. Preserve this narrow test and qualify the other stages through actual providers under COR03/COR04/COR24.

The direct-controller wrapper suite adds useful no-side-effect checks when repository operations throw: no cache mutation before a failed rotation; controlled preauth failure and cleanup; no active-cache promotion when finalization throws. These use preset exceptions/outcomes, not actual partial commits. Future outage and operation-identity corrections must reconcile the expected status/code mapping and prove persisted authority after late outcomes; do not keep an old expected failure code if it conflicts with the corrected transient-failure contract.

SQL source checks inspect hashed-secret columns, stamp predicates, audit fields, return codes and named functions. The concurrency suite improves on whole-file searches by extracting individual functions and asserting account-before-session text ordering. It still runs no SQL transactions, acquires no row locks and creates no competing schedule. A whole-baseline one-session assertion at RepositoryContractTests lines 74–83 is weaker: matching account and expiry fragments may come from different functions. Both remain supplemental structural checks under COR02/COR09/COR24.

### Reader-lifetime assertion boundary — refine existing COR23A

`AccountRepo_get_credentials_disposes_reader_before_committing_transaction` at RepositoryContractTests lines 33–53 checks reader-start, commit and return text order, presence of Found/NotFound assignments, and absence of two immediate-return formatting patterns. It never establishes the closing boundary of the reader scope. A hypothetical method with this shape satisfies those predicates:

```csharp
await using (NpgsqlDataReader dr = await command.ExecuteReaderAsync())
{
    if (await dr.ReadAsync()) result = CredentialLookupResult.Found(mapped);
    else result = CredentialLookupResult.NotFound();
    await tran.CommitAsync();
}
return result;
```

The evidence builder records a textual counterexample satisfying the exact predicate shapes. It was **not compiled or executed**, and the project was not modified. Actual GetCredentials source currently leaves its nested reader scope before committing at AccountRepo lines 765–820. This review does **not** assert a new GetCredentials transaction defect. The prior activation reader-lifetime finding R06-01 remains owned by COR23A; strengthen its regression coverage and shared qualification criteria rather than adding a duplicate finding for a weak guard.

COR23A already requires actual pinned-Npgsql activation repository tests and durable-state checks from a second connection. Add a regression that fails when commit is moved inside an active reader lifetime, using observable provider behavior or an appropriate structural scope check plus the real repository test. Cover false/no-row, decode failure and rollback paths. Text order alone cannot satisfy reader-lifetime acceptance.

## Cache contract evidence

The cache suite directly invokes `CacheJsonSettings` and actual session models. Its golden JSON and round-trip cases check NodaTime values, enum representation, account/session stamps, hard versus access expiration, selected two-factor state and omission of computed convenience properties. It rejects missing security fields and malformed JSON, and exercises actual cache-service decoding using substitute `IDatabase` and `IConnectionMultiplexer` objects. These are useful serializer/adapter checks, stronger than an object-reference dictionary fixture.

It also distinguishes malformed/legacy payload exceptions from infrastructure read failures, preserving the latter exception rather than labeling it stale payload. Retain that distinction under COR03/COR10. No real Redis-compatible service was contacted.

Separate-database tests check `BuildConfiguration(...).DefaultDatabase` values. Both actual services set that configured default and call `GetDatabase()` without an explicit index. The substitute accepts any database request; this does not demonstrate live active/preauth key isolation. Add actual writes of the same key into the selected databases and verify independent values and revoke/TTL effects under COR03/COR10/COR24. Also validate the selected production Redis-like topology's support for the intended logical database policy.

Cache writes pass serialized payloads and expiration to Redis; renewal calls KeyExpire; revoke treats a deleted or now-missing key as success. Tests cover missing-key and still-present outcomes for two-factor revoke. They do not prove network TTL, renewal deadlines, real deletion races or reconnect/cancellation behavior. The cache services still establish connections through synchronous lazy `ConnectionMultiplexer.Connect`; AUTH-11/COR03 remains open. Setting Redis timeout options and validating positive fallback numbers do not qualify the aggregate application timeout or lifecycle design.

No new cache atomicity or stale-authority finding is added here. AUTH-03, AUTH-06–08 and other existing coordination findings remain governed by their actual transaction/cache schedules, rather than closed by serializer or interface-substitution cases.

## Account service and delivery evidence

The service suite uses real AccountService, token hashing and an Argon2id user-secret hasher, while substituting repository and SMTP operations. It captures account crypto metadata, outgoing URLs, hashed verification tokens, deletion passphrase hashes and requested policy limits. The deletion test additionally confirms the delivered verification sequence hashes to the captured repository token hash. These are useful service-boundary contracts, not durable transaction or actual SMTP submission evidence.

Its hasher uses test work factors of one iteration and `Argon2MemoryUsePer = 8192`; this cannot qualify production password cost, concurrency budget or signup admission. Keep hash/token identity assertions while COR07/COR08/COR11 prove configured cost and admission before expensive work, duplicate claim races and current verification/unlock authority.

Email-change and deletion delivery failure/exception tests expect immediate pending-request cancellation. Existing R08-02/COR23I already identifies unknown acceptance becoming definite non-delivery; COR12/COR17/COR18 also govern nondestructive replacement and durable budgets. Update these tests when typed delivery outcomes land: definite non-submission, unknown acceptance, accepted submission, cancellation and configuration failure must have their specified distinct effects. A thrown SMTP exception alone must not prescribe destruction of potentially delivered proof authority. Preserve explicit security revocation and user cancellation semantics.

Purge tests currently check a supplied time is non-null and map a preset count; they do not prove exact cutoff, bounded batching or retained budgets/audit data. COR18/COR22/COR24 must inspect durable state after cancellation/purge and qualify retention and work limits. Avoid multiplying the existing budget/cleanup findings.

## Detailed acceptance addendum for existing PRs

| Owner | Files to adapt or supplement | Executed acceptance required |
| --- | --- | --- |
| COR23A, COR24 | RepositoryContractTests; actual activation repository SQL tests | Reader lifetime ends before commit; placement/cancel/disable/verify outcomes agree with state queried from another connection; failure/rollback leaves no partial commit |
| COR01, COR24 | StartupConfigurationTests; startup result manifest | All 17 required section absence cases; representative option boundaries; runtime discovery and expected environment-specific startup failures |
| COR15, COR23D, COR23L | StartupConfigurationTests; hosting fixtures | Reject production sample secrets and enabled test capabilities; validate selected provider credentials/sender prerequisites; isolated test settings remain explicitly allowed |
| COR23G, COR23X, COR24 | HostingSettings/Profile/Startup tests; actual hosting/system lane | Exercise profile listeners/certificates and public verification origin; trusted versus untrusted forwarded IP/proto; isolated port ownership; no reliance on source key presence |
| COR02, COR03, COR04, COR24 | RepositoryFailureBoundary/Boolean/Mapping tests; real repository contracts | Installed function signature and result types; missing/malformed rows; execute/read/commit/rollback/cancellation stages; typed unavailable outcomes and connection reuse after failure |
| COR07, COR08, COR11 | AccountServiceSetup and credential mapping tests | Valid production hash format/cost and admission ordering; independent salt/SIV/nonce negative cases; real duplicate/resend/unlock schedules |
| COR03, COR09, COR10, COR24 | CacheJsonSettingsTests; actual Redis/SQL/HTTP contracts | Preserve serializer compatibility and stale versus unavailable distinction; real logical DB isolation, TTL/renewal and current authority; refresh winner/loser and actual lock schedules |
| COR12, COR17, COR18, COR23I, COR23J | AccountServiceSetup delivery and cleanup cases; provider/storage contracts | Distinct definite/unknown/accepted delivery outcomes; bounded cancellation/deadlines; no unsafe proof erasure on unknown outcome; budget continuity across cleanup |
| COR18, COR22, COR24 | Service purge tests; retention/cleanup contracts | Exact cutoff boundaries, bounded batches and counts, durable budget continuity and approved audit retention; performance measured at declared dataset sizes |

These are review-derived acceptance refinements, not new finding owners or implemented changes. Apply test updates with the PR that defines the corrected behavior. Keep focused unit/structural checks, and require the corresponding real provider/storage/system evidence before closing findings. No migration is needed for the source-test refinement itself; migrations and rollback remain governed by the owning production PR specifications.

## Verification and remaining scope

The static evidence builder verifies all 451 source files against the original archive, suite/attribute metadata, 15 source observations, the reader-order counterexample and the inventory/ledger update. It does not simulate C# execution.

Both original Release/locked-restore runners were attempted and exited **127** because the .NET SDK is absent. They stopped before restore, build, discovery and tests. No Kestrel/proxy requests, real PostgreSQL/cache contracts, hash/resource benchmarks or concurrent provider schedules ran. Source inspection does not establish feature completeness, security approval or measured performance.

The Through_10G inventory records 15 R10 files and the three newly completed prior cache files as source-complete, runtime-pending. **23 R10-assigned files remain**, alongside the three partially reviewed R06 SQL suites. This is not a global outstanding-file count: earlier R01–R05 legacy qualification rows and indexed/partial test suites still require individual reconciliation before a whole-project completion claim.

Next is **R10H: remaining API/model/identity contract suites and system account-flow/support files**. Then finish deferred SQL-contract suites, release/API/SQL documentation, remaining observability/HTTP configuration and dependency binary qualification. Runtime/performance qualification remains required across those areas.

The cumulative bundle retains earlier reports/evidence and updates the current ledger/inventory to Through_10G. Original design/PR-plan Word documents are unchanged; this report is their correction-acceptance addendum.
