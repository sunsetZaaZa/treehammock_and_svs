# Treehammock review 10A — Build, dependency graphs and local validation

Reviewed 2026-10-03 against the unchanged uploaded source. **Three new P2 findings; cumulative: 71 open findings, comprising 18 P1 and 53 P2.** No finding is closed and no application changes were made.

R10 is divided into subchunks because its 155 assigned files include large test suites and several independent delivery/operations surfaces. R10A covers **33 files**: four project files, four complete package-lock graphs, two shared build/package property files, two solutions, eight Bash/PowerShell runner pairs and five C# tooling/dependency contract test files. There are **122 R10-assigned files remaining**, plus the three partial R06 SQL-test files already carried forward. Next is **R10B — CI, release, container and deployment tooling**. Deployment/CI snippets consulted here remain cross-checks, not a declaration of complete pipeline review.

## Evidence and qualification

All source files still match the original archive's exact 451-file set and hashes. The actual unit runner exited **127 before restore/build/test** because the .NET SDK is unavailable. PowerShell, Docker, PostgreSQL tools and Redis server are also unavailable. Consequently the PowerShell failure scenario, real Sandbox build/test and coverage collector invocation are source/contract-derived findings, not reproduced application runs.

The separate tooling experiment runs copied Bash scripts with a fake dotnet executable in a disposable directory. It checks eight scripts for syntax, twelve stop-on-failure cases, argument forwarding and missing-lock rejection: **22 isolated checks**. These exercise shell control flow and command arguments only; they do not compile code, discover tests or validate PostgreSQL/cache behavior. Fixture scripts are made executable because the uploaded ZIP records no Unix modes. Source files/permissions are left unchanged.

The four lock graphs were completely parsed: **104 application entries and 182 entries in each test graph**, with 306/631/631/631 dependency edges. Checks cover node references, direct/central-transitive pin agreement, minimum version constraints and valid SHA-512 checksum encoding. All three test lock graphs are identical. This does not prove downloaded package hashes, availability, compatibility, absence of advisories or selected platform assets. Full dependency security/native-asset qualification remains open.

## Findings

| ID | Priority | Defect | Correction owner |
|---|---|---|---|
| R10A-01 | P2 | PowerShell validation/proof runners can continue after native command failures. | COR23Q |
| R10A-02 | P2 | Coverage switches request a collector that the package policy excludes. | COR23R |
| R10A-03 | P2 | Sandbox builds produce Debug test output but no-build runners request Sandbox output. | COR23S |

### R10A-01 — PowerShell proof does not reliably propagate failed stages

**Evidence.** `eng/validate.ps1` invokes dotnet info, restore, build, unit tests and integration tests without checking native exit codes. `eng/dotnet-unit-tests.ps1`, `eng/dotnet-integration-tests.ps1`, `eng/sql-contracts.ps1` and `eng/restore-locks.ps1` have the same pattern. `$ErrorActionPreference = 'Stop'` is set, but none of these scripts checks `$LASTEXITCODE` or establishes `$PSNativeCommandUseErrorActionPreference`. The build/release proof wrappers delegate without a fail-fast native-command contract. Restore-locks can proceed to checking existing locks and printing completion even after failed restores.

The [PowerShell native error contract](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_error_handling?view=powershell-7.6) distinguishes native process exit codes from PowerShell error records. The [7.4 preference documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_preference_variables?view=powershell-7.4) gives PSNativeCommandUseErrorActionPreference a default of false. An external host/profile can enable it, but these committed scripts do not require that setup. Missing executables and actual cmdlet exceptions can still stop; the defect concerns installed native tools returning nonzero.

**Inferred impact.** Failed restore/build/unit stages can be followed by later successful commands. For example, unit failure followed by successful integration can leave the overall proof apparently successful; stale output can also be tested after a failed build. Shell entry mode and final command affect the eventual process exit, so not every failure is guaranteed to return zero. The scripts nevertheless fail to enforce the required first-failure stop and reproducible result. Bash uses set -e and passed the isolated injected-native-failure cases; this distinction is not claimed as actual PowerShell execution.

**Correction.** Introduce a small shared native invocation helper that captures the exit code immediately and throws/returns a nonzero top-level result on failure. Alternatively require and validate a supported PowerShell version/native-error preference, with explicit exit checks where compatibility requires them. Apply the policy to each stage and nested proof wrapper. Preserve command context and code without exposing credentials. No later stage should run after a failed prerequisite, and completion messages should require successful work.

**Required regression.** Run an executable fixture returning a chosen nonzero code at info, each restore, build and each test stage. Assert no later commands run and direct pwsh -File invocation returns failure. Exercise nested build/release proof and lock refresh under every supported PowerShell host, including Windows PowerShell 5.1 if it remains supported. Verify failed unit tests cannot be masked by passing integration/SQL tests, and existing lock files cannot convert failed refresh into success. Then run real failing and passing .NET fixtures on Windows/Linux PowerShell; source-string assertions alone are insufficient.

### R10A-02 — The coverage option cannot activate its named collector

**Evidence.** Bash and PowerShell validate/unit/integration runners add `--collect "XPlat Code Coverage"` when the coverage switch is enabled. None of the four project/lock graphs includes coverlet.collector. `treehammock.Tests/Unit/ProjectDependencyBoundaryTests.cs` explicitly puts coverlet.collector in RemovedTestPackages and asserts its absence. Microsoft.CodeCoverage 17.14.1 is present transitively through the test SDK, but it is a different collector.

The [Microsoft coverage documentation](https://learn.microsoft.com/en-us/dotnet/core/testing/unit-testing-code-coverage) identifies XPlat Code Coverage as Coverlet's friendly name; the Microsoft collector uses Code Coverage. The [Coverlet VSTest integration contract](https://github.com/coverlet-coverage/coverlet/blob/master/Documentation/VSTestIntegration.md) requires the matching test-project collector dependency. These runners do not supply an external adapter/collector path or an equivalent package configuration.

**Inferred impact.** The coverage switch does not deliver the requested Coverlet result from the committed dependency setup. VSTest can report a missing collector without giving the desired artifact; exact warning/exit behavior needs execution with the pinned SDK/adapter. A successful test exit must not be treated as proof that coverage was collected. An externally provisioned collector could change behavior, but it is not part of this reproducible project configuration.

**Correction.** Choose and document one compatible collection contract. Either add a pinned, private test-only Coverlet collector and revise the explicit removal policy, or select the supported Microsoft collector and its artifact format. Keep the xUnit/VSTest versus Microsoft.Testing.Platform mode explicit; do not mix incompatible flags/extensions. When coverage is requested, require a fresh, parseable coverage artifact with expected nonempty modules/source data and report failures clearly. Keep collectors out of the runtime application dependency closure.

**Required regression.** Run coverage-enabled unit and integration lanes from a clean checkout on supported platforms; assert actual collection and artifact shape, not just flag forwarding. Disable/remove the selected collector and verify the coverage lane fails instead of silently publishing nothing. Test stale artifacts, failed tests, collector errors and unique result paths. Check a small fixture with known executed/unexecuted branches so a placeholder or empty report cannot satisfy the gate. Test-only dependency privacy must remain enforced.

### R10A-03 — Sandbox no-build test paths disagree with the solution build

**Evidence.** `treehammock.sln` maps the test project's Sandbox ActiveCfg and Build.0 to Debug. `eng/treehammock.SqlContracts.sln` does the same for its SQL test project. The application is mapped to Sandbox. The validation/unit/integration/SQL runners build those solutions with the requested configuration, then invoke dotnet test directly on the test project with that same configuration and `--no-build`. Their interfaces explicitly accept Sandbox. Test projects have no output-path override redirecting Sandbox to Debug.

The [dotnet test VSTest contract](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-test-vstest) makes configuration determine the test output location and states that no-build skips producing it. Solution mapping and direct project configuration are therefore different inputs in this sequence.

**Inferred impact.** In a clean Sandbox lane, the solution creates Debug test binaries while the direct no-build invocation looks for Sandbox output. The intended tests cannot reliably execute from the build just performed. If a stale Sandbox output directory exists, it can instead run old binaries. Release/Debug mappings are aligned; default CI Release runs are not asserted to suffer this specific defect. The Bash experiment confirms Sandbox/no-build forwarding; a real clean SDK build is still required to reproduce the output-path effect.

**Correction.** Use consistent solution/project configuration and output identity. Map test Sandbox to Sandbox, or deliberately build/test projects with the declared test configuration and explain how the application reference is configured. Reject unsupported configurations rather than silently falling back. Retain no-build only when the exact matching output has just been built. Apply the same contract to Docker/unit and future proof lanes, with no accidental testing of a different application assembly.

**Required regression.** Remove bin/obj, then run Debug, Release and Sandbox through all supported local runners and the SQL lane against a disposable database. Capture MSBuild configuration/output paths and the test assembly actually loaded. Assert the tested application/test pair comes from the current checkout/configuration, not stale Debug/Sandbox files. Include a deliberately stale output fixture and verify it cannot satisfy the proof. Validate Bash and PowerShell argument/configuration behavior together with COR23Q.

## Positive checks and remaining work

| Surface | Source result and practical limit |
|---|---|
| Dependency management | Central versions are explicit, unique and stable; project references use the central pins without local version overrides. Four lock files exist and their graph structure is consistent. The local lock audit checks presence only; locked restore supplies semantic enforcement when an SDK is available. |
| Runtime/test boundaries | Test dependencies are private and excluded from application compile/content globbing. The three test project files are structurally identical except identity. Their broad repeated package lists should be simplified only after actual restore/asset qualification. |
| SDK policy | global.json requests .NET 8.0.100 with latestFeature roll-forward and excludes prereleases. This allows newer .NET 8 feature bands but does not itself establish that an installed SDK/runtime is patched. CI setup snippets request 8.0.x. Actual SDK/package restore/build remains unqualified. |
| Support lifecycle | On the review date, .NET 8 is supported in maintenance and its published end of support is **2026-11-10**. The [official support table](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core) reports 8.0.31 as the current patch. Plan a supported framework/runtime migration before that deadline and audit the project's 8.0.27 ASP.NET package pins. Version age alone is not recorded here as a proven vulnerability. |
| Legacy package closure | System.Net.Http/System.Text.RegularExpressions package references bring a broad older System.* and platform-native graph. Investigate removal where net8 supplies the API, comparing restored/published assets and behavior first. Old lock entries do not establish that the runtime loads those old assets or that a CVE is reachable. |
| Runtime tuning | The application sets server GC, disables concurrent GC, fixes thread-pool min/max and sets invariant globalization/IPv6 behavior. Benchmark against defaults under Argon2, SQL/cache outage and delivery workloads before treating those settings as performance improvements. They are not measured regressions in this pass. |
| Vendored assembly | CityHash_103.dll is a referenced managed PE32 assembly with a .NET Framework config companion, and no source usage was found in the searched code. PE format alone does not prove Windows-only behavior. Package locks do not cover this binary's provenance/license/API/platform behavior; full binary audit or justified removal remains pending. |
| Tooling portability | Bash scripts stop on injected native failures; lock audit rejects a missing file. restore-locks.sh has a UTF-8 BOM before the shebang: normalize script encoding and verify direct invocation on supported shells. ZIP Unix mode absence needs an explicit executable-bit/setup policy; CI snippets currently chmod scripts. No new production failure is inferred solely from archive mode loss. |
| Test contract strength | Reviewed tests largely check file text, names, package lists and absence of TODO/placeholder strings. Those checks do not qualify native exit propagation, actual collector output, loaded configuration or feature completeness. Add behavioral tooling tests and retain their useful architectural boundaries. |
| Deferred release surfaces | Full CI/release dependency gating, container publishing/provenance, image/base pinning, secret handling, deployment readiness/edge configuration and operational documentation are R10B or later. System/integration coverage and the three large R06 SQL test files remain explicitly pending. |

No latency, memory, throughput, vulnerability-free or release-complete claim is made. COR22 owns measurement and retention budgets; COR24 remains the final real-system qualification gate.

## Detailed correction-plan addendum

Prior addenda supplied COR23A–P. Add **COR23Q–S** below to the correction plan. These are PR specifications, not implemented/opened PRs. The trusted-grant activation decision and original design remain unchanged. Original Word planning documents have not been rewritten.

### COR23Q — Make validation failures stop every proof runner

- **Owns:** R10A-01. **Depends on:** tooling host/version policy; coordinate qualification orchestration with COR24. This can ship before application fixes.
- **Files:** all PowerShell validation/restore/build/test/proof scripts, a shared native invocation helper, executable runner tests and supported-host documentation. Extend the audit to remaining Docker/release PowerShell wrappers in R10B.
- **Implementation:** immediate native exit capture, sanitized stage/code errors, explicit nonzero top-level propagation and first-failure stop across nested scripts. Avoid shell-profile-dependent behavior and completion output after failure.
- **Acceptance:** the injected stage matrix and real failing fixtures pass under each supported host and entry mode; later successful stages cannot mask a failure. Existing passing lanes remain usable; Bash and PowerShell share the same proof semantics.
- **Migration/rollback:** publish minimum supported PowerShell version or preserve compatible explicit exit checks. No database migration. A wrapper rollback must retain failure propagation; never accept a green result from an unchecked failing stage.

### COR23R — Deliver a real coverage collection contract

- **Owns:** R10A-02. **Depends on:** collector/test-platform selection; coordinate COR23Q and COR24 artifact policy.
- **Files:** central package versions and test project/lock files if adding a collector; coverage flags in runners, dependency-boundary tests, result/artifact checks and test-command documentation. CI collection/upload integration follows in its pipeline owner work.
- **Implementation:** compatible private test-only collector or correct existing collector name, explicit format/output location, clean per-run artifact identity and mandatory parse/content validation whenever collection is requested. Update the test that currently forbids Coverlet if that route is selected.
- **Acceptance:** clean unit/integration lanes produce a parseable nonempty coverage artifact on supported systems. Missing collector and stale/empty output fail the coverage contract; test failures still fail. A known-branch fixture verifies actual measurement and application publish has no test collector dependency.
- **Migration/rollback:** commit regenerated locks with the package/tool choice and update consumers to the declared format. No schema change. If collector compatibility breaks, fail or explicitly disable the optional feature with an honest diagnostic; do not claim coverage was collected.

### COR23S — Align build and test configuration identity

- **Owns:** R10A-03. **Depends on:** COR23Q runner reliability; coordinate Docker configuration handling and COR24 proof artifacts.
- **Files:** both solution configuration maps, test project/configuration policy as needed, local and Docker test runners, loaded-assembly/path tests and configuration documentation.
- **Implementation:** one explicit build/test configuration contract, corresponding no-build output checks, and deliberate application-reference configuration. Remove unsupported choices or give them fully aligned mappings; prevent stale binaries from satisfying a fresh proof.
- **Acceptance:** clean Debug/Release/Sandbox lanes run the newly built intended application/test assemblies in Bash and PowerShell. SQL runs use an isolated disposable database. Stale output cannot substitute for a missing current build.
- **Migration/rollback:** invalidate incompatible cached build output and update runner/solution maps together. No data migration. Rollback may remove Sandbox support explicitly, but cannot retain a mismatched advertised lane.

## Deliverables and next chunk

The cumulative bundle retains R01–R09 reports and evidence, adds this report, the complete structural graph evidence, the isolated Bash flow evidence, the blocked real validation attempt, a reproducible builder and the latest inventory/71-finding ledger. The ledger records R10A without declaring all of R10 complete. Previously opened findings remain open.

Next review CI/release/container/deployment tooling as R10B, then continue through remaining test suites and operational/documentation contracts. Preserve the 122-file R10 remainder and the three partial R06 files as explicit coverage obligations. Complete release qualification requires implemented corrections or accepted dispositions plus real builds, tests, state/fault/concurrency evidence and measured budgets.
