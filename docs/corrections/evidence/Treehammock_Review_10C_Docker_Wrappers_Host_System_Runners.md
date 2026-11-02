# Treehammock review R10C — Docker wrappers and host/system runners

Reviewed 2026-10-03 against the unchanged uploaded source. This chunk is a **source review and correction-plan addendum**, not implementation. Application files and original source permissions remain unchanged.

R10C adds **four P2 findings**, bringing the ledger to **80 open findings: 18 P1 and 62 P2**. No prior finding is closed. Complete source inspection now covers the 36 selected R10C files; **57 R10-assigned files and three partial R06 SQL test files remain**. No chunk is declared runtime-qualified.

## Scope and evidence

| Selected surface | Complete source inspection |
|---|---|
| Runtime wrappers | Bash and PowerShell variants of docker-all-runtime-up, docker-api-direct-up, docker-api-proxy-up, docker-api-proxy-scale, docker-postgres-up, docker-dragonfly-up and docker-infra-up |
| Test wrappers | Bash and PowerShell variants of docker-all-tests, docker-sql-contracts, docker-http-contracts-direct, docker-http-contracts-proxy, docker-system-stack-tests and docker-host-system-stack-tests |
| Help/cleanup | Bash and PowerShell docker-help and docker-down; docker-host-system-stack-tests.cmd |
| Supporting tests | DockerDeveloperWrapperScriptsTests.cs, DockerHostSystemStackTests.cs, DockerHttpDirectRunnerTests.cs, DockerHttpProxyRunnerTests.cs and DockerSqlContractRunnerTests.cs |

That is 15 Bash scripts, 15 PowerShell scripts, one CMD launcher and five C# test classes: 36 files and 1,754 source lines. Existing Docker CLI selection/image helpers, Compose/HAProxy configuration, the system test project reference and CI cleanup clauses were cross-checked. README and the command guide received targeted instruction/claim checks; they remain scheduled for full document review.

**Thirty-six isolated copied-fixture checks** cover 15 Bash syntax checks, 12 final Compose failure-propagation cases, four host-runner lifecycle scenarios and five stop-at-failed-lane cases in the actual Bash all-tests wrapper. Docker, dotnet and curl are disposable stubs. The partial-startup resource is a local marker, not a real container or volume. No network requests, image builds, database/cache operations, application tests or PowerShell execution occurred.

The original host runner was attempted and exited 1 at absent Docker CLI selection, before startup or teardown. dotnet, pwsh, powershell.exe, Docker, PostgreSQL/psql and redis-server are unavailable. Real process-tree shutdown, peer-network reachability, Compose mutation and PowerShell portability remain unqualified. No performance measurements were made.

The five inspected test classes check source strings/file presence. Their assertions do not execute the wrappers, establish per-run resource ownership or prove that a healthy endpoint belongs to the API launched by the current checkout. In particular, checking ErrorActionPreference text does not establish native fail-fast behavior, and the host test currently asserts the problematic powershell.exe invocation.

## Findings

| ID | Priority | Finding | Correction owner |
|---|---|---|---|
| R10C-01 | P2 | System runners reset a shared Compose project and delete volumes without per-run ownership. | COR23Y |
| R10C-02 | P2 | Host cleanup is registered after startup, missing partial-startup failure. | COR23Z |
| R10C-03 | P2 | Host proof can pass after its launched API exits because readiness is not tied to that run. | COR23AA |
| R10C-04 | P2 | The PowerShell host runner unconditionally requires the legacy Windows executable. | COR23AB |

### R10C-01 — Test teardown can destroy another local run's state

**Evidence.** eng/docker-system-stack-tests.sh:31–39 and its PowerShell counterpart call down --volumes --remove-orphans before running tests. eng/docker-host-system-stack-tests.sh:55–56,65 and .ps1:98–100,268 use the same destructive options before/after the host lane. They do not allocate a private project name or verify resource ownership. The integration and local-system Compose files reside in the same source directory and have no top-level project name or external-volume protection.

The [Compose project-name contract](https://docs.docker.com/compose/how-tos/project-name/) makes that directory the default project identity, unless an explicit name/environment override is supplied. The [down contract](https://docs.docker.com/reference/cli/docker/compose/down/) removes declared named volumes with --volumes and other same-project service containers with --remove-orphans. Separate files/profiles in one directory do not provide a separate project namespace.

**Impact and limit.** The container-system lane can remove integration volumes used by the developer's PostgreSQL/Dragonfly wrappers. The host lane removes its declared local fixture volumes and can stop/remove other same-project containers as orphans; it does not thereby prove deletion of differently named integration volumes absent from its configuration. Concurrent test runs can reset each other's state or break a running developer stack. A caller-provided COMPOSE_PROJECT_NAME can reduce interference, but the scripts neither require a fresh test identity nor establish ownership. Disposable CI agents can make the risk less consequential; these commands are also advertised for local use.

Fixed ports 5001/8080/5432/6379, shared .artifacts host logs and the default .docker image-override path introduce further cross-run collisions. Network publication itself remains R10B-05/COR23X. This finding owns **resource ownership and destructive lifecycle**, not another count for wildcard exposure. Real volume deletion and concurrent Docker execution were not attempted; the conclusion combines source arguments with the documented Compose contract.

**Correction.** Allocate a private test-run project/resource identity, separate it from persistent development stacks, and carry the exact identity through all lifecycle commands. Namespace result/configuration files and provide a deliberate port allocation or serialization contract for host-backed lanes. Teardown may delete only positively owned disposable resources. Never infer ownership merely from a matching service name or directory. Keep the explicit developer docker-down --volumes command available with clear intent; do not silently turn a test into a reset of unrelated development state.

**Required regression.** Seed a developer project with a sentinel account/volume, run each system lane, and verify the developer project is unchanged. Run two isolated test projects simultaneously and cancel one; the other must remain functional. Check resources, keys, ports and output files as well as Compose names. Validate lifecycle recovery and ownership on Linux/Desktop/supported CI daemons. Use only disposable resources for deletion tests.

### R10C-02 — Partial host startup occurs outside cleanup

**Evidence.** The Bash host runner calls Compose up -d at line 57, then defines cleanup and installs its EXIT trap at 59–67. With set -e, a nonzero up result exits before the trap exists. Compose startup is not an atomic operation; some resources may have started before a later service fails. The PowerShell runner likewise starts Compose at 100 before entering try at 170/finally at 263.

**Reproduction.** The copied Bash fixture records a simulated resource on up, returns 37, and observes only the initial down call. No exit cleanup executes and the disposable marker remains. By contrast, failure of restore after the trap is installed triggers a second down and returns 37. These are real shell-control-flow observations with fake Docker, not observed Docker resource leakage.

**PowerShell qualification.** Earlier native-command exit handling remains R10A-01: a default PowerShell native up failure may be ignored and continue instead of throwing. The ordering defect applies when startup terminates/throws, and becomes essential when COR23Q adds reliable native failure propagation. An unchecked command must not be used to argue that cleanup coverage is correct.

**Impact.** A failed local startup can leave containers/ports/volumes active and confuse the next run. Existing CI always/after_script teardown provides an outer mitigation, which does not fix standalone local execution. A process killed without a catchable cleanup path also requires later owned-resource recovery; no trap/finally can promise cleanup after every hard kill.

**Correction.** Establish run ownership and install cleanup before the first resource acquisition. Track partial acquisition, make cleanup idempotent, and preserve the primary failure code even if cleanup fails. Capture diagnostics before destruction. Bound process/service shutdown and add narrowly scoped recovery for abandoned owned runs. Coordinate with COR23Y so earlier cleanup cannot widen deletion of unowned resources.

**Required regression.** Fail each startup/acquisition point, including partial Compose startup, restore, API spawn, readiness and final tests. Verify owned cleanup, primary result preservation, bounded shutdown and readable diagnostics. Exercise supported interruption paths and cleanup failure. Then reproduce partial failures with actual disposable Docker resources and real host process trees. Do not count a simulated marker as real lifecycle qualification.

### R10C-03 — A responding readiness URL does not prove the launched API is alive

**Evidence.** The Bash host runner backgrounds dotnet run at 140, stores its PID at 141, waits on a fixed readiness URL at 143 and runs tests at 145. It never observes that child's startup/exit status before testing. Its kill -0/wait calls exist only inside cleanup. PowerShell Start-Process at 242–248 similarly proceeds to fixed-URL readiness at 250; HasExited is checked only in finally. Both use fixed host API/proxy ports with a shared fixture key.

**Reproduction.** In the copied Bash fixture, fake dotnet run exits 37, fake curl reports readiness success and fake dotnet test succeeds. The host wrapper returns 0. This proves that the shell accepts a successful endpoint/test response despite failed launch; no real API or passing system tests were used. The fixture does not model the full dotnet child process tree.

**Inferred failure scenario.** If an existing compatible API owns port 5001, the current checkout's API can fail to bind while HAProxy/readiness reaches the existing instance. Tests can consequently run against a different build. A fixed-key-compatible instance makes that scenario plausible without assuming a malicious service. This is a host startup/qualification defect distinct from R10B-02's incorrect release metadata. A readiness 200 by itself also cannot bind state or configuration to the intended test run.

**Correction.** Build the expected application explicitly, launch the corresponding artifact, and monitor its lifecycle while waiting and testing. Reserve isolated endpoints through COR23Y/COR23X, fail promptly on owned-process exit, and verify a safe run/build identity through the intended proxy path. Keep fixture identity private/test-gated; do not expose secrets or unrestricted debug metadata in production health responses. Recheck process/target ownership during the test period and propagate any early API exit as proof failure.

**Required regression.** Put a healthy old fixture API on the default port, force the new API to fail to bind, and prove the lane fails before testing the old instance. Test startup errors, exit during readiness/tests, proxy pointed at the wrong instance and mismatched build/run identity. Verify successful lanes use the intended current artifact and state. Include actual .NET/Docker runs with loaded assembly/source identity evidence alongside command-flow fixtures.

### R10C-04 — The PowerShell host lane switches to an unconditional Windows-only dependency

**Evidence.** eng/docker-host-system-stack-tests.ps1:84 invokes powershell.exe to run check-locks. The launcher chooses pwsh.exe when available at CMD lines 5–12, and the script itself guards execution-policy changes by Windows platform at PS lines 14–16, yet its child-host choice is unconditional. README advertises PowerShell equivalents by filename; DockerHostSystemStackTests.cs explicitly asserts the powershell.exe command rather than testing host behavior.

The [PowerShell CLI contract](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pwsh?view=powershell-7.6) distinguishes pwsh from the Windows PowerShell 5.1 executable. Microsoft also documents [supported Linux installations](https://learn.microsoft.com/en-us/powershell/scripting/install/linux-overview?view=powershell-7.6). A functioning pwsh environment with Docker/.NET does not establish that powershell.exe exists. The script can fail on a non-Windows host, and the CMD preference for modern PowerShell does not keep the child step on that selected host. This is source/contract-derived; PowerShell is unavailable for reproduction.

**Correction.** Invoke the prerequisite in the current PowerShell process where practical, or resolve a supported executable from the current host and platform. Keep any execution-policy bypass limited to its documented Windows process scope. Declare the supported host matrix and check all prerequisites before resource mutation, including curl for the Bash readiness path. If the product deliberately supports only Windows for this variant, reject other hosts clearly before any pulls/startup and state the restriction; do not advertise an unrestricted equivalent while requiring an undeclared executable.

**Required regression.** Execute the wrapper under supported Windows PowerShell/pwsh hosts and pwsh-only Linux/macOS environments where those are supported. Remove powershell.exe from lookup, verify intended current-host lock audit invocation, and assert failed/missing prerequisites stop before acquisition. Check direct .ps1 and CMD entrypoints, paths containing spaces and sanitized diagnostics. Native error propagation stays with COR23Q; a string-presence test is insufficient.

## Existing findings and practical limits

| Area | Review result and ownership |
|---|---|
| Outer Bash failures | Twelve copied wrappers returned the injected final Compose failure 37. The all-tests wrapper stopped at each failed lane and skipped later lanes. This qualifies shell flow only, not discovery/execution of app tests. |
| PowerShell native results | Most wrappers still rely on ErrorActionPreference/StrictMode without immediate native exit checks. The host runner does check its final test exit; pulls also check exit codes. Earlier info/restore/Compose/lock child stages remain part of R10A-01/COR23Q rather than a new finding. |
| Inner Compose prerequisites | Outer wrappers cannot repair R10B-04's ignored readiness/restore errors. COR23W still owns fail-fast inner commands, bounded HTTP waits and real result/discovery requirements. |
| Host exposure and proxy trust | Both host scripts bind the API to 0.0.0.0, use fixed known test keys and trust all forwarded proxy peers. Existing COR23X/COR23D and hosting work must include those runtime overrides. No second wildcard-exposure finding is added. |
| Environment restoration | The PowerShell host script snapshots and restores all process-environment keys it changes within the guarded body. Structural checks confirm the key sets match. Actual restoration under errors/entry modes remains unexecuted. Bash exports are scoped to its invoked process; sourcing these executable wrappers is not an advertised usage. |
| Readiness timing | Host variants have a 120-second loop budget and five-second request timeout, unlike the unbounded individual inner Compose requests. Retry and request timing can overshoot the nominal loop deadline; COR23Z/AA should define a monotonic aggregate budget. No measured timing guarantee is made. |
| Scaling contract | The scale wrapper accepts arbitrary numeric replica counts while the checked HAProxy server-template has eight backend slots. Validate or document the supported range and qualify DNS/backend participation before promising arbitrary scale. This is recorded as an acceptance/design limit, not a measured performance regression or another counted defect. |
| Manual runtime lifecycle | Long-running up wrappers deliberately leave services running; explicit docker-down is documented. One-shot Compose run --rm removes its runner, not every dependency. Do not count that intentional developer workflow as a leak; test ownership/cleanup policy must be explicit. |
| Base/CLI policy | Bash selects a usable Docker CLI, handles cached images and disables implicit SDK-runtime fallback in CI unless explicitly opted in. PowerShell parity/configured base behavior remains qualification work. COR23U owns release input/artifact consistency. |
| Mode/permissions | No defect is inferred solely from uploaded ZIP mode loss. Copied fixture scripts are made executable; original source modes and bytes remain unchanged. CMD returns the selected host's exit code and uses its script directory; actual Windows invocation is pending. |

No application correctness, production isolation, real cleanup, throughput, latency or release completeness claim is inferred from the copied fixtures. Performance qualification stays with COR22/COR24; retained security/state findings remain open.

## Correction design and detailed PR-plan addendum

Append **COR23Y, COR23Z, COR23AA and COR23AB** to the existing correction plan. These are detailed PR specifications, not implemented/opened PRs. Trusted-grant activation remains the accepted product decision. The original Word design/PR documents have not been rewritten.

### COR23Y — Give test runs owned, isolated resources

- **Owns:** R10C-01. **Depends on:** coordinate COR23X host/network profile design; align COR24 run/result identity. Can precede application fixes.
- **Files:** container/host/all-tests runners, Compose profiles, generated override/result plumbing and lifecycle documentation/behavioral fixtures.
- **Implementation:** create a validated unique test project/run ID; separate disposable test and persistent developer identities. Pass the same explicit project ID/files through every operation and teardown. Namespace artifacts and generated overrides. Allocate restricted host ports or serialize an explicitly supported host lane. Label/manifest ownership and remove only owned test resources. Keep deliberate developer reset commands distinct in behavior and documentation.
- **Acceptance:** sentinel developer state survives tests and cleanup; two concurrent test runs cannot reset or overwrite each other. Cancellation of one preserves the other. Verify namespace, state, keys, ports, artifacts and merged configuration on supported daemons. Assert no broad/prune/default-project deletion occurs in test failure paths.
- **Migration/rollback:** introduce test identities without migrating or deleting developer volumes. Explain legacy fixture cleanup as an explicit targeted action. No production schema migration. Rollback may restrict concurrency temporarily while retaining ownership-safe deletion.

### COR23Z — Cover acquisition failures with bounded owned cleanup

- **Owns:** R10C-02. **Depends on:** COR23Y ownership; COR23Q native failure contract. Coordinate COR24 diagnostic retention.
- **Files:** Bash/PowerShell host runners, reusable acquisition/cleanup helpers if useful, outer CI safety cleanup and lifecycle failure fixtures.
- **Implementation:** prepare an owned run manifest and cleanup boundary before acquisition; track partial resources/API process trees. Preserve the original error/result independently of teardown, collect bounded diagnostics, perform idempotent cleanup with time limits, and provide narrowly scoped abandoned-run recovery. Restore process environment despite cleanup failure. Distinguish deliberate retained-debug resources from a successful cleanup claim.
- **Acceptance:** each acquisition/startup/restore/readiness/test failure triggers owned cleanup and a nonzero primary result; injected cleanup failure cannot turn the run green or hide the initiating failure. Supported interrupts clean up within budget. Real partial Compose startup and .NET child lifecycle are qualified, not just local markers.
- **Migration/rollback:** no data migration; enable cleanup only for resources owned under the new identity contract. Keep outer CI safety cleanup using that same identity. Rollback can retain owned resources with an explicit failure diagnostic, never delete unowned resources to achieve a clean report.

### COR23AA — Prove the host lane tests its launched application

- **Owns:** R10C-03. **Depends on:** COR23Y isolated endpoints, COR23Z lifecycle monitoring; coordinate COR23U artifact identity and COR24 qualification. COR23D must gate any fixture-only identity surface.
- **Files:** host runners, explicit application build/launch commands, safe test-only run/build identity plumbing, readiness checks and executable wrong-target regressions.
- **Implementation:** build and launch the exact intended assembly/configuration; record its identity in the run manifest. Track owned process exit continuously during startup/tests, bind expected proxy/endpoint identity to the run, and fail promptly on launch/early exit or mismatched target. Avoid accepting arbitrary successful HTTP responses. Define one aggregate monotonic startup budget and useful sanitized failure output.
- **Acceptance:** healthy old-process/port conflict, startup exception, wrong proxy target, exit during readiness/tests and mismatched identity all fail proof. Successful real runs establish current artifact, process, endpoint and backing-state identity and produce fresh expected test results. No production secret/debug leakage is introduced.
- **Migration/rollback:** fixture identity exists only under the safe test capability contract; update runner and fixture together. No production database migration. A rollback must preserve fail-on-launch failure, isolated targeting and honest qualification status.

### COR23AB — Use the declared PowerShell host and verify prerequisites

- **Owns:** R10C-04. **Depends on:** COR23Q native invocation policy; coordinate COR23Z lifecycle and supported-host matrix.
- **Files:** PowerShell host runner, CMD launcher if required, lock invocation/host-selection helper, Bash tool preflight, DockerHostSystemStackTests and command docs.
- **Implementation:** call lock audit in the current host or an explicitly resolved compatible child executable. Keep Windows-only process policy handling conditional and avoid switching hosts implicitly. Check supported platforms, Docker/Compose, .NET, readiness tools and required configuration before mutation. Replace the test that demands the legacy executable string with behavioral host/result checks.
- **Acceptance:** supported Windows/pwsh-only Unix entrypoints use the intended host, handle paths with spaces and propagate missing/failed prerequisites before acquisition. Unsupported hosts get a clear early diagnostic. CMD continues forwarding the selected host's result without changing machine-wide policy.
- **Migration/rollback:** publish the supported host/version contract and update command instructions together. No schema migration or global execution-policy change. If a host cannot be supported, disable that variant explicitly and retain a working documented alternative rather than silently invoking an absent tool.

## Completion and next chunk

The cumulative 48-member bundle retains prior reports/evidence and adds this report, source assertions, copied Bash flow evidence, the blocked original runner attempt, reproducible builder and the latest 80-finding ledger/451-file inventory. Every source file is checked against the original archive; no runtime-qualified chunk or closed finding is asserted.

Next is **R10D: remaining authentication/controller test contracts and in-process test infrastructure**. The 57-file R10 remainder also includes system tests, documentation/feature matrices, operational dashboard and binary qualification; the three partial R06 SQL test files remain explicit obligations. Feature completeness requires their review plus implemented corrections or accepted dispositions, real state/fault/concurrency tests, verified release artifacts and measured performance budgets.
