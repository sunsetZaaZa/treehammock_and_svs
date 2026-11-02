# Test Command Guide

This guide explains the purpose, feature set, strengths, and tradeoffs of the common validation commands used in this project.

Use this when deciding whether you need a quick local correctness check, focused integration coverage, or a production-like system-stack smoke run.

## Source reconciliation and qualification commands

`python3 eng/reconcile-source-inventory.py --check` checks source mapping consistency. `--require-qualified` exits 2 while source/native/release obligations remain open. Neither a static index nor a source-declared test count proves discovery, coverage or passing outcomes. Run the repository-native result collector with Release and locked restore for attributable results. Shared Compose and host wrappers still require independent host-ownership, readiness, failure-propagation and cleanup verification; a smoke command cannot prove release readiness.

## Command summary

| Command | Main purpose | Scope | Best used for |
|---|---|---|---|
| `dotnet test` | Broad .NET test run from the current project or solution context. | Whatever test projects are discovered from the current directory, project, or solution. | General local health check before committing or before a focused test pass. |
| `dotnet test .\treehammock.Tests\treehammock.Tests.csproj --configuration Debug --filter "FullyQualifiedName~treehammock.Tests.Integration"` | Focused integration test run for the main test project. | Tests in `treehammock.Tests` whose fully qualified name contains `treehammock.Tests.Integration`. | Auth, login, password reset, 2FA, controller, service, and in-memory integration regressions. |
| `.\eng\docker-host-system-stack-tests.cmd` | Host-backed Docker system-stack test lane. | PostgreSQL, Dragonfly, and HAProxy in Docker; ASP.NET backend and system tests on the host. | Legacy smoke lane; ownership, readiness and process proof remain pending native qualification. |

## `dotnet test`

### Purpose

`dotnet test` is the general-purpose .NET test command. Run from the repository root, it is the simplest way to ask: “Is the normal .NET test surface still healthy?”

### Feature set

- Restores and builds as needed unless `--no-restore` or `--no-build` is provided.
- Discovers tests from the current project, solution, or directory context.
- Runs unit and integration tests when they are part of the discovered test graph.
- Supports common test options such as `--configuration`, `--filter`, `--logger`, and coverage collectors.

### Pros

- Simple and easy to remember.
- Good broad regression check.
- Catches failures outside a narrow integration-test filter.
- Useful before a commit because it is less likely to miss renamed or relocated tests.

### Cons

- Less targeted than a project-specific or filter-specific test run.
- Can be slower than filtered integration or unit test commands.
- The exact scope depends on the directory and project or solution files available there.
- Does not prove Docker, PostgreSQL, Dragonfly, HAProxy, or deployment-like wiring unless those are explicitly part of the normal test graph.

### Use it when

- You want a broad local safety check.
- You have changed shared code used by both unit and integration tests.
- You want to catch test failures outside the immediately changed area.

## Focused integration test command

```powershell
 dotnet test .\treehammock.Tests\treehammock.Tests.csproj --configuration Debug --filter "FullyQualifiedName~treehammock.Tests.Integration"
```

### Purpose

This command runs the main test project but narrows execution to integration tests. It is the best fit for the auth, login, password reset, and 2FA integration suites because those tests pin full security ceremonies rather than isolated method outputs.

### Feature set

- Targets `treehammock.Tests\treehammock.Tests.csproj` directly.
- Uses the `Debug` configuration for local development feedback.
- Filters tests to fully qualified names containing `treehammock.Tests.Integration`.
- Exercises ASP.NET Core integration hosts, controller/service flows, in-memory test fakes, and regression ceremonies covered by the integration namespace.

### Pros

- Faster and cleaner than running every test when working on integration features.
- Lower noise because it excludes unrelated unit tests.
- Good at catching auth/reset/2FA flow regressions.
- Works well after changes to controller actions, password reset flow, 2FA selection, method removal, and abuse-counter integration behavior.

### Cons

- Misses unit tests outside `treehammock.Tests.Integration`.
- Misses system-stack tests and real infrastructure behavior.
- Depends on namespace naming. If an integration test is moved or renamed outside `treehammock.Tests.Integration`, this filter may skip it.
- Does not replace full `dotnet test` before final validation.

### Use it when

- Working on integration workflows.
- Iterating on password reset, login, 2FA, abuse counter, or controller integration behavior.
- You need fast feedback before running the heavier validation lanes.

## Docker host system-stack command

```powershell
.\eng\docker-host-system-stack-tests.cmd
```

### Purpose

This command runs the host-backed Docker system-stack lane. It is designed for environments where Docker can run PostgreSQL, Dragonfly, and HAProxy, while the ASP.NET backend and system tests run on the host using the local .NET SDK.

Use it to answer a different question from `dotnet test`: “Does the application still work when real infrastructure enters the room?”

### Feature set

- Starts PostgreSQL in Docker.
- Starts Dragonfly in Docker.
- Starts HAProxy in Docker.
- Runs the ASP.NET backend on the host.
- Runs `treehammock.Tests.System` on the host.
- Exercises the app through HAProxy, typically using `http://localhost:8080`.
- Covers system-level flows such as health, registration, login, 2FA setup/login, password reset paths, account delete, and lockout/unlock behavior.

### Pros

- Closest local validation lane to deployed behavior.
- Catches configuration, networking, proxy, database, and cache issues that in-memory integration tests cannot catch.
- Good final smoke test before calling a branch ready.
- Avoids needing the backend Docker image when the host can run the app directly.

### Cons

- Heavier and slower than normal `dotnet test`.
- Requires Docker and local port/environment availability.
- More moving parts means more possible local-environment failures.
- Intended as a smoke/system lane, not an exhaustive matrix. Detailed matrix coverage belongs in unit and integration tests.

### Use it when

- `dotnet test` and focused integration tests are already green.
- You are preparing a branch for review.
- You changed infrastructure-facing code, configuration, health checks, database/cache behavior, auth flows, or system test coverage.

## Recommended local validation order

For normal development:

```powershell
dotnet test
```

For authentication, reset and two-factor integration work:

```powershell
dotnet test .\treehammock.Tests\treehammock.Tests.csproj --configuration Debug --filter "FullyQualifiedName~treehammock.Tests.Integration"
```

Before declaring a branch ready:

```powershell
.\eng\docker-host-system-stack-tests.cmd
```

A practical full local sequence is:

```powershell
dotnet test
dotnet test .\treehammock.Tests\treehammock.Tests.csproj --configuration Debug --filter "FullyQualifiedName~treehammock.Tests.Integration"
.\eng\docker-host-system-stack-tests.cmd
```

## How to interpret failures

| Failing command | Most likely meaning | First place to look |
|---|---|---|
| `dotnet test` | General code/test regression. | Failing unit or integration test output. |
| Focused integration command | Security ceremony or integration-flow regression. | `treehammock.Tests/Integration`, controller/service changes, test fakes. |
| Docker host system-stack command | Runtime stack, infrastructure, proxy, database, cache, or environment issue. | `eng/docker-host-system-stack-tests.*`, Docker logs, HAProxy/backend logs, system test output. |

## Relationship to validation scripts

The README also documents wrapper scripts such as `eng/validate.*` and `eng/build-proof.*`. Prefer wrappers for CI-like proof runs because they standardize restore, build, and test options. Use the raw commands in this guide when you need targeted local diagnostics or fast iteration.

## Explicit test capabilities

Deployable Container and ContainerReverseProxy compositions disable fake delivery, capture and privileged seed/inspection routes. Intentional disposable API test stacks add `docker-compose.testing.yml` after the direct/proxy transport files; the HTTP and system test wrappers already include this overlay. It selects the exact `Testing` environment and enables the keyed fixture capabilities. Host-backed system wrappers also select Testing. Generic developer runtime wrappers retain real delivery and no privileged routes.

Test inspection uses a single `X-System-Test-Key` header matching `SystemTestSettings:TestKey`. Enabled inspection requires a 24–128 character printable ASCII key without whitespace. Capture-only Testing uses Enabled=true, inspection=false and an empty key. All other environment/flag/key combinations that request test capabilities fail startup. `DeliveryCaptureConnection` is unsupported; capture and seed use the fixture StorageContext. Restart the host to change the capability or key. Never point the Testing composition at a production database.

Native verification is mandatory: fast `Cor23DTestIsolationTests`, owned sql-harness `Cor23DTestCapabilityHttpTests`, the full SQL lane and the existing system account lane. Source/config checks do not establish native passes or qualify the legacy wrappers' independent ownership/readiness/exit-propagation findings.


## Verification-link public origins

Set a recipient-reachable `RegistrationSettings__PublicOrigin` when overriding a listener/edge. Direct Docker defaults to http://localhost:5001; proxy Docker defaults to http://localhost:8080 and supports `TREEHAMMOCK_PUBLIC_ORIGIN`. In-process tests have explicit fixture origins. Owned Kestrel tests use ephemeral loopback listeners and a pinned self-signed fixture certificate for HTTPS; they cover direct/proxy clicks without claiming deployed TLS trust. Native tests include actual Program captures, all four flow URLs, encoded payload/hash round trips, read-only email GET/explicit POST, no-store and spoofed Host/forwarded-Host isolation. SQL regressions separately exercise actual verification state and encrypted published email/deletion proofs. All native results require the .NET/PostgreSQL fixture and remain NotRun until executed.

## SMTP transport qualification

Run the mandatory fast lane (Unit + Integration) with the locked .NET 8/MailKit 4.16.0 dependencies, including `Cor23HSmtpPolicyTests` and `Cor23HSmtpTransportTests`. The latter owns loopback TCP listeners and ephemeral certificates, records AUTH/MAIL/DATA encryption state, and exercises all ten legacy mail methods plus eight durable payload kinds. Successful STARTTLS/implicit TLS use a test-only custom root chain that still checks hostname, validity and server-auth EKU; production uses normal OS trust and revocation checks. Invalid/untrusted/expired/wrong-host certificates, missing/refused/fake STARTTLS and TLS below 1.2 must fail before credentials/message submission. Rejected authentication is encrypted and diagnostic logs omit provider reply, credentials, proof and full recipient. An explicit Testing loopback relay remains usable.

```bash
python3 eng/check-smtp-transport.py
python3 -m unittest discover -s eng/tests -v
python3 eng/correction-baseline.py --lane fast --output .correction-results/cor23h-fast
```

Source witnesses cannot qualify these cases. Native tests are NotRun when the SDK is unavailable; there is no skipped-success replacement. No external relay/account is contacted. The TLS-floor test also accepts server-side refusal of obsolete TLS on an OS that disables it; AUTH/DATA must remain absent. Published OS/container trust, actual relay configuration and production network transport remain outstanding native qualification gates. The unchanged outbox delivery-result/unknown-acceptance, deadline and template contracts retain their independent qualification requirements.

## Delivery acceptance qualification

The fast lane includes Cor23ISmtpOutcomeTests (real owned TLS relay, accepted DATA with lost acknowledgement, definite 451/550, accepted disconnect) and Cor23IProviderOutcomeTests (real Twilio HTTP adapter with controlled reply faults; SNS client substitute). The SQL lane's Cor12DeliveryOutboxTests and Cor21ActivationCreationTests include the corresponding test methods covering actual HTTP adapter/worker quarantine, eight proof lineages, retry/receipt identities, crash/restart, late acknowledgement, cancellation, expiry, activation budget and retention cascade. SNS locked SDK wire behavior and deployed provider behavior remain separate qualification obligations. No external mail/SMS is sent.

```bash
python3 eng/check-delivery-outcomes.py
python3 eng/correction-baseline.py --lane all --output .correction-results/cor23i-final
python3 eng/correction-sql-fixture.py
```

All 17 new native methods (55 expanded cases) are authored NotRun until these lanes execute. Source mutation witnesses do not establish protocol, SQL or compiler passes. Deadline/cancellation joining and template rendering have independent qualification requirements.

## Cancellation and deadline qualification

The fast lane includes Cor23JDeliveryBudgetTests, Cor23JTransportDeadlineTests and Cor23JLoginCancellationTests. Run the real SMTP blocked greeting/TLS/AUTH/DATA/QUIT matrix and assert socket closure plus released capacity; HTTP/SNS cancellation tests must observe the transport token. The eight-hung-send/two-slot profile must retain unfinished ownership and bound physical starts, then release capacity only after actual completion. Aggregate fallback timing must use remaining time, and login unknown/cancellation must retain issued challenge authority. SQL Cor12DeliveryOutboxTests has the corresponding test cases for lease/expiry/revocation, occupied capacity, late receipt expiry, shutdown commit, independent committed-job lifetime and no secondary after primary-side revocation.

```bash
python3 eng/check-delivery-deadlines.py
python3 eng/correction-baseline.py --lane all --output .correction-results/cor23j-final
python3 eng/correction-sql-fixture.py
```

Nineteen methods (44 expanded cases) remain authored NotRun until native lanes execute. The source mutation suite does not establish compiler, latency, SDK wire behavior or local capacity/socket release. Uncooperative tasks retain bounded slots; shutdown must never report them terminated merely because its drain wait ends. No external mail/SMS is used by these owned fixtures.

### Provider health

Run `python3 eng/check-provider-health.py` and the full Python tooling suite for supplemental source/Lua checks. The deterministic `texlua eng/tests/provider-health-script-boundaries.lua .` command shim is not Redis/Dragonfly qualification. Native fast/SQL lanes must execute Cor23KProviderHealthTests, Cor23KSmtpHealthTests and Cor23KProviderHealthCacheTests with the owned correction cache fixture. Real cache tests use independent connections and 64-way permit/probe races; real HTTP/SMTP adapters remain owned and send no external messages. Native execution is NotRun in this delivery.

### Selected SMS configuration

Run `python3 eng/check-sms-transport-configuration.py` and `python3 -m unittest discover -s eng/tests -p 'test_sms_transport_configuration.py'` for supplemental source witnesses. The fast native lane must execute `Cor23LTwilioStartupTests` and `Cor23LTwilioConfigurationTests`: 21 authored methods, 84 inline-expanded cases. Host tests retain real Program/options/startup composition while removing background hosted services and substituting the provider client; they do not qualify background workers or remote readiness. .NET 8 options startup validation remains part of real host startup. Native compilation/execution is NotRun in this delivery.

Deployment CI must run `bash eng/validate-sms-config.sh /path/to/published/treehammock.dll` with its real deployment environment and secret injection before rollout. The wrapper uses the published application directory; nonzero exit fails deployment. Alternatively invoke `dotnet treehammock.dll validate-sms-config` there. Do not print injected secrets or enable shell tracing. Repository CI also exercises the command on shipped disabled physical settings after the fast build; it cannot validate production secrets. Successful preflight reports local checks only, not Twilio credential/sender ownership, credit, reachability or readiness.

### Authoritative admission budgets

Run `python3 eng/check-authoritative-abuse-budgets.py` and `python3 -m unittest discover -s eng/tests -p 'test_authoritative_abuse_budgets.py'` for supplemental source witnesses. Native fast coverage is Cor23MAuthoritativeBudgetTests and Cor23MBudgetStartupTests. Cor23MAbuseBudgetTests is mandatory in the SQL harness: it uses independent PostgreSQL owners plus two actual owned cache connections, 64-way threshold/cooldown races across all six supported pairs, healthy/outage/recovery history, actual SQL lock timeout, an observed row-lock window rollover, isolated reset, bounded dry-run cleanup and unsupported SQL inputs. Execute it against both pinned Redis and Dragonfly correction fixtures before qualification. All 25 native methods (64 cases) remain NotRun here. No external providers/messages are involved.

## Optional validated coverage

Use `bash eng/validate.sh --locked-restore --collect-coverage` or `./eng/validate.ps1 -LockedRestore -CollectCoverage`; individual unit/integration runners accept the same switch. Python 3.10+ is required when collection is requested. The existing pinned private Microsoft Code Coverage collector emits application-only Cobertura into fresh `.artifacts/coverage/<uuid>/<lane>` directories. A zero native test exit alone cannot satisfy the contract: nonzero passing TRX discovery and consistent nonempty measured application lines are required. Test failures retain their child result.

For attributable baseline coverage use `bash eng/correction-baseline.sh --lane fast --collect-coverage` or `./eng/correction-baseline.ps1 -Lane fast -CollectCoverage`. Native qualification: `python3 eng/test-coverage-contract.py --host bash`, or on the selected PowerShell host `python eng/test-coverage-contract.py --host pwsh` / `--host powershell.exe`. See [COVERAGE_CONTRACT.md](README.md). CI upload integration and Sandbox configuration identity remain with their scoped owners. Native collector/host execution remains pending; synthetic tooling results do not qualify measured coverage.

## Configuration identity

Debug, Release and Sandbox now build and test matching application/test outputs. Owned local/collector/Docker wrappers carry a fresh UUID through restore/build/no-build tests. Missing/stale receipts or differently identified/configured loaded assemblies fail; per-test output includes identity JSON with paths, MVIDs and binary hashes. Host/container system tests explicitly use Release. Run `python3 eng/test-build-configuration.py --host bash` or `python eng/test-build-configuration.py --host pwsh` / `--host powershell.exe` on a supported host with the real SDK and Docker. The fixture runs each configuration's real fast lanes, owned disposable SQL fixture and Docker build; its System assembly probe has no remote HTTP coverage. See [BUILD_CONFIGURATION_CONTRACT.md](HOST_PREREQUISITES.md). Native matrix execution remains pending. Use separate checkouts for concurrent proof builds.
