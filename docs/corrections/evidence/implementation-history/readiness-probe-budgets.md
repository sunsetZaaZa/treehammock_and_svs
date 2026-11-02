# COR23O — readiness budgets, sampling and probe ownership

Date: 2026-10-09 (America/Chicago). Baseline: delivered COR23N. Owner: R09-03, P2. Status: FixedPendingQualification; native compilation/execution NotRun.

## Current-source recheck and behavior

COR03 already made PostgreSQL acquisition/commands cancellation aware; COR23N supplies one shared asynchronous cache initializer per role. Readiness therefore must not recreate clients or wait synchronously for initialization. The remaining COR23N health service executes four sequential probes per caller without an aggregate budget, sampling or ownership of raw commands after a timeout. A timeout wrapper alone would still allow another PING while the previous raw command remains unfinished.

HealthDependencyService is now an on-demand singleton sampler registered as the same IHealthDependencyService and hosted-service instance. Startup and /health/live perform no probes. Anonymous /health/ready and /health/dependencies join one sample flight, or reuse a completed report younger than the configured maximum age. Four dependency checks run in parallel. A caller's cancellation stops that caller's wait and never cancels a shared sample. A pre-canceled request starts no sample, connection acquisition or PING.

HealthProbeSettings is required and rejects unknown keys, inverted dependency/total budgets and out-of-range values. Every supplied appsettings profile and the native test settings include explicit defaults. The sampler snapshots the options at composition.

| Setting | Default | Valid range / meaning |
| --- | --- | --- |
| TotalTimeoutMilliseconds | 2000 | 50–5000; caller wait and aggregate sample admission budget, including scheduling. |
| DependencyTimeoutMilliseconds | 500 | 10–5000 and <= total; each dependency gets min(per-dependency budget, remaining total). |
| SampleMaxAgeMilliseconds | 250 | 10–1000; completed-sample reuse/freshness interval; expiry is exclusive. |

Both caller and dependency waits use independent TimeProvider-aware timers. The sample's monotonic admission timestamp is captured before it is queued. Queued raw work rechecks its remaining admission time before starting. Successful dependency completion is checked against its monotonic budget, and a sample completing at/after the total deadline cannot publish healthy results. Timer scheduling races cannot turn an already expired success into readiness. The declared native test scheduling tolerance is up to 350ms for the real 300ms pool-pressure case and up to 250ms for controlled small-budget cases; these are authored assertions, not measured guarantees. CPU/thread-pool starvation still requires COR22/COR24 qualification.

## Bounded residual work and cancellation

One ProbeSlot retains the raw operation task for each of PostgreSQL, active sessions, factor sessions and abuse counters. A sample encountering an unfinished slot returns unhealthy/probe_in_progress rather than scheduling a replacement. The slot becomes available only when the raw operation, resource cleanup and cancellation callbacks have actually completed. At most one raw operation per dependency and one sample flight remain pending. Completed tasks are replaced, not accumulated in an unbounded history.

PostgreSQL's raw adapter passes the isolated probe token through CreateConnection and ExecuteScalarAsync, retains await-using ownership of the connection/command, and checks cancellation after acquisition before creating a command. A late acquired connection is disposed without starting new SQL work. The SELECT 1 command retains an independent two-second provider CommandTimeout; the application budget is shorter by default and covers acquisition plus execution/cleanup. StorageContext's existing cancellation-aware acquisition interface is preserved.

The cache adapter borrows the current COR23N slot and awaits its RAW Database.PingAsync task. It deliberately does not use the general cache ExecuteAsync wait wrapper: that wrapper could finish while PING is still running, falsely freeing a readiness slot. Cold/disconnected shared initialization returns unavailable immediately; health never waits for or replaces the owner's ConnectAsync task. Redis cancellation terminates the application wait only. A pending transport PING continues to occupy its readiness slot until the actual task finishes.

Providers receive a private operation token. Host/finish signals are connected only to the sampler's lightweight timer; provider cancellation uses CancelAsync and is awaited as part of raw-task ownership. A blocked provider cancellation callback therefore keeps one slot pending rather than blocking the readiness response or being abandoned repeatedly. Late successes/faults cannot update a previously completed report. Fault observation remains attached to retained tasks.

Stop marks the sampler unavailable and prevents new work, starts cancellation, then drains the current sample and retained raw tasks. StopAsync honors the host's wait token; Dispose/DisposeAsync share one drain task. Canceling the shutdown wait does not terminate a driver or release its resource early. A permanently hung provider, cleanup routine or cancellation callback can leave at most one raw task per dependency and an incomplete disposal drain. No forced task termination or unconditional bounded final disposal is claimed. The sampler never disposes the borrowed StorageContext/data source or cache owner/clients. Host registration order stops sampling before cache ownership shuts down.

## Readiness contract and freshness

PostgreSQL and all three cache roles are required. Any timeout, unexpected response, unavailable dependency, pending old operation, stale sample or stopped host yields not_ready/503. Login/Delivery's selected durable budget fallback does not make sessions or other cache policies degradable. Remote email/SMS providers are not dependencies of these endpoints and retain their separate delivery circuit policy.

This is basic connectivity: SELECT 1 and PING do not prove schema version, required function availability, permissions for writes/scripts, issuer configuration, cryptographic keys or all business flows. No intrusive capability probe or database mutation is added.

Responses expose completed sample UTC time, monotonic sample age, sample duration, configured freshness limit and whether a completed sample was reused. Age is measured from completion. Individual observations can be older by the sample duration; interpret duration + age together (default admission bound 2000ms plus up to 250ms completed-report reuse, subject to scheduling tolerance). UTC timestamps are informational; wall-clock changes cannot extend cache validity. Invalid/stale/deadline-only responses have no invented successful sample timestamp. Sample collections are read-only, and /health/live retains its dependency-free live status.

All health routes use no-store so intermediaries cannot cache healthy readiness beyond the sampler policy. Dependency names remain the existing bounded names, including dragonfly_* on either supported cache product. Reason codes are fixed; exceptions, connection strings, credentials and identifiers are never serialized. No operational transition metric is introduced (COR23P owns metric semantics).

HAProxy check exchanges now have an explicit six-second timeout, above the maximum validated five-second application total budget. Its existing five-second connection timeout is separate. The six-second check timeout is headroom configuration, not a measured end-to-end network bound. Deploy probes without authentication/session headers so middleware cannot add session work before the controller. See READINESS_RUNBOOK.md for measurement, freshness/recovery and fault expectations.

## Validation boundaries

Native controlled tests cover all four hung dependencies, concurrent sample joins, caller cancellation, aggregate timing, exact age expiry, late faults/recovery, mutable options, pre-cancellation, sanitized results, invalid budgets, shutdown drains and blocked cancellation callbacks. Actual cache adapters with multiplexer doubles retain raw PINGs after the wait budget and never wait for/restart cold owner initialization. Real Program/MVC routing tests exercise healthy/outage status, no-store, response metadata, liveness and startup validation with the probe backend substituted.

Cor23OReadinessBudgetTests uses actual PostgreSQL and Redis/Dragonfly fixtures for 64 joined probes under real one-slot pool pressure, recovery, a held late real connection and disposal, actual delayed SQL cancellation, and retained cache-owner initialization followed by real client readiness. The pg_sleep command is an explicit private IHealthProbeClient substitution for the production SELECT 1 query; it exercises Npgsql cancellation/resource cleanup through the production sampler, not an invented production slow-query route. The late acquisition uses a private StorageContext barrier that intentionally ignores cancellation after acquiring a real connection. Cold initialization uses a private factory barrier before actual ConnectAsync. Raw delayed Redis PING is a controlled adapter double, not a real network-fault test. Full transport-fault, deployment rollout, process-crash, p95/p99, handles/memory and thread-pool qualification remains required.

Twenty-two new Python checks include twenty-one rejection mutations and consistency. They execute source/tooling contracts only; they do not compile C#, execute callback/disposal behavior, measure elapsed budgets or qualify the services. COR23N's ownership guard is narrowed specifically to borrowed cache disposal so it can also validate the sampler's independent owned lifetime; its 19 negative/fixture checks remain in place. CI requires the native SQL/cache suite in the existing independent Redis and Dragonfly fixture matrix.

This environment lacks .NET SDK, Docker, PostgreSQL server/client and PowerShell. Executed source/tooling checks and Blocked/NotRun native attempts are recorded separately in the delivery. R09-03 is FixedPendingQualification; all other findings and all 186 Open release gates are retained. No schema, migration, backfill, package-lock or legacy execution system is added. Next: COR23P/R09-04, operational transition metrics.
