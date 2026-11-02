# Database-backed Dragonfly session warmup

Enable an asynchronous hosted worker that fills missing active-session cache entries from the database already configured by `DatabaseSettings`. Point that existing connection pool at your Yugabyte YSQL endpoint; the worker uses the existing Npgsql session repository and Dragonfly active-session cache, including its database index and credentials. It starts after yielding host startup and runs independently of readiness. It is disabled by default in all shipped profiles.

## Environment configuration

Copy `deploy/session-cache-warmup.env.example` into your deployment environment. The usual double underscore separator binds these variables to the validated `SessionCacheWarmupSettings` section. Values are read at host startup; restart the host after changing them.

| Environment variable | Default | Range / meaning |
| --- | --- | --- |
| `SessionCacheWarmupSettings__Enabled` | `false` | Opt in with `true`. |
| `SessionCacheWarmupSettings__BatchSize` | `100` | 1–1000 candidate sessions per batch. |
| `SessionCacheWarmupSettings__IntervalSeconds` | `10` | 1–3600 seconds after each completed or failed batch before starting the next. |
| `SessionCacheWarmupSettings__DurationSeconds` | `300` | 0–86400 seconds for the warmup run; 0 replenishes continuously until host shutdown. |
| `SessionCacheWarmupSettings__CacheTtlSeconds` | `300` | 1–86400 seconds maximum lifetime of each newly warmed cache entry. |
| `SessionCacheWarmupSettings__BatchTimeoutMilliseconds` | `5000` | 100–30000 milliseconds for a whole batch, including enumeration, database reloads and cache writes. |

For example, enable the worker with batch size 100, interval 10 and duration 300 to attempt at most 100 sessions per batch for five minutes after startup. Cache TTL 300 separately caps each entry at five minutes. The actual run stops issuing work when its duration token is canceled; native dependency cancellation/cleanup and an already-issued Redis command can finish afterward. A duration of zero keeps scanning, so entries evicted after startup can be replenished throughout the host lifetime.

The limit is per API instance, not a cluster-wide quota. Batches run sequentially with a delay after completion, so slow or failing dependencies do not cause catch-up bursts. One batch performs one bounded keyset query, at most `BatchSize` existing authoritative `get_session` reloads, and at most `BatchSize` cache insert attempts. Tune the values for your number of replicas and database pool budget. Warmup loads sessions that still have valid access tokens; expired access tokens with a refreshable family are left to the normal refresh protocol.

The supplied integration Compose stack forwards these six environment variables to the API with the same disabled defaults. Its PostgreSQL service remains the disposable test database; configure your actual deployment's existing `DatabaseSettings` for Yugabyte rather than replacing the fixture topology.

## Authority and expiry

Candidates must belong to a verified, currently unlocked account, match the current account security stamp, have protocol version 2 and a family lifetime, and have unexpired access/session/account and session cutoffs. Enumeration follows the existing access-token-hash primary key with `ORDER BY`, a cursor and `LIMIT`; no offset or entire-table materialization is used. Native query cancellation bounds scan time, including when a large inactive history is present.

Each candidate is reloaded through `SessionRepo.GetSession` so signing key, account/session stamps, family, generation, protocol and entitlement projection come from the same production mapping as a cache miss. Missing, incomplete, expired or no-longer-current projections are skipped. Cache TTL is the earliest of the warmup cap, existing JWT cache lifetime, access expiry, hard session/cutoff expiry and next entitlement boundary. Warmup never changes a database expiration or creates a new token/session.

An atomic `SET NX` preserves every existing cache entry and its TTL. This means warmup does not repair existing malformed/stale entries; request-time hydration handles those. A concurrent rotation/revocation/lock/entitlement change can race a database snapshot and leave a stale cache value. The existing JWT middleware revalidates every cache hit against database authority before authenticating, and retains its expiry and entitlement checks. Warmup does not bypass those checks or make cache presence an authorization decision.

The worker borrows the host-owned cache connection and database pool, issues one operation at a time, propagates batch/run/shutdown cancellation, retains its cursor after an interrupted entry, and wraps at the end of a scan. A cache insert failure retries the unfinished entry in the next batch; missing sessions are skipped and reconsidered on a later scan. Dependencies can recover during the configured run; a finite completed run restarts only with a new host. Warning logs contain fixed messages and debug logs contain inserted-entry counts, never hashes, keys or session payloads.

## Yugabyte configuration and qualification

Use the existing schema and existing `DatabaseSettings` credentials/TLS policy. Yugabyte's [official Npgsql driver documentation](https://docs.yugabyte.com/stable/develop/drivers-orms/csharp/postgres-npgsql-reference/) describes YSQL connections and the usual 5433 listener. No driver package, second database, schema migration or compatibility layer is introduced by this feature.

This connection path is implemented; no Yugabyte deployment was available for qualification here. The existing schema/session authority functions (including their lock/entitlement behavior), YSQL catalog/type support, TLS, query plans and cancellation must be verified on the chosen Yugabyte version. The native tests below use the project's owned PostgreSQL fixture and real Redis/Dragonfly; passing those does not qualify Yugabyte.

## Validation commands

```bash
python3 eng/check-session-cache-warmup.py
python3 -m unittest discover -s eng/tests -p 'test_session_cache_warmup.py'
dotnet test treehammock.Tests/treehammock.Tests.csproj --filter FullyQualifiedName~SessionCacheWarmupTests
python3 eng/correction-sql-fixture.py --cache-product dragonfly
```

The SQL/cache cases are mandatory in the native baseline filter and therefore run for both Redis and Dragonfly in the existing CI matrix. They check active-candidate exclusions and keyset pagination, real payload/TTL hydration, atomic preservation of existing entries and rejection of database revocation despite a cached snapshot. Native unit cases check TTL caps, projection validity, bounds, interruption/resume, duration/shutdown, failure pacing and configuration.

Python checks and source mutation witnesses are supplemental source checks. They do not compile C# or execute a database/cache. Native .NET, SQL/Dragonfly and Yugabyte qualification remains NotRun when the necessary SDK/services are unavailable. Existing finding/gate qualification is unchanged by adding this feature.
