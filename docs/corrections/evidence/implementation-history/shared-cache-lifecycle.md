# COR23N — shared cache ownership and lifecycle

Date: 2026-10-09 (America/Chicago). Baseline: completed COR23M. Owner: R09-02, P2. Status: FixedPendingQualification; native compilation and qualification NotRun.

## Current-source recheck

COR03 already replaced PublicationOnly health initialization with CacheConnectionOwner and one slot per active-session, two-factor-session and abuse-counter role. Production DI registers the same singleton as the hosted service; active sessions, factor sessions, counters, replay, CAPTCHA continuation, provider health and readiness borrow its role slots. The historical health race therefore does not survive in the delivered COR23M source. This PR preserves that composition rather than adding another initializer.

Remaining lifecycle gaps were mutable options during retries/requests, an uncapped delay for directly supplied retry settings, use of a borrowed slot after disposal, and external client disposal under the slot lock. The host's StopAsync also ignored its cancellation token. Existing COR03 cases did not cover concurrent startup bursts, disposal callbacks acquiring diagnostics on another thread, production consumer composition or real repeated-host connection counts.

## Resulting lifecycle

- Slot construction snapshots all cache endpoint, database, credential, name and timing values. Initial retries and commands cannot retarget a slot when the supplied options object changes. Production options validation remains in force; local defensive bounds cap connection/command timeouts at 10–10000ms and the retry base at 10–60000ms.
- Start has one locked asynchronous worker per owned slot. Request/health getters never connect. Repeated/concurrent starts are idempotent before shutdown; starting a disposed slot or owner throws. The owner serializes its start/dispose transition across all three roles.
- Initialization exceptions retry with exponential delay: clamp(base,10,60000) * 2^(failure-1), capped at 60000ms with overflow-safe arithmetic. Cancellation interrupts retry delay. Only one attempt can be pending; provider ConnectRetry is zero. After the provider returns a multiplexer, that same client owns reconnects, including when initially disconnected under AbortOnConnectFail=false. A disconnected client is not replaced by a new initializer. Retry continues while the host is alive; a capped delay is not a finite attempt count or a guaranteed recovery time.
- Slot disposal atomically stops access, detaches its visible client and publishes one shared cleanup task. Cancellation and external client disposal run outside the lifecycle lock. Owned connected clients are disposed once; late successful initialization is disposed by the worker without publication. Late failures are observed. Borrowed clients are detached but never disposed. Shared consumer disposal cannot stop the owner slot; the existing explicit dedicated-consumer constructors own their private slot and preserve borrowed-client semantics. These constructors are an ownership API, not a separate legacy execution path.
- StopAsync starts cleanup even with an already canceled host token, then bounds the host's wait using that token. Canceling the wait does not terminate ConnectAsync or abandon its result. Dispose/DisposeAsync drain the same work and surface disposal faults. They intentionally do not claim a hard deadline against a connector that ignores its configured timeout: a permanently hung custom connector leaves one pending worker and an incomplete drain. There is no timeout-triggered replacement or unbounded collection of abandoned attempts. Shutdown qualification must verify the pinned provider honors configured initial-connect bounds.
- Local diagnostics expose lifecycle, initialization attempts/failures, zero-or-one pending initialization, client presence/connectivity, ownership, retry delay and disposal-failure flag. They expose no endpoint, password, configured name, raw exception or account data and start no connections. A reported Disposed lifecycle means the logical slot is closed; DisposalFailed means external resource cleanup failed, not proven resource release. No operational transition metric is added (COR23P owns that work).
- Owner-generated client names append a COR23N role and random host-generation suffix. This distinguishes independently owned roles and overlapping host lifetimes in scoped CLIENT LIST checks without exposing configuration through the diagnostics API. Client names remain operational metadata accessible only to the cache administrator. The owner still creates three multiplexers when roles share an endpoint; one multiplexer may use multiple interactive/subscription sockets.

HealthDependencyService remains a borrower with no cache disposal responsibility. Readiness aggregate deadlines, sampling, database/probe concurrency and residual PING isolation remain COR23O. There is no schema/package/deployment history migration, backfill, compatibility mode or restored legacy system.

## Regression and qualification boundaries

Cor23NCacheLifecycleTests uses controlled connector tasks and multiplexer doubles for 128-way starts, unavailable first requests, failure/recovery and capped backoff, mutable-options rejection, shutdown during backoff/initialization, late faults, callback lock safety, borrowed/client-sharing boundaries, reconnect reuse, request cancellation, repeated generic host lifetimes, canceled host waiting, disposal faults and no-connect pre-canceled startup. Cor23NCacheHostTests starts real Program/options/consumer DI with cache connectors substituted; unrelated hosted workers are removed and the cache host alias is restored. It verifies actual consumer role identity and host disposal. Its pre-canceled health check does not qualify a completed PostgreSQL readiness probe.

Cor23NCacheOwnershipTests runs actual pinned PostgreSQL, cache clients, production HealthDependencyService and generic host ownership. It drives three host lifetimes, each with a 64-start burst and 64 complete readiness probes; checks three logical initializers, scoped cache CLIENT LIST counts of 3–12 sockets while active and zero after shutdown; and covers a retained late actual connection plus survival of a borrowed real client. The 3–12 bound accounts for provider socket composition, not one socket per role or a measured capacity budget. CLIENT LIST qualification requires fixture administrator access. The existing mandatory Cor03CacheRecoveryTests supplies the actual failed handshake/recovery case. Native cases must execute against both owned Redis and Dragonfly fixture products. They do not qualify a full process crash, deployment rollout under real traffic, or aggregate readiness bounds.

Nineteen Python checks include seventeen rejected source mutations, current-source consistency and the actual owned fixture command-selection function. They supplement native tests; no source guard proves compilation, disposal execution or network counts. CI runs these checks, and the native SQL collector explicitly selects Cor23NCacheOwnershipTests. All existing native/qualification gates remain required.

This environment lacks the .NET SDK, Docker, PostgreSQL server/client and PowerShell. The delivery records executed source/tooling checks separately from Blocked/NotRun native lanes. R09-02 moves to FixedPendingQualification; no finding or release gate closes. All other finding identities/history and frozen review evidence are preserved. Next: COR23O/R09-03, readiness deadlines and probe lifetime isolation.

## Run on a capable machine

```bash
python3 eng/check-cache-client-lifecycle.py
python3 -m unittest discover -s eng/tests -p 'test_cache_client_lifecycle.py'
bash eng/correction-baseline.sh --lane fast
bash eng/correction-sql-fixture.sh --cache-product redis
bash eng/correction-sql-fixture.sh --cache-product dragonfly
```

The fixture owns generated credentials, loopback listeners, native SQL/cache lanes, image identity recording and teardown. CI runs both fixture products through an explicit matrix, using the existing Redis fixture and the pinned Dragonfly v1.36.0 overlay. Each product records the resolved image identity independently. Neither documented nor configured matrix execution is evidence that a lane passed. Preserve reports with scoped client counts and provider versions. Revert coherently to a single ownership composition if necessary; do not restore PublicationOnly factories or dispose borrowed clients. No persisted data changes require rollback handling.
