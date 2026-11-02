# COR23J — Bound delivery lifetimes and retain cancellation ownership

Owns R08-03, based on completed COR23I. FixedPendingQualification; native compilation, latency/capacity profiling and PostgreSQL execution remain NotRun. This pre-1.0 correction edits current setup/configuration directly, with no appended migration, backfill or compatibility aliases. The frozen review/specification and earlier implementation documents remain historical evidence.

## Budgets and capacity

DeliveryExecutionPolicy snapshots the execution settings and owns one semaphore/operation registry per host. SMTP, the entire SMS provider chain and synchronous login delivery use this shared policy. Nested throttle/adapter/transport calls inherit the same DeliveryBudget through an async context; they cannot restart the timer or acquire another capacity slot. Remaining time uses elapsed monotonic Stopwatch time. Durable expiry also clamps the initial timer, and each physical attempt rechecks current database authority.

| DeliveryOutboxSettings property | Default | Validation and meaning |
| --- | --- | --- |
| ProviderTimeoutSeconds | 20 | 1–30 seconds; aggregate capacity wait/throttle/provider lifecycle |
| ProviderAttemptTimeoutSeconds | 10 | 1–30 seconds, no larger than aggregate; one provider's complete transport phase |
| CancellationDrainSeconds | 2 | 1–5 seconds; bounded join after cancellation and hosted policy shutdown |
| MaxConcurrentSends | 4 | 1–8 unfinished root operations per host, including retained cancelled work |
| LeaseSeconds | 60 | Existing 5–120 range; strictly greater than aggregate + drain + 10 seconds for acquisition/commit |

All eight profiles explicitly set the three new budget/capacity values. Base/Example keep aggregate=20 and lease=60; other profiles inherit the current base settings. No timeout spelling or old-contract alias is added. Restart the host to apply execution policy changes. A root normally finishes within its aggregate budget; cancellation adds at most the drain interval to its caller wait. Worker acquisition and independent receipt/publication commitment each retain a five-second budget, so default claim/send/drain/commit allowance is 32 seconds inside its 60-second lease. These are application policy bounds, not measured native passes.

The worker serializes ProcessOnceAsync itself, including concurrent manual invocations; hosted worker concurrency is one. The transport policy independently caps all synchronous and durable delivery at four unfinished operations per host. This is a per-host bound, not a distributed cluster concurrency cap. Async capacity wait is cancellation-aware and consumes the existing root budget. A request that expires/cancels before acquiring capacity is confirmed NotSubmitted; it starts no transport. A durable capacity timeout can retry only through COR23I's bounded confirmed-non-submission rule.

## Cancellation and task ownership

The worker no longer abandons provider work through an untracked WaitAsync. Policy cancellation reaches the actual underlying operation. The caller first waits for transport completion or cancellation, requests cancellation, then waits a bounded drain interval. Cooperative work closes/disposes its owned resources before its slot is released. If it remains unfinished, a retained observer owns its Task, budget and slot, observes every fault and awaits actual completion. The caller receives Unknown; the live operation cannot cause another capacity slot or fallback just because its caller stopped waiting.

An uncooperative operation can retain a slot indefinitely. Its count remains bounded, further sends fail closed at their deadlines, and shutdown does not claim the task or remote submission was terminated. No thread/process kill or unsafe concurrent disposal is used. Remaining work may retain its bounded in-memory payload until completion/process exit; persisted payload expiry and proof consumption remain independently authoritative. Qualification must inspect SDK/socket cancellation and local capacity release, rather than treating a bounded caller wait as transport termination.

On host stop, the registered policy cancels root operations and drains its ownership registry for the configured interval. Worker shutdown cancellation still uses an independent five-second receipt/publication budget. If cooperative work returns Accepted while cancellation/disconnect is occurring, acceptance is persisted and normal publication checks apply. A retained durable observer may later persist only its own definitive Accepted/Rejected result, through COR23I's exact job/attempt receipt fence. Expired/cancelled/superseded authority cannot resurrect, and Unknown cannot become retryable NotSubmitted. An unavailable late commit leaves the durable Unknown/abandoned-claim contract intact. No late callback sends another message.

A committed outbox job belongs to its durable worker lifetime, not its original HTTP request. RequestAborted is used for synchronous login email/SMS and throttle calls; it is never captured as a committed job's execution token. Cancelling a client request after staging does not cancel or erase its independently accepted job. Explicit security cancellation and stamp/family/proof revocation remain separate authority.

## Transport and authority boundaries

All ten legacy SMTP methods now accept and forward an optional CancellationToken to the common policy. Existing callers with no external token still receive the aggregate budget. A single attempt covers connect, required TLS, authentication, submission and disconnect; MailKit receives the same bounded token for every phase. Cancellation that unwinds before submission is NotSubmitted; unfinished work remains conservatively Unknown after its drain limit. A send-phase fault with possible acceptance is Unknown. A successful DATA acknowledgement followed by blocked/cancelled QUIT remains Accepted. Client disposal occurs as the actual SMTP task unwinds, before capacity is reusable. Required STARTTLS/implicit TLS, certificate validation and COR23H's isolated loopback exception remain unchanged.

SMS SendCode/SendMessage and purpose-aware fake/capture contracts expose cancellation. Every provider in the configured distinct chain receives a linked attempt token bounded by remaining aggregate time. Attempt cancellation stops the root chain; a definitive negative may remain known, but no secondary transport starts after budget exhaustion. Unknown never falls back. A slow rejected primary does not give the secondary a fresh aggregate timer. SNS PublishAsync receives the attempt token and retains MaxErrorRetry=0. The named Twilio client uses the application token with an infinite independent HttpClient timeout, disabled redirects/cookies and a 16 KiB receipt buffer ceiling; both headers and response-body buffering remain under the same application budget. Low-level SDK/HTTP adapters take their caller's bounded token; application entry points establish the policy.

Current setup adds only cor23j_delivery_can_send. Before dispatch, it locks account authority and validates the exact live claimed job/lease/attempt, payload expiry, current stamp/predecessor and existing activation, deletion, email and factor enrollment authority. The worker checks before entering its provider adapter; SMTP/SMS check again before physical attempts, including fallback after a definite primary rejection. This is point-in-time dispatch authorization, not a lock held across external I/O. A later revocation remains authoritative at publication/consumption. The existing SQL receipt/proof state machine is unchanged. Generated baselines/checksums and lexical binding/factor inventories are refreshed without changing identity allocation or other SQL definitions.

Fake capture cancellation now reaches its actual schema wait, connection and INSERT operations; it does not abandon a SQL Task with WaitAsync. The same direct contract signatures are used by production and isolated providers. Capture still requires COR23D's explicit capability and provides no production provider evidence. Capture-only activation rendering remains its existing independent template owner.

## Synchronous login proof ownership

TwoFactorAuthenticateService includes throttle admission, provider work and bounded diagnostic counting in one root budget. Admission cancellation before transport returns confirmed non-submission. Diagnostic failure counting cannot replace a known provider result. SMTP null and SMS uncertainty remain DeliveryAcceptanceUnknownException. The login selection/resend/next-proof paths forward RequestAborted and preserve issued challenge identity/hash/version on typed Unknown or unexpected provider exceptions; they return the normal API envelope with 503 and DELIVERY_ACCEPTANCE_UNKNOWN. A definite false still runs the existing version-fenced proof cancellation. This closes a caller catch that could otherwise turn a cancellation/unknown result into destructive cleanup. No security revocation is suppressed.

## Authored qualification and executed tooling

Nineteen new native methods expand to 44 cases. The matrix includes real owned MailKit/TLS stalls at greeting, handshake, AUTH, DATA acknowledgement and QUIT in both secure modes, socket closure/capacity checks and precancellation through all ten legacy methods. HTTP tests use the real Twilio adapter/client with an owned handler that blocks headers/body; SNS tests use its cancellable client substitute. Aggregate fallback timing and an eight-hung-send/two-slot profile verify cancellation, bounded starts, retained ownership and release after completion. Policy tests cover nesting, settings validation/snapshot, shutdown and observed late faults.

Actual SQL tests cover current lease/expiry/stamp/cancel/attempt authority, expiry while waiting for occupied capacity using correctly bound encrypted payload metadata, noncooperative transport plus late accepted receipt with/without expiry, shutdown commitment of Accepted/Unknown, committed job survival after client cancellation, and security revocation between primary rejection and secondary dispatch. The login test joins the actual controller with the real two-factor service and asserts cancellation propagation plus durable challenge retention. These are authored NotRun; no latency percentiles, throughput or SDK wire results are asserted.

Eighteen supplemental source mutation witnesses reject missing ownership/join/capacity fences, nested budget reset, incorrect remaining time, fallback after exhaustion, dropped legacy/throttle/capture tokens, unknown-proof compensation, missing expiry and invalid lease/profile limits. They are source checks, not compiler/protocol/SQL evidence.

```bash
python3 -m unittest discover -s eng/tests -v
python3 eng/check-delivery-deadlines.py
python3 eng/check-delivery-outcomes.py
python3 eng/check-smtp-transport.py
python3 eng/generate-database-baseline.py --check
python3 eng/check-sql-output-bindings.py
python3 eng/check-factor-identities.py
python3 eng/check-correction-evidence.py
python3 eng/cor23-reconciliation.py --check
python3 eng/correction-baseline.py --lane all --output .correction-results/cor23j-final
python3 eng/correction-sql-fixture.py
```

The delivery records final-source attempts and exact patch replay/archive checks. .NET SDK, PostgreSQL, Docker/cache and PowerShell are absent, so compilation/SMTP/TLS/HTTP/SDK/SQL/profile lanes remain Blocked/NotRun. Published provider behavior, operating-system trust/cancellation and COR24 qualification remain open. R08-03 becomes FixedPendingQualification; the other 83 findings, original 451-file inventory, frozen reviews, previous implementation records and all 186 Open release gates are preserved. Totals: 62 FixedPendingQualification, 22 Open. Next: COR23K. COR23K/L retain rendering ownership; COR23I's retry/receipt/proof semantics remain authoritative.

Rollback may tighten/adjust validated budgets, but must retain bounded concurrency, cancellation ownership and Unknown fences. There is no production migration/backfill, deployed rollback or external email/SMS action. Primary design references do not qualify the locked runtime:

- https://learn.microsoft.com/en-us/dotnet/api/system.threading.tasks.task.waitasync
- https://devblogs.microsoft.com/dotnet/how-do-i-cancel-non-cancelable-async-operations/
- https://mimekit.net/docs/html/M_MailKit_IMailTransport_SendAsync_3.htm
- https://docs.aws.amazon.com/sdkfornet/v4/apidocs/items/SNS/MISNSPublishAsyncPublishRequestCancellationToken.html
