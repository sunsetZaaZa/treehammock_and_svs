# COR23I — Preserve delivery uncertainty and fence retries

Owns R08-02, based on completed COR23H. FixedPendingQualification; native compilation, provider protocol and PostgreSQL execution are NotRun. This pre-1.0 correction edits current setup directly: no seventh migration, upgrade/backfill, old-result aliases or compatibility deployment are introduced. Frozen review/specification text and earlier implementation documents remain historical evidence.

## Delivery contract

`DeliverySendResult` exposes Accepted, NotSubmitted, Rejected and Unknown, an independent CanRetry flag, bounded provider name, sanitized outcome code and optional bounded receipt identity. Invalid enum, retry/state combinations, provider or receipt shapes normalize to Unknown. Raw error codes, response bodies, secrets and destinations do not become persisted receipt metadata. Acceptance means provider submission acceptance; it does not mean mailbox/handset receipt.

| Outcome | Fallback and worker behavior | Proof/payload ownership |
| --- | --- | --- |
| Accepted | Stop provider chain; persist fenced receipt, then publish once | Erase ciphertext after acceptance; publication checks current predecessor, stamp and expiry |
| NotSubmitted | Fallback allowed; same job may retry only when CanRetry=true and attempt bound permits | Safe retry retains ciphertext/proof; permanent/configuration failure or exhaustion rejects candidate |
| Rejected | Explicit negative receipt; fallback allowed, otherwise terminal | Reject candidate and erase ciphertext; established domain cleanup ownership remains unchanged |
| Unknown | Stop fallback; never requeue or classify as false | Quarantine current candidate with encrypted payload until authoritative cancellation/expiry or its own late definitive receipt |

The durable SMTP interface now returns the typed contract. Legacy SMTP retains bool? with Unknown=null; the remaining legacy two-factor Email bool boundary throws DeliveryAcceptanceUnknownException on null. Legacy SMS bool methods throw the same sanitized exception on Unknown. They cannot return false and trigger non-delivery compensation. Active password reset, email change, deletion and activation producers already enqueue COR12 jobs and do not call a provider for immediate compensation; their source and idempotent staging/admission behavior are preserved. This is an internal breaking contract; producer/worker versions must match.

## Provider retry table

| Provider boundary | Result | Retry decision |
| --- | --- | --- |
| SMTP connect/TLS/authentication failure before SendAsync | NotSubmitted, nonretryable | No worker retry; existing required TLS remains authoritative |
| SMTP explicit sender/recipient/message negative reply during send | 4xx NotSubmitted retryable; other definite negative Rejected | Bounded safe retry or terminal rejection |
| SMTP SendAsync returns successfully, then disconnect fails | Accepted | Never resend because QUIT failed |
| SMTP connection/cancellation/protocol fault after submission starts, including accepted DATA with lost acknowledgement | Unknown | No automatic retry or fallback |
| Twilio 201 with object/string SID matching SM plus 32 hexadecimal characters | Accepted | Retain validated provider receipt |
| Twilio 429 | NotSubmitted retryable | Provider documents rejected, unprocessed request; bounded retry/fallback |
| Twilio 400/401/403/404/422 | Rejected | Explicit request rejection permits fallback |
| Twilio 5xx, 408, unexpected status, transport/read/cancellation fault, malformed/missing success SID | Unknown | Stop chain; no speculative resend |
| SNS response with usable UUID MessageId | Accepted | Retain validated provider receipt |
| SNS 429, or 400 with known throttle error | NotSubmitted retryable | Bounded retry/fallback |
| SNS other 400/401/403/404/422 | Rejected | Explicit request rejection permits fallback |
| SNS other service/transport/cancellation failures or missing/malformed receipt | Unknown | Stop chain |
| Local disabled/missing configuration/invalid request | NotSubmitted, nonretryable | No provider submission; terminal if no alternative |

The SNS client explicitly sets MaxErrorRetry=0 so hidden SDK retries cannot replay an uncertain Publish. The named Twilio client disables automatic redirects and cookies; no retry handler is added. Twilio faults exercise the real HTTP client/service/chain through an owned handler. SNS tests substitute its client interface: locked AWS SDK wire/retry behavior remains a native qualification obligation. The SMTP matrix uses real MailKit against the owned COR23H encrypted relay, including lost DATA acknowledgement, explicit 451/550 and disconnect after a positive acknowledgement. It sends no external mail and retains COR23H's test-only certificate trust boundary.

A worker attempt may try at most the configured distinct provider chain, sequentially, and advances only after a definite negative. Its one persisted result describes the final provider outcome. No SMTP/SNS/Twilio provider idempotency key or receipt-query API is implemented. SMTP stores the owned attempt UUID as correlation receipt and Message-Id, not an independently queryable provider transaction ID. These identifiers do not establish provider deduplication. A crash after acceptance before receipt persistence can leave a message delivered while its proof remains pending; conservative quarantine trades availability for avoiding a blind duplicate. A safe retry/fallback is justified by confirmed non-submission/rejection, yet cannot guarantee exactly-once behavior if a provider violates its negative-response contract. New independent requests after expiry/cancellation may produce another message; stale proof authority must fail normally.

## Durable attempt and proof fences

Current setup adds delivery_attempts, keyed by the immutable lease UUID and unique (job, attempt ordinal). The job/proof/ciphertext remain stable across bounded safe retries; each claim allocates a distinct attempt identity. Receipt rows carry no plaintext body, destination or proof. A trigger rejects changes to identity/ordinal/creation timestamp or definitive receipts, and prohibits Unknown becoming claimed/NotSubmitted. Existing outbox `ambiguous` is the work-queue quarantine state; the result/attempt receipt is Unknown. It is excluded from send selection while live.

Claim and receipt writes run under the account authority lock. Record requires the exact job/lease binding. Normalized metadata, attempt receipt and job transition commit together. Exact final receipt replay returns true without changing it, including after publication cleared the lease; conflicting receipt replay returns false. Worker publication proceeds only after a successful recording CAS. A failed bounded receipt write leaves the claim for reconciliation. An abandoned expired lease becomes Unknown for the same immutable attempt rather than a fresh send. A trusted late Accepted/Rejected result can resolve only its own live Unknown attempt; Unknown cannot later claim NotSubmitted to requeue. There is no unauthenticated/manual receipt override or automatic provider polling endpoint.

Accepted publication retains COR12 checks for expiry, account stamp, current predecessor and domain authority. Unknown leaves the staged pending proof in place and retains any prior independently valid proof through existing domain lineage. Pending candidates cannot be consumed as delivered proofs. Replaying the same staging request returns its existing job; caller lookup preserves the current pending identity. Existing authorization, stamp/family revocation and explicit cancel are independent security intent, never inferred from an uncertain provider result. Grant activation cancellation still runs through cor19_transition_activation and does not refund the creation budget. Late results cannot resurrect cancelled/expired candidates. Existing domain owners determine which reservation/pending row exists; uncertainty does not undo it as failed delivery.

Quarantine is bounded by the protected candidate's existing TTL (encryption policy clamps payload lifetime to 1–24 hours and domain expiry may be shorter). Expiry and COR22 bounded retention erase nonce/ciphertext/tag and fence pending claims as Unknown without rewriting definitive receipts. Idle worker cleanup retains terminal history seven days and deletes at most 100 terminal candidates per pass; FK cascades erase outbox and attempt history together. This preserves inspectable bounded receipts without an unbounded plaintext or encrypted queue. There is no new retention daemon: progress depends on the existing worker/retention lanes. Active deadlines and cancellation joining remain COR23J's responsibility; WaitAsync abandonment is conservatively Unknown here. Template rendering remains COR23K/L.

## Authored tests and validation

Seventeen new native methods expand to 55 InlineData cases: real SMTP TLS acknowledgement faults and legacy null projection; Twilio malformed/lost/error receipts and definite fallback; SNS uncertainty; malformed typed metadata; actual HTTP adapter/worker/PostgreSQL quarantine; eight proof purposes after restart; immutable attempt identities and bounded retry; late accepted receipt/replay; explicit cancellation/expiry; activation budget preservation; crash without receipt and terminal retention cascade. SQL tests observe actual rows from a second connection and assert ciphertext, pending authority, provider call count and receipt state. They remain authored NotRun, not execution evidence.

Eighteen supplemental Python mutation tests guard conservative projections, fallback, SDK/redirect replay, SMTP phase ownership, attempt identity/CAS, SQL retry and receipt fences, retained ciphertext and cascade cleanup. They inspect source contracts, not provider side effects or SQL execution. Required checks:

```bash
python3 -m unittest discover -s eng/tests -v
python3 eng/check-delivery-outcomes.py
python3 eng/check-smtp-transport.py
python3 eng/generate-database-baseline.py --check
python3 eng/check-sql-output-bindings.py
python3 eng/check-factor-identities.py
python3 eng/check-correction-evidence.py
python3 eng/cor23-reconciliation.py --check
python3 eng/correction-baseline.py --lane all --output .correction-results/cor23i-final
python3 eng/correction-sql-fixture.py
```

Native .NET, PostgreSQL, Docker/cache and PowerShell are unavailable. Application/SQL/SMTP/TLS execution remains Blocked/NotRun and COR24 qualification remains open. R08-02 becomes FixedPendingQualification; the other 83 findings, frozen reviews, original 451-file inventory and all 186 Open gates are preserved. Totals: 61 FixedPendingQualification, 23 Open. Next: COR23J. Reverting to old false/unknown consumers or replaying quarantined jobs is unsafe; a rollback must preserve the current certainty fences and encrypted-key ownership. No production migration, external mail/SMS or deployed rollback was performed.

Primary design references (documentation does not qualify the locked runtime):

- https://www.twilio.com/docs/api/errors/20429
- https://docs.aws.amazon.com/sdk-for-net/v4/developer-guide/retries-timeouts.html
- https://docs.aws.amazon.com/sdkfornet/v4/apidocs/items/Runtime/TClientConfig.html
- https://docs.aws.amazon.com/sns/latest/api/API_Publish.html
