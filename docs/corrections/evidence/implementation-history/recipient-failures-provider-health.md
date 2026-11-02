# COR23K — Separate recipient failures from provider health circuits

Owns R08-04; based on completed COR23J. FixedPendingQualification, with native compilation, real-cache concurrency and actual transport execution NotRun. The current frozen COR23K specification owns provider health; the earlier COR23J document's statement assigning rendering to K/L was mistaken. Rendering remains COR23L's separate owner. Frozen review/specification and earlier implementation documents are preserved.

## Admission and health are separate

DeliveryAbuseThrottleService retains the same atomic account, destination fingerprint and client-IP budgets. Its existing untyped RecordProviderFailureAsync surface has no circuit authority: callers cannot infer an outage from a bool/null or catch. It no longer increments or reads providerfailure-email/providerfailure-sms channel cooldowns. Those old ephemeral keys are disregarded and expire naturally; no user budget is reset, deleted, renamed or bypassed. FailureCooldownSettings continues to own other abuse policies, not provider health.

IProviderHealthService is registered against the host's shared AbuseCounters CacheConnectionSlot. Every production SMTP/SMS physical attempt acquires a permit for its configured route, then rechecks COR23J's current authority under the same attempt/aggregate token before invoking the transport. Skipped providers have confirmed non-submission, so a healthy distinct fallback may be tried. Known recipient/credential/payload rejection may retain the existing safe fallback rule. An outage result that is Unknown never permits fallback or retry; opening a health circuit changes future attempts, not the acceptance or proof state of the current message. All blocked routes produce retryable NotSubmitted under COR23I's bounded retry/expiry rules. Emergency channel stops prevent physical delivery but do not erase or bypass admission budgets.

ProviderDeliveryResult and DeliverySendResult carry separate ProviderHealthEvidence. It is not persisted as receipt authority and cannot alter the existing acceptance lattice, immutable attempt identities, SQL receipt rules, publication or proof consumption. Invalid evidence enum metadata is normalized conservatively. SMTP reports health only after its actual task unwinds; SMS reports each actual distinct provider outcome. Health report failure never replaces a known Accepted/Rejected/Unknown outcome. Cancellation/late reporting may leave an expiring permit; it cannot fabricate successful recovery.

| Evidence | Classification |
| --- | --- |
| Healthy | Actual accepted SMTP DATA or a valid SMS provider receipt |
| Outage | SMTP socket/I/O service failure when caller token is not cancelled, SMTP 421, Twilio/SNS explicit throttling or server 5xx, uncancelled HTTP transport failure |
| Neutral | Recipient rejection, invalid request, missing configuration, auth/TLS configuration failure, malformed receipt without independent outage evidence, cancellation, untyped exceptions |

SMTP pre-submission outage remains confirmed non-submission; faults after possible submission remain Unknown. Twilio 5xx/SNS uncertain service failures remain Unknown even while counting outage evidence. HTTP 400/401/403/404/422 and SNS equivalent explicit negatives remain neutral health evidence. A credential failure does not disable unrelated providers. Existing provider hidden-retry/redirect restrictions, authenticated TLS and receipt validation remain unchanged.

## Bounded distributed state

Health has one `delivery:health:v1:<provider>:<128-bit-route-fingerprint>` hash per configured route. Provider is the fixed smtp/twilio/aws-sns set. The key never contains end-user account, destination, IP, proof or credentials. SMTP's route fingerprint includes operator scope, relay host/port and service username; Twilio includes operator scope and configured account SID. SNS uses the operator-owned AwsSnsScope identifying its credential/account/region route under the SDK's existing default credential/region resolution. Set a distinct stable scope for distinct SNS account/region routes, and use the same scopes across replicas sharing each route. Configure SmtpScope/TwilioScope similarly when operator route identity is otherwise distinct. Credential/region changes require a host restart and deliberate scope update; a route hash is not automatic provider account discovery.

Settings are validated and snapshotted per host. All eight profiles ship the same defaults:

| ProviderHealthSettings | Default | Validation |
| --- | --- | --- |
| Enabled | true | Automatic health only; emergency controls are independent |
| EmergencyEmailStop / EmergencySmsStop | false / false | Explicit operator channel stops, effective after restart |
| FailureThreshold | 5 | 1–100 outage completions |
| WindowSeconds | 300 | 10–3600, fixed server-time outage window |
| OpenSeconds | 60 | 1–900, route cooldown and failed/neutral probe recovery wait |
| PermitSeconds | 45 | 45–120, greater than maximum 30-second aggregate + 5-second drain + bounded health reporting |
| MaxInFlightPerRoute | 32 | 1–128 unexpired health permits across replicas |
| SmtpScope / TwilioScope / AwsSnsScope | default | Required operator labels, `[a-z0-9-]{1,64}` |

Two fixed embedded Lua scripts use one explicit key and Redis server TIME. Acquire/complete each perform their entire decision atomically. Closed state allocates bounded numbered permit slots with ID/deadline. Outage completion increments only once within the fixed window; threshold opens the circuit and rotates the generation, invalidating older results. Closed healthy results do not erase concurrent outage evidence. Exact generation, slot, permit ID and live deadline fence completion and duplicate replay.

After the open interval, exactly one unexpired half-open probe is admitted across replicas. Only Healthy completion closes/reset-counts/rotates the circuit. Neutral or Outage probe completion reopens it. Abandoned/expired probe acquisition first reopens for another bounded interval; its late result cannot close a newer state. Closed expired permits are reusable, but stale completion cannot mutate the new holder. Route state expires after window + open + permit (405 seconds by default; bounded maximum 4620 seconds), refreshed by activity. Fields are bounded to 6 control fields plus 2 per configured slot. Previous configurations' idle route hashes expire; keys and script bodies are not generated from recipients.

Permit expiration authorizes later health checks; it does not prove an uncooperative transport has terminated. COR23J still owns the underlying Task and retains its local capacity slot until actual completion/process exit. The policy bounds unexpired health permits, not global cluster-wide physical work or exactly-once delivery. No durable cache dependency is introduced for already accepted SQL receipts. Cache acquire failure/corrupt response denies transport (safe fallback may consult an independently allowed provider); complete failure leaves conservative expiring state. Existing DependencyDeadline observes cache tasks after a timed-out wait, as Redis commands lack caller cancellation; no split GET/INCR/SET circuit writes are issued.

Metrics expose only the fixed provider and bounded action names; route fingerprints, configured scope, recipient/domain, service account and proof are omitted. Circuit blocks, cache acquisition/report failures, accepted/neutral/outage completions, stale receipts and probes are distinguishable. Production uses the health service through DI; directly constructed isolated legacy tests may explicitly use the null fixture service. Disabled auto-health does not disable explicit emergency stops or user budgets.

## Regression coverage and qualification

17 authored native methods expand to 34 cases. Unit/owned transport tests classify real HTTP adapter responses and SNS client responses independently of acceptance, retain Unknown fallback fences, skip an open primary safely, assert all-blocked non-submission, cache failure/cancellation and emergency controls, and reject invalid settings. Owned MailKit/TLS tests reject one recipient then accept another on the same route, keep authentication/STARTTLS rejection neutral, and prove an open route creates no socket.

Actual cache tests use two independent connections and new service instances. They author 64-way permit and recovery-probe races, exact concurrent outage threshold and duplicate/old-epoch fences, independent providers/routes, fixed window, retained account budgets, expiry/corruption, and the real Twilio adapter joined to the cache: repeated HTTP 400 does not open health, while 500 remains Unknown without current-message fallback and opens only Twilio for subsequent safe selection. These are NotRun in this environment. Twenty supplemental tooling tests include source mutations and eleven scenarios executing the actual Lua script bodies with an explicit deterministic command shim. The shim is not Redis/Dragonfly concurrency, deployment or transport qualification.

The DI owner now explicitly imports the delivery namespace for the current/new transport policies. Three duplicate CancellationToken arguments in COR23I mock assertions introduced during COR23J test adaptation are corrected without changing their acceptance assertions. Existing recipient/cooldown tests now assert ignored old ephemeral channel state and intact account/destination/IP counters. Earlier native methods and original finding references are preserved.

```bash
python3 -m unittest discover -s eng/tests -v
python3 eng/check-provider-health.py
texlua eng/tests/cor23k-health-boundaries.lua .
python3 eng/check-delivery-outcomes.py
python3 eng/check-delivery-deadlines.py
python3 eng/check-correction-evidence.py
python3 eng/cor23-reconciliation.py --check
python3 eng/correction-baseline.py --lane all --output .correction-results/cor23k-final
python3 eng/correction-sql-fixture.py
```

The archive records final-source validation and exact patch replay/archive checks. .NET SDK, PostgreSQL, Docker/cache and PowerShell are absent; native lanes remain Blocked/NotRun. No native threshold, recovery latency, throughput, provider wire behavior or external mailbox delivery is claimed. No schema/setup/migration, backfill or compatibility alias is added. Reverting recipient-driven channel gating reopens R08-04; rollback can adjust validated budgets or disable automatic health while preserving explicit emergency stops and user budgets. Do not reset user budgets when updating route scope. R08-04 becomes FixedPendingQualification; the other 83 findings, original inventory, frozen evidence and all 186 Open release gates are retained. Totals: 63 FixedPendingQualification, 21 Open. Next: COR23L.

Primary design references (not execution evidence): https://redis.io/docs/latest/commands/eval/ and https://redis.io/docs/latest/develop/interact/programmability/ .
