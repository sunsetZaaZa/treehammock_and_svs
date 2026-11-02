# Treehammock review 08 — Providers, delivery and templates

Reviewed 2026-10-03 against the unchanged uploaded source. This is source review and a correction-plan addendum; no application fixes or provider sends were performed.

**Five new findings: one P1 and four P2. Cumulative: 64 open findings, comprising 18 P1 and 46 P2.** All 19 files assigned to R08 received complete source inspection, including all four assigned test files. No finding is closed. Next is **R09 — health, abuse controls, observability, replay coordination and system-test support**.

## Scope and evidence limits

Reviewed SMTP configuration/transport/template rendering, SMS provider naming and fallback, AWS SNS and Twilio adapters, provider results, test delivery adapters, six assigned email templates and four provider/SMTP test files. Focused cross-checks cover startup validation, caller cleanup, password-reset delivery, delivery throttling/cooldown, dependency versions and template publishing. Additional reset/unlock/deletion templates were checked to trace active methods. The inventory distinguishes full assigned-file review from targeted cross-chunk inspection; it does not declare R09/R10 complete.

Pinned dependencies include MailKit/MimeKit **4.16.0**, AWSSDK.Core **4.0.7.1** and AWSSDK.SimpleNotificationService **4.0.2.33**. Published MailKit reference pages consulted currently describe 4.17.0; their TLS/cancellation contracts support source interpretation, while exact pinned transport behavior still needs execution.

The unit runner exited **127**, before restore/build/test, because the .NET SDK is absent. Docker, PostgreSQL tools and Redis server are also absent. No network delivery, packet capture, provider-account inspection, real cooldown test, load test or benchmark ran. Fault scenarios below are source-derived expected behavior, not reproduced incidents. All 451 source files and the source archive were hash-checked against the upload; application code is unchanged. No credentials, live proof payloads or private configuration values are included in this report/evidence.

## Findings

| ID | Priority | Defect | Correction owner |
|---|---|---|---|
| R08-01 | P1 | SMTP explicitly disables TLS before authentication and security-mail submission. | COR23H |
| R08-02 | P2 | Unknown delivery outcomes are treated as non-delivery, enabling blind fallback and destructive proof cleanup. | COR23I |
| R08-03 | P2 | Delivery cancellation stops at callers; adapters have no application-wide deadline. | COR23J |
| R08-04 | P2 | Recipient/configuration failures can trip a channel-wide cooldown for unrelated users. | COR23K |
| R08-05 | P2 | Enabled Twilio routing passes startup validation with missing required transport settings. | COR23L |

### R08-01 — SMTP has no secure production transport path

**Evidence.** `Services/SMTPService.cs` 118–124 creates a client, connects with `SecureSocketOptions.None`, then authenticates and submits the message. Every SMTP method delegates to that path. `Rigging/Config/SMTPSettings.cs` exposes server, port, username/password and sender address, with no TLS policy. Changing the deployment hostname/port cannot select STARTTLS or implicit TLS.

**Impact.** Successful SMTP sessions send security-mail contents without TLS on this application-to-relay hop. Credentials may also be exposed when the server selects a plaintext authentication mechanism; not every SASL mechanism transmits the literal password. Verification links, reset/unlock codes, factor proofs and activation codes all use this service. A relay requiring TLS can instead reject/fail the connection or authentication, making those workflows unavailable. The default localhost:1025 test relay is a deliberate local configuration, but the same hardcoded option is used after configuring a remote production relay. No observed interception or deployed relay is asserted.

The primary [MailKit SecureSocketOptions reference](https://mimekit.net/docs/html/T_MailKit_Security_SecureSocketOptions.htm) defines None as disabling encryption. It distinguishes required STARTTLS and implicit TLS from opportunistic modes that can continue without encryption.

**Correction.** Add a validated transport policy requiring STARTTLS or implicit TLS for production, with normal certificate/hostname verification. Fail before authentication/submission if encryption cannot be established. Make any plaintext test relay exception explicit and isolated, coordinated with R07-01; do not substitute Auto/StartTlsWhenAvailable where production requires encryption. Never solve certificate failures by accepting every certificate. Retain sender and credential validation without logging their values.

**Required regression.** Use a controllable SMTP server: successful required STARTTLS and implicit TLS; missing STARTTLS; invalid/untrusted or hostname-mismatched certificates; credentials rejected; and the explicitly allowed isolated plaintext lane. Assert that AUTH and DATA are never sent before required encryption. Include all public SMTP methods via the common transport boundary. Current SMTP tests check configuration/property names and fallback template construction, not secure transport.

### R08-02 — Unknown acknowledgement becomes false delivery authority

**Evidence.** SMTP catches all transport errors and returns null (`SMTPService.cs` 127–134). SMS results have Sent/Failed/ProviderUnavailable/etc. but no unknown-acceptance state (`ProviderDeliveryResult.cs`). Twilio maps timeout/network exceptions to ProviderUnavailable (`SmsSender.cs` 315–323), and a response missing a usable SID to Failed (176–180). AWS generic errors become Failed (`AWSService.cs` 103–106). `SmsSender.cs` 64–78 tries the next provider after every non-success, regardless of whether the first may have accepted the message.

Caller consequences are concrete: `AccountService.cs` 269–272 cancels an email-change request after non-success and 362–365 cancels deletion; `ActivationService.cs` 139–143 cancels a pending activation; `PasswordResetService.cs` 348–361 cancels the reset artifact and 581–583 revokes the proof session. These paths cannot distinguish an actual rejection from a message accepted remotely whose response was lost. Signup/resend have a different pending response policy; this finding does not claim every caller deletes its proof.

**Inferred failure schedule.** Provider A accepts an SMS POST, then the acknowledgement is lost: the adapter reports failure and the chain submits the same message to provider B, producing duplicate deliveries/spend. Alternatively the SMTP server accepts DATA, but the final acknowledgement does not reach the client: a null result causes callers to cancel a proof whose message may still arrive. A lost/malformed success response has the same uncertainty. Cancellation does not prove the remote side did nothing. Provider SDK retry behavior must also be included in this accounting; an application outbox alone cannot create exactly-once network delivery.

SMTP acceptance is described in [RFC 5321](https://datatracker.ietf.org/doc/html/rfc5321), section 4.2.5. As a contrast to an unknown network result, [Twilio's 20429 documentation](https://www.twilio.com/docs/api/errors/20429) explicitly says an HTTP 429 request is not processed and permits a retry with backoff. Do not generalize that guarantee to timeouts or all 5xx responses.

**Correction.** Carry typed delivery outcomes end to end: accepted, definitely rejected/not submitted, unknown acceptance, configuration failure and cancellation before submission. Persist operation/job identity, provider attempt/receipt and proof lineage in COR12's durable delivery design. Retry/failover only under a documented safe classification or an explicit bounded duplicate-tolerant policy; reconcile when the provider offers a usable lookup/idempotency contract. Unknown acceptance must not immediately erase proof authority as though non-delivery were certain. Preserve explicit user cancellation/security revocation independently. Define accepted submission separately from final mailbox/handset delivery; do not claim receipt from an API message ID.

**Required regression.** A fake HTTP provider and SMTP server record acceptance, then drop the response. Assert the job/attempt remains unknown, fallback does not run blindly, delivered proof remains subject to the declared pending/expiry policy and operation replay cannot create uncontrolled new sends. Test definite pre-submission failure, recipient rejection, safe 429, malformed acceptance response and genuine accepted receipt separately. Verify cleanup from another database connection for reset, email change, deletion and activation. Tests that merely return ProviderUnavailable from a mock do not establish safe failover.

### R08-03 — Cancellation and elapsed-time budgets do not reach transports

**Evidence.** `ISMTPService`, `ISmsSender`, `ITwilioMessageClient`, `IAwsSnsSmsClient` and their implementations accept no cancellation token. SMTP calls Connect/Authenticate/Send/Disconnect without one; Twilio calls `HttpClient.SendAsync(request)` at 159; AWS calls PublishAsync without a token at 22–26. There is no per-delivery aggregate deadline in these adapters/settings. `PasswordResetDeliveryService.cs` 70 checks the supplied token only before entering the send path: the private methods at 92/129 do not accept it, and their throttle/network calls omit it. Cancelling after that first check cannot stop their subsequent work through the supplied token.

**Impact and limits.** Abandoned requests can retain delivery work and continue provider submission. Serial primary/secondary attempts, SDK retries and connection/authentication phases can outlive the caller's intended budget or proof lifetime. This is not a claim of infinitely unbounded socket waits: library/HTTP/SDK defaults exist, but they do not form an application-defined total budget or propagate the caller's cancellation. AUTH-02 concerns database rotation; this finding separately covers delivery boundaries.

**Correction.** Define total and per-attempt delivery deadlines, bounded concurrency and retry budget, then propagate appropriate cancellation through admission and transport calls. For an accepted durable outbox job, worker lifetime/deadline governs delivery rather than the original request's later disconnect. Request cancellation before durable acceptance and worker shutdown after acceptance require different policies. Revalidate authority/expiry before starting each attempt and abandon superseded/expired jobs; an already accepted remote send cannot be recalled. Classify cancellation after possible submission as unknown per R08-02 instead of automatically false. Carry separate diagnostic reasons without charging a user proof-attempt budget.

The primary [MailKit ConnectAsync contract](https://mimekit.net/docs/html/M_MailKit_Net_Smtp_SmtpClient_ConnectAsync_2.htm), [SendAsync overloads](https://mimekit.net/docs/html/Overload_MailKit_Net_Smtp_SmtpClient_SendAsync.htm) and [AWS PublishAsync contract](https://docs.aws.amazon.com/sdkfornet/v4/apidocs/items/SNS/MSNSPublishAsyncPublishRequestCancellationToken.html) expose cancellation parameters; the adapter boundary currently omits them.

**Required regression.** Block admission, SMTP greeting/TLS/auth/DATA, HTTP response and SNS publish separately; trigger cancellation/deadline and assert prompt bounded local completion, released capacity and correct definitive/unknown state. Cancellation before submission must prevent provider calls. Do not start fallback after the aggregate deadline, expiry or observed cancellation. Confirm a durable accepted job can continue under its worker budget after client disconnect, without resurrecting revoked proofs. Measure p95/p99 elapsed time and concurrent in-flight operations under hung providers.

### R08-04 — A recipient error can suppress the whole channel

**Evidence.** SMS adapters distinguish Rejected, ConfigurationMissing, Disabled and ProviderUnavailable, but `SmsSender` reduces all exhausted-chain failures to false. `TwoFactorAuthenticateService.cs` 101–104 and 129–132 count every false as a provider failure. `AccountService.cs` 597–600 and `PasswordResetDeliveryService.cs` 122/160 similarly record unsuccessful results without classification.

`DeliveryAbuseThrottleService.cs` 116–133 increments one key produced at 179–184: `providerfailure-email` or `providerfailure-sms`. It contains neither provider identity nor recipient/account scope. Admission at 80–91 checks that channel cooldown before account/destination/IP limits. A recipient-specific permanent rejection can therefore be accumulated as evidence of a platform-wide transport outage.

**Inferred impact.** An unhealthy/rejected set of recipients can deny security delivery for unrelated accounts and healthy destinations for the channel cooldown. Defaults enable this policy, with MaxAttempts/FailureThreshold 5, a 900-second window and 900-second cooldown. The current real counter accepts counts up to five and starts cooldown when count exceeds the limit: the sixth recorded failure can trip it, subject to admission limits, timing and cache availability. Sufficient failures across admitted destinations/accounts are enough; no claim of one account's unlimited SMS requests is made. R03-08's missing setup account ID can exacerbate the issue but is an independent existing defect.

**Correction.** Pass the typed provider result into health/circuit policy. Attribute only appropriate transport/provider-health failures to provider/account/region-scoped circuits. Recipient rejection, invalid input, disabled feature and missing configuration require their own handling; they are not evidence that all recipients/providers are unavailable. Preserve per-user/destination/IP abuse budgets, avoid attacker-controlled unbounded circuit keys, and permit a healthy fallback only when R08-02 makes retry safe. A channel-wide emergency breaker may remain explicit operator policy rather than being driven by arbitrary rejected recipients.

**Required regression.** Repeated definite recipient rejections never block another account's valid recipient. Verify isolated AWS/Twilio failures, healthy alternate providers, configuration errors, disabled routes, real threshold boundary (five versus six), cooldown recovery and multiple instances sharing the cache. Existing DeliveryAbuseThrottlePolicyTests assert the channel-global key and denial behavior; they do not test whether the failure is appropriate evidence for that key.

### R08-05 — Twilio can be configured unusably while startup remains valid

**Evidence.** `SidewalkSettings.cs` has nullable Twilio SID, auth token and sender, without conditional validation. `ConfigurationValidation.cs` 44–84 checks configured provider names, duplicate aliases, feature flags and enabled routing, but does not check those transport prerequisites. DI validates these options at startup; a Twilio-only enabled chain with blank prerequisites still passes this validator. Only `TwilioSmsService` at `SmsSender.cs` 281–293 discovers the missing settings during a real send. The unit test `TwilioSmsService_returns_configuration_missing_before_provider_call` confirms that adapter guard exists; it does not exercise production startup.

**Impact.** The host can advertise enabled SMS/factor/recovery workflows while every send on its only configured route returns ConfigurationMissing. A missing secondary also leaves advertised failover unusable. Current startup tests cover routing names/flags/aliases, without missing Twilio credentials/sender cases. This is validation of known required local settings, not a demand to authenticate to every external provider during startup.

**Correction.** Validate each selected enabled route's required local prerequisites, with conditional rules that keep genuinely disabled/unused providers optional. Diagnose the missing setting name without revealing values. Validate sender shape according to the supported sender contract; keep the runtime adapter checks as defense. External credentials validity, AWS credential/region resolution and provider readiness need a separate deployment/readiness policy rather than an invented requirement for hardcoded AWS secrets.

**Required regression.** Start a real host with Twilio primary/secondary settings independently missing SID, token or sender: startup fails with a sanitized configuration diagnostic. Valid selected routes pass; disabled/unused routes may omit credentials. Real readiness tests separately cover credential rejection without classifying it as bad user proof or an invalid recipient.

## Positive checks and remaining measurements

| Surface | Source result / follow-up |
|---|---|
| Twilio transport | HTTPS fixed endpoint; escaped account SID; per-request Basic authorization; encoded form fields; request/response disposal; factory-created client. No static SDK credential initializer or mutable shared authorization header. Test coverage checks request shape and 429/rejection mapping. |
| SMS composition | Alias normalization, ordered primary/secondary routing and deduplication exist. Disabled routes fail closed. Startup rejects unknown/duplicate aliases and selected disabled providers. Typed results exist inside adapters, but caller policy loses that information. |
| AWS adapter | Uses SDK credential/region resolution, checks nonempty returned message ID and classifies service rejection/throttling. The concrete client is constructed/disposed per publish. Prefer a lifecycle-owned SDK client where suitable, and measure actual pool/credential-resolution costs before claiming connection churn. |
| SMTP construction | Loads templates once per singleton; resolves published-base and working-directory paths; supplies fallback content if files are absent. A new SMTP connection/authentication session is created for each message. Measure setup costs and adopt a bounded pool/worker if justified; never share a non-thread-safe SMTP session concurrently. |
| Templates | All six assigned templates contain the expected link/code markers; configured reset/unlock/deletion files exist and publishing metadata includes HTML/TXT templates. No remote image/tracker resources were found in assigned templates. Add production-render tests and plaintext alternatives for email accessibility. |
| Rendering policy | Rendering uses string replacement without context-aware HTML encoding or placeholder validation. Current proofs are server-generated and origins are trusted configuration, so no proven request-controlled HTML injection is added. Encode values by HTML text/attribute context, validate URL schemes and test special characters as renderer hardening. R07-04 still owns wrong origins. |
| Fallback templates | Missing files deliberately use functional fallbacks; this is tested. Record fallback use rather than silently losing branded/security copy. Unreadable files or malformed markers need startup/render diagnostics. Absence of a required visual design is not counted as an authentication failure. |
| Test providers | System adapters capture proofs and return success while bypassing production template rendering/SMTP/Twilio/SNS. Test SMS normalization can add +1 for unqualified numbers; production destination logic differs. Capture-based system tests cannot qualify TLS, rendering, real destination contracts or lost acknowledgements. R07-01 still owns isolation. |
| Logging/status | Normal provider logs omit raw bodies/code values; SMTP logs recipient domain. Exception/provider reply text can still carry provider-supplied PII: test sanitization. Sent represents accepted submission, not observed handset/mailbox delivery. Delivery receipts/bounce handling require explicit scope and signature/security/retention policy if adopted. |
| Deferred surfaces | AspenTrees is a passive unused provider model; no active provider workflow is proven. SMSHardStop is not an enforced transport spend cap in these paths. Document supported capability/budget contracts rather than presenting placeholders as implemented features. |

Under COR22, measure SMTP setup latency, SMS provider retries/fallback, queue age, proof lifetime remaining, failed/unknown outcomes, allocations, open sockets and throughput under outages. Short expiry margins, duplicate delivery and channel suppression are correctness concerns before throughput tuning. No performance target is reported as achieved.

## Detailed correction-plan addendum

The delivered design/PR plan covered 52 findings; R06/R07 added COR23A–G. Add COR23H–L below, scheduled with their prerequisites. These are concrete review-derived PR specifications, not opened/implemented PRs. COR12 remains the owner of the existing durable delivery/replacement architecture; this addendum supplies transport/state/circuit acceptance requirements underneath it. The trusted-grant activation decision is unchanged. Original Word artifacts have not been rewritten.

### COR23H — Require authenticated TLS for SMTP

- **Owns:** R08-01. **Depends on:** COR01 and configuration composition; coordinate the isolated test relay with COR23D. Can be delivered before outbox migration.
- **Files:** SMTP settings/validation/service, SMTP transport seam/controlled-server tests, deployment examples and exact-property-name tests.
- **Implementation:** supported TLS enum/policy, required STARTTLS or implicit TLS production path, certificate validation and explicit isolated plaintext exception. Reject incompatible settings; sanitize auth/protocol diagnostics.
- **Acceptance:** the transport matrix above runs against pinned MailKit; no AUTH/DATA before encryption; invalid certificates or unavailable required TLS fail closed; real local test lane remains usable. Exercise startup and published configuration.
- **Migration/rollback:** configure relay mode/cert trust and credentials before rollout. Rotate exposed SMTP credentials if an actual insecure deployment is established. Do not roll back into plaintext production transport.

### COR23I — Preserve unknown acceptance and constrain retries/cleanup

- **Owns:** R08-02. **Depends on:** COR03 typed failures, COR04 operation identity and COR12 outbox/proof lineage; coordinate activation producers with COR21.
- **Files:** provider result/SMTP/SMS contracts and adapters; outbox attempt/receipt schema/worker; reset, email, deletion and activation caller cleanup; acknowledgement-loss tests.
- **Implementation:** immutable attempt identity and explicit Accepted/NotSubmitted/Rejected/Unknown state, safe retry table per provider/error, bounded reconciliation/retention, ciphertext payload ownership and idempotent caller outcomes. Preserve explicit security revocation even when delivery is unknown. Specify tolerated duplicate behavior where providers cannot deduplicate.
- **Acceptance:** accepted-then-lost responses and malformed success receipts cannot trigger blind cross-provider sends or immediate non-delivery cleanup. Definite failures still permit the intended cleanup/retry. Verify job receipt/proof state after crash/restart and response replay, with current version/expiry. No outbox-only exactly-once claim is accepted.
- **Migration/rollback:** version delivery results and producer/worker payloads; backfill pending state only when authority can be established. Do not allow old workers/callers to consume Unknown as false. Drain compatible jobs before removing keys or reverting consumers.

### COR23J — Propagate cancellation and bound delivery work

- **Owns:** R08-03. **Depends on:** COR03 and coordination with COR12/COR23I state semantics.
- **Files:** all delivery/provider interfaces and adapters, caller/throttle paths, worker policy and settings; controllable cancellation/latency tests.
- **Implementation:** total/per-attempt deadlines and bounded worker concurrency, cancellation-aware SDK/HTTP/SMTP calls, expiry/authority check before attempts, no fallback after budget exhaustion, phase-aware cancellation outcome. Request and durable-job lifetimes remain distinct.
- **Acceptance:** blocked phase tests observe propagated cancellation and released local capacity; no new provider work starts after expiry/deadline; possible remote acceptance remains unknown. Accepted durable jobs survive client disconnect under their own bounded lifecycle. Profile under hung primary plus secondary/retry workloads.
- **Migration/rollback:** introduce validated budgets and document compatibility. Preserve accepted job ownership at shutdown and across worker versions; rollback may adjust budgets but cannot erase uncertain attempts or remove all limits.

### COR23K — Separate recipient failures from provider health circuits

- **Owns:** R08-04. **Depends on:** COR05 atomic cache windows and COR23I typed provider outcomes; coordinate COR12 delivery admission and R09 abuse-policy audit.
- **Files:** DeliveryAbuseThrottleService/request/result policy, delivery callers, circuit keys and telemetry, real-cache/multiple-instance tests.
- **Implementation:** classify circuit-eligible failures, bounded provider/account/region key space, recipient-specific failure policy, explicit emergency channel breaker and safe healthy-provider selection. Preserve account/destination/IP budgets.
- **Acceptance:** bad recipients cannot block unrelated valid users; healthy providers remain usable under the safe retry policy; actual provider outage opens only intended circuits; recovery/half-open probes are bounded. Verify real-cache threshold and existing atomicity rules under concurrency, not just a mock key assertion.
- **Migration/rollback:** version circuit keys and let old ephemeral channel keys expire or deliberately disregard them after policy rollout. Never clear durable user budgets as circuit migration. Reverting global recipient-driven gating reopens the finding.

### COR23L — Validate selected SMS transport prerequisites at startup

- **Owns:** R08-05. **Depends on:** COR01/configuration tests; coordinate COR23D test-host composition and deployment/readiness policy.
- **Files:** SidewalkSettings/ConfigurationValidation, startup tests, deployment examples/readiness diagnostics; retain adapter runtime guards.
- **Implementation:** conditional local prerequisite validation for selected enabled Twilio routes and supported sender format; unused/disabled routes remain optional. Emit setting names only. Keep remote credential validity/readiness separate from static validation.
- **Acceptance:** real host startup matrix rejects each missing prerequisite in primary/secondary positions; valid and disabled-provider matrices pass; diagnostics/logs contain no credential values. Verify missing secondary cannot masquerade as available failover.
- **Migration/rollback:** update secret/config provisioning before enabling routes; validate configuration in deployment CI. No database migration; remove/disable unusable routes explicitly rather than continuing silently.

## Evidence and next chunk

The cumulative bundle contains R01–R08 reports/static evidence, builders, blocked validation attempts and the latest 451-file inventory/64-finding ledger. The R08 builder verifies archive/source parity, transport/result/cancellation/circuit/configuration patterns, test catalogs, template markers/resource references, publishing metadata and one correction owner per new finding. These are structural assertions; they do not execute MailKit, AWS, Twilio, PostgreSQL or Redis/Dragonfly.

R09 follows the mapped scope: health/dependency readiness, abuse controls/counters, operational telemetry, mutation replay and test support. R10 retains the broad test/dependency/build/operations/documentation audit and the three partial R06 SQL-test files. Feature completeness requires fixes or explicit dispositions, runtime fault/state/concurrency evidence and measured performance budgets; the source pass alone cannot qualify release.
