# COR23H — Require authenticated TLS for SMTP

Owns R08-01 only, based on completed COR23G. Implementation is FixedPendingQualification; native compilation and transport qualification are NotRun. This undeployed pre-1.0 project changes the current settings directly. No database/setup/package change, aliases, migration or backfill is introduced. The frozen review/specification remain historical evidence; this document describes the implemented contract.

## Validated, immutable transport

SMTPSettings retains host, port, required credentials and sender validation and adds TransportMode plus AllowIsolatedPlaintext. Supported enum values are RequiredStartTls (default), ImplicitTls and IsolatedPlaintext. Undefined numeric values, unsupported names, unknown properties and malformed host shapes fail validation/binding. Hosts are bare hostnames/IPs without URL, path, embedded port, whitespace or control characters. Startup validation runs before hosted delivery can start.

| Mode | MailKit selection | Policy |
| --- | --- | --- |
| RequiredStartTls | SecureSocketOptions.StartTls | Required upgrade before AUTH, MAIL or DATA; unavailable/refused/fake TLS fails closed |
| ImplicitTls | SecureSocketOptions.SslOnConnect | TLS handshake before SMTP greeting/authentication/submission |
| IsolatedPlaintext | SecureSocketOptions.None | Exact Testing environment, explicit AllowIsolatedPlaintext=true and a literal loopback IP only |

The explicit plaintext mode permits 127.0.0.1/::1, not localhost DNS, private network hosts or Docker service names. Production, Development, LocalHttps, Container, ContainerReverseProxy, ReverseProxy, custom/null/case-mismatched environments cannot enable it. A true permission flag with a secure mode is also invalid. Conventional incompatible port combinations (STARTTLS on 465 or implicit TLS on 587) fail; correctly configured custom ports remain supported. Secure modes are valid in every environment, including direct isolated construction.

All eight shipped profiles explicitly select RequiredStartTls and disable the exception. Base/Example use port 587. Operators provide the actual TLS relay hostname, port and secret credentials before real delivery; no runnable plaintext deployment default remains. The real isolated plaintext Testing lane uses disposable local credentials and an owned relay's published loopback port. COR23D fake/capture providers retain their separate environment/capability boundary and bypass real SMTP; they cannot qualify this transport.

SmtpTransportPolicy copies validated host/port/credentials/sender and mode once. It is a singleton snapshot registered from validated IOptions, not a live mutable settings object. Configuration changes require host restart. Direct SMTPService construction without an explicit policy permits secure modes and rejects plaintext because it has no isolated environment. SMTPService still constructs a new owned client per send; no non-thread-safe session is shared across concurrent mail.

The production SmtpClientFactory allows TLS 1.2/1.3, enables revocation checking and leaves ServerCertificateValidationCallback unset. Normal chain, time, hostname and platform trust validation remain authoritative. There is no certificate-ignore option, test pin, custom root or protocol transcript logger in production. Install an authorized relay CA into the application's/container's OS trust store when private trust is necessary and configure a matching certificate hostname. Deployment trust and real certificate/revocation behavior require native qualification.

The common send boundary connects with the exact policy, then checks IsSecure and negotiated TLS 1.2/1.3 before AuthenticateAsync or SendAsync. Every legacy public mail method and all eight durable payload kinds delegate to this boundary. Missing/refused STARTTLS, failed certificates, fake plaintext upgrades and unsupported negotiated protocol never fall through to opportunistic authentication or message submission. Greeting/EHLO/STARTTLS may precede encryption as required by the protocol; no credentials or message envelope/body do so in secure modes.

Diagnostics preserve the existing sanitized email-kind/recipient-domain/error-type log. Raw exception/provider reply, SMTP credentials, proof, body and full recipient are not logged. No protocol logger is enabled. The accepted-DATA/disconnect handling and bool? delivery result remain unchanged. R08-02/COR23I owns acknowledgement uncertainty and retry/cleanup; R08-03/COR23J owns aggregate deadlines/cancellation; subsequent template corrections own rendering. TLS does not claim exactly-once delivery or mailbox receipt.

## Authored native matrix

19 new attributed methods expand to 63 cases. Ten policy methods cover every shipped profile, exact isolated environment/destination permissions, unsupported enum values, incompatible flags/ports/host shapes, removed/opportunistic values, unknown settings, factory certificate/TLS policy, deployable startup rejection before a worker, and real-provider Testing host startup. Existing SMTP exact-property-name and template-construction tests now reflect the current seven-property schema.

Nine integration methods run the real SMTPService and pinned MailKit against a controlled owned loopback TCP relay. Cases include successful required STARTTLS and implicit TLS; untrusted, expired and wrong-host certificates in both modes; missing/refused/fake STARTTLS; a plaintext relay advertising AUTH; encrypted credential rejection; below-floor TLS; every ten legacy mail methods plus eight durable payload kinds; explicit Testing plaintext; and mutated options after construction. The transcript records only command verbs and encryption state, asserts AUTH/MAIL/RCPT/DATA are encrypted in secure modes, and verifies absence of authentication/submission on TLS failures. Successful DATA is locally captured, never sent externally.

The owned fixture uses ephemeral root/leaf certificates and does not alter OS trust. Successful TLS cases inject a real MailKit client through ISmtpClientFactory with a test-only custom-root validator: it retains SslStream hostname/no-certificate error checks and validates chain, time and server-auth EKU. Fixture root revocation is disabled because that ephemeral CA has no CRL service; production online revocation/default trust is separately asserted and remains a deployment qualification obligation. Untrusted cases use the normal production validation callback behavior. This tests the transport and certificate rejection logic, not a deployed relay trust store.

The server owns one ephemeral port, a 45-second lifetime and bounded line/message reads; clients use bounded per-operation timeouts. Disposal cancels listeners, waits at most five seconds for owned tasks and disposes certificates. Expected rejected-client handshake/EOF errors are contained. A native OS refusing obsolete TLS 1.1 also establishes no-auth/no-data failure; it is not a skipped success. No native result has been observed in this workspace.

## Validation and remaining gates

Supplemental Python mutation tests witness profile defaults, STARTTLS/implicit selection, environment and literal-loopback isolation, explicit permission, TLS floor/revocation, certificate callback absence, encryption ordering, unknown keys and sanitized diagnostics. They are source/configuration checks, not executed MailKit/TLS evidence.

```bash
python3 -m unittest discover -s eng/tests -v
python3 eng/check-smtp-transport.py
python3 eng/check-verification-origins.py
python3 eng/check-request-body-boundary.py
python3 eng/check-security-response-cache.py
python3 eng/check-correction-evidence.py
python3 eng/generate-database-baseline.py --check
python3 eng/cor23-reconciliation.py --check
python3 eng/correction-baseline.py --lane all --output .correction-results/cor23h-final
python3 eng/correction-sql-fixture.py
```

The delivery records executed tooling, exact patch replay/archive integrity and blocked native attempts tied to the final source identity. .NET SDK, PostgreSQL, Docker/cache and PowerShell are unavailable. Compile, SMTP/TLS/certificate/host-start and published/deployed trust results remain NotRun. R08-01 is FixedPendingQualification; the other 83 findings, original 451-file inventory, frozen reviews and all 186 Open gates remain preserved. No finding or release gate is Closed. Totals: 60 FixedPendingQualification, 24 Open. Next ordered correction: COR23I.

Rollback must retain required authenticated TLS or the explicitly isolated Testing loopback contract. No insecure deployment/exposed credentials were established; credential rotation is not asserted as a performed action. Primary design references: MailKit SecureSocketOptions and SmtpClient properties documentation (currently newer than locked 4.16.0), and upstream 4.16.0 release notes. These references do not qualify the locked runtime:

- https://mimekit.net/docs/html/T_MailKit_Security_SecureSocketOptions.htm
- https://mimekit.net/docs/html/Properties_T_MailKit_Net_Smtp_SmtpClient.htm
- https://github.com/jstedfast/MailKit/blob/master/ReleaseNotes.md
