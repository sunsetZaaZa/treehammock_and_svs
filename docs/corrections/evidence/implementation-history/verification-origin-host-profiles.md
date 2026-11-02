# COR23G — Make verification origins match public hosting profiles

Owns R07-04 only, based on completed COR23F. Implementation is FixedPendingQualification; native qualification is NotRun. This is the direct pre-1.0 configuration contract: no schema/setup/package change, migration, backfill, compatibility redirect or data transition. No deployed or already-emailed URL population has been established for this greenfield project.

## One configuration-owned origin

RegistrationSettings.PublicOrigin replaces the three repeated AccountVerificationBaseUrl, AccountEmailChangeVerificationBaseUrl and AccountDeleteVerifyBaseUrl settings. There are no aliases or relative-URL fallback. Registration settings reject unknown keys; update the current configuration directly. All other existing registration validation and proof periods remain in force.

The origin is required and must be an absolute HTTP(S) authority, optionally ending in a single root slash. Credentials, a path prefix (including normalized dot paths), query/fragment, whitespace/control characters, backslashes, wildcard/unspecified bind addresses and port zero are rejected. Input is bounded to 2048 characters. Raw syntax is checked before System.Uri normalization so `/a/..` cannot masquerade as an origin. Authority normalization uses System.Uri, and all payloads use Uri.EscapeDataString.

VerificationLinkBuilder owns one readonly URI snapshot and three fixed routes. AccountService uses it for initial registration and resend, email change and deletion, including the existing encrypted outbox delivery intents. The host registers one immutable builder from validated IOptions. Request Host, X-Forwarded-Host, Forwarded, effective scheme and forwarded-header trust never select emailed authorities. Changes to configuration require restarting the host to adopt a new origin.

| Profile/composition | Canonical origin/input | Listener contract |
| --- | --- | --- |
| Base / Example / Development | https://localhost:5001 | Explicit Kestrel HTTPS settings |
| LocalHttps | https://localhost:5001 | Direct local HTTPS |
| Container / direct Compose | http://localhost:5001 | Published direct API listener |
| ContainerReverseProxy / proxy Compose | http://localhost:8080 | Recipient-visible HAProxy edge |
| Testing | http://localhost:5001 | Explicit local fixture/host override when using another listener |
| ReverseProxy | Required operator input; overlay is empty | Public TLS terminator, separate HTTP backend |
| Production | Required explicit non-loopback HTTPS origin | Deployment-specific public endpoint |
| Launch profile http | http://localhost:5001 | Explicit HTTP/HTTP1AndHTTP2, no HTTPS redirect |
| Launch profile https | https://localhost:5001 | HTTPS listener/browser URL agree |
| IIS Express | https://localhost:44323 | Declared IIS SSL port; explicit Kestrel listeners disabled |

Environment-aware validation runs on startup before hosted delivery starts. Production rejects inherited localhost defaults and HTTP; a missing origin also fails required options validation. HTTP is allowed only in exact Development, Testing, Container and ContainerReverseProxy lanes; generic ReverseProxy, Staging/custom deployment environments require HTTPS. Direct isolated tests without an environment use explicit validated fixture origins; a running host passes its actual IHostEnvironment.

Docker defaults reflect the recipient's published listener, not internal `api:5001` DNS. Set TREEHAMMOCK_PUBLIC_ORIGIN for both direct/proxy Compose when publishing another authority. Both compositions map it to RegistrationSettings__PublicOrigin with matching local defaults. Disposable testing overlays keep the chosen transport origin. Host system Bash/PowerShell wrappers explicitly use http://localhost:8080; PowerShell also restores the prior environment value in its existing cleanup. Runner ownership/readiness/failure findings remain with their existing COR23 owners.

The default localhost origin targets a browser on the stack host. A separate machine requires an explicit reachable public authority. Container-internal test clients must map a captured path/query through their test base URL or set an origin reachable from that client. Public reachability, DNS, deployed TLS and trusted proxy routing require COR24 execution; matching configuration alone does not establish reachability.

## Routes and existing proof semantics

| Flow | Fixed route | Consumer behavior |
| --- | --- | --- |
| Registration / resend | /account/verifyaccount?payload=... | Existing verification HTML and actual verified-account transition |
| Email change | /account/adjust/email/verify?payload=... | GET renders read-only confirmation form; explicit POST consumes approved proof |
| Deletion | /account/wipeout/verify?payload=... | Verifies the published proof; does not finalize deletion |

Every generated link has exactly one encoded payload query value and round-trips to the proof whose hash is staged. Joining fixed rooted paths against a validated authority cannot retain a caller-selected path/query or redirect to another origin. Existing no-store and the COR17/COR18 approval, publication and proof-consumption boundaries remain authoritative. No security controller/SQL behavior is weakened to make a click test pass.

## Authored native boundaries

Actual Program tests resolve the real DI AccountService and canonical builder, capturing all four outgoing URL intents for direct HTTPS, direct Container, ContainerReverseProxy and explicitly configured ReverseProxy origins. They follow production MVC routes over TestServer, assert successful HTML rather than status alone, exact JSON success, payload/hash consistency, read-only email scanner GET and explicit confirmation POST. Authority, password-work/admission and durable delivery are declared substitutes, so these tests do not prove PostgreSQL publication/state.

Owned loopback Kestrel tests supply explicit ephemeral origin overrides, avoiding shared fixed ports. LocalHttps uses a real TLS listener with a fixture certificate; ReverseProxy uses a real TLS edge and separate HTTP origin; Container uses direct HTTP; ContainerReverseProxy uses an HTTP edge/origin. The client pins the exact fixture certificate and allows only its expected chain-trust error, retaining hostname validation. Spoofed Host in HTTP lanes and forwarded-Host/Forwarded headers in all lanes cannot change captured authority. The same production MVC consumers follow the returned links through the selected listener. The two-stage test fixture starts its owned listeners before freezing their explicit public origin in the real producer; it is not a configuration reload path. Deployed trust, HAProxy binary/config behavior and IIS hosting remain independent native obligations.

Three additional PostgreSQL methods live in already-mandatory Cor11/17/18 selectors. Registration and resend URL payloads complete the actual account verification state. Email/deletion URL payloads are encrypted, persisted, claimed/opened from the actual outbox, recorded as provider Accepted and published before actual proof consumption. Email remains unchanged before explicit completion; deletion verification leaves the account present and records no completed deletion. No real mail is sent, and this does not qualify provider delivery behavior. Existing native authority/proof tests are preserved; their fixtures now provide an explicit PublicOrigin where constructing AccountService.

Unit cases cover profile and launch overlays, invalid origin shapes and raw dot-path normalization, production/local HTTP policy, fixed-route encoding of reserved/Unicode payloads, required ReverseProxy input, obsolete-key rejection, immutable origins despite mutated options/request headers and invalid Production host startup before a delivery worker can start.

## Verification and gates

Supplemental Python tests mutate TLS/edge origins, obsolete settings, payload escaping, credential/raw-path acceptance, production policy, unknown-key handling and Compose/host authority settings. These are configuration/source witnesses, not native HTTP/URI proof. Required checks:

```bash
python3 -m unittest discover -s eng/tests -v
python3 eng/check-verification-origins.py
python3 eng/check-request-body-boundary.py
python3 eng/check-security-response-cache.py
python3 eng/check-correction-evidence.py
python3 eng/generate-database-baseline.py --check
python3 eng/cor23-reconciliation.py --check
python3 eng/correction-baseline.py --lane all --output .correction-results/cor23g-final
python3 eng/correction-sql-fixture.py
```

The delivery includes executed tooling evidence and blocked native attempts tied to the exact final source. .NET SDK, PostgreSQL, Docker/cache and PowerShell are unavailable. New native cases, real click/TLS/proxy/IIS deployment behavior and actual database proof results are NotRun. R07-04 is FixedPendingQualification; the other 83 findings, original 451-file inventory, frozen reviews and all 186 Open gates are preserved. No finding or gate is Closed. Current totals: 59 FixedPendingQualification, 25 Open. Next ordered correction: COR23H.

A rollback must retain a validated, reachable public origin and safe payload joining; do not restore the unrelated port-5000 defaults. Configuration changes and restarts are the only rollout requirements. Official API references used for design: https://learn.microsoft.com/en-us/dotnet/api/system.uri and https://learn.microsoft.com/en-us/aspnet/core/fundamentals/configuration/options . The locked .NET 8 runtime behavior still requires execution.
