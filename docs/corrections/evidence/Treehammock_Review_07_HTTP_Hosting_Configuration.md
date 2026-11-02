# Treehammock review 07 — HTTP, hosting and configuration

Reviewed 2026-10-03 against the unchanged uploaded source. This is a source review and correction-plan addendum, not an implementation or runtime certification.

**Four new P2 findings. Cumulative: 59 open findings, comprising 17 P1 and 42 P2.** No prior finding is closed. All 54 files assigned to R07 have completed source inspection; the 451-file inventory records cross-chunk inspection separately. Next: **R08 — email/SMS delivery, providers and templates**.

## Scope and qualification

The assigned scope covers `Program.cs`, HTTP/compression setup, Kestrel and forwarded-header configuration, DI registration, shared configuration/response/status contracts, account validation helpers, `AccountService`, entities, hosting overlays, Dockerfile, launch configuration and repository metadata. The base and example settings have equivalent parsed content. Settings were inspected with secret values suppressed in review output; the evidence and bundle do not reproduce credentials or cryptographic keys.

Focused cross-checks cover token transport/middleware, profile/session GETs, test-only controllers/settings, registration configuration, test-provider wiring, documented listeners and the integration compose overlay. The three hosting test files were inspected completely. API validation tests and startup-configuration tests were consulted for relevant cases; their complete R10 test audit remains pending. No tests were executed.

`bash eng/dotnet-unit-tests.sh` exited **127**, before restore/build/test, because `dotnet` is unavailable. Docker, PostgreSQL tools and Redis server are also unavailable. There was no running application, proxy/cache experiment, database execution, concurrency test, deployment inspection or performance measurement. The exact compressed-request status/body behavior is an inference requiring the real HTTP tests specified below. The archive still contains the same 451 files with matching hashes; application source is unchanged.

## Findings

| ID | Priority | Defect | Correction owner |
|---|---|---|---|
| R07-01 | P2 | Test delivery and privileged inspection/seed capabilities can be enabled in any environment. | COR23D |
| R07-02 | P2 | Sensitive account/session responses and refreshed credentials lack an explicit no-store policy. | COR23E |
| R07-03 | P2 | Compressed-body failures have no application error boundary or stable API error contract. | COR23F |
| R07-04 | P2 | Shipped verification-link origins disagree with the shipped/documented hosting profiles. | COR23G |

### R07-01 — Test capabilities are configuration-only, without production isolation

**Evidence.** `Rigging/DependencyInjection/TreehammockServiceCollectionExtensions.cs` line 45 uses unvalidated `Configure<SystemTestSettings>`. Lines 100–110 read `Enabled` and select `SystemTestSmtpService` / `SystemTestSmsSender` instead of real delivery. The registration method receives configuration, without an environment or separate test-host capability. `Program.cs` 41–46 discovers the controller assembly containing the test controllers.

`Controllers/SystemTestAccountController.cs` 40–46 exposes verified-account seeding. Its guard at 134–150 checks the two flags and a nonempty matching `X-System-Test-Key`, without an environment check. `Controllers/SystemTestDeliveryController.cs` 29–49 returns captured deliveries; its guard at 65–80 follows the same policy. `Rigging/Config/SystemTestSettings.cs` has no validation or environment constraint. The integration compose file intentionally enables both flags and supplies a sample key at 107–110.

**Impact and limits.** An accidental reuse of test settings in a production host silently selects simulated delivery; if inspection is also enabled, the key authorizes account seeding and retrieval of delivered proof material. Empty inspection keys disable those endpoints but do not prevent fake delivery selection. Defaults disable test mode, and inspection is key-gated: this is a conditional configuration defect, not an unauthenticated default exposure or an observed production compromise. The integration compose lane is intentionally a test environment even though its API environment names are `Container` / `ContainerReverseProxy`.

**Correction.** Prefer registering test providers/controllers only in a dedicated test host/application part. If a shared binary is retained, require an explicit isolated test-host capability, validate the combination at startup, and reject test delivery/inspection/seeding in every production deployment mode. Do not rely solely on the generic `Container` environment name or merely require a nonempty key. Production DI must select real providers even when stale test configuration is present, or fail startup visibly rather than silently running with it.

### R07-02 — Missing HTTP cache policy for identity-bearing responses

**Evidence.** No production C# source defines `Cache-Control`, `ResponseCache`, `NoStore` or an equivalent response policy. `Controllers/AccountProfileController.cs` 174 onward returns account details on GET `/account/view`; `Controllers/AccountSessionController.cs` 267 onward lists device sessions on GET `/account/sessions`. `Rigging/Authentication/AccessTokenTransport.cs` 11–20 supports both `Authorization: Bearer` and the legacy `AccessToken` header. `JsonWebTokenMiddleware.cs` 132 can write a refreshed credential into the response `AccessToken` header before the endpoint response, including a request to an anonymous endpoint that supplies a token.

**Inferred impact.** A shared cache that stores a heuristically cacheable GET by URI can reuse account data across callers using the legacy header unless it has its own exclusion policy. Private caches can also retain account data and credential-bearing responses. The special shared-cache rule for `Authorization` does not apply to an arbitrary `AccessToken` header. The shipped HAProxy configuration does not establish that a shared response cache is active; no cache leak was reproduced. This remains an HTTP boundary defect because clients/intermediaries should receive an explicit privacy policy.

The relevant primary contract is [RFC 9111](https://www.rfc-editor.org/rfc/rfc9111.html), sections 3, 3.5, 4.1 and 5.2.2.5: cache reuse depends on cache keys and response directives, Authorization receives specific treatment, and `no-store` forbids storage of the associated exchange.

**Correction.** Apply `Cache-Control: no-store` to account/security endpoints, success and failure responses, verification pages containing sensitive state, and every response that carries a refreshed credential or credential-clear instruction. Ensure the policy encloses authentication and error handling so headers survive short-circuits. A global no-store default is a reasonable baseline for this identity API; allow public caching only through deliberate endpoint opt-in. `Vary: AccessToken` alone would still retain credential-bearing responses and is insufficient as the privacy policy.

### R07-03 — Decompression failures bypass the validation envelope

**Evidence.** `Program.cs` 39 registers request decompression, 51–56 enables the Newtonsoft formatter, and 92 places decompression before authentication/controllers. The custom invalid-model-state factory at 44 covers model-state errors. No application exception middleware, exception filter or compressed-body error mapper is registered. `ApiValidationEnvelopeTests` exercises malformed uncompressed JSON and ordinary validation/authentication cases; no decompression/expanded-limit cases were found in the test source search.

**Inferred impact.** Invalid compressed content or a decompressed-size overflow can throw during body reads, before an action executes. The application has no explicit boundary to turn those failures into its JSON envelope and chosen client-error statuses. An unhandled server error or framework/development response is expected rather than the intended stable validation contract; exact behavior on the supported runtime must be reproduced. This does not establish an unlimited decompression bomb: the framework uses endpoint/server body limits unless disabled.

The [ASP.NET Core request-decompression documentation, 8.0 view](https://learn.microsoft.com/fil-ph/aspnet/core/fundamentals/middleware/request-decompression?view=aspnetcore-8.0) describes lazy body decompression, invalid-data exceptions and a size-limit exception. The [upstream Newtonsoft formatter source](https://github.com/dotnet/aspnetcore/blob/main/src/Mvc/Mvc.NewtonsoftJson/src/NewtonsoftJsonInputFormatter.cs) illustrates buffering before JSON deserialization and a malformed-input-only exception policy. That source is upstream `main`, not proof of the exact installed binary; version-specific behavior remains a runtime gate.

**Correction.** Define bounded compressed/expanded request budgets appropriate for the small account payloads. Add an error boundary around decompression and downstream body consumption, with explicit classification for invalid encoded input (400), expanded-limit violations (413) and unsupported encoding if rejected by policy (415). Return the existing envelope, suppress exception/body/secret details, and preserve no-store headers. The framework passes unsupported/multiple encodings downstream, so decide their contract explicitly. Avoid translating every `InvalidOperationException` into a client error: unrelated application failures remain sanitized 500s. Handle aborted requests and already-started responses separately.

### R07-04 — Default links point at an unrelated listener

**Evidence.** `appsettings.json` and `appsettings.Example.json` 184–189 configure registration, email-change and deletion verification origins as `http://localhost:5000`. None of the shipped environment overlays overrides those three settings. `AccountService.cs` 672–709 concatenates the configured origin with the verification route and URL-encoded proof. Hosting overlays configure port 5001; `README.md` 208–209 documents the HAProxy edge at `http://localhost:8080` and direct HTTPS at `https://localhost:5001`. The integration compose API environment does not supply replacement verification origins.

**Impact.** Following a generated registration, email-change or deletion link in those configurations targets port 5000 rather than the intended API/edge. The direct HTTPS lane additionally emits HTTP links. A frontend/redirector deliberately listening on port 5000 could alter the conclusion, but no such component or documented forwarding contract was found in the uploaded project. Deployment overrides can correct the value; the shipped profiles remain inconsistent. This is a broken default workflow, not a claim of Host-header poisoning: these URLs come from configuration, not the incoming Host header.

**Correction.** Give each runnable profile a canonical public origin, or require it explicitly during startup and document the local value. Validate absolute scheme/authority and the production HTTPS policy; allow local HTTP only in the intended isolated lane. Consolidate repeated origins if they share one authority, with deliberate exceptions where product routing requires them. Preserve path construction and proof encoding. Do not derive emailed origins from untrusted request headers. Click-follow tests must account for the separate R04-09 finding about GET consuming email-change proof.

## Positive checks and follow-up observations

| Surface | Reviewed result / remaining gate |
|---|---|
| Proxy ordering/trust | Forwarded headers precede HTTPS redirection and JWT/IP policy. Known proxy/network parsing, hop bounds and symmetry are validated. Trust-all is explicit in the local reverse-proxy test lane; it is not added as a separate production exposure. Exercise trusted/untrusted peer chains with the deployed proxy. |
| Options startup | Most substantive settings use section checks, `IValidatableObject`/annotation validation and `ValidateOnStart`. Registration rejects a zero effective verification period; it is not a finding. System-test isolation remains the exception above. |
| Serialization/transport | Entity secrets have Newtonsoft ignore attributes. No unsafe type-name deserialization setting was found. Token transport inspected here is header-based; no cookie-authentication CSRF finding is inferred. |
| DI lifetime | Repositories and shared clients/data sources are singleton registrations, avoiding a pool per request. R06 ownership/disposal and AUTH-11 lazy cache-connection observations remain open. |
| Validation | Shared helpers enforce configured input policies and standard model-state envelopes. Authorization/model-validation ordering has relevant in-process tests. These tests have not run in this workspace. |
| Compression and buffering | Brotli uses Fastest and HTTPS compression is enabled. Measure CPU, allocations, temporary-file spill and latency under concurrent valid/invalid compressed bodies; select smaller expanded limits for account routes. Evaluate reflected-secret compression against the actual client threat model; no BREACH exploit is claimed. |
| Protocols and hosting | Enum parsing alone can admit numeric protocol values outside the intended named combinations. Add a strict supported-combination startup matrix, certificate/HTTP2/HTTP3 checks and real listener tests. This is recorded as a configuration follow-up, without a new numbered defect. |
| API surface | CORS is not configured; browser-origin support needs an explicit product decision. Launch settings mention Swagger without visible Swagger registration. Neither is promoted to a feature blocker without a required client/documentation contract. |
| Shared enums/stubs | Empty/deferred provider enums and the unused `HTTPService.InternalEmailOut` stub do not establish active workflow failures. Confirm public product scope and remove or implement unsupported surface before the final completeness gate. |

Performance observations are source-derived work items for COR22, not benchmark results. The previous trusted-grant activation decision remains unchanged.

## Detailed correction-plan addendum

The original design/PR plan covered 52 findings; R06 added COR23A–C. Add these four scoped owners under COR23's reconciliation program, scheduled when their prerequisites are ready. They are proposed implementation PRs, not opened or implemented PRs. No Word planning artifact was silently rewritten.

### COR23D — Isolate test-only delivery and privileged endpoints

- **Owns:** R07-01. **Depends on:** COR01 test foundations; coordinate provider composition with the delivery program and startup configuration gate. **Gates:** COR24 production qualification.
- **Files:** `Program.cs`, DI extensions, `SystemTestSettings`, both test controllers, test host/provider registrations and integration compose/test harness configuration.
- **Implementation:** choose dedicated test composition or an isolated test-host capability; disallow production activation of fake delivery, capture and seeding; reject invalid flag/key combinations at startup. Keep intentional test-container lanes usable without equating generic Container with a safe test boundary.
- **Acceptance:** host-start tests cover disabled/enabled flags in Production and every deployable profile, missing/wrong inspection keys, and the dedicated allowed test lane. Verify resolved production provider types, inability to reach privileged routes and lack of captured production proof material. Also verify intentional test delivery/seed flows still work.
- **Migration/rollback:** configuration/composition change, no schema migration. Roll out explicit test-lane configuration with the harness; fail startup with actionable diagnostics. A rollback that allows production test mode reopens the finding.

### COR23E — Enforce no-store across security responses

- **Owns:** R07-02. **Depends on:** COR01; coordinate middleware order and response contracts with COR23F and session corrections COR05–07. **Gates:** COR24 HTTP/privacy qualification.
- **Files:** pipeline/response policy, authentication short-circuits, security controllers and real HTTP/proxy-cache regressions.
- **Implementation:** set no-store before token refresh and error handling; cover data, proofs, HTML and credential-control headers; make any future public caching an explicit opt-in. Avoid caching by credential-specific keys as a substitute.
- **Acceptance:** real HTTP requests with both bearer and legacy headers receive no-store for profile/session success, authentication/validation failures, refreshed credentials and anonymous endpoints supplied with a token. Through a configured standards-compliant caching intermediary, requests from two accounts and an unauthenticated caller cannot receive one another's data/headers. Verify intended public opt-ins independently.
- **Migration/rollback:** no data migration. Removing the policy reopens the privacy contract; compare cache traffic and latency without accepting cross-user reuse as a performance optimization.

### COR23F — Bound encoded bodies and normalize HTTP errors

- **Owns:** R07-03. **Depends on:** COR01 and shared error/result policy; coordinate ordering with COR23E. **Gates:** COR24 protocol qualification.
- **Files:** pipeline, request-limit configuration, error envelope mapping, endpoint metadata and real Kestrel HTTP tests.
- **Implementation:** explicit account-payload budgets, narrow encoded-body failure classification and sanitized unexpected-error handling; define unsupported/multiple encoding policy; preserve cancellation, no-store and correct logging without body/credential disclosure.
- **Acceptance:** supported compressed valid JSON works; malformed/truncated gzip, deflate and Brotli get the declared envelope/status; below/at/over compressed and expanded limits behave correctly, including chunked requests without Content-Length. Unsupported/multiple encodings follow the policy. Ordinary malformed JSON retains its contract; unrelated application exceptions remain 500, cancellation does not become a fabricated success, and rejected bodies cannot trigger durable account writes. Run over Kestrel as well as in-process tests.
- **Performance:** measure concurrent expansion/buffering CPU, memory, disk spill and p95/p99 latency within the configured limits. Record budgets and overload behavior under COR22.
- **Migration/rollback:** document the new request contract and client limits. Tightened limits need compatibility checks; do not roll back by disabling all body limits.

### COR23G — Make verification origins match public hosting profiles

- **Owns:** R07-04. **Depends on:** COR01 and the registration/email/deletion corrections, including R04-09's proof-consumption contract. **Gates:** COR24 end-to-end workflow completion.
- **Files:** registration/public-origin settings and validation, hosting overlays, `AccountService` URL builders, compose environment, README and capture/click-follow tests.
- **Implementation:** canonical validated origins per profile or required explicit startup input; production HTTPS; route-safe joining and encoded payloads; consolidate defaults without trusting Host/forwarded-Host input.
- **Acceptance:** capture each generated registration, resend, email-change and deletion URL under LocalHttps, Container and proxy lanes; assert exact public scheme/authority/path and payload round-trip. Follow it through the appropriate listener and validate the intended confirmation/proof flow. Spoofed Host/proxy headers do not change emailed origins. Invalid/absent required production origin fails startup before delivery.
- **Migration/rollback:** configuration change. Pending already-emailed URLs may require a bounded compatibility redirect or resend policy if such data exists; this project is described as undeployed, so establish deployment/data disposition before selecting a migration. A rollback must not silently restore unusable origins.

## Evidence and remaining review

The cumulative bundle contains R01–R07 reports/evidence, builders, blocked validation logs and the latest 451-file inventory/59-finding ledger. The R07 builder checks archive/file parity, configuration/wiring patterns, origin mismatch, privacy/error-boundary absence, source/test catalogs, report links and correction ownership. Its structural assertions are not executable application tests.

R08 covers delivery services, SMS providers, SMTP configuration and email templates. R09 and R10 remain pending, including complete test/dependency/build/operations qualification as mapped. The three partially inspected R06 SQL test files remain queued for R10. Feature completion still requires implementing/dispositioning all findings, exercising runtime state/concurrency contracts and meeting measured performance budgets.
