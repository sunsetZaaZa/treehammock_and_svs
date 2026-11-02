# COR23D implementation — test composition and privileged routes

Owns R07-01 only. Builds on completed COR23C; qualification is NotRun. Current pre-1.0 configuration is edited directly. Database setup, schemas, setup versions, SDK/package locks, original reviews and original inventory are unchanged.

## Startup and access contract

One immutable `SystemTestCapability` is created from configuration and the host environment before provider registration. Only the exact environment name `Testing` may enable it. Missing/unknown environments and Production, Staging, Development, Container and ContainerReverseProxy cannot activate test delivery. Generic container profiles remain deployable profiles. Enabled test capabilities also reject the Production database profile. Testing must be selected only for an owned disposable fixture; a profile name cannot establish infrastructure ownership.

| Enabled | Inspection | Key | Environment | Behavior |
|---|---|---|---|---|
| false | false | empty | Any | Real SMTP/SMS providers; no capture registration; privileged controllers removed |
| true | false | empty | Testing | Fake SMTP/SMS and real fixture capture; no inspection or seed routes |
| true | true | 24–128 printable ASCII characters without whitespace | Testing | Fake delivery/capture and keyed inspection/seed routes |
| true | either | any | Any other/missing environment | Startup rejected before provider registration |
| false | true | any | Any | Startup rejected |
| false | false | nonempty | Any | Startup rejected |
| true | false | nonempty | Testing | Startup rejected |
| true | true | missing, short, oversized or whitespace | Testing | Startup rejected |

Unsupported settings are rejected without echoing values. The unused `DeliveryCaptureConnection` property/configuration is removed: fixture capture deliberately uses the same owned `StorageContext` as seeding. There is no secondary connection fallback. All five shipped JSON defaults disable test capabilities with an empty key.

The capability controls SMTP/SMS selection, capture registration, MVC controller discovery and each privileged action's guard. Disabled inspection removes both system-test controllers from the effective route collection, rather than relying only on action-time guards. Capture and fake provider constructors also require an enabled capability. Configuration reload cannot grant capabilities or replace their inspection key; restart is required to change the startup decision. Responses and validation errors do not disclose the configured key.

Inspection accepts exactly one `X-System-Test-Key` header value. Missing, incorrect, repeated and comma-combined keys fail authorization before inspection, clear or seed work. SHA-256 key digests are compared in fixed time. The full literal source endpoint index still contains three test actions; its native discovery comparison explicitly selects enabled Testing inspection. Other profiles have those three actions removed.

## Intentional harness configuration

`docker-compose.integration.yml` now defaults to Container with test flags disabled and an empty key. The generic proxy overlay keeps ContainerReverseProxy. New `docker-compose.testing.yml` explicitly selects Testing and enables keyed fixture capabilities. Bash and PowerShell direct HTTP, proxy HTTP and full system test wrappers layer it after the generic transport override. Host-backed system wrappers set both environment variables to Testing and retain their explicit transport settings. Developer runtime wrappers inherit disabled test capabilities.

This is capability isolation, not qualification of the legacy stack's resource ownership, shared reset/capture coordination, readiness, recovery, proxy trust or wrapper exit propagation. Their existing follow-up owners remain unchanged.

## Authored native regressions

`Cor23DTestIsolationTests` adds nine methods with 42 inline-expanded cases:

- Actual application entrypoint rejects activation in Production, Staging, Development, Container, ContainerReverseProxy, a custom profile and lowercase testing, with inspection on/off.
- Actual application entrypoint starts disabled profiles, resolves production SMTP/SMS and exposes none of the three privileged actions. Background workers and unrelated durable delivery authority are fixture substitutes; no external provider calls occur.
- Separate production DI/MVC TestServer cases check disabled custom/Testing profiles, real provider types and absence of capture registration/routes.
- Actual entrypoint rejects inconsistent flags, unused keys, missing/short/whitespace/oversized keys, unsupported connection settings, Production database capture and environment omission.
- Capture-only Testing resolves actual fake providers/capture but removes all privileged routes.
- Missing/wrong/repeated/comma-combined inspection keys reject GET/DELETE/POST. These fast cases substitute capture, and assert no capture work; SQL effects are independently checked below.
- Actual entrypoint allows a matching key with a declared capture substitute.
- Startup decisions and inspection keys remain immutable after configuration changes; fake provider/capture direct construction rejects disabled capabilities.

`Cor23DTestCapabilityHttpTests` adds two methods with four inline-expanded cases in the mandatory sql-harness lane. The actual DI/controller/fake-provider/password hash/capture implementations use owned native PostgreSQL. Storage search_path is the persistence substitute; background jobs and external delivery are excluded. The positive flow captures email proof and SMS code, inspects both, denies unauthorized clear/seed without changing rows, seeds and verifies a real password hash/security stamp, then clears captured messages. Production/Container/ContainerReverseProxy disabled-host cases verify 404 for all three routes, real providers, no capture registration, no captured-message table and no seeded account.

All eleven methods (46 inline-expanded cases) are authored, NotRun. The existing routed system account lane remains required. These cases cannot qualify production database roles/TLS, external delivery, cache, stack ownership or resource budgets.

## Validation and qualification

```bash
python3 eng/check-system-test-isolation.py
python3 eng/check-factor-identities.py
python3 eng/check-sql-output-bindings.py
python3 eng/generate-database-baseline.py --check
python3 eng/cor23-reconciliation.py --check
python3 eng/check-correction-evidence.py
python3 -m unittest discover -s eng/tests -q
python3 eng/correction-sql-fixture.py
python3 eng/correction-baseline.py --lane all
```

Eight additional Python source/config mutation cases cover current contracts, Container activation, unconditional capture, removed route isolation, unsafe deployable defaults, incorrect test environment, omitted proxy test overlay and duplicate-header acceptance. These checks are supplemental source evidence, not native host or HTTP execution.

.NET SDK, PostgreSQL, Docker/cache and PowerShell are unavailable. Native compilation and host/provider/HTTP/persistence execution remain Blocked/NotRun. Qualification must retain actual native failing mutation evidence: restoring environment-free activation must fail entrypoint denial; unconditional capture registration must fail disabled-provider cases; removing controller filtering must fail disabled routes; accepting the first duplicate key must fail repeated-key denials. Reintroducing the old ignored connection setting must fail unsupported configuration startup. Compilation failure or a lexical witness does not qualify these mutations.

R07-01 is FixedPendingQualification with appended history. The other 83 findings and all 186 gates remain unchanged; no finding or gate is Closed. Next ordered correction: COR23E.
