# System overview

## Components and authority

**TreeHammock public API** owns registration, login, factor challenges, session issuance/refresh, account state, credential revocation and related durable mutations. Its implementation is in `Program.cs`, `Controllers/`, `Services/`, `Repos/` and `Rigging/`.

**Session Validation Service (SVS)** is a separately hosted internal-only .NET 10 application in `src/Treehammock.SessionValidation.Api/`. It accepts a private validation request and returns a bounded decision based on current session evidence. It does not create or rotate a session and is not a public login API.

**Durable authority** is in the TreeHammock SQL state, accessed by the persistence layer and by SVS's controlled read path. The repository has PostgreSQL-compatible SQL assets and support for Yugabyte/YSQL-oriented authority reads; deployment compatibility must be checked against the selected database and schema.

**Dragonfly** is used for cached session authority. SVS can make a coherent cache-first decision or fall back to authoritative database reads; cache participation and publication are fenced so a revoked or obsolete projection cannot authorize requests simply because it was present in a cache. The public application's optional [cache warmup](../deployment/SESSION_CACHE_WARMUP.md) is a separate behavior with different checks.

**Consumers**, such as another backend service, use the shared `Treehammock.SessionValidation.Client` library and a private authenticated connection. Consumers must enforce their own resource/operation authorization after session validation; a successful session check alone is not an application-specific permission grant.

## Trust and traffic diagram

```text
Client -> public ingress -> TreeHammock API -> account/session writers -> SQL authority
                                     |                         |
                                     |                      cache fences
                                     v                         v
                            public API checks              Dragonfly

Backend service -> SVS Client -> private mTLS HTTP/2 gRPC -> SVS host
                                                       |         |
                                             coherent cache   SQL read fallback
                                                       |         |
                                                    Dragonfly  durable authority
```

The diagram is logical; it is not a deployment topology or a claim that every component is currently deployed. Consult [SVS architecture](../session-validation/architecture.md), [cache consistency](../session-validation/cache-consistency.md) and [deployment](../session-validation/deployment-and-operations.md).

## Source and operational entry points

- Public host and settings: `Program.cs`, `Rigging/Config/`, `Rigging/Authentication/`.
- Private host and validation: `src/Treehammock.SessionValidation.Api/SvsHost.cs`, `ValidationService.cs`, `HostSettings.cs`.
- Shared decision logic: `src/Treehammock.SessionValidation.Core/TreehammockSessionPolicyEvaluator.cs`.
- Cache/SQL coordinator: `src/Treehammock.SessionValidation.Storage/SessionEvidenceCoordinator.cs`.
- Source protocol: `docs/session-validation/design/contracts/session-validation-v1.proto`.

See the [current verification](../session-validation/current-verification.md) before treating an example or source file as production qualified.
