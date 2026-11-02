# Session validation architecture

## Separation of responsibility

TreeHammock's public authentication service issues and modifies credentials, controls account/session eligibility and owns durable mutation and revocation. The private SVS host validates an *existing* credential and a caller-authorized action. SVS does not issue access/refresh tokens, perform registration, or own TreeHammock's writer permissions.

## Projects

| Project | Responsibility |
| --- | --- |
| `Treehammock.SessionValidation.Api` | Standalone host, private listeners, request admission, lifecycle, health, telemetry and validation handler |
| `Treehammock.SessionValidation.Client` | Bounded private HTTP/2 client and typed validation outcome |
| `Treehammock.SessionValidation.Contracts` | Strict contract/rule checks and generated gRPC/protobuf bindings |
| `Treehammock.SessionValidation.Core` | Stateless token/session policy evaluation and deny-by-default decisions |
| `Treehammock.SessionValidation.Storage` | Coherent Dragonfly reads, primary SQL authority fallback, refill and publication coordination |

## Validation path

1. The consumer establishes private TLS with its allowed certificate and identity and sends a bounded validation request.
2. The SVS API checks the peer, request limits, wire format, deadline and caller's action policy.
3. The coordinator attempts an admissible coherent cached session projection. A valid cached projection can be evaluated without foreground SQL, subject to live cache-admission and expiry checks.
4. An unusable cache projection triggers the controlled durable SQL authority read path. The coordinator evaluates the resulting projection and may request optional guarded SVS-owned publication.
5. Only a current `Active` result carries subject information. Refusals and infrastructure failures must fail closed, with finite response validity.

Concrete call sites: `Api/ValidationService.cs`, `Storage/SessionEvidenceCoordinator.cs`, `Storage/CoherentSessionCacheReader.cs`, `Core/TreehammockSessionPolicyEvaluator.cs`, and `Contracts/ContractCodec.cs` under `src/Treehammock.SessionValidation.*`.

## Fleet and refill

The host contains separate fleet-admission, lifecycle and local refill-worker components. When configured, `HostSettings.Fleet` selects the coherent resources path; `RefillSettings` is bound to that lifecycle and uses a separately constrained publisher identity. Do not introduce a remote refill endpoint or reuse writer credentials when following older documents. Consult [cache consistency](cache-consistency.md), [security](data-access-and-security.md) and [operations](deployment-and-operations.md).

The public TreeHammock session cache warmup is different from SVS's guarded read-through/refill system: [warmup guide](../deployment/SESSION_CACHE_WARMUP.md).
