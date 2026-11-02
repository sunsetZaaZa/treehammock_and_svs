# Session Validation Service

Session Validation Service (SVS) is an internal ASP.NET Core/.NET 10 service that validates existing TreeHammock session credentials for other backend services. TreeHammock remains the only account/session authority writer; SVS issues decisions, not credentials.

## Guides

| Guide | Use it for |
| --- | --- |
| [Architecture](architecture.md) | Service components, boundaries and processing path |
| [Protocol and client](protocol-and-client.md) | Private mTLS gRPC, caller identity, request/reply semantics, typed SDK |
| [Cache consistency](cache-consistency.md) | Read-through, SQL fallback, guarded refill, revocation and admission |
| [Data access and security](data-access-and-security.md) | Read-only database identity, certificates and trust boundaries |
| [Deployment and operations](deployment-and-operations.md) | Configuration, private hosts, health, rollout, recovery and monitoring |
| [Testing and qualification](testing-and-qualification.md) | Local checks, native tests, acceptance and nonproduction constraints |
| [Current verification](current-verification.md) | Supported statements about implementation and outstanding qualification |
| [Wire-contract sources](design/README.md) | Proto, JSON contract and historical provenance artifacts |

## Where the code lives

- `src/Treehammock.SessionValidation.Api/` for the private host.
- `src/Treehammock.SessionValidation.Client/` for the consumer SDK.
- `src/Treehammock.SessionValidation.Contracts/` for binary request/reply validation.
- `src/Treehammock.SessionValidation.Core/` for the pure policy evaluator.
- `src/Treehammock.SessionValidation.Storage/` for cache/database consistency.
- `deploy/session-validation/` for operator templates and SQL support.
- `eng/session-validation/` for checks, orchestration and qualification.

## Qualification warning

The code and local testing tools are present. The supplied source and inherited evidence do **not** establish completion of real native Yugabyte/Dragonfly tests, physical/failover/soak exercises, independent security approval or production readiness. The root repository SDK configuration and real host/certificate settings must also be checked locally. See [current verification](current-verification.md).
