# TreeHammock

TreeHammock is an ASP.NET Core account-security and authentication service. This repository also contains a separate, private **Session Validation Service (SVS)** for other services that need an authenticated session decision without implementing TreeHammock's session policy themselves.

The public TreeHammock API and private SVS have different responsibilities: TreeHammock creates and changes account/session authority; SVS validates an existing credential against coherent evidence. Source implementation and local checks do **not** imply production qualification. See [current verification and remaining work](docs/session-validation/current-verification.md).

## Start here

| Topic | Documentation |
| --- | --- |
| All documentation | [Documentation home](docs/README.md) |
| Service boundaries | [System overview](docs/architecture/system-overview.md) |
| Authentication, refresh, logout | [Authentication and session lifecycle](docs/architecture/authentication-and-session-lifecycle.md) |
| Private session validation | [SVS guide](docs/session-validation/README.md) |
| Database/cache consistency | [SVS cache and revocation](docs/session-validation/cache-consistency.md) |
| Deployment and runtime configuration | [SVS deployment and operations](docs/session-validation/deployment-and-operations.md) |
| Local tests and infrastructure qualification | [Testing](docs/testing/README.md) |
| Release controls and artifacts | [Release documentation](docs/release/README.md) |
| Public API reference navigation | [Endpoints and source](docs/reference/api-endpoints.md) |

## Capabilities represented in the source

TreeHammock has registration, account verification and profile flows; password login; JWT access credentials and separate refresh authority; logout/revocation; two-factor authentication (including authenticator-app TOTP); password-reset and account-unlock flows; activation management; abuse controls; and health endpoints. The source tree and included tests are the implementation reference. The [authentication guide](docs/architecture/authentication-and-session-lifecycle.md) covers the main boundaries.

SVS contains a .NET 10 private API host, reusable shared contracts and policy, a typed client SDK, and cache/database readers. It uses a private HTTP/2 gRPC validation operation and authenticated service identity. It is **not** an alternative login, token issuer, account writer, or public authentication endpoint. Begin with the [service architecture](docs/session-validation/architecture.md).

## Repository map

| Location | Responsibility |
| --- | --- |
| `Controllers/`, `Services/`, `Repos/`, `Entities/` | Public TreeHammock API, workflows and persistence |
| `Rigging/`, `Program.cs` | Authentication, infrastructure and public hosting |
| `src/Treehammock.SessionValidation.Api/` | Private SVS host and validation endpoint |
| `src/Treehammock.SessionValidation.Client/` | Typed SVS client |
| `src/Treehammock.SessionValidation.Contracts/` | Request/reply contract validation and generated bindings |
| `src/Treehammock.SessionValidation.Core/` | Pure session/token decision policy |
| `src/Treehammock.SessionValidation.Storage/` | Cache, durable authority reads and consistency coordination |
| `tests/Treehammock.SessionValidation.*/` | Service, contract, client and infrastructure-related tests |
| `treehammock.Tests/` | Public API tests |
| `deploy/session-validation/` | SVS deployment and infrastructure examples |
| `eng/session-validation/` | SVS validation and qualification tools |
| `eng/` | Public API build, test and operational scripts |
| `docs/` | Maintained technical and operator documentation |

## Development prerequisites

The root [`global.json`](global.json) selects a .NET **10.0.100** SDK with feature-band roll-forward; the public TreeHammock application targets .NET 8 and the SVS API targets .NET 10. Install an SDK compatible with the repository and both required runtimes. A Visual Studio installation must support the .NET 10 target. Docker/Compose and infrastructure dependencies are necessary for the corresponding integration lanes, not for reading or editing these sources. Some Python helper scripts have additional host/tool prerequisites.

Open [`treehammock.sln`](treehammock.sln) to see TreeHammock and the SessionValidation projects. To inspect the installed toolchain:

```sh
dotnet --info
dotnet --list-sdks
```

The repository provides both Bash and PowerShell tooling. A standard local TreeHammock build/check entry point is:

```sh
./eng/restore-locks.sh
./eng/validate.sh --configuration Debug
```

Windows PowerShell:

```powershell
./eng/restore-locks.ps1
./eng/validate.ps1 -Configuration Debug
```

These commands are developer checks and do not constitute a production release approval. For focused service checks and explicit infrastructure prerequisites, use [testing and qualification](docs/testing/README.md).

## Public API development stack

The repository includes local Docker helpers for the public API's database, cache and proxy environment:

```sh
./eng/docker-api-direct-up.sh
# or
./eng/docker-api-proxy-up.sh
```

For the direct stack, the public health endpoints are `/health/live`, `/health/ready` and `/health/dependencies` (the default developer port is documented in the Docker scripts). Stop owned developer resources using `./eng/docker-down.sh` and consult the scripts before removing volumes. Public API containers and the **private** SVS listener have different network and security requirements; do not publish SVS publicly or assume the public API compose commands deploy it.

## Release and safety boundary

This is a development/source workspace, not a certified deployment. Existing historical source pins and milestone artifacts may describe older states and may not match the current checkout. Native Yugabyte/Dragonfly tests, real private transport and certificate qualifications, independent review and physical/failover/soak evidence must be assessed separately. Refer to the [verification status](docs/session-validation/current-verification.md) and [release guide](docs/release/README.md). Do not infer approval from the presence of source, unit tests or deployment examples.
