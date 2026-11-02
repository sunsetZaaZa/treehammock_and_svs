# Session Validation Service deployment assets

These files support the **private** Session Validation Service, not TreeHammock's public login/registration routes. The service host exists in `src/Treehammock.SessionValidation.Api/` and accepts a protected JSON configuration file through `--config`. Begin with the maintained [deployment and operations guide](../../docs/session-validation/deployment-and-operations.md) and [security guide](../../docs/session-validation/data-access-and-security.md).

## Assets in this directory

| Directory or file | Role |
| --- | --- |
| `sql/` | Current-schema read functions, validator identity provisioning/inspection/removal scripts |
| `systemd/` | Example private-host Linux units |
| `nginx/`, `haproxy/`, `firewall/` | Private proxy configuration and network restrictions |
| `monitoring/` | Metrics, alerts and dashboard examples |
| `physical/`, `linux/` | Physical infrastructure and kernel/host example settings |
| `security/` | Private key inventory example |
| `rollout/` | Traffic and rollback procedures |
| `ci/`, `disposable/` | CI and isolated test environment assets |
| `conformance/`, `compose.integration.yaml` | Contract and integration inputs |

## Operating sequence

1. Install the supported .NET 10 runtime and inspect `src/Treehammock.SessionValidation.Api/HostSettings.cs` for the exact JSON schema and validation rules.
2. Prepare a *private* listener with approved mTLS roots, server/client certificate pinning, caller identities and action policies. Avoid wildcard binds and publicly routed validation ports.
3. Provision the required validator SQL identity with least privilege. **Audit** actual grants and role memberships before any traffic; do not assume that success on a PostgreSQL fixture establishes Yugabyte behavior.
4. Configure Dragonfly TLS/credentials and any separately approved cache-publisher/refill identity. Coherent fleet and refill settings must satisfy the host's lifecycle checks.
5. Deploy proxy, firewall and systemd settings appropriate to the host and isolate monitoring identities. Treat shipped templates as starting material, not secure production defaults.
6. Perform current native cache/database, certificate, revocation, failure/recovery and independent release checks before routing consumers.

**Filename caution:** Several SQL files retain historical labels because they are referenced by embedded C# resources, source inventory code or existing tooling. Do not rename them until that dependency graph is updated and built together. File labels are not an instruction to perform old implementation steps.

For run acceptance, see [current verification](../../docs/session-validation/current-verification.md) and [qualification](../../docs/session-validation/testing-and-qualification.md). For urgent traffic reversal, consult [`rollout/ROLLBACK.md`](rollout/ROLLBACK.md), then verify the source-bound behavior and security boundary before using it on a live fleet.
