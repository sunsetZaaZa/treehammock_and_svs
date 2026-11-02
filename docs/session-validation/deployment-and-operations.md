# Deployment and operations

## Preparation

The SVS API is a separate `.NET 10` executable. The repository's `global.json` selects an appropriate .NET 10 SDK and the private host project targets `net10.0`; the public TreeHammock application remains on `.NET 8`. Build and package each with the correct runtime assets. `deploy/session-validation/` contains example files for firewall, nginx, HAProxy, Linux/systemd, monitoring, security, rollout and SQL. They are examples, not approved values for a production host.

The entry point `src/Treehammock.SessionValidation.Api/Program.cs` accepts exactly `--config PATH`. Configuration is a bounded JSON `HostSettings` document, rather than the public application's `appsettings.json` behavior. Verify the current property schema and validation in `HostSettings.cs` and ensure the supplied file is protected by OS permissions.

```sh
# Illustrative: use an operator-approved, private HostSettings JSON file.
dotnet run --project src/Treehammock.SessionValidation.Api -- --config /absolute/private/svs-host.json
```

This is an invocation example, not a guaranteed ready-to-run fixture. The file must supply valid private listener, certificate and database/cache/role settings. Never commit actual keys or passwords to this repository.

## Exposed interface

The private host provides its gRPC validation method and bounded operational endpoints implemented in `HealthEndpoints.cs`: `/health/live`, `/health/ready`, `/operations/status`, and `/metrics`. Access restrictions differ by route and service identity; do not expose these paths on public ingress. Readiness is distinct from liveness and may depend on cache and/or database admission. See `SvsHost.cs` before installing monitoring routes.

## Operating and recovery references

| Location | Content |
| --- | --- |
| [`deploy/session-validation/README.md`](../../deploy/session-validation/README.md) | Deployment file map and safe setup sequence |
| `deploy/session-validation/systemd/` | Linux service unit examples |
| `deploy/session-validation/nginx/`, `haproxy/`, `firewall/` | Private transport and network policy examples |
| `deploy/session-validation/monitoring/` | Monitoring and alert templates |
| `deploy/session-validation/physical/` | Physical deployment configuration example |
| `deploy/session-validation/sql/` | SQL privilege inspection and provisioning scripts |
| [`deploy/session-validation/rollout/ROLLBACK.md`](../../deploy/session-validation/rollout/ROLLBACK.md) | Existing detailed rollback procedure (historical wording may remain until documentation normalization is complete) |
| [`eng/session-validation/qualification/README.md`](../../eng/session-validation/qualification/README.md) | Target-host and long-duration qualification requirements |

## Conditions before enabling traffic

Do not enable live traffic because unit tests succeed or because a local readiness endpoint responds. Confirm real certificate trust, SQL role grants, epoch/fleet state, cache coherence, caller action policies, rollback capacity, monitoring, draining and independent release authorization. Consult [current verification](current-verification.md).
