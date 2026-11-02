# Data access and security

## Access boundaries

SVS uses separate service and database identities for distinct purposes. A validation request is never permission to mutate sessions or to issue refresh credentials. The host's `HostSettings` and storage's `ValidatorDatabaseIdentity`, `DatabaseIdentityPolicy`, `TreehammockIdentityAuditor` and `TreehammockIdentityPolicy` enforce the configured validator database boundary.

SQL provisioning/inspection/removal material is under `deploy/session-validation/sql/`. **These files still have legacy work-item names because their paths are used by embedded resources and tools.** Use the files as named until a coordinated dependency-safe rename has been completed. Do not rename installed SQL routines, role names, protocol fields or privileges to match documentation headings.

## Host and client trust

The private host validates TLS client identity and pinning against configured allowed callers. Its listener is private; it has no public login or account management routes. The typed SDK supplies an explicit root/hostname/certificate trust policy, and does not acquire authority to reissue credentials. The configuration includes dedicated certificate paths, client roots, private addresses and bounded connection/request settings. See `src/Treehammock.SessionValidation.Api/HostSettings.cs` and `src/Treehammock.SessionValidation.Client/ClientOptions.cs`.

## Operating principles

- Fail closed on malformed protocol, invalid signatures, stale data, unusable key material, unavailable authority, or missing action grants.
- Keep validator SQL access read-only and separately audit any publisher/refill identity and its actual effective grants.
- Avoid storing tokens, subject secrets or private keys in diagnostic output, reusable fixture examples or source archives.
- Require exact certificate/issuer and endpoint trust; do not substitute public ingress headers or proxy-forwarded identity for client certificate proof.
- Keep testing, rollout, telemetry and recovery paths bounded and isolated from production credentials.

## Scope of verification

Source-enforced checks and local testing are not a real database role audit, TLS operational review or red-team signoff. Before an approved deployment, verify effective YSQL privileges, private networking, certificate chain/pin rotation, role separation, cache command ACLs and system failure behavior on the actual environment. See [testing](testing-and-qualification.md) and [verification](current-verification.md).
