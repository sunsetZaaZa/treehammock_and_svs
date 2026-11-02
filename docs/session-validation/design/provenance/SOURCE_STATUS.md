# Source provenance and verification boundaries

This page describes the source lineage and limits of the available evidence. It is **not** a deployment approval, and historical delivery reports are not a substitute for executing current qualification checks.

## Repository and authority boundaries

TreeHammock's public application is the account and session authority. The public project is `treehammock.csproj` and targets .NET 8. TreeHammock's session middleware, session repository, cache worker and SQL routines implement the writer-side account/session behavior. The separate Session Validation Service (SVS) validates credentials through a private service; the standalone host targets .NET 10. SVS does not acquire login, token-issuance, session-mutation or database writer authority.

| Source location | What to inspect |
| --- | --- |
| `Rigging/Authentication/JsonWebTokenMiddleware.cs` | Public authentication middleware and refresh-path handling |
| `Rigging/Authentication/JsonWebTokenUtility.cs` | Access-token signature and lifetime verification code |
| `Rigging/Authentication/SessionProtocol.cs` | Session protocol version and credential family/generation |
| `Rigging/Authentication/AccessTokenTransport.cs` | Bearer/header credential transport |
| `Rigging/Cache/ActiveUserCacheService.cs` | Public application's cache read/write/invalidations |
| `Repos/SessionRepo.cs` | Public app session reads and mutations; not a validator read-only adapter |
| `src/Treehammock.SessionValidation.Core/` | Shared stateless validation rules |
| `src/Treehammock.SessionValidation.Storage/` | Primary-consistent SQL read, guarded cache and refill coordination |
| `src/Treehammock.SessionValidation.Contracts/` | Private wire-contract validation |
| `src/Treehammock.SessionValidation.Api/` | Private mTLS service host |
| `src/Treehammock.SessionValidation.Client/` | Consumer-side typed validation client |

## Storage and trust observations

The public middleware has historically used SQL-backed cache trust checks. A legacy routine named `validate_cached_session_trust` calls an account-authority locking helper and is not to be treated as a safe read-only validator interface just because it contains the word *validate*. SVS uses its separately constrained projection and dedicated read-only database identity. Cache-hit authorization, writer fencing, SVS-owned refill, cache isolation and revocation are described in the maintained [cache consistency guide](../../cache-consistency.md) and [security guide](../../data-access-and-security.md).

The first historical source review was made against a separately supplied TreeHammock archive; source hashes and exact original archive identity belong to the unchanged `SOURCE_EVIDENCE.json` file. That historical snapshot is **not** an assertion that the current tree is byte-identical or that old execution totals apply to this checkout. Treat historical source inventories, proof IDs and hashes as immutable evidence, not operational instructions.

## Qualification status

The repository contains local tests and integration harnesses, but the supplied evidence does not establish successful live YugabyteDB/Dragonfly permission and revocation tests, physical two-or-more-node failover, full-duration soak, independent security signoff or authorization to deploy. Historical findings and release gates remain open until individually adjudicated. A compiled or discovered native test is not an executed passing native test.

Review [current verification](../../current-verification.md), [testing and qualification](../../testing-and-qualification.md), and the [independent review procedure](../../../../eng/session-validation/release/README.md) before making a release claim. The preservation check for an edited source tree must be run against the actual local source and the relevant unchanged original archive, not by re-signing a prior manifest.
