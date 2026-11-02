# Current verification and release status

**Source snapshot reviewed:** user-provided `treehammock.zip` used for this documentation workspace, 2026-11-02. This page describes what can be established from the supplied files, not a new live infrastructure or security test result.

| Subject | Status supported by this snapshot |
| --- | --- |
| Separate private SVS API | Present in source (`src/Treehammock.SessionValidation.Api/`) |
| Typed client, shared contracts and policy, storage coordinator | Present in corresponding source projects |
| Primary TreeHammock API | Present in public application source |
| Solution registration | `treehammock.sln` includes TreeHammock and SessionValidation projects; loading and compilation depend on installed SDK/workloads |
| Local verification | Historical testing artifacts and tooling present; **no fresh .NET or infrastructure tests performed as part of this documentation step** |
| Native Yugabyte/Dragonfly qualification | Not established by this source package |
| Target-host TLS, privilege and fleet acceptance | Not established by this source package |
| Independent security and release approvals | Not established; inherited release controls remain blocked |
| Production authorization | **Not approved** |

The inherited `eng/session-validation/ci/source-pins.json` records `native_acceptance: NotRun`, `grant_rights: false`, and `release_ready: false`. The existing proof and design manifests have entries which do not match or are absent from this working snapshot; this was observed in the previous read-only inventory and is not repaired by editing documentation. Old pin digests are historical evidence rather than an automatically regenerated attestation of this checkout.

The application and SVS paths are present, but local builds, private certificate validation, database privileges, race tests, physical load/failover and full release adjudication remain separate acceptance work. Consult [testing and qualification](testing-and-qualification.md) and the [release review tool](../../eng/session-validation/release/README.md).
