# GitHub CI/CD release lane for 1.0.0

The release workflow uses [candidate identity and digest promotion](RELEASE_ARTIFACT_IDENTITY.md) and a separate versioned workflow. This document defines the GitHub Actions release lane that mirrors the existing GitLab child-pipeline design without changing the release contract. GitHub Actions is an additional CI/CD surface for Treehammock / Raptor Balcony 1.0.0, not a replacement for the existing GitLab workflows.

## Goals

- Keep routine branch and change validation fast by running only .NET unit and in-process integration tests by default.
- Keep PostgreSQL SQL contracts and Docker Compose system tests explicit heavy lanes.
- Run every release gate before packaging or publishing `v1.0.0`.
- Restrict the GitHub release lane to the initial commit to the `main` branch of a fresh repository for the one-time `v1.0.0` bootstrap release.
- Produce a versioned API publish archive and SHA256 checksum for the GitHub release.
- Allow optional GitHub Container Registry publishing without requiring it for source release creation.

## Workflow files

| Workflow | File | Trigger | Purpose |
| --- | --- | --- | --- |
| Treehammock CI | `.github/workflows/treehammock-ci.yml` | `pull_request`, selected branch `push`, and manual `workflow_dispatch` | Runs the fast validation lanes by default. Manual dispatch can run SQL contracts and Docker lanes. |
| Treehammock Release | `.github/workflows/treehammock-release.yml` | first `main` push or manual `workflow_dispatch` | Bootstraps `v1.0.0` only when the resolved target is the initial commit to `main` and no `v1.0.0` tag or Release exists; later automatic runs skip release work. |
| Treehammock Versioned Release | `.github/workflows/treehammock-versioned-release.yml` | `v*.*.*` tag pushes or manual dispatch | Later-version candidate release from a checked immutable main-ancestor commit; default manual version `v1.1.0`. |

## Normal CI behavior

Proposed changes and branch pushes run:

1. `./eng/check-locks.sh`
2. `./eng/dotnet-unit-tests.sh --configuration "$BUILD_CONFIGURATION" --locked-restore`
3. `./eng/dotnet-integration-tests.sh --configuration "$BUILD_CONFIGURATION" --locked-restore`

The CI workflow uploads TRX files as artifacts even when a lane fails. Manual dispatch exposes these lanes:

- `all`
- `unit`
- `integration`
- `sql`
- `docker-direct`
- `docker-proxy`
- `docker-system`

The `sql` lane starts disposable PostgreSQL 16 and sets:

```text
TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS=true
TREEHAMMOCK_DB_CONTRACT_CONNECTION=Host=localhost;Port=5432;Database=treehammock_contract;Username=postgres;Password=postgres
```

GitHub Actions emits and documents `TREEHAMMOCK_*` as the SQL and release contract. Only the documented `TREEHAMMOCK_*` environment variables are supported. See `TREEHAMMOCK_ENVIRONMENT_VARIABLES.md` for the current variable list.

The Docker lanes call the existing repository scripts:

- `./eng/docker-http-contracts-direct.sh`
- `./eng/docker-http-contracts-proxy.sh`
- `./eng/docker-host-system-stack-tests.sh`

The CI/release system lane is host-backed: PostgreSQL, Dragonfly, and HAProxy run in Docker, while the API and system tests run on the GitHub-hosted .NET SDK. This avoids making the system lane depend on pulling `mcr.microsoft.com/dotnet/sdk:8.0` as a Compose service image, which has proven flaky on some GitHub runner network paths.

Each Docker lane tears down the Compose stack in an `always()` cleanup step.

## Release behavior

The release workflow defaults manual dispatch to `v1.0.0`. It also runs automatically on pushes to `main`. This bootstrap workflow intentionally does not listen to tag pushes. The separate Treehammock Versioned Release workflow listens to canonical version tags and supports later main-ancestor source.

For a `main` branch push, the workflow enters bootstrap mode: it targets `v1.0.0`, resolves the pushed commit SHA, and computes the initial commit on the first-parent history of `origin/main`. The release is allowed only when the trigger commit equals that initial main commit. It also checks GitHub for an existing `v1.0.0` Release or tag. If the trigger is not the initial main commit, or if the tag or Release already exists, every downstream release gate/package/publish job is skipped. This makes the fresh repository initial `main` commit the only automatic source for the 1.0.0 release.

Release gates run in this order before packaging when the preflight says a release should run:

1. Release metadata preflight validates the `vMAJOR.MINOR.PATCH` tag format and computes package names.
2. Release .NET unit gate.
3. Release .NET in-process integration gate.
4. Release PostgreSQL SQL gate against disposable PostgreSQL 16.
5. Release Docker direct HTTP integration gate.
6. Release Docker HAProxy HTTP integration gate.
7. Release Docker host-backed system stack gate.
8. Release package job.
9. Optional GitHub Container Registry image job.
10. GitHub Release creation.

## Release artifacts

For `v1.0.0`, the package job creates:

- `treehammock-api-v1.0.0.tar.gz`
- `treehammock-api-v1.0.0.sha256`

The release build workflow applies Version/PackageVersion, base AssemblyVersion/FileVersion, informational source SHA and build UUID during compilation and no-build publish. The archive is extracted from one tested OCI candidate; `release-manifest.json` and `release-summary.json` accompany the archive/checksum. Native assembly/image inspection, digest-preserving promotion and partial recovery are detailed in [release artifact identity](RELEASE_ARTIFACT_IDENTITY.md). Development defaults are not release provenance.

## Optional GHCR publishing

GitHub Container Registry publishing is intentionally opt-in:

- Manual dispatch: set `publish_ghcr=true`.
- Initial-main-commit push: set repository variable `PUBLISH_GHCR=true`.

When enabled, `eng/release-container-publish.sh` uses `REGISTRY_KIND=github` and promotes the original tested OCI candidate with digest preservation to:

```text
ghcr.io/<owner>/<repo>
```

Stable tags such as `v1.0.0` also receive `latest` when `PUSH_LATEST_FOR_STABLE=true`. Prerelease tags such as `v1.0.0-rc.1` do not receive `latest`.

## Operator path for 1.0.0

Preferred bootstrap release for the first GitHub commit:

```bash
git push origin main
```

On that initial-main-commit push, the workflow creates `v1.0.0` after all gates pass. Later `main` pushes resolve to a non-initial commit, or see the existing `v1.0.0` tag or Release, and skip release work.

Manual release from GitHub Actions for explicit recovery:

1. Open **Actions**.
2. Select **Treehammock Release**.
3. Choose **Run workflow**.
4. Use `release_tag=v1.0.0` and `target_ref=<initial-main-commit-sha>`.
5. Leave `create_release=true`.
6. Enable `publish_ghcr` only when the container image should be published to GHCR.

The manual path creates the release from `target_ref` after all release gates pass only when the resolved target is the initial commit to `main`. Existing GitHub Releases or tags cause preflight to skip downstream release work so the once-only release contract stays intact.

The release workflow passes all dispatch fields through environment variables into the trusted main metadata helper. Malformed refs/tags/flags fail before external commands; immutable SHA and validated publish flags flow through explicit outputs. Failed GitHub lookups block release work. Preflight, gates and packaging have read-only repository tokens; only GHCR and Release publication have their necessary write scopes. See [release input policy and hosted qualification](RELEASE_INPUT_POLICY.md). Actual dispatch authority/token enforcement and native release gates remain unqualified.

## License metadata

The release package includes the repository `LICENSE` file and project metadata declares `PackageLicenseExpression` as `MIT`.

## Combined TreeHammock and SessionValidation GitHub Releases

Both GitHub release workflows now require an additional `release-package-svs` job.
The `create-github-release` job depends on **both** the tested TreeHammock API
package and the managed SessionValidation package. A missing or failing SVS
build/test/package prevents creation of a new combined release.

The workflows install .NET 8 and .NET 10 SDKs because the repository selects a
.NET 10 SDK in `global.json`, the TreeHammock API targets .NET 8, the private
SVS host targets .NET 10, and shared SVS libraries/tests target both.

For a canonical tag such as `v1.2.3`, the **same GitHub Release** will contain:

| GitHub Release asset | Contents |
| --- | --- |
| `treehammock-api-v1.2.3.tar.gz` | Existing tested TreeHammock API bundle |
| `treehammock-api-v1.2.3.sha256` | TreeHammock API checksum |
| `release-manifest.json`, `release-summary.json` | Existing TreeHammock release evidence |
| `session-validation-v1.2.3.tar.gz` | Private SVS host, managed client assemblies, documentation/examples |
| `session-validation-v1.2.3.sha256` | SessionValidation SHA-256 checksum |
| `session-validation-release-manifest.json` | SVS source SHA, archive and per-file hashes, framework and qualification status |

The SVS bundle includes `service/` with the **framework-dependent** .NET 10
ASP.NET Core gRPC host, `client/net8.0` and `client/net10.0` with compiled client
and contracts DLLs, and deploy guidance/examples. Installing the .NET 10 ASP.NET
Core runtime is required on the host. The client DLLs are **reference binaries**,
not standalone NuGet packages: their NuGet dependencies must be restored from
the corresponding source project. No credentials or private keys are bundled.

This package does not change SVS production security admission. Its manifest
explicitly has `production_approved: false`: managed tests and CI archive
verification do **not** replace native Yugabyte/Dragonfly, mTLS and network
security, physical-host, capacity, revocation/failover, soak, or independent
release-security qualifications.

### Managed validation

- On PR and branch CI, the `svs-managed-tests` job runs the six owned managed
  SVS xUnit v3 executable test projects on their supported .NET 8/.NET 10
  targets, including the .NET 10 host tests.
- The release SVS package job repeats the managed suite at the selected
  immutable release commit. It checks each test XML has a nonzero number of
  tests, no skipped or failed tests, and verifies the resulting archive before
  exposing its artifacts.
- Native-provider suites and physical qualification remain separate gates.
  Do not present a GitHub Release asset as proof of those checks.

The supporting entry points are `eng/session-validation-release.sh`,
`eng/session_validation_artifacts.py` and
`eng/session_validation_test_results.py`. The package-only integrity tests run
without the .NET SDK using:

```bash
python3 -m unittest discover -s eng/tests -p 'test_session_validation_artifacts.py'
```

### Publishing a versioned combined release

1. Commit the CI/workflow changes **and all SessionValidation source and lock
   files** to the root of your TreeHammock GitHub repository. The workflows live
   in the repository's `.github/workflows` directory.
2. Confirm the normal `Treehammock CI` workflow, including
   `svs-managed-tests`, passes. A green CI lane alone does not grant SVS
   production approval.
3. Create and push a canonical, new version tag pointing to the approved
   source commit, for example `v1.2.3`, or manually invoke **Treehammock
   Versioned Release** in Actions with the desired tag and `target_ref`.
4. Wait for all release gates, the TreeHammock artifact job, and the SVS
   artifact job to pass. The final GitHub Release job will attach both sets
   of assets to the same tag. You may keep `publish_ghcr=false`; the GitHub
   Release downloads still include both APIs.
5. Open **GitHub repository → Releases → chosen tag** and verify the
   `session-validation-...` archive, checksum, and manifest are all present.

The older `Treehammock Release` workflow remains restricted to initial
`v1.0.0` bootstrap behavior; normal later releases should use
`Treehammock Versioned Release`. The release preflight intentionally skips
existing tags/releases. **This update does not retroactively modify older
GitHub Releases.** Publishing older assets requires a separately reviewed
backfill/migration, not disabling existing source-boundary checks.

The scripts can be checked locally without publishing:

```bash
bash eng/session-validation-release.sh test artifacts/session-validation/tests
# After a clean checkout of a release commit, with RELEASE_TAG and
# RELEASE_SOURCE_SHA set:
bash eng/session-validation-release.sh publish artifacts/session-validation/published
python3 eng/session_validation_artifacts.py package \
  --source artifacts/session-validation/published \
  --output artifacts/session-validation/release \
  --tag "$RELEASE_TAG" --sha "$RELEASE_SOURCE_SHA"
```

Publishing requires GitHub Actions with `GITHUB_TOKEN` scoped to
`contents:write` in its final release job. The artifact and test jobs require
only read permission. Existing GitHub Release assets retain the repository's
current `--clobber` update semantics, so do not rerun publication against an
existing tag unless overwriting assets is explicitly intended.
