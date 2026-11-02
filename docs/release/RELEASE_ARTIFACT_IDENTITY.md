# Release candidate identity and digest promotion

The current release tooling builds and verifies a source-bound image candidate. The release builder produces one Linux/amd64 OCI candidate, exercises that candidate, and extracts the API archive from its `/app` payload. Registry jobs copy the original OCI manifest and layers with digest preservation; they do not rebuild. Native SDK, Docker and registry qualification remains NotRun in this delivery.

## Canonical identity

`eng/release_identity.py` validates `vMAJOR.MINOR.PATCH[-prerelease]` and a lowercase full 40-character source commit. Base components have no leading zeros and must fit the assembly range 0–65534; numeric prerelease identifiers have no leading zeros. Build metadata (`+...`) is deliberately excluded because the version is also an OCI tag. The immutable checkout must match the requested commit byte for byte. Executable-bit repair is allowed; modified, missing, linked or untracked source is rejected. Generated artifacts stay in ignored directories excluded from the Docker context.

| Identity | Stable example | Prerelease example |
| --- | --- | --- |
| Release/registry version tag | `v1.1.0` | `v1.1.0-rc.1` |
| Version and PackageVersion | `1.1.0` | `1.1.0-rc.1` |
| AssemblyVersion and FileVersion | `1.1.0.0` | `1.1.0.0` |
| InformationalVersion | `1.1.0+sha.<full checkout SHA>` | `1.1.0-rc.1+sha.<full checkout SHA>` |
| OCI version/revision | Version / full checkout SHA | Version / full checkout SHA |
| Build identity | Fresh UUID in assembly metadata and OCI label | Fresh UUID in assembly metadata and OCI label |

These properties enter restore, compilation, no-build unit tests and no-build publish consistently. Ordinary development builds retain a distinct `1.0.0-dev` informational version. The release inspector reads actual PE metadata, file version, module ID and assembly bytes, rather than inferring them from a filename or workflow declaration.

## Candidate and evidence

The builder resolves SDK, ASP.NET runtime, BuildKit, Dockerfile frontend, PostgreSQL and Dragonfly references to Linux/amd64 digests and records the tool versions and resolved inputs. Buildx uses a unique container builder and exports a single OCI image without provenance/attestation index entries. The Dockerfile's API publish stage depends on the unit-test stage. All existing six release gates must succeed before candidate creation in either CI provider.

After export, Skopeo loads the candidate into Docker. The loaded config digest, filesystem diff IDs and labels must match the OCI candidate. Docker transport may represent its manifest differently; promotion always uses the original OCI archive. A container created by the exact config digest supplies the archive payload. A separate package-free .NET inspector reads the extracted assembly and the actual image assembly. Both must match the canonical identity and archive assembly hash.

The same candidate runs read-only on a unique internal network with owned PostgreSQL and Dragonfly instances, fresh encryption/HMAC keys, test capabilities disabled, no published host ports, a probe volume and a writable `/tmp`. Dependencies have bounded readiness waits; `/health/live` and `/health/ready` must both return 200 under the probe deadline. This is startup/readiness evidence only. The preceding source-based HTTP/system gates and this smoke probe do not establish full product flows against the final image; that remains a the historical source qualification obligation.

The builder cleans only its recorded containers/anonymous volumes, named probe volume, network, loaded image tag and Buildx builder. It never prunes the daemon. Build, inspection, runtime or cleanup failure leaves a failed, unpromotable manifest. Reusing an existing output directory is rejected.

Outputs under `artifacts/release/` include `candidate.oci.tar`, the API tarball and checksum, native archive/image/runtime reports, and `release-manifest.json`. The manifest binds source/version/build UUID, archive and assembly hashes, original OCI/config digests, resolved inputs and successful cleanup. `release-summary.json` adds each enabled registry outcome to that same identity/archive/digest record. Both JSON files accompany the published archive/checksum; the OCI artifact remains in CI for promotion/recovery.

## Publication and recovery

Every publisher requires the preflight `RELEASE_TAG` and `RELEASE_SOURCE_SHA`, then independently verifies the candidate, archive and proof hashes. Credentials use a private temporary auth file and password stdin. Default registry connections require TLS. Plain HTTP is allowed only with an explicit opt-in and a `127.0.0.1:<port>` destination for native disposable fixtures.

The version tag and full checkout-SHA tag are immutable: already matching remote bytes are reused; conflicting bytes stop publication. `latest` may move only for a stable release with `PUSH_LATEST_FOR_STABLE=true`. A new version built from the same source UUID/commit can have different bytes; its existing SHA tag must not be silently overwritten. Use a distinct release source commit, or an isolated fixture repository when qualifying different versions from one source.

Each tag outcome is written before/after lookup, copy and raw remote manifest verification. Copy uses `--preserve-digests`; transformed manifest bytes fail verification. Already verified tags remain visible if a later tag fails. An interrupted operation is recorded as `FailedOrUnknownOutcome`, not assumed rolled back. Retry verifies actual remote state, skips matching completed tags, and copies from the retained original candidate. It never rebuilds an old tag to manufacture matching provenance.

GitLab's always-running summary retains successful, failed, missing and invalid enabled registry evidence. An incomplete enabled target blocks asset/release publication. GitHub GHCR remains optional: failure or invalid/missing image evidence produces an incomplete summary while source Release creation may proceed after the candidate/package gate passes. Preserve original CI job results alongside the reports. No legacy publisher or tag alias fallback is retained.

For an authorized local release build in a clean committed checkout with Docker/Buildx, Skopeo, Python 3/PyYAML and network access:

```bash
export RELEASE_TAG=v1.1.0
export RELEASE_SOURCE_SHA="$(git rev-parse HEAD)"
python3 eng/release_artifacts.py build --output artifacts/release
python3 eng/release_artifacts.py verify --manifest artifacts/release/release-manifest.json
```

A failed registry job should be retried against the retained package artifact, rather than rerunning the package builder. To resume an explicitly selected destination using the downloaded original artifact:

```bash
# Supply the selected registry's existing credentials/settings through environment.
export REGISTRY_KIND=generic
export RELEASE_MANIFEST=artifacts/release/release-manifest.json
export PUBLICATION_REPORT=artifacts/release/generic-publication.json
bash eng/release-container-publish.sh
```

Restore `RELEASE_TAG` and `RELEASE_SOURCE_SHA` from the approved release intent, and supply `SELF_HOSTED_REGISTRY`, `SELF_HOSTED_REGISTRY_IMAGE`, `SELF_HOSTED_REGISTRY_USERNAME`, and `SELF_HOSTED_REGISTRY_PASSWORD` securely. Other supported kinds are `github`, `gitlab`, `dockerhub`, and `aws-ecr`. Retain the original manifest/archive/proof/OCI files together. To roll `latest` back, promote a retained verified stable candidate with its original identity; immutable historical tags remain checked. Never infer provenance for previously ambiguous images.

`release-proof.sh` / `release-proof.ps1` continue to execute local source build/SQL gates. They do not create or qualify the immutable candidate. Use the candidate CLI and native matrix for that additional boundary.

## Separate GitHub release policies

`treehammock-release.yml` remains the deliberate initial-main-commit `v1.0.0` bootstrap. `treehammock-versioned-release.yml` is separate: tag pushes matching `v*.*.*` or manual dispatch (default `v1.1.0`) resolve a checked immutable commit reachable from trusted `origin/main`. Manual trigger SHA may differ from checkout SHA. Existing tags must resolve to that checkout; existing Releases skip source creation. Validated fields and read/write job scopes retain the validated workflow input boundary. The target commit must contain the current release helpers and candidate contract.

## Required native and hosted qualification

```bash
python3 -m unittest discover -s eng/tests -p test_release_artifacts.py -v
python3 eng/check-release-artifact-identity.py
python3 eng/test-release-artifacts.py
```

The first two commands are supplemental tooling/source checks. Synthetic OCI blobs, PE reports and controlled command/registry responses are clearly marked fixtures and never count as native execution.

The final command requires a Linux/amd64 Docker daemon, Buildx, Skopeo, Git, Python/PyYAML, image/package network access and adequate disk space. It imports an owned temporary source checkout and builds actual `v1.1.0` and `v1.1.0-rc.1` candidates with real SDK/PE/runtime probes. It starts two pinned disposable registries on loopback-assigned ports, verifies exact promoted digests and stable-only latest, stops the second registry to retain partial failure, resumes without rebuilding, rejects mismatched version/source/digest, and removes only its owned resources. It retains candidates and qualification JSON under ignored `artifacts/native-release/`. Missing tools produce NotRun with zero executed cases.

Run unchanged workflows in designated disposable GitHub/GitLab repositories and registry namespaces to qualify scheduling, artifact transport, flag conversion, credentials, effective job permissions and protected policies. Record runner/tool versions, exact source/workflow hashes, job IDs, original failure/success outcomes and cleanup. Real hosted artifact upload/download and each enabled registry backend remain required, as do complete final-image qualification flows. Release artifact integrity remains FixedPendingQualification and all 186 release gates remain Open.

## Primary contracts

- [Buildx build options](https://docs.docker.com/reference/cli/docker/buildx/build/)
- [OCI/Docker exporters](https://docs.docker.com/build/exporters/oci-docker/)
- [Pinned Dockerfile frontend override](https://docs.docker.com/build/buildkit/frontend/)
- [Skopeo copy and digest preservation](https://github.com/containers/skopeo/blob/main/docs/skopeo-copy.1.md)
