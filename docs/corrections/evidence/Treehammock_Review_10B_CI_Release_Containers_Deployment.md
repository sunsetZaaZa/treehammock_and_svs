# Treehammock review R10B — CI, releases, containers and deployment

Reviewed 2026-10-03 against the unchanged uploaded source archive. This is a **review and correction-plan addendum**, not an implementation. No application source or source permissions were changed.

R10B records **five new P2 findings**, bringing the cumulative ledger to **76 open findings: 18 P1 and 58 P2**. No prior finding is closed. This chunk completes source/configuration inspection of 29 R10-assigned files; **93 R10-assigned files and three partial R06 SQL test files remain**. Real build, release, deployment and performance qualification remain pending.

## Scope and evidence

| Selected surface | Files fully inspected in this chunk |
|---|---|
| GitHub | .github/workflows/treehammock-ci.yml; .github/workflows/treehammock-release.yml |
| GitLab | .gitlab-ci.yml; all seven .gitlab/ci/pipelines files: dotnet-unit, dotnet-integration, dotnet-sql, docker-direct, docker-proxy, docker-system and release |
| Compose and edge | All five docker-compose.*.yml files; deploy/haproxy/haproxy.cfg and haproxy.host-system.cfg |
| Container helpers | eng/release-container-publish.sh; eng/docker-cli.sh; eng/docker-api-image.sh/.ps1; eng/docker-unit-tests.sh/.ps1 |
| Contract tests | GitHubActionsPipelineTests.cs; GitLabCiPipelineTests.cs; GitLabDockerIntegrationCiTests.cs; GitLabReleasePipelineTests.cs; DockerProxyConfigurationTests.cs |
| Release policy | docs/release/GITHUB_CI_CD_RELEASE_1_0_0.md |

Dockerfile, .dockerignore and Directory.Build.props received complete cross-checks while retaining their original assignments. The direct/proxy HTTP and container-system Bash runners were read to trace Compose exit propagation; their broader wrapper qualification stays in R10C. README and production deployment documentation were consulted only for relevant policy slices. The inventory distinguishes selected completion, cross-checks and pending work.

The structural evidence parses selected YAML, checks release needs graphs for known references/cycles, records published ports and inventories the five inspected test classes. These checks establish source structure, not hosted CI validity or successful jobs. The reviewed tests primarily assert source text; their presence does not qualify release behavior, real image metadata or network isolation.

**Thirteen isolated checks** use real Bash/sh interpreters and disposable fake git, gh, node, npm, bru, dotnet and Docker commands: two harmless marker substitutions in release inputs, three Compose prerequisite-failure scenarios, four publisher success/failure scenarios and four Bash syntax checks. They reproduce shell handling and command arguments without contacting GitHub, GitLab, a registry or an application. No real credentials enter the fixture. Compose's sh -lc is retained with a fixture PATH preamble; doubled dollar signs are normalized as Compose would. The checks intentionally confirm current defects as well as positive failure propagation.

The original API-image runner was attempted and stopped at absent Docker CLI selection, exit 1, before any build. dotnet, pwsh, Docker, psql/PostgreSQL and redis-server are unavailable. PowerShell behavior and built assembly identity are source/contract-derived, not executed reproductions. No peer-network test, real readiness probe, SQL/cache test, throughput or latency measurement occurred.

## Findings

| ID | Priority | Finding | Correction owner |
|---|---|---|---|
| R10B-01 | P2 | Manual release inputs become shell code before validation. | COR23T |
| R10B-02 | P2 | Release version/SHA metadata can disagree with built artifacts. | COR23U |
| R10B-03 | P2 | PowerShell base-image iteration overwrites the requested API image tag. | COR23V |
| R10B-04 | P2 | Compose runners can mask failed readiness or locked restore. | COR23W |
| R10B-05 | P2 | Local test stacks publish state and privileged test services on wildcard host ports. | COR23X |

### R10B-01 — Manual release data is substituted directly into a privileged script

**Evidence.** .github/workflows/treehammock-release.yml:92–93 embeds github.event.inputs.release_tag directly inside a Bash assignment and target_ref inside a git command substitution. GitHub expression substitution happens before shell parsing. Tag validation at 97–100 and the initial-commit restriction at 121–132 occur afterward. The workflow defaults to contents: write and packages: write; preflight receives GH_TOKEN.

The [GitHub script-injection guidance](https://docs.github.com/en/actions/concepts/security/script-injections) explains why interpolating context data into a generated script can execute commands. In the isolated fixture, a harmless local marker command embedded in either input executed before validation; the remaining tag/ref still passed the fixture checks. This is a shell reproduction with fake git/gh, not an attack against a repository.

**Impact and boundary.** A manual dispatcher who can provide these strings can make validation interpret code while the job has a write-capable token. Manual dispatch requires an authorized repository actor; this is **not anonymous input or a demonstrated fork-PR privilege escalation**. The defect is the data/code boundary and overly broad privilege of a metadata step, including accidental malformed input. Permission and protected-environment settings must be verified in the actual repository.

**Correction.** Pass dispatch inputs through intermediate environment variables and reference quoted shell variables. Validate tag/reference syntax before resolution, use an option-safe commit-resolution command, and carry a canonical SHA forward. Keep metadata/test jobs read-only and grant only the publishing jobs their required write privileges. Do not assume a post-execution regular expression makes an interpolated script safe.

**Acceptance evidence.** Actual supported Actions execution must treat dollar signs, command-substitution text, quotes, CR/LF, leading options and malformed refs as data or reject them before any side effect. Verify both valid bootstrap/manual cases and protected dispatch/permission boundaries. Use harmless marker fixtures and a disposable repository; record checkout identity without logging tokens.

### R10B-02 — Release names and SHA tags are not a consistent artifact identity

**Evidence.** GitLab release preflight computes RELEASE_VERSION from CI_COMMIT_TAG and names its archive with that tag, but .gitlab/ci/pipelines/release.yml:228 publishes without release version overrides. Directory.Build.props fixes PackageVersion/InformationalVersion to 1.0.0 and AssemblyVersion/FileVersion to 1.0.0.0. A supported later tag such as v1.1.0 can therefore name an archive containing the unchanged 1.0.0 assembly metadata unless the source properties are separately edited.

The shared publisher, eng/release-container-publish.sh:117–143, rebuilds the API with docker build --pull and release/SHA tags, but does not pass release version/revision build inputs. Dockerfile:24–55 has no corresponding release identity properties; its OCI labels contain only title/description. The isolated publisher argument capture confirms version/revision inputs are absent; it does not inspect a built image. GitHub's archive lane explicitly supplies version properties, which is a positive distinction from GitLab's archive lane.

GitHub's optional image job checks out preflight.checkout_ref (the initial main commit) at workflow lines 463–466, but IMAGE_SHA_TAG uses github.sha at 473. The [GitHub context contract](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts) defines that value as the triggering commit. Manual recovery from a later workflow ref can consequently label initial-commit source with the later trigger SHA. The marker fixture also demonstrates a later trigger and initial checkout as distinct metadata values; no actual GHCR publication occurred.

**Impact.** Operators can deploy, identify or roll back an artifact using a version/SHA that does not describe its contents. The six validation lanes precede publication, but the registry publisher rebuilds afterward with mutable base tags; no tested digest is passed for promotion and its metadata file contains tags rather than a resolved digest. This adds an unqualified reproducibility gap; no differing image bytes were observed here. Package checksums establish archive byte identity, not the intended version/source or equivalence to a later container build.

**Correction.** Resolve one release version and source SHA, inject them consistently at compilation and publication, label OCI artifacts, and bind the release manifest to archive hashes and registry digests. Build the candidate once, test that candidate where relevant, and promote its exact digest. Test source-level unit contracts alongside the production artifact tests; neither substitutes for the other. Preserve a clearly identified development build default.

**Acceptance evidence.** Build v1.1.0 and a prerelease from unchanged default version properties; inspect application assembly/file/informational versions, OCI revision/version labels, source SHA, checksum and resolved registry digest. Run manual bootstrap recovery where trigger SHA differs from checkout SHA. Verify stable/latest policy, prerelease behavior, digest-based promotion and interrupted multi-registry publication. A tag alone cannot satisfy identity acceptance.

### R10B-03 — The PowerShell API build overwrites its caller's image name

**Evidence.** eng/docker-api-image.ps1 declares $Image at line 6, then iterates foreach ($image in $requiredImages) at 54. The final loop item is mcr.microsoft.com/dotnet/aspnet:8.0. The Docker build argument at 63 uses $Image. [PowerShell's variable-name contract](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_case-sensitivity?view=powershell-7.6) is case-insensitive on supported systems, so these names refer to the same script-scope variable. The function's parameter scope does not avoid the loop assignment in the caller.

**Inferred behavior.** On successful pulls, the build ignores either the default treehammock:api or a caller's custom tag and tags the application as the upstream ASP.NET base image. This can replace that local tag and confuse subsequent builds; it does not itself push to the Microsoft registry. PowerShell is unavailable, so the actual invocation/tag mutation remains to be reproduced. The final native build's missing exit check belongs to R10A-01/COR23Q and is not counted twice.

**Correction and regression.** Use distinct base-image and output-image variables, preserve the caller's tag through every step, and share explicit native failure propagation with COR23Q. Test the actual PowerShell wrapper with a fake Docker executable capturing argv for default/custom tags, failed pulls and failed builds; then build disposable real images on supported hosts and inspect the requested tag. Assert upstream base-image tags are not repointed by the application build.

### R10B-04 — Compose test prerequisites can fail while the container returns success

**Evidence.** docker-compose.integration.yml:159–166 and 180–187 execute readiness, npm install, file checks and Bruno sequentially in sh -lc without errexit or conditional chaining. docker-compose.ci-system.yml:21–26 similarly follows locked restore with dotnet test --no-restore. A shell's last command supplies success even if an earlier prerequisite failed. The outer HTTP runners use Compose run and the system runner uses --exit-code-from system-tests; they propagate the container's eventual code, not an earlier ignored code.

**Reproduction.** In both HTTP commands, fake readiness exited 37, subsequent npm/Bruno still ran and the shell returned 0. In the system command, fake locked restore exited 37, test still ran and the shell returned 0. Actual Bruno or .NET tests can independently fail; the finding is that failure of a required prerequisite does not necessarily fail the lane. With existing mounted assets, a later test can also use stale restore state. No real tests or stale .NET assets were run in this fixture.

The readiness JavaScript retries responses/errors but applies no per-request timeout. A request that never produces either can prevent the retry counter from advancing; CI job timeouts bound the whole job but do not supply the intended readiness deadline. This is a runner closure requirement within this finding, separate from R09's application dependency-probe budget.

**Correction and regression.** Make each prerequisite failure terminate the container with a nonzero result; add explicit per-request and overall readiness deadlines and sanitize the diagnostic. Pin and reliably provision the HTTP runner rather than treating an uncontrolled global install as proof infrastructure. Exercise failed readiness, hung requests, install/file-check failure, failed restore and failed final tests. Assert later stages are not invoked and the top-level direct/proxy/system lane fails. Then run those cases in actual Compose and check real test discovery/results; an exit 0 with no executed tests must not qualify a release.

### R10B-05 — Local fixture services are reachable through broad host publications

**Evidence.** Both integration and local-system Compose files publish 5432:5432 and 6379:6379 without a host address. PostgreSQL uses a known fixture password; Dragonfly has no configured password and binds 0.0.0.0 inside its container. Both proxies publish 8080:8080; the direct override publishes 5001:5001. The integration API enables inspection/test capabilities with a committed fixture key at lines 107–110.

Under the [Docker default port-publishing contract](https://docs.docker.com/engine/network/port-publishing/), mappings without a specific host address publish on all host addresses. Effective remote reachability depends on daemon/network/firewall configuration; this review did not establish Internet exposure or make a connection from a peer. These defaults nevertheless unnecessarily expose account/session fixture data, cache control and privileged test helpers on developer or runner networks. This is a **local networking defect**, distinct from R07-01's missing production isolation for test capability selection.

**Correction.** Omit host publications for container-only lanes and put services on a dedicated disposable project network. Use explicit loopback publications only for host-backed lanes that require them, with generated fixture credentials/key where practical. Design the container HAProxy-to-host API connection deliberately: binding a host API only to loopback can break host-gateway access, so choose a restricted reachable interface/path rather than silently broadening it. Offer remote development only as an explicit configured opt-in.

**Acceptance evidence.** Render the effective Compose configuration, inspect listening addresses, and verify expected host/container access plus denied independent-peer access on supported Linux/Desktop/CI environments. Test IPv4/IPv6 and supported Docker versions. Docker documents older-than-28 loopback-publication limitations on the same L2 segment; a loopback string alone is not a universal isolation proof. Keep container-only state unpublished, or qualify additional host/network restrictions. Production must reject all fixture capabilities through COR23D. No real peer-network qualification occurred here.

## Gate and policy conclusions

| Surface | Source result | Required qualification or disposition |
|---|---|---|
| GitHub release package | Requires unit, integration, SQL, direct HTTP, proxy HTTP and host system gates. | Run real failure-injection and successful release lanes; gate names/needs alone do not prove test execution. |
| GitLab release package/images | Each requires the six validation gates. Parent triggers use strategy: depend. | Verify actual child status propagation, enabled/disabled lane rules and hosted lint behavior. |
| GitLab optional image needs | optional: true permits the job to be absent; it is not evidence that an enabled failure is accepted. | The [GitLab needs contract](https://docs.gitlab.com/ci/yaml/#needsoptional) requires waiting when that job is present. Test failure behavior with the actual supported GitLab version. |
| GitHub bootstrap policy | The initial-main-commit/v1.0.0 restriction is explicit in docs and tests. | This is an intentional capability limit, not a newly counted defect. A release process for later corrected source must be defined before claiming ongoing feature completeness. |
| GitHub optional GHCR | Source release creation explicitly can proceed independently of optional image publication. | Preserve the documented choice; report image outcome clearly. No defect is added solely because optional GHCR failure does not prevent a source release. |
| Shared publisher | Password-stdin, required variable checks, stable-only latest and fail-fast Bash behavior are present. Fake build/push failures stop it before metadata output. | Test real auth, digest recording, retries/partial publication and safe credential cleanup on disposable supported registries. No registry was contacted. |
| HAProxy examples | Header rewriting/local host-gateway routing are present; public TLS/Cloudflare examples are comments. Configuration healthcheck validates syntax. | Comment-presence tests do not qualify an active production edge or backend readiness. Validate effective production configuration and real forwarded identity/TLS end to end under existing COR23D and hosting work. |
| Build consistency | Locked restore is used; runtime image copies publish output rather than an SDK. Mutable SDK/runtime/PostgreSQL/Dragonfly/HAProxy tags remain. | Record and control actual resolved inputs/digests. No vulnerability or measured slowdown is inferred merely from mutable tags. |
| Tooling and reports | Bash runners enforce failure outside the inner Compose commands. PowerShell final native calls remain unchecked. HTTP report uploads are permissive. | COR23Q owns native error propagation. COR24 must require actual discovered/executed tests and fresh expected artifacts, not optional uploads or source-string tests. |

Archive mode loss is not counted as a repository defect: the uploaded ZIP records no Unix modes, CI chmods scripts, and isolated fixtures do not alter original permissions. Deferred binary/dependency security qualification from R10A remains open.

## Correction design and detailed PR-plan addendum

Append **COR23T–X** to the existing design/PR plan alongside COR23A–S. These are reviewable specifications, not code changes or opened PRs. The trusted-grant activation decision remains unchanged. Original Word design/plan files have not been rewritten. Each PR must include behavioral evidence appropriate to its boundary, and COR24 retains the final release qualification decision.

### COR23T — Separate release inputs from shell code and scope credentials

- **Owns:** R10B-01. **Dependencies:** repository permission/protected-ref policy; coordinate COR23U canonical source identity. Can ship before application corrections.
- **Files:** GitHub release workflow, metadata resolution helper if extracted, behavioral Actions/helper fixtures and release policy documentation.
- **Implementation:** environment-backed inputs, pre-resolution validation, option-safe ref resolution to immutable SHA; read-only preflight/validation tokens and write privileges only for necessary publish jobs. Carry explicit outputs instead of reparsing unsafe inputs in later jobs.
- **Acceptance:** harmless injection fixtures never execute; malformed/option-like/multiline inputs fail before side effects. Valid bootstrap/manual recovery preserves intended policy. Verify actual dispatch authority and job token permissions in a disposable repository.
- **Migration/rollback:** adjust workflow permission declarations and any required environment policies together. No schema migration. Rollback may disable manual dispatch temporarily but must retain the data/code boundary.

### COR23U — Bind release artifacts to one source, version and tested digest

- **Owns:** R10B-02. **Dependencies:** COR23T safe metadata; COR23S build/test configuration identity; COR24 artifact execution policy. No dependency on arbitrary activation product changes.
- **Files:** GitLab/GitHub release workflows, shared publisher, Dockerfile, MSBuild identity inputs, manifest/checksum tooling, artifact inspection tests and release docs.
- **Implementation:** validate canonical semantic version/base assembly version and source SHA once. Override all fixed release properties consistently during build, including the build stage preceding no-build publish. Populate OCI version/revision labels. Build an immutable candidate, record resolved bases and content digest, exercise the candidate and promote/copy that digest to enabled registries. Record each registry outcome, source/build identity and archive hashes in a release manifest. Use checkout SHA for SHA tags. Define later-version release policy separately from the deliberate GitHub bootstrap restriction.
- **Acceptance:** inspect real archives/images for v1.1.0 and prerelease identities; prove trigger/checkout divergence cannot mislabel contents. Verify the tested and promoted digest match, immutable inputs are recorded, latest remains stable-only, and partial multi-registry failures produce honest recoverable status. Test against disposable registries without publication to production.
- **Migration/rollback:** retain legacy tag aliases only with explicit digest/source mapping; document previously ambiguous metadata rather than fabricating provenance. Promote known verified digests for rollback. No database migration; never rebuild an old tag and assume identical bytes.

### COR23V — Preserve the requested API image tag in PowerShell

- **Owns:** R10B-03. **Dependencies:** COR23Q native-command failure contract. Coordinate Bash/PowerShell base override/configuration parity with remaining R10C wrapper review.
- **Files:** eng/docker-api-image.ps1 and behavioral Docker-wrapper fixtures; supported-host documentation where needed.
- **Implementation:** distinct immutable output-tag and loop variables, explicit final native result propagation, and consistent target/configuration/no-cache/progress forwarding. Avoid assigning an application build to a base-image reference.
- **Acceptance:** real PowerShell fake-executable argv tests cover default/custom output tags, successful/failed pulls and failed build. Disposable real Docker builds produce the requested output tag and leave upstream base tags pointing to their original images.
- **Migration/rollback:** explain how affected developers can inspect and restore accidentally overwritten local base tags; do not automatically delete unrelated images. No schema migration. Reverting variable safety is not an acceptable rollback.

### COR23W — Make Compose prerequisites fail the proof lane

- **Owns:** R10B-04. **Dependencies:** runner host/tool policy and COR24 test execution/artifact contract; coordinate COR23Q for wrapper parity.
- **Files:** integration/ci-system Compose commands, readiness helper or runner image, direct/proxy/system runners and executable lane-failure fixtures.
- **Implementation:** fail-fast shell contract for every prerequisite; explicit bounded HTTP attempts and overall readiness deadline; deterministic HTTP tooling provision. Preserve the actual failing stage/code and pass it through Compose to CI. Require fresh results with nonzero expected discovery/execution rather than accepting a successful final command alone.
- **Acceptance:** injected failures at readiness, install, collection file validation, restore and tests stop later commands and return nonzero at container/runner/CI layers. A hung HTTP response terminates within budget. Real supported Compose/.NET/Bruno runs demonstrate both success and failure; stale assets/results cannot satisfy the lane.
- **Migration/rollback:** update runner provisioning and result consumers together, clearing only per-run fixture output. No schema migration. A failing prerequisite should stay failed even if provisioning changes must be rolled back.

### COR23X — Isolate local fixture state and test capabilities

- **Owns:** R10B-05. **Dependencies:** COR23D production rejection of test capabilities; R10C host/container runner network design. Coordinate COR24 isolation qualification.
- **Files:** all Compose variants, host-stack launch/configuration helpers, generated fixture credential plumbing and local deployment docs/tests.
- **Implementation:** container-only default network without host state publications; explicit restricted host-backed profiles; generated credentials/key and lifecycle scoped to each disposable test project. Design a restricted proxy-to-host API route with supported Desktop/Linux behavior and opt-in remote lab access. Keep effective configuration inspectable and avoid profile combinations that reopen wildcard access inadvertently.
- **Acceptance:** rendered Compose variants expose only intended endpoints, including merged overrides. Verify host/container usability and denied unrelated peer access under supported IPv4/IPv6/daemon versions, including any older-engine limits. Ensure test inspection is inaccessible without the per-run key, production rejects it, and parallel projects do not reuse ports/state/keys unexpectedly.
- **Migration/rollback:** update local connection documentation and generated fixture configuration together; recreate disposable state only with explicit fixture ownership. Do not delete a developer's unrelated volumes or modify global firewall settings implicitly. Rollback can restore a documented restricted host lane while retaining isolation requirements.

## Completion and next chunk

The cumulative 43-member bundle retains prior reports/evidence and adds this report, structural evidence, isolated command-flow evidence, the blocked real image-runner attempt, a reproducible builder and the latest 76-finding ledger/file inventory. Archive parity checks cover every one of the 451 source files. All existing findings remain open; no runtime-qualified chunk is declared.

R10C should complete the remaining Docker/developer wrappers, host/system runners and their supporting tests. The **93-file R10 remainder plus three partial R06 SQL tests** remain explicit obligations, followed by remaining suite/documentation/operational coverage. Correctness, performance and feature completeness require implemented corrections or accepted dispositions, real state/concurrency/fault tests, verified release artifacts and measured budgets; source inspection alone cannot close that goal.
