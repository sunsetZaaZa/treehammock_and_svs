# GitHub release input and token policy

The current release tooling enforces a validated input and executable-command boundary. The GitHub release lane remains an intentional one-time v1.0.0 bootstrap from the initial commit on the first-parent history of origin/main. Manual recovery may be dispatched from a later workflow commit, but its target must resolve to that same initial commit. A separate versioned workflow supports later versions for later corrected source; see [candidate identity and versioned policy](RELEASE_ARTIFACT_IDENTITY.md). The bootstrap restriction remains intentional.

Preflight checks out trusted main with full history, then runs `python3 eng/release-metadata.py`. The helper reads the environment and uses argument-list subprocess APIs, with no shell evaluation. Environment-backed dispatch input never forms script text. Python 3, Git with `rev-parse --end-of-options`, and GitHub CLI are required on the Ubuntu Actions runner. Errors return 2 without printing input or credentials. Missing tools and failed commands cannot emit success outputs.

| Input | Accepted data | Result |
| --- | --- | --- |
| release_tag | ASCII vMAJOR.MINOR.PATCH, optionally a dot-separated alphanumeric/hyphen prerelease such as `-rc.1`; at most 128 characters, no leading zeros in base or numeric prerelease components; base components 0–65534 | v1.0.0 may release; other valid tags skip under the existing bootstrap limit |
| target_ref | Branch/tag name or 7–40 character hexadecimal SHA, or explicit refs/heads, refs/tags, refs/remotes/origin name; at most 255 characters | Resolution must produce exactly one immutable 40-character commit SHA |
| create_release | `true` or `false` | Validated output controls source Release creation |
| publish_ghcr | `true` or `false` | Validated output controls optional GHCR publication |
| PUBLISH_GHCR on push | Empty/unset, `false`, or `true` | Empty/unset means false; true opts in |

Refs exclude leading options, whitespace, quotes, dollar/backtick substitutions, CR/LF, Git revision expressions (`HEAD~1`, `main^{commit}`, `main:path`, reflog expressions), dot-dot, empty/dot-prefixed components and `.lock` suffixes. Git additionally checks full ref syntax before fetching. Bare names consider local branches, tags and remote origin branches; names resolving to different commits fail as ambiguous. Tags are peeled to commit objects. Short SHAs must resolve uniquely. Use the full initial commit SHA for recovery.

After syntax checks, only a fixed main-history fetch and read-only Git/GitHub queries occur. Outputs are written only after successful resolution/policy checks. Release/tag GET lookups distinguish existing objects, actual 404 absence and failures. Authentication/permission/server/transport errors block downstream jobs instead of treating the object as absent. Skip reasons are fixed safe text. Downstream checkouts use the immutable preflight SHA; publish conditions consume validated flags.

| Job | Declared GITHUB_TOKEN scopes | Checkout credentials |
| --- | --- | --- |
| Preflight | contents: read | Read-only credential retained for explicit main fetch |
| Six validation jobs and API package builder | contents: read | Not persisted |
| GHCR image publication | contents: read, packages: write | Not persisted |
| GitHub Release creation | contents: write | Immutable source checkout, credentials not persisted |

Unspecified scopes are omitted. Artifact/cache Actions use runner services; their use does not justify repository contents/package writes. Administrators separately restrict workflow/ref modification and review dispatch/protected environment rules. Source declarations do not prove actor authorization or effective hosted token scopes.

## Executed fixtures and required hosted qualification

```bash
python3 -m unittest discover -s eng/tests -p test_release_input_boundary.py -v
python3 eng/check-release-input-boundary.py
```

Local boundary tests execute the actual metadata command in Bash against a disposable real Git origin. The gh process uses controlled HTTP headers/exits and has no token. They do not execute the hosted scheduler, perform real CLI requests or enforce job permissions. the release input controls remains FixedPendingQualification; all 186 release gates remain Open.

Before claiming hosted qualification, use an explicitly designated disposable GitHub repository/package namespace. Record exact workflow/helper/source hashes, runner/CLI versions, run IDs, resolved SHA, job permissions and outcomes. Keep tokens and response bodies out of evidence; retain original success and failure results.

1. Import this complete source as the initial main commit so the target contains the required runners. Configure disposable authority/package settings before pushing: the unchanged workflow can automatically publish its bootstrap there. Execute the unchanged workflow with actual gate resources. Record job permissions, discovery/results and publication outcomes. Confirm existing release/tag skips afterward. Remove only this disposable release/tag before a deliberate manual recovery run if necessary, recording the fixture reset.
2. Add a harmless later main commit. Confirm later pushes skip and manual `target_ref=<initial SHA>` checks out the original SHA. Observe true/false dispatch flag conversion and remote-only branch/tag recovery. Complete the actual six gates/archive before claiming passing publication. Optional GHCR remains separately observed in the disposable namespace.
3. Dispatch harmless marker substitutions and quote/CR/LF/leading-option/malformed ref/version values. Require failed metadata, no marker, no enabling outputs, skipped publication and no created release/tag/package. Scope markers to the job workspace. A fixture-only artifact step may preserve marker absence; record its separate workflow hash.
4. Record real actor roles and authorized/unauthorized dispatch attempts using disposable test accounts. Verify administrator-configured protected workflow/ref/environment policy. Inspect hosted job token permission summaries. In a disposable workflow copy, use harmless write probes to require denial under preflight/validation tokens, and observe only the necessary publication scopes succeeding. Record each fixture modification/hash separately from unchanged workflow evidence.
5. Reproduce missing/ambiguous refs, fetch failures, actual CLI API auth/permission failures and unavailable-object 404 behavior. Failed lookups must emit no enabling outputs. Keep all probes and cleanup confined to owned disposable resources.

Hosted dispatch authority, effective scopes, actual CLI HTTP behavior, full native gates and registry publication remain NotRun here. Local fixtures do not substitute for them. The current release tooling implements trigger/build/image consistency, manifest checks, tested digest promotion and a separate later-version release policy; their actual native and hosted qualification remains NotRun.

## Primary contracts

- [GitHub script injection guidance](https://docs.github.com/en/actions/reference/security/secure-use): environment-backed input boundary.
- [GitHub workflow permissions](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions): explicit job scopes and omitted permissions.
- [GitHub CLI API](https://cli.github.com/manual/gh_api): explicit GET and included response headers.
- [Git commit resolution](https://git-scm.com/docs/git-rev-parse): verify commit objects with end-of-options for untrusted names.

These contracts were checked during implementation; repository-specific enforcement requires the qualification above.
