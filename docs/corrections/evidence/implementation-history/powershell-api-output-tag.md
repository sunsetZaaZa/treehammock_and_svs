# COR23V — preserve the requested PowerShell API output tag

Owner: R10B-03 only. Rebased on completed COR23U. Status: FixedPendingQualification; real PowerShell/Docker qualification NotRun.

PowerShell treats `$Image` and `$image` as the same variable. The base-image pull loop therefore replaced the caller's default/custom API output tag with the final ASP.NET base reference. Capture the requested output in a read-only variable, use a distinct `$baseImage` loop variable, and pass only the captured tag to Docker build. Reject blank output and known exact output/base collisions before Docker work.

Resolve optional SDK/runtime process-environment overrides and forward those same references to pulls and Dockerfile build arguments. Preserve the API target, configuration, fresh COR23S build identity, progress, no-cache and context. Retain COR23Q's native helper as the final build operation so failed pulls/builds stop immediately and preserve their exit codes. No native-command helper or Bash retry/fallback behavior changes.

Add a supplemental variable/forwarding source guard and 16 tooling regressions: source mutations, actual Bash invocations with a controlled Docker process, and honest missing-native-host rejection. The separate native fixture compiles the existing COR23Q controlled executable, parses with real PowerShell and invokes both File/Command modes across default/custom tags, configurations, overrides and native failure stages. Optional actual Docker qualification builds a unique owned API tag, snapshots/preserves upstream base tags, and verifies a failed build creates no output tag. Owned output cleanup attempts every removal; no shared images are removed or caches pruned.

The 16 focused tooling cases execute here. Actual PowerShell parsing/argv/native exit enforcement and Docker builds remain NotRun without PowerShell/.NET/Docker. No source mutation or Bash fixture substitutes for those cases. See [API wrapper operation and qualification](../release/API_IMAGE_WRAPPER.md), including deliberate inspection/restoration of previously overwritten local base tags. No automatic cleanup or fabricated old-image provenance.

No SQL, package graph/locks, migrations, compatibility systems, other finding/followup or historical evidence changes. All 186 release gates remain Open.

Next: COR23W.
