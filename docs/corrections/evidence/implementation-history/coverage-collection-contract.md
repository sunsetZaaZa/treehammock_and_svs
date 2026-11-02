# COR23R — real coverage collection contract

Owner: R10A-02 only. Rebased on completed COR23Q. Status: FixedPendingQualification; native qualification NotRun.

The coverage switches selected XPlat Code Coverage while the project intentionally excluded Coverlet. Microsoft.NET.Test.Sdk already provides the locked Microsoft.CodeCoverage 17.14.1 collector, privately owned by the test project. Select that existing VSTest collector, explicitly request Cobertura and restrict collection to the application assembly. Preserve the exact package graph/locks and Coverlet exclusion.

Route Bash/PowerShell unit, integration and fast validate coverage paths through a shared Python runner. Require a fresh UUID result directory, nonzero complete passing TRX discovery, exactly one parseable report, executable and hit application lines, source/class measurements and consistent summary counts. Record invocation/configuration argv, settings/report/TRX hashes and measurements. Native test failures retain their original code; successful processes with invalid output fail. Existing nested build-proof propagation uses the same contract.

Allow `validate` baseline-output collection and the fast correction collector to request coverage. Separate unit/integration outputs, reject a bad unit artifact before integration runs, and revalidate hashes/content on evidence import. Keep unsupported SQL/system collection explicitly rejected. No finding or release gate can close from tooling/source consistency alone.

Author an actual SDK/collector known-branch fixture with positive/negative measurement assertions, absent collector, stale sibling, zero discovery and test-failure cases. It runs clean real fast lanes through the selected host and checks the actual published application has no collector. Add a native dependency-boundary regression for private locked collector provenance and application isolation. Synthetic Python artifact/control-flow and wiring mutations are supplemental; they do not measure coverage or qualify the collector.

See `COVERAGE_CONTRACT.md` for commands, host requirements, result format, primary documentation and qualification limits. CI artifact integration and Sandbox configuration correction remain separately owned. No database, migration, compatibility system or package-lock changes.

Next: COR23S — align build and test configuration identity.

## Current follow-up acceptance — COR25.38

The current COR23R follow-up now names the implemented locked Microsoft.CodeCoverage 17.14.1 collector, friendly name `Code Coverage`, application-only Cobertura and the unchanged Coverlet exclusion. The old `real_xplat_collector_is_discovered_and_emits_nonempty_coverage` acceptance name is superseded and retained in the follow-up current_note_history; it is not a request to select XPlat again. The frozen implementation specification/report/hash, original owner and native NotRun state are preserved.

The actual collector oracle remains `eng/test-coverage-contract.py`: `unit-known-positive-branch`, `integration-known-negative-branch`, `collector-absent`, `zero-discovery`, `test-failure-retained`, `stale-sibling-cannot-satisfy-new-run`, `real-project-clean-fast-lanes` and `application-publish-has-no-test-collector`. Run through each supported native host and retain real coverage/TRX/application-publish identities. Source/synthetic wiring and report checks do not measure coverage or qualify any host. COR25.Q01 retains those actual native obligations.
