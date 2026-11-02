# COR23W — fail Compose proof at the actual prerequisite

Owner: R10B-04 only. Rebased on completed COR23V. Status: FixedPendingQualification; actual Docker/SDK/Bruno qualification NotRun.

The direct/proxy HTTP Compose commands previously continued after failed readiness, npm install or missing collection checks, so a later command could mask the initiating failure. Replace the inline shell chains with one Node proof runner. Validate the collection, use built-in HTTP with explicit attempt/aggregate deadlines and active-request cancellation, install Bruno into that run's private tool directory, execute the recursive collection, then require a fresh report with all four expected health tests passing and no failed/skipped request/assertion summary. Preserve native stage exits; failed diagnostic writes cannot replace the original native result.

The container system command delegates to a fail-fast Bash script using one fresh COR23S build UUID. Compile a package-free SDK HTTP/TRX probe in an owned temporary directory, check readiness before locked restore/build/no-build tests, and write results in a fresh UUID report directory. Validate complete expected system discovery against the current reconciled Fact inventory, matching counters/results/method names and refusing failed, skipped, duplicate, missing or malformed results. New Theory expansion is rejected until its discovery contract is explicitly supported. The probe is excluded from application compilation and adds no package dependency/lock.

Both readiness implementations default to a 60-second aggregate budget with 2-second attempts and a bounded response body. An HTTP 200 with an incomplete body cannot hang the Node lane or bypass readiness completion. Missing tools, invalid collection/budgets, failed install/restore/build/tests, and invalid fresh evidence remain failures. The system trap retains stage/exit diagnostics and the primary result across owned temporary-tool cleanup failure.

Compose run/up exit propagation remains with the existing Bash/PowerShell wrappers and COR23Q native helper. Direct/proxy proof results and container system reports are retained under ignored `artifacts/compose-proof/` and uploaded by relevant CI jobs. Per-proof result directories are fresh; this does not repair default shared Compose projects, host publications, credentials or outer lifecycle cleanup. Those remain COR23X/Y/Z/AA/AB; host-backed system identity and full release qualification are separate. No shared-volume reset behavior is expanded in this PR.

Twenty-one focused Python regressions execute actual Node loopback readiness, controlled npm/Bruno commands, actual Bash stage ordering and source mutations. Controlled command reports are not real SDK/Bruno outcomes. Two existing C# HTTP source-contract classes and the existing configuration guard/mutation location follow the extracted runners; C# compilation/execution is pending.

`eng/test-compose-proof.py` authors an actual disposable Linux-container matrix: real direct/proxy/system success; hung readiness; install/collection/restore/build/test failure; and missing fresh TRX. It renders a private unique Compose project, removes host publications in that fixture, generates its own DB/test credentials, and cleans only that project's resources. Missing Docker records NotRun with zero cases. Native tool compilation, real Bruno report compatibility, rendered Compose/exit transport, supported Docker hosts and actual hosted CI remain unqualified here.

See [Compose proof contract](../testing/COMPOSE_PROOF_CONTRACT.md) for commands and scope. No SQL, package graph/locks, migrations, compatibility, other finding/followup or historical evidence changes. All 186 release gates remain Open.

Next: COR23X.
