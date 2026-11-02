# Owned test acquisition and cleanup

Each Docker test entrypoint establishes a private schema-2 manifest and a nonblocking coordinator/recovery lease before copying source, generating credentials, rendering Compose or running a child. Preparation failures retain that identity and run through the same outer cleanup boundary. Docker acquisition is tracked by the owned test harness owner/project/role labels; label inspection remains mandatory before deletion. Developer and sibling resources are preserved.

The coordinator registers a process supervisor receipt before releasing its launch gate. Uncommitted children cannot start acquisition. Host Bash and PowerShell wrappers request their API through an authenticated loopback broker in that coordinator, so the API remains tracked when the wrapper fails, exits or is interrupted. PowerShell establishes its primary-error/environment-restoration `try/finally` before Compose startup. Bash establishes its exit/interrupt traps before startup and retains native test exit codes. API output is drained into capped, generated-secret-redacted host logs; wrapper output is capped at 1 MiB. Owned Docker diagnostic logs request the last 100 lines and retain at most 64 KiB per container; failed diagnostics do not prevent deletion.

Linux supervisors use a child subreaper, namespace-aware process birth identities, and PID handles. Detached descendants stay owned after the immediate child exits. Linux requires PID-handle support; unsupported setup fails before the gated child launches. Windows supervisors assign themselves to a kill-on-close Job Object before creating children. Normal break requests allow shutdown; forced termination uses a birth-checked process handle, and supervisor exit closes the job. Windows execution/ACL/nested-job/break handling remains pending native qualification. Other operating systems currently fail containment setup rather than claiming complete tree cleanup. macOS support and final host selection remain COR23AB work. WSL host mode remains disabled; container lanes need a supported Linux Python runtime.

Process receipts bind a supervisor PID to a Linux boot/namespace/start identity or Windows creation time, plus exact private state/request/gate paths. An absent or reused supervisor without a committed stopped receipt is reported as incomplete process cleanup. It never authorizes signaling an unrelated PID. An exited API supervisor stays alive to retain ownership of SDK grandchildren until cleanup. An unexplained externally killed Linux supervisor can leave orphan descendants; recovery reports failure instead of inferring that they are gone or killing them by guessed names/PIDs.

## Budgets and outcomes

`TREEHAMMOCK_TEST_CLEANUP_TIMEOUT_SECONDS` sets one monotonic teardown budget, default 45 seconds, accepted range 1–120. Supervisor shutdown and every Docker inventory/inspect/log/removal consume that same budget. Each Docker command is additionally capped; logs get a short subordinate allowance. Budget exhaustion fails cleanup. Process cleanup precedes Docker resource deletion. The coordinator holds the fixed-port host lease until cleanup completes, then releases both leases and restores signal handlers. Host wrapper environment restoration runs even if API stop fails.

The initiating failure or interrupt code is retained independently of process/Docker/diagnostic failures. Teardown or outcome-write failure makes an otherwise successful run nonzero. `run.json` is a runner outcome, not discovery qualification. SIGINT/SIGTERM normally produce 130/143. Force-kill of the coordinator cannot execute its finally block; explicit recovery or exact-job CI recovery is required.

For deliberate debugging, set `TREEHAMMOCK_TEST_RETAIN_FAILED_RESOURCES=true`. Only a failed run can retain labeled Docker resources; processes are still stopped. Its manifest/outcome says `RetainedDebug`, never successful cleanup. Private snapshots and credentials remain ignored diagnostic inputs in every mode, independent of live Docker retention. Do not upload `.docker`.

## Abandoned recovery

Use the printed UUID and the original source checkout:

```bash
python3 eng/test-ownership.py recover --run <UUID>
# Only when deliberately discarding retained debug resources:
python3 eng/test-ownership.py recover --run <UUID> --discard-retained
```

Recovery accepts only a canonical UUID and the exact private current-schema manifest beneath that source checkout. It takes a nonblocking run lease, refuses an active coordinator, and checks recorded process birth and owned receipt paths. It applies the same shared budget and label-verified Docker cleanup. Repeating successful recovery is harmless. `recovery.json` records its outcome separately from the initiating `run.json`; recovery cannot retroactively make a failed test pass. Old schemas, missing identities, foreign roots, linked paths, active locks and ambiguous process loss fail closed. No compatibility conversion, project guessing or global cleanup is provided.

`cleanup-ci` uses this same recovery path for the exact current GitHub repository/run/attempt/job or GitLab project/pipeline/job identity. A GitLab after-script status alone does not close a release gate. Do not reuse a private checkout with a different daemon/PID namespace and assume its process receipts identify that host.

## Validation

```bash
python3 eng/check-test-lifecycle.py
python3 -m unittest discover -s eng/tests -p test_test_lifecycle.py -v
python3 eng/test-test-lifecycle.py --output .correction-results/cor23z-lifecycle.json
python3 eng/test-powershell-runners.py --host pwsh
```

Tooling runs actual Python/Bash processes, private files, locks, sockets, gated registration, detached descendants, host acquisition failures, cancellation and exact recovery against a controlled Docker adapter. This is not Docker/.NET qualification. The native lifecycle tool separately authors real partial Compose acquisition and a compiled SDK parent/application-child tree. Missing real Docker/SDK/Bash records zero cases/NotRun. Successful local cases remain Partial until the supported Windows/PowerShell/Desktop/application and interruption/restart matrix completes. The [host test evidence guide](README.md) covers direct DLL/loaded identity, endpoint monitoring and complete results. The [host prerequisites](HOST_PREREQUISITES.md) cover supported executable selection and platform preflight. Native host and integrated release qualification remain pending. All release gates stay Open.

Primary process contracts: [Linux child subreaper](https://man7.org/linux/man-pages/man2/PR_SET_CHILD_SUBREAPER.2const.html), [Windows Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects), [Python subprocess](https://docs.python.org/3/library/subprocess.html).
