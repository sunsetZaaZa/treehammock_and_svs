# Testing and qualification

## Test levels

| Level | What it establishes | What it does not establish |
| --- | --- | --- |
| Static inventory and policy checks | Tracked source/configuration invariants, file presence, known consistency rules | Build success, live database/cache correctness |
| .NET unit/contract/host tests | Function, parser, client, evaluator and local service behavior under tested conditions | Real Yugabyte/Dragonfly, physical fleet or production permission acceptance |
| Disposable stack | Tests against locally provisioned services within its declared isolation | Production topology, capacity or long-running failures |
| Native physical qualification | Actual database/cache, host, network and failure behavior on target infrastructure | Independent release approval unless its evidence is reviewed |
| Independent review | Signed/approved security and operations acceptance based on authentic evidence | An automatic consequence of successful test runs |

## Tooling entry points

- `eng/session-validation/restore-build-test.sh`: shared restore/build/test launcher.
- `eng/session-validation/validate-core.py`, `validate-rpc.py`, `validate-cache.py` and other `validate-*.py`: scoped source/contract checks. Review the command and its dependencies before running it.
- `eng/session-validation/run-disposable-stack.sh`: isolated stack runner.
- `eng/session-validation/qualification/README.md`: benchmark, load, soak and failure qualification instructions.
- `eng/session-validation/release/README.md`: the independent release reviewer, evidence requirements and blocked states.
- `docs/testing/README.md`: public TreeHammock test commands and prerequisites.

Do not run potentially destructive or production-impacting site adapters without reviewing their explicit ownership and isolated-staging constraints. Never supply production credentials to sample configurations.

## Required qualification areas

- Real SQL privilege isolation and cancellation on the selected Yugabyte/YSQL baseline.
- Real Dragonfly cache miss/hit/expiry, admission transitions and publication fencing.
- Writer concurrent login/refresh/revocation under controlled multi-replica schedules.
- mTLS caller identity, certificate rotation, network loss and protocol refusal.
- Load/capacity limits, failover, target host permissions, observation integrity and a sustained soak (where required by release policy).
- Independent native and security adjudication based on actual proof, not synthetic tests.

The current source-pins file and inherited reports do **not** mark native acceptance or production release as complete. See [current verification](current-verification.md).
