# COR23AD — deterministic two-factor flow factory disposal

Owner: R10F-01 only. Baseline: completed COR23AC. Status: FixedPendingQualification; actual compiled host/DI cleanup remains NotRun.

Give the private LoginTwoFactorHarness async disposal ownership and scope all fifteen allocations with await using. Share one disposal operation and reject later owner factory access. Preserve twelve direct factory scopes and client/response scope ordering. Close helper JSON before returning detached values/no value, including assertion failure. Dispose successful parallel responses even if another request fails.

Add four actual-host lifecycle Facts in a partial of the existing flow class. A single DI-owned hosted-service probe observes start/stop, stopping/stopped callbacks and exact provider disposal on normal and exceptional exits, with the original exception identity preserved. Cover an unstarted factory and twelve normal/exceptional iterations in one CLR process, including repeated cleanup callers and zero live probe instances. The native runner requires all 31 flow/probe Facts, two full Release executions, fresh complete results and existing Z process cleanup.

Focused Python tooling executes source rejection and synthetic result rejection; it does not qualify C# cleanup. Missing SDK records zero native cases/NotRun; required CI runs the actual host/probe suite. See [account-flow ownership](../testing/ACCOUNT_FLOW_LIFETIMES.md).

Only R10F-01/COR23AD advance. Other 83 findings/31 followups, all 76 protected SQL/lock/original evidence/gate files, production behavior and the shared application factory remain unchanged. Ledger: 82 FixedPendingQualification / 2 Open; all 186 release gates Open. No migration, schema, endpoint, auth or delivery policy change.

Next: COR23AE, prove committed registration verification in the System lane.
