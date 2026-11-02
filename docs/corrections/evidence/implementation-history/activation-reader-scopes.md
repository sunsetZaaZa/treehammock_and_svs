# COR23A — activation reader scopes and actual repository qualification

COR23A implements R06-01 against completed COR23. All six ActivationRepo operations now materialize their full result inside a nested asynchronous reader scope; receipt writing and commit occur after that scope closes. This replaces method-level using declarations plus explicit early DisposeAsync added in COR04/COR19/COR21. Read/SQL failure still unwinds reader ownership before existing rollback/reconciliation. Normal false results commit their denial receipt; missing/malformed results cannot become a successful or ordinary denial response.

The two current grant methods also format expected receipt grant versions as invariant text, matching SecurityOperationService.BeginAsync's string contract, while their SQL parameters remain bigint. The previous source passed long directly to that string argument. This local invocation correction is included in the actual repository tests; C# compilation remains unqualified here.

The four legacy functions remain fail-closed with ACTIVATION_TRUSTED_GRANT_REQUIRED. COR23A does not restore caller-selected paid activation, change SQL/schema, alter provider behavior or enable grant-derived premium rights. Current trusted-grant admission, verify/cancel/disable paths are qualified against their current contracts. The pre-1.0 direct setup policy remains unchanged.

## Regression boundaries

`Cor23AActivationReaderTests` declares five native methods and 27 cases after its inline theory rows are expanded:

- Four actual legacy method denials assert materialized results, committed negative receipt and unchanged grant/request state through an independent connection; a repeated call establishes pool reuse.
- Actual production admission asserts committed ticket/budget/receipt, invariant expected version, then false throttle with no extra budget charge.
- Actual production verify/cancel/disable asserts complete lifecycle decoding, independent committed grant/request state, receipt, then controlled stale-version denial.
- Eighteen no-row, null-code decode and SQL-error cases cover all six repository methods. Local disposable-schema function-body injection writes a probe row before failure. Independent observations require zero probe writes and zero success receipts, unchanged grant authority, RolledBack reconciliation and reuse of the single pool slot. This tests provider/result/rollback handling; injected function bodies do not establish domain SQL behavior or authorize a legacy success path.
- A real pinned-Npgsql oracle attempts receipt/commit while a reader remains alive and requires NpgsqlOperationInProgressException, then closes the reader and commits successfully. Moving the production commit inside its reader scope must make the corresponding repository case fail. Run that mutation in a disposable source checkout and retain failing test results; compile failure or a source-only witness is insufficient mutation evidence.

The suite uses the owned COR01 PostgreSQL fixture and production StorageContext/ActivationRepo/SecurityOperationService, with a one-slot pool and an independent nonpooled observer. It substitutes only issuer membership and delivery publication inside its private schema. It does not prove actual issuer ACLs, SMTP/SMS, HTTP authentication/proxy, cache, restart or resource budgets. Existing security-operation scope disposal projects uncommitted failures into RolledBack outcome exceptions; this PR retains that contract rather than treating them as business denial.

`check-activation-reader-scopes.py` checks all six lexical method/scope boundaries. Its seven Python cases reject the R10G commit-inside-reader counterexample, method-level declarations, premature commits and all six individual scope mutations, and check nested/literal braces. This strengthens supplemental scope evidence rather than relying on text order. Native provider and actual-repository cases remain mandatory. CI and the owned sql-harness include the new checks/cases.

## Validation commands

```bash
python3 eng/check-activation-reader-scopes.py
python3 -m unittest discover -s eng/tests -q
python3 eng/cor23-reconciliation.py --check
python3 eng/generate-database-baseline.py --check
python3 eng/check-correction-evidence.py
python3 eng/correction-sql-fixture.py
python3 eng/correction-baseline.py --lane all
```

Native prerequisites are missing here: .NET SDK, PostgreSQL, Docker/cache and PowerShell. The authored native suite and live commit-inside-reader mutation are NotRun/Blocked. Executed Python/structural checks are supplemental; no provider behavior or C# compilation is represented as observed. Delivery validation separates these outcomes.

R06-01 becomes FixedPendingQualification, with append-only history and named cases. The other 82 findings, all 186 Open gates, frozen review/inventory, package/SDK locks, dependency bytes and database setup remain unchanged. Next scoped correction is COR23B. Rollback reverts COR23A repository/guard/test changes; retain prior explicit disposal if doing so, and never restore legacy activation authority.
