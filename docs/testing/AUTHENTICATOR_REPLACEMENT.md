# Authenticator replacement qualification

The canonical setup target includes normalized label, required flag, provider, expected predecessor enrollment UUID and expected version. The controller, provisioning service and repository must use the same typed helper with all five values. A fresh setup uses null/null; a replacement uses the live predecessor and version. Grant presence and SQL authority/consumption checks remain mandatory.

## Actual repository and service cases

`Cor23AFAuthenticatorReplacementTests` has six methods and eighteen executions. The native fixture uses an isolated schema, default PostgreSQL variable_conflict=error and the actual production repository/security-operation service. Provisioning service cases use the real local RFC6238 provider and v2 secret protector. The test fixture grant seeder explicitly substitutes completed password/factor attestation; real target hashing and PostgreSQL grant validation/consumption are exercised. This is not full HTTP/password/provider qualification.

A separate observer connection checks fresh insert and committed replacement, including the preserved row slot, new setup/enrollment UUID, incremented version, token hash, encrypted secret version/key and stored algorithm/digits/period/skew. Rebuild associated-data context from persisted columns and decrypt the envelope, comparing to the input secret or service manual key. Observe actual grant consumption. Thirteen denial variants cover stale ID/version, target for another predecessor, changed label/required/provider, missing grant, wrong stamp/session/account/purpose/token/target hash. Compare the complete original enrollment row JSON and unconsumed grant after denial. Verified-enrollment protection preserves the original row and the existing authorized-grant consumption behavior.

All connections and storage scopes are owned; the fixture disposes its schema and outstanding work on failure. Production SQL, helper/controller/service target shape and reader conversions remain unchanged. The local logging stage parameter correction makes the touched repository's existing failure paths well-defined.

```bash
python3 eng/check-authenticator-replacement.py
python3 -m unittest discover -s eng/tests -p test_authenticator_replacement.py -v
bash eng/correction-sql-fixture.sh --cache-product redis --authenticator-replacement
bash eng/correction-sql-fixture.sh --cache-product dragonfly --authenticator-replacement
```

The existing owned fixture checks local Docker prerequisites, creates a unique PostgreSQL/cache project with private credentials, publishes loopback ports, records immutable image identities and tears down only that project. The Release native runner uses its explicit disposable PostgreSQL environment; it never selects an external database automatically. Alternate build configurations are rejected for this qualification mode.

The runner restores locked packages in a fresh private checkout, executes all eighteen cases, then changes only the repository's canonical comparison to the former three-argument call. Build and execute the designated `Actual_repository_replacement_with_predecessor_bound_grant_commits` Fact. Require one real failed Shouldly assertion in that method's async fixture body, exact test identity/counters and fresh TRX; missing results or compile errors are failures, not a passed negative control. Restore private source in finally and execute the complete current suite again. The test-run process containment applies 900-second stage and 15-second cleanup bounds; the outer SQL fixture retains its own acquisition/stage/teardown limits.

Publish native full/current, mutation and restored TRX hashes, exact method/theory discovery and immutable PostgreSQL image identity, plus the fixture outcome and cleanup. Passing repository and service tests are only partial evidence pending integrated native qualification. Missing SDK, disposable database or Docker prerequisite is NotRun/Blocked with zero executed cases. Source mutation checks and synthetic receipts are only tooling tests and cannot close native qualification findings.

Here the SDK and Docker are absent. Native repository/service/SQL cases and the mutation remain NotRun. All 186 release gates remain Open; no runtime pass, capacity/provider claim, schema migration or legacy fallback is implied.
