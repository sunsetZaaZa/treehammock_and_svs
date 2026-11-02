# COR23B — qualify replacement predicates under default PostgreSQL binding

COR23B implements R06-02 against the completed COR23A source. The surviving defect is in `cor08_authorized_begin_authenticator_app_setup`: its replacement UPDATE used bare `two_factor_index`, also a TABLE output variable. Under PostgreSQL's default `plpgsql.variable_conflict=error`, compiling that branch can raise ambiguity and the broad handler maps it to AUTHENTICATOR_SETUP_FAILED. The fresh INSERT branch does not establish replacement correctness.

The UPDATE now declares table alias `t` and qualifies account_id, two_factor_index, verified and revoked_at in its predicate. SET assignment targets retain PostgreSQL's unqualified assignment syntax. Parameters, TABLE outputs, pending/live/account conditions, statuses, grant consumption and CAS behavior are unchanged. The current setup source, its checksum and both generated baselines are updated directly. No script/version, rollout, backfill or compatibility layer is added under the pre-1.0 policy.

The original `begin_authenticator_app_setup` and `disable_activation` entry points now only deny under COR08/COR19. Their obsolete mutating branches are not restored. The current trusted-grant activation transition already qualifies its potentially colliding references. Native regressions assert the legacy denials and exercise the current disable contract, including absence of a pending request. Old caller-selected activation authority remains denied.

## Other TABLE-returning function inspection

`COR23B_SQL_BINDINGS.json` deterministically indexes all 170 current canonical definitions, their output names and definition hashes. Its conservative semicolon/predicate-tail search leaves 11 candidates in ten functions:

| Functions | Bare output token and inspected position | Disposition |
|---|---|---|
| cor08_record_login_failure, cor08_clear_login_attempts | attempt_version, ON CONFLICT SET assignment target | Column assignment grammar; no replacement predicate changed |
| logout_current_session, revoke_session_for_account, revoke_pending_password_reset_sessions_for_account | code, INSERT column list later in the same PL/pgSQL statement | Column-list grammar; not an expression binding |
| list_active_sessions | is_current, explicit SELECT alias and ORDER BY alias | Alias scope requires native execution; retained |
| cancel_unlock_account | status, UPDATE SET assignment target | Column assignment grammar; not the old activation WHERE expression |
| get_pending_password_reset_session | account_id, JOIN USING column list | Join column-list grammar; native branch coverage remains required |
| cor12_claim_delivery | state, UPDATE SET assignment target | Column assignment grammar; retained |
| cor21_admit_creation | admission_id, ON CONFLICT SET assignment target | Column assignment grammar; retained |

This inspection is a focused source assessment, not a full SQL parser, universal binding proof or completion of original source gates. Other variables, SELECT expressions, dynamic SQL and native branch binding remain outside the lexical search. The guard rejects the known bare predicate, weakened verified/revoked conditions, missing alias, conflict preference overrides and restored legacy mutations; audit drift requires an intentional refresh. Nine Python mutation/rejection tests exercise these checks. CI includes the source guard; the owned sql-harness selector includes the native class.

## Native regressions and limits

`Cor23BSqlBindingTests` has seven native methods and 27 inline-expanded cases. Every owned schema case asserts SHOW plpgsql.variable_conflict is `error`; it does not configure use_column/use_variable. Typed Npgsql parameters invoke actual current SQL. Real enrollment-bound v2 AES-GCM envelopes are persisted, read independently and decrypted using the intended account/enrollment/parameters.

- Fresh INSERT checks exact pending status, index, expiry, committed material and consumed grant.
- Pending email, SMS and authenticator replacements keep the selected index, advance setup version, replace request/token/secret material and clear obsolete contacts.
- Ten invalid replacement cases check exact codes and byte-for-byte JSON state retention: provider, token, expiry, secret, predecessor, version, stamp, target, purpose and missing grant. CAS exception paths also require rolled-back grant consumption; ordinary validation denials may consume the admitted grant under the existing contract.
- Verified authenticator material is retained on already-attached denial.
- A private-schema zero-row trigger yields CONFLICT with no replacement/consumption, then succeeds after removal. A separate private-schema mutation reinstates bare two_factor_index, requires FAILED with retained state under default binding, then restores the original definition and retries successfully with the same grant. These are executable oracles, currently NotRun, not claimed mutation results.
- Legacy setup and activation disable deny with no factor/activation mutations for absent and pending email/SMS/authenticator states.
- Current trusted-grant disable covers absent, pending and expired request states plus stale version, wrong stamp and revoked grant denials. Independent observations assert committed revocation/version and unchanged grant state on denial. Request insertion and issuer membership are declared private-schema fixtures; admission/publication/issuer ACLs are qualified elsewhere.

Proof attestation uses the existing COR16 fixture as a stand-in for completed password/factor proof. Tests bypass the repository to establish SQL branches: inspection discovered R23B-01, assigned to COR23AF, where the repository omits predecessor identity/version from its canonical grant target comparison. These SQL tests cannot qualify HTTP, service/repository replacement success, deployment issuer ACLs, external delivery, cache, recovery or budgets. The repository defect is recorded with current source hashes and a scoped specification in `COR23B_ADDITIONAL_REVIEW.md`; original review bytes and ownership are preserved.

## Validation

```bash
python3 eng/check-sql-output-bindings.py
python3 eng/generate-database-baseline.py --check
python3 eng/check-activation-reader-scopes.py
python3 eng/cor23-reconciliation.py --check
python3 eng/check-correction-evidence.py
python3 -m unittest discover -s eng/tests -q
python3 eng/correction-sql-fixture.py
python3 eng/correction-baseline.py --lane all
```

.NET SDK, PostgreSQL, Docker/cache and PowerShell prerequisites are unavailable here. C# compilation, default-setting branch execution and native mutation qualification remain Blocked/NotRun. Tooling/structural passes do not waive them. R06-02 is FixedPendingQualification with append-only history and named methods; R23B-01 is Open. All 83 original findings, the 451-file frozen inventory and all 186 Open gates are retained. No finding or release gate is closed. Next ordered correction is COR23C; COR23AF remains a separately scoped repository follow-up.
