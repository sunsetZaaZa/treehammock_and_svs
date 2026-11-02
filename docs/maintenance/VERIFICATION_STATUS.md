# Verification status and open qualifications

## Verified from the packaged development source

Rechecked on November 2, 2026, from the same source bytes as the previous verified working archive, plus documentation-only handoff updates:

| Check | Observed result |
| --- | --- |
| Main Visual Studio solution | 19 C# projects, including 17 SessionValidation projects, in 5 solution folders |
| SQL-contract solution | 2 projects |
| Relative project assets | 43 resolved |
| Relative Markdown links before handoff docs | 116 resolved, 0 unresolved |
| Explicit CI file paths | 53 resolved |
| Python source layout tests | 3 passed |
| Python build configuration tests | 45 passed |
| Python authenticator tests | 22 passed |
| Python cross-feature qualification-tool tests | 28 passed |
| ZIP integrity | original and finished archives checked |

The focused checks comprise 98 passing Python tests. They are not native database, production mTLS, or deployed security qualification.

## Work that remains open

The broader per-module Python sweep from the previous verification phase evaluated 47 modules: 33 passing, 8 failing, and 6 timing out (a 22-second per-module cap). The eight failing modules are `test_correction_collector.py`, `test_correction_evidence.py`, `test_correction_migrations.py`, `test_correction_reconciliation.py`, `test_factor_identities.py`, `test_smtp_transport.py`, `test_sql_output_bindings.py`, and `test_verification_origins.py`. The six timed-out modules were `test_compose_proof.py`, `test_host_system_proof.py`, `test_release_artifacts.py`, `test_release_input_boundary.py`, `test_test_lifecycle.py`, and `test_test_ownership.py`.

Some failures reflect immutable history/reference-path expectations and older pinned source inputs; these are *not* accepted as passing checks. The SessionValidation source policy checker reports `TEST_LOCK_HISTORY` on both this lineage and its unchanged previous baseline. The historic source pin records were not modified or reapproved.

A full .NET restore/build/test and the complete uncapped Python tests were not executed in this packaging phase. Live Yugabyte/Dragonfly qualification, private TLS trust and rotation checks, host failover, extended performance/soak tests, and independent security/production authorization remain **not run / not approved**.

## Repeatable local checks

From `treehammock/`:

```sh
python3 eng/verify-source-layout.py
python3 eng/check-build-configuration.py
python3 -m unittest discover -s eng/tests -p 'test_source_layout.py' -q
python3 -m unittest discover -s eng/tests -p 'test_build_configuration.py' -q
python3 -m unittest discover -s eng/tests -p 'test_authenticator_replacement.py' -q
python3 -m unittest discover -s eng/tests -p 'test_cross_feature_qualification.py' -q
```

Install the pinned .NET 10 SDK and a compatible Visual Studio, then perform the documented locked restore, build, and selective test/qualification workflows on the target platforms. A static project-registration check does not establish that all projects compile or pass native tests.
