# COR23C — durable factor row identities beyond retained smallint history

COR23C implements R06-03 against completed COR23B. The current factor row key and repository readers used smallint/short, while fresh enrollment allocated MAX(history)+1. Retaining index 32767 could permanently prevent new enrollment; removing history could recycle a numeric reference. The original frozen review and functional acceptance remain authoritative, with migration proposals superseded by the pre-1.0 direct setup policy.

## Current identity contract

`two_factor_authentications.two_factor_index` is now a noncycling PostgreSQL bigint identity starting at zero. Both current fresh-enrollment writers omit that column on INSERT and capture the database-generated value with qualified RETURNING. They no longer scan retained history to allocate IDs. Allocation is shared by the owned table, atomic across accounts, and may have gaps after failure/rollback; neither deletion nor transaction rollback resets it. Never treat it as a compact list position or reset its sequence during retention. BY DEFAULT permits explicit owned fixture keys; production enrollment writers never supply a row key. Explicit fixture inserts do not advance the identity sequence; boundary tests either generate real identities or explicitly set their private sequence.

The row slot and enrollment identity have separate meanings. Pending replacement retains its current row slot for CAS and creates a fresh setup/enrollment UUID, incrementing the setup version. Removal retains the retired row and clears abandoned secret material under COR15; later fresh enrollment receives a new row identity and enrollment UUID. COR22 remains the owner of terminal-history retention. Widening is not permission to recycle identities or retain secret material after revocation.

The existing immutable TOTP enrollment UUID remains the v2 AES-GCM associated-data identity and an explicit replay parameter. It is not replaced with the numeric row key. Account/row/enrollment UUID plus verified/unrevoked state must all match for step marking. A retired reference cannot mutate a new enrollment's replay state. Existing envelope/algorithm/key/nonce/tag binding and replay counters are unchanged; saved current v2 envelopes remain decryptable with their original UUID context. This PR adds no legacy format adapter or conversion.

Display ordering continues to use the existing required/priority fields, with numeric row identity only a deterministic tie-breaker. HTTP enrollment contracts continue to expose the enrollment UUID and bounded version, not an editable row identifier. All repository factor identity fields/parameters use long/long?, readers use GetInt64 and replay parameters use NpgsqlDbType.Bigint. Methods, providers, attempt counts, display priority and policy flags retain their short/smallint types.

The current initial table plus ordered setup declarations in stages 001, 002 and 006, their checksums and both generated baselines are updated directly. Eleven final function contracts widen only factor index outputs/parameters. There is no new setup version, ALTER/backfill/dual-reader path, or compatibility strategy. Earlier superseded setup bodies retain coherent bigint contracts; their old unbound mutations are not callable in the completed setup, whose legacy functions still deny. Recreate pre-release development databases from the current setup.

## Consumer review and regression boundaries

`COR23C_IDENTITY_CONSUMERS.json` records every current lexical C#/SQL consumer, line and file hash, along with the eleven widened contracts. It includes production records, login/reset call sites, reader ordinals, replay parameters, allocator/authority code, factor policy/retention references, fixtures and both baselines. The six production C# consumers are AccountRepo, AuthenticatorAppEnrollmentRepo, PasswordResetTotpRepo, AuthenticatorAppProvisioningService, AuthenticatorAppLoginService and PasswordResetTotpService. The last two require no body change because their inferred values flow from the widened records. Existing C# fixtures, service fakes, reflection/schema assertions, SQL reader and COR23B native tests are updated to the current types; method/provider/attempt ordinals are preserved.

The focused source guard rejects narrow schema/records/readers/replay parameters, cycling identity, MAX(history) allocation, explicit fresh row-key insertion, removed UUID replay binding and changed encryption associated data. Nine Python tests exercise these mutations and stale consumer inventory. These are supplemental source checks, not compilation, PostgreSQL catalog inspection, resource measurements or native execution. CI includes the guard and the owned sql-harness includes the native class.

`Cor23CFactorIdentityTests` contains eight native methods and thirteen inline-expanded cases:

- Three cases create 32,768 actual generated retired rows and invoke current email, SMS or authenticator enrollment, requiring index 32768, retained history and the bound request UUID. Authenticator ciphertext is independently read and decrypted.
- Two cases exercise actual authenticator begin/pending/completion/verified readers and the reset reader at 32768 and 4294967296. Production Npgsql/StorageContext and security operations are used. Real completion rotates the session; both actual replay repositories then accept a new step, deny the same step and expose durable replay advancement independently.
- Three cases replace pending email/SMS/TOTP at the boundary, retaining the row slot, changing the enrollment UUID/version and decrypting the new envelope. Saved old v2 material still decrypts under its original context; wrong-enrollment associated data must fail authentication. Replacement goes directly through current SQL because R23B-01/COR23AF still blocks the repository target comparison; these cases do not qualify repository replacement success.
- Rollback burns its generated identity, retry gets a later one, and deletion of owned discarded history does not recycle the committed key.
- Same-account creation is interleaved with the real account lock and observed PostgreSQL blocking, leaving one pending enrollment and a controlled loser conflict. Different accounts create concurrently on separate connections and receive distinct generated keys.
- Actual approved removal retains a revoked row and clears its ciphertext. Fresh re-enrollment gets a new row/UUID; old-row and cross-UUID step markers fail, while the new login/reset paths share only their own replay counter. The verified-row setup in this removal case is a declared fixture substitute; actual promotion has separate production-repository cases above.
- AccountRepo's production setup reader consumes an actual current delivery setup result at 4294967296 using the production NodaTime-enabled connection.

The two existing login/reset verifier unit success cases now carry a value above Int32.MaxValue through the production services and mocked repository boundary. All native and C# unit cases remain NotRun in this environment. Proof attestation is the existing explicit COR16 fixture stand-in, not a claim about password/factor proof service execution. Owned schema substitutes and source audits do not qualify HTTP, external delivery, database deployment roles, Yugabyte runtime parity, cache, recovery or budgets.

## Validation and status

```bash
python3 eng/check-factor-identities.py
python3 eng/check-sql-output-bindings.py
python3 eng/generate-database-baseline.py --check
python3 eng/cor23-reconciliation.py --check
python3 eng/check-correction-evidence.py
python3 -m unittest discover -s eng/tests -q
python3 eng/correction-sql-fixture.py
python3 eng/correction-baseline.py --lane all
```

.NET SDK, PostgreSQL, Docker/cache and PowerShell prerequisites are unavailable. Native compilation, catalog/type/default-setting parity, branch/concurrency/replay execution and real mutation qualification are Blocked/NotRun. Delivery separates executed Python/structural results from authored tests. In an owned source checkout, reverting the identity to smallint must fail the retained-history native case; restoring MAX(history) allocation must fail rollback/deleted-history nonreuse; narrowing each reader must fail the corresponding actual-repository boundary case. Retain executed failing results, not compile-only failures or lexical witnesses.

R06-03 is FixedPendingQualification with append-only history; the other 83 findings (including Open R23B-01) and all 186 Open gates are unchanged. The 83 original findings, frozen reviews and 451-file original inventory remain intact. No finding or release gate is Closed. The next ordered correction is COR23D.
