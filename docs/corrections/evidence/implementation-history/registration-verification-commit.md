# COR23AE — prove committed registration verification

Owner: R10H-01 only. Baseline: completed COR23AD. Status: FixedPendingQualification; actual HTTP and full SQL/proxy System execution remain NotRun.

The dedicated registration System case first requires HTTP 200, text/html and the exact controlled success template. It then performs ordinary password login, requires a nonempty active token and reads the protected account profile. The response must identify the same unique email, report ACCOUNT_VIEW_SUCCEEDED and expose SUCCESSFUL verification from the database-backed account repository. These independent authorized operations prevent a rendered success page from substituting for committed account state.

The shared registration helper owns every response/document, retries only the exact pending-publication page within its existing deadline and otherwise requires the successful HTML contract. It creates no hidden login/session, preserving unlock and other callers. A shared test-only assertion compiles into both test projects, checks missing/wrong content type and full template equality, and fails if the controlled template is unavailable rather than accepting a marker or fallback.

Ten actual Program/MVC HTTP/assertion Facts cover valid success, intended-account-only commit, invalid and expired tokens, rejected or unavailable completion, unavailable lookup, legitimate already-verified output, a successful marker embedded in failure HTML, wrong content type and missing content type. An isolated in-memory repository fixture independently retains account statuses and returns detached proof records. Rejected/unavailable completion leaves verification SENT; expiration becomes EXPIRED, not SUCCESSFUL; already-verified does not perform another completion. This fixture is not a SQL observer. The System login/protected profile path supplies the separate real durable-state proof.

The native Release runner requires all ten Facts with fresh exact TRX and existing COR23Z process containment. Required CI runs it; the existing complete host/System lane includes the corrected registration Fact, with COR23AA loaded assembly/process/endpoint/result proof. Python source mutations and synthetic TRX checks do not qualify CLR, SQL or proxy behavior. See [verification qualification](../testing/REGISTRATION_VERIFICATION.md).

Only R10H-01/COR23AE advance. Other 83 findings/31 followups and all 76 protected SQL/lock/original evidence/gate files remain unchanged. Ledger: 83 FixedPendingQualification / 1 Open; all 186 release gates Open. Production controllers, HTML templates, repository behavior, shared application factory and package graph remain unchanged. No schema, endpoint, migration or legacy compatibility change.

Next: COR23AF, bind authenticator replacement grants to predecessor identity/version in the repository.
