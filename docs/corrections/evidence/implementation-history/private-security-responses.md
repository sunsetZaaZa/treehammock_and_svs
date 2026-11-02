# COR23E implementation — private security responses

Owns R07-02 only; builds on completed COR23D. Qualification is NotRun. There is no database/setup, package/SDK, backfill or compatibility change. R07-03/COR23F remains Open and is an explicit qualification dependency.

## Response contract

`SecurityResponseCacheMiddleware` establishes privacy headers before forwarded headers, redirects, compression, decoding, security-operation handling, dependency errors, authentication and controllers. Every application response defaults to:

```http
Cache-Control: no-store
Pragma: no-cache
Expires: Thu, 01 Jan 1970 00:00:00 GMT
```

This includes account/session success, proof pages and JSON, refreshed credentials, anonymous routes supplied with credentials, authentication/authorization/validation denials, dependency outages, operation errors, unexpected failures, redirects, 404 and 405 responses. Neither bearer nor legacy AccessToken credentials are cache keys that can substitute for this policy. No current production route opts into public caching. Future exceptions require an explicit reviewed opt-in with independent cache tests; a downstream public/max-age header or cache attribute cannot bypass the current policy.

Headers are applied before downstream work. An early OnStarting callback reasserts them immediately before transmission, after downstream callbacks. Unsent responses are also reasserted on unwind. Credential protocol header writing and the refresh action apply the same policy directly as defense for action/protocol callers outside the full host.

A shared `HttpExceptionFallbackMiddleware` inside the cache policy ensures that unhandled failures before response start produce a sanitized failure envelope with no-store. It preserves a BadHttpRequestException's HTTP status with HTTP_REQUEST_FAILED; other unexpected failures return 500/INTERNAL_SERVER_ERROR. It clears unsent partial headers and logs only exception type, without the exception, message, body, path, query or credentials. Caller cancellation propagates. Started response failures propagate for server abort; their already committed privacy headers remain intact.

This is the shared privacy foundation coordinated with COR23F. It does not claim the precise compressed-body classification, unsupported/multiple encoding policy, encoded/expanded/chunked limits or CPU/memory/latency budgets that COR23F still owns. Existing inner dependency and security-operation error contracts remain authoritative. COR23E cannot complete runtime qualification until the coordinated protocol boundary is qualified.

## Authored regression evidence

Eleven new native methods expand to 27 cases, all NotRun:

- `Cor23ENoStoreHttpTests`: actual Program pipeline, middleware, authorization, controllers and serializers with explicit cache/repository/JWT authority substitutes. Covers profile and sessions success with bearer/legacy credentials and session-family headers; missing/invalid credentials and clear-token hash; ordinary malformed JSON and refresh preconditions; anonymous proof HTML with credentials; actual dependency and unexpected authentication failures; unknown routes, method denials and security-operation missing-key errors.
- `Cor23EKestrelCacheTests`: owned loopback Kestrel origin and caching intermediary using the framework HTTP ResponseCaching implementation. Actual controllers and authentication run with declared cache/repository/JWT substitutes. A credential-free fixture branch explicitly returns public/max-age and must be served from cache after one origin visit. This control is test-only; there is no production public opt-in.
- The intermediary matrix covers profile, sessions, proof HTML and a deliberate downstream public cache-header overwrite, each with bearer and legacy transport. Two accounts, an unauthenticated caller and a repeated first caller must reach the origin on every request, with no reused body, session-family, clear-token-hash or AppStatus headers. The same routes also run directly. Forwarded metadata is accepted only from the owned loopback proxy.
- An executable fixture mutation omits only the host cache policy and demonstrates legacy cross-account body/session-family reuse after the deliberate downstream public overwrite. Both the mutation and its positive controls remain NotRun; this is not claimed failing runtime evidence.
- `Cor23EResponsePolicyTests`: unsent error clear/rewrite, preserved HTTP 413 versus unexpected 500, private exception text excluded from logs/response, caller cancellation propagation and started-response abort propagation.

The existing mandatory `Cor09RefreshHttpTests.Concurrent_routed_refresh_after_two_validations_has_one_winner_in_both_response_orders` additionally asserts no-store for the actual native PostgreSQL rotation winner/conflict and stale/current credential probes in both response orders (two existing cases). This fixture uses actual refresh controller/service/repositories/JWS verification with declared cache substitutions and owned schema storage; it does not qualify password/factor proofs or external deployment. Its source now composes the same early privacy/fallback boundary. Actual refreshed credentials and generation headers continue to be checked by the original regression.

Seven supplemental Python source mutation cases guard no-store instead of no-cache, middleware order, final callback enforcement, direct credential-header protection, sanitized exception logging and cancellation propagation. These are source witnesses, not C# execution or native cache evidence.

## Validation and status

```bash
python3 eng/check-security-response-cache.py
python3 eng/check-system-test-isolation.py
python3 eng/check-factor-identities.py
python3 eng/check-sql-output-bindings.py
python3 eng/generate-database-baseline.py --check
python3 eng/cor23-reconciliation.py --check
python3 eng/check-correction-evidence.py
python3 -m unittest discover -s eng/tests -q
python3 eng/correction-baseline.py --lane all
python3 eng/correction-sql-fixture.py
```

The environment has no .NET SDK, PostgreSQL, Docker/cache or PowerShell. Native compilation, real Kestrel/intermediary execution, actual database refresh, cancellation/abort and native mutation qualification remain Blocked/NotRun. Run and retain the positive cache-control hit and policy-disabled fixture mutation, as well as actual Program and PostgreSQL results. Removing the final OnStarting policy must fail the late public-header overwrite; moving policy after authentication must fail pre-auth failures; removing the policy must fail wire-header coverage. Compile failures and lexical witnesses cannot qualify these oracles.

Original evidence, the 451-file frozen inventory and all 186 Open gates are preserved. R07-02 is FixedPendingQualification with appended history. Other 83 findings, including R07-03/COR23F, are unchanged; no finding or gate is Closed. Next ordered correction: COR23F.

Framework behavior reference: https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.http.httpresponse.onstarting and https://learn.microsoft.com/en-us/aspnet/core/performance/caching/middleware . The locked project targets .NET 8; execution against that target remains required.
