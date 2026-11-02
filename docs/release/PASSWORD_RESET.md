# Password reset: endpoint behavior and security boundaries

This document describes the password-reset contract in the source tree. Implementation presence does not establish native SQL, live messaging-provider, security or production qualification. Verify actual behavior with the current controller, service, repository and integration tests.

| Endpoint | Source contract | Required verification |
| --- | --- | --- |
| `POST /account/password-reset/request` | Accepts identifier and email/SMS channel; uses a generic HTTP 202 response with a fresh opaque public reset ID even for unknown, ineligible or suppressed requests | Routed timing, provider and admission behavior |
| `POST /account/password-reset/verify` | Refuses invalid bootstrap proof without disclosing eligibility; valid proof binds a durable authorization | Durable SQL and replay/concurrency semantics |
| `POST /account/password-reset/twofactor/select` | Selects from eligible factors while preserving identity, expiry, progress and attempt budgets | Concurrent selection and policy changes |
| `POST /account/password-reset/twofactor/verify` | Advances the expected challenge and accounts for invalid attempts without allowing stale proof to affect a later challenge | Real cryptographic, database and cache verification |
| `POST /account/password-reset/finalize` | Rechecks account/session stamp, possession proof, factor policy, expiry and version before password update and authority revocation | Atomic promotion, denial and recovery |

## Invariants

Email bootstrap does not count as a second email proof. Updated factor policy revokes obsolete reset authorizations, and a request made under a different policy must not reuse its predecessor's state. Removing the final extra factor is not an unguarded bypass.

The threshold CAPTCHA continuation uses a bound, expiring, single-use value. Clients resubmit the same identifier and delivery channel along with `captchaToken` and `captchaContinuation`, and the continuation is consumed before external verification. Unknown or corrupt continuation state fails closed. Testing adapters or a queued delivery are not evidence of successful production CAPTCHA, SMTP or SMS delivery.

The reset workflow must not expose account existence through response shape, transport status or optional-factor disclosure. Session authority changes and storage writes must be validated against the real current database schema.

See the [authentication lifecycle](../architecture/authentication-and-session-lifecycle.md), [API endpoint guide](../reference/api-endpoints.md), [endpoint source matrix](API_ENDPOINT_MATRIX.md), and [testing documentation](../testing/README.md).
