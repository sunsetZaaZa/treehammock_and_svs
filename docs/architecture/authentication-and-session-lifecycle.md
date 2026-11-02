# Authentication and session lifecycle

TreeHammock is the **writer** for account and session authority; SVS is a **reader and validator** of already-issued authority. Do not give SVS signing credentials or general database write access to simplify deployment.

## Public authentication

The public application implements registration, verification, login, two-factor authentication and password recovery through its controllers and services. `Rigging/Authentication/` contains shared authentication middleware and JWT logic. The application's database and cache settings, issuer, signing-key configuration and enabled credentials determine the actual runtime behavior; inspect these before deploying.

Access credentials are signed JWTs. The current public source includes an explicit `POST /account/refresh` flow with a separate opaque refresh credential. An ordinary authenticated request is not a refresh operation. Logging out, resetting a password or changing protected account state affects the authority against which subsequent access requests are checked.

Session-family behavior and credential validity depend on the durable account/session state, including expiry and generation or security-stamp boundaries. Cache presence is not independent authority. Application-specific access control remains the consuming API's responsibility.

## Private validation

For an internal call, a backend client uses the typed `Treehammock.SessionValidation.Client` library to contact SVS over private, mutually authenticated HTTP/2. SVS checks caller identity and the requested action, parses the strict validation contract, evaluates current session evidence and returns a bounded result. The implementation distinguishes active, unauthenticated, forbidden and unavailable outcomes; only an active decision supplies a validated subject.

Relevant implementation:

- `Controllers/AccountLoginController.cs`, `Controllers/` and `Repos/SessionRepo.cs`
- `src/Treehammock.SessionValidation.Api/ValidationService.cs`
- `src/Treehammock.SessionValidation.Client/SessionValidatorClient.cs`
- `src/Treehammock.SessionValidation.Core/SessionDecision.cs`
- `src/Treehammock.SessionValidation.Storage/SessionEvidenceCoordinator.cs`

Read the [wire contract and client guide](../session-validation/protocol-and-client.md) and [cache/revocation guide](../session-validation/cache-consistency.md) for the guarantees and failure cases.

## Recovery and operational checks

Password reset and factor flows must preserve non-enumerating public behavior and durable authorization boundaries. The versioned [password reset reference](../release/PASSWORD_RESET.md) is a historical contract snapshot; verify the current controller and service implementations before relying on individual field names. Releasing or restoring validation capacity after outages must not create fresh authority or bypass active session revocation.
