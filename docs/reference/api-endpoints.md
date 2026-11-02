# API endpoints and implementation references

## Public TreeHammock API

Public HTTP routes are implemented in `Controllers/` and registered by the application's `Program.cs` and host configuration. The repository carries a [versioned API endpoint matrix](../release/API_ENDPOINT_MATRIX.md), which is useful as a *source snapshot*. Verify paths, HTTP methods and current request/response schemas against the actual controller attributes before publishing an API contract.

Relevant source areas:

- `Controllers/AccountLoginController.cs`: login and session-related actions, including explicit credential refresh.
- `Controllers/PasswordResetController.cs`: password-reset ceremony.
- `Controllers/AccountTwoFactorController.cs`: two-factor enrollment, selection or validation paths.
- `Controllers/`: registration, profile, recovery and account-related API controllers.
- `Rigging/Authentication/`: authentication/authorization middleware and token handling.

Do not confuse public API routes with SVS's authenticated internal RPC.

## Private Session Validation Service

The private host maps the gRPC method `treehammock.sessionvalidation.v1.SessionValidator/Validate` and operational endpoints `/health/live`, `/health/ready`, `/operations/status` and `/metrics`. Source: `src/Treehammock.SessionValidation.Api/ValidationService.cs`, `SvsHost.cs` and `HealthEndpoints.cs`.

It requires a private transport and authenticated caller admission. The wire format is specified in [the v1 proto](../session-validation/design/contracts/session-validation-v1.proto) and described by the [client/protocol guide](../session-validation/protocol-and-client.md). It is not a user-facing REST authentication endpoint.
