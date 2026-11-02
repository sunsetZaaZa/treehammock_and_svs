# API route and source index

This reference indexes the application's literal controller routes and the explicit security-operation status middleware route. It identifies source entry points; it does not prove effective authentication, capability checks, response envelopes or runtime qualification. Three system-test controllers are available only behind the validated Testing inspection capability and must not be exposed in production.

The source index is maintained by the repository's reconciliation utility. Before publishing, compare it with the actual ASP.NET Core route descriptor set and exercise permitted and denied request paths against native dependencies. A `NotRun` entry is a qualification status, not a claim that an endpoint is absent.

| Method | Route | Source | Action | Qualification |
|---|---|---|---|---|
| POST | `/__system-test/accounts/verified` | `Controllers/SystemTestAccountController.cs` | SeedVerified | NotRun |
| DELETE | `/__system-test/deliveries` | `Controllers/SystemTestDeliveryController.cs` | Clear | NotRun |
| GET | `/__system-test/deliveries/latest` | `Controllers/SystemTestDeliveryController.cs` | Latest | NotRun |
| GET | `/__system-test/identity` | `Controllers/SystemTestIdentityController.cs` | Current | NotRun |
| POST | `/account/adjust` | `Controllers/AccountProfileController.cs` | ModifyAccount | NotRun |
| GET | `/account/adjust/email/verify` | `Controllers/AccountProfileController.cs` | VerifyEmailChange | NotRun |
| POST | `/account/adjust/email/verify` | `Controllers/AccountProfileController.cs` | ConfirmEmailChange | NotRun |
| POST | `/account/logoff` | `Controllers/AccountSessionController.cs` | LogoffAccount | NotRun |
| POST | `/account/logoff/all` | `Controllers/AccountSessionController.cs` | LogoffAllAccount | NotRun |
| POST | `/account/password-reset/finalize` | `Controllers/PasswordResetController.cs` | FinalizeReset | NotRun |
| POST | `/account/password-reset/request` | `Controllers/PasswordResetController.cs` | RequestReset | NotRun |
| POST | `/account/password-reset/twofactor/select` | `Controllers/PasswordResetController.cs` | SelectTwoFactorConfiguration | NotRun |
| POST | `/account/password-reset/twofactor/verify` | `Controllers/PasswordResetController.cs` | VerifyTwoFactorProof | NotRun |
| POST | `/account/password-reset/verify` | `Controllers/PasswordResetController.cs` | VerifyResetToken | NotRun |
| POST | `/account/reauthenticate` | `Controllers/AccountSessionController.cs` | Reauthenticate | NotRun |
| POST | `/account/reauthenticate/factor` | `Controllers/AccountSessionController.cs` | CompleteSensitiveFactorProof | NotRun |
| POST | `/account/refresh` | `Controllers/AccountSessionController.cs` | Refresh | NotRun |
| POST | `/account/requestaccess` | `Controllers/AccountLoginController.cs` | Authenticate | NotRun |
| GET | `/account/security-operations/status` | `Rigging/Operations/SecurityOperationMiddleware.cs` | SecurityOperationMiddleware.InvokeAsync | NotRun |
| GET | `/account/sessions` | `Controllers/AccountSessionController.cs` | ListActiveSessions | NotRun |
| POST | `/account/sessions/revoke` | `Controllers/AccountSessionController.cs` | RevokeSession | NotRun |
| POST | `/account/setupaccount` | `Controllers/AccountRegistrationController.cs` | AccountSetup | NotRun |
| POST | `/account/setuptwofactormethod` | `Controllers/AccountTwoFactorController.cs` | SetupTwoFactorMethod | NotRun |
| POST | `/account/twofactor/authenticator/cancel` | `Controllers/AccountTwoFactorController.cs` | CancelAuthenticatorAppSetup | NotRun |
| POST | `/account/twofactor/authenticator/setup` | `Controllers/AccountTwoFactorController.cs` | StartAuthenticatorAppSetup | NotRun |
| POST | `/account/twofactor/authenticator/verify` | `Controllers/AccountTwoFactorController.cs` | VerifyAuthenticatorAppSetup | NotRun |
| POST | `/account/twofactor/method/remove` | `Controllers/AccountTwoFactorController.cs` | RemoveTwoFactorMethod | NotRun |
| POST | `/account/twofactor/select` | `Controllers/AccountTwoFactorController.cs` | SelectTwoFactorConfiguration | NotRun |
| POST | `/account/twofactorauth` | `Controllers/AccountTwoFactorController.cs` | TwoFactorAuthenticate | NotRun |
| POST | `/account/unlock/start` | `Controllers/AccountRecoveryController.cs` | StartRecovery | NotRun |
| POST | `/account/unlock/verify` | `Controllers/AccountRecoveryController.cs` | VerifyRecovery | NotRun |
| GET | `/account/verifyaccount` | `Controllers/AccountRegistrationController.cs` | VerifyAccountCreation | NotRun |
| POST | `/account/verifyaccount/resend` | `Controllers/AccountRegistrationController.cs` | ResendAccountVerification | NotRun |
| POST | `/account/verifytwofactormethod` | `Controllers/AccountTwoFactorController.cs` | VerifyTwoFactorMethod | NotRun |
| GET | `/account/view` | `Controllers/AccountProfileController.cs` | ViewAccount | NotRun |
| POST | `/account/wipeout` | `Controllers/AccountDeleteController.cs` | DeleteAccount | NotRun |
| POST | `/account/wipeout/finalize` | `Controllers/AccountDeleteController.cs` | FinalizeDeleteAccount | NotRun |
| GET | `/account/wipeout/verify` | `Controllers/AccountDeleteController.cs` | DeleteAccountConfirmation | NotRun |
| POST | `/account/wipeout/verify` | `Controllers/AccountDeleteController.cs` | VerifyDeleteAccount | NotRun |
| POST | `/activations/cancel` | `Controllers/ActivationsController.cs` | CancelActivation | NotRun |
| POST | `/activations/disable` | `Controllers/ActivationsController.cs` | DisableActivation | NotRun |
| POST | `/activations/place` | `Controllers/ActivationsController.cs` | PlaceActivation | NotRun |
| POST | `/activations/verify` | `Controllers/ActivationsController.cs` | VerifyActivation | NotRun |
| GET | `/health/dependencies` | `Controllers/HealthController.cs` | Dependencies | NotRun |
| GET | `/health/live` | `Controllers/HealthController.cs` | Live | NotRun |
| GET | `/health/ready` | `Controllers/HealthController.cs` | Ready | NotRun |
