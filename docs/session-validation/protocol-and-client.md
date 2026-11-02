# Private validation protocol and client

## Contract

The validation protocol source is [`design/contracts/session-validation-v1.proto`](design/contracts/session-validation-v1.proto). Generated bindings and strict decoders live in `src/Treehammock.SessionValidation.Contracts/`. The host maps the unary gRPC method `treehammock.sessionvalidation.v1.SessionValidator/Validate`, as shown in `Api/ValidationService.cs`.

The host validates raw serialized input before generated protobuf parsing is allowed to collapse duplicate or unknown fields. Validation includes caller identity/action, credential shape, finite deadlines and reply bounds. A client-sent absolute deadline metadata ceiling (`svs-deadline-unix-ms`) may reduce, never extend, the effective request budget.

## Transport and trust

- Private HTTP/2 with authenticated TLS is required. `Api/SvsHost.cs` configures the listener; `Api/HostSettings.cs` rejects public/wildcard listener and invalid peer settings.
- Certificate roots, pinsets and caller service identities must be configured explicitly. `Api/ServiceCertificates.cs` and `Client/ClientTrust.cs` handle trust construction.
- A caller's service identity and requested action are not interchangeable with the end-user's validated session identity.
- The SDK owns bounded network resources and call lifetime; consumers must dispose the client and retain their own authorization logic.

## Outcomes

`Active` means the requested validation succeeded and can include a bounded subject. `Unauthenticated` means session evidence did not authorize the credential, `Forbidden` means the requested action was not granted, and `Unavailable` is the fail-closed infrastructure/admission outcome. The client maps these to typed results, not a locally verified substitute JWT. Consult `Core/SessionDecision.cs`, `Api/ValidationService.cs` and `Client/SessionValidatorClient.cs` for exact wire and status mappings.

The returned lifetime is bounded by the original request budget and relevant authority expiration. Clients must not cache an identity beyond its returned validity or interpret an unavailable result as active.

## Files to review when integrating a consumer

- `src/Treehammock.SessionValidation.Client/ClientOptions.cs`
- `src/Treehammock.SessionValidation.Client/SessionValidatorClient.cs`
- `src/Treehammock.SessionValidation.Client/GrpcValidationTransport.cs`
- `src/Treehammock.SessionValidation.Contracts/ContractRules.cs`
- `docs/session-validation/design/contracts/session-validation-v1.proto`

Use [security and data access](data-access-and-security.md) for credential boundaries and [testing](testing-and-qualification.md) before production rollout.
