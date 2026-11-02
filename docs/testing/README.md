# Testing TreeHammock and Session Validation

Tests in this repository range from local code checks to infrastructure and deployment exercises. A passing unit test cannot certify real database/cache permission behavior or a target-host production release.

## Public TreeHammock API

- [Source layout and references](SOURCE_LAYOUT_VALIDATION.md): solution membership, developer tooling, and documentation-link checks.
- [Test commands](TEST_COMMAND_GUIDE.md): command selection, unit/integration and Docker-backed lanes (some detailed examples still require wording cleanup).
- [Host prerequisites](HOST_PREREQUISITES.md): supported native host variants and pre-acquisition checks.
- [Run lifecycle](TEST_RUN_LIFECYCLE.md): ownership, cleanup and resource limits.
- [Authenticator tests](AUTHENTICATOR_REPLACEMENT.md): authenticator-related checks.

## Session Validation

- [Service qualification](../session-validation/testing-and-qualification.md): test levels and required native evidence.
- [Current verification status](../session-validation/current-verification.md): what remains unproven by source alone.
- [Qualification driver](../../eng/session-validation/qualification/README.md): load, soak, failover and evidence planning.
- [Release review](../../eng/session-validation/release/README.md): independent proof and release gate tooling.

## Commands

At the repository root:

```sh
./eng/validate.sh --configuration Debug
./eng/dotnet-unit-tests.sh --configuration Release --locked-restore
```

PowerShell equivalents are in `eng/`. A broader Docker stack requires Docker/Compose and host prerequisites. Service-specific scripts under `eng/session-validation/` may depend on actual private certificates, physical site plans or native infrastructure. Check each script before use. The root SDK selection is .NET 10 and the public app targets .NET 8; the SVS private API targets .NET 10.

## Status language

Use **present in source**, **build succeeded locally**, **test passed against local substitutes**, **native qualified**, and **approved** distinctly. Only claim tests which have really been executed on the corresponding environment and artifact. Further details: [service qualification](../session-validation/testing-and-qualification.md).
