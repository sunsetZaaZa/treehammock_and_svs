# Documentation

This is the reader-facing entry point for the TreeHammock account-security API and its private Session Validation Service. The documents below are organized by responsibility, not by the sequence in which their code was developed.

## Architecture

- [System overview](architecture/system-overview.md): service roles, durable authority, cache and dependencies.
- [Authentication and session lifecycle](architecture/authentication-and-session-lifecycle.md): login, refresh, credential validation and revocation.
- [SVS documentation](session-validation/README.md): internal validation architecture, wire protocol, cache, security, operations and qualification.

## Using and operating the software

- [API endpoint orientation](reference/api-endpoints.md): where the HTTP contracts are implemented and what the supplied endpoint inventory represents.
- [Testing guide](testing/README.md): commands, host requirements, infrastructure boundaries and qualification.
- [Release guide](release/README.md): reproducible inputs, artifact identity and independent authorization.
- [Public API session-cache warmup](deployment/SESSION_CACHE_WARMUP.md): an opt-in TreeHammock feature, distinct from the SVS cache-coherence path.

## Project handoff

- [Maintenance handoff](maintenance/README.md): package provenance, verification boundaries, follow-up checks and rollback.

## Source-of-truth conventions

Use current C# source, contract files and operator configuration as the behavioral authority. The documentation describes their roles and points to relevant files, but configuration and runtime behavior must still be verified against the checkout. Release-versioned reference documents in `release/` are retained as versioned snapshots, not automatically as the latest product specification. Evidence/pin files are not rewritten simply to change wording.

**Qualification:** implemented, locally tested, tested on real infrastructure, and approved for production are separate states. The current [qualification status](session-validation/current-verification.md) intentionally does not imply native or production approval.
