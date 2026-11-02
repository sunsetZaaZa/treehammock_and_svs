# Session-validation wire contracts and provenance

The maintained description of the running design lives at [Session Validation Service documentation](../README.md). Start with the [architecture](../architecture.md), [wire protocol](../protocol-and-client.md), [cache consistency](../cache-consistency.md), [security](../data-access-and-security.md) and [verification status](../current-verification.md).

## Versioned protocol source

- [`contracts/session-validation-v1.proto`](contracts/session-validation-v1.proto): v1 gRPC request/reply schema.
- [`contracts/auth-state-events-v1.json`](contracts/auth-state-events-v1.json): an event-envelope contract retained in the design materials. Its presence does **not** mean an event bus authorizes session decisions or that this contract is active in production.

## Historical source provenance

`provenance/SOURCE_EVIDENCE.json`, `provenance/SOURCE_STATUS.md` and `SHA256_MANIFEST.txt` are retained historical design evidence. Some refer to checkpoints or files absent from the supplied working ZIP. They are not the active product guide or current release attestation. Their internal contents are preserved until the separate historical-evidence normalization phase; do not use them as an operational runbook.

`tools/verify_design_package.py` is an evidence-checking utility for its original scope; it is not a substitute for current source/infrastructure qualification.
