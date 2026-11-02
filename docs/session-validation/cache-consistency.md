# Cache consistency, refill and revocation

## Authority model

Durable TreeHammock session/account state is the authority source; Dragonfly is a bounded cache of session evidence, not an independent session writer. A cached projection is usable only if the reader can establish coherent admission, valid expiry and matching policy/authority. The relevant code is in `src/Treehammock.SessionValidation.Storage/`.

## Read and fallback

`SessionEvidenceCoordinator` first uses `CoherentSessionCacheReader`. The coordinator checks the cache-admission witness and time boundaries around evaluation and reply. A suitable hit can avoid foreground SQL, control and refill work. Absent, stale, ambiguous or unavailable cache evidence is not treated as authorized; the controlled authority read supplies the fallback when available. If neither path can safely validate, the result is unavailable rather than a guessed positive decision.

## Publication and revocation

`ConditionalProjectionPublisher`, `DragonflyAuthorityStore`, `authority-transition.lua`, `BoundedSessionRefillQueue` and the private host's `LocalRefillWorker` implement bounded publication and cache transitions. The coherent fleet path distinguishes foreground reader identity from permitted refill/publisher identity. Its lifecycle and writer fence coordination are intended to prevent an older projection from being resurrected after a revocation or epoch transition.

**Functional names that must remain intact:** the `SVSRefill.v1` and `authority-fleet.v2` protocols (where present in the source/configuration) are *versioned interoperability contracts*, not document milestones. Never rename them for editorial consistency.

## Failure expectations

- A database outage may permit already-coherent, still-valid cached evaluations; it must not turn missing/expired/incoherent cache data into active authority.
- A cache outage moves traffic to the bounded durable fallback when available; saturation and unavailable authority fail closed.
- A concurrent logout, account lock, key/family rotation or entitlement change can invalidate an otherwise previously readable projection. Expiry and admission checks apply at response time.
- No broker event alone can grant a session. Controlled durable authority and fencing determine what may be published.

These are implemented design boundaries and test targets, **not claims that every physical race, database failure or multi-replica scenario has passed native acceptance**. See [qualification](testing-and-qualification.md) and [current verification](current-verification.md).
