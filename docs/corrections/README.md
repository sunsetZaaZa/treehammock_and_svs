# Correction qualification inventories

This folder holds current machine-readable inventories for reviewed authentication,
SQL, session, and source integrity behavior. **Filenames describe the evidence's
purpose**, not the PR or milestone under which the evidence was first recorded.

| File | Purpose |
| --- | --- |
| `AUTHENTICATED_MUTATION_INVENTORY.json` | Mutation operations and their replay/stamp requirements |
| `AUTHENTICATED_REPLAY_INVENTORY.json` | Replay-safe authenticated endpoints |
| `SQL_OUTPUT_BINDING_REVIEW.json` | Indexed output-binding risks in canonical SQL |
| `FACTOR_IDENTITY_CONSUMER_REVIEW.json` | TOTP factor identity usage across SQL and C# |
| `DOCUMENTATION_REVIEW.json` | Source-to-document review findings |
| `FOCUSED_SOURCE_REVIEW.json` | Focused source inspection evidence |
| `SOURCE_FINDING_FOLLOWUPS.json` | Finding ownership and pending qualification |
| `SOURCE_RECONCILIATION.json` | Indexed source file reconciliation |
| `APPLICATION_SURFACE_INDEX.json` | Static endpoint, SQL and test source index |
| `CORRECTION_REQUIREMENTS.json` | Requirements and outstanding work inventory |
| `ADDED_FILES.json` | Current inventory of files added after the immutable baseline |
| `BASELINE_MANIFEST.json` | Immutable baseline history (never rewrite to approve a change) |
| `FILE_REVIEW_INVENTORY.csv` | Original frozen review inventory |
| `FINDING_CLOSURE.json` | Current finding status and evidence requirements |
| `REVIEW_GATES.json` | Qualification and approval gates |

Scripts in `eng/` consume several of these files by path. When renaming a
file, update its references together with the file catalog and run the
applicable source verification checks.

Historical correction IDs in JSON *values* (finding owners, stored SQL
function names, proof keys, and pinned snapshots) remain unchanged by a
filename cleanup. The file inventory records current bytes and names; it does
not certify native or production security qualification.

See [documentation home](../README.md) and [source layout
validation](../testing/SOURCE_LAYOUT_VALIDATION.md) for development guidance.

## Historical Git import of the correction ledger

The current source contains implementation history before its correction ledger
was introduced to this Git repository. On the first commit where the preceding
revision has no `BASELINE_MANIFEST.json`, CI explicitly pins the unchanged
`FINDING_CLOSURE.json` SHA-256:

`ee3a33805ece63287c82f62490cd16ccf67c3c1a9c5d445b7950030d847cc48e`

The checker validates a continuous history starting in `Open` for every
finding, and refuses `Closed` or `Dispositioned` findings or passed review
gates on this first import. Later commits use the predecessor Git snapshot
for append-only transition checks. The exception is **only for importing a
previously developed ledger**, not an approval of runtime/native/security
qualification. Never regenerate the hash automatically in CI. New historical
imports require independent review of their source and a deliberate pin update.

The frozen inventory still names the original release documents. The
checker maps those immutable historical names to current functional filenames
without modifying the frozen source hashes.
