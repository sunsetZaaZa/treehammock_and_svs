# Source and documentation handoff

## Source directories and tooling

Extract the entire archive without flattening directory structure:

```text
workspace/
  treehammock/
    treehammock.sln
    global.json
    README.md
    docs/
  contact-backup/
    src/
```

Open `treehammock/treehammock.sln`. The `contact-backup/` sibling supplies a project reference from a SessionValidation host-test project; maintain the relative directory layout. Use Visual Studio with .NET 10 support and inspect `global.json` for SDK selection. The authentication service and private validator remain separately deployed applications.

## Documentation normalization

Living guides describe current behavior under `docs/`, `deploy/session-validation/`, and related `eng/` subtrees. Working filenames now describe their purpose. The rename ledger in the external delivery kit gives exact old and new paths. Code-facing names such as the embedded SQL resource identity, wire protocol labels, and stable source verification keys were deliberately not renamed. Historical provenance snapshots and package pin names are retained where their exact identity is evidence.

**Do not** replace, revise or discard signed or historical records merely to make their filenames look uniform. The original source archive is an independent historical reference and should be retained offline.

## Integrity and rollback

The delivery kit includes a SHA-256 manifest of every file in the final source, a file delta inventory, and an archive checksum list. Verify the full source ZIP before extraction, and check hashes against the manifest after extraction. The final documentation-only patch is intended for the exact immediately preceding full-source baseline, while the cumulative upgrade patch requires the exact user-provided original source ZIP and performs checksum verification before reconstruction.

To roll back this handoff only, return to the previous full-source archive. To reverse all editorial renames, extract the unmodified original archive into a **new** directory. Avoid overlaying earlier versions into a current working tree, because stale paths may coexist with renamed files and silently affect test discovery.

## Outstanding review

See [verification status](VERIFICATION_STATUS.md) and the external completion report before declaring test, release, or deployment readiness. The working source has not been granted production readiness or signed off by an independent security reviewer.
