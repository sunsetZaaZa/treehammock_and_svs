# COR23AB — declared host selection and prerequisites

Owner: R10C-04 only. Baseline: completed COR23AA. Status: FixedPendingQualification; native PowerShell/Windows/Docker/.NET qualification remains NotRun.

Use the current PowerShell executable for the private wrapper and lock-audit child. Windows ACL setup honors that explicit host instead of requiring powershell.exe. Keep Windows execution-policy changes process scoped and conditional; CMD honors explicit selection without silent fallback and forwards the child exit. Remove the legacy executable assertion and cover selected-host paths, versions, native failure results and acquisition ordering with executable tooling. Add a required actual selected-host fixture to the existing CI matrix; local missing hosts execute zero cases.

Run shared read-only preflight before creating owned directories, snapshots, credentials, leases or Docker resources. Validate supported OS/shell/Python, Docker Engine/local Linux daemon/Desktop opt-in, Compose, SDK/8.x runtimes, required configuration and lock audit. Render Compose with placeholder credentials; freeze the selected Docker executable/context. Missing tools and failed native checks retain their result, invalid variants/configurations fail clearly, and preflight shares AA's aggregate startup clock. Private snapshot checks and Z/AA ownership, cleanup, environment restoration, identity and fresh-results proof continue unchanged.

See [host prerequisites](../testing/HOST_PREREQUISITES.md). Tooling uses explicitly controlled Docker/SDK actors; source inspection and simulated Windows replies do not qualify those hosts. Actual PowerShell, CMD, ACL, Docker, application and System execution remain pending in this environment. Only R10C-04/COR23AB advance; other 83 findings/31 followups, SQL/locks/original evidence and all 186 Open release gates remain unchanged. Ledger: 80 FixedPendingQualification / 4 Open. Direct pre-1.0 edits; no migrations or legacy systems.

Next: COR23AC, strict HTTP failure envelope/error-code assertions.
