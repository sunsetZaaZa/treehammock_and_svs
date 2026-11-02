# COR23S — align build and test configuration identity

Owner: R10A-03 only. Rebased on completed COR23R. Status: FixedPendingQualification; native qualification NotRun.

Both solutions previously mapped Sandbox test projects to Debug while no-build runners requested Sandbox. The host system lane also used a Release API and default Debug tests. Align all solution/project configurations and application references, and explicitly build/test Release in host/container system lanes.

Give owned Bash/PowerShell/collector/Docker proof builds a fresh invocation UUID. Embed it in actual application/test assemblies, write a per-output build receipt, and reject missing or differently identified output before VSTest. The shared native module initializer independently verifies the actual loaded configuration, invocation, application copy and output paths before test code executes, recording MVIDs and binary hashes. Keep ordinary IDE use available without claiming owned proof evidence. New metadata changes the SDK assembly-attribute input hash, so stale outputs cannot satisfy a new invocation. Native runtime measurement is still required to qualify this behavior.

Pass fresh Docker build IDs through build/test stages and exclude host proof artifacts from the context. Preserve existing image/Compose/resource scopes. PowerShell restores inherited proof identity across nested scripts and errors. The existing controlled-native PowerShell fixture validates and normalizes only the new unpredictable UUID argv value; all remaining argv/order and first-failure checks remain exact.

Author native clean Debug/Release/Sandbox host lanes, loaded identities/MVIDs, stale/missing/wrong-application rejection, unique owned SQL fixtures, a network-free system assembly probe, and fresh Docker unit builds. Add C# loaded-assembly/solution/reference regressions plus supplemental source mutations, Bash identity execution and synthetic artifact rejection. Missing SDK/Docker/hosts is Blocked/NotRun, never measured success. See BUILD_CONFIGURATION_CONTRACT.md for commands and boundaries.

No package graph/lock, SQL/schema, migration, compatibility-system or frozen review changes. All other findings/followups and release gates remain unchanged. Sandbox does not change the application deployment environment or test capability contract.

Next: COR23T.
