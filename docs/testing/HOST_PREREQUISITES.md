# Host test lane prerequisites

The declared host variants are native Linux with Bash 4+ or PowerShell 7+, and native Windows with PowerShell 7+ or Windows PowerShell 5.1. Use native Python 3.10+ in the same OS; Linux requires PID handles. macOS, WSL, Cygwin/MSYS and Windows Bash host variants are disabled; use the owned container test lane, or native Windows PowerShell. These are implementation contracts pending the real supported-host matrix, not a claim of completed platform qualification.

The PowerShell entrypoint carries its current process executable into the coordinator and private wrapper. Its lock audit starts a child of that exact executable. Windows fixture ACL operations use that same selection. Windows execution-policy bypass is process scoped; Unix does not set execution policy. No machine or user policy changes are made. The CMD launcher honors an explicit `TREEHAMMOCK_POWERSHELL_HOST` executable/path; an unavailable explicit selection returns 127 without fallback. Otherwise it selects available pwsh first, then Windows PowerShell. Paths and arguments remain separate and the selected process exit is returned.

```powershell
pwsh -NoLogo -NoProfile -File ./eng/docker-host-system-stack-tests.ps1
# Native Windows CMD, explicit host; a path containing spaces is supported:
# set "TREEHAMMOCK_POWERSHELL_HOST=C:\Program Files\PowerShell\7\pwsh.exe"
# .\eng\docker-host-system-stack-tests.cmd
```

```bash
bash ./eng/docker-host-system-stack-tests.sh
pwsh -NoLogo -NoProfile -File ./eng/docker-host-system-stack-tests.ps1
```

Before creating run directories, private checkouts, credentials, leases or Docker resources, the outer coordinator checks the selected shell and platform, Docker CLI/Engine 28+, local Linux-container daemon, Compose v2, .NET SDK 8+ and both Microsoft.NETCore.App/Microsoft.AspNetCore.App 8.x runtimes. Readiness uses Python's standard-library HTTP implementation, so curl is not required. Docker Desktop requires enabled host networking and explicit `TREEHAMMOCK_HOST_NETWORKING_CONFIRMED=true`. Remote Docker endpoints are rejected. The effective daemon context and Docker executable are frozen for the owned run; explicit CLI/context settings remain selected.

Required Compose, ownership, application/System project, canonical database and HAProxy files must exist. The ownership template is parsed, and Compose renders the host configuration with constant placeholder values, without generating credentials or starting/pulling resources. Package lock audit runs in the selected child host before acquisition, then the private wrapper rechecks its own snapshot before pulls. Bash lock audit also requires find, sort and grep. Generated fixture credentials belong to the later ownership phase; caller credentials never satisfy this preflight.

One existing monotonic startup budget includes preflight. Missing executables return 127; native prerequisite failures preserve their exit code; invalid configuration/platform/version returns 2; budget expiration returns 124. Diagnostics identify the failed prerequisite without printing native output, credentials or command arguments. No owned manifest exists for a preflight rejection because no resources were acquired. Once acquisition starts, the owned test cleanup/recovery and process/endpoint/result evidence rules remain in force.

```bash
python3 eng/check-host-prerequisites.py
python3 -m unittest discover -s eng/tests -p test_host_prerequisites.py -v
python3 eng/test-host-prerequisites.py --host pwsh --require-native --output .correction-results/cor23ab-host.json
```

Tooling behavior tests use controlled Docker/SDK/version replies and execute an actual Bash lock audit. The native fixture uses actual selected PowerShell version/lock processes in a checkout containing spaces and real Windows CMD when available, with explicitly controlled Docker/SDK replies. CI requires that fixture for Linux pwsh, Windows pwsh and Windows PowerShell; missing native hosts fail required mode. Local absent runtimes record zero cases/NotRun. Full native Docker/.NET/ACL/process containment and platform qualification still belong to the native host and integrated qualification matrix; all release gates remain Open. No migration or legacy compatibility system is introduced.
