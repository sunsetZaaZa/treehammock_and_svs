# PowerShell API image wrapper

The current wrapper isolates the case-insensitive `$Image`/`$image` collision in `eng/docker-api-image.ps1`. The wrapper captures the caller's output tag in a read-only variable, uses a separate base-reference loop variable, and builds only the requested API tag. Known exact collisions with the selected SDK/runtime references and blank output values are rejected before Docker work. Docker remains responsible for full reference syntax and alias interpretation.

```powershell
./eng/docker-api-image.ps1
./eng/docker-api-image.ps1 -Image 'treehammock:local-check' -Configuration Release -NoCache -Progress plain
```

The default tag is `treehammock:api`. `Debug`, `Release`, and `Sandbox` remain supported configurations. The wrapper forwards target `api`, the selected SDK/runtime references, configuration, a fresh build UUID, progress, optional no-cache and context `.`. Inputs remain native argument-array values. The wrapper's command boundary stops on failed lock checks, pulls or builds and preserves the failed native exit code; no later work masks the final build result.

Optional process environment overrides match the Bash Dockerfile inputs:

```powershell
$env:TREEHAMMOCK_DOTNET_SDK_IMAGE = 'mcr.microsoft.com/dotnet/sdk:8.0'
$env:TREEHAMMOCK_DOTNET_RUNTIME_IMAGE = 'mcr.microsoft.com/dotnet/aspnet:8.0'
./eng/docker-api-image.ps1 -Image 'treehammock:local-check'
```

Unset/empty values use the normal defaults. Tagged or digest-pinned references are pulled and passed consistently. The PowerShell wrapper requires successful pulls; the existing Bash retry/cache policy is separate. This developer wrapper does not publish a registry image or create the release workflow release-candidate provenance. Use the immutable candidate workflow for release promotion.

## Qualification

```bash
python3 -m unittest discover -s eng/tests -p test_api_image_tag.py -v
python3 eng/check-api-image-tag.py
python3 eng/test-api-image-wrapper.py --host pwsh
python3 eng/test-api-image-wrapper.py --host pwsh --docker
```

On Windows, select `--host powershell.exe` for the Windows PowerShell 5.1 matrix or `--host pwsh` for PowerShell 7. On Linux select PowerShell 7. Python 3 and .NET 8 are needed to compile the controlled native executable. The fixture uses a source checkout and executable path containing spaces, parses the wrapper with the actual selected PowerShell parser, then invokes unchanged scripts through both `-File` and `-Command`. It verifies default/custom tags, all configurations, tag/digest base overrides, no-cache/progress, first/second pull failures, build failure, known base collisions, blank output and missing locks. These are real PowerShell/native-process argv and failure checks, with a controlled executable replacing Docker. They do not qualify the Docker engine.

The optional `--docker` phase requires a reachable Linux-container Docker daemon plus package/image network access and enough disk space. It uses a temporary source copy, restores executable bits in that copy, pins the pulled SDK/runtime inputs, snapshots both shared upstream tag IDs, builds a unique owned API output tag, and verifies upstream IDs are unchanged. A deliberately failing Dockerfile in that copy must produce a nonzero result without a new output tag. Cleanup removes only the two unique owned output tags and attempts both removals if one fails; it never deletes shared base tags or prunes Docker caches. It does not overwrite the caller's default `treehammock:api` tag. Default output selection is covered by the actual PowerShell controlled-executable matrix.

PowerShell/.NET/Docker qualification is NotRun in this delivery. Source guards are supplemental; actual Bash fixtures qualify Bash forwarding only. Missing native tools produce a Blocked report with zero PowerShell/Docker cases. Windows 5.1, Windows/Linux PowerShell 7 and real Docker execution must pass before closing the PowerShell image wrapper. Full release/application qualification remains separate.

## Inspecting previously affected local tags

An older wrapper could tag the API image as the ASP.NET base image after its second pull. Inspect the tag and its entrypoint before changing anything:

```powershell
docker image inspect 'mcr.microsoft.com/dotnet/aspnet:8.0'
docker image inspect 'treehammock:api'
```

If inspection confirms the local upstream tag points to an API image, record its ID. Preserve it under an explicitly chosen recovery tag if needed, then pull the intended upstream reference to restore that local base tag. A digest-pinned upstream reference gives an explicit restoration identity. Choose the correct API tag and rebuild using the repaired wrapper. Do not assume the overwritten tag's old API payload or a missing requested tag has verified release provenance. This change requests does not automatically retag, remove or prune any developer images.
