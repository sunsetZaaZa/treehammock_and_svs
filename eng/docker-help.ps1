[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'native-command.ps1')

Invoke-TreehammockRunner -Stage 'docker-help' -Body {
@'
Treehammock Docker developer commands

First-time setup:
  ./eng/restore-locks.ps1

Build/test images:
  ./eng/docker-unit-tests.ps1             Build and run fast tests in Docker
  ./eng/docker-api-image.ps1              Build the published API runtime image

Selectable services:
  ./eng/docker-postgres-up.ps1            Run PostgreSQL only
  ./eng/docker-dragonfly-up.ps1           Run DragonflyDB only
  ./eng/docker-infra-up.ps1               Run PostgreSQL + DragonflyDB
  ./eng/docker-api-direct-up.ps1          Run PostgreSQL + DragonflyDB + API on localhost:5001
  ./eng/docker-api-proxy-up.ps1           Run PostgreSQL + DragonflyDB + API + HAProxy on localhost:8080
  ./eng/docker-api-proxy-scale.ps1 [-ApiReplicas N]
                                          Run HAProxy mode with N API replicas, default 2
  ./eng/docker-all-runtime-up.ps1         Alias for all long-running runtime services: PostgreSQL + DragonflyDB + API + HAProxy

Test lanes:
  ./eng/docker-sql-contracts.ps1          Run SQL contract suite tests against Compose PostgreSQL
  ./eng/docker-http-contracts-direct.ps1  Run Bruno HTTP checks against api:5001
  ./eng/docker-http-contracts-proxy.ps1   Run Bruno HTTP checks against haproxy:8080
  ./eng/docker-system-stack-tests.ps1     Run full Compose system tests through HAProxy
  ./eng/docker-host-system-stack-tests.ps1
                                          Run host-backed system tests through HAProxy without pulling MCR .NET images
  ./eng/docker-all-tests.ps1              Run unit, SQL contract, direct HTTP, proxy HTTP, and full system Docker lanes

Cleanup:
  ./eng/docker-down.ps1                   Stop Compose services
  ./eng/docker-down.ps1 --volumes         Stop Compose services and remove named volumes

Bash equivalents exist for every command above.
Windows PowerShell downloaded-checkout shortcut:
  ./eng/docker-host-system-stack-tests.cmd  # runs the host system lane with process-local ExecutionPolicy Bypass
'@ | Write-Output
}
