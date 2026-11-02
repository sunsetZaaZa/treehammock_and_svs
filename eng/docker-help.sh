#!/usr/bin/env bash
set -euo pipefail

cat <<'USAGE'
Treehammock Docker developer commands

First-time setup:
  ./eng/restore-locks.sh

Build/test images:
  ./eng/docker-unit-tests.sh             Build and run fast tests in Docker
  ./eng/docker-api-image.sh              Build the published API runtime image

Selectable services:
  ./eng/docker-postgres-up.sh            Run PostgreSQL only
  ./eng/docker-dragonfly-up.sh           Run DragonflyDB only
  ./eng/docker-infra-up.sh               Run PostgreSQL + DragonflyDB
  ./eng/docker-api-direct-up.sh          Run PostgreSQL + DragonflyDB + API on localhost:5001
  ./eng/docker-api-proxy-up.sh           Run PostgreSQL + DragonflyDB + API + HAProxy on localhost:8080
  ./eng/docker-api-proxy-scale.sh [N]    Run HAProxy mode with N API replicas, default 2
  ./eng/docker-all-runtime-up.sh         Alias for all long-running runtime services: PostgreSQL + DragonflyDB + API + HAProxy

Test lanes:
  ./eng/docker-sql-contracts.sh          Run SQL contract suite tests against Compose PostgreSQL
  ./eng/docker-http-contracts-direct.sh  Run Bruno HTTP checks against api:5001
  ./eng/docker-http-contracts-proxy.sh   Run Bruno HTTP checks against haproxy:8080
  ./eng/docker-system-stack-tests.sh     Run full Compose system tests through HAProxy
  ./eng/docker-host-system-stack-tests.sh
                                         Run host-backed system tests through HAProxy without pulling MCR .NET images
  ./eng/docker-all-tests.sh              Run unit, SQL contract, direct HTTP, proxy HTTP, and full system Docker lanes

Cleanup:
  ./eng/docker-down.sh                   Stop Compose services
  ./eng/docker-down.sh --volumes         Stop Compose services and remove named volumes

PowerShell equivalents exist for every command above.

Windows PowerShell downloaded-checkout shortcut:
  ./eng/docker-host-system-stack-tests.cmd  # runs the host system lane with process-local ExecutionPolicy Bypass
USAGE

