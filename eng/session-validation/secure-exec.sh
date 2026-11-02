#!/usr/bin/env bash
# Service launcher: prevent runtime IPC/debugger/profiler and crash-dump capture.
set -euo pipefail
ulimit -c 0
export DOTNET_EnableDiagnostics=0 DOTNET_EnableDiagnostics_IPC=0
export DOTNET_EnableDiagnostics_Debugger=0 DOTNET_EnableDiagnostics_Profiler=0
export DOTNET_DbgEnableMiniDump=0 COMPlus_DbgEnableMiniDump=0
unset DOTNET_DiagnosticPorts DOTNET_DefaultDiagnosticPortSuspend
unset DOTNET_DbgMiniDumpName COMPlus_DbgMiniDumpName
unset DOTNET_STARTUP_HOOKS CORECLR_ENABLE_PROFILING COR_ENABLE_PROFILING
if [[ $# -lt 1 || "$1" != /* || "$1" != *.dll ]]; then
  echo SERVICE_ARGUMENTS_REFUSED >&2; exit 1
fi
exec dotnet "$@"
