#!/usr/bin/env bash
# Source-only helper: the caller owns restore/build/no-build test under one ID.
treehammock_begin_build() {
  case "$1" in Debug|Release|Sandbox) ;; *) echo 'Unsupported build configuration.' >&2; return 2 ;; esac
  if [[ -r /proc/sys/kernel/random/uuid ]]; then
    TREEHAMMOCK_BUILD_RUN_ID="$(cat /proc/sys/kernel/random/uuid)"
  elif command -v uuidgen >/dev/null 2>&1; then
    TREEHAMMOCK_BUILD_RUN_ID="$(uuidgen | tr '[:upper:]' '[:lower:]')"
  else
    echo 'A native UUID source is required for the build proof.' >&2
    return 2
  fi
  [[ "$TREEHAMMOCK_BUILD_RUN_ID" =~ ^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$ ]] || return 2
  TREEHAMMOCK_BUILD_CONFIGURATION="$1"
  export TREEHAMMOCK_BUILD_RUN_ID TREEHAMMOCK_BUILD_CONFIGURATION
}
