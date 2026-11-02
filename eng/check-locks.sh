#!/usr/bin/env bash
set -euo pipefail

mode="fail"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --warn-only)
      mode="warn"
      shift
      ;;
    -h|--help)
      cat <<'USAGE'
Usage: ./eng/check-locks.sh [--warn-only]

Verifies that every project containing PackageReference items has a sibling
packages.lock.json file. Use --warn-only while bootstrapping the first lock-file
commit; use the default fail mode once locks are committed.
USAGE
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

missing=()
while IFS= read -r -d '' project; do
  if grep -q '<PackageReference[[:space:]]' "$project"; then
    lock_file="$(dirname "$project")/packages.lock.json"
    if [[ ! -f "$lock_file" ]]; then
      missing+=("$lock_file")
    fi
  fi
done < <(find . -name '*.csproj' -not -path './**/bin/*' -not -path './**/obj/*' -print0 | sort -z)

if [[ ${#missing[@]} -eq 0 ]]; then
  echo "All package lock files are present."
  exit 0
fi

message="Missing package lock file(s):"
for file in "${missing[@]}"; do
  message+=$'\n  - '"$file"
done
message+=$'\nRun ./eng/restore-locks.sh on a machine with the .NET SDK, review the generated locks, then commit them.'

if [[ "$mode" == "warn" ]]; then
  echo "::warning::${message//$'\n'/ }"
  echo "$message"
  exit 0
fi

echo "$message" >&2
exit 1
