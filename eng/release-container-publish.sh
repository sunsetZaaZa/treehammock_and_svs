#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  cat <<'USAGE'
Usage: eng/release-container-publish.sh
Promotes an already tested OCI candidate; never builds or relabels trigger source.
Required: REGISTRY_KIND (gitlab | generic | dockerhub | aws-ecr | github),
RELEASE_TAG, RELEASE_SOURCE_SHA, RELEASE_MANIFEST, registry credentials.
Optional: IMAGE_ENV_FILE, PUBLICATION_REPORT, PUSH_LATEST_FOR_STABLE.
USAGE
  exit 0
fi
: "${REGISTRY_KIND:?Missing registry kind}"
: "${RELEASE_MANIFEST:?Missing tested release manifest}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
python3 eng/release_artifacts.py promote --manifest "$RELEASE_MANIFEST" \
  --registry "$REGISTRY_KIND" --report "${PUBLICATION_REPORT:-artifacts/release/${REGISTRY_KIND}-publication.json}" \
  --env-file "${IMAGE_ENV_FILE:-image.env}"
