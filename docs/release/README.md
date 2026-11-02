# Release documentation

This directory contains release procedures and reference snapshots. A repository checkout is not approved for production solely because it contains release scripts, CI configuration or a feature matrix.

## Maintained operational topics

- [Artifact identity](RELEASE_ARTIFACT_IDENTITY.md): source/image provenance and digest controls.
- [Input policy](RELEASE_INPUT_POLICY.md): permitted input and source boundaries.
- [API image wrapper](API_IMAGE_WRAPPER.md): containerized build details.
- [GitHub release/CI overview](GITHUB_CI_CD_RELEASE.md): combined TreeHammock and SessionValidation release gates, archives, and operator instructions.
- [SVS independent review](../../eng/session-validation/release/README.md): protected native/security release acceptance.
- [SVS verification status](../session-validation/current-verification.md): release gating limitations for this working source.

## Versioned reference snapshots

The following documents contain version-stamped source matrices. They are **preserved as versioned records**, not reclassified as the latest living specification merely because they are linked here:

- [API endpoint matrix](API_ENDPOINT_MATRIX.md)
- [Feature matrix](RELEASE_FEATURE_MATRIX.md)
- [Password reset contract](PASSWORD_RESET.md)

The living [API orientation](../reference/api-endpoints.md) explains where to verify routes against source. Existing versioned records may still contain historical implementation labels; their cleanup is staged separately so audit meaning is not silently altered.
