# Maintenance and source handoff

This is the maintenance entry point for the TreeHammock authentication API and the separate Session Validation Service. The source archive also contains a sibling `contact-backup/` checkout because a SessionValidation host-test project references that path; its presence does not mean the backup service is part of the same deployment or production authorization boundary.

- [Verification status](VERIFICATION_STATUS.md) separates the checks that actually passed from blocked, failed, timed-out and not-run qualification.
- [Source and documentation handoff](SOURCE_HANDOFF.md) documents source identities, installation, historic evidence, and how to verify and roll back this editorial change.

Read the [documentation home](../README.md), [SessionValidation architecture](../session-validation/architecture.md), and [testing guide](../testing/README.md) for operational details.

**Release state:** The source workspace is available for development. It is not certified for production deployment. Historical proof data, source pins, signed/immutable records and internal review decisions retain their original meanings and are not superseded by this handoff.
