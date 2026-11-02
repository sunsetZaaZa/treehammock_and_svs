# Source layout and reference validation

From the repository root, run:

```sh
python3 eng/verify-source-layout.py
python3 eng/check-build-configuration.py
python3 -m unittest discover -s eng/tests -p 'test_source_layout.py'
python3 -m unittest discover -s eng/tests -p 'test_build_configuration.py'
python3 -m unittest discover -s eng/tests -p 'test_authenticator_replacement.py'
python3 -m unittest discover -s eng/tests -p 'test_cross_feature_qualification.py'
```

These checks verify solution registration and configuration, compile-time file references, the stable embedded SQL resource name, documentation links, and selected tooling behavior. The source-layout verifier checks 19 projects in the main solution, including 17 SessionValidation projects. Specialist native/qualification projects remain visible in the solution without default Build Solution selection. It also verifies the two projects in the separate SQL-contract solution.

The private host's integration tests reference a sibling `contact-backup` directory outside the `treehammock` folder. Extract both project directories at the same parent level when validating that integration test project. This companion is a source-pinned development dependency, not proof that the independently maintained backup service is ready to deploy.

Some qualification tools consume immutable machine-readable inventories under `docs/corrections`. They retain historical schema fields and technical identifiers because changing those keys without coordinated reconciliation would falsify evidence or break the verifier. They are not the navigable development documentation. The current human-readable documentation begins at [Documentation home](../README.md).

The source-layout and Python tests **do not** replace a local .NET SDK restore/build, native Yugabyte or Dragonfly testing, TLS/host integration, security review, or release qualification. The source-pin and historical evidence tools must be verified separately. Do not regenerate or bypass an inherited cryptographic pin simply to obtain a green CI result.
