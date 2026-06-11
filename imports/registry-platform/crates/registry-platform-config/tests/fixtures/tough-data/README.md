# TUF Test Fixtures

These fixtures are the minimal `tough` public test data needed by the
`registry-platform-config` verifier contract tests. They are checked in so the
tests do not depend on a local Cargo registry source cache or a specific crate
source directory layout. Private signing keys are generated into temporary test
directories at runtime rather than stored here.

Source: `tough` test data, licensed `MIT OR Apache-2.0`.
