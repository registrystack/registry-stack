# OpenFn Sidecar Demo TUF Fixtures

These fixtures are deterministic lab-only TUF root and signing-key material used by
`scripts/generate-openfn-sidecar-governed-config.sh`.

They replace the previous dependency on Cargo's local `tough` crate cache, which
made hosted artifact generation sensitive to a developer machine's cache layout.
Do not use these keys outside demo or test deployments.
