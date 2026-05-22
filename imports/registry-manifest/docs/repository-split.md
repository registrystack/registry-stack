# Repository Split Notes

Registry Metadata was extracted from `registry_relay` as the portable metadata repository.

The initial cut copies the current metadata crates, golden fixtures, CLI tests, and profile fixtures into this workspace. Registry Relay integration, external dependency conversion, and source crate removal remain owned by the Relay integration worker.

The split boundary is intentionally narrow: metadata manifests and pure renderers live here; HTTP publication, runtime source binding, authentication, authorization, and audit behavior do not.
