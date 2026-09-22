# Relay guidance

This guide covers `registry-relay-v2`, `registry-relayctl`, and
`products/relay-v2`. Client work also follows
[client guidance](../../crates/CLIENTS.md).

One Relay process serves one governed Registry through compiled, read-only
SQLite operations. Responses are unsigned. Record consultation, declared
search, spatial operations, and explicitly bound statistical dataflows remain
confined to their compiled routes and plans. Relay owns neither the source
data nor Evidence semantics.

## Boundaries to preserve

- The closed governed contract decides resources, operations, classification,
  access, and disclosure. Runtime configuration binds deployment resources and
  cannot override those decisions. Startup rederives the compiled Registry and
  every artifact from the sealed package before activation. Package revision
  proves integrity, not authenticity; changes take effect by restart.
- Production compilation enforces review and source-completeness requirements.
  Default `relayctl check`, `generate`, `test`, and `diff` use authoring rules;
  `check --production` and `package` provide the production check.
- Select and authorize one finite access profile before source access. Caller
  headers, filters, and query parameters create no authority; projection only
  narrows that profile. Cursors, ETags, quotas, and metadata retain the compiled
  operation and relevant profile context. Unauthorized and unknown surfaces
  share the prescribed absence outcome.
- Public processing may not read non-public fields through hidden filters,
  transforms, joins, or ordering. A malformed row discards the complete held
  response. Required attempt audit precedes source I/O and terminal audit gates
  the exact serialized bytes. Errors, logs, and traces remain value-free.
- `registry-platform-sqlite` owns bounded read-only execution. Preserve
  snapshot digest checks, live-source path identity, and truthful revision
  claims. A compiler query that the kernel refuses does not justify widening
  the kernel's permissions.
- Editor support uses the in-memory authoring compiler and observes no SQLite
  or source values. The language server must not introduce a second compiler.

Use [CONCEPT.md](CONCEPT.md) for architecture,
[CONFIGURATION-EXAMPLES.md](CONFIGURATION-EXAMPLES.md) for authoring,
[STANDARDS-ALIGNMENT.md](STANDARDS-ALIGNMENT.md) for claim boundaries, and
`contracts/security-invariant-matrix.yaml` for the relevant enforcement points
and executable negatives. `contracts/artifact-inventory.yaml` and
`contracts/package-layout.yaml` own the artifact and sealed-package inventories.
Acceptance projects are coequal configured deployments, not built-in domains.

Run focused changed-crate tests and the gates matching the boundary from the
monorepo root:

```sh
products/relay-v2/scripts/check-contracts.sh
products/relay-v2/scripts/test-http.sh
```

Contract checks reproduce artifacts and enforce neutrality; HTTP journeys
exercise compiled authorization and disclosure through the real router.
For client-only route inventory work, use
`products/relay-v2/scripts/check-client-contract.sh`.
For authoring schema changes, regenerate from Rust types and verify:

```sh
cargo run --locked -p registry-relay-v2 --features schema --example authoring-schema -- --output crates/registry-relayctl/schemas/authoring
products/relay-v2/scripts/check-authoring-schema.sh
```

Do not edit generated schemas, OpenAPI, or other compiled artifacts by hand.
Use the owning generator and review the output diff. For adopter-facing work,
exercise authoring through packaging and the existing HTTP client, preserving
the small read-only deployment and avoiding source-system modifications.
Optional fetched standards checks follow explicit options in
[README.md](README.md); they are not prerequisites for unrelated maintenance.
