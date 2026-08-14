# Registry Discovery future work ledger

The following ideas are deliberately absent from the first implementation.
Their prior design material remains recoverable from the PR 748 backup branch,
but none is dormant production code or a current public contract.

| Capability | Reconsider only when |
|---|---|
| Periodic harvesting, per-origin snapshots, diffs, and status | A manual immutable build has proven insufficient for real operators. |
| Provider routing | An adopter journey has a public, non-subject routing input and a defined authority model. |
| Aggregate DCAT catalog | An interoperating catalog needs a projection derived from normalized records. |
| Keyword search, ranking, pagination | Measured catalog size and a defined user language policy require them. |
| Evidence procedure authoring | Evidence owns the workflow and its trust boundary. |
| Node and Python bindings | The Rust public API and errors are stable. |
| Release, installers, OCI images | The source product and end-to-end contract are stable. |
