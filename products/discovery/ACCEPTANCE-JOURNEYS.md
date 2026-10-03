# Registry Discovery acceptance journeys

The following journeys are product requirements. Their executable local tests
are added by the owning provider, builder, runtime, and client crates and then
become enforced bindings in the security matrix.

## Evidence

1. A validated Evidence deployment derives and packages a public description.
2. `discoveryctl package` reads that exact description from an approved local
   fixture origin and writes one package containing the index and `SHA256SUMS`.
3. A relying application resolves an explicit requirement to evidence types,
   searches that type, and selects one exact record.
4. Existing application-owned Evidence trust accepts the selection.
5. The maintained native Evidence client requests and verifies an assertion
   directly. Discovery observes neither credentials nor the assertion.

## Failure cases

- A remote context, duplicate JSON member, unknown public field, or invalid
  product-kind capability is refused before a description can reach an index.
- A hostile origin, resource-bound breach, collision, mapping failure,
  validation failure, canonicalization failure, or output-bound failure emits
  no new visible package.
- A local trust refusal occurs before native credential creation or traffic.
- A historical Relay description is refused by current Rust publication and a
  pre-retirement mixed index is refused as a whole with rebuild guidance.
