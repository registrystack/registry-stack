# Registry Discovery acceptance journeys

The following journeys are product requirements. Their executable local tests
are added by the owning provider, builder, runtime, and client crates and then
become enforced bindings in the security matrix.

## Evidence

1. A validated Evidence deployment derives and packages a public description.
2. `discoveryctl build` reads that exact description from an approved local
   fixture origin and writes one immutable index.
3. A relying application resolves an explicit requirement to evidence types,
   searches that type, and selects one exact record.
4. Existing application-owned Evidence trust accepts the selection.
5. The maintained native Evidence client requests and verifies an assertion
   directly. Discovery observes neither credentials nor the assertion.

## Relay

1. A validated Relay deployment packages its public description as a sealed
   public artifact.
2. The one-shot build indexes it as a separate origin record.
3. A relying application searches an exact public semantic class or operation
   family, explicitly selects the record, and applies existing native Relay
   trust.
4. The maintained Relay client invokes the provider directly. A protected-only
   Relay advertisement may have no public semantic class or operation family.

## Failure cases

- A remote context, duplicate JSON member, unknown public field, or invalid
  product-kind capability is refused before a description can reach an index.
- A hostile origin, resource-bound breach, collision, mapping failure,
  validation failure, canonicalization failure, or output-bound failure emits
  no new visible index.
- A local trust refusal occurs before native credential creation or traffic.
