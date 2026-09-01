# Relay V2 product source

This directory is the tracked product source for the Relay V2 rebuild. It
contains the approved product direction, its completion contract, executable
acceptance inputs, and the small machine-readable catalogs enforced by the
Relay V2 crates and product gates.

The initial boundary is intentionally narrow:

- one Relay process serves one governed Registry;
- SQLite is read-only and is the only source profile;
- resources are Record types within the Registry;
- compiled operations map only to Consultation Retrieve, List, and constrained
  Search;
- explicitly bound, pre-aggregated statistical datasets map only to the
  Aggregate Data statistical-dataflow pattern and the aligned SDMX read subset;
- responses are unsigned;
- Registry Mint is optional and Registry Evidence remains a separate product;
- the separately versioned Relay client, including its Node and Python native
  bindings, consumes the fixed public HTTP contract but never adds a route,
  deployment capability, or Relay authorization semantic;
- the written GovStack drafts are alignment inputs, not conformance contracts;
- the obsolete Digital Registries OpenAPI is not consumed.

## Layout

| Path | Purpose |
|---|---|
| `CONCEPT.md` | Approved product boundaries and architecture. |
| `DEFINITION-OF-DONE.md` | Completion and acceptance contract. |
| `CONFIGURATION-EXAMPLES.md` | Illustrative authoring examples. |
| `IMPLEMENTATION.md` | Approved implementation sequence and verification policy. |
| `STANDARDS-ALIGNMENT.md` | Maintained directional mapping to the pinned GovStack drafts. |
| `CHANGELOG.md` | Breaking contract changes and migration guidance. |
| `contracts/` | Hand-authored product catalogs and security invariants. |
| `acceptance/` | Four coequal one-Registry deployment projects. |
| `scripts/` | Product-local validation, neutrality, and fixture checks. |

The acceptance projects are synthetic. Their identifiers, organisations, and
records are deliberately fictional and use reserved `.invalid` service names.
Tracked SQL constructs each SQLite fixture; generated `.sqlite` files are not
committed.

## Current checks

Run the focused product gates from the repository root:

```bash
products/relay-v2/scripts/check-contracts.sh
products/relay-v2/scripts/test-http.sh
```

Together they validate the product catalogs and configs, build each SQLite
fixture in a temporary directory, run the canonical `relayctl test` journeys,
reproduce generated artifacts, enforce source neutrality, and exercise all
four deployments through the real Relay router. Official SDMX schema bytes are
used only through the explicit temporary-fetch option or an external cache in
`scripts/validate-sdmx-profile.py`; those upstream bytes are never committed.
Set `RELAY_V2_SDMX_CONFORMANCE=1` when running `scripts/test-http.sh` to fetch
the digest-locked schemas temporarily and validate generated data and structure
responses.

`scripts/check-client-contract.sh` verifies the standalone fixed route and
problem inventory used by `registry-relay-client`; it has no live deployment or
fixture dependency.

For an assembled deployment, `relay check --runtime <runtime.yaml>` performs
the complete startup preparation without taking the listener socket. It
verifies the sealed package, observed SQLite source, audit writer, secrets, and
configured issuer discovery or JWKS transport. Exact token `iss` validation is
bound to `authentication.issuer.trustedIssuer` when that explicit field is
present, independent of the transport hostname.
