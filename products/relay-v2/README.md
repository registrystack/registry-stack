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
- responses are unsigned;
- Registry Mint is optional and Registry Evidence remains a separate product;
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
| `contracts/` | Hand-authored product catalogs and security invariants. |
| `acceptance/` | Three coequal one-Registry deployment projects. |
| `scripts/` | Product-local validation, neutrality, and fixture checks. |

The acceptance projects are synthetic. Their identifiers, organisations, and
records are deliberately fictional and use reserved `.invalid` service names.
Tracked SQL constructs each SQLite fixture; generated `.sqlite` files are not
committed.

## Current checks

Run the focused product gates from the repository root:

```bash
products/relay-v2/scripts/check-contracts.sh
products/relay-v2/scripts/check-generated.sh
products/relay-v2/scripts/test-http.sh
```

Together they validate the product catalogs and configs, build each SQLite
fixture in a temporary directory, run the canonical `relayctl test` journeys,
reproduce generated artifacts, enforce source neutrality, and exercise all
three deployments through the real Relay router.
