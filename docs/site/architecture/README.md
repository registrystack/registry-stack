# Registry Stack architecture model

This experimental LikeC4 model records stable cross-product boundaries and selected
implementation-level zoom paths.
It supplements the narrative documentation and specifications.
The source code, tests, OpenAPI documents, and RS requirements remain the sources of truth.

## Scope and C4 levels

The model contains two complete C4 zoom paths for the runtime products.
Do not infer lower-level structure for Registry Manifest or Registry Platform from their
portfolio boxes.
Use the official [C4 diagram definitions](https://c4model.com/diagrams) when classifying a new view.

| View | Diagram type | C4 status | Review question |
| --- | --- | --- | --- |
| `relayContext`, `notaryContext` | System context | C4 level 1 | Are the people, systems, and external responsibilities around one product correct? |
| `relayContainers`, `notaryContainers` | Container | C4 level 2 | Are the executable processes, data stores, protocols, and ownership boundaries correct? |
| `relayComponents`, `notaryComponents` | Component | C4 level 3 | Do the in-process responsibilities and security gates match the source structure? |
| `relayProtectedReadCode`, `notaryIssuanceCode` | Code | C4 level 4, selected slices | Do the named Rust symbols preserve the security-critical ordering and boundaries? |
| `index` | Portfolio overview | C4-adjacent, not a strict system landscape | Are product, tooling, adopter, and decision boundaries correct? |
| `protectedRegistryApi` | Dynamic | Software-system interaction | Does a protected Relay read preserve source, minimization, and audit boundaries? |
| `registryBackedIssuance` | Dynamic | Software-system interaction | Does issuance retain the exact Relay-backed provenance boundary? |
| `delegatedEvaluation` | Dynamic | Software-system interaction | Does the view show only the shipped inbound federation capability? |
| `singleNodeDeployment` | Deployment | Software-system instances and infrastructure | Does the documented production target keep product state and dependencies separate? |

Registry Relay and Registry Notary are modeled as C4 software systems.
Registry Manifest is an offline application, and Registry Platform is a supporting library.
That mixed portfolio is why `index` is not labeled as a C4 system landscape.

The Relay path zooms from the software system into its server and PostgreSQL store, then into the
server components, and finally into the protected-read code that preserves governed and
principal-bound query gates.
The Notary path zooms into the corresponding runtime and store, then into evaluation,
consultation, issuance, federation, and audit components, and finally into the code that refuses
credential issuance without exact stored Relay provenance.

The code views are intentionally small.
They name selected Rust symbols instead of reproducing the crate graph, and the tests verify that
each symbol still exists in its evidence file.
Add another code view only when one component has a security, maintenance, or onboarding question
that a source link alone does not answer.

## Correctness contract

Architecture correctness has four independent gates:

1. Source evidence: every logical element and relationship names a repository path or RS
   requirement.
2. Executable semantics: the Node tests query the computed LikeC4 model and pin product,
   source-access, issuance, federation, decision, audit, signing, and deployment-state boundaries.
3. Rendered review: a reviewer opens all 13 views and checks labels, nesting, edge direction,
   density, and merged relationships.
4. Maintainer judgment: security, trust, and privacy claims require Tier-C source-pack sign-off
   before merge.

`likec4 validate` proves syntax and model consistency.
It does not prove that a claim matches shipped behavior, that a C4 level is appropriate, or that a
rendered diagram is readable.

## Review a change

Install and run the model gate:

```sh
npm ci
npm run check:architecture
```

For dependency changes, also run:

```sh
npm audit
```

Open the explorer:

```sh
npm run architecture:dev
```

Review every view at the default browser width.
Reject a change when a node is unconnected without an explicit reason, an edge direction does not
match the actor, a label implies behavior not present in source, a boundary mixes C4 levels without
being declared as a portfolio view, a scoped C4 view contains elements below its declared level,
or the diagram depends on unreadable zoom.

Then run the complete docs gate:

```sh
npm test
npm run check
```

The pull request description must name the implementation evidence reviewed for changed behavior
claims.
For a deployment target, it must also say whether the diagram represents shipped generated
artifacts, a verified production topology, or documented target guidance.
