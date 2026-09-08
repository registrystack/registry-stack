# BReg registry starters

Each `*/core` directory is an ordinary authored BReg project. The fixed models,
clients and synthetic scenarios are versioned together. `starter-template.json`
describes the template for distribution tooling; it grants no runtime authority.
The project source is authoritative after download.

The starter models use PublicSchema draft vocabulary at
[`1ea9ce333918693b29aec31068fac412e02cb8dc`](https://github.com/PublicSchema/publicschema.org/tree/1ea9ce333918693b29aec31068fac412e02cb8dc).
The embedded offline reference catalog is updated with
`crates/registry-linkml/publicschema/sync-snapshot.sh`, whose pin and license
remain the attribution source. This is draft alignment, not conformance,
certification or a claim about an institution's legal authority.

The executable examples require the BReg tool version selected by the
published starter distribution. The maintained native `bregctl dev` and
`bregctl examples` commands run the project locally. `clients.yaml` contains
synthetic client definitions, no credentials. Pass it explicitly with
`bregctl dev --clients-file clients.yaml`. Startup itself loads no records.
Only an explicit `bregctl examples run starter-data .` populates samples.
The first-record exercise is independent of those samples.

`tests/journeys.yaml` is the native schema-test suite. It covers real submitted,
approved, applied and rejected requests and applicable domain date and quantity constraints.
`tests/security-journeys.yaml` is a separate complete suite for the native
credential-generating security proof: it includes refusal of a reviewer action precondition reused by the
submitting principal and callers missing a required scope. The separate HTTP
proof checks the independent-review policy itself: the submitting principal
with reviewer scopes has no approval action, while a distinct reviewer does. The normal dev
rehearsal uses only the three teaching identities in `clients.yaml`. Direct
PATCH refusal, concrete wrong-type UUIDs, history and retained-state recovery
are exercised by the native HTTP integration proof.
Presence of these files is not an execution receipt. Validate and test the exact
personalized project before use.
