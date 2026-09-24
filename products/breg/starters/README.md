# BReg registry starters

Each `*/core` directory is an ordinary authored BReg project. The fixed models,
clients and synthetic scenarios are versioned together. `starter-template.json`
describes the template for distribution tooling; it grants no runtime authority.
The project source is authoritative after download.

The starter models use PublicSchema draft vocabulary at
[`bd07bda1fe9cb9eb8582cf7bc1c77367e2455e5b`](https://github.com/PublicSchema/publicschema.org/tree/bd07bda1fe9cb9eb8582cf7bc1c77367e2455e5b).
The embedded offline reference catalog is updated with
`crates/registry-linkml/publicschema/sync-snapshot.sh`, whose pin and license
remain the attribution source. This is draft alignment, not conformance,
certification or a claim about an institution's legal authority.

The executable examples require the BReg tool version selected by the
published starter distribution. The maintained native `bregctl dev` and
`bregctl examples` commands run the project locally. `dev-clients.yaml` contains
synthetic client definitions, no credentials. A first `bregctl dev` reads it
from the project directory. Startup itself loads no records.
Only an explicit `bregctl examples run starter-data .` populates samples.
The first-record exercise is independent of those samples.

`tests/journeys.yaml` is the native schema-test suite. It covers real submitted,
approved, applied and rejected requests and applicable domain date and quantity constraints.
`tests/security-journeys.yaml` is a separate complete suite for the native
credential-generating security proof: it includes refusal of a reviewer action precondition reused by the
submitting principal and callers missing a required scope. The separate HTTP
proof checks the independent-review policy itself: the submitting principal
with reviewer scopes has no approval action, while a distinct reviewer does. The normal dev
rehearsal uses only the three teaching identities in `dev-clients.yaml`. Direct
PATCH refusal, concrete wrong-type UUIDs, history and retained-state recovery
are exercised by the native HTTP integration proof.
Presence of these files is not an execution receipt. Validate and test the exact
personalized project before use.

## Authored population scenarios

An `examples/scenarios.json` version 1 catalogue can declare 1..32 scenarios,
each with 1..100 steps. Scenario identifiers use lowercase letters, digits and
hyphens, up to 64 characters. Each input file contains exactly the named payloads
used by that scenario. Population steps use `create`, `get`, or `invoke` and
explicitly name a dev client and access profile.

An invocation selects an immediate action and one of its disclosed result
aliases. `entity` declares the expected entity of that result; `capture` gives
its returned UUID a local name for later steps:

```json
{
  "id": "register",
  "operation": "invoke",
  "action": "register-entry",
  "entity": "entry",
  "result": "entry",
  "client": "registrar",
  "accessProfile": "registrar",
  "input": "registration",
  "capture": "registered-entry"
}
```

The action and result names must exist in caller-filtered metadata. A logical
`{"recordRef":"registered-entry"}` input resolves only in an advertised
reference field with the matching target entity. The runner checks every
payload and dependency before sending the first mutation.

To use captures from another completed population, pass its returned attempt
identifier with `--from-attempt ID`. Both attempts must use the same governed
source, package, client configuration, catalogue and database generation. This
imports identifiers, not authorization. The combined captures remain limited
to 100. The reserved `reviewed-change` scenario keeps its explicit submit,
inspect, approval or rejection, and separate Apply stages; its default parent
is one completed `first-record` attempt.

Before invoking, the runner saves the original input, idempotency key and any
required target conditions in private retained state. After an interrupted
response, resume the same `--attempt ID`. It reuses those exact conditions,
checks current caller-filtered metadata, and explicitly retries the original
operation. Completed mutations are not sent again; reads inspect current state.
Changing input requires `--new-attempt`, which creates new idempotency keys and
can encounter normal uniqueness constraints.
