# Base Registry Engine CLI

`bregctl` provides deterministic authoring and operator workflows
for Base Registry Engine. It delegates model compilation, artifact generation,
package verification, and migration behavior to the `breg` library
rather than defining parallel semantics.

AI-assisted tools may invoke this CLI, but receive no separate authority to
sign or apply production changes.

`bregctl examples list PROJECT` describes the project's declared teaching
scenarios and retained attempts without starting services or creating credentials.
`bregctl examples run SCENARIO PROJECT` uses only that project's ready owned
`bregctl dev` instance. The fixed scenarios are `starter-data`, `first-record`
and `reviewed-change`. Inputs default to the file declared in
`examples/scenarios.json`; `--input FILE` selects a separately editable JSON file.
The runner uses ordinary native client authorization and never issues a schema-test
receipt. It accepts no remote endpoint, database credential or script.

The examples v1 catalogue is a closed JSON object with `version: 1` and a
`scenarios` array. Each scenario declares `id`, `description`, `input` (a relative
file under `examples/`) and `steps`. Every step declares `id`, `operation`,
`entity`, `client` and `accessProfile`. A `create` step additionally declares an
`input` payload key and `capture` alias; other steps declare a `record` alias.
Inputs contain exactly those named payload objects. A field reference uses the
same exact `{ "recordRef": "alias" }` form as authored fixtures. Captures must
precede references, and their entity must match the native metadata's reference
field target. The catalogue and input files are each bounded to 1 MiB; scenarios
have at most 100 steps and nested reference inputs at most 32 levels. Payloads
are checked against caller-filtered create schemas before the first mutation.

`first-record` creates one independent record and reads its returned UUID. Running
it again with `--attempt ID` reads that same record without repeating the create.
`reviewed-change` imports one completed first-record attempt; use
`--from-attempt ID` when more than one exists. Its seven declared steps are
`draft` (`create`), `submit`, `inspect` (`get`), `approve`, `reject`, `apply` and
`history`. Run `--step submit` (the default) to create and submit the draft, then
explicitly run `--step inspect`, `--step approve` or `--step reject`, and
`--step apply` after approval. Approval alone does not change the target record.
`--step history` reads the native revision endpoint's first page and retains its
pagination information in the output; the runner does not follow pages.

Every mutation first persists its exact native request or action, preconditions
and attempt-scoped idempotency key in owner-only `.breg/dev/examples` state.
Returned UUIDs are persisted before dependent writes. Uncertain operations resume
through the native client's validated recovery API with the original action,
including when an applied action is no longer advertised on the current record.
A completed mutation never repopulates an edited or deleted sample. Attempts bind
exact source, package, clients, scenario and input bytes plus the owned database
container identity. Ordinary stop/start retains attempts; explicit database
removal invalidates them. Changed inputs require `--new-attempt` and ordinary
uniqueness checks. Concurrent examples and dev lifecycle changes share the dev
lock. Failures retain partial progress and never reset the registry; list attempts
and resume the original command. Successful reports include UUIDs and the actual
next command.

`bregctl project lock PROJECT` computes the compiler-enforced
digests for discovered `modules/<id>/module.yaml` sources and their declared
SQL assets, then rewrites only `PROJECT/registry.yaml`. `--check` performs the
same deterministic comparison without writing and fails when locks are stale.

`bregctl project migrate PROJECT` is the only reader for the retired
singular Manifest projection dialect. By default it prints a deterministic,
reviewable diff and writes nothing. `--write` explicitly applies the same bytes,
including module entity memberships and refreshed module locks. The rewrite
preserves the explicit legacy dataset id or its effective `registry.id`
fallback, uses the already governed catalogue base URL as `canonicalBaseIri`,
and proposes `<registry-id>-authority` and `<registry-id>-service` for review.
It preserves comments, scalar quoting, and unrelated key order in conventional
block-style YAML. Ambiguous flow-style or partially migrated source fails closed
with a manual-rewrite diagnostic instead of being reformatted.

`bregctl explain queries PROJECT [--production]` renders query
operations using HTTP API field names as the primary copyable identifiers.
Every filterable, sortable, and selector field also includes its logical field
id so authors can trace the output back to source.

`bregctl package PROJECT --database-id ID --schema-fingerprint
SHA256 --output BUILD` always recompiles with the production profile. It writes
the exact canonical `BUILD/signing-input.json`.
For a non-local environment it reports `awaiting_signatures` and creates no
package until a later invocation supplies an external signature document. It
has no signing command and never receives private key material. The required
schema fingerprint is the exact digest from the separately reviewed
PostgreSQL rehearsal, not a compiler approximation.

`bregctl apply --runtime-config ACTIVE_RUNTIME --package TARGET`
loads the package selected by the runtime configuration as the verified
current state, verifies the separate target with activation intent, resolves
the configured database secret, and delegates the closed plan to the server
library. `--initial` is explicit and also requires the runtime package binding
to name the sequence-one target. There is no maintenance-clear, arbitrary SQL,
down-migration, role grant, or signing path in the CLI.

`bregctl diff PROJECT` compiles the candidate in authoring mode and
compares it with a closed, rederived package baseline. Exactly one baseline is
required: `--runtime-config ABSOLUTE_FILE` verifies configured deployment and
trust bindings without opening runtime dependencies, while `--package
DIRECTORY` performs integrity-only inspection and grants no activation
authority.

`bregctl explain events PROJECT [--production]` renders only the
compiler's deterministic event-delivery inventory. It contains logical
destination identifiers and governed delivery policy, never deployed URLs,
secret references, or secret values.

`bregctl webhook sample PROJECT --event ID` compiles the authoring
project and renders a deterministic CloudEvents HTTP request with typed
synthetic projection values. The request target and signature are explicit
placeholders because this offline command does not load deployment
configuration or secrets.

`bregctl webhook list --runtime-config ABSOLUTE_FILE [--limit N]`
verifies the current package and database identity before returning bounded
pending, dead-lettered, and expired metadata. The default limit is 50 and the
product maximum is 100. Results contain delivery identity, state, attempt,
payload eligibility, and expiry only. They never contain projected values,
record identifiers, destination URLs, secret references, or keys.

`bregctl webhook replay --runtime-config ABSOLUTE_FILE --event-id
UUID --delivery-id ID --expected-generation N` delegates one optimistic replay
to Base Registry Engine. Replay is limited to a current, replay-enabled dead letter
whose retained payload and exact destination binding are still available.
Configuration, identity, generation, eligibility, and retention refusals share
one value-free diagnostic.

`bregctl doctor --runtime-config ABSOLUTE_FILE` verifies the startup
dependencies opened by the current preparation path without binding a
listener. It does not claim listener activation, webhook worker readiness, or
webhook delivery readiness.

JSON failures expose only CLI-owned diagnostics with the stable keys
`severity`, `code`, `artifact`, `path`, `message`, and `suggestedAction`.
`artifact` is a logical source or operation identifier, never a filesystem
path. `suggestedAction` is a closed snake-case identifier and never contains
authored or deployed values. Human diagnostics retain the existing
`severity/code/path/message` rendering.
