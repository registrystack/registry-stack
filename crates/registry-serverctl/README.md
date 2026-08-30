# Registry Server CLI

`registry-serverctl` provides deterministic authoring and operator workflows
for Registry Server. It delegates model compilation, artifact generation,
package verification, and migration behavior to the `registry-server` library
rather than defining parallel semantics.

AI-assisted tools may invoke this CLI, but receive no separate authority to
sign or apply production changes.

`registry-serverctl package PROJECT --database-id ID --schema-fingerprint
SHA256 --output BUILD` always recompiles with the production profile. It writes
the exact canonical `BUILD/signing-input.json`.
For a non-local environment it reports `awaiting_signatures` and creates no
package until a later invocation supplies an external signature document. It
has no signing command and never receives private key material. The required
schema fingerprint is the exact digest from the separately reviewed
PostgreSQL rehearsal, not a compiler approximation.

`registry-serverctl apply --runtime-config ACTIVE_RUNTIME --package TARGET`
loads the package selected by the runtime configuration as the verified
current state, verifies the separate target with activation intent, resolves
the configured database secret, and delegates the closed plan to the server
library. `--initial` is explicit and also requires the runtime package binding
to name the sequence-one target. There is no maintenance-clear, arbitrary SQL,
down-migration, role grant, or signing path in the CLI.

`registry-serverctl diff PROJECT` compiles the candidate in authoring mode and
compares it with a closed, rederived package baseline. Exactly one baseline is
required: `--runtime-config ABSOLUTE_FILE` verifies configured deployment and
trust bindings without opening runtime dependencies, while `--package
DIRECTORY` performs integrity-only inspection and grants no activation
authority.

`registry-serverctl explain events PROJECT [--production]` renders only the
compiler's deterministic event-delivery inventory. It contains logical
destination identifiers and governed delivery policy, never deployed URLs,
secret references, or secret values.

`registry-serverctl webhook sample PROJECT --event ID` compiles the authoring
project and renders a deterministic CloudEvents HTTP request with typed
synthetic projection values. The request target and signature are explicit
placeholders because this offline command does not load deployment
configuration or secrets.

`registry-serverctl webhook list --runtime-config ABSOLUTE_FILE [--limit N]`
verifies the current package and database identity before returning bounded
pending, dead-lettered, and expired metadata. The default limit is 50 and the
product maximum is 100. Results contain delivery identity, state, attempt,
payload eligibility, and expiry only. They never contain projected values,
record identifiers, destination URLs, secret references, or keys.

`registry-serverctl webhook replay --runtime-config ABSOLUTE_FILE --event-id
UUID --delivery-id ID --expected-generation N` delegates one optimistic replay
to Registry Server. Replay is limited to a current, replay-enabled dead letter
whose retained payload and exact destination binding are still available.
Configuration, identity, generation, eligibility, and retention refusals share
one value-free diagnostic.

`registry-serverctl doctor --runtime-config ABSOLUTE_FILE` verifies the startup
dependencies opened by the current preparation path without binding a
listener. It does not claim listener activation, webhook worker readiness, or
webhook delivery readiness.

JSON failures expose only CLI-owned diagnostics with the stable keys
`severity`, `code`, `artifact`, `path`, `message`, and `suggestedAction`.
`artifact` is a logical source or operation identifier, never a filesystem
path. `suggestedAction` is a closed snake-case identifier and never contains
authored or deployed values. Human diagnostics retain the existing
`severity/code/path/message` rendering.
