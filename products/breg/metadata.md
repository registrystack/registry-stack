# Caller-filtered application metadata

`GET /v1/registry?accessProfile=<profile>` describes the active registry contract
under the selected caller and profile. Discovery grants no authority: execution
rechecks current package identity, verified claims, fields, rows, and operation
grants. Unknown and ungranted work remains concealed. Discard metadata, records,
ETags, cursors, and drafts when caller or profile identity changes.

## Record types and operations

The authoring model declares `recordTypes`. Runtime metadata describes configured
record operations, their exact method and path, selected access profile, fields,
request contract, query capabilities, and required capabilities. Use the served
operation descriptor instead of constructing a path from a record label.

Field IDs are stable authored identities. `apiName` is the exact wire property;
never derive it by changing case or punctuation. Requiredness, nullability,
readability, writability, removability, value schema, and native storage
validation are separate properties. PostgreSQL regular-expression validation is
not a JavaScript validator. Preserve int64 values and fixed-scale decimals
without lossy conversion.

Display labels and safe instance titles help applications present the contract;
render them as plain text. A title exposes only fields the current profile may
read. Reference descriptors and bounded forward/inverse navigation reuse normal
record authority. A link or relationship never grants target disclosure.

## Actions

One Action descriptor carries a fixed `execution.mode`: `immediate` or `proposal`.
It includes stable identity and revision, public names, typed inputs, reference
inputs, bounds, permitted results, required capabilities, and the promoted route
for Invoke or Start. Selection validates the descriptor before producing an
opaque client binding. Every input requires the compiler-emitted JSON Schema;
clients do not reconstruct a partial schema from a field type. The MCP gateway
copies that schema exactly. The caller cannot change its execution mode.

Immediate Invoke commits one atomic plan. Proposal Start returns a durable
Proposal with its own locator and revision. Generated TypeScript and Python
project types come from the same compiled contract; generic metadata clients
remain available. The facility console uses these contracts for typed Action
inputs, titles, reference navigation, refusals, and Proposal resumption.

## Proposals and promoted links

Proposal representations are distinct from Registry Record envelopes. An
ordinary authorized Get carries `id`, `actionId`, `actionRevision`,
`submissionVersion`, `revision`, `state`, the frozen `effectDigest` when known,
and caller-authorized links. Disclosed inputs, attachments, application evidence,
and `applicationStatus` follow their independent permissions and retention.

Keep the exact Action revision, submission version, and effect digest while
observing progress. Revise or Rebase makes the earlier frozen binding stale.
A consumer must not silently follow the successor. `applicationStatus` reports
local application state, a safe blocked reason and recovery hint, and bounded
automatic retry information where applicable. Applied work exposes retained
application evidence. Get does not aggregate another product's live status or
reconcile an uncertain Start or Submit.

Promote links only through a client-bound Proposal. Validate origin, registry
base, method, selected profile, operation binding, and the strong lifecycle
condition. Never substitute a record ETag, invent a lifecycle URL, or follow a
credential-bearing redirect. Refetch after a transition and select a new link.
List requires explicit List authority and conceals inaccessible work before
filtering or counting; Get alone does not permit collection discovery.

Attachments expose only granted slots and operations. Respect each slot's byte
bound, content types, required-for-submit rule, verification status, and current
revision. Submission binds content digest and verification; changed bytes cannot
inherit an earlier approval. BReg sends review context, not raw attachment bytes,
to the review authority.

## Prepare, execute, recover

Retain the original prepared command with its input, target conditions, selected
binding, and idempotency key until its outcome is known. Replay of that exact
command recovers a retained result without replanning or reacquiring Evidence.
A changed command conflicts. Expired or erased receipts refuse execution and
keep the key spent. An accepted-submission observation is not proof that an
earlier uncertain command executed.

`requiredCapabilities` is a must-understand execution gate. An unsupported
capability disables its operation. Unknown optional object members remain
ignorable within the client's validated grammar; malformed required members,
duplicate identities, resource bounds, and broken references refuse selection.
A descriptor alone never permits an operation under another profile.

## Queries and response contracts

Use the advertised `$filter`, `$orderby`, `$select`, `$top`, and `$count` query
capabilities and bounds. Filters reduce a permitted collection; they do not
supply authorization. Continuation uses the opaque cursor and selected profile.
References, spatial reads, historical reads, and statistical datasets expose
only their declared capability variants.

Record routes use the shared Registry Record v1 envelope. Its independently
versioned `entityTypeIdentifier` names the Record type; it is not a BReg authoring
key. Action receipts and Proposals have separate response contracts. All responses
use `Cache-Control: no-store`. `/v1/registry` also carries
`Registry-Engine-Version` for matching-build consumers; concealed responses
publish no version hint.

Owning implementation: `crates/registry-breg/src/api/mod.rs`,
`crates/registry-breg/src/api/proposals.rs`,
`crates/registry-breg-client/src/metadata.rs`,
`crates/registry-breg-client/src/actions.rs`, and
`crates/registry-breg-client/src/proposal.rs`. The canonical generated examples
live under `products/breg/generated/refactor*/`; change their source and generator,
never the generated copy.
