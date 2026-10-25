# Caller-filtered application metadata

`GET /v1/registry?accessProfile=<profile>` describes the active
Base Registry Engine (BReg) contract
under the selected caller and profile. Discovery grants no authority: execution
rechecks current package identity, verified claims, fields, rows, and operation
grants. Unknown and ungranted work remains concealed. Discard metadata, records,
ETags, cursors, and drafts when caller or profile identity changes.

The served format is `metadataVersion: "2"`. Clients refuse version 1 before
interpreting its shape; there are no aliases for retired members. Unknown
optional extensions remain ignorable within the validated version-2 grammar.

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

## Domain occurrences

A record type that declares a domain occurrence descriptor carries an
`occurrence` member, filtered for the caller and profile: `descriptorVersion`,
`label`, `recordedTime`, and only those subjects, sources, summary, correction,
source event identifier, and time mappings whose fields the profile may read.
Withheld and undeclared members are omitted, never `null`. A native `target` is
kept only when that record type is visible to the caller. The member is
additive and ignorable within `metadataVersion: "2"`, and it grants nothing.
See [Domain occurrences](occurrences.md).

## Actions

One Action descriptor carries a fixed `mode`: `immediate` or `proposal`.
It includes stable identity and revision, public names, typed inputs, reference
inputs, bounds, permitted results, required capabilities, and the promoted route
for Invoke or Start. Selection validates the descriptor before producing an
opaque client binding. Every input requires the compiler-emitted JSON Schema;
clients do not reconstruct a partial schema from a field type. The MCP gateway
copies that schema exactly. The caller cannot change its execution mode.

Request metadata for the intended `accessProfile`, select the Action from that
caller-filtered document, and prepare from the resulting binding. Do not discover
profiles by probing an Action route: an omitted profile when no default exists,
an unknown profile, and a profile unusable by the caller all return the same
concealed 404, with no list of alternatives.

For an immediate Action, `required` means the value must be present at Invoke.
For a Proposal Action, Start, Edit, Revise, and Rebase may retain an incomplete
draft; Submit enforces required inputs before any plan runs. Supplied values are
always typed and remain subject to the selected profile's input authority.

Immediate Invoke commits one atomic plan. Proposal Start returns a durable
Proposal with its own locator and revision. Generated TypeScript and Python
project types come from the same compiled contract; generic metadata clients
remain available. The facility console uses these contracts for typed Action
inputs, titles, reference navigation, refusals, and Proposal resumption.

An immediate Action with a reference input also advertises one
`routes.availability` endpoint. Each request selects one declared reference
input as its target and may include any declared input subset needed to
evaluate that target's field guards. Query several targets separately. Its
answer is advisory and names the observed revision when it is disclosed. An
unknown answer distinguishes missing form input from facts the current profile
may not read without exposing hidden fields, row boundaries, or target
existence. The route grants no token or mutation authority, and Invoke repeats
every current check at commit time. A true answer covers only the selected
target's field guards; form completeness, Functions, Evidence, other targets,
and SQL constraints may still refuse Invoke.

For build-time form generation, `bregctl generate actions PROJECT --output DIR`
writes the public `action-contracts/v1` document and its schema under
`generated/`. Check the format version and each Action's revision when consuming
it. This export is a build artifact, not an activated-package discovery endpoint.
It describes the authored contract without a caller's grants; use runtime
metadata and promoted Proposal links for current permissions and availability.
Regenerate it when the authored Action changes.

A caller-visible Proposal Action includes declared `attachments` summaries:
slot `id`, `required`, `contentTypes`, and `maximumBytes`. A starter can explain
document requirements before creating a draft. A Get-only Action description
includes only that profile's readable slots. These summaries disclose no bytes
or lifecycle links and grant no upload, download, or delete authority.

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

`proposals.actions` is a read-only inventory of each visible `actionId` and
`accessProfile` pair, its `operations`, and its `readableInputs`. Rust exposes
`proposal_actions()`, Node exposes `proposalActions`, and Python exposes
`proposal_actions` from one validated client model. Profiles are never unioned.
Start does not imply Get, and List or Apply can be advertised without a Start
route. Hosts can use the exact inventory to choose their UI; per-Proposal links
still determine currently available lifecycle operations.

Attachments expose only granted slots and operations. Respect each slot's byte
bound, content types, required-for-submit rule, verification status, and current
revision. Submission binds content digest and verification; changed bytes cannot
inherit an earlier approval. BReg sends review context, not raw attachment bytes,
to the review authority.

## Prepare, execute, recover

Retain the original prepared command with its input, target conditions, selected
binding, and idempotency key until its outcome is known. Replay of that exact
command recovers a retained result without replanning or reacquiring Evidence.
A changed command returns `409 idempotency.key-reused`. This is the only wire
code for a key bound to another request. The protocol accepts 1 to 256 visible
ASCII bytes; keep portable keys at 128 bytes or fewer for intermediaries and
client stores. Expired or erased receipts refuse execution and keep the key
spent. An accepted-submission observation is not proof that an earlier uncertain
command executed.

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
`crates/registry-breg/src/api/actions.rs`,
`crates/registry-breg/src/api/proposals.rs`,
`crates/registry-breg-client/src/metadata.rs`,
`crates/registry-breg-client/src/actions.rs`, and
`crates/registry-breg-client/src/proposal.rs`. The canonical generated examples
live under `products/breg/generated/facility*/`; change their source and generator,
never the generated copy.
