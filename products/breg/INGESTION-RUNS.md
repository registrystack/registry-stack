# Durable ingestion runs

An ingestion run is the durable, caller-driven account of one bulk import. The
client keeps the source file and submits one bounded chunk at a time; the run
keeps the checkpoint, the committed prefix, and the receipt of every committed
chunk. Source rows never reach the run tables. The protocol is synchronous:
no server worker, no scheduling, no automatic retries, no server-side file
storage, no GUI, and no privileged database load path. A run drives the same
compiled batch route an ordinary batch client uses, one chunk at a time.

## Binding

Creating a run binds the active package revision, the schema fingerprint, the
entity, the selected access profile, the create-or-patch operation, the input
digest and a positive length, the chunking algorithm
`greedy-canonical-http-batch-v1`, and the expected item and chunk counts. A run refuses any other algorithm, so
remaining source bytes are never reinterpreted under a different chunking
contract. `maximumItems` and `maximumBytes` on the run are the compiled batch
bounds every chunk stays inside. `maximumBytes` bounds the chunk's canonical
batch body; the request envelope that wraps it (chunk index, content and
length digests, and their member names) is read under a separate fixed
transport ceiling of the compiled batch byte ceiling plus 1 KiB, so a chunk
the run's own bounds admit is never refused for the envelope that carries it.

Every operation rechecks current profile authority against the compiled batch
route. A run id is not a capability: visibility is creator-scoped, another
caller's run and an unknown run answer the same concealed 404, and a caller
whose profile no longer satisfies the binding makes no progress. The claim
context a run is bound to covers the caller's task grant when the claims carry
one, the same member the ordinary idempotency binding carries, so two sibling
grants are never one authority; every operation re-derives that reference from
the caller's claims. Run creation also refuses an announced operation the
selected profile cannot execute to the end of every chunk, decided exactly as
an import binding decides it: the profile's operations, the item route for the
profile, and patch only on a mutable entity. The refused run never exists.

## Chunk protocol

A submission names the run, the expected chunk index, the chunk digest, and the
rolling input-prefix digest. The three digest and index members must match the
run's committed prefix exactly; a divergent value is refused and nothing is
written. Every item carries the run's announced operation and the closed
create-or-patch batch item shape, and the maintained clients refuse an item
outside that shape before the chunk encodes. The final chunk
totals the announced item count exactly and binds the whole-input digest, so a
run never completes on an underrun or a mixed-operation chunk. The ingestion
routes take no `Idempotency-Key` header: the server derives the attempt key
from the run id, input digest, chunk index, and chunk digest, so resubmitting
the exact chunk replays the original receipt instead of writing again. A
committed chunk index is answered with the retained receipt only when both the
submitted chunk digest and the submitted prefix digest match the stored ones.

Chunk mutations, record revisions, run audit, the idempotency receipt, and the
checkpoint advancement commit in one transaction. A fault after that commit is
recovered by reading the run and replaying the chunk, never by a second
mutation. Every release of a stored receipt appends a value-free disclosure
record to the run audit before the answer leaves, so an audit outage gates the
release instead of passing silently. The service-level replay and the recovery
read append it inside the same guarded record transaction that verifies the
durable registry identity, so a serving instance a successor activation has
left stale refuses the release with an outage and commits nothing: no
disclosure record, and for the replay no replayed attempt marker either. The
row-lock replay a duplicate submission takes when a concurrent submission
already committed the chunk appends it in the same transaction as its attempt
record, inside the run lock that decided the replay. A fresh submission's
first release needs no
disclosure record of its own: its terminal and run-committed audit records,
written in the same transaction as the receipt it stores, already account for
that release.

## States

A run is `open`, `complete`, `cancelled`, or `blocked`. An open run whose
package or schema binding no longer matches the active package reports
`blocked` with reason `activePackageChanged`; the report and the blocked
transition answer to the binding the database holds active, so a serving
instance a successor activation has left stale reports and blocks the run the
same way the successor does. A blocked run is retained and inspectable,
and a successor run created under the new binding carries the work forward. A
committed chunk replays its receipt in any run status, including blocked: the
binding governs only chunks the checkpoint has not covered, and the replay is
compared against the run's own stored bounds, so a successor package that
lowers the batch ceilings cannot strand the committed prefix. A cancelled run
keeps its counts and its audit; cancellation records the last attempt as
`refused` with no chunk index, because cancellation is not a chunk attempt,
and it takes the same guarded record transaction run creation takes, so a
stale instance answers an outage instead of closing a run its successor can
still resume.
The last attempt is classified as
`committed`, `replayed`, `invalidItem`, `refused`, `bindingChanged`,
`chunkMismatch`, `runNotOpen`, or `unavailable`.

## Value-free surfaces

Run list and read responses carry operational metadata and bounded failure
classifications only: no source rows, no committed record values, and no chunk
bodies. The listing answers on the access context the caller presents, the
same bound context every per-run operation enforces, so a changed profile,
purpose, row-boundary, or grant context lists none of another context's runs
even under the same principal. Reading one run owes the run the same
admission, so a drifted context is refused with `ingestion.profile_mismatch`
rather than shown the run's binding, digest, counts, or progress. Its status
filter answers on the status a run document renders: after a successor
package activation, `status=blocked` finds the stored-open runs the durable
binding retired, and `status=open` returns only runs that still match the
active binding. The page renders against the very binding its own filter
read, so a package activation cannot fall between the filter and the
rendering. Problem codes are
`ingestion.profile_mismatch`,
`ingestion.run_not_open`, `ingestion.run_blocked`, `ingestion.chunk_mismatch`,
and `ingestion.receipt_erased`, alongside the ordinary `request.invalid`,
`resource.not_found`, `precondition.failed`, and `service.unavailable`
refusals.

## Recovery

| Failure | Contracted recovery |
| --- | --- |
| Lost response after a commit | Reread the run and replay the exact chunk; the original receipt returns. |
| Transport interruption | Resubmit the chunk `nextChunkIndex` names. |
| Invalid item or business refusal | Keep the checkpoint and start a successor run. Row skipping is never a default recovery. |
| Authorization lost | Refuse progress. |
| Package or schema binding changed | Block the run; continue in a successor run. |
| Operator stop | Explicit cancel, preserving counts and audit. |

## Retention

A chunk receipt holds exactly what the ordinary batch route answers the same
authorized caller with, and it is erased when the record history it describes
is erased, through the revision the erasure names: a receipt describing only
later revisions of the same record survives. A later receipt read answers
`410 ingestion.receipt_erased`; the chunk and its counts stay visible in the
run.

Over an entity with encrypted fields, a receipt stores the sealed field
envelopes exactly as the ordinary batch route stores them, and every release
path, the fresh answer, the replay, and the recovery read, opens those members
at the same serve edge the batch route opens its answers. The stored receipt
bytes stay sealed, and a process without key state, or one whose open fails,
answers `service.unavailable` instead of releasing an envelope.

Every release of a retained receipt re-projects the stored answer through the
field identities it was committed under: chunk commit stores, beside the
receipt, the map of each answer member to the logical field that produced it,
and a member is retained only while that field is still a readable field of
the run's profile carrying the same API name in the current package. A
successor that revokes or renames a readable field drops that member from
every later release, and a successor that retires a field while reusing its
API name inherits none of its stored value, while the members the successor
still grants keep serving, encrypted ones included. A live receipt whose row
lost its map is refused as an outage. A member that still parses as a sealed envelope in a receipt
stored under a package the database no longer holds active fails the release
closed with `service.unavailable`, unless the active entity declares that
member's field encrypted; a successor that retires the encryption itself
therefore still answers closed, and the envelope stays sealed at rest. An
envelope-shaped value stored under the package the database still holds active
is caller data, never refused for its shape, and the ordinary batch route's
idempotency answer never takes that closed check at all, because its key binds
the package revision that produced it.

Releasing a retained receipt is a protected read: a serving instance whose
package a successor retired answers `service.unavailable` on the replay and
the recovery read instead of releasing, and a current instance serves the
receipt the committed prefix retains.

## Contract material

The delivery row is `BREG-V1-INGESTION-RUNS` in
`contracts/definition-of-done.yaml`, the acceptance scenarios are journey
`BREG-J21` in `contracts/acceptance-scenario-matrix.yaml`, and the security
rows are `BREG-SEC-75` through `BREG-SEC-82` in
`contracts/security-invariant-matrix.yaml`. The published HTTP reference is
`docs/site/src/content/docs/reference/breg-api.mdx`; the operator procedure is
`docs/site/src/content/docs/operate/breg-data.mdx`.
