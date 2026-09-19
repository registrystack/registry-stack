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
digest and length, the chunking algorithm `greedy-canonical-http-batch-v1`, and
the expected item and chunk counts. A run refuses any other algorithm, so
remaining source bytes are never reinterpreted under a different chunking
contract. `maximumItems` and `maximumBytes` on the run are the compiled batch
bounds every chunk stays inside.

Every operation rechecks current profile authority against the compiled batch
route. A run id is not a capability: visibility is creator-scoped, another
caller's run and an unknown run answer the same concealed 404, and a caller
whose profile no longer satisfies the binding makes no progress.

## Chunk protocol

A submission names the run, the expected chunk index, the chunk digest, and the
rolling input-prefix digest. The three digest and index members must match the
run's committed prefix exactly; a divergent value is refused and nothing is
written. The ingestion routes take no `Idempotency-Key` header: the server
derives the attempt key from the run id, input digest, chunk index, and chunk
digest, so resubmitting the exact chunk replays the original receipt instead of
writing again.

Chunk mutations, record revisions, run audit, the idempotency receipt, and the
checkpoint advancement commit in one transaction. A fault after that commit is
recovered by reading the run and replaying the chunk, never by a second
mutation.

## States

A run is `open`, `complete`, `cancelled`, or `blocked`. An open run whose
package or schema binding no longer matches the active package reports
`blocked` with reason `activePackageChanged`; it is retained and inspectable,
and a successor run created under the new binding carries the work forward. A
cancelled run keeps its counts and its audit. The last attempt is classified as
`committed`, `replayed`, `invalidItem`, `refused`, `bindingChanged`,
`chunkMismatch`, `runNotOpen`, or `unavailable`.

## Value-free surfaces

Run list and read responses carry operational metadata and bounded failure
classifications only: no source rows, no committed record values, and no chunk
bodies. Problem codes are `ingestion.profile_mismatch`,
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
is erased. A later receipt read answers
`410 ingestion.receipt_erased`; the chunk and its counts stay visible in the
run.

## Contract material

The delivery row is `BREG-V1-INGESTION-RUNS` in
`contracts/definition-of-done.yaml`, the acceptance scenarios are journey
`BREG-J21` in `contracts/acceptance-scenario-matrix.yaml`, and the security
rows are `BREG-SEC-70` through `BREG-SEC-77` in
`contracts/security-invariant-matrix.yaml`. The published HTTP reference is
`docs/site/src/content/docs/reference/breg-api.mdx`; the operator procedure is
`docs/site/src/content/docs/operate/breg-data.mdx`.
