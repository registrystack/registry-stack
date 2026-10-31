# Camel 4.23.0 side-by-side port review

A read-only comparison of the ported engine against the pinned Camel
clone, judging semantic fidelity against the port table, recorded
versus unrecorded divergences, and whether the implementation reads as
a Rust port or translated Java. Reviewed areas: the file source
(readLock, doneFileName, include glob, maxMessagesPerPoll), CSV and
JSONL decoders, pollEnrich, split and loop, redelivery, circuit
breaker and throttle, idempotent consumer, the exchange property
model, and the postgres source beside camel-sql.

## Verdict

The port reads as a genuine Rust port of Camel's behavior, not
translated Java: the EIPs are free functions over an owned exchange
with enum faults and closed error classes instead of Processor and
AsyncCallback machinery; resilience state is Arc-shared per node
rather than per-processor singletons; options are typed and bounded at
the reader rather than stringly-typed setters; the transport layer
compiles once into frozen templates behind traits; and the value-free
diagnostics discipline holds everywhere, with every journal fact a
closed name or a count. Spot-verified fidelity is strong: the changed
read lock's two-equal-checks shape, the doneFileName substitution and
refusal grammar, the maxMessagesPerPoll window-after-cursor placement,
the split default (UseOriginal with propagate), the redelivery delay
order, the breaker's resilience4j defaults, the throttle's rolling
window, SqlConsumer-style typed parameter binding with the onConsume
exclusion recorded, and exact CamelSplit and CamelLoop property names.

## Findings and their disposition

1. P1, file source hidden files: Camel always skips dot-file names;
   the port admitted them. FIXED: `candidates()` skips names beginning
   with a dot, and the module doc cites `isMatchedHiddenFile`.
2. P1, CSV short records: the core port record claimed a per-item
   refusal while the landed decoder pads missing members with the
   empty string. FIXED: the port-record row now records the padding as
   the deliberate divergence from Camel's silent short map.
3. P2, CSV trim also trims quoted fields, where Commons CSV trims
   unquoted only. RECORDED in the port-record `trim` and
   `ignoreSurroundingSpaces` rows.
4. P2, split drops a failure-accounted piece from the merged result
   where Camel folds it. RECORDED in the split module doc and the 8.10
   Splitter row (the omission is the deliberate choice; a failed piece
   has no body worth merging).
5. P2, loop restores the pre-iteration exchange on error where Camel
   copies the failed iteration's results back. RECORDED as a
   divergence in the loop module doc and the 8.10 Loop row, replacing
   a doc sentence that had claimed the behaviors matched.
6. P2, readLock carried as a runtime-checked string beside an existing
   enum. FIXED: the reader carries the closed `ReadLockName` set, so an
   unknown lock name refuses at the reader and never reaches a read.
7. P3, the sortBy default claim misstated Camel (Camel ships no
   default sorter). FIXED: the doc names name-ascending as an addition
   for the cursor's stable resume order.
8. P3, the breaker's node key is a pointer address under a documented
   invariant. NOTED as a follow-up in the engine2 port record, with
   the structural-key direction; not churned in this pass.
9. P3, CamelSplitResult omits the per-item failures map and the
   aborted flag. RECORDED in the split module doc (value-free
   contract; the raised failure is the abort).
10. P3, done-file matching checks both static sides where Camel checks
    one. RECORDED in the engine2 port record (ours recognizes the
    spelling Camel's own createDoneFileName produces).
11. P3, the redelivery delay cap is always on; Camel's zero disables
    it. RECORDED in the engine2 port record beside the
    maxMessagesPerPoll precedent.
12. P3, CamelExceptionCaught moved from exchange property to header
    and from throwable to class name. RECORDED in the exchange module
    doc.
