# Camel collection and direct attribution

Date: 2026-10-31

## Scope and source freeze

This is a bounded attribution review for the Adapter's `split`, `loop`,
`enrich`, aggregation-strategy, and `direct` conformance cases. It does not
repeat the broader C6a review and does not claim full Camel conformance from
source citations alone.

The read-only reference was
`/Volumes/CodexWorktrees/agent-scratch/camel-src/camel-4.23.0`, exact tag
`camel-4.23.0`, commit `b2329103df8f5d1edfca2ad262be09e3be95ee68`.
The reference tree was clean. It was neither edited nor built.

## Applicable Camel methods mapped to Adapter tests

Paths below are relative to the pinned Camel tree. A row means that the named
Camel method exercises behavior within the Adapter's bounded port and that the
named Rust test now cites and asserts that behavior. The Rust tests remain the
evidence. The citation is provenance, not a substitute for an assertion.

| Behavior | Camel 4.23.0 unit-test methods | Adapter test |
|---|---|---|
| Split index and size | `core/camel-core/src/test/java/org/apache/camel/processor/SplitterTest.java#testSendingAMessageUsingMulticastReceivesItsOwnExchange` | `split_runs_each_piece_under_engine_properties_and_returns_the_original` |
| Split completion flag | `core/camel-core/src/test/java/org/apache/camel/processor/SplitterCompletedPropertyTest.java#testSplitterCompleted` | `split_runs_each_piece_under_engine_properties_and_returns_the_original` |
| No explicit strategy leaves the original result | `core/camel-core/src/test/java/org/apache/camel/processor/SplitterNoAggregationStrategyTest.java#testSplitNoAggregationStrategy` | `split_runs_each_piece_under_engine_properties_and_returns_the_original` |
| `use-latest` returns the final piece | `core/camel-core/src/test/java/org/apache/camel/processor/SplitterTest.java#testSplitterWithAggregationStrategy` | `split_use_latest_returns_the_last_piece` |
| Default `stopOnException: false` finishes the split before surfacing failure | `core/camel-core/src/test/java/org/apache/camel/processor/SplitterNoStopOnExceptionTest.java#testSplitNoStopOnExceptionStop` | `split_item_failures_raise_after_the_split_or_sooner_or_never` |
| `stopOnException: true` stops on the first failure | `core/camel-core/src/test/java/org/apache/camel/processor/SplitterStopOnExceptionTest.java#testSplitStopOnExceptionStop` | `split_item_failures_raise_after_the_split_or_sooner_or_never` |
| `use-original` can suppress or propagate piece failure | `core/camel-core/src/test/java/org/apache/camel/processor/SplitterUseOriginalNotPropagateExceptionTest.java#testUseOriginalNotPropagateException`; `core/camel-core/src/test/java/org/apache/camel/processor/SplitterUseOriginalPropagateExceptionTest.java#testUseOriginalPropagateException` | `split_item_failures_raise_after_the_split_or_sooner_or_never` |
| Failure ratio continues below its threshold and aborts at it | `core/camel-core/src/test/java/org/apache/camel/processor/SplitterErrorThresholdTest.java#testErrorThresholdBelowRatio`; `core/camel-core/src/test/java/org/apache/camel/processor/SplitterErrorThresholdTest.java#testErrorThresholdStopsWhenRatioExceeded` | `split_failure_accounting_counts_stops_and_reports` |
| Combined ratio and failed-record bounds abort on the first reached condition | `core/camel-core/src/test/java/org/apache/camel/processor/SplitterErrorThresholdTest.java#testCombinedErrorThresholdAndMaxFailedRecords` | `split_failure_accounting_counts_stops_and_reports` |
| Failed-record count aborts at its threshold | `core/camel-core/src/test/java/org/apache/camel/processor/SplitterMaxFailedRecordsTest.java#testMaxFailedRecordsStopsAfterThreshold` | `split_failure_accounting_counts_stops_and_reports` |
| `CamelSplitResult` accounts for a completed split containing failures | `core/camel-core/src/test/java/org/apache/camel/processor/SplitterSplitResultTest.java#testSplitResultWithFailures` | `split_failure_accounting_counts_stops_and_reports` |
| `CamelSplitResult` covers all-success, aborted, and empty accounting, and remains absent without accounting | `core/camel-core/src/test/java/org/apache/camel/processor/SplitterSplitResultTest.java#testSplitResultAllSuccess`; `core/camel-core/src/test/java/org/apache/camel/processor/SplitterSplitResultTest.java#testSplitResultWhenAborted`; `core/camel-core/src/test/java/org/apache/camel/processor/SplitterSplitResultTest.java#testSplitResultEmptyInput`; `core/camel-core/src/test/java/org/apache/camel/processor/SplitterSplitResultTest.java#testNoSplitResultWithoutErrorThreshold` | `split_failure_accounting_counts_stops_and_reports`; `split_item_failures_raise_after_the_split_or_sooner_or_never` |
| Count loop repeats and exposes index and size | `core/camel-core/src/test/java/org/apache/camel/processor/LoopTest.java#testCounterLoop`; `core/camel-core/src/test/java/org/apache/camel/processor/LoopTest.java#testLoopProperties` | `a_count_loop_repeats_with_loop_properties` |
| `doWhile` observes the current exchange | `core/camel-core/src/test/java/org/apache/camel/processor/LoopDoWhileTest.java#testLoopDoWhileSimple` | `a_do_while_loop_tests_its_predicate_before_each_iteration` |
| Default loop chains each iteration; `copy` restarts from the input | `core/camel-core/src/test/java/org/apache/camel/processor/LoopNoCopyTest.java#testLoopNoCopy`; `core/camel-core/src/test/java/org/apache/camel/processor/LoopCopyTest.java#testLoopCopy` | `copy_mode_starts_each_iteration_from_the_original_and_keeps_the_last` |
| An iteration failure stops both no-copy and copy loops | `core/camel-core/src/test/java/org/apache/camel/processor/LoopExceptionTest.java#testLoopException`; `core/camel-core/src/test/java/org/apache/camel/processor/LoopCopyErrorTest.java#testLoopCopy` | `an_iteration_failure_stops_copy_and_no_copy_loops` |
| Default enrich replaces the body | `core/camel-core/src/test/java/org/apache/camel/processor/enricher/EnricherDefaultAggregationStrategyTest.java#testEnrichInOut` | `direct_enrich_runs_the_resource_route_on_a_copy`; `enrich_merges_the_resource_reply_through_its_strategy` |
| Custom enrich strategy sees both exchanges | `core/camel-core/src/test/java/org/apache/camel/processor/enricher/EnricherTest.java#testEnrichInOut` | `enrich_merges_the_resource_reply_through_its_strategy` |
| A header on the original exchange survives enrichment | `core/camel-core/src/test/java/org/apache/camel/processor/enricher/EnricherTest.java#testEnrichInOutPlusHeader` | `direct_enrich_runs_the_resource_route_on_a_copy`; the same Adapter test's resource-header discard is an Adapter-only assertion |
| `aggregateOnException` controls whether the strategy receives a failed resource exchange | `core/camel-core/src/test/java/org/apache/camel/processor/enricher/EnricherAggregateOnExceptionTest.java#testEnrichTrueKaboom`; `core/camel-core/src/test/java/org/apache/camel/processor/enricher/EnricherAggregateOnExceptionTest.java#testEnrichFalseKaboom` | `enrich_failure_propagates_unless_it_aggregates_on_exception` |
| Direct request-reply returns target body changes on the same synchronous flow | `core/camel-core/src/test/java/org/apache/camel/component/direct/DirectNoToTypeTest.java#testNoToType`; `core/camel-core/src/test/java/org/apache/camel/component/direct/DirectShouldUseSameThreadTest.java#testUseSameThread` | `a_direct_call_shares_the_exchange_and_its_changes` |
| Missing direct consumer fails InOut | `core/camel-core/src/test/java/org/apache/camel/component/direct/DirectNoConsumerTest.java#testInOut` | `a_direct_send_to_an_undeclared_route_fails_the_exchange`; `an_undeclared_direct_target_is_refused_at_load`, with the Adapter's earlier load-time refusal as an addition |
| Camel redelivers through a direct subroute | `core/camel-core/src/test/java/org/apache/camel/processor/RedeliverToSubRouteRemoveHeadersDecrementTest.java#testDecrementCounterWithRemoveHeaders` | `a_direct_send_is_never_redelivered`, as the contract's deliberate opposite behavior |

The table maps 33 distinct Camel methods to 15 Adapter test functions. Some
Adapter functions cover more than one upstream case, and two Adapter tests
share one upstream default-enrich method.

## Source contradiction resolved

The pinned implementation and its tests store split and loop metadata as
exchange properties:

- `core/camel-core-processor/src/main/java/org/apache/camel/processor/Splitter.java`
  calls `exchange.setProperty` for `SPLIT_INDEX`, `SPLIT_SIZE`, and
  `SPLIT_COMPLETE`.
- `core/camel-core-processor/src/main/java/org/apache/camel/processor/LoopProcessor.java`
  calls `setProperty` for `LOOP_SIZE` and `LOOP_INDEX`.
- `SplitterTest#testSendingAMessageUsingMulticastReceivesItsOwnExchange`,
  `SplitterCompletedPropertyTest#testSplitterCompleted`, and
  `LoopTest#testLoopProperties` read exchange properties.

The Adapter now follows that placement: `CamelSplitIndex`, `CamelSplitSize`,
`CamelSplitComplete`, `CamelSplitResult`, `CamelLoopIndex`, and
`CamelLoopSize` are engine-owned exchange properties. They have no message
header aliases. The focused tests assert the properties and the absence of the
old headers. Authoring checks refuse set, remove, conversion, and declarative
strategy writes to those exact case-sensitive names. The runtime also rejects
reserved property writes returned dynamically by a custom Rhai aggregation
strategy before either split or enrich can apply them.

## Upstream cases outside the bounded port

These cases were inspected but must not be presented as ported:

| Camel method or family | Disposition |
|---|---|
| `SplitterTest#testSendingAMessageUsingMulticastReceivesItsOwnExchangeParallel`, `#testSplitterWithAggregationStrategyParallel`, `#testSplitterWithAggregationStrategyParallelStreaming`, `#testSplitterParallelAggregate` | Not applicable. `parallelProcessing` and `streaming` are explicitly not ported. |
| `SplitterGroupTest#testSplitterGroup`, `#testSplitterGroupExactMultiple`, `#testSplitterGroupSingleItem`, `#testGroupWithMaxFailedRecords` | Not applicable. Camel's splitter `group` option is not ported. This is separate from the supported `grouped-body` aggregation strategy. |
| `SplitterOnPrepareTest#testSplitterOnPrepare` | Not applicable. `onPrepare` is not ported. |
| `SplitterMapTest#testSplitMap` and `SplitterTest#testSplitterWithIterable` | Divergence. The Adapter accepts only a JSON array and refuses maps, strings, and arbitrary Java iterables. |
| `SplitterNullBodyTest#testSplitNullBody` | Divergence. Camel treats null as no pieces; the Adapter's array-only expression rule makes null a `validation` failure. `split_refuses_its_shape_and_bound_faults` asserts the exact null edge. |
| `LoopAsyncCopyTest#testLoopCopy` and `LoopAsyncNoCopyTest#testLoopNoCopy` | No separate port case. The engine has no asynchronous processor boundary; synchronous copy and no-copy behavior is mapped above. |
| `LoopOnPrepareTest#testLoopOnPrepare` | Not applicable. Loop `onPrepare` is not ported. |
| `EnrichVariableTest#testSend`, `#testReceive`, `#testSendAndReceive` | Not applicable. Camel variables are not ported. The Adapter strategy returns only `body` and named `properties`. |
| `EnrichWithUnitOfWorkTest#testEnrichWithShareUnitOfWork` | Not applicable. `shareUnitOfWork` is not ported. |
| `DirectNoConsumerTest#testInOnly` | Not applicable. The Adapter is InOut only. |
| `DirectNoConsumerTest#testFailIfNoConsumerFalse` | Not applicable. `failIfNoConsumers` is not ported and every undeclared target is refused. |
| `DirectProducerBlockingTest#testProducerBlocksWithNoConsumers` and the suspended-consumer tests | Not applicable. `block`, `timeout`, suspension, and runtime consumer arrival are not ported; routes form one static table. |
| `DirectNoMultipleConsumersTest#testNoMultipleConsumersTest` | Structurally inapplicable. One `routeId` has one entry in the compiled route table, so a second consumer cannot be represented. |
| The stateful Aggregate EIP test suite under `processor/aggregator` | Not applicable as an EIP. The Adapter ports only named aggregation strategies inside `split` and `enrich`, not correlation repositories, completion policies, optimistic locking, recovery, or aggregate consumers. |

Adapter-only tests intentionally have no fabricated Camel method citation:
mandatory `maximumItems` and `maximumIterations`, JSON-only split input,
bounded direct depth, static target and cycle checks, the value-free failure
classes, `json-array-append`, `json-merge`, selected-property carry, reserved
collection-property protection, and the rule that a resource route's ordinary
headers do not come back. These are recorded additions or divergences in
`CONCEPT.md`.

The pinned test tree contains no focused method for a `stop` EIP inside a
split piece or inside a direct target. The Adapter cases
`a_stop_inside_a_piece_ends_the_split_and_the_route` and
`a_stop_in_the_target_ends_the_whole_route` assert the current contract, but
are not counted as mapped Camel unit tests. Likewise, no single direct test
isolates the Adapter's target-first clause handling. The current
`the_targets_own_clauses_handle_the_target_first`,
`an_unhandled_target_error_reaches_the_callers_clauses`, and
`the_targets_own_sends_carry_their_redelivery` cases remain contract tests,
not method-attributed ports. This is preferable to attaching a nearby Camel
test that does not assert the same boundary.

## Remaining gaps

- No supported, applicable split, loop, enrich, aggregation-strategy, or
  direct case identified in this bounded inventory remains deliberately
  untested. The additions in this pass cover `use-latest`, loop failure in
  both copy modes, combined split thresholds, the all-success, aborted, empty,
  and absent `CamelSplitResult` edges, the Adapter's null-input divergence,
  `json-merge`, old-header absence, and authored-property protection.
- This remains bounded unit and integration attribution, not a claim of full
  Camel conformance. The explicit non-applicable families and deliberate
  divergences above remain outside the port.

No Camel tests were executed. The focused Adapter integration targets passed
against the uncommitted candidate working tree: `camel_direct` 10/10 and
`camel_split_loop` 21/21. This is behavior evidence for the candidate tree,
not clean revision-bound release evidence. The lead must still run the
consolidated Adapter acceptance commands after all owned modules are
integrated.
