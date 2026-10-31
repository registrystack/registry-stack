# Camel error-cluster attribution

Date: 2026-10-31

## Scope and source freeze

This review is limited to the Adapter's declared `defaultErrorHandler`,
`noErrorHandler`, redelivery, `onException`, and `doTry`/`doCatch`/`doFinally`
surface in `CONCEPT.md` section 8.7. It does not repeat the broader C6a review.

The read-only upstream source was Apache Camel tag `camel-4.23.0`, commit
`b2329103df8f5d1edfca2ad262be09e3be95ee68`, at
`/Volumes/CodexWorktrees/agent-scratch/camel-src/camel-4.23.0`. The clone was
clean when inspected. It was not edited, copied, or built.

`Mapped` below means an executable Rust test asserts the corresponding
behavior. A source citation alone is not treated as a port. `Bounded mapping`
means the Rust test asserts the common behavior while the named Adapter
divergence remains. `Outside port` means no conformance claim is made.

## Default and no error handler

| Camel 4.23.0 test method | Status and Rust case |
|---|---|
| `core/camel-core/src/test/java/org/apache/camel/processor/DefaultErrorHandlerRedeliveryTest.java#testNoRedeliveriesTest` | Mapped by `camel_error_cluster::the_error_handler_shapes_the_attempts_and_clause_reach`: one initial call, no implicit redelivery. |
| `core/camel-core/src/test/java/org/apache/camel/processor/DefaultErrorHandlerRedeliveryTest.java#testRedeliveryTest` and `#testOneRedeliveryTest` | Mapped by `camel_error_cluster::the_default_error_handler_redelivers_under_its_policy`: attempts are one plus `maximumRedeliveries`, and exhaustion propagates. |
| `core/camel-core/src/test/java/org/apache/camel/processor/onexception/OnExceptionRecursionTest.java#testRecursionDirectNoErrorHandler` | Bounded mapping by `camel_error_cluster::the_error_handler_shapes_the_attempts_and_clause_reach`: `noErrorHandler` leaves a failure bare and does not activate another clause. Camel's cross-route topology is not ported literally. |
| `core/camel-core/src/test/java/org/apache/camel/processor/SendToNoErrorHandlerTest.java#testSendToNoErrorHandler` | Bounded mapping by the same Rust case for bare propagation. Camel's caller dead-letter channel and Adapter `direct:` redelivery differ by contract. |
| `core/camel-core/src/test/java/org/apache/camel/processor/ErrorHandlerTest.java#testError` | Outside port for its configurable dead-letter endpoint. The Adapter always journals an exhausted failure and exposes no dead-letter endpoint. |

## Redelivery

| Camel 4.23.0 test method | Status and Rust case |
|---|---|
| `core/camel-core/src/test/java/org/apache/camel/processor/RedeliveryPolicyPerExceptionTest.java#testUsingCustomExceptionHandlerAndOneRedelivery` | Mapped by `camel_error_cluster::the_clause_policy_governs_its_classes_and_the_handler_the_rest`: the matched clause's policy overrides the handler policy. `camel_error_cluster::the_default_error_handler_redelivers_under_its_policy` also asserts the counter, maximum counter, and redelivered headers. |
| `core/camel-core/src/test/java/org/apache/camel/processor/RedeliveryPolicyPerExceptionTest.java#testUsingCustomExceptionHandlerWithNoRedeliveries` | Mapped. The Camel clause has output `.to("mock:b")` and no clause policy, so `ExceptionPolicy.createRedeliveryPolicy` copies the parent but sets `maximumRedeliveries` to 0. `camel_error_cluster::an_output_bearing_clause_without_policy_disables_handler_redelivery` asserts one request despite a route policy of three redeliveries and passed in the shared-target run. The existing outputless inheritance branch matches Camel's separate no-output path. |
| `core/camel-core/src/test/java/org/apache/camel/processor/onexception/DefaultErrorHandlerRetryWhileTest.java#testRetryUntil` | Bounded mapping by `camel_error_cluster::retry_while_narrows_redelivery_without_raising_the_cap`: the handler predicate controls retries. Camel permits the predicate to drive an unbounded count; the Adapter keeps `maximumRedeliveries` as a hard cap. |
| `core/camel-core/src/test/java/org/apache/camel/processor/onexception/OnExceptionRetryUntilTest.java#testRetryUntil` | Bounded mapping by the same Rust case: a matching clause owns `retryWhile`, and the redelivery headers are visible. The Adapter hard-cap divergence remains. |
| `core/camel-core/src/test/java/org/apache/camel/processor/onexception/ErrorHandlerFailurePathsTest.java#testDeadLetterChannelRetryWhileThrows` | Bounded mapping by the same Rust case: a raising predicate stops redelivery and the original class remains the final failure. Camel's suppressed Java exception and dead-letter endpoint have no literal Adapter equivalent. |
| `core/camel-core/src/test/java/org/apache/camel/processor/RedeliverToSubRouteRemoveHeadersTest.java#testRedeliveryCounterWithRemoveHeaders` and `#testOnRedeliverySeesCorrectCounter` | The counter portion is mapped by `camel_error_cluster::the_default_error_handler_redelivers_under_its_policy`. The `direct:` subroute retry, wildcard header removal, and `onRedelivery` callback are outside the port. |
| `core/camel-core/src/test/java/org/apache/camel/processor/RedeliveryPolicyDelayPatternTest.java#testDelayPattern` and `#testDelayPatternJavadocExample` | Outside port. `delayPattern` is explicitly not ported. |
| `core/camel-core/src/test/java/org/apache/camel/processor/onexception/OnExceptionRedeliveryDelayDurationTest.java#testDurationRedeliveryDelay` and `#testDurationValues` | Outside port. The Adapter uses numeric `retryDelaySeconds`, not Camel duration strings. |

The other declared delay options, exponential backoff, maximum delay, and
collision avoidance, are exercised in the existing resilience suite. They
were not re-reviewed here because this slice is the attribution gap in the
error-cluster tests.

## Exception clauses

| Camel 4.23.0 test method | Status and Rust case |
|---|---|
| `core/camel-core/src/test/java/org/apache/camel/processor/exceptionpolicy/DefaultExceptionPolicyStrategyTest.java#testDirectMatch1`, `#testDirectMatch2`, and `#testDirectMatch3` | Mapped to the closed Adapter hierarchy by the exact-class branches in `camel_error_cluster::the_closest_exception_clause_wins_and_on_when_narrows_ties`. |
| `core/camel-core/src/test/java/org/apache/camel/processor/exceptionpolicy/DefaultExceptionPolicyStrategyTest.java#testClosetMatch1`, `#testClosetMatch2`, and `#testClosetMatch3` | Mapped by the same new Rust case: a more specific descendant clause wins over an earlier ancestor clause. |
| `core/camel-core/src/test/java/org/apache/camel/processor/exceptionpolicy/DefaultExceptionPolicyStrategyTest.java#testNoMatch1ThenMatchingJustException` and `#testNoMatch1ThenNull` | Mapped by the ancestor and unhandled branches of the new Rust case and `camel_error_cluster::handled_ends_continued_resumes_and_default_propagates`. |
| `core/camel-core/src/test/java/org/apache/camel/processor/exceptionpolicy/DefaultExceptionPolicyStrategyTest.java#testCausedBy`, `#testCausedByWrapped`, `#testCausedByNotConnected`, and `#testCausedByOtherIO` | Outside port by recorded divergence. Camel walks a Java cause chain; the Adapter carries one closed `RouteFailure` class. |
| `core/camel-core/src/test/java/org/apache/camel/processor/exceptionpolicy/DefaultExceptionPolicyStrategyUsingWhenTest.java#testNoWhen` and `#testWithWhen` | Mapped by the new Rust case: equal specificity preserves declaration order, and a narrowing `onWhen` selects the applicable clause. |
| `core/camel-core/src/test/java/org/apache/camel/processor/onexception/ErrorHandlerFailurePathsTest.java#testOnWhenThrowsIsNoMatch` | Mapped by the new Rust case: a raising `onWhen` is skipped and the next applicable clause handles the failure. |
| `core/camel-core/src/test/java/org/apache/camel/processor/onexception/OnExceptionHandledTest.java#testHandled` | Mapped by `camel_error_cluster::handled_ends_continued_resumes_and_default_propagates`: clause steps run and `handled` ends successfully without resuming the route. |
| `core/camel-core/src/test/java/org/apache/camel/processor/onexception/OnExceptionContinueTest.java#testContinued` | Mapped by the same Rust case: clause steps run and `continued` resumes after the failed step. |
| `core/camel-core/src/test/java/org/apache/camel/processor/onexception/ErrorHandlerFailurePathsTest.java#testContinuedThenUnrelatedFailure` | Mapped by the added branch in the same Rust case: a later independent failure becomes final. |
| `core/camel-core/src/test/java/org/apache/camel/processor/onexception/OnExceptionHandledAndContinueTest.java#testHandledAndContinued` | Mapped by `camel_error_cluster::the_cluster_refuses_its_unservable_shapes_at_load`: the pair is refused. |
| `core/camel-core/src/test/java/org/apache/camel/processor/onexception/OnExceptionRecursionTest.java#testRecursionDirect` | Recorded divergence, asserted by `error_lifecycle::a_direct_call_inside_an_exception_clause_does_not_activate_callee_handlers` and attributed in `camel_error_cluster::a_clause_error_replaces_the_failure_and_keeps_the_original`. Camel invokes the callee's handler again; the Adapter keeps the call inside the fatal clause scope. |
| `core/camel-core/src/test/java/org/apache/camel/processor/onexception/OnExceptionUseOriginalMessageTest.java#testOnExceptionError`, `#testOnExceptionStreamReset`, `OnExceptionUseOriginalBodyTest.java#testUseOriginalBody`, and `#testDoNotUseOriginalBody` | Outside port. Section 8.7 defines neither `useOriginalMessage` nor `useOriginalBody`; `camel_error_cluster::the_cluster_refuses_its_unservable_shapes_at_load` now proves both fields are rejected rather than silently ignored. Stream-cache behavior is also outside the Adapter message model. |

## Try, catch, and finally

| Camel 4.23.0 test method | Status and Rust case |
|---|---|
| `core/camel-core/src/test/java/org/apache/camel/processor/TryProcessorTest.java#testTryCatchFinallyProcessor` | Mapped by `camel_error_cluster::do_try_catches_its_block_and_resumes_the_route`: the catch sees `CamelExceptionCaught`, handles the failure, and the route resumes after the block. |
| `core/camel-core/src/test/java/org/apache/camel/processor/TryProcessorTest.java#testTryCatchFinallyExpression` and `#testTryCatchFinallyPredicate` | The common catch/finally behavior is mapped by the same Rust test. Camel's distinct Java `Expression` and `Predicate` callback forms are outside the Adapter's authored expression model. |
| `core/camel-core/src/test/java/org/apache/camel/processor/TryProcessorMultipleExceptionTest.java#testIOException`, `#testIllegalStateException`, and `#testOk` | Mapped by the added multi-class catch branch in `camel_error_cluster::do_try_catches_its_block_and_resumes_the_route` and the clean path in `camel_error_cluster::do_finally_runs_on_every_path_and_yields_to_a_pending_failure`. |
| `core/camel-core/src/test/java/org/apache/camel/processor/TryProcessorOnWhenTest.java#testIOException`, `#testIllegalStateException`, `#testCamelException`, `#testOtherBug`, and `#testOk` | Mapped across `camel_error_cluster::a_do_catch_on_when_narrows_or_fails`, `do_try_catches_its_block_and_resumes_the_route`, and `do_finally_runs_on_every_path_and_yields_to_a_pending_failure`: a true predicate catches, a false predicate skips, another catch may match, an unmatched error escapes, and finally runs on success. |
| `core/camel-core/src/test/java/org/apache/camel/processor/DoTryEdgeCasesTest.java#testOnWhenThrowsException` | Mapped by `camel_error_cluster::a_do_catch_on_when_narrows_or_fails`: the predicate's error wins and the original is journaled as suppressed. |
| `core/camel-core/src/test/java/org/apache/camel/processor/DoTryEdgeCasesTest.java#testOnWhenOnEachCatch` and `#testOnWhenNotEvaluatedWhenHandled` | Mapped by the per-catch predicates and first-catch-wins assertions in `a_do_catch_on_when_narrows_or_fails` and `do_try_catches_its_block_and_resumes_the_route`. |
| `core/camel-core/src/test/java/org/apache/camel/processor/DoTryEdgeCasesTest.java#testNestedDoTryKeepsTryBlock` | Mapped at the error-handler boundary by `camel_error_cluster::the_route_error_handler_does_not_wrap_a_do_try_block` and `error_lifecycle::a_top_level_do_try_runs_bare`. The exact Java recipient-list topology is outside the port. |
| `core/camel-core/src/test/java/org/apache/camel/processor/DoTryEdgeCasesTest.java#testDoFinallyThrowsKeepsOriginal` | Mapped by `camel_error_cluster::do_finally_runs_on_every_path_and_yields_to_a_pending_failure`: the pending original wins, while the finally error is journaled as suppressed. |
| `core/camel-core/src/test/java/org/apache/camel/processor/DoTryEdgeCasesTest.java#testDoFinallyKeepsEarlierFailureDetails` | Outside literal port because Camel failure route identifiers are not in the Adapter exchange. The applicable invariant, finally does not erase a pending failure, is mapped by the preceding Rust case. |
| `core/camel-core/src/test/java/org/apache/camel/processor/DoTryEdgeCasesTest.java#testDoTryWithoutCatchOrFinally` | Mapped. `error_lifecycle::an_unanchored_do_try_is_refused_at_load` asserts the exact value-free load error and passed in the shared-target run, while `a_top_level_do_try_runs_bare` carries an empty `doFinally` so it remains structurally valid. |
| `core/camel-core/src/test/java/org/apache/camel/processor/DoTryEdgeCasesTest.java#testStepIdOnCatchAndFinally` | Outside port. Adapter steps do not expose Camel processor IDs. |

## Confirmed semantics and integration status

The inventory exposed two source or contract defects that this bounded
test-only slice cannot fix.

First, the redelivery difference is conditional, not a blanket default.
`RedeliveryPolicyPerExceptionTest.java:57-73,97-105` gives the matching
`NullPointerException` clause an output (`to("mock:b")`) but no clause policy;
the route handler permits three redeliveries, while the assertions require
counter 0, no maximum-counter header, and `redelivered == false`.
`ExceptionPolicy.java:114-128` explains the result: with no custom clause
policy, an output-bearing clause copies the parent and resets only
`maximumRedeliveries` to 0; an outputless clause returns the parent unchanged.
At the initial inspection, Adapter selected
`clause.redelivery_policy.or(handler_policy)` without testing whether clause
steps existed. Its inheritance assertion used an outputless handled
clause, which conforms to Camel. The missing case was an output-bearing
clause with no policy. The integrated core and runtime now share
`effective_clause_redelivery_policy`, and the contract states the
output-sensitive rule. The focused zero-redelivery regression and the
existing outputless-inheritance case both pass.

Second, `DoTryEdgeCasesTest.java:181-196` builds an ordinary
`from("direct:start")` route, not a nested `onException`, and requires route
startup to fail when `doTry` has neither `doCatch` nor `doFinally`.
`TryReifier.java:36-54` enforces the structural guard while Camel creates the
processor, before it constructs `TryProcessor` at line 64. Separately,
`ProcessorDefinitionHelper.java:426-447` keeps the route error handler off
try/catch/finally and `onException` blocks; that wrapping rule explains bare
failure behavior but is not the structural validation. Camel's 4.23 upgrade
guide states that previously accepting this shape turned off the route error
handler (`camel-4x-upgrade-guide-4_23.adoc:4397-4405`). The reifier guard is
generic to every `TryDefinition`, although the cited test proves a regular
route case. Section 8.7 (`CONCEPT.md:671-682`) says the EIP is ported as in
Camel and records no unanchored-block divergence. At inspection, Adapter serving checks
only inspect catches and finally blocks that exist
(`registry-adapter/src/route.rs:282-304`), and authoring checks likewise only
walk present catches (`registry-adapter-core/src/checks.rs:1847-1858`), so
the guard was missing.

Focused Camel-attributed regressions now cover both rules. The integrated
runtime includes output-sensitive clause policy resolution and the exact
`doTry` guard; its library suite passed 190/190 and problem-data integration
passed 9/9. The core includes the typed
`adapter.route.do-try-clause-required` diagnostic, authoring guard, and shared
policy helper; its all-feature suite passed 308 unit tests and one doc test,
with strict Clippy passing.
The subsequent shared-target run with `postgres-test` executed
`camel_error_cluster` 15/15 and `error_lifecycle` 7/7; both focused
regressions passed.

The supported exception-policy cases that were executable but not directly
covered are now covered by
`the_closest_exception_clause_wins_and_on_when_narrows_ties`. The existing
try tests were also extended for a multi-class catch, a true `doCatch`
predicate, and a later failure after `continued`. These are behavior
assertions, not citation-only claims.

## Verification limit

This slice itself ran no Cargo command. The root-owned shared-target run with
`postgres-test` passed `camel_error_cluster` 15/15 and `error_lifecycle` 7/7.
The broader Adapter format, clippy, PostgreSQL, and integration gates remain
the root integration stream's acceptance record.
