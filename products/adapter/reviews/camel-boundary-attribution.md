# Camel boundary source and test attribution

Date: 2026-10-31

Scope: the HTTP failure and header-filter rows, the circuit-breaker and
throttler rows, and the fixture-replay use of Camel mock and intercept. This is
an attribution review, not a claim that a citation completes a port or that the
whole Increment 1 or C6 acceptance surface passed.

## Source freeze

- Contract pin: Apache Camel tag `camel-4.23.0`, commit
  `b2329103df8f5d1edfca2ad262be09e3be95ee68`.
- Inspected clone:
  `<camel-source-checkout>`.
- Readback: `git rev-parse HEAD` returned the contract pin and
  `git status --short` returned no entries.
- The clone was read only. It was not edited, built, or copied.

“Mapped” below means the Rust test asserts the same observable behavior that
the named Camel test exercises. “Divergence” means the Camel test is relevant
evidence for the baseline, but the Adapter intentionally asserts different
behavior recorded in `CONCEPT.md`. “Outside” means the Camel case depends on a
feature the bounded port does not expose.

## HTTP failure handling

| Camel 4.23.0 test or source method | Current Rust proof | Disposition |
|---|---|---|
| `components/camel-http/src/test/java/org/apache/camel/component/http/HttpThrowExceptionOnFailureTest.java#httpGetWhichReturnsHttp501` | `egress_wiring::without_the_throw_an_out_of_range_status_returns_the_reply` | Mapped. The status and body return when `throwExceptionOnFailure` is false. |
| `components/camel-http/src/test/java/org/apache/camel/component/http/HttpThrowExceptionOnFailureTest.java#httpGetWhichReturnsHttp501ShouldThrowAnException` | `egress_wiring::a_decodable_out_of_range_body_raises_http_with_the_body_under_the_throw` and `an_undecodable_out_of_range_body_raises_http_without_a_body_under_the_throw` | Mapped for raising and retaining status. JSON-only bounded body retention is the Adapter divergence. |
| `components/camel-http/src/main/java/org/apache/camel/component/http/HttpProducer.java#populateHttpOperationFailedException` | `egress_wiring::a_decodable_out_of_range_body_raises_http_with_the_body_under_the_throw` | Mapped for status and error-body retention. The Adapter drops status text, response headers, and `Location`. |
| `components/camel-http/src/test/java/org/apache/camel/component/http/HttpRedirectTest.java#httpRedirectFalse` | `egress_wiring::a_redirect_is_raised_and_never_followed` | Divergence. Both expose a 3xx failure when redirects are disabled. The Adapter always refuses every 3xx, even with `throwExceptionOnFailure: false`, never follows it, and retains no location value. |
| `components/camel-http/src/test/java/org/apache/camel/component/http/helper/HttpHelperTest.java#testIsStatusCodeOkComplexRange` | `egress_wiring::sparse_status_ranges_accept_each_entry_and_reject_a_hole` | Mapped for a comma-separated sparse union. The focused Adapter case admits 400 and 404, rejects the 403 hole, and the redirect case proves a declared 3xx remains refused. |
| `components/camel-http/src/test/java/org/apache/camel/component/http/HttpThrowExceptionOnFailureTest.java#httpGetWhichReturnsHttp501WithIgnoreResponseBody` and `#httpGetWhichReturnsHttp501ShouldThrowAnExceptionWithIgnoreResponseBody` | None | Outside. `ignoreResponseBody` is not in the bounded HTTP form. |
| `components/camel-http-common/src/test/java/org/apache/camel/http/common/HttpOperationFailedExceptionTest.java#testUriIsSanitized` | `egress_wiring::a_send_debug_render_carries_no_value` and value-free error types | Divergence with stronger minimization. Adapter failures do not retain or render a destination URI, so there is no URI value to sanitize. |

Additional Adapter-only failure cases are directly tested in
`egress_wiring.rs`: malformed JSON, empty bodies as JSON `null`, response-size
bounds, connection certainty, attempt timeout, address-policy refusal, and the
single bounded attempt-timeout model. Camel's broad transport options do not
establish those Adapter additions.

This review found and fixes a contract mismatch in comma-separated
`okStatusCodeRange`: `OkStatusCodeRanges` now carries the complete sparse set
through the live and replay egress paths, and route compilation parses every
singleton or inclusive range. The default remains `200-299`; redirect refusal
runs before status-set membership.

## HTTP header filter

| Camel 4.23.0 test method | Current Rust proof | Disposition |
|---|---|---|
| `components/camel-http-common/src/test/java/org/apache/camel/http/common/HttpHeaderFilterStrategyTest.java#applyFilterToCamelHeaders` | `camel_header_filter::only_listed_request_headers_are_sent`, `engine_headers_and_facade_inputs_are_not_sent_unless_listed`, and `every_reserved_name_is_refused_in_either_list` | Divergence. Camel applies a deny filter. The Adapter starts from an allowlist and then refuses security- and transport-owned names. Matching remains case-insensitive. |
| `components/camel-http-common/src/test/java/org/apache/camel/http/common/HttpHeaderFilterStrategyTest.java#applyFilterToExternalHeaders` | `camel_header_filter::a_camel_engine_header_is_refused_as_a_response_header` and `only_declared_response_headers_are_copied_under_their_declared_names` | Divergence. Camel admits most external headers except its engine prefix. The Adapter copies only declared response names and refuses its closed reserved set. |
| `components/camel-http/src/test/java/org/apache/camel/component/http/HeaderFilteringTest.java#shouldFilterIncomingHttpHeadersInProducer` | `camel_header_filter::every_reserved_name_is_refused_in_either_list` | Mapped for the invariant that an exchange `Host` value cannot choose the wire host. Adapter construction refuses `Host` rather than silently filtering it during the send. |
| `components/camel-http/src/test/java/org/apache/camel/component/http/HttpProducerTwoHeadersWithSameKeyTest.java#testTwoHeadersWithSameKeyHeader` | `camel_header_filter::two_exchange_entries_for_one_listed_name_are_refused` and `a_repeated_declared_response_header_is_upstream_malformed` | Divergence. Camel joins a multi-value request and returns a list for a repeated response. The Adapter refuses either ambiguity so a header stays one bounded string. |
| `components/camel-http-common/src/test/java/org/apache/camel/http/common/HttpRestHeaderFilterStrategyTest.java#shouldDecideOnApplingHeaderFilterToTemplateTokens` and `#shouldDecideOnApplingHeaderFilterToTemplateTokensUnencoded` | None | Outside. Adapter path and query parameters are structured expressions, never dynamic Camel headers. |

The remaining `camel_header_filter.rs` cases are Adapter additions: strict
RFC 9110 value bytes, value-size and list-count bounds, credential-slot
separation, facade-input separation, declared response spelling, and equality
between authoring checks and runtime filter construction. They are not
attributed to Camel tests.

## Circuit breaker

The applicable synchronous resilience4j cases map as follows:

| Camel 4.23.0 source or test methods | Current Rust proof | Disposition |
|---|---|---|
| `components/camel-resilience4j/src/main/java/org/apache/camel/component/resilience4j/ResilienceReifier.java#configureCircuitBreaker` | `camel_resilience::successful_slow_calls_open_at_the_authored_duration_and_rate` | Mapped for wiring and enforcing the slow-call duration and rate thresholds. One delayed successful HTTP call and one fast success make an exact 50 percent slow rate in a two-call window; the next exchange is refused without reaching the source. Camel 4.23.0 has no focused slow-call-rate unit in this component. |
| `components/camel-resilience4j/src/main/java/org/apache/camel/component/resilience4j/ResilienceReifier.java#configureCircuitBreaker` | `camel_resilience::default_breaker_enforces_one_hundred_call_minimum_and_window` | Adapter-default proof. Camel leaves omitted values to resilience4j, while the Adapter authors the equivalent count-window values explicitly. One lane admits 99 failures and opens after call 100 meets the minimum. A second stays closed at 49 failures in its first 100 calls, then call 101 evicts the oldest success, leaves 50 failures in the retained 100, and opens the breaker. |
| `ResilienceRouteOkTest.java#testResilience` | `camel_resilience::an_open_breaker_recovers_through_half_open_trials` includes successful guarded and subsequently closed calls | Mapped for a successful call through a closed breaker. Camel exchange-property assertions are outside the port. |
| `ResilienceRouteFallbackTest.java#testResilience` | `camel_resilience::on_fallback_answers_on_failure_and_on_rejection` | Mapped for fallback on a guarded failure. |
| `ResilienceOpenWithFallbackExchangePropertyTest.java#testRejectedOnlyWhenBreakerOpen` | `a_failure_storm_opens_the_breaker_and_refuses_without_calling` and `on_fallback_answers_on_failure_and_on_rejection` | Mapped for two failed calls opening the window and the next call not reaching the guarded operation. Camel response properties are outside the port. |
| `ResilienceRecordExceptionTest.java#testHello`, `#testFile`, `#testKaboom`, `#testIo` | `record_exception_matches_descendants_and_only_recorded_failures_use_fallback` plus successful calls in `an_open_breaker_recovers_through_half_open_trials` | Mapped for success, parent-to-descendant matching, a non-match counting as success, and a recorded exact class using fallback. |
| `ResilienceIgnoreExceptionTest.java#testHello`, `#testFile`, `#testKaboom`, `#testIo` | `ignore_exception_wins_overlap_and_never_uses_fallback` plus the record-exception case | Mapped for ignored descendants continuing without fallback. |
| `ResilienceRecordIgnoreExceptionTest.java#testHello`, `#testFile`, `#testKaboom`, `#testIo` | `ignore_exception_wins_overlap_and_never_uses_fallback` and `record_exception_matches_descendants_and_only_recorded_failures_use_fallback` | Mapped for ignore precedence, recorded matches, and non-recorded matches. |
| `ResilienceRouteRejectedTest.java#testResilienceWithThrowException` | `a_failure_storm_opens_the_breaker_and_refuses_without_calling` | Mapped for raising on rejection, but Adapter makes that behavior mandatory. The Camel test's forced-open JMX control is outside the port. |
| `ResilienceInheritErrorHandlerTest.java#testResilience` | `the_route_error_handler_does_not_wrap_a_breaker_block` | Divergence. Camel opts into inherited redelivery. Adapter guarded and fallback steps always run bare. |

The timeout-enabled siblings, async, pooled, bulkhead, thread-pool, console,
management, externally injected breaker, JMX forced-state, and suspend/resume
tests are outside the declared port. Camel's
`throwExceptionWhenHalfOpenOrOpenState: false` cases are a recorded divergence:
the Adapter always raises `breaker.open` or runs fallback. Camel's breaker
response properties and counters are not ported as exchange state.

Defaults are asserted by
`registry_adapter_core::route::tests::circuit_breaker_step_round_trips_with_defaults`
and `breaker_and_throttle_defaults_stay_off_the_wire`. The processor-level
`default_breaker_enforces_one_hundred_call_minimum_and_window` now exercises
the full default 100-call minimum and independently proves count-window
eviction, while
`successful_slow_calls_open_at_the_authored_duration_and_rate` exercises the
slow-call duration and rate through real guarded HTTP sends. This review also
found that
`automaticTransitionFromOpenToHalfOpenEnabled` was accepted by the model but
not passed into the platform breaker. The wiring now passes it as
`BreakerConfig::automatic_transition`, with
`resilience::tests::authored_automatic_transition_reaches_the_platform_breaker`
covering the Adapter boundary. The platform remains deliberately timerless:
when automatic transition is true, passive `state()` observation advances an
elapsed open breaker to half-open without admitting a guarded call; when false,
it remains observably open until `acquire()` performs Camel's lazy transition.
That is equivalent at the bounded port's observable state and request
boundaries. It does not claim a background task or Camel management-event port.

## Throttler

| Camel 4.23.0 test methods | Current Rust proof | Disposition |
|---|---|---|
| `processor/throttle/requests/ThrottlerTest.java#testSendLotsOfMessagesButOnly3GetThroughWithin2Seconds`, `#testSendLotsOfMessagesSimultaneouslyButOnly3GetThrough`, and `#testConfigurationWithConstantExpression` | `camel_resilience::the_throttler_paces_requests_over_the_period` | Mapped for total-request pacing and a constant expression. |
| `processor/throttle/requests/ThrottlerTest.java#testSendLotsOfMessagesWithRejectExecution` | `reject_execution_refuses_instead_of_waiting` | Mapped for immediate rejection above the total-request limit. |
| `processor/throttle/requests/ThrottlerTest.java#testConfigurationWithHeaderExpression` and `#testConfigurationWithChangingHeaderExpression` | `a_header_limit_is_re_evaluated_for_each_exchange` | Mapped. The focused Rust case was added by this review because the supported dynamic limit previously had no positive-value conformance proof. |
| `processor/throttle/concurrent/ConcurrentRequestsThrottlerTest.java#testSendLotsOfMessagesSimultaneouslyButOnly3GetThrough` and `#testConfigurationWithConstantExpression` | `concurrent_requests_mode_bounds_in_flight_calls` | Mapped for bounded in-flight calls and waiting. |
| `processor/throttle/concurrent/ConcurrentRequestsThrottlerTest.java#testConfigurationWithHeaderExpression` and `#testConfigurationWithChangingHeaderExpression` | `concurrent_requests_mode_re_reads_a_changed_header_limit` | Mapped for per-exchange re-evaluation in concurrent mode. A first body enters under header limit 1, a changed limit 2 admits a second body, and a third exchange at limit 2 is refused while both permits are held. |
| `processor/throttle/concurrent/ConcurrentRequestsThrottlerTest.java#testSendLotsOfMessagesWithRejectExecution` | `concurrent_requests_mode_rejects_over_the_limit` | Mapped for immediate concurrent-mode rejection. |
| `processor/throttle/concurrent/ConcurrentRequestsThrottlerTest.java#testPermitReleaseOnException` | `concurrent_requests_mode_releases_its_permit_on_failure` | Mapped. The focused Rust case was added by this review. |
| `processor/throttle/ThrottlerNullEvalTest.java#testFirstNullEvalTest`, `#testFirstNoHeaderTest`, `#testNullEvalTest`, and `#testNoHeaderTest` | `a_non_integer_limit_fails_the_exchange` | Divergence. Camel's later null can pass under the existing throttler. Adapter requires a positive integer on every evaluation and fails closed. |
| `processor/throttle/requests/ThrottlerAsyncDelayedNoPermitTest.java#testNoPermitAsyncDelayed` | Load checks and `a_non_integer_limit_fails_the_exchange` | Divergence. Camel can re-evaluate zero until a permit appears. Adapter refuses zero at load when constant and at runtime when evaluated. |
| `processor/throttle/ThrottlerInvalidConfiguredTest.java#testInvalid` | `the_resilience_steps_refuse_their_unservable_shapes_at_load` | Mapped for refusing a missing limit, with additional bounded-shape checks. |

Camel's FIFO test is not a promised Adapter option. Thread-pool, executor,
async-delayed, caller-runs, correlation grouping, sampling, and route-policy
tests are outside the bounded throttler. The Adapter-specific deadline refusal
is covered by `a_wait_past_the_deadline_raises_throttle_rejected`.

## Fixture replay, mock, and intercept

Fixture replay is not a general port of Camel's `MockEndpoint` assertion DSL or
`AdviceWith`. It ports one test idiom: intercept an outbound `http` or
`graphql` send, skip the original destination, answer from an ordered
transcript, and verify the complete result.

| Camel 4.23.0 test method | Current Rust proof | Disposition |
|---|---|---|
| `core/camel-core/src/test/java/org/apache/camel/processor/interceptor/AdviceWithMockEndpointsWithSkipTest.java#testAdvisedMockEndpointsWithSkip` | `registry_adapter::replay::tests::matches_the_complete_ordered_data_send_and_finishes` and `registry_adapterctl/tests/fixtures_replay.rs::the_minimal_suite_replays_against_its_compiled_contract` | Mapped for intercepting a send and skipping the original destination. The Adapter substitutes a recorded reply instead of routing to a mock endpoint. |
| `core/camel-core/src/test/java/org/apache/camel/processor/intercept/InterceptSendToEndpointTest.java#testInterceptEndpointStop` | The same two replay cases | Mapped for skip-and-continue semantics. Fixture replay has no authored detour processor. |
| `core/camel-core/src/test/java/org/apache/camel/processor/intercept/InterceptSendToEndpointWithParametersTest.java#testInterceptSendToEndpoint` | Replay matching accepts the compiled fixed endpoint and concrete request parameters | Mapped at the endpoint-send boundary. Camel wildcard matching is outside the fixed endpoint model. |
| `core/camel-core/src/test/java/org/apache/camel/component/mock/MockEndpointTest.java#testExpectsBodiesInOrder` | `matches_the_complete_ordered_data_send_and_finishes`, `fails_visibly_for_excess_and_leftover_sends`, and the CLI contract comparison | Mapped for ordered expectations and visible excess or missing exchanges. Adapter additionally matches method, path, query, ordered headers, and body digest. |

Current Adapter replay proof also includes
`token_send_matches_without_a_secret_header_or_body`,
`refuses_header_reordering_even_when_members_match`,
`fails_visibly_for_excess_and_leftover_sends`, exact facade comparison,
compiled-contract status checks, missing-intercept refusal, stable synthetic
cursor bytes, write simulation reporting, and all maintained OpenCRVS fixture
entries. Those are Adapter fixture-contract additions, not general Camel mock
features.

The following Camel behaviors are outside the replay boundary: mock assertion
predicates, any-order matching, retention windows, timing clauses, reset,
minimum counts, endpoint wildcard advice, conditional intercepts, detour
routes, intercept-after, intercept-from, route weaving, and use of mock as a
runtime component. No `camel_testing.rs` module currently embeds these method
citations, and this bounded review did not edit `replay.rs` or adapterctl tests.

## Verification status

- Source inventory and exact-method readback: completed against the clean
  pinned clone.
- Focused Rust tests added: sparse HTTP status membership, redirect precedence,
  dynamic total-request header limit, concurrent permit release on failure,
  slow-call duration and rate, the full default 100-call breaker window,
  concurrent changed-header admission, and Adapter-to-platform
  automatic-transition wiring.
- Focused integration tests passed: `camel_header_filter` 28 of 28,
  `camel_resilience` 19 of 19, and `egress_wiring` 28 of 28. The focused
  Adapter unit test
  `authored_automatic_transition_reaches_the_platform_breaker` passed 1 of 1.
- An earlier all-target Adapter Clippy attempt found
  `clippy::unnecessary_lazy_evaluations` in a concurrent route change. The
  integrated runtime now uses the shared core policy helper instead of
  that expression. The lead records the final all-target gate separately;
  the focused results above do not stand in for it.
- Earlier owned and platform-test formatting differences were corrected.
  `git diff --check` is clean for every file this review owns. The lead
  records the final workspace formatting result separately.
- Broad C6 acceptance: deliberately not rerun. The integration lead owns the
  consolidated acceptance command and final module layout.

