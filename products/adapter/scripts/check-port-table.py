#!/usr/bin/env python3
"""Hold CONCEPT.md 8.10 (the Camel port table) to the code.

Every table row is the contract for one ported Camel concept: the
camel.apache.org page that defines its semantics, our form, what diverges,
and the increment that delivers it. This script is the section 13.2 gate:
it fails when the table and the code disagree, and reports later-increment
rows as pending rather than failing them.

What it checks, in order:

1. Table shape. The table under `### 8.10 The Camel port table` parses into
   five cells per row (concept, reference, our form, divergence, Inc) and
   one concept per row.
2. References. Every backticked span in a row's reference cell must be a
   relative camel.apache.org path: no scheme, no leading slash, no domain,
   and a `.html` page. Camel publishes its manual and component pages as
   `.html`; if a row ever cites another extension the row and this check
   change together. Parenthetical qualifiers outside the backticks (for
   example "(component docs)") are prose, not paths, and are ignored.
3. Delivered rows have evidence. `INCREMENT_DELIVERED` is the highest
   increment this tree delivers. A row with `Inc` at or below it must map,
   in `EVIDENCE` below, to at least one named Rust function carrying a
   `#[test]` or `#[tokio::test]` attribute, and each named test must exist
   in the mapped file. Core rows map into
   `crates/registry-adapter-core/src/`; runtime rows map through the
   `engine:` form into shared-engine tests, the `facade:` form into facade
   conformance suites, and the `job:` form into job-host tests. A row with a
   higher Inc is reported as pending and never fails
   the run for lacking evidence, but any evidence already recorded for it
   must still resolve.
4. Every accepted key has a row. The generated schemas under
   `products/adapter/schemas/` are the machine-readable form of what the
   core model accepts. Every step key (`Step`, `Expression`,
   `AggregationStrategy`), every EIP capability name (`Eip`), every
   language (`Language`), and every component kind (`ComponentKind`) the
   pack schema accepts must appear in some row's text. The `SendComponent`
   enum is skipped: its values are the URI-prefix spellings (`Direct`,
   `Http`, `GraphQl`) of the same components `ComponentKind` already
   covers.

Increment 0 evidence mapping (row concept -> the core tests that hold the
row to the code). Extend this map when an increment lands. The engine
conformance mappings also cover runtime rows such as HeaderFilterStrategy,
HTTP authentication and Languages. The gate requires a row only after its
whole increment is accepted.

- "Route, YAML DSL": the route form, its `direct:`-only `from`, the acyclic
  graph, and the bounded depth
  (checks.rs routes_accept_a_well_formed_direct_call,
  routes_refuse_a_from_outside_direct, routes_refuse_a_direct_cycle,
  routes_refuse_a_direct_chain_past_the_bounded_depth,
  a_chain_within_depth_passes_the_whole_workspace; route.rs
  route_definition_round_trips_with_direct_from).
- "Route template, templatedRoute": the typed-template form and the
  instantiation rules
  (route.rs route_template_and_templated_route_round_trip; checks.rs
  project_admits_a_resolved_instantiation_within_budget,
  project_refuses_an_instantiated_route_id_that_collides,
  project_refuses_unknown_operation_record_type_route_and_template).
- "Kamelet catalog": the pack as a reviewed catalog of templates with
  digest-pinned script references
  (checks.rs pack_accepts_producer_endpoints_with_pinned_scripts,
  pack_refuses_an_unpinned_rhai_reference).
- "Property placeholders": the `{{name}}` and `{{?name}}` forms and the
  malformed-placeholder refusal
  (checks.rs placeholder_scanner_covers_both_forms_and_refuses_malformed).
- "Testing: mock, intercept": fixture intercepts and entries
  (checks.rs fixtures_accept_declared_intercepts_and_entries,
  fixtures_refuse_unknown_intercepts_and_entries; fixture.rs
  fixture_round_trips).

Deterministic and offline: standard library only, no network, no
timestamps; the same tree always prints the same report. Exit 0 when the
table holds, 1 with one FAIL line per violation.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
CONCEPT = REPO_ROOT / "products" / "adapter" / "CONCEPT.md"
SCHEMAS = REPO_ROOT / "products" / "adapter" / "schemas"
CORE_SRC = REPO_ROOT / "crates" / "registry-adapter-core" / "src"
ENGINE_ROOT = REPO_ROOT / "crates" / "registry-adapter-engine"
FACADE_ROOT = REPO_ROOT / "crates" / "registry-adapter"
JOB_ROOT = REPO_ROOT / "crates" / "registry-adapter-job"
PACK_SCHEMA = SCHEMAS / "pack.v1alpha1.schema.json"

#: The highest increment this tree delivers. Rows above it are pending.
INCREMENT_DELIVERED = 1

#: Delivered row concept -> the test functions that evidence it. An entry
#: "file.rs:function_name" resolves against crates/registry-adapter-core/src/;
#: "engine:file.rs:function_name" resolves against the engine crate's own
#: tree; "facade:file.rs:function_name" resolves against the facade crate
#: for transport conformance suites, rather than core authoring checks;
#: "job:file.rs:function_name" resolves against the job-host crate;
#: "platform:crate/file.rs:function_name" resolves against crates/, for the
#: generic mechanisms the engine leans on but does not own (the resilience
#: and rate-limit primitives). Every entry is held to existence even while
#: its row's increment is still pending, so the map cannot rot before the
#: increment lands.
EVIDENCE: dict[str, list[str]] = {
    "HeaderFilterStrategy": [
        "facade:tests/camel_header_filter.rs:every_reserved_name_is_refused_in_either_list",
        "facade:tests/camel_header_filter.rs:only_listed_request_headers_are_sent",
        "facade:tests/camel_header_filter.rs:only_declared_response_headers_are_copied_under_their_declared_names",
    ],
    "HTTP authentication": [
        "facade:tests/camel_http_authentication.rs:basic_sends_one_preemptive_header",
        "facade:tests/camel_http_authentication.rs:static_kinds_render_no_marker",
        "facade:tests/camel_http_authentication.rs:a_401_with_an_unparseable_body_is_still_rejected",
        "engine:src/auth/material.rs:basic_values_encode_and_refuse",
    ],
    "Languages": [
        "facade:tests/language.rs:a_selector_over_the_length_bound_is_refused",
        "facade:tests/language.rs:a_singular_query_yields_its_one_value",
        "facade:tests/language.rs:any_other_query_yields_the_node_list",
        "facade:tests/camel_processors.rs:a_non_boolean_predicate_fails_and_a_non_singular_one_never_loads",
    ],
    "setBody, transform": [
        "facade:tests/camel_processors.rs:transform_replaces_the_body_from_its_expression",
        "facade:tests/camel_processors.rs:jsonpath_yields_its_singular_value_or_its_node_list",
    ],
    "setHeader, setProperty, removeHeader, removeProperty": [
        "facade:tests/camel_processors.rs:set_header_sets_one_header_from_its_expression",
        "facade:tests/camel_processors.rs:header_writes_refuse_the_read_only_targets_at_load",
        "facade:tests/camel_processors.rs:remove_header_removes_a_route_set_header",
        "facade:tests/camel_processors.rs:remove_property_removes_a_route_property_and_refuses_facade_names",
        "engine:src/route.rs:a_route_may_set_its_own_property_and_the_next_continuation_only",
    ],
    "script": [
        "facade:tests/camel_processors.rs:script_sets_properties_from_a_returned_map_and_leaves_the_body",
        "facade:tests/camel_processors.rs:script_writes_the_next_continuation_and_no_other_reserved_property",
        "facade:tests/camel_processors.rs:script_returning_no_map_fails_the_exchange",
    ],
    "Content-Based Router": [
        "facade:tests/camel_processors.rs:choice_runs_the_first_matching_when_and_otherwise_when_none_matches",
        "facade:tests/camel_processors.rs:a_non_boolean_predicate_fails_and_a_non_singular_one_never_loads",
    ],
    "Message Filter": [
        "facade:tests/camel_processors.rs:filter_runs_its_steps_only_on_match_and_records_the_outcome",
    ],
    "validate": [
        "facade:tests/camel_processors.rs:validate_raises_validation_on_a_failing_predicate",
    ],
    "Provider schema validation": [
        "engine:src/route.rs:provider_schema_validation_is_digest_pinned_and_terminal",
    ],
    "SQLite extract producer": [
        "engine:tests/sqlite_extract.rs:executes_reviewed_sql_with_typed_parameters_and_one_host_clock",
        "engine:tests/sqlite_extract.rs:stale_extract_and_attempted_clock_override_are_refused",
        "engine:tests/sqlite_extract.rs:write_statement_is_refused_by_the_platform_authorizer",
        "engine:tests/sqlite_extract.rs:evidence_route_reads_captured_sqlite_under_one_audit_and_aggregate_budget",
        "engine:tests/sqlite_extract.rs:audit_refusal_precedes_extract_open_and_no_match_is_explicit",
    ],
    "stop": [
        "facade:tests/camel_processors.rs:stop_ends_the_route_without_failing",
    ],
    "Route, YAML DSL": [
        "checks.rs:routes_accept_a_well_formed_direct_call",
        "checks.rs:routes_refuse_a_from_outside_direct",
        "checks.rs:routes_refuse_a_direct_cycle",
        "checks.rs:routes_refuse_a_direct_chain_past_the_bounded_depth",
        "checks.rs:a_chain_within_depth_passes_the_whole_workspace",
        "route.rs:route_definition_round_trips_with_direct_from",
    ],
    "Route template, templatedRoute": [
        "route.rs:route_template_and_templated_route_round_trip",
        "checks.rs:project_admits_a_resolved_instantiation_within_budget",
        "checks.rs:project_refuses_an_instantiated_route_id_that_collides",
        "checks.rs:project_refuses_unknown_operation_record_type_route_and_template",
    ],
    "Kamelet catalog": [
        "checks.rs:pack_accepts_producer_endpoints_with_pinned_scripts",
        "checks.rs:pack_refuses_an_unpinned_rhai_reference",
    ],
    "Property placeholders": [
        "checks.rs:placeholder_scanner_covers_both_forms_and_refuses_malformed",
    ],
    "Testing: mock, intercept": [
        "checks.rs:fixtures_accept_declared_intercepts_and_entries",
        "checks.rs:fixtures_refuse_unknown_intercepts_and_entries",
        "fixture.rs:fixture_round_trips",
    ],
    # Increment 1 rows, recorded as they land; pending until the increment
    # is delivered as a whole.
    "Splitter": [
        "facade:tests/camel_split_loop.rs:split_runs_each_piece_under_engine_properties_and_returns_the_original",
        "facade:tests/camel_split_loop.rs:a_stop_inside_a_piece_ends_the_split_and_the_route",
        "facade:tests/camel_split_loop.rs:split_item_failures_raise_after_the_split_or_sooner_or_never",
        "facade:tests/camel_split_loop.rs:split_failure_accounting_counts_stops_and_reports",
        "facade:tests/camel_split_loop.rs:split_refuses_its_shape_and_bound_faults",
    ],
    "Loop": [
        "facade:tests/camel_split_loop.rs:a_count_loop_repeats_with_loop_properties",
        "facade:tests/camel_split_loop.rs:a_do_while_loop_tests_its_predicate_before_each_iteration",
        "facade:tests/camel_split_loop.rs:a_loop_at_its_bound_completes_and_one_past_it_raises",
        "facade:tests/camel_split_loop.rs:a_loop_count_must_be_an_integer_and_the_shape_must_be_well_formed",
        "facade:tests/camel_split_loop.rs:copy_mode_starts_each_iteration_from_the_original_and_keeps_the_last",
    ],
    "Content Enricher": [
        "facade:tests/camel_split_loop.rs:enrich_merges_the_resource_reply_through_its_strategy",
        "facade:tests/camel_split_loop.rs:enrich_failure_propagates_unless_it_aggregates_on_exception",
        "facade:tests/camel_split_loop.rs:enrich_refuses_the_unserved_shapes_at_load",
    ],
    "Aggregation strategies": [
        "engine:src/processor/aggregation/mod.rs:use_latest_and_use_original_pick_their_bodies",
        "engine:src/processor/aggregation/mod.rs:grouped_body_concatenates_and_skips_null_bodies",
        "engine:src/processor/aggregation/mod.rs:json_array_append_appends_into_the_named_member_and_refuses_duplicates",
        "engine:src/processor/aggregation/mod.rs:json_merge_merges_member_wise_into_the_named_member",
        "engine:src/processor/aggregation/mod.rs:the_properties_map_sets_carries_and_clears",
        "engine:src/processor/aggregation/mod.rs:a_custom_strategy_returns_its_body_and_properties",
        "engine:src/processor/aggregation/mod.rs:a_custom_strategy_without_a_body_member_fails",
    ],
    "Default error handler": [
        "facade:tests/camel_error_cluster.rs:the_error_handler_shapes_the_attempts_and_clause_reach",
        "facade:tests/camel_error_cluster.rs:the_default_error_handler_redelivers_under_its_policy",
        "facade:tests/camel_error_cluster.rs:the_clause_policy_governs_its_classes_and_the_handler_the_rest",
        "facade:tests/camel_error_cluster.rs:the_route_error_handler_does_not_wrap_a_do_try_block",
    ],
    "Redelivery policy": [
        "engine:src/processor/redelivery.rs:the_model_policy_maps_onto_the_platform_computation",
        "engine:src/processor/redelivery.rs:a_draw_stays_inside_the_factor",
        "platform:registry-platform-resilience/src/redelivery.rs:the_first_delay_is_the_retry_delay_whatever_the_growth",
        "platform:registry-platform-resilience/src/redelivery.rs:the_delay_grows_only_with_back_off_and_a_multiplier_above_one",
        "platform:registry-platform-resilience/src/redelivery.rs:the_variance_applies_after_the_growth_and_the_cap_bounds_it",
        "platform:registry-platform-resilience/src/redelivery.rs:a_delay_sequence_follows_the_whole_order",
        "facade:tests/camel_error_cluster.rs:retry_while_narrows_redelivery_without_raising_the_cap",
    ],
    "Exception clause": [
        "facade:tests/camel_error_cluster.rs:handled_ends_continued_resumes_and_default_propagates",
        "facade:tests/camel_error_cluster.rs:a_clause_error_replaces_the_failure_and_keeps_the_original",
        "facade:tests/camel_error_cluster.rs:an_uncatchable_class_matches_no_clause",
        "facade:tests/camel_error_cluster.rs:the_cluster_refuses_its_unservable_shapes_at_load",
    ],
    "Try, catch, finally": [
        "facade:tests/camel_error_cluster.rs:do_try_catches_its_block_and_resumes_the_route",
        "facade:tests/camel_error_cluster.rs:a_do_catch_on_when_narrows_or_fails",
        "facade:tests/camel_error_cluster.rs:do_finally_runs_on_every_path_and_yields_to_a_pending_failure",
    ],
    "Circuit Breaker": [
        "facade:tests/camel_resilience.rs:a_failure_storm_opens_the_breaker_and_refuses_without_calling",
        "facade:tests/camel_resilience.rs:on_fallback_answers_on_failure_and_on_rejection",
        "facade:tests/camel_resilience.rs:an_open_breaker_recovers_through_half_open_trials",
        "facade:tests/camel_resilience.rs:the_route_error_handler_does_not_wrap_a_breaker_block",
        "facade:tests/camel_resilience.rs:the_resilience_steps_refuse_their_unservable_shapes_at_load",
    ],
    "Throttler": [
        "facade:tests/camel_resilience.rs:the_throttler_paces_requests_over_the_period",
        "facade:tests/camel_resilience.rs:reject_execution_refuses_instead_of_waiting",
        "facade:tests/camel_resilience.rs:a_wait_past_the_deadline_raises_throttle_rejected",
        "facade:tests/camel_resilience.rs:concurrent_requests_mode_bounds_in_flight_calls",
        "facade:tests/camel_resilience.rs:concurrent_requests_mode_rejects_over_the_limit",
        "facade:tests/camel_resilience.rs:a_non_integer_limit_fails_the_exchange",
    ],
    "direct": [
        "facade:tests/camel_direct.rs:a_direct_call_shares_the_exchange_and_its_changes",
        "facade:tests/camel_direct.rs:the_targets_own_clauses_handle_the_target_first",
        "facade:tests/camel_direct.rs:an_unhandled_target_error_reaches_the_callers_clauses",
        "facade:tests/camel_direct.rs:a_direct_send_is_never_redelivered",
        "facade:tests/camel_direct.rs:the_targets_own_sends_carry_their_redelivery",
        "facade:tests/camel_direct.rs:a_stop_in_the_target_ends_the_whole_route",
        "facade:tests/camel_direct.rs:a_direct_send_to_an_undeclared_route_fails_the_exchange",
        "facade:tests/camel_direct.rs:an_undeclared_direct_target_is_refused_at_load",
        "facade:tests/camel_direct.rs:a_direct_chain_past_the_bounded_depth_is_refused_at_run",
        "facade:tests/camel_direct.rs:a_direct_send_with_parameters_is_not_served",
    ],
    "to": [
        "facade:tests/camel_origin_link.rs:an_http_uri_send_follows_the_source_link_as_written",
        "facade:tests/camel_origin_link.rs:a_link_off_the_endpoint_origin_is_refused_without_a_send",
        "facade:tests/camel_origin_link.rs:a_link_on_another_host_is_refused",
        "facade:tests/camel_origin_link.rs:a_link_outside_the_base_path_is_refused",
        "facade:tests/camel_origin_link.rs:a_link_with_a_fragment_or_userinfo_is_refused",
        "facade:tests/camel_origin_link.rs:a_link_the_parser_would_repair_is_refused",
        "facade:tests/camel_origin_link.rs:a_non_string_link_fails_the_exchange_as_validation",
        "facade:tests/camel_origin_link.rs:a_query_beside_an_http_uri_is_not_served",
        "facade:tests/camel_origin_link.rs:a_path_and_an_http_uri_together_are_not_served",
        "facade:tests/camel_error_cluster.rs:the_error_handler_shapes_the_attempts_and_clause_reach",
    ],
    "graphql": [
        "facade:tests/camel_graphql.rs:a_send_posts_the_pinned_query_with_its_operation_and_variables",
        "facade:tests/camel_graphql.rs:the_endpoints_variables_expression_answers_when_the_send_carries_no_body",
        "facade:tests/camel_graphql.rs:an_errors_array_fails_the_exchange_as_upstream_http",
        "facade:tests/camel_graphql.rs:partial_data_with_errors_still_fails_the_exchange",
        "facade:tests/camel_graphql.rs:variables_that_yield_no_object_fail_as_validation",
        "facade:tests/camel_graphql.rs:a_graphql_send_to_an_endpoint_without_a_query_is_refused",
        "facade:tests/camel_graphql.rs:the_graphql_send_shape_carries_operation_and_body_only",
        "facade:tests/camel_graphql.rs:the_loader_holds_the_query_files_own_line",
    ],
    "Type Converter": [
        "facade:tests/camel_conversion.rs:the_body_conversion_writes_each_scalar_kind",
        "facade:tests/camel_conversion.rs:a_null_body_passes_through_whatever_mandatory_says",
        "facade:tests/camel_conversion.rs:a_non_string_body_raises_conversion_unmapped",
        "facade:tests/camel_conversion.rs:a_miss_raises_unless_mandatory_is_false",
        "facade:tests/camel_conversion.rs:the_lookup_is_exact_and_case_sensitive",
        "facade:tests/camel_conversion.rs:the_header_conversion_replaces_in_place_and_to_name_redirects",
        "facade:tests/camel_conversion.rs:an_absent_header_and_a_lenient_miss_write_nothing",
        "facade:tests/camel_conversion.rs:a_non_string_header_value_raises_conversion_unmapped",
        "facade:tests/camel_conversion.rs:the_property_conversion_follows_the_header_form",
        "facade:tests/camel_conversion.rs:a_conversion_naming_no_declared_map_fails_the_exchange",
        "facade:tests/camel_conversion.rs:the_served_shape_is_refused_by_name",
        "facade:tests/camel_conversion.rs:rhai_code_map_takes_the_same_lookup",
        "facade:tests/camel_conversion.rs:the_declared_map_parses_from_the_pack_form",
        "checks.rs:routes_accept_a_well_formed_conversion",
        "checks.rs:routes_refuse_a_conversion_naming_no_declared_code_map",
        "checks.rs:routes_refuse_the_conversion_shapes",
        "checks.rs:pack_refuses_a_code_map_entry_that_is_not_a_scalar",
        "checks.rs:pack_refuses_a_code_map_no_conversion_references",
    ],
    "Exchange, MEP": [
        "engine:src/exchange.rs:headers_are_case_insensitive",
        "facade:tests/records_get_served.rs:a_found_record_comes_back_shaped_through_the_served_binary",
    ],
    "Message": [
        "engine:src/exchange.rs:headers_are_case_insensitive",
        "engine:src/exchange.rs:script_value_lowercases_headers_and_keeps_a_null_body",
    ],
    "REST DSL contract-first": [
        "facade:tests/records_get_served.rs:a_found_record_comes_back_shaped_through_the_served_binary",
        "facade:tests/person_search_served.rs:an_undeclared_or_out_of_bounds_input_is_refused_before_any_upstream_call",
        "facade:tests/person_search_served.rs:the_first_page_comes_back_shaped_with_a_sealed_cursor",
        "facade:tests/govstack_consultation_served.rs:one_record_comes_back_as_a_record",
        "facade:tests/govstack_consultation_served.rs:a_cursor_refuses_a_different_page_size_and_a_forged_text",
    ],
    "http": [
        "facade:tests/camel_http_uri.rs:the_query_is_sent_as_written",
        "facade:tests/camel_http_uri.rs:a_query_the_parser_would_rewrite_is_refused",
        "facade:tests/camel_origin_link.rs:an_http_uri_send_follows_the_source_link_as_written",
        "facade:tests/camel_origin_link.rs:a_link_off_the_endpoint_origin_is_refused_without_a_send",
        "facade:tests/camel_http_authentication.rs:static_authorization_presents_the_declared_scheme",
        "facade:tests/records_get_served.rs:an_identifier_with_a_space_or_a_non_ascii_character_is_sent_as_one_encoded_segment",
    ],
    "Simple, bean, process": [
        "facade:tests/opencrvs_scripts.rs:only_the_mapped_declaration_keys_reach_the_record_under_the_mapped_field",
        "facade:tests/script_budget.rs:a_reply_at_the_cap_is_processed",
    ],
    "Throw Exception": [
        "route.rs:throw_exception_step_round_trips",
        "facade:tests/camel_error_cluster.rs:a_clause_error_replaces_the_failure_and_keeps_the_original",
        "facade:tests/camel_error_cluster.rs:an_uncatchable_class_matches_no_clause",
        "facade:tests/camel_direct.rs:the_targets_own_clauses_handle_the_target_first",
    ],
    "Event Notifier": [
        "facade:tests/postgres_journal.rs:the_journal_refuses_unknown_kinds_and_oversized_details",
        "facade:tests/postgres_journal.rs:append_stamps_occurred_at_from_the_runtime_clock",
        "facade:tests/records_get_served.rs:a_verified_caller_refused_by_scope_or_record_type_is_journaled_without_values",
        "facade:tests/records_get_served.rs:every_401_path_leaves_a_value_free_log_line",
    ],
    # Increment 4 source rows remain pending. These references record the
    # mechanically valid tests that exist now without promoting the increment
    # or its wider acceptance claims.
    "file (job source) [ingestion]": [
        "facade:tests/camel_file.rs:a_raw_read_orders_the_files_and_ends_the_scan",
        "facade:tests/camel_file.rs:the_noop_divergence_re_reads_a_consumed_file",
        "facade:tests/camel_file.rs:the_done_file_forms_gate_candidates",
        "facade:tests/camel_file.rs:the_changed_read_lock_paces_a_stable_file",
        "facade:tests/camel_file.rs:max_messages_per_poll_bounds_the_candidates",
        "facade:tests/camel_file.rs:a_symlink_escape_refuses_the_read",
    ],
    "CSV data format [ingestion]": [
        "facade:tests/camel_csv.rs:the_pipe_delimiter_reads_maps",
        "facade:tests/camel_csv.rs:a_quoted_multiline_field_decodes_whole",
        "facade:tests/camel_csv.rs:a_comment_marker_line_is_not_a_record",
        "facade:tests/camel_csv.rs:the_header_disabled_decoder_reads_arrays",
        "facade:tests/camel_file.rs:an_oversized_csv_row_refuses_the_read",
    ],
    "JSONL decoder [ingestion]": [
        "facade:tests/camel_jsonl.rs:a_malformed_line_continues_with_a_count",
        "facade:tests/camel_jsonl.rs:jsonl_pages_at_the_rows_bound",
        "facade:tests/camel_jsonl.rs:an_oversized_line_refuses_the_read",
    ],
    "SQL (read-only job source) [ingestion]": [
        "facade:tests/camel_sql.rs:the_query_compile_refuses_everything_but_one_plain_select",
        "facade:tests/camel_sql.rs:a_send_over_the_seam_pages_and_shapes_rows",
        "facade:tests/camel_sql.rs:the_read_only_transaction_refuses_a_write",
        "facade:tests/camel_sql.rs:a_real_fetch_bounds_its_rows_and_statement",
        "job:src/postgres_source.rs:cancelled_read_is_detached_before_same_pool_creates_fresh_backend",
        "job:src/postgres_source.rs:tls_cancelled_read_is_detached_before_same_pool_creates_fresh_backend",
        "job:tests/postgres_source_host.rs:actual_named_parameters_bind_text_integer_float_and_boolean_values",
    ],
    "sftp (job source) [ingestion]": [
        "job:tests/sftp_cli_host.rs:check_refuses_invalid_or_unsupported_host_keys_without_effects",
        "job:tests/sftp_cli_host.rs:actual_cli_pass_recovers_cursor_and_same_name_replacement",
        "job:src/sftp_source.rs:done_file_gates_partial_file_and_completed_file_is_read_only",
        "job:src/sftp_source.rs:stalled_and_oversize_reads_are_bounded",
        "job:src/sftp_source.rs:traversal_symlink_and_off_root_candidates_are_refused",
        "job:src/sftp_source.rs:incorrect_host_key_does_not_reach_credential_resolution_or_authentication",
    ],
    "pollEnrich (job only) [ingestion]": [
        "checks.rs:poll_steps_check_their_uri_timeout_and_decoder",
        "facade:tests/camel_file.rs:a_raw_read_orders_the_files_and_ends_the_scan",
        "facade:tests/camel_csv.rs:the_read_aggregates_like_an_enrich",
        "facade:tests/adapter_job.rs:the_default_build_refuses_a_file_job",
    ],
    "rabbitmq (job source) [ingestion]": [
        "job:tests/rabbitmq_source.rs:real_broker_manual_settlement_and_failure_contract",
        "job:tests/rabbitmq_pass.rs:real_broker_and_postgres_pass_acknowledge_only_after_durable_acceptance",
    ],
    "RabbitMQ JSON decoder [ingestion]": [
        "job:tests/rabbitmq_pass.rs:rabbitmq_json_refuses_strings_and_keys_over_the_profile_field_bound",
    ],
}

SECTION = "### 8.10 The Camel port table"
HEADER_CELLS = ["Camel concept", "Reference (camel.apache.org)", "Our form", "Divergence", "Inc"]

#: A reference span: a relative Camel documentation path. No scheme, no
#: leading slash, no domain, a `.html` page.
REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_/.-]*\.html$")

BACKTICKED = re.compile(r"`([^`]+)`")


def parse_table(text: str) -> tuple[list[tuple[int, list[str]]], list[str]]:
    """Return the table rows with their line numbers, and any problems."""
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if line.strip() == SECTION), None)
    if start is None:
        return [], [f"FAIL: {CONCEPT}: section '{SECTION}' not found"]
    rows: list[tuple[int, list[str]]] = []
    problems: list[str] = []
    header_seen = False
    for offset in range(start, len(lines)):
        line = lines[offset]
        if not line.startswith("|"):
            if header_seen:
                break
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if cells == HEADER_CELLS:
            header_seen = True
            continue
        if all(set(cell) <= {"-"} for cell in cells):
            continue
        if not header_seen:
            continue
        rows.append((offset + 1, cells))
    if not rows:
        problems.append(f"FAIL: {CONCEPT}:{start + 1}: the port table has no rows")
    return rows, problems


def check_references(row: int, cells: list[str]) -> list[str]:
    """Every backticked span in the reference cell is a relative path."""
    problems = []
    for span in BACKTICKED.findall(cells[1]):
        if "://" in span or span.startswith(("/", "www.")) or ".org" in span or ".com" in span:
            problems.append(
                f"FAIL: {CONCEPT}:{row}: reference '{span}' is not a relative camel.apache.org path"
            )
        elif not REFERENCE.match(span):
            problems.append(
                f"FAIL: {CONCEPT}:{row}: reference '{span}' is not a Camel documentation page path"
            )
    return problems


def has_rust_test_function(source: str, function: str) -> bool:
    """Whether source declares the named function as an attributed Rust test."""
    attributed_function = re.compile(
        rf"(?P<attributes>(?:^[ \t]*#\[[^\]]*\][ \t]*(?:\n|$)"
        rf"|^[ \t]*//[^\n]*(?:\n|$)|^[ \t]*\n)+)"
        rf"^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?(?:async[ \t]+)?"
        rf"fn[ \t]+{re.escape(function)}\b",
        re.MULTILINE,
    )
    return any(
        re.search(
            r"^[ \t]*#\[\s*(?:test|tokio::test)\b",
            match.group("attributes"),
            re.MULTILINE,
        )
        for match in attributed_function.finditer(source)
    )


def function_exists(relative: str) -> bool:
    """Whether the entry names an attributed Rust test function.

    A plain `file.rs:function` resolves against the core sources;
    `engine:file.rs:function` resolves against the shared engine;
    `facade:file.rs:function` resolves against the facade conformance tree;
    `job:file.rs:function` resolves against the job-host conformance tree;
    `platform:crate/file.rs:function` resolves against crates/.
    """
    roots = {
        "engine": ENGINE_ROOT,
        "facade": FACADE_ROOT,
        "job": JOB_ROOT,
        "platform": REPO_ROOT / "crates",
    }
    prefix, _, remainder = relative.partition(":")
    root = roots.get(prefix, CORE_SRC)
    if prefix in roots:
        relative = remainder
    file, _, function = relative.partition(":")
    if not file or not function:
        return False
    source = root / file
    if not source.is_file():
        return False
    return has_rust_test_function(source.read_text(encoding="utf-8"), function)


def check_evidence(row: int, concept: str, inc: int) -> list[str]:
    """A delivered row names tests that exist; a pending row's recorded
    evidence must still resolve, so the map cannot rot while its
    increment waits."""
    mapped = EVIDENCE.get(concept)
    if not mapped:
        if inc > INCREMENT_DELIVERED:
            return []
        return [
            f"FAIL: {CONCEPT}:{row}: delivered row '{concept}' names no conformance tests"
        ]
    return [
        f"FAIL: {CONCEPT}:{row}: evidence '{relative}' of '{concept}' is not a test function"
        for relative in mapped
        if not function_exists(relative)
    ]


def accepted_keys(schema: dict) -> tuple[set[str], list[str]]:
    """The step, language, EIP, and component keys the pack schema accepts."""
    keys: set[str] = set()
    problems: list[str] = []
    definitions = schema.get("$defs")

    def union_keys(name: str) -> None:
        for branch in definitions.get(name, {}).get("oneOf", []):
            properties = branch.get("properties", {})
            if len(properties) == 1:
                keys.add(next(iter(properties)))

    def const_keys(name: str) -> None:
        node = definitions.get(name, {})
        for value in node.get("enum", []):
            keys.add(value)
        for branch in node.get("anyOf", []):
            if "const" in branch:
                keys.add(branch["const"])
            properties = branch.get("properties", {})
            if len(properties) == 1:
                keys.add(next(iter(properties)))

    for name in ("Step", "Expression", "AggregationStrategy"):
        union_keys(name)
    for name in ("Eip", "Language", "ComponentKind"):
        const_keys(name)
    if not keys:
        problems.append(f"FAIL: {PACK_SCHEMA}: no accepted step, language, or component keys found")
    return keys, problems


def main() -> int:
    problems: list[str] = []
    if not CONCEPT.is_file():
        print(f"FAIL: {CONCEPT}: not found")
        return 1
    rows, parse_problems = parse_table(CONCEPT.read_text(encoding="utf-8"))
    problems.extend(parse_problems)
    if parse_problems:
        for line in problems:
            print(line)
        return 1

    concepts: set[str] = set()
    pending: list[str] = []
    delivered = 0
    for row, cells in rows:
        if len(cells) != 5:
            problems.append(f"FAIL: {CONCEPT}:{row}: row has {len(cells)} cells, expected 5")
            continue
        concept = cells[0].replace("`", "")
        if concept in concepts:
            problems.append(f"FAIL: {CONCEPT}:{row}: duplicate row for '{concept}'")
        concepts.add(concept)
        problems.extend(check_references(row, cells))
        try:
            inc = int(cells[4])
        except ValueError:
            problems.append(f"FAIL: {CONCEPT}:{row}: Inc '{cells[4]}' is not an increment number")
            continue
        problems.extend(check_evidence(row, concept, inc))
        if inc > INCREMENT_DELIVERED:
            pending.append(f"{concept} (Inc {inc})")
        else:
            delivered += 1

    if PACK_SCHEMA.is_file():
        schema = json.loads(PACK_SCHEMA.read_text(encoding="utf-8"))
        keys, key_problems = accepted_keys(schema)
        problems.extend(key_problems)
        row_text = "\n".join("|".join(cells) for _, cells in rows)
        for key in sorted(keys):
            if key not in row_text:
                problems.append(
                    f"FAIL: {PACK_SCHEMA}: accepted key '{key}' has no port-table row"
                )
    else:
        problems.append(
            f"FAIL: {PACK_SCHEMA}: generated schemas are missing; run `adapterctl schemas` first"
        )

    for line in problems:
        print(line)
    if problems:
        print(f"{len(problems)} failed")
        return 1
    print(
        f"port table holds: {len(rows)} rows, {delivered} delivered with evidence, "
        f"{len(pending)} pending"
    )
    for row in pending:
        print(f"pending: {row}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
