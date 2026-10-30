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
   in `EVIDENCE` below, to at least one named test function, and each
   named function must exist in the mapped file. Core rows map into
   `crates/registry-adapter-core/src/`; runtime rows map through the
   `engine:` form into the engine crate's conformance suites and unit
   tests. A row with a higher Inc is reported as pending and never fails
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
row to the code). Extend this map when an increment lands. The 2026-10-31
port walk additionally recorded the engine conformance suites for the
runtime rows the code already delivers (HeaderFilterStrategy, HTTP
authentication, Languages); they stay pending until increment 1 lands as
a whole.

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
ENGINE_ROOT = REPO_ROOT / "crates" / "registry-adapter"
PACK_SCHEMA = SCHEMAS / "pack.v1alpha1.schema.json"

#: The highest increment this tree delivers. Rows above it are pending.
INCREMENT_DELIVERED = 0

#: Delivered row concept -> the test functions that evidence it. An entry
#: "file.rs:function_name" resolves against crates/registry-adapter-core/src/;
#: "engine:file.rs:function_name" resolves against the engine crate's own
#: tree (tests/ conformance suites and src/ unit tests), because the runtime
#: rows are proven by the engine's suites, not by core authoring checks.
#: Every entry is held to existence even while its row's increment is still
#: pending, so the map cannot rot before the increment lands.
EVIDENCE: dict[str, list[str]] = {
    "HeaderFilterStrategy": [
        "engine:tests/camel_header_filter.rs:every_reserved_name_is_refused_in_either_list",
        "engine:tests/camel_header_filter.rs:only_listed_request_headers_are_sent",
        "engine:tests/camel_header_filter.rs:only_declared_response_headers_are_copied_under_their_declared_names",
    ],
    "HTTP authentication": [
        "engine:tests/camel_http_authentication.rs:basic_sends_one_preemptive_header",
        "engine:tests/camel_http_authentication.rs:static_kinds_render_no_marker",
        "engine:tests/camel_http_authentication.rs:a_401_with_an_unparseable_body_is_still_rejected",
        "engine:src/auth/material.rs:basic_values_encode_and_refuse",
    ],
    "Languages": [
        "engine:tests/language.rs:a_selector_over_the_length_bound_is_refused",
        "engine:tests/language.rs:a_singular_query_yields_its_one_value",
        "engine:tests/language.rs:any_other_query_yields_the_node_list",
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


def function_exists(relative: str) -> bool:
    """Whether the entry names a `fn` item that exists.

    A plain `file.rs:function` resolves against the core sources; an
    `engine:file.rs:function` resolves against the engine crate's own
    tree, where the runtime conformance suites live.
    """
    engine = relative.startswith("engine:")
    if engine:
        relative = relative[len("engine:") :]
    file, _, function = relative.partition(":")
    if not file or not function:
        return False
    source = (ENGINE_ROOT if engine else CORE_SRC) / file
    if not source.is_file():
        return False
    return re.search(rf"\bfn {re.escape(function)}\b", source.read_text(encoding="utf-8")) is not None


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
