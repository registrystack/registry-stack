"""Tests for run-config-conformance.py.

The mutation tests apply one corpus operation to a small example and assert
the exact text the runner writes and the positions it expects the reader to
report. The report tests feed the runner hand-written check output and assert
the problems it finds. The end-to-end tests build a repository in a temporary
directory, with a format registry, a corpus, and a fake check command, and run
the runner over it. The corpus tests load the committed corpus and harness.
Test names cite the rule they prove.

Run with PyYAML available:

    uv run --no-project --with PyYAML==6.0.2 python -m unittest \
        products/platform/scripts/test_run_config_conformance.py
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import yaml

SCRIPT = Path(__file__).with_name("run-config-conformance.py")
SPEC = importlib.util.spec_from_file_location("run_config_conformance", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)

ROOT = Path(__file__).resolve().parents[3]

EXAMPLE = """\
# A demo project.
apiVersion: id.registrystack.org/formats/demo/project/v1alpha1
kind: DemoProject
project:
  id: demo
  version: "1"
listener:
  bind: 127.0.0.1:8080
  timeoutSeconds: 30
items:
  - id: first
    enabled: true
    note: 'quoted'
labels: {owner: team}
"""


def demo_format(**changes) -> "runner.Format":
    values = dict(
        id="demo/project",
        syntax="yaml",
        audience="authored",
        check="fakectl check {project}",
        example="products/demo/example/project.yaml",
        kind="DemoProject",
        roles={
            "requiredText": "/project/id",
            "optionalText": "/items/0/note",
            "integer": "/listener/timeoutSeconds",
            "boolean": "/items/0/enabled",
        },
        harness={},
    )
    values.update(changes)
    return runner.Format(**values)


def one(variants):
    assert len(variants) == 1, variants
    return variants[0]


class PlaceholderTest(unittest.TestCase):
    def test_marker_and_repeat_expand(self) -> None:
        self.assertEqual(
            runner.expand("a: {marker} {repeat:3:[}", {}),
            f"a: {runner.MARKER} [[[",
        )

    def test_named_values_expand_and_unknown_braces_stay(self) -> None:
        self.assertEqual(
            runner.expand('"${NAME}" {pointer} {other}', {"pointer": "/a/b"}),
            '"${NAME}" /a/b {other}',
        )

    def test_cfg_diag_6_unit_word_comes_from_the_key(self) -> None:
        self.assertEqual(runner.unit_word("timeoutSeconds"), "seconds")
        self.assertEqual(runner.unit_word("dueWorkingDays"), "working days")
        self.assertEqual(runner.unit_word("milliseconds"), "milliseconds")
        self.assertIsNone(runner.unit_word("maximumItems"))
        self.assertEqual(runner.number_of_unit("recordDays"), "number of days")
        self.assertEqual(runner.number_of_unit("maximumItems"), "number")

    def test_cfg_change_1_spelling_variant(self) -> None:
        self.assertEqual(runner.spelling_variant("timeoutSeconds"), "timeout_seconds")
        self.assertEqual(runner.spelling_variant("max_length"), "maxLength")
        self.assertIsNone(runner.spelling_variant("id"))


class MutationTest(unittest.TestCase):
    def test_cfg_check_3_append_anchors_the_line_after_the_example(self) -> None:
        variant = one(runner.mutate(EXAMPLE, {"append": "x: 1\ny: 2\n"}, demo_format()))
        self.assertEqual(variant.text, EXAMPLE + "x: 1\ny: 2\n")
        self.assertEqual(variant.sites[0].anchors["start"], (15, 1))

    def test_append_completes_a_missing_final_newline(self) -> None:
        variant = one(runner.mutate("a: 1", {"append": "b: 2\n"}, demo_format()))
        self.assertEqual(variant.text, "a: 1\nb: 2\n")
        self.assertEqual(variant.sites[0].anchors["start"], (2, 1))

    def test_prepend_and_replace_anchor_the_first_line(self) -> None:
        variant = one(runner.mutate(EXAMPLE, {"prepend": "---\n"}, demo_format()))
        self.assertEqual(variant.text, "---\n" + EXAMPLE)
        self.assertEqual(variant.sites[0].anchors["start"], (1, 1))
        variant = one(runner.mutate(EXAMPLE, {"replace": ""}, demo_format()))
        self.assertEqual(variant.text, "")
        self.assertEqual(variant.sites[0].anchors["start"], (1, 1))

    def test_no_mutation_keeps_the_example(self) -> None:
        variant = one(runner.mutate(EXAMPLE, None, demo_format()))
        self.assertEqual(variant.text, EXAMPLE)

    def test_cfg_check_3_member_replaces_the_registered_scalar(self) -> None:
        variant = one(
            runner.mutate(EXAMPLE, {"member": {"role": "integer", "value": '"7"'}}, demo_format())
        )
        self.assertIn('  timeoutSeconds: "7"\n', variant.text)
        site = variant.sites[0]
        self.assertEqual(site.anchors["value"], (9, 19))
        self.assertEqual(site.anchors["key"], (9, 3))
        self.assertEqual(site.values["pointer"], "/listener/timeoutSeconds")
        self.assertEqual(site.values["numberOfUnit"], "number of seconds")

    def test_member_replaces_a_quoted_scalar_with_its_quotes(self) -> None:
        variant = one(
            runner.mutate(EXAMPLE, {"member": {"role": "optionalText", "value": "~"}}, demo_format())
        )
        self.assertIn("    note: ~\n", variant.text)
        self.assertEqual(variant.sites[0].anchors["value"], (13, 11))

    def test_member_with_an_empty_value_leaves_the_key(self) -> None:
        variant = one(
            runner.mutate(EXAMPLE, {"member": {"role": "requiredText", "value": ""}}, demo_format())
        )
        self.assertIn("  id: \n", variant.text)
        self.assertEqual(variant.sites[0].anchors["key"], (5, 3))

    def test_member_role_none_does_not_apply(self) -> None:
        fmt = demo_format(roles={"integer": None})
        with self.assertRaises(runner.NotApplicable):
            runner.mutate(EXAMPLE, {"member": {"role": "integer", "value": "1"}}, fmt)

    def test_member_pointer_the_example_lacks_is_a_harness_error(self) -> None:
        fmt = demo_format(roles={"integer": "/listener/missing"})
        with self.assertRaises(runner.HarnessError):
            runner.mutate(EXAMPLE, {"member": {"role": "integer", "value": "1"}}, fmt)

    def test_cfg_env_1_envelope_replaces_kind_and_anchors_it(self) -> None:
        variant = one(
            runner.mutate(EXAMPLE, {"envelope": {"kind": "{marker}"}}, demo_format())
        )
        self.assertIn(f"kind: {runner.MARKER}\n", variant.text)
        self.assertIn("apiVersion: id.registrystack.org/formats/demo/project/v1alpha1\n", variant.text)
        self.assertEqual(variant.sites[0].anchors["kind"], (3, 7))
        self.assertEqual(variant.sites[0].anchors["apiVersion"], (2, 13))

    def test_cfg_env_1_envelope_removal_anchors_the_root(self) -> None:
        variant = one(
            runner.mutate(
                EXAMPLE, {"envelope": {"apiVersion": "remove", "kind": "remove"}}, demo_format()
            )
        )
        self.assertNotIn("apiVersion", variant.text)
        self.assertNotIn("kind:", variant.text)
        self.assertTrue(variant.text.startswith("# A demo project.\nproject:\n"))
        self.assertEqual(variant.sites[0].anchors["root"], (2, 1))
        self.assertNotIn("kind", variant.sites[0].anchors)

    def test_envelope_inserts_an_absent_member_before_the_first_key(self) -> None:
        bare = "# Note.\nid: demo\n"
        variant = one(runner.mutate(bare, {"envelope": {"kind": "Other"}}, demo_format()))
        self.assertEqual(variant.text, "# Note.\nkind: Other\nid: demo\n")
        self.assertEqual(variant.sites[0].anchors["kind"], (2, 7))

    def test_cfg_change_2_removed_keys_go_into_their_parent_mapping(self) -> None:
        fmt = demo_format(
            harness={"removedKeys": ["/listener/port", "/version", "/metrics/port"]}
        )
        variant = one(runner.mutate(EXAMPLE, {"removedKeys": {"value": "{marker}"}}, fmt))
        self.assertIn(f"  timeoutSeconds: 30\n  port: {runner.MARKER}\nitems:\n", variant.text)
        self.assertTrue(variant.text.endswith(f"labels: {{owner: team}}\nversion: {runner.MARKER}\n"))
        self.assertNotIn("metrics", variant.text)
        anchors = {site.values["pointer"]: site.anchors["key"] for site in variant.sites}
        self.assertEqual(anchors, {"/listener/port": (10, 3), "/version": (16, 1)})

    def test_removed_keys_without_a_present_parent_do_not_apply(self) -> None:
        fmt = demo_format(harness={"removedKeys": ["/metrics/port"]})
        with self.assertRaises(runner.NotApplicable):
            runner.mutate(EXAMPLE, {"removedKeys": {"value": "x"}}, fmt)

    def test_removed_keys_insert_into_a_flow_mapping(self) -> None:
        fmt = demo_format(harness={"removedKeys": ["/labels/team"]})
        variant = one(runner.mutate(EXAMPLE, {"removedKeys": {"value": "x"}}, fmt))
        self.assertIn("labels: {owner: team, team: x}\n", variant.text)
        self.assertEqual(variant.sites[0].anchors["key"], (14, 23))

    def test_cfg_change_2_retired_api_versions_replace_the_value(self) -> None:
        fmt = demo_format(harness={"retiredApiVersions": ["demo/v1", "demo/v2"]})
        variants = runner.mutate(EXAMPLE, {"retiredApiVersion": {}}, fmt)
        self.assertEqual(len(variants), 2)
        self.assertIn("apiVersion: demo/v1\n", variants[0].text)
        self.assertEqual(variants[1].sites[0].anchors["apiVersion"], (2, 13))

    def test_retired_api_version_without_a_declaration_does_not_apply(self) -> None:
        with self.assertRaises(runner.NotApplicable):
            runner.mutate(EXAMPLE, {"retiredApiVersion": {}}, demo_format())

    def test_cfg_change_1_spelling_inserts_the_other_spelling_beside_the_member(self) -> None:
        variant = one(runner.mutate(EXAMPLE, {"spelling": {"role": "integer"}}, demo_format()))
        self.assertIn("  timeoutSeconds: 30\n  timeout_seconds: 30\n", variant.text)
        site = variant.sites[0]
        self.assertEqual(site.values["pointer"], "/listener/timeout_seconds")
        self.assertEqual(site.anchors["key"], (10, 3))

    def test_spelling_of_a_one_word_key_does_not_apply(self) -> None:
        with self.assertRaises(runner.NotApplicable):
            runner.mutate(EXAMPLE, {"spelling": {"role": "requiredText"}}, demo_format())

    def test_unknown_operation_is_a_harness_error(self) -> None:
        with self.assertRaises(runner.HarnessError):
            runner.mutate(EXAMPLE, {"rename": {}}, demo_format())


class EncodingTest(unittest.TestCase):
    def test_cfg_yaml_6_byte_order_mark_and_crlf(self) -> None:
        data = runner.encode("a: 1\nb: 2\n", {"byteOrderMark": True, "lineEndings": "crlf"})
        self.assertEqual(data, b"\xef\xbb\xbfa: 1\r\nb: 2\r\n")

    def test_append_bytes_are_raw(self) -> None:
        self.assertEqual(runner.encode("# x ", {"appendBytes": "ff0a"}), b"# x \xff\n")

    def test_cfg_yaml_6_size_pads_with_comments_to_the_exact_byte(self) -> None:
        for size in (1048576, 1048577, 1025, 1026, 1027, 7, 8):
            data = runner.encode("a: 1\n", {"size": size})
            self.assertEqual(len(data), size, size)
            self.assertTrue(data.startswith(b"a: 1\n"))
            for line in data.decode().splitlines()[1:]:
                self.assertTrue(line == "" or line.startswith("#"), line)

    def test_size_smaller_than_the_text_is_a_harness_error(self) -> None:
        with self.assertRaises(runner.HarnessError):
            runner.encode("a: 1\n", {"size": 3})


class ExpectationTest(unittest.TestCase):
    def test_relative_positions(self) -> None:
        self.assertEqual(runner.relative((9, 19), {"line": 1, "column": 1}), (9, 19))
        self.assertEqual(runner.relative((9, 19), {"line": 1, "column": 3}), (9, 21))
        self.assertEqual(runner.relative((9, 19), {"line": 2, "column": 3}), (10, 3))

    def test_cfg_check_3_expectations_resolve_against_each_site(self) -> None:
        fmt = demo_format()
        variant = one(
            runner.mutate(EXAMPLE, {"member": {"role": "integer", "value": "7s"}}, fmt)
        )
        expect = {
            "exit": 1,
            "diagnostics": [
                {
                    "code": "config.expected-integer",
                    "path": "{pointer}",
                    "at": {"line": 1, "column": 1},
                    "suggestedAction": "Write the {numberOfUnit} as digits.",
                }
            ],
        }
        resolved = runner.resolve_expected(expect, "member", variant, "/w/project.yaml")
        self.assertEqual(
            resolved,
            [
                {
                    "severity": "error",
                    "code": "config.expected-integer",
                    "path": "/listener/timeoutSeconds",
                    "file": "/w/project.yaml",
                    "line": 9,
                    "column": 19,
                    "suggestedAction": "Write the number of seconds as digits.",
                    "related": [],
                }
            ],
        )

    def test_file_level_expectation_has_no_position(self) -> None:
        variant = one(runner.mutate(EXAMPLE, None, demo_format()))
        expect = {"exit": 1, "diagnostics": [{"code": "yaml.too-large", "path": "", "at": "file"}]}
        resolved = runner.resolve_expected(expect, None, variant, "/w/p.yaml")
        self.assertIsNone(resolved[0]["line"])
        self.assertIsNone(resolved[0]["column"])

    def test_expectation_naming_a_missing_anchor_is_a_harness_error(self) -> None:
        variant = one(runner.mutate(EXAMPLE, {"append": "a: 1\n"}, demo_format()))
        expect = {"exit": 1, "diagnostics": [{"code": "x.y", "path": "", "from": "kind", "at": {"line": 1, "column": 1}}]}
        with self.assertRaises(runner.HarnessError):
            runner.resolve_expected(expect, "append", variant, "/w/p.yaml")


def diagnostic(**changes):
    value = {
        "severity": "error",
        "code": "yaml.duplicate-key",
        "path": "/a",
        "message": "the key `a` is defined twice in this mapping",
        "suggestedAction": "Keep one definition of the key.",
        "source": {"file": "/w/p.yaml", "line": 3, "column": 1},
    }
    value.update(changes)
    return value


def expected(**changes):
    value = {
        "severity": "error",
        "code": "yaml.duplicate-key",
        "path": "/a",
        "file": "/w/p.yaml",
        "line": 3,
        "column": 1,
        "related": [],
    }
    value.update(changes)
    return value


class ReportTest(unittest.TestCase):
    def test_cfg_diag_1_report_needs_a_diagnostics_list(self) -> None:
        diagnostics, problems = runner.parse_report('{"ok": false, "diagnostics": []}')
        self.assertEqual((diagnostics, problems), ([], []))
        for stdout in ("", "[]", '{"ok": true}', "not json", '{"diagnostics": {}}'):
            diagnostics, problems = runner.parse_report(stdout)
            self.assertIsNone(diagnostics, stdout)
            self.assertEqual(len(problems), 1, stdout)

    def test_cfg_diag_1_valid_diagnostic_has_no_shape_problem(self) -> None:
        self.assertEqual(runner.shape_problems(diagnostic(), "DemoProject"), [])
        self.assertEqual(
            runner.shape_problems(diagnostic(artifact="DemoProject", source={"file": "p.yaml"}), "DemoProject"),
            [],
        )

    def test_cfg_diag_1_shape_problems(self) -> None:
        cases = [
            (diagnostic(severity="fatal"), "severity is not error or warning"),
            (diagnostic(extra=1), "unknown member `extra`"),
            (diagnostic(path="a/b"), "path is not a JSON pointer"),
            (diagnostic(suggestedAction=""), "suggestedAction is empty"),
            (diagnostic(source={"file": "p", "line": 0}), "source.line is not a positive integer"),
            (diagnostic(source={"file": "p", "column": 2}), "source.column without source.line"),
            (diagnostic(artifact="Other"), "artifact is not DemoProject"),
            (diagnostic(related=[]), "related is empty"),
            (diagnostic(related=[{"file": "p", "path": "/a"}]), "related[0] has no message"),
        ]
        for value, problem in cases:
            self.assertIn(problem, runner.shape_problems(value, "DemoProject"), value)
        missing = diagnostic()
        del missing["suggestedAction"]
        self.assertIn("missing member `suggestedAction`", runner.shape_problems(missing, "DemoProject"))

    def test_cfg_diag_3_code_shape(self) -> None:
        self.assertEqual(runner.shape_problems(diagnostic(code="config.unknown-key"), None), [])
        for code in ("Config.unknown", "config", "config.unknown_key", "config..x", "config.-x"):
            self.assertIn(
                "code is not dotted lowercase kebab-case",
                runner.shape_problems(diagnostic(code=code), None),
                code,
            )

    def test_cfg_check_3_exact_match_passes(self) -> None:
        self.assertEqual(runner.match_problems([expected()], [diagnostic()]), [])

    def test_cfg_check_3_match_compares_files_after_normalizing(self) -> None:
        actual = diagnostic(source={"file": "/w/./p.yaml", "line": 3, "column": 1})
        self.assertEqual(runner.match_problems([expected()], [actual]), [])

    def test_cfg_check_3_match_reports_missing_and_unexpected(self) -> None:
        problems = runner.match_problems([expected()], [diagnostic(code="source.yaml.invalid")])
        self.assertEqual(
            problems,
            [
                "missing yaml.duplicate-key at /a 3:1",
                "unexpected source.yaml.invalid at /a 3:1",
            ],
        )

    def test_cfg_check_3_match_is_exact_on_position_and_count(self) -> None:
        self.assertEqual(
            runner.match_problems([expected()], [diagnostic(source={"file": "/w/p.yaml", "line": 3, "column": 2})]),
            ["missing yaml.duplicate-key at /a 3:1", "unexpected yaml.duplicate-key at /a 3:2"],
        )
        self.assertEqual(
            runner.match_problems([expected()], [diagnostic(), diagnostic()]),
            ["unexpected yaml.duplicate-key at /a 3:1"],
        )

    def test_cfg_diag_6_match_asserts_the_stated_action_and_message(self) -> None:
        stated = expected(suggestedAction="Remove the quotes.")
        self.assertEqual(
            runner.match_problems([stated], [diagnostic()]),
            ["missing yaml.duplicate-key at /a 3:1", "unexpected yaml.duplicate-key at /a 3:1"],
        )
        stated = expected(message="the key `a` is defined twice in this mapping")
        self.assertEqual(runner.match_problems([stated], [diagnostic()]), [])

    def test_cfg_diag_1_match_checks_related_locations(self) -> None:
        stated = expected(related=[{"file": "/w/p.yaml", "line": 2, "column": 1, "path": "/a"}])
        good = diagnostic(
            related=[{"file": "/w/p.yaml", "line": 2, "column": 1, "path": "/a", "message": "first"}]
        )
        self.assertEqual(runner.match_problems([stated], [good]), [])
        self.assertEqual(
            runner.match_problems([stated], [diagnostic()]),
            ["missing yaml.duplicate-key at /a 3:1", "unexpected yaml.duplicate-key at /a 3:1"],
        )

    def test_cfg_diag_2_human_output(self) -> None:
        output = textwrap.dedent(
            """\
            error[yaml.duplicate-key] /w/p.yaml:3:1 /a
              the key is defined twice
              next: Keep one definition of the key.
              note: /w/p.yaml:2:1 /a the first definition
            1 error, 0 warnings in 1 file
            """
        )
        stated = expected(related=[{"file": "/w/p.yaml", "line": 2, "column": 1, "path": "/a"}])
        self.assertEqual(runner.human_problems([stated], output), [])
        self.assertEqual(
            runner.human_problems([stated, expected(path="/b")], output),
            [
                "human output has no line for yaml.duplicate-key at /b 3:1",
                "human output has no summary line starting `2 errors, 0 warnings`",
            ],
        )
        self.assertEqual(
            runner.human_problems([expected(related=[{"file": "/w/p.yaml", "line": 9, "column": 1, "path": "/a"}])], output),
            ["human output has no note for /a 9:1"],
        )

    def test_cfg_diag_2_human_output_of_a_file_level_problem(self) -> None:
        output = "error[yaml.too-large] /w/p.yaml\n  too large\n  next: Split it.\n1 error, 0 warnings in 1 file\n"
        stated = expected(code="yaml.too-large", path="", line=None, column=None)
        self.assertEqual(runner.human_problems([stated], output), [])

    def test_cfg_sec_3_marker_in_output_is_a_problem(self) -> None:
        self.assertEqual(runner.marker_problems(b"fine", b""), [])
        self.assertEqual(
            runner.marker_problems(b"", f"value {runner.MARKER}".encode()),
            ["the output repeats the planted marker value (CFG-SEC-3)"],
        )

    def test_sanitize_hides_the_work_directory_and_the_marker(self) -> None:
        self.assertEqual(
            runner.sanitize(f"/tmp/run.x/project/a.yaml {runner.MARKER}", "/tmp/run.x"),
            "<work>/project/a.yaml <marker>",
        )


class PlanTest(unittest.TestCase):
    def case(self, **changes):
        value = {
            "id": "demo-case",
            "rules": ["CFG-YAML-2"],
            "summary": "A demo case.",
            "expect": {"exit": 1, "diagnostics": []},
        }
        value.update(changes)
        return runner.Case.from_document(value, "demo-case")

    def test_cfg_check_3_audiences_and_envelope_select_formats(self) -> None:
        authored = demo_format()
        operator = demo_format(id="demo/runtime", audience="operator")
        bare = demo_format(id="demo/metadata", kind=None)
        only_operator = self.case(appliesTo={"audiences": ["operator"]})
        self.assertIsNotNone(runner.not_applicable(only_operator, authored))
        self.assertIsNone(runner.not_applicable(only_operator, operator))
        envelope = self.case(appliesTo={"envelope": True})
        self.assertIsNotNone(runner.not_applicable(envelope, bare))
        self.assertIsNone(runner.not_applicable(envelope, authored))

    def test_case_file_shape_is_checked(self) -> None:
        with self.assertRaises(runner.HarnessError):
            runner.Case.from_document({"id": "x", "rules": [], "expect": {"exit": 1}}, "x")
        with self.assertRaises(runner.HarnessError):
            runner.Case.from_document({"id": "y", "rules": ["CFG-YAML-2"], "expect": {"exit": 1}}, "x")
        with self.assertRaises(runner.HarnessError):
            runner.Case.from_document(
                {"id": "x", "rules": ["CFG-YAML-2"], "summary": "s", "expect": {"exit": 1}, "extra": 1},
                "x",
            )

    def test_skipped_formats_name_their_reason(self) -> None:
        formats = [
            demo_format(check=None),
            demo_format(id="demo/b", example=None),
            demo_format(id="demo/c", syntax="json"),
            demo_format(id="demo/d"),
        ]
        reached, skipped = runner.partition_formats(formats)
        self.assertEqual([fmt.id for fmt in reached], ["demo/d"])
        self.assertEqual(
            skipped,
            {
                "demo/project": "no check command",
                "demo/b": "no example",
                "demo/c": "syntax json; the corpus mutates YAML text",
            },
        )


class ExpectedFailuresTest(unittest.TestCase):
    def test_cfg_check_3_statuses(self) -> None:
        expected = runner.ExpectedFailures(
            failures={("demo/a", "dup"): "r1", ("demo/a", "anchor"): "r2"},
            unreached={},
            inapplicable={},
        )
        results = {
            ("demo/a", "dup"): ["missing yaml.duplicate-key at /a 3:1"],
            ("demo/a", "anchor"): [],
            ("demo/a", "tag"): ["exit status 2, expected 1"],
            ("demo/a", "alias"): [],
        }
        self.assertEqual(
            runner.statuses(results, expected),
            {
                ("demo/a", "dup"): "expected failure",
                ("demo/a", "anchor"): "stale",
                ("demo/a", "tag"): "fail",
                ("demo/a", "alias"): "pass",
            },
        )

    def test_reason_is_the_first_two_problems_with_a_count(self) -> None:
        self.assertEqual(runner.reason(["a", "b", "c", "d"]), "a; b (and 2 more problems)")
        self.assertEqual(runner.reason(["a", "b", "c"]), "a; b (and 1 more problem)")
        self.assertEqual(runner.reason(["a", "b"]), "a; b")
        self.assertEqual(runner.reason(["a"]), "a")

    def test_expected_failures_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "expected-failures.yaml"
            value = runner.ExpectedFailures(
                failures={("demo/b", "tag"): "r2", ("demo/a", "dup"): "r1"},
                unreached={"demo/c": "no example"},
                inapplicable={"retired": "no format declares one"},
            )
            runner.write_expected_failures(path, value, ["dup", "tag", "retired"])
            text = path.read_text(encoding="utf-8")
            self.assertTrue(text.startswith("# "))
            self.assertLess(text.index("format: demo/a"), text.index("format: demo/b"))
            self.assertEqual(runner.load_expected_failures(path), value)

    def test_expected_failures_refuse_duplicates_and_unknown_members(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "expected-failures.yaml"
            entry = {"format": "demo/a", "case": "dup", "reason": "r"}
            path.write_text(yaml.safe_dump({"expectedFailures": [entry, entry]}), encoding="utf-8")
            with self.assertRaises(runner.HarnessError):
                runner.load_expected_failures(path)
            path.write_text(yaml.safe_dump({"expectedFailures": [dict(entry, why="x")]}), encoding="utf-8")
            with self.assertRaises(runner.HarnessError):
                runner.load_expected_failures(path)


FAKECTL = r'''#!/usr/bin/env python3
"""A check command implementing one reader rule: duplicate top-level keys."""
import json
import os
import sys

args = sys.argv[1:]
if "--conformance-unknown-option" in args:
    print("error: unexpected argument", file=sys.stderr)
    raise SystemExit(2)
project = args[1]
if args[0] == "prepare":
    if os.path.exists(os.path.join(project, "prepare-fails")):
        print("error: cannot prepare", file=sys.stderr)
        raise SystemExit(3)
    with open(os.path.join(project, "prepared"), "w", encoding="utf-8") as handle:
        handle.write("prepared\n")
    raise SystemExit(0)
if os.path.exists(os.path.join(project, "needs-prepare")) and not os.path.exists(os.path.join(project, "prepared")):
    print("error: the project was not prepared", file=sys.stderr)
    raise SystemExit(3)
target = os.path.join(project, "project.yaml")
seen = {}
diagnostics = []
with open(target, encoding="utf-8") as handle:
    for number, line in enumerate(handle, start=1):
        if line[:1] in " #-" or ":" not in line:
            continue
        key = line.split(":", 1)[0]
        if key in seen:
            diagnostics.append({
                "severity": "error",
                "code": "yaml.duplicate-key",
                "path": "/" + key,
                "message": "the key is defined twice in this mapping",
                "suggestedAction": "Keep one definition of the key.",
                "source": {"file": target, "line": number, "column": 1},
                "related": [{"file": target, "line": seen[key], "column": 1,
                             "path": "/" + key, "message": "the first definition"}],
            })
        seen.setdefault(key, number)
if os.environ.get("FAKECTL_BAD_PATH"):
    for item in diagnostics:
        item["path"] = item["path"].lstrip("/")
if os.environ.get("FAKECTL_LEAK"):
    print(os.environ["REGISTRY_CONFORMANCE_VALUE"], file=sys.stderr)
if "--format" in args:
    print(json.dumps({"ok": not diagnostics, "diagnostics": diagnostics}))
else:
    for item in diagnostics:
        source = item["source"]
        print(f"error[{item['code']}] {source['file']}:{source['line']}:{source['column']} {item['path']}")
        print("  " + item["message"])
        print("  next: " + item["suggestedAction"])
        for note in item["related"]:
            print(f"  note: {note['file']}:{note['line']}:{note['column']} {note['path']} {note['message']}")
    count = len(diagnostics)
    print(f"{count} error{'' if count == 1 else 's'}, 0 warnings in 1 file")
raise SystemExit(1 if diagnostics else 0)
'''

REGISTRY_TEXT = """\
apiVersion: id.registrystack.org/formats/platform/config-format-registry/v1alpha1
kind: PlatformConfigFormatRegistry
formats:
  - id: demo/project
    syntax: yaml
    audience: authored
    target: {apiVersion: id.registrystack.org/formats/demo/project/v1alpha1, kind: DemoProject}
    check: fakectl check {project}
    example: products/demo/example/project.yaml
    conformance: {requiredText: /project/id, optionalText: none, integer: none, boolean: none}
  - id: demo/runtime
    syntax: yaml
    audience: operator
    target: {apiVersion: id.registrystack.org/formats/demo/runtime/v1alpha1, kind: DemoRuntimeConfig}
    check: fakectl check --runtime-config {file}
    example: none
  - id: demo/notes
    syntax: yaml
    audience: authored
    target: none
    check: none
    example: products/demo/example/notes.yaml
"""

CASES = {
    "baseline": """\
        id: baseline
        rules: [CFG-CHECK-1]
        summary: The unmutated example is accepted.
        expect: {exit: 0, diagnostics: []}
        """,
    "duplicate-key": """\
        id: duplicate-key
        rules: [CFG-YAML-2]
        summary: A key written twice is refused.
        mutation:
          append: |
            conformanceDuplicate: one
            conformanceDuplicate: two
        expect:
          exit: 1
          diagnostics:
            - code: yaml.duplicate-key
              path: /conformanceDuplicate
              at: {line: 2, column: 1}
              suggestedAction: Keep one definition of the key.
              related:
                - path: /conformanceDuplicate
                  at: {line: 1, column: 1}
        human: true
        """,
    "anchor": """\
        id: anchor
        rules: [CFG-YAML-3]
        summary: An anchor is refused.
        mutation:
          append: "conformanceAnchor: &conformance {marker}\\n"
        expect:
          exit: 1
          diagnostics:
            - {code: yaml.anchor, path: /conformanceAnchor, at: {line: 1, column: 20}}
        """,
    "usage-error": """\
        id: usage-error
        rules: [CFG-DIAG-4]
        summary: An unknown option is a usage error.
        args: [--conformance-unknown-option]
        expect: {exit: 2, report: false}
        """,
    "operator-only": """\
        id: operator-only
        rules: [CFG-SEC-2]
        summary: Applies to operator files only.
        appliesTo: {audiences: [operator]}
        expect: {exit: 0, diagnostics: []}
        """,
}

HARNESS_TEXT = "formats: {}\n"


class EndToEndTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(os.path.realpath(temporary.name))
        (self.root / "products/platform/conformance/yaml/cases").mkdir(parents=True)
        (self.root / "products/platform/config-formats.yaml").write_text(REGISTRY_TEXT, encoding="utf-8")
        example = self.root / "products/demo/example"
        example.mkdir(parents=True)
        (example / "project.yaml").write_text(EXAMPLE, encoding="utf-8")
        (example / "notes.yaml").write_text("note: x\n", encoding="utf-8")
        for name, text in CASES.items():
            (self.root / "products/platform/conformance/yaml/cases" / f"{name}.yaml").write_text(
                textwrap.dedent(text), encoding="utf-8"
            )
        (self.root / "products/platform/conformance/yaml/formats.yaml").write_text(HARNESS_TEXT, encoding="utf-8")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        fake = self.bin / "fakectl"
        fake.write_text(FAKECTL, encoding="utf-8")
        fake.chmod(0o755)
        self.expected_path = self.root / "products/platform/conformance/yaml/expected-failures.yaml"
        self.write_expected({})

    def write_expected(self, value) -> None:
        self.expected_path.write_text(yaml.safe_dump(value), encoding="utf-8")

    def run_runner(self, *args: str, env: dict[str, str] | None = None) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        saved = dict(os.environ)
        os.environ.update(env or {})
        try:
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = runner.main(["--root", str(self.root), "--bin-dir", str(self.bin), *args])
        finally:
            os.environ.clear()
            os.environ.update(saved)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_cfg_check_3_conforming_check_passes_every_case(self) -> None:
        code, stdout, _ = self.run_runner("--matrix")
        self.assertEqual(code, 1, stdout)
        self.assertIn("demo/project\tbaseline\tpass", stdout)
        self.assertIn("demo/project\tduplicate-key\tpass", stdout)
        self.assertIn("demo/project\tusage-error\tpass", stdout)
        self.assertIn("demo/project\tanchor\tfail", stdout)
        self.assertIn("demo/project\toperator-only\tnot applicable", stdout)
        self.assertIn("skipped demo/runtime: no example", stdout)
        self.assertIn("skipped demo/notes: no check command", stdout)
        self.assertNotIn(runner.MARKER, stdout)

    def test_cfg_check_3_expected_failure_keeps_the_run_green(self) -> None:
        self.write_expected(
            {"expectedFailures": [{"format": "demo/project", "case": "anchor", "reason": "not converged"}]}
        )
        code, stdout, _ = self.run_runner()
        self.assertEqual(code, 0, stdout)
        self.assertIn("1 expected failure", stdout)

    def test_strict_refuses_unacknowledged_unreached_formats_and_cases(self) -> None:
        self.write_expected(
            {"expectedFailures": [{"format": "demo/project", "case": "anchor", "reason": "not converged"}]}
        )
        code, stdout, _ = self.run_runner("--strict")
        self.assertEqual(code, 1)
        self.assertIn("demo/runtime has a check command but is not reached: no example", stdout)
        self.assertIn("case operator-only applies to no format", stdout)
        self.write_expected(
            {
                "expectedFailures": [{"format": "demo/project", "case": "anchor", "reason": "not converged"}],
                "unreachedFormats": [{"format": "demo/runtime", "reason": "no example yet"}],
                "inapplicableCases": [{"case": "operator-only", "reason": "no operator example yet"}],
            }
        )
        code, stdout, _ = self.run_runner("--strict")
        self.assertEqual(code, 0, stdout)

    def test_strict_refuses_a_stale_expected_failure(self) -> None:
        self.write_expected(
            {
                "expectedFailures": [
                    {"format": "demo/project", "case": "anchor", "reason": "not converged"},
                    {"format": "demo/project", "case": "duplicate-key", "reason": "not converged"},
                ],
                "unreachedFormats": [{"format": "demo/runtime", "reason": "no example yet"}],
                "inapplicableCases": [{"case": "operator-only", "reason": "no operator example yet"}],
            }
        )
        code, stdout, _ = self.run_runner()
        self.assertEqual(code, 0, stdout)
        self.assertIn("stale: demo/project duplicate-key now passes", stdout)
        code, stdout, _ = self.run_runner("--strict")
        self.assertEqual(code, 1, stdout)

    def test_unknown_ids_in_expected_failures_are_errors(self) -> None:
        self.write_expected({"expectedFailures": [{"format": "demo/nope", "case": "anchor", "reason": "r"}]})
        code, _, stderr = self.run_runner()
        self.assertEqual(code, 1)
        self.assertIn("demo/nope", stderr)

    def test_cfg_sec_3_marker_leak_fails_the_cell(self) -> None:
        code, stdout, _ = self.run_runner("--matrix", env={"FAKECTL_LEAK": "1"})
        self.assertEqual(code, 1)
        self.assertIn("demo/project\tbaseline\tfail", stdout)
        self.assertIn("the output repeats the planted marker value (CFG-SEC-3)", stdout)
        self.assertNotIn(runner.MARKER, stdout)

    def test_write_expected_failures_records_every_failure(self) -> None:
        code, _, _ = self.run_runner("--write-expected-failures")
        self.assertEqual(code, 0)
        value = runner.load_expected_failures(self.expected_path)
        self.assertEqual(list(value.failures), [("demo/project", "anchor")])
        self.assertEqual(value.unreached, {"demo/runtime": "no example"})
        self.assertEqual(value.inapplicable, {"operator-only": "no reached format is an operator file"})
        code, _, _ = self.run_runner("--strict")
        self.assertEqual(code, 0)

    def test_expected_failure_reasons_lead_with_the_diagnostics_that_do_not_match(self) -> None:
        code, _, _ = self.run_runner("--write-expected-failures", env={"FAKECTL_BAD_PATH": "1"})
        self.assertEqual(code, 0)
        reason = runner.load_expected_failures(self.expected_path).failures[("demo/project", "duplicate-key")]
        self.assertRegex(
            reason,
            r"^missing yaml\.duplicate-key at /conformanceDuplicate \d+:1; "
            r"unexpected yaml\.duplicate-key at conformanceDuplicate \d+:1 \(and \d+ more problems?\)$",
        )

    def test_prepare_commands_run_in_the_staged_project_before_the_check(self) -> None:
        (self.root / "products/demo/example/needs-prepare").write_text("", encoding="utf-8")
        code, stdout, _ = self.run_runner("--matrix")
        self.assertIn("demo/project\tbaseline\tfail", stdout)
        (self.root / "products/platform/conformance/yaml/formats.yaml").write_text(
            "formats:\n  demo/project:\n    prepare: ['fakectl prepare {project}']\n", encoding="utf-8"
        )
        code, stdout, _ = self.run_runner("--matrix")
        self.assertIn("demo/project\tbaseline\tpass", stdout)
        self.assertIn("demo/project\tduplicate-key\tpass", stdout)

    def test_a_failing_prepare_command_fails_the_cell(self) -> None:
        (self.root / "products/demo/example/prepare-fails").write_text("", encoding="utf-8")
        (self.root / "products/platform/conformance/yaml/formats.yaml").write_text(
            "formats:\n  demo/project:\n    prepare: ['fakectl prepare {project}']\n", encoding="utf-8"
        )
        code, stdout, _ = self.run_runner("--matrix")
        self.assertEqual(code, 1)
        self.assertIn("demo/project\tbaseline\tfail", stdout)
        self.assertIn("preparing with `fakectl prepare {project}`: exit status 3, expected 0: error: cannot prepare", stdout)

    def test_missing_binary_fails(self) -> None:
        (self.bin / "fakectl").unlink()
        code, stdout, _ = self.run_runner("--matrix")
        self.assertEqual(code, 1)
        self.assertIn("demo/project\tbaseline\tfail", stdout)
        self.assertIn("fakectl is not in the binary directory", stdout)


class CommittedCorpusTest(unittest.TestCase):
    """The committed corpus, harness, and expected failures load and agree."""

    def setUp(self) -> None:
        self.corpus = ROOT / runner.CORPUS
        self.cases = runner.load_cases(self.corpus / "cases")
        self.registry = runner.load_registry(ROOT / runner.REGISTRY)

    def test_cfg_check_3_every_case_cites_known_rules(self) -> None:
        convention = (ROOT / "products/platform/CONFIG-CONVENTIONS.md").read_text(encoding="utf-8")
        known = set(re.findall(r"^\*\*(CFG-[A-Z]+-[0-9]+) \(", convention, re.MULTILINE))
        self.assertGreater(len(self.cases), 0)
        for case in self.cases:
            self.assertTrue(case.rules, case.id)
            self.assertLessEqual(set(case.rules), known, case.id)

    def test_brief_reader_rules_each_have_a_case(self) -> None:
        ids = {case.id for case in self.cases}
        for required in (
            "duplicate-key", "anchor", "alias", "merge-key", "tag", "multiple-documents",
            "non-string-key", "oversize", "ambiguous-number", "text-member-boolean",
            "integer-member-quoted", "null-in-required-member", "null-in-optional-member",
            "unknown-keys", "removed-key", "retired-api-version", "wrong-kind",
            "wrong-api-version", "missing-envelope", "empty-file",
            "substitution-in-authored-file", "substitution-in-reference", "tab-indentation",
            "planted-marker", "bom-accepted", "crlf-accepted", "document-start-accepted",
            "document-end-accepted",
        ):
            self.assertIn(required, ids)

    def test_harness_and_expected_failures_name_known_formats_and_cases(self) -> None:
        formats = {fmt.id for fmt in self.registry}
        harness = runner.load_harness(self.corpus / "formats.yaml")
        self.assertLessEqual(set(harness), formats)
        expected = runner.load_expected_failures(self.corpus / "expected-failures.yaml")
        ids = {case.id for case in self.cases}
        for format_id, case_id in expected.failures:
            self.assertIn(format_id, formats)
            self.assertIn(case_id, ids)
        self.assertLessEqual(set(expected.unreached), formats)
        self.assertLessEqual(set(expected.inapplicable), ids)

    def test_every_case_mutates_every_reached_example(self) -> None:
        reached, _ = runner.partition_formats(self.registry)
        harness = runner.load_harness(self.corpus / "formats.yaml")
        for fmt in reached:
            fmt = fmt.with_harness(harness.get(fmt.id, {}))
            text = (ROOT / fmt.example).read_text(encoding="utf-8")
            text = runner.prepare_example(text, fmt, {})
            for case in self.cases:
                if runner.not_applicable(case, fmt):
                    continue
                try:
                    variants = runner.mutate(text, case.mutation, fmt)
                except runner.NotApplicable:
                    continue
                for variant in variants:
                    runner.resolve_expected(case.expect, case.operation, variant, "/w/file.yaml")
                    runner.encode(variant.text, case.encoding)


if __name__ == "__main__":
    unittest.main()
