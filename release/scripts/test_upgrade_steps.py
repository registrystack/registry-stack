#!/usr/bin/env python3
"""Tests for the upgrade steps engine; no network, no binaries.

The engine needs PyYAML for `.yaml` files, as the rehearsal does:
`uv run --no-project --with PyYAML==6.0.2 python -m unittest
release/scripts/test_upgrade_steps.py`.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import upgrade_steps  # noqa: E402

Error = upgrade_steps.StepError


def edit(**fields: object) -> dict[str, object]:
    return dict(fields)


class EditKindsTest(unittest.TestCase):
    """One sample document per edit kind."""

    def apply(self, document: Any, **fields: Any) -> Any:
        return upgrade_steps.apply_edit(document, edit(**fields), "sample-step")

    def test_envelope_puts_the_header_first_and_replaces_an_old_one(self) -> None:
        old = {"apiVersion": "old/v1", "kind": "Old", "name": "x"}
        new = self.apply(old, op="envelope", apiVersion="new/v1", kind="New")
        self.assertEqual(list(new), ["apiVersion", "kind", "name"])
        self.assertEqual(new, {"apiVersion": "new/v1", "kind": "New", "name": "x"})
        bare = self.apply({"name": "x"}, op="envelope", apiVersion="new/v1", kind="New")
        self.assertEqual(list(bare), ["apiVersion", "kind", "name"])

    def test_set_writes_a_member_and_if_absent_keeps_an_existing_one(self) -> None:
        self.assertEqual(self.apply({"a": 1}, op="set", path="b", value="x"),
                         {"a": 1, "b": "x"})
        self.assertEqual(self.apply({"a": 1}, op="set", path="a", value=2), {"a": 2})
        self.assertEqual(self.apply({"a": 1}, op="set", path="a", value=2, ifAbsent=True),
                         {"a": 1})
        profiles = {"profiles": [{"id": "p"}, {"id": "q", "scope": "kept"}]}
        self.assertEqual(
            self.apply(profiles, op="set", path="profiles.*.scope", value="unrestricted",
                       ifAbsent=True),
            {"profiles": [{"id": "p", "scope": "unrestricted"},
                          {"id": "q", "scope": "kept"}]})

    def test_delete_removes_a_member_wherever_the_path_matches(self) -> None:
        document = {"version": 1, "project": "p", "keep": True}
        self.assertEqual(self.apply(document, op="delete", path="version"),
                         {"project": "p", "keep": True})
        nested = {"profiles": [{"id": "a", "anonymous": False}, {"id": "b"}]}
        self.assertEqual(self.apply(nested, op="delete", path="profiles.*.anonymous"),
                         {"profiles": [{"id": "a"}, {"id": "b"}]})

    def test_rename_keeps_the_value_and_the_position(self) -> None:
        document = {"retention": {"payloadDays": 7, "recordDays": 30}}
        renamed = self.apply(document, op="rename", path="retention.payloadDays",
                             to="payloadRetentionDays")
        self.assertEqual(list(renamed["retention"]), ["payloadRetentionDays", "recordDays"])
        self.assertEqual(renamed["retention"]["payloadRetentionDays"], 7)

    def test_rename_follows_wildcards_and_deep_paths(self) -> None:
        document = {"providers": {"a": {"kind": "smtp"}, "b": {"kind": "http"}}}
        self.assertEqual(
            self.apply(document, op="rename", path="providers.*.kind", to="type"),
            {"providers": {"a": {"type": "smtp"}, "b": {"type": "http"}}})
        deep = {"journeys": [{"steps": [{"request": {"recordRef": "r",
                                                       "data": {"group": {"recordRef": "g"}}}}]}]}
        self.assertEqual(
            self.apply(deep, op="rename", path="journeys.**.recordRef", to="recordCapture"),
            {"journeys": [{"steps": [{"request": {
                "recordCapture": "r", "data": {"group": {"recordCapture": "g"}}}}]}]})

    def test_rename_can_scale_a_number(self) -> None:
        document = {"smtp": {"attemptTimeoutSeconds": 10}}
        self.assertEqual(
            self.apply(document, op="rename", path="smtp.attemptTimeoutSeconds",
                       to="attemptTimeoutMilliseconds", multiplyBy=1000),
            {"smtp": {"attemptTimeoutMilliseconds": 10000}})

    def test_scaling_a_value_that_is_not_a_number_is_refused(self) -> None:
        with self.assertRaisesRegex(Error, "sample-step.*not a number"):
            self.apply({"t": "ten"}, op="rename", path="t", to="u", multiplyBy=1000)

    def test_replace_value_changes_only_the_matching_value(self) -> None:
        document = {"profiles": [{"requiredScopes": []}, {"requiredScopes": ["a"]},
                                 {"requiredScopes": "unrestricted"}]}
        self.assertEqual(
            self.apply(document, op="replace-value", path="profiles.*.requiredScopes",
                       **{"from": [], "to": "unrestricted"}),
            {"profiles": [{"requiredScopes": "unrestricted"}, {"requiredScopes": ["a"]},
                          {"requiredScopes": "unrestricted"}]})

    def test_replace_value_maps_a_value_to_another(self) -> None:
        document = {"steps": [{"kind": "transactional_sql"}, {"kind": "chunked_backfill"}]}
        once = self.apply(document, op="replace-value", path="steps.*.kind",
                          **{"from": "transactional_sql", "to": "transactional-sql"})
        self.assertEqual(once, {"steps": [{"kind": "transactional-sql"},
                                          {"kind": "chunked_backfill"}]})

    def test_replace_value_refuses_a_path_whose_value_differs_unless_optional(self) -> None:
        document = {"api": {"version": "registry.example/v1alpha1-found"}}
        fields = {"op": "replace-value", "path": "api.version",
                  "from": "registry.example/v1alpha1", "to": "registry.example/v1"}
        with self.assertRaisesRegex(Error, r"sample-step.*api\.version.*no value to replace") as raised:
            upgrade_steps.apply_edit(document, fields, "sample-step")
        self.assertNotIn("v1alpha1-found", str(raised.exception))
        self.assertEqual(
            upgrade_steps.apply_edit(document, {**fields, "optional": True}, "sample-step"),
            {"api": {"version": "registry.example/v1alpha1-found"}})

    def test_a_replace_value_that_differs_in_a_file_names_step_file_and_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "runtime.yaml"
            file.write_text("mode: other\n", encoding="utf-8")
            catalog = {"sample-step": {
                "id": "sample-step", "kind": "edit", "file": "runtime.yaml", "root": "project",
                "edits": [{"op": "replace-value", "path": "mode", "from": "old", "to": "new"}]}}
            with self.assertRaisesRegex(Error, r"sample-step.*runtime\.yaml.*mode") as raised:
                upgrade_steps.apply_steps(["sample-step"], {"project": Path(directory)}, catalog)
            self.assertNotIn("other", str(raised.exception))

    def test_an_edit_that_matches_nothing_is_refused_unless_optional(self) -> None:
        for fields in (
            {"op": "delete", "path": "version"},
            {"op": "rename", "path": "a.b", "to": "c"},
            {"op": "replace-value", "path": "a", "from": 1, "to": 2},
            {"op": "set", "path": "x.y", "value": 1},
        ):
            with self.subTest(fields=fields):
                with self.assertRaisesRegex(Error, r"sample-step.*matches nothing"):
                    upgrade_steps.apply_edit({"other": 1}, fields, "sample-step")
                upgrade_steps.apply_edit({"other": 1}, {**fields, "optional": True},
                                         "sample-step")

    def test_an_unknown_edit_is_refused_by_name(self) -> None:
        with self.assertRaisesRegex(Error, "sample-step.*unknown edit 'shuffle'"):
            self.apply({}, op="shuffle")

    def test_a_rename_onto_an_existing_member_is_refused(self) -> None:
        with self.assertRaisesRegex(Error, "sample-step.*already has"):
            self.apply({"a": 1, "b": 2}, op="rename", path="a", to="b")


class ExpandAliasesTest(unittest.TestCase):
    """`expand-aliases` writes every alias out in full, when a step asks."""

    STEP = {"id": "sample-expand", "product": "breg", "kind": "edit", "file": "file.yaml"}

    def run_step(self, text: str, *edits: dict[str, Any]) -> str:
        step = {**self.STEP, "edits": list(edits), "root": "project"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "file.yaml"
            path.write_text(text, encoding="utf-8")
            upgrade_steps.apply_steps(
                ["sample-expand"], {"project": Path(directory)}, {"sample-expand": step})
            return path.read_text(encoding="utf-8")

    def expand(self, text: str) -> str:
        return self.run_step(text, {"op": "expand-aliases"})

    def assert_expanded(self, text: str) -> str:
        import yaml
        result = self.expand(text)
        self.assertNotRegex(result, r"(^|[ :\[,-])[&*][A-Za-z]")
        self.assertEqual(yaml.safe_load(result), yaml.safe_load(text))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "file.yaml"
            path.write_text(result, encoding="utf-8")
            upgrade_steps.load_document(path)
        return result

    def test_a_mapping_anchor_is_written_out_at_every_alias(self) -> None:
        result = self.assert_expanded("a: &c {x: 1, y: two}\nb: *c\nc:\n  d: *c\n")
        self.assertEqual(result.count("x: 1"), 3)

    def test_a_sequence_anchor_is_expanded(self) -> None:
        result = self.assert_expanded("a: &l [1, 2]\nb: *l\n")
        self.assertEqual(result.count("- 2"), 2)

    def test_a_scalar_anchor_is_expanded(self) -> None:
        self.assertIn("b: shared\n", self.assert_expanded("a: &s shared\nb: *s\n"))

    def test_nested_aliases_are_expanded(self) -> None:
        result = self.assert_expanded("a: &inner {k: v}\nb: &outer {i: *inner}\nc: *outer\n")
        self.assertEqual(result.count("k: v"), 3)

    def test_a_quoted_scalar_in_an_expanded_value_keeps_its_source(self) -> None:
        result = self.assert_expanded("a: &c {q: 'yes', n: 010, t: \"10:30\"}\nb: *c\n")
        self.assertEqual(result.count("q: 'yes'"), 2)
        self.assertEqual(result.count("n: 010"), 2)
        self.assertEqual(result.count('t: "10:30"'), 2)

    def test_comments_are_not_kept(self) -> None:
        result = self.expand("# header\na: &c {x: 1}  # note\nb: *c\n")
        self.assertNotIn("#", result)

    def test_later_edits_see_independent_copies(self) -> None:
        import yaml
        result = self.run_step(
            "a: &c {x: 1}\nb: *c\n",
            {"op": "expand-aliases"},
            {"op": "set", "path": "b.x", "value": 2})
        self.assertEqual(yaml.safe_load(result), {"a": {"x": 1}, "b": {"x": 2}})

    def test_a_step_without_the_op_still_refuses_an_anchor(self) -> None:
        with self.assertRaisesRegex(Error, r"file\.yaml:1.*anchor or alias"):
            self.run_step("a: &c {x: 1}\nb: *c\n", {"op": "set", "path": "z", "value": 1})

    def test_a_merge_key_and_a_duplicate_key_stay_refused(self) -> None:
        with self.assertRaisesRegex(Error, r"merge key"):
            self.expand("base: &b {x: 1}\nuse:\n  <<: *b\n")
        with self.assertRaisesRegex(Error, r"duplicate key"):
            self.expand("a: 1\na: 2\n")

    def test_the_journeys_step_expands_the_aliases_the_previous_starter_wrote(self) -> None:
        step = upgrade_steps.load_catalog()["breg-journeys"]
        self.assertEqual(step["edits"][0], {"op": "expand-aliases"})

    def test_the_op_must_come_first_and_takes_no_members(self) -> None:
        with self.assertRaisesRegex(Error, "first"):
            upgrade_steps.validate_step_edits(
                "s", [{"op": "set", "path": "a", "value": 1}, {"op": "expand-aliases"}])
        with self.assertRaisesRegex(Error, "takes no"):
            upgrade_steps.validate_edit({"op": "expand-aliases", "path": "a"}, "s")


class DocumentFilesTest(unittest.TestCase):
    def test_a_yaml_document_round_trips_without_anchors(self) -> None:
        shared = {"principal": "p"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "journeys.yaml"
            upgrade_steps.dump_document(path, {"a": shared, "b": shared})
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("&id", text)
            self.assertNotIn("*id", text)
            self.assertEqual(upgrade_steps.load_document(path),
                             {"a": {"principal": "p"}, "b": {"principal": "p"}})

    def test_the_file_suffix_picks_the_syntax(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scenarios.json"
            path.write_text('{"version": 1}', encoding="utf-8")
            self.assertEqual(upgrade_steps.load_document(path), {"version": 1})
            upgrade_steps.dump_document(path, {"kind": "K"})
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"kind": "K"})
            odd = Path(directory) / "notes.txt"
            odd.write_text("x", encoding="utf-8")
            with self.assertRaisesRegex(Error, "notes.txt.*YAML or JSON"):
                upgrade_steps.load_document(odd)

    def test_an_unparseable_document_names_the_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.yaml"
            path.write_text("a: [unclosed\n", encoding="utf-8")
            with self.assertRaisesRegex(Error, "bad.yaml"):
                upgrade_steps.load_document(path)


class SourceFidelityTest(unittest.TestCase):
    """An edit rewrites the values it names and no others."""

    def edited(self, text: str) -> str:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "file.yaml"
            path.write_text(text, encoding="utf-8")
            document = upgrade_steps.load_document(path)
            document = upgrade_steps.apply_edit(
                document, {"op": "set", "path": "added", "value": "x"}, "sample-step")
            upgrade_steps.dump_document(path, document)
            return path.read_text(encoding="utf-8")

    def test_a_scalar_no_step_names_keeps_its_text_and_quoting(self) -> None:
        for scalar in ("2026-01-01T00:00:00Z", "yes", "10:30", "010", "1_000", "0x1F",
                       "'yes'", '"10:30"', "'plain text'", "~", "1e3", "Null"):
            with self.subTest(scalar=scalar):
                self.assertIn(f"value: {scalar}\n", self.edited(f"value: {scalar}\nother: 1\n"))
        listed = self.edited("items:\n- 010\n- '1_000'\n- {inner: yes}\n")
        self.assertIn("- 010\n", listed)
        self.assertIn("- '1_000'\n", listed)
        self.assertIn("inner: yes", listed)

    def test_a_scalar_key_keeps_its_text(self) -> None:
        self.assertIn("yes: 1\n", self.edited("yes: 1\n"))
        self.assertIn("10:30: a\n", self.edited("10:30: a\n"))

    def test_a_document_the_new_readers_refuse_is_refused_with_its_line(self) -> None:
        cases = {
            "duplicate key": "a: 1\nb: 2\na: 3\n",
            "merge key": "base: {x: 1}\nuse:\n  <<: {x: 2}\n",
            "anchor": "a: &shared {x: 1}\n",
            "alias": "a: &shared {x: 1}\nb: *shared\n",
        }
        lines = {"duplicate key": 3, "merge key": 3, "anchor": 1, "alias": 1}
        words = {"anchor": "anchor or alias", "alias": "anchor or alias"}
        for name, text in cases.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "old.yaml"
                path.write_text(text, encoding="utf-8")
                with self.assertRaisesRegex(Error, rf"old\.yaml:{lines[name]}.*{words.get(name, name)}"):
                    upgrade_steps.load_document(path)

    def test_a_json_document_is_not_checked_for_yaml_forms(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "old.json"
            path.write_text('{"a": 1}', encoding="utf-8")
            self.assertEqual(upgrade_steps.load_document(path), {"a": 1})


CATALOG = """\
apiVersion: id.registrystack.org/formats/release/upgrade-steps/v1alpha1
kind: ReleaseUpgradeSteps
steps:
  - id: sample-header
    product: casework
    kind: edit
    root: project
    file: "fixtures/*.yaml"
    edits:
      - {op: envelope, apiVersion: new/v1, kind: Fixture}
      - {op: rename, path: name, to: id}
  - id: sample-target
    product: evidence
    kind: edit
    root: target
    file: governance.yaml
    edits:
      - {op: delete, path: version}
  - id: sample-manual
    product: breg
    kind: manual
    file: schema-test-receipt.json
    instruction: Run bregctl test again.
  - id: sample-unknown
    product: breg
    kind: unknown
    file: descriptor.json
    diagnostic: config.removed-key
"""


class CatalogTest(unittest.TestCase):
    def catalog(self, text: str):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "steps.yaml"
            path.write_text(text, encoding="utf-8")
            return upgrade_steps.load_catalog(path)

    def test_a_catalog_loads_by_id(self) -> None:
        catalog = self.catalog(CATALOG)
        self.assertEqual(sorted(catalog),
                         ["sample-header", "sample-manual", "sample-target", "sample-unknown"])
        self.assertEqual(catalog["sample-header"]["root"], "project")
        self.assertEqual(catalog["sample-manual"]["root"], "project")

    def test_an_unparseable_catalog_names_the_file(self) -> None:
        with self.assertRaisesRegex(Error, "steps.yaml"):
            self.catalog("steps: [unclosed\n")

    def test_a_catalog_without_the_envelope_is_refused(self) -> None:
        with self.assertRaisesRegex(Error, "apiVersion"):
            self.catalog("steps: []\n")

    def test_a_repeated_id_is_refused(self) -> None:
        with self.assertRaisesRegex(Error, "repeats the id 'sample-manual'"):
            self.catalog(CATALOG + "  - id: sample-manual\n    product: breg\n"
                         "    kind: manual\n    file: x\n    instruction: y\n")

    def test_an_entry_missing_a_field_is_refused_by_id(self) -> None:
        for broken, message in (
            ("  - id: bad\n    product: breg\n    kind: edit\n    file: f.yaml\n",
             "bad.*edits"),
            ("  - id: bad\n    product: breg\n    kind: manual\n    file: f\n",
             "bad.*instruction"),
            ("  - id: bad\n    product: breg\n    kind: unknown\n    file: f\n",
             "bad.*diagnostic"),
            ("  - id: bad\n    product: breg\n    kind: sideways\n    file: f\n",
             "bad.*kind 'sideways'"),
            ("  - id: bad\n    product: breg\n    kind: edit\n    root: elsewhere\n"
             "    file: f\n    edits: []\n", "bad.*root 'elsewhere'"),
            ("  - id: Bad_Id\n    product: breg\n    kind: manual\n    file: f\n"
             "    instruction: y\n", "Bad_Id.*kebab"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(Error, message):
                self.catalog(CATALOG.split("steps:\n")[0] + "steps:\n" + broken)

    def test_a_catalog_edit_is_checked_when_it_loads(self) -> None:
        broken = ("  - id: bad\n    product: breg\n    kind: edit\n    file: f.yaml\n"
                  "    edits:\n      - {op: shuffle}\n")
        with self.assertRaisesRegex(Error, "bad.*unknown edit 'shuffle'"):
            self.catalog(CATALOG.split("steps:\n")[0] + "steps:\n" + broken)


class ApplyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.project = root / "project"
        self.target = root / "target"
        (self.project / "fixtures").mkdir(parents=True)
        self.target.mkdir()
        catalog_file = root / "steps.yaml"
        catalog_file.write_text(CATALOG, encoding="utf-8")
        self.catalog = upgrade_steps.load_catalog(catalog_file)
        self.roots = {"project": self.project, "target": self.target}

    def test_a_step_edits_every_file_its_glob_matches_under_its_root(self) -> None:
        for name in ("a", "b"):
            (self.project / "fixtures" / f"{name}.yaml").write_text(
                f"apiVersion: old/v1\nname: {name}\n", encoding="utf-8")
        (self.target / "governance.yaml").write_text("version: 1\nkeep: true\n",
                                                     encoding="utf-8")
        manual = upgrade_steps.apply_steps(["sample-header", "sample-target"], self.roots,
                                           self.catalog)
        self.assertEqual(manual, [])
        for name in ("a", "b"):
            self.assertEqual(
                upgrade_steps.load_document(self.project / "fixtures" / f"{name}.yaml"),
                {"apiVersion": "new/v1", "kind": "Fixture", "id": name})
        self.assertEqual(upgrade_steps.load_document(self.target / "governance.yaml"),
                         {"keep": True})

    def test_a_glob_that_matches_no_file_is_refused(self) -> None:
        with self.assertRaisesRegex(Error, r"sample-header.*fixtures/\*\.yaml.*project"):
            upgrade_steps.apply_steps(["sample-header"], self.roots, self.catalog)

    def test_a_failing_edit_names_the_file_it_was_applied_to(self) -> None:
        (self.target / "governance.yaml").write_text("keep: true\n", encoding="utf-8")
        with self.assertRaisesRegex(Error, r"sample-target.*governance\.yaml.*matches nothing"):
            upgrade_steps.apply_steps(["sample-target"], self.roots, self.catalog)

    def test_a_manual_step_is_returned_not_applied(self) -> None:
        manual = upgrade_steps.apply_steps(["sample-manual"], self.roots, self.catalog)
        self.assertEqual(manual, ["sample-manual (schema-test-receipt.json): "
                                  "Run bregctl test again."])

    def test_a_step_unknown_is_refused_with_its_file_and_diagnostic(self) -> None:
        with self.assertRaisesRegex(
                Error, r"sample-unknown.*step unknown.*descriptor\.json.*config\.removed-key"):
            upgrade_steps.apply_steps(["sample-unknown"], self.roots, self.catalog)

    def test_an_unknown_step_id_is_refused_by_name(self) -> None:
        with self.assertRaisesRegex(Error, "unknown upgrade step id 'no-such-step'"):
            upgrade_steps.apply_steps(["no-such-step"], self.roots, self.catalog)

    def test_a_missing_root_is_refused(self) -> None:
        with self.assertRaisesRegex(Error, "sample-target.*root 'target'"):
            upgrade_steps.apply_steps(["sample-target"], {"project": self.project},
                                      self.catalog)

    def test_a_runtime_root_is_accepted_and_an_unlisted_root_is_refused(self) -> None:
        runtime = self.catalog["sample-target"]
        entry = {k: v for k, v in runtime.items() if k != "root"} | {"root": "runtime"}
        self.assertEqual(upgrade_steps._validate_step(entry)["root"], "runtime")
        with self.assertRaisesRegex(Error, "root 'elsewhere' is not project, target or runtime"):
            upgrade_steps._validate_step(dict(entry, root="elsewhere"))

    def test_a_file_outside_its_root_is_refused(self) -> None:
        escaped = dict(self.catalog["sample-target"], file="../governance.yaml")
        with self.assertRaisesRegex(Error, "sample-target.*outside"):
            upgrade_steps.apply_steps(["sample-target"], self.roots,
                                      {"sample-target": escaped})


FRAGMENT = """\
# Product: configuration conventions

## BREAKING: first
<!-- upgrade: sample-header, sample-target -->

Text.

## BREAKING: second
<!-- upgrade: already-wrong -->

## Other changes

## BREAKING: third
<!-- upgrade: no-file -->
"""

NUMBERED = """\
## Tools

### BREAKING changes
<!-- upgrade: 1=sample-header,sample-target; 2=no-file; 3=already-wrong -->

1. **First.** Text.
2. **Second.** Text.
   Continued text.
3. **Third.** Text.

### Other changes

1. Not a breaking item.
"""


class FragmentTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        catalog_file = self.root / "steps.yaml"
        catalog_file.write_text(CATALOG, encoding="utf-8")
        self.catalog = upgrade_steps.load_catalog(catalog_file)

    def check(self, text: str):
        path = self.root / "product.md"
        path.write_text(text, encoding="utf-8")
        return upgrade_steps.check_fragment(path, self.catalog)

    def test_every_breaking_heading_names_its_steps_or_a_reserved_word(self) -> None:
        items = self.check(FRAGMENT)
        self.assertEqual([(item.line, item.ids) for item in items], [
            (3, ("sample-header", "sample-target")),
            (8, ("already-wrong",)),
            (13, ("no-file",)),
        ])

    def test_a_numbered_breaking_list_is_marked_item_by_item(self) -> None:
        items = self.check(NUMBERED)
        self.assertEqual([(item.number, item.ids) for item in items], [
            (1, ("sample-header", "sample-target")),
            (2, ("no-file",)),
            (3, ("already-wrong",)),
        ])

    def test_a_heading_without_a_marker_is_refused_with_its_line(self) -> None:
        with self.assertRaisesRegex(Error, r"product\.md:3.*no upgrade marker"):
            self.check("# P\n\n## BREAKING: bare\n\nText.\n")

    def test_an_unknown_step_id_in_a_marker_is_refused(self) -> None:
        with self.assertRaisesRegex(Error, r"product\.md:3.*unknown upgrade step id 'nope'"):
            self.check("# P\n\n## BREAKING: x\n<!-- upgrade: nope -->\n")

    def test_a_malformed_marker_is_refused(self) -> None:
        for marker in ("<!-- upgrade: -->", "<!-- upgrade: a b -->", "<!-- upgrade: , -->",
                       "<!-- upgrade: sample-header -- >", "<!-- upgrade -->"):
            with self.subTest(marker=marker), self.assertRaisesRegex(
                    Error, r"product\.md:3.*(unparseable|no upgrade marker)"):
                self.check(f"# P\n\n## BREAKING: x\n{marker}\n")

    def test_a_reserved_word_cannot_be_mixed_with_a_step(self) -> None:
        with self.assertRaisesRegex(Error, r"product\.md:3.*alone"):
            self.check("# P\n\n## BREAKING: x\n<!-- upgrade: no-file, sample-header -->\n")

    def test_a_numbered_marker_must_cover_exactly_the_numbered_items(self) -> None:
        short = NUMBERED.replace("; 3=already-wrong", "")
        with self.assertRaisesRegex(Error, r"product\.md:3.*item 3.*no marker"):
            self.check(short)
        extra = NUMBERED.replace("3=already-wrong", "3=already-wrong; 4=no-file")
        with self.assertRaisesRegex(Error, r"product\.md:3.*item 4.*no such item"):
            self.check(extra)

    def test_a_numbered_heading_needs_item_markers_and_a_plain_one_does_not(self) -> None:
        with self.assertRaisesRegex(Error, r"product\.md:3.*item 1"):
            self.check(NUMBERED.replace("1=sample-header,sample-target; 2=no-file; "
                                        "3=already-wrong", "no-file"))

    def test_a_fragment_with_no_breaking_heading_is_unparseable(self) -> None:
        with self.assertRaisesRegex(Error, r"product\.md.*no BREAKING heading"):
            self.check("# P\n\n## Changes\n\nText.\n")



def write(root: Path, name: str, text: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# The one file in the fragments directory that is not a product fragment: the
# index of breaking changes by product. It repeats the product fragments'
# headings and carries no markers.
INDEX_FRAGMENT = "stack.md"


def product_fragments(directory: Path) -> list[Path]:
    """Every fragment in the directory except the index."""

    return sorted(path for path in directory.glob("*.md") if path.name != INDEX_FRAGMENT)


class FragmentSelectionTest(unittest.TestCase):
    def test_only_the_index_is_excluded_and_an_unknown_fragment_is_not(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("stack.md", "known.md", "brand-new.md"):
                (root / name).write_text("# x\n", encoding="utf-8")
            self.assertEqual([path.name for path in product_fragments(root)],
                             ["brand-new.md", "known.md"])


class ReleaseCatalogTest(unittest.TestCase):
    """The shipped catalog and the shipped release-note fragments agree."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = upgrade_steps.load_catalog()
        cls.fragments = product_fragments(upgrade_steps.FRAGMENTS)
        cls.items = {}
        cls.refused = {}
        for fragment in cls.fragments:
            try:
                cls.items[fragment.stem] = upgrade_steps.check_fragment(fragment, cls.catalog)
            except Error as error:
                # The error names the fragment and the heading line.
                cls.refused[fragment.stem] = str(error)

    def test_every_fragment_marks_every_breaking_heading(self) -> None:
        self.assertEqual(self.refused, {})
        self.assertEqual(sorted(self.items),
                         sorted(path.stem for path in self.fragments))

    def test_every_breaking_item_names_a_step_or_a_reserved_word(self) -> None:
        for name, items in self.items.items():
            with self.subTest(fragment=name):
                self.assertTrue(items)
                for item in items:
                    self.assertTrue(item.ids, f"{name}.md:{item.line}")

    def test_every_catalog_entry_is_cited_by_a_fragment(self) -> None:
        cited = {step for items in self.items.values() for item in items for step in item.ids}
        self.assertEqual(sorted(set(self.catalog) - cited), [])

    def test_a_step_is_cited_only_from_its_own_product_fragment(self) -> None:
        for name, items in self.items.items():
            for item in items:
                for step in item.ids:
                    if step in self.catalog:
                        self.assertEqual(self.catalog[step]["product"], name, step)

    def test_every_catalog_step_has_an_edit_or_an_instruction(self) -> None:
        # A step of kind `unknown` is a breaking item whose edit is not yet
        # derived; the shipped catalog carries none.
        unknown = [step["id"] for step in self.catalog.values() if step["kind"] == "unknown"]
        self.assertEqual(unknown, [])


class ReleaseStepsApplyTest(unittest.TestCase):
    """Each shipped edit step turns the previous release's shape into the current one."""

    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.root = Path(self._directory.name)
        self.target = self.root / "target"
        self.runtime = self.root / "runtime"
        self.target.mkdir()
        self.runtime.mkdir()

    def apply(self, *ids: str) -> list[str]:
        return upgrade_steps.apply_steps(
            list(ids), {"project": self.root, "target": self.target, "runtime": self.runtime})

    def load(self, name: str, root: Path | None = None):
        return upgrade_steps.load_document((root or self.root) / name)

    def test_casework_fixture_simulation_holiday_set_and_dev_clients(self) -> None:
        write(self.root, "fixtures/a.yaml", """\
apiVersion: registry.registrystack.org/casework-fixture/v1alpha1
kind: CaseworkFixture
name: standalone
source: {id: records, requestEntity: person, reviewStage: review}
expect: {queue: decisions}
""")
        write(self.root, "simulations/s.yaml", """\
apiVersion: registry.registrystack.org/casework-simulation/v1alpha1
kind: CaseworkSimulation
subject: {id: r-1}
expect: {ruleId: first, dueState: atRisk}
""")
        write(self.root, "simulations/holiday-sets/h-1.yaml", "name: h\\nrevision: 1\\n".replace("\\n", "\n"))
        write(self.root, "dev-clients.yaml", "version: 1\nclients: []\n")
        self.apply("casework-fixture-spelling", "casework-simulation-spelling",
                   "casework-holiday-set-envelope", "casework-dev-clients-envelope")
        fixture = self.load("fixtures/a.yaml")
        self.assertEqual(list(fixture)[:2], ["apiVersion", "kind"])
        self.assertEqual(fixture["apiVersion"],
                         "id.registrystack.org/formats/casework/fixture/v1alpha1")
        self.assertEqual(fixture["id"], "standalone")
        self.assertNotIn("name", fixture)
        self.assertEqual(fixture["request"], {"source": "records", "entity": "person"})
        self.assertNotIn("source", fixture)
        simulation = self.load("simulations/s.yaml")
        self.assertEqual(simulation["subject"], {"recordId": "r-1"})
        self.assertEqual(simulation["expect"], {"rule": "first", "dueState": "at-risk"})
        holiday = self.load("simulations/holiday-sets/h-1.yaml")
        self.assertEqual(holiday["kind"], "CaseworkHolidaySet")
        clients = self.load("dev-clients.yaml")
        self.assertEqual(clients["kind"], "CaseworkDevClients")
        self.assertNotIn("version", clients)

    def test_a_casework_simulation_with_no_rule_expects_no_rule_after_migration(self) -> None:
        write(self.root, "simulations/none.yaml", "subject: {id: r-1}\nexpect: {queue: q}\n")
        write(self.root, "simulations/named.yaml", "subject: {id: r-1}\nexpect: {ruleId: first}\n")
        write(self.root, "simulations/bare.yaml", "subject: {id: r-1}\n")
        self.apply("casework-simulation-spelling")
        self.assertEqual(self.load("simulations/none.yaml")["expect"], {"queue": "q", "rule": "none"})
        self.assertEqual(self.load("simulations/named.yaml")["expect"], {"rule": "first"})
        self.assertNotIn("expect", self.load("simulations/bare.yaml"))

    def test_the_casework_fixture_target_instruction_covers_an_omitted_target(self) -> None:
        step = upgrade_steps.load_catalog()["casework-fixture-target"]
        self.assertIn("omitted expect.targetElapsed", step["instruction"])

    def test_the_casework_simulation_extension_step_is_manual_and_precedes_the_spelling_step(self) -> None:
        catalog = list(upgrade_steps.load_catalog())
        step = upgrade_steps.load_catalog()["casework-simulation-file-extension"]
        self.assertEqual((step["kind"], step["file"]), ("manual", "simulations/*.yml"))
        self.assertLess(catalog.index("casework-simulation-file-extension"),
                        catalog.index("casework-simulation-spelling"))

    def test_the_casework_fixture_extension_step_is_manual_and_precedes_the_fixture_spelling_step(self) -> None:
        catalog = list(upgrade_steps.load_catalog())
        step = upgrade_steps.load_catalog()["casework-fixture-file-extension"]
        self.assertEqual((step["kind"], step["file"]), ("manual", "fixtures/*.yml"))
        self.assertLess(catalog.index("casework-fixture-file-extension"),
                        catalog.index("casework-fixture-spelling"))

    def test_the_messaging_null_member_steps_are_manual_and_name_the_refused_members(self) -> None:
        catalog = upgrade_steps.load_catalog()
        project = catalog["messaging-project-null-members"]
        self.assertEqual((project["kind"], project["file"]), ("manual", "messaging.yaml"))
        self.assertIn("actorKind", project["instruction"])
        runtime = catalog["messaging-runtime-null-members"]
        self.assertEqual((runtime["kind"], runtime["root"], runtime["file"]),
                         ("manual", "runtime", "runtime.yaml"))
        self.assertIn("metricsListener", runtime["instruction"])

    def test_a_casework_fixture_with_no_source_block_still_migrates(self) -> None:
        write(self.root, "fixtures/a.yaml", "name: x\nexpect: {queue: q}\n")
        self.apply("casework-fixture-spelling")
        self.assertEqual(self.load("fixtures/a.yaml")["id"], "x")

    def test_evidence_project_question_fixture_and_target_governance(self) -> None:
        write(self.root, "evidence-project.yaml", "version: 1\nproject: evidence-authoring\n")
        write(self.root, "questions/q.yaml", "id: record-status\n")
        write(self.root, "fixtures/f.yaml", "fixture: registry.evidence.reference.x/v1\ncommon: {}\n")
        write(self.target, "governance.yaml", "version: 1\nauthentication: {}\n")
        self.apply("evidence-project-envelope", "evidence-question-envelope",
                   "evidence-fixture-envelope", "evidence-target-governance-envelope")
        self.assertEqual(self.load("evidence-project.yaml"), {
            "apiVersion": "id.registrystack.org/formats/evidence/authoring-project/v1alpha1",
            "kind": "EvidenceAuthoringProject"})
        self.assertEqual(self.load("questions/q.yaml")["kind"], "EvidenceQuestion")
        fixture = self.load("fixtures/f.yaml")
        self.assertEqual((fixture["kind"], fixture["common"]), ("EvidenceFixture", {}))
        self.assertNotIn("fixture", fixture)
        governance = self.load("governance.yaml", self.target)
        self.assertEqual(governance["kind"], "EvidenceTargetGovernance")
        self.assertNotIn("version", governance)

    def test_breg_journeys_with_a_batch(self) -> None:
        write(self.root, "tests/journeys.yaml", """\
apiVersion: registry.registrystack.org/breg-journeys/v1
journeys:
  - id: j
    steps:
      - id: create
        claims: {principal: p}
        request: {operation: create, data: {a: 1}}
        capture: made
      - id: submit
        claims: {principal: p}
        request:
          operation: submit_request
          recordRef: made
          etagRef: made
      - id: read
        claims: {principal: p}
        request: {operation: read_path, data: {parent: {recordRef: made}}}
      - id: batch
        claims: {principal: p}
        request:
          operation: batch
          items:
            - {operation: apply_request, recordRef: made}
            - {operation: create, data: {centroid: {type: Point}}}
""")
        self.apply("breg-journeys")
        journeys = self.load("tests/journeys.yaml")
        self.assertEqual(journeys["apiVersion"], "id.registrystack.org/formats/breg/journeys/v1")
        self.assertEqual(journeys["kind"], "BRegJourneys")
        steps = journeys["journeys"][0]["steps"]
        self.assertEqual(steps[0]["request"], {"type": "create", "data": {"a": 1}})
        self.assertEqual(steps[1]["request"],
                         {"type": "submit-request", "recordCapture": "made", "etagCapture": "made"})
        self.assertEqual(steps[1]["claims"], {"principal": "p"})
        self.assertEqual(steps[2]["request"]["type"], "read-path")
        self.assertEqual(steps[2]["request"]["data"], {"parent": {"recordCapture": "made"}})
        self.assertEqual(steps[3]["request"]["type"], "batch")
        self.assertEqual(steps[3]["request"]["items"][0],
                         {"type": "apply-request", "recordCapture": "made"})
        self.assertEqual(steps[3]["request"]["items"][1]["data"], {"centroid": {"type": "Point"}})
        text = (self.root / "tests/journeys.yaml").read_text(encoding="utf-8")
        self.assertNotIn("&", text)
        self.assertNotIn("*claims", text)

    def test_breg_example_inputs_credentials_selection_and_scenarios(self) -> None:
        write(self.root, "examples/inputs/a.json", json.dumps({"x": {"recordRef": "made"}}))
        write(self.root, "credentials.yaml", """\
apiVersion: registry.registrystack.org/breg-schema-test-credentials/v1
kind: SchemaTestCredentials
bindings: []
""")
        write(self.root, "model/selection.yaml", """\
apiVersion: registry.registrystack.org/breg-model-selection/v1alpha1
kind: ModelSelection
name: x
""")
        write(self.root, "examples/scenarios.json", json.dumps({"version": 1, "scenarios": []}))
        self.apply("breg-example-inputs", "breg-schema-test-credentials", "breg-model-selection",
                   "breg-example-scenarios")
        self.assertEqual(self.load("examples/inputs/a.json"), {"x": {"recordCapture": "made"}})
        self.assertEqual(self.load("credentials.yaml"), {
            "apiVersion": "id.registrystack.org/formats/breg/schema-test-credentials/v1",
            "kind": "BRegSchemaTestCredentials", "bindings": []})
        self.assertEqual(self.load("model/selection.yaml")["kind"], "BRegModelSelection")
        self.assertEqual(self.load("examples/scenarios.json"), {
            "apiVersion": "id.registrystack.org/formats/breg/example-scenarios/v1alpha1",
            "kind": "BRegExampleScenarios", "scenarios": []})

    def test_breg_example_inputs_without_a_record_reference_are_left_alone(self) -> None:
        write(self.root, "examples/inputs/plain.json", json.dumps({"x": {"name": "n"}}))
        write(self.root, "examples/inputs/ref.json", json.dumps({"x": {"recordRef": "made"}}))
        self.apply("breg-example-inputs")
        self.assertEqual(self.load("examples/inputs/plain.json"), {"x": {"name": "n"}})
        self.assertEqual(self.load("examples/inputs/ref.json"), {"x": {"recordCapture": "made"}})

    def test_breg_registry_period_and_unrestricted_members(self) -> None:
        write(self.root, "registry.yaml", """\
statisticalDatasets:
  - id: d
    period: {kind: flow, unit: month}
accessProfiles:
  - id: reader
    requiredScopes: []
    permissions:
      - entity: facility
        rowBoundaries: []
        applyTargets:
          - {entity: site, rowBoundaries: []}
  - id: open
    permissions: []
  - id: scoped
    requiredScopes: [read]
    permissions:
      - {entity: facility, rowBoundaries: [north]}
""")
        self.apply("breg-statistical-period", "breg-access-unrestricted")
        registry = self.load("registry.yaml")
        self.assertEqual(registry["statisticalDatasets"][0]["period"],
                         {"type": "flow", "unit": "month"})
        reader, open_, scoped = registry["accessProfiles"]
        self.assertEqual(reader["requiredScopes"], "unrestricted")
        self.assertEqual(reader["permissions"][0]["rowBoundaries"], "unrestricted")
        self.assertEqual(reader["permissions"][0]["applyTargets"][0]["rowBoundaries"],
                         "unrestricted")
        self.assertEqual(open_["requiredScopes"], "unrestricted")
        self.assertEqual(scoped["requiredScopes"], ["read"])
        self.assertEqual(scoped["permissions"][0]["rowBoundaries"], ["north"])

    def test_breg_module_access_members_take_unrestricted(self) -> None:
        write(self.root, "modules/benefits/module.yaml", """\
id: benefits
version: "1"
entities:
  - id: grant
    accessProfiles:
      - id: reader
        operations: [get]
        rowBoundaries: []
        applyTargets:
          - {entity: site, rowBoundaries: []}
        requestPresence:
          - {requestType: correction, rowBoundaries: []}
      - id: scoped
        requiredScopes: [read]
        operations: [get]
        rowBoundaries:
          - {field: region, claim: region, operator: equals}
extendEntities:
  - entity: person
    accessProfiles:
      - id: reader
        requiredScopes: []
        operations: [get]
        rowBoundaries: []
        applyTargets:
          - {entity: site, rowBoundaries: []}
        requestPresence:
          - {requestType: correction, rowBoundaries: []}
""")
        # A module that contributes no profile is left as it was written.
        write(self.root, "modules/plain/module.yaml", """\
id: plain
version: "1"
entities:
  - id: site
    fields: []
""")
        self.apply("breg-module-access-unrestricted")
        module = self.load("modules/benefits/module.yaml")
        reader, scoped = module["entities"][0]["accessProfiles"]
        extended = module["extendEntities"][0]["accessProfiles"][0]
        for profile in (reader, extended):
            self.assertEqual(profile["requiredScopes"], "unrestricted")
            self.assertEqual(profile["rowBoundaries"], "unrestricted")
            self.assertEqual(profile["applyTargets"][0]["rowBoundaries"], "unrestricted")
            self.assertEqual(profile["requestPresence"][0]["rowBoundaries"], "unrestricted")
        self.assertEqual(scoped["requiredScopes"], ["read"])
        self.assertEqual(scoped["rowBoundaries"],
                         [{"field": "region", "claim": "region", "operator": "equals"}])
        self.assertEqual(self.load("modules/plain/module.yaml"),
                         {"id": "plain", "version": "1", "entities": [{"id": "site", "fields": []}]})

    def test_the_breg_access_steps_cover_every_module_and_end_with_a_relock(self) -> None:
        catalog = upgrade_steps.load_catalog()
        self.assertEqual(catalog["breg-module-access-unrestricted"]["file"],
                         "modules/*/module.yaml")
        ids = list(catalog)
        for step in ("breg-remove-anonymous", "breg-module-access-unrestricted",
                     "breg-access-requirements"):
            self.assertLess(ids.index(step), ids.index("breg-module-relock"), step)
        manual = self.apply("breg-remove-anonymous", "breg-access-requirements",
                            "breg-module-relock")
        self.assertEqual(len(manual), 3)
        anonymous, requirements, relock = manual
        self.assertIn("module.yaml", anonymous)
        self.assertIn("module.yaml", requirements)
        self.assertIn("bregctl project lock", relock)

    def test_the_breg_fragment_cites_the_module_steps_where_a_module_changes(self) -> None:
        catalog = upgrade_steps.load_catalog()
        items = upgrade_steps.check_fragment(upgrade_steps.FRAGMENTS / "breg.md", catalog)
        citing = [item.ids for item in items if "breg-module-relock" in item.ids]
        self.assertIn(("breg-remove-anonymous", "breg-module-relock"), citing)
        self.assertIn(("breg-access-unrestricted", "breg-module-access-unrestricted",
                       "breg-access-requirements", "breg-module-relock"), citing)

    def test_breg_runtime_allowed_clients(self) -> None:
        write(self.runtime, "runtime.yaml", "authentication:\n  oidc:\n    allowedClients: []\n")
        self.apply("breg-runtime-allowed-clients")
        self.assertEqual(self.load("runtime.yaml", self.runtime)["authentication"]["oidc"],
                         {"allowedClients": "unrestricted"})
        write(self.runtime, "runtime.yaml", "authentication:\n  oidc:\n    issuer: x\n")
        self.apply("breg-runtime-allowed-clients")
        self.assertEqual(self.load("runtime.yaml", self.runtime)["authentication"]["oidc"],
                         {"issuer": "x", "allowedClients": "unrestricted"})
        write(self.runtime, "runtime.yaml", "authentication:\n  oidc:\n    allowedClients: [a]\n")
        self.apply("breg-runtime-allowed-clients")
        self.assertEqual(self.load("runtime.yaml", self.runtime)["authentication"]["oidc"],
                         {"allowedClients": ["a"]})

    def test_messaging_runtime_project_template_and_provider(self) -> None:
        write(self.runtime, "runtime.yaml", """\
apiVersion: registry.registrystack.org/messaging-runtime/v1alpha1
kind: MessagingRuntime
retention: {payloadDays: 7, recordDays: 30, submissionReceiptDays: 90}
audit: {retainDays: 400}
providers:
  mail: {kind: smtp, attemptTimeoutSeconds: 10, authentication: {kind: password}}
  hook:
    kind: http
    timeoutMilliseconds: 500
    concurrencyLimit: 4
    callbackVerifier: {kind: hmac}
authentication: {oidc: {jwksSource: {kind: url}}}
""")
        write(self.root, "messaging.yaml", """\
apiVersion: registry.registrystack.org/messaging-package/v1alpha1
kind: MessagingPackage
providers: [{id: mail, kind: smtp}]
accessProfiles:
  - {id: a, dailyLimit: 5, requiredScopes: []}
  - {id: b}
  - {id: c, requiredScopes: [send]}
""")
        write(self.root, "templates/welcome/1/template.yaml", "locales: [en]\n")
        write(self.root, "providers/hook/provider.yaml", "capabilities: {concurrencyLimit: 4}\n")
        self.apply("messaging-runtime-keys", "messaging-project-renames",
                   "messaging-template-envelope", "messaging-provider-envelope",
                   "messaging-provider-capabilities", "messaging-required-scopes")
        runtime = self.load("runtime.yaml", self.runtime)
        self.assertEqual(runtime["apiVersion"],
                         "id.registrystack.org/formats/messaging/runtime/v1alpha1")
        self.assertEqual(runtime["retention"], {"payloadRetentionDays": 7,
                                                 "recordRetentionDays": 30,
                                                 "submissionReceiptRetentionDays": 90})
        self.assertEqual(runtime["audit"], {"retentionDays": 400})
        self.assertEqual(runtime["providers"]["mail"], {
            "type": "smtp", "attemptTimeoutMilliseconds": 10000,
            "authentication": {"type": "password"}})
        self.assertEqual(runtime["providers"]["hook"], {
            "type": "http", "attemptTimeoutMilliseconds": 500, "maximumConcurrentRequests": 4,
            "callbackVerifier": {"type": "hmac"}})
        self.assertEqual(runtime["authentication"], {"oidc": {"jwksSource": {"kind": "url"}}})
        project = self.load("messaging.yaml")
        self.assertEqual(project["providers"], [{"id": "mail", "type": "smtp"}])
        self.assertEqual([profile.get("requiredScopes") for profile in project["accessProfiles"]],
                         ["unrestricted", "unrestricted", ["send"]])
        self.assertEqual(project["accessProfiles"][0]["maximumMessagesPerDay"], 5)
        self.assertEqual(self.load("templates/welcome/1/template.yaml")["kind"],
                         "MessagingTemplate")
        provider = self.load("providers/hook/provider.yaml")
        self.assertEqual(provider["kind"], "MessagingProvider")
        self.assertEqual(provider["capabilities"], {"maximumConcurrentRequests": 4})

    def test_manual_steps_are_reported_with_their_file_and_never_applied(self) -> None:
        manual = self.apply("breg-schema-test-receipt", "casework-dev-session-reset")
        self.assertEqual(len(manual), 2)
        self.assertIn("schema-test-receipt.json", manual[0])
        self.assertIn("bregctl test", manual[0])
        self.assertIn(".casework/dev", manual[1])
        self.assertEqual(sorted(path.name for path in self.root.iterdir()), ["runtime", "target"])


class ProductStepsApplyTest(unittest.TestCase):
    """The Scheduling, Render, and Platform edit steps on the previous release's shapes."""

    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.root = Path(self._directory.name)
        self.runtime = self.root / "runtime"
        self.runtime.mkdir()

    def apply(self, *ids: str) -> list[str]:
        return upgrade_steps.apply_steps(
            list(ids), {"project": self.root, "runtime": self.runtime})

    def load(self, name: str, root: Path | None = None) -> Any:
        return upgrade_steps.load_document((root or self.root) / name)

    def test_evidence_source_resolutions_take_an_envelope_and_type(self) -> None:
        write(self.root, "source-resolutions.json", json.dumps({
            "formatVersion": 1,
            "artifacts": {
                "adapters/a.rhai": {"choice": "keep"},
                "adapters/b.rhai": {"choice": "file", "path": "reviewed/b.rhai"}}}))
        self.apply("evidence-source-resolution-envelope")
        document = self.load("source-resolutions.json")
        self.assertEqual(list(document)[:3], ["apiVersion", "kind", "artifacts"])
        self.assertEqual(document["apiVersion"],
                         "id.registrystack.org/formats/evidence/source-resolution/v1alpha1")
        self.assertEqual(document["kind"], "EvidenceSourceResolution")
        self.assertEqual(document["artifacts"], {
            "adapters/a.rhai": {"type": "keep"},
            "adapters/b.rhai": {"type": "file", "path": "reviewed/b.rhai"}})

    def test_evidence_dev_state_and_source_import_state_are_manual(self) -> None:
        manual = self.apply("evidence-dev-state-reset", "evidence-source-import-state-reset")
        self.assertEqual(len(manual), 2)
        self.assertIn(".evidence/dev/state.json", manual[0])
        self.assertIn(".evidence/source-imports", manual[1])

    def test_scheduling_project_keys(self) -> None:
        write(self.root, "scheduling.yaml", """\
apiVersion: registry.registrystack.org/scheduling-policy-package/v1alpha1
kind: SchedulingPolicyPackage
scheduling: {id: registry-updates, version: 3}
holdPolicy: {maxPerCaller: 2, ttlMinutes: 10}
offerings:
  - id: a
    exactTime: {maxRecipients: 4, durationMinutes: 30}
    reminders: [{minutesBefore: 1440}, {minutesBefore: 120}]
  - id: b
hooks:
  - {id: h, handler: {kind: url, destination: d}}
""")
        self.apply("scheduling-project-keys")
        project = self.load("scheduling.yaml")
        self.assertEqual(list(project)[:3], ["apiVersion", "kind", "project"])
        self.assertEqual(project["apiVersion"],
                         "id.registrystack.org/formats/scheduling/project/v1alpha1")
        self.assertEqual(project["kind"], "SchedulingProject")
        self.assertEqual(project["project"], {"id": "registry-updates", "version": 3})
        self.assertEqual(project["holdPolicy"], {"maximumPerCaller": 2, "ttlMinutes": 10})
        self.assertEqual(project["offerings"][0]["exactTime"],
                         {"maximumRecipients": 4, "durationMinutes": 30})
        self.assertEqual(project["offerings"][0]["reminders"],
                         [{"offsetMinutes": 1440}, {"offsetMinutes": 120}])
        self.assertEqual(project["hooks"][0]["handler"], {"type": "url", "destination": "d"})

    def test_scheduling_records_and_fixture_units_policy(self) -> None:
        write(self.root, "records.yaml", """\
windows:
  - id: w
    unitsPolicy: {kind: perRecipient, perRecipient: 1}
  - id: x
    unitsPolicy:
      kind: bandedTable
      input: serviceRecipientCount
      aboveHighestBand: {policy: refuse}
  - id: y
    unitsPolicy: {kind: fixed, units: 1}
""")
        write(self.root, "fixtures/a.yml", """\
apiVersion: registry.registrystack.org/scheduling-fixture/v1alpha1
kind: SchedulingFixture
now: 2026-10-05T00:00:00Z
facts:
  windows:
    - {id: w, unitsPolicy: {kind: bandedTable, input: serviceRecipientCount}}
cases:
  - {id: c, request: {policyRevision: 1}, expect: {outcome: admitted}}
""")
        self.apply("scheduling-records-envelope", "scheduling-fixture-keys")
        records = self.load("records.yaml")
        self.assertEqual(records["apiVersion"],
                         "id.registrystack.org/formats/scheduling/records/v1alpha1")
        self.assertEqual(records["kind"], "SchedulingRecords")
        self.assertEqual([window["unitsPolicy"] for window in records["windows"]], [
            {"type": "per-recipient", "perRecipient": 1},
            {"type": "banded-table", "input": "service-recipient-count",
             "aboveHighestBand": {"type": "refuse"}},
            {"type": "fixed", "units": 1}])
        fixture = (self.root / "fixtures/a.yml").read_text(encoding="utf-8")
        self.assertIn("now: 2026-10-05T00:00:00Z\n", fixture)
        fixture = self.load("fixtures/a.yml")
        self.assertEqual(fixture["apiVersion"],
                         "id.registrystack.org/formats/scheduling/fixture/v1alpha1")
        self.assertEqual(fixture["facts"]["windows"][0]["unitsPolicy"],
                         {"type": "banded-table", "input": "service-recipient-count"})
        self.assertEqual(fixture["cases"][0]["expect"], {"type": "admitted"})

    def test_scheduling_runtime_keys(self) -> None:
        write(self.runtime, "runtime.yaml", """\
apiVersion: registry.registrystack.org/scheduling-runtime/v1alpha1
kind: SchedulingRuntime
audit: {retainDays: 90}
retention: {attemptReceiptDays: 30, hookPayloadDays: 7}
""")
        self.apply("scheduling-runtime-keys")
        runtime = self.load("runtime.yaml", self.runtime)
        self.assertEqual(runtime["apiVersion"],
                         "id.registrystack.org/formats/scheduling/runtime/v1alpha1")
        self.assertEqual(runtime["audit"], {"retentionDays": 90})
        self.assertEqual(runtime["retention"], {"attemptReceiptRetentionDays": 30,
                                                 "hookPayloadRetentionDays": 7})

    def test_render_manifest_keys(self) -> None:
        write(self.root, "manifest.yaml", """\
apiVersion: render.registrystack.org/v1alpha1
kind: RenderBundle
bundleVersion: 1
documents:
  - {id: card, version: 1, entry: templates/card.typ, schema: schemas/card.schema.json}
  - {id: slip, version: 1, entry: templates/slip.typ, schema: schemas/slip.schema.json}
""")
        self.apply("render-manifest-keys")
        manifest = self.load("manifest.yaml")
        self.assertEqual(manifest["apiVersion"],
                         "id.registrystack.org/formats/render/bundle/v1alpha1")
        self.assertEqual(manifest["documents"][1],
                         {"id": "slip", "version": 1, "entryFile": "templates/slip.typ",
                          "schemaFile": "schemas/slip.schema.json"})

    def test_render_runtime_keys_scale_the_grace_to_milliseconds(self) -> None:
        write(self.runtime, "runtime.yaml", """\
apiVersion: registry.registrystack.org/render-runtime/v1alpha1
kind: RenderRuntimeConfig
listener: {bind: "127.0.0.1:8080", shutdownGraceSeconds: 30}
limits: {maxOutputBytes: 100, maxRequestBodyBytes: 200, maxConcurrency: 3, renderTimeoutSeconds: 20}
audit: {retainDays: 14}
""")
        self.apply("render-runtime-keys")
        runtime = self.load("runtime.yaml", self.runtime)
        self.assertEqual(runtime["apiVersion"],
                         "id.registrystack.org/formats/render/runtime/v1alpha1")
        self.assertEqual(runtime["listener"], {"bind": "127.0.0.1:8080",
                                               "shutdownGraceMilliseconds": 30000})
        self.assertEqual(runtime["limits"], {"maximumOutputBytes": 100,
                                             "maximumRequestBytes": 200,
                                             "maximumConcurrentRenders": 3,
                                             "renderTimeoutSeconds": 20})
        self.assertEqual(runtime["audit"], {"retentionDays": 14})

    def test_platform_task_connection_envelope(self) -> None:
        write(self.root, "task-connection.yaml", "version: 1\ncaseworkUrl: http://127.0.0.1:8090\n")
        self.apply("platform-task-connection-envelope")
        self.assertEqual(self.load("task-connection.yaml"), {
            "apiVersion": "id.registrystack.org/formats/platform/task-connection/v1alpha1",
            "kind": "PlatformTaskConnection", "caseworkUrl": "http://127.0.0.1:8090"})


class RehearsalEnvelopeTieTest(unittest.TestCase):
    """The rehearsal's own credentials envelope is the catalog's step."""

    def test_the_rehearsal_envelope_is_the_credentials_step(self) -> None:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "rehearse_upgrade_for_tie", SCRIPTS / "rehearse-upgrade.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules["rehearse_upgrade_for_tie"] = module
        spec.loader.exec_module(module)
        envelope = module.BREG_CREDENTIALS_ENVELOPE
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(root, "credentials.yaml", "\n".join(
                f"{key}: {value}" for key, value in envelope["from"].items()) + "\nbindings: []\n")
            upgrade_steps.apply_steps(["breg-schema-test-credentials"], {"project": root})
            migrated = upgrade_steps.load_document(root / "credentials.yaml")
        self.assertEqual({key: migrated[key] for key in ("apiVersion", "kind")}, envelope["to"])

    def rehearsal(self) -> Any:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "rehearse_upgrade_for_lists", SCRIPTS / "rehearse-upgrade.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules["rehearse_upgrade_for_lists"] = module
        spec.loader.exec_module(module)
        return module

    LEG_LISTS = ("BREG_UPGRADE_STEPS", "BREG_RUNTIME_UPGRADE_STEPS", "CASEWORK_UPGRADE_STEPS",
                 "EVIDENCE_UPGRADE_STEPS", "MESSAGING_UPGRADE_STEPS",
                 "MESSAGING_RUNTIME_UPGRADE_STEPS")

    def test_the_rehearsal_performs_the_manual_messaging_project_envelope_step(self) -> None:
        module = self.rehearsal()
        step = upgrade_steps.load_catalog()["messaging-project-envelope"]
        self.assertEqual(step["kind"], "manual")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = write(root, "messaging.yaml", """\
apiVersion: registry.registrystack.org/messaging-package/v1alpha1
kind: MessagingPackage
providers:
  - id: mail-relay
    type: smtp
""")
            module.write_messaging_project_envelope(root)
            text = path.read_text(encoding="utf-8")
            project = upgrade_steps.load_document(path)
        self.assertEqual(list(project), ["apiVersion", "kind", "project", "providers"])
        self.assertEqual(project["providers"], [{"id": "mail-relay", "type": "smtp"}])
        # The envelope written is the one the step's instruction spells out.
        self.assertIn(f"apiVersion: {project['apiVersion']} ", step["instruction"])
        self.assertIn(f"kind: {project['kind']},", step["instruction"])
        self.assertEqual(project["project"], {"id": module.MESSAGING_PROJECT_ID,
                                              "version": module.MESSAGING_PROJECT_VERSION})
        # The version is a label: it stays text on disk, never a YAML number.
        self.assertIsInstance(project["project"]["version"], str)
        self.assertIn(f"version: '{module.MESSAGING_PROJECT_VERSION}'", text)

    def test_the_messaging_project_envelope_step_refuses_a_file_that_is_not_a_mapping(
            self) -> None:
        module = self.rehearsal()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(root, "messaging.yaml", "- not\n- a mapping\n")
            with self.assertRaisesRegex(module.RehearsalError, "messaging-project-envelope"):
                module.write_messaging_project_envelope(root)

    def test_every_step_the_rehearsal_applies_is_a_documented_edit(self) -> None:
        module = self.rehearsal()
        catalog = upgrade_steps.load_catalog()
        for name in self.LEG_LISTS:
            ids = getattr(module, name)
            self.assertTrue(ids, name)
            for step in ids:
                self.assertIn(step, catalog, f"{name}: {step} is not in the catalog")
                self.assertIn("edits", catalog[step], f"{name}: {step} is not an edit")

    def test_every_edit_step_is_in_a_leg_or_listed_as_unit_tested_only(self) -> None:
        module = self.rehearsal()
        catalog = upgrade_steps.load_catalog()
        in_legs = {step for name in self.LEG_LISTS for step in getattr(module, name)}
        unit_only = module.UNIT_TESTED_ONLY_STEPS
        edits = {step_id for step_id, step in catalog.items() if step["kind"] == "edit"}
        self.assertEqual(sorted(edits - in_legs - set(unit_only)), [],
                         "an edit step no rehearsal leg applies needs a reason in "
                         "UNIT_TESTED_ONLY_STEPS")
        self.assertEqual(sorted(set(unit_only) - edits), [],
                         "UNIT_TESTED_ONLY_STEPS names a step that is not a catalog edit")
        self.assertEqual(sorted(set(unit_only) & in_legs), [],
                         "a step a leg applies is not unit-tested only")
        for step_id, reason in unit_only.items():
            self.assertTrue(reason.strip(), f"{step_id} has no reason")


if __name__ == "__main__":
    unittest.main()
