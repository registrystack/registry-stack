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

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import upgrade_steps  # noqa: E402

Error = upgrade_steps.StepError


def edit(**fields: object) -> dict[str, object]:
    return dict(fields)


class EditKindsTest(unittest.TestCase):
    """One sample document per edit kind."""

    def apply(self, document: object, **fields: object) -> object:
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


if __name__ == "__main__":
    unittest.main()
