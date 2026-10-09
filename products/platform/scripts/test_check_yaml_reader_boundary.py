#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "products" / "platform" / "scripts" / "check-yaml-reader-boundary.py"

spec = importlib.util.spec_from_file_location("check_yaml_reader_boundary", SCRIPT)
assert spec is not None and spec.loader is not None
gate = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = gate
spec.loader.exec_module(gate)

REASON = "read configuration through registry_platform_yaml::Document::decode or RuntimeConfigLoader (CFG-YAML-1)"


def configuration(*, skip: str = "", reason: str = REASON, extra: str = "") -> str:
    lines = ["cognitive-complexity-threshold = 25", "disallowed-methods = ["]
    for path in gate.required_paths():
        if path != skip:
            lines.append(f'  {{ path = "{path}", reason = "{reason}" }},')
    if extra:
        lines.append(extra)
    lines.append("]")
    return "\n".join(lines) + "\n"


def audit(files: dict[str, str], external: frozenset[str] = frozenset()) -> list[str]:
    problems, _ = gate.suppression_problems(files, external)
    return problems


class ConfigurationTest(unittest.TestCase):
    def test_a_complete_configuration_passes(self) -> None:
        self.assertEqual(gate.configuration_problems("clippy.toml", configuration()), [])

    def test_every_reader_entry_point_is_required(self) -> None:
        self.assertEqual(len(gate.required_paths()), 14)
        self.assertIn("serde_norway::from_value", gate.required_paths())
        self.assertIn("serde_yaml_ng::Deserializer::from_reader", gate.required_paths())

    def test_a_missing_entry_names_the_entry_to_add(self) -> None:
        problems = gate.configuration_problems(
            "crates/x/clippy.toml", configuration(skip="serde_norway::from_slice")
        )
        self.assertEqual(len(problems), 1)
        self.assertIn("crates/x/clippy.toml", problems[0])
        self.assertIn('{ path = "serde_norway::from_slice"', problems[0])

    def test_a_reason_must_name_the_shared_reader(self) -> None:
        problems = gate.configuration_problems(
            "clippy.toml", configuration(reason="do not do this")
        )
        self.assertEqual(len(problems), 14)
        self.assertIn("registry_platform_yaml", problems[0])

    def test_an_entry_without_a_reason_is_refused(self) -> None:
        text = configuration(skip="serde_norway::from_str", extra='  "serde_norway::from_str",')
        problems = gate.configuration_problems("clippy.toml", text)
        self.assertEqual(len(problems), 1)
        self.assertIn("serde_norway::from_str", problems[0])

    def test_an_entry_allowed_to_be_invalid_is_refused(self) -> None:
        text = configuration(
            skip="serde_yaml_ng::from_str",
            extra=f'  {{ path = "serde_yaml_ng::from_str", reason = "{REASON}", allow-invalid = true }},',
        )
        problems = gate.configuration_problems("clippy.toml", text)
        self.assertEqual(len(problems), 1)
        self.assertIn("allow-invalid", problems[0])

    def test_a_configuration_that_does_not_parse_is_refused(self) -> None:
        problems = gate.configuration_problems("clippy.toml", "disallowed-methods = [")
        self.assertEqual(len(problems), 1)
        self.assertIn("clippy.toml", problems[0])

    def test_every_tracked_configuration_carries_every_entry(self) -> None:
        names = gate.tracked_configurations(ROOT)
        self.assertIn("clippy.toml", names)
        self.assertIn("crates/registry-breg-mcp/clippy.toml", names)
        for name in names:
            with self.subTest(configuration=name):
                text = (ROOT / name).read_text(encoding="utf-8")
                self.assertEqual(gate.configuration_problems(name, text), [])


class BanTest(unittest.TestCase):
    def test_a_reader_out_of_the_graph_must_be_banned(self) -> None:
        problems = gate.ban_problems("[bans]\ndeny = []\n", {"serde_yaml_ng"})
        self.assertEqual(len(problems), 1)
        self.assertIn('{ crate = "serde_yaml_ng"', problems[0])

    def test_a_ban_in_either_spelling_holds(self) -> None:
        for text in (
            '[bans]\ndeny = [{ crate = "serde_yaml_ng", reason = "x" }]\n',
            '[bans]\ndeny = ["serde_yaml_ng"]\n',
            '[bans]\ndeny = [{ name = "serde_yaml_ng" }]\n',
        ):
            with self.subTest(text=text):
                self.assertEqual(gate.ban_problems(text, {"serde_yaml_ng"}), [])

    def test_a_ban_with_wrappers_does_not_hold(self) -> None:
        text = '[bans]\ndeny = [{ crate = "serde_yaml_ng", wrappers = ["x"] }]\n'
        problems = gate.ban_problems(text, {"serde_yaml_ng"})
        self.assertEqual(len(problems), 1)
        self.assertIn("wrappers", problems[0])

    def test_a_reader_in_the_graph_needs_no_ban(self) -> None:
        self.assertEqual(gate.ban_problems("[bans]\ndeny = []\n", set()), [])

    def test_the_repository_bans_serde_yaml_ng(self) -> None:
        text = (ROOT / "deny.toml").read_text(encoding="utf-8")
        self.assertEqual(gate.ban_problems(text, {"serde_yaml_ng"}), [])


class OtherParserBanTest(unittest.TestCase):
    ALLOWED = {
        "saphyr-parser": ["registry-platform-yaml"],
        "serde_yaml": ["hayagriva", "typst-library"],
        "yaml-rust": ["syntect"],
        "serde_yml": [],
        "yaml-rust2": [],
        "saphyr": [],
    }

    def deny(self, *, skip: str = "", extra_wrapper: tuple[str, str] | None = None) -> str:
        entries = []
        for name, wrappers in self.ALLOWED.items():
            if name == skip:
                continue
            if extra_wrapper and extra_wrapper[0] == name:
                wrappers = [*wrappers, extra_wrapper[1]]
            clause = f", wrappers = {wrappers!r}".replace("'", '"') if wrappers else ""
            entries.append(f'{{ crate = "{name}"{clause}, reason = "x" }}')
        return "[bans]\ndeny = [" + ", ".join(entries) + "]\n"

    def test_the_complete_set_of_bans_passes(self) -> None:
        self.assertEqual(gate.other_parser_ban_problems(self.deny()), [])

    def test_every_other_yaml_parser_must_be_banned(self) -> None:
        for name in self.ALLOWED:
            with self.subTest(name=name):
                problems = gate.other_parser_ban_problems(self.deny(skip=name))
                self.assertEqual(len(problems), 1)
                self.assertIn(f'crate = "{name}"', problems[0])

    def test_a_wrapper_beyond_the_known_ones_is_refused(self) -> None:
        for name in self.ALLOWED:
            with self.subTest(name=name):
                problems = gate.other_parser_ban_problems(
                    self.deny(extra_wrapper=(name, "some-new-crate"))
                )
                self.assertEqual(len(problems), 1)
                self.assertIn("some-new-crate", problems[0])

    def test_the_repository_bans_every_other_yaml_parser(self) -> None:
        text = (ROOT / "deny.toml").read_text(encoding="utf-8")
        self.assertEqual(gate.other_parser_ban_problems(text), [])


class RegisterTest(unittest.TestCase):
    def test_external_formats_are_read_from_the_register(self) -> None:
        text = """\
formats:
  - id: a/configured
    exceptionClass: exchange-model
    reader:
      file: x.rs
  - id: a/foreign
    audience: authored
    exceptionClass: external-format
  - id: a/plain
"""
        self.assertEqual(gate.external_formats(text), frozenset({"a/foreign"}))

    def test_the_repository_register_names_the_formats_read_directly(self) -> None:
        text = (ROOT / "products/platform/config-formats.yaml").read_text(encoding="utf-8")
        formats = gate.external_formats(text)
        self.assertIn("breg/linkml-schema", formats)
        self.assertIn("platform/thunderid-resources", formats)


class BlankTest(unittest.TestCase):
    def test_comments_and_literals_are_blanked_in_place(self) -> None:
        source = (
            'let a = "serde_norway::from_str"; // serde_norway\n'
            "/* serde_norway /* nested */ still */ let b = r#\"serde_norway\"#;\n"
            "let c = '\"'; let d: &'static str = b\"x\"; serde_norway::to_string(&a);\n"
        )
        blanked = gate.blank(source)
        self.assertEqual(len(blanked), len(source))
        self.assertEqual(blanked.count("\n"), source.count("\n"))
        self.assertEqual(blanked.count("serde_norway"), 1)
        self.assertIn("&'static str", blanked)


class SuppressionTest(unittest.TestCase):
    PRODUCTION = """\
use serde_norway::Value;

#[allow(clippy::disallowed_methods, reason = "REASON")]
pub fn read(text: &str) -> Value {
    serde_norway::from_str(text).unwrap()
}
"""

    def test_a_production_suppression_must_name_an_external_format(self) -> None:
        source = self.PRODUCTION.replace("REASON", "because")
        problems = audit({"crates/a/src/lib.rs": source}, frozenset({"a/foreign"}))
        self.assertEqual(len(problems), 1)
        self.assertIn("crates/a/src/lib.rs:3", problems[0])
        self.assertIn("registry_platform_yaml", problems[0])

    def test_a_production_suppression_naming_an_external_format_is_accepted(self) -> None:
        source = self.PRODUCTION.replace("REASON", "a/foreign owns its grammar")
        problems, accepted = gate.suppression_problems(
            {"crates/a/src/lib.rs": source}, frozenset({"a/foreign"})
        )
        self.assertEqual(problems, [])
        self.assertEqual(len(accepted), 1)
        self.assertIn("a/foreign", accepted[0])

    def test_a_suppression_without_a_reason_is_refused_even_in_tests(self) -> None:
        source = self.PRODUCTION.replace(', reason = "REASON"', "")
        problems = audit({"crates/a/tests/read.rs": source})
        self.assertEqual(len(problems), 1)
        self.assertIn("reason", problems[0])

    def test_a_suppression_in_test_code_with_a_reason_is_accepted(self) -> None:
        source = self.PRODUCTION.replace("REASON", "reads back this tool's own output")
        for path in (
            "crates/a/tests/read.rs",
            "crates/a/examples/driver.rs",
            "crates/a/benches/read.rs",
            "crates/a/src/tests.rs",
            "crates/a/src/blocks_tests.rs",
        ):
            with self.subTest(path=path):
                self.assertEqual(audit({path: source}), [])

    def test_an_inline_test_module_is_test_code_and_what_follows_it_is_not(self) -> None:
        test_allow = '#[allow(clippy::disallowed_methods, reason = "tool output")]'
        source = f"""\
pub fn ok() {{}}

#[cfg(test)]
mod tests {{
    fn braces() -> &'static str {{ "}}" }}

    {test_allow}
    fn read() {{ let _ = serde_norway::from_str::<u8>("1"); }}
}}

{test_allow}
pub fn read() {{ let _ = serde_norway::from_str::<u8>("1"); }}
"""
        problems = audit({"crates/a/src/lib.rs": source})
        self.assertEqual(len(problems), 1)
        self.assertIn("crates/a/src/lib.rs:11", problems[0])

    def test_a_module_declared_under_cfg_test_is_test_code(self) -> None:
        files = {
            "crates/a/src/lib.rs": "#[cfg(test)]\nmod support;\n",
            "crates/a/src/support.rs": self.PRODUCTION.replace("REASON", "tool output"),
        }
        self.assertEqual(audit(files), [])

    def test_a_suppression_in_a_file_that_never_names_a_reader_is_left_alone(self) -> None:
        source = """\
#[allow(clippy::disallowed_methods)]
pub fn other() -> &'static str {
    "serde_norway::from_str"
}
"""
        self.assertEqual(audit({"crates/a/src/lib.rs": source}), [])

    def test_an_inner_suppression_covers_the_modules_below_it(self) -> None:
        files = {
            "crates/a/src/lib.rs": "#![allow(clippy::disallowed_methods)]\nmod read;\n",
            "crates/a/src/read.rs": "pub fn r() { let _ = serde_norway::from_str::<u8>(\"1\"); }\n",
        }
        problems = audit(files)
        self.assertEqual(len(problems), 1)
        self.assertIn("crates/a/src/lib.rs:1", problems[0])

    def test_an_outer_suppression_on_a_module_declaration_covers_that_module(self) -> None:
        files = {
            "crates/a/src/lib.rs": "#[allow(clippy::disallowed_methods)]\nmod read;\n",
            "crates/a/src/read/mod.rs": "mod inner;\n",
            "crates/a/src/read/inner.rs": "pub fn r() { let _ = serde_norway::from_slice::<u8>(b\"1\"); }\n",
        }
        problems = audit(files)
        self.assertEqual(len(problems), 1)
        self.assertIn("crates/a/src/lib.rs:1", problems[0])

    def test_every_spelling_that_silences_the_lint_is_audited(self) -> None:
        call = "pub fn r() { let _ = serde_yaml_ng::from_str::<u8>(\"1\"); }\n"
        for attribute in (
            "#[allow(clippy::disallowed_methods)]",
            "#[expect(clippy::disallowed_methods)]",
            "#[allow(clippy::style)]",
            "#[allow(clippy::all)]",
            "#[allow(warnings)]",
            "#[allow(\n    clippy :: disallowed_methods,\n)]",
            "#[cfg_attr(not(test), allow(clippy::disallowed_methods))]",
        ):
            with self.subTest(attribute=attribute):
                problems = audit({"crates/a/src/lib.rs": f"{attribute}\n{call}"})
                self.assertEqual(len(problems), 1)

    def test_unrelated_suppressions_are_left_alone(self) -> None:
        source = """\
#[allow(clippy::disallowed_types, dead_code)]
pub fn r() { let _ = serde_norway::from_str::<u8>("1"); }
"""
        self.assertEqual(audit({"crates/a/src/lib.rs": source}), [])

    def test_the_shared_reader_is_the_one_crate_left_alone(self) -> None:
        source = self.PRODUCTION.replace(', reason = "REASON"', "")
        self.assertEqual(audit({"crates/registry-platform-yaml/src/lib.rs": source}), [])

    def test_the_repository_has_no_unexplained_suppression(self) -> None:
        files = gate.tracked_sources(ROOT)
        external = gate.external_formats(
            (ROOT / "products/platform/config-formats.yaml").read_text(encoding="utf-8")
        )
        problems, _ = gate.suppression_problems(files, external)
        self.assertEqual(problems, [])


class AliasTest(unittest.TestCase):
    def test_a_reader_reachable_under_another_name_is_refused(self) -> None:
        for source in (
            "pub use serde_norway::from_str;\n",
            "pub(crate) use serde_norway as yaml;\n",
            "pub use {serde_yaml_ng::Deserializer};\n",
            "extern crate serde_norway as yaml;\n",
        ):
            with self.subTest(source=source):
                problems = gate.alias_problems({"crates/a/src/lib.rs": source})
                self.assertEqual(len(problems), 1)
                self.assertIn("crates/a/src/lib.rs:1", problems[0])

    def test_a_private_import_is_allowed(self) -> None:
        source = 'use serde_norway as yaml;\n// pub use serde_norway::from_str;\nconst S: &str = "pub use serde_norway";\n'
        self.assertEqual(gate.alias_problems({"crates/a/src/lib.rs": source}), [])

    def test_a_renamed_reader_dependency_is_refused(self) -> None:
        manifest = '[dependencies]\nyaml = { package = "serde_norway", version = "0.9" }\n'
        problems = gate.manifest_problems({"crates/a/Cargo.toml": manifest})
        self.assertEqual(len(problems), 1)
        self.assertIn("crates/a/Cargo.toml", problems[0])

    def test_a_manifest_that_allows_the_lint_is_refused(self) -> None:
        for manifest in (
            '[lints.clippy]\ndisallowed_methods = "allow"\n',
            '[workspace.lints.clippy]\nstyle = { level = "allow", priority = -1 }\n',
            '[lints.rust]\nwarnings = "allow"\n',
        ):
            with self.subTest(manifest=manifest):
                problems = gate.manifest_problems({"Cargo.toml": manifest})
                self.assertEqual(len(problems), 1)

    def test_ordinary_manifests_pass(self) -> None:
        manifest = '[dependencies]\nserde_norway = "0.9"\n\n[lints.clippy]\nstyle = "warn"\n'
        self.assertEqual(gate.manifest_problems({"Cargo.toml": manifest}), [])

    def test_cargo_configuration_that_silences_the_lint_is_refused(self) -> None:
        for text in (
            '[build]\nrustflags = ["-A", "clippy::disallowed_methods"]\n',
            '[target.x86_64-unknown-linux-gnu]\nrustflags = "--cap-lints allow"\n',
        ):
            with self.subTest(text=text):
                problems = gate.manifest_problems({".cargo/config.toml": text})
                self.assertEqual(len(problems), 1)

    def test_the_repository_reaches_the_readers_by_their_own_names(self) -> None:
        self.assertEqual(gate.alias_problems(gate.tracked_sources(ROOT)), [])
        self.assertEqual(gate.manifest_problems(gate.tracked_manifests(ROOT)), [])


class CommandTest(unittest.TestCase):
    def test_the_command_writes_the_probe_plan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            completed = subprocess.run(
                [sys.executable, str(SCRIPT), "--root", str(ROOT), "--plan", directory],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            configurations = Path(directory, "configurations").read_text(encoding="utf-8")
            self.assertIn("clippy.toml\n", configurations)
            readers = Path(directory, "readers").read_text(encoding="utf-8").split()
            self.assertIn("serde_norway", readers)


if __name__ == "__main__":
    unittest.main()
