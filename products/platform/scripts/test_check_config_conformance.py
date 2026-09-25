#!/usr/bin/env python3
from __future__ import annotations

import dataclasses
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "products" / "platform" / "scripts" / "check-config-conformance.py"

spec = importlib.util.spec_from_file_location("check_config_conformance", SCRIPT)
assert spec is not None and spec.loader is not None
gate = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = gate
spec.loader.exec_module(gate)

CANONICAL = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Registry Stack shared runtime configuration blocks",
    "$defs": {
        "ListenerBind": {"type": "string", "maxLength": 64},
        "ListenerConfig": {
            "type": "object",
            "properties": {"bind": {"$ref": "#/$defs/ListenerBind"}},
            "required": ["bind"],
        },
        "PackageConfig": {
            "type": "object",
            "properties": {"root": {"type": "string"}},
            "required": ["root"],
        },
    },
}

LOADER_SOURCE = """
use registry_platform_config::RuntimeConfigLoader;

pub fn load() {
    let _ = RuntimeConfigLoader::new(ENVELOPE);
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_reference_refuses_substitution() {}

    #[test]
    #[should_panic]
    fn an_authored_file_refuses_substitution() {}
}
"""


def row(**changes: object) -> object:
    base = gate.Row(
        product="sample",
        loader_sources=("crates/sample/src",),
        runtime_schema="crates/sample/runtime.schema.json",
        shared_blocks=("ListenerBind", "ListenerConfig"),
        reference_refusal=gate.TestRef(
            "crates/sample/src/lib.rs", "a_reference_refuses_substitution"
        ),
        authored_refusal=gate.TestRef(
            "crates/sample/src/lib.rs", "an_authored_file_refuses_substitution"
        ),
    )
    return dataclasses.replace(base, **changes)


class ConfigConformanceFixtureTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.write_json(gate.CANONICAL_SCHEMA, CANONICAL)
        runtime = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "SampleRuntimeConfig",
            "type": "object",
            "$defs": {
                name: CANONICAL["$defs"][name]
                for name in ("ListenerBind", "ListenerConfig")
            }
            | {"AuditConfig": {"type": "object"}},
        }
        self.write_json("crates/sample/runtime.schema.json", runtime)
        self.write_text("crates/sample/src/lib.rs", LOADER_SOURCE)

    def write_json(self, relative: str, value: object) -> None:
        self.write_text(relative, json.dumps(value, indent=2) + "\n")

    def write_text(self, relative: str, text: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def edit_runtime_schema(self, edit) -> None:
        path = self.root / "crates/sample/runtime.schema.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        edit(document["$defs"])
        self.write_json("crates/sample/runtime.schema.json", document)

    def problems(self, *rows: object) -> list[str]:
        return gate.check(self.root, rows or (row(),))

    def assert_one_problem(self, expected: str, *rows: object) -> None:
        problems = self.problems(*rows)
        self.assertEqual(1, len(problems), problems)
        self.assertIn(expected, problems[0])

    def test_a_conforming_product_passes(self) -> None:
        self.assertEqual([], self.problems())

    def test_an_altered_shared_block_is_refused(self) -> None:
        self.edit_runtime_schema(
            lambda defs: defs["ListenerBind"].update({"maxLength": 4096})
        )
        self.assert_one_problem(
            "sample: crates/sample/runtime.schema.json re-declares shared block "
            "ListenerBind instead of embedding it unchanged"
        )

    def test_a_missing_shared_block_is_refused(self) -> None:
        self.edit_runtime_schema(lambda defs: defs.pop("ListenerConfig"))
        self.assert_one_problem(
            "sample: crates/sample/runtime.schema.json does not embed shared "
            "block ListenerConfig"
        )

    def test_an_undeclared_copy_of_a_shared_block_must_still_match(self) -> None:
        self.edit_runtime_schema(
            lambda defs: defs.update({"PackageConfig": {"type": "object"}})
        )
        self.assert_one_problem("re-declares shared block PackageConfig")

    def test_a_declared_block_the_platform_does_not_publish_is_refused(self) -> None:
        self.assert_one_problem(
            "sample: shared block AuditConfig is not in "
            "products/platform/generated/runtime-config-blocks.schema.json",
            row(shared_blocks=("ListenerBind", "ListenerConfig", "AuditConfig")),
        )

    def test_a_missing_runtime_schema_is_refused(self) -> None:
        (self.root / "crates/sample/runtime.schema.json").unlink()
        self.assert_one_problem(
            "sample: runtime schema crates/sample/runtime.schema.json is missing"
        )

    def test_a_product_without_the_shared_loader_is_refused(self) -> None:
        self.write_text(
            "crates/sample/src/lib.rs",
            LOADER_SOURCE.replace("RuntimeConfigLoader::new(ENVELOPE)", "parse()"),
        )
        self.assert_one_problem(
            "sample: no source under crates/sample/src reads runtime.yaml through "
            "RuntimeConfigLoader"
        )

    def assert_loader_refused(self) -> None:
        self.assert_one_problem(
            "sample: no source under crates/sample/src reads runtime.yaml through "
            "RuntimeConfigLoader"
        )

    def without_loader(self) -> str:
        return LOADER_SOURCE.replace("RuntimeConfigLoader::new(ENVELOPE)", "parse()")

    def test_a_loader_call_inside_a_test_module_does_not_count(self) -> None:
        self.write_text(
            "crates/sample/src/lib.rs",
            self.without_loader().replace(
                "fn a_reference_refuses_substitution() {}",
                "fn a_reference_refuses_substitution() {\n"
                "        let _ = RuntimeConfigLoader::new(ENVELOPE);\n    }",
            ),
        )
        self.assert_loader_refused()

    def test_a_loader_call_in_a_comment_or_a_string_does_not_count(self) -> None:
        self.write_text(
            "crates/sample/src/lib.rs",
            self.without_loader()
            + "// RuntimeConfigLoader::new(ENVELOPE)\n"
            + "/* RuntimeConfigLoader::new(ENVELOPE) */\n"
            + 'const NOTE: &str = "RuntimeConfigLoader::new(ENVELOPE)";\n'
            + 'const RAW: &str = r#"RuntimeConfigLoader::new(ENVELOPE)"#;\n',
        )
        self.assert_loader_refused()

    def test_a_loader_call_in_a_test_only_module_file_does_not_count(self) -> None:
        self.write_text(
            "crates/sample/src/lib.rs",
            self.without_loader()
            + "#[cfg(test)]\nmod loader_tests;\n"
            + '#[cfg(test)]\n#[path = "elsewhere/probe.rs"]\nmod probe;\n',
        )
        call = "fn t() { let _ = RuntimeConfigLoader::new(ENVELOPE); }\n"
        self.write_text("crates/sample/src/loader_tests.rs", call)
        self.write_text("crates/sample/src/elsewhere/probe.rs", call)
        self.assert_loader_refused()

    def test_a_loader_call_after_a_test_module_still_counts(self) -> None:
        self.write_text(
            "crates/sample/src/lib.rs",
            self.without_loader()
            + "\npub fn late() { let _ = RuntimeConfigLoader::new(ENVELOPE); }\n",
        )
        self.assertEqual([], self.problems())

    def test_a_product_still_calling_the_legacy_expansion_is_refused(self) -> None:
        self.write_text(
            "crates/sample/src/legacy.rs",
            "fn read() { registry_platform_config::expand_config_env_vars(text) }\n",
        )
        self.assert_one_problem(
            "sample: crates/sample/src/legacy.rs calls expand_config_env_vars"
        )

    def test_a_missing_reference_refusal_test_is_refused(self) -> None:
        self.write_text(
            "crates/sample/src/lib.rs",
            LOADER_SOURCE.replace("a_reference_refuses_substitution", "renamed"),
        )
        self.assert_one_problem(
            "sample: crates/sample/src/lib.rs has no test named "
            "a_reference_refuses_substitution (a *Ref field must refuse ${VAR})"
        )

    def test_a_refusal_function_that_is_not_a_test_is_refused(self) -> None:
        self.write_text(
            "crates/sample/src/lib.rs",
            LOADER_SOURCE.replace(
                "#[test]\n    #[should_panic]\n    fn an_authored",
                "fn an_authored",
            ),
        )
        self.assert_one_problem(
            "has no test named an_authored_file_refuses_substitution "
            "(an authored project file must refuse ${VAR})"
        )

    def test_a_missing_test_file_is_refused(self) -> None:
        self.assert_one_problem(
            "sample: test file crates/sample/src/missing.rs is missing",
            row(
                reference_refusal=gate.TestRef(
                    "crates/sample/src/missing.rs", "a_reference_refuses_substitution"
                )
            ),
        )

    def test_an_exemption_needs_a_reason(self) -> None:
        self.assert_one_problem(
            "sample: the authored_refusal exemption needs a reason",
            row(authored_refusal=gate.Exemption("")),
        )

    def test_an_exempt_schema_declares_no_shared_blocks(self) -> None:
        self.assert_one_problem(
            "sample: a product without a runtime schema declares no shared blocks",
            row(runtime_schema=gate.Exemption("no generated runtime schema")),
        )

    def test_exemptions_with_reasons_pass(self) -> None:
        self.assertEqual(
            [],
            self.problems(
                row(
                    runtime_schema=gate.Exemption("no generated runtime schema"),
                    shared_blocks=(),
                    reference_refusal=gate.Exemption("no *Ref field"),
                    authored_refusal=gate.Exemption("no authored project file"),
                )
            ),
        )

    def block_row(self, *blocks: object) -> object:
        return row(
            rust_blocks=blocks
            or (
                gate.RustBlock(
                    "crates/sample/src/lib.rs", "SampleRuntime", "package", "PackageConfig"
                ),
            )
        )

    def with_runtime_struct(self, declaration: str, imports: str = "PackageConfig") -> None:
        self.write_text(
            "crates/sample/src/lib.rs",
            f"use registry_platform_config::{{{imports}, RuntimeConfigLoader}};\n"
            + declaration
            + LOADER_SOURCE.replace(
                "use registry_platform_config::RuntimeConfigLoader;\n", ""
            ),
        )

    RUNTIME_STRUCT = """
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SampleRuntime {
    pub listener: ListenerRuntime,
    /// The sealed package.
    pub package: PackageConfig,
    #[serde(default)]
    pub limits: Limits,
}
"""

    def test_a_runtime_struct_holding_the_shared_type_passes(self) -> None:
        self.with_runtime_struct(self.RUNTIME_STRUCT)
        self.assertEqual([], self.problems(self.block_row()))

    def test_a_runtime_field_of_another_type_is_refused(self) -> None:
        self.with_runtime_struct(
            self.RUNTIME_STRUCT.replace(
                "pub package: PackageConfig", "pub package: PackageRuntime"
            )
        )
        self.assert_one_problem(
            "sample: crates/sample/src/lib.rs SampleRuntime.package is not typed "
            "PackageConfig",
            self.block_row(),
        )

    def test_a_local_copy_of_a_shared_type_is_refused(self) -> None:
        self.with_runtime_struct(
            self.RUNTIME_STRUCT + "pub struct PackageConfig { pub root: String }\n",
            imports="ListenerBind",
        )
        problems = self.problems(self.block_row())
        self.assertIn(
            "sample: crates/sample/src/lib.rs declares its own PackageConfig "
            "instead of using the shared block",
            problems,
        )
        self.assertIn(
            "sample: crates/sample/src/lib.rs does not import PackageConfig from "
            "registry_platform_config",
            problems,
        )

    def test_a_shared_type_named_by_its_full_path_passes(self) -> None:
        self.with_runtime_struct(
            self.RUNTIME_STRUCT.replace(
                "pub package: PackageConfig",
                "pub package: registry_platform_config::PackageConfig",
            ),
            imports="ListenerBind",
        )
        self.assertEqual([], self.problems(self.block_row()))

    def test_a_missing_runtime_struct_is_refused(self) -> None:
        self.assert_one_problem(
            "sample: crates/sample/src/lib.rs has no struct SampleRuntime",
            self.block_row(),
        )

    def test_a_runtime_struct_inside_a_test_module_does_not_count(self) -> None:
        self.with_runtime_struct(
            "#[cfg(test)]\nmod fixtures {\n" + self.RUNTIME_STRUCT + "}\n"
        )
        self.assert_one_problem(
            "sample: crates/sample/src/lib.rs has no struct SampleRuntime",
            self.block_row(),
        )

    def test_a_rust_block_the_platform_does_not_publish_is_refused(self) -> None:
        self.with_runtime_struct(
            self.RUNTIME_STRUCT.replace("PackageConfig", "AuditConfig"),
            imports="AuditConfig",
        )
        self.assert_one_problem(
            "sample: shared block AuditConfig is not in "
            "products/platform/generated/runtime-config-blocks.schema.json",
            self.block_row(
                gate.RustBlock(
                    "crates/sample/src/lib.rs", "SampleRuntime", "package", "AuditConfig"
                )
            ),
        )

    HAND_LISTENER = {
        "type": "object",
        "required": ["bind"],
        "properties": {
            "bind": {
                "type": "string",
                "maxLength": 64,
                "description": "A socket address literal.",
                "allOf": [{"pattern": ":[0-9]+$"}],
            }
        },
    }

    def hand_row(self) -> object:
        return row(
            hand_schemas=(
                gate.HandSchema(
                    "crates/sample/hand.schema.json",
                    ("properties", "listener"),
                    "ListenerConfig",
                ),
            )
        )

    def write_hand_schema(self, listener: object) -> None:
        self.write_json(
            "crates/sample/hand.schema.json",
            {"type": "object", "properties": {"listener": listener}},
        )

    def test_a_hand_written_block_that_only_narrows_passes(self) -> None:
        self.write_hand_schema(self.HAND_LISTENER)
        self.assertEqual([], self.problems(self.hand_row()))

    def assert_hand_drift(self, listener: object, detail: str) -> None:
        self.write_hand_schema(listener)
        self.assert_one_problem(
            "sample: crates/sample/hand.schema.json at /properties/listener does "
            f"not match shared block ListenerConfig: {detail}",
            self.hand_row(),
        )

    def test_a_hand_written_block_with_a_changed_bound_is_refused(self) -> None:
        listener = json.loads(json.dumps(self.HAND_LISTENER))
        listener["properties"]["bind"]["maxLength"] = 4096
        self.assert_hand_drift(listener, "maxLength differs at /properties/bind")

    def test_a_hand_written_block_with_an_extra_member_is_refused(self) -> None:
        listener = json.loads(json.dumps(self.HAND_LISTENER))
        listener["properties"]["port"] = {"type": "integer"}
        self.assert_hand_drift(listener, "properties differ at /")

    def test_a_hand_written_block_that_drops_a_requirement_is_refused(self) -> None:
        listener = json.loads(json.dumps(self.HAND_LISTENER))
        listener["required"] = []
        self.assert_hand_drift(listener, "required differs at /")

    def test_a_hand_written_block_that_widens_is_refused(self) -> None:
        listener = json.loads(json.dumps(self.HAND_LISTENER))
        listener["properties"]["bind"]["anyOf"] = [{"type": "integer"}]
        self.assert_hand_drift(
            listener, "anyOf is not a narrowing keyword at /properties/bind"
        )

    def test_a_missing_hand_written_block_is_refused(self) -> None:
        self.write_json("crates/sample/hand.schema.json", {"type": "object"})
        self.assert_one_problem(
            "sample: crates/sample/hand.schema.json has no schema at "
            "/properties/listener",
            self.hand_row(),
        )

    def test_a_missing_canonical_schema_is_refused(self) -> None:
        (self.root / gate.CANONICAL_SCHEMA).unlink()
        problems = self.problems()
        self.assertEqual(
            [f"{gate.CANONICAL_SCHEMA} is missing; run {gate.GENERATOR_COMMAND}"],
            problems,
        )

    def fake_generator(self, rendered: str | None):
        def generate(output: Path) -> None:
            if rendered is None:
                raise gate.GeneratorFailed("generator exited with status 101")
            (output / Path(gate.CANONICAL_SCHEMA).name).write_text(
                rendered, encoding="utf-8"
            )

        return generate

    def test_a_fresh_canonical_schema_passes(self) -> None:
        committed = (self.root / gate.CANONICAL_SCHEMA).read_text(encoding="utf-8")
        self.assertEqual(
            [],
            gate.check_canonical_freshness(self.root, self.fake_generator(committed)),
        )

    def test_a_stale_canonical_schema_is_refused(self) -> None:
        self.assertEqual(
            [
                f"{gate.CANONICAL_SCHEMA} differs from its generator; run "
                f"{gate.GENERATOR_COMMAND}"
            ],
            gate.check_canonical_freshness(self.root, self.fake_generator("{}\n")),
        )

    def test_a_failing_generator_is_refused(self) -> None:
        self.assertEqual(
            [
                f"{gate.CANONICAL_SCHEMA} could not be regenerated: generator "
                "exited with status 101"
            ],
            gate.check_canonical_freshness(self.root, self.fake_generator(None)),
        )

    def test_main_reports_problems_and_fails(self) -> None:
        self.edit_runtime_schema(lambda defs: defs.pop("ListenerConfig"))
        completed = subprocess.run(
            (sys.executable, str(SCRIPT), "--root", str(self.root)),
            check=False,
            capture_output=True,
            text=True,
        )
        # The fixture root carries no product rows of its own, so every real
        # row reports its missing inputs; the exit status is what matters.
        self.assertEqual(1, completed.returncode)
        self.assertIn("runtime configuration conformance failed", completed.stderr)


class ConfigConformanceRepositoryTest(unittest.TestCase):
    def test_the_repository_conforms(self) -> None:
        self.assertEqual([], gate.check(ROOT, gate.ROWS))

    def test_every_row_names_a_distinct_product(self) -> None:
        products = [entry.product for entry in gate.ROWS]
        self.assertEqual(len(products), len(set(products)))


if __name__ == "__main__":
    unittest.main()
