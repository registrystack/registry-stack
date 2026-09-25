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
