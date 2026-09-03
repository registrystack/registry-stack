#!/usr/bin/env python3

from __future__ import annotations

import copy
import importlib.util
import os
import subprocess
import sys
import tomllib
import unittest
from pathlib import Path
from unittest import mock


sys.dont_write_bytecode = True
SCRIPT_PATH = Path(__file__).with_name("validate_product.py")
SPEC = importlib.util.spec_from_file_location("registry_server_validate_product", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VALIDATOR
SPEC.loader.exec_module(VALIDATOR)


class RegistryServerProductCatalogTests(unittest.TestCase):
    def test_tracked_product_catalog_is_internally_complete(self) -> None:
        self.assertEqual([], VALIDATOR.validate_all())

    def test_rls_assurance_and_operator_credential_posture_are_exact(self) -> None:
        decisions = (VALIDATOR.PRODUCT_ROOT / "DECISIONS.md").read_text(encoding="utf-8")
        assurance = (
            "Generated RLS policies defend against application mistakes and pooled-context\n"
            "  leakage. They do not constrain a party holding the runtime database\n"
            "  credential, which can set the same custom transaction context; credential\n"
            "  posture and rotation remain operator controls."
        )
        self.assertIn(assurance, decisions)
        self.assertNotIn("RLS protects the runtime database credential", decisions)
        self.assertNotIn("Registry Server rotates the runtime database credential", decisions)

    def test_every_pre_w5_security_invariant_is_enforced_with_an_executable_negative(self) -> None:
        matrix = VALIDATOR.load_yaml(
            VALIDATOR.CONTRACTS / "security-invariant-matrix.yaml"
        )
        pre_w5 = [
            invariant
            for invariant in matrix["invariants"]
            if invariant["targetWave"] != "W5"
        ]
        self.assertTrue(pre_w5)
        for invariant in pre_w5:
            with self.subTest(invariant=invariant["id"]):
                self.assertEqual("enforced", invariant["state"])
                self.assertIn("negativeTest", invariant)
                self.assertIn("path", invariant["negativeTest"])
                self.assertIn("name", invariant["negativeTest"])

    def test_security_range_is_closed_through_rhai_planner_invariants(self) -> None:
        matrix = VALIDATOR.load_yaml(
            VALIDATOR.CONTRACTS / "security-invariant-matrix.yaml"
        )
        self.assertEqual(
            list(VALIDATOR.SECURITY_INVARIANT_IDS),
            [invariant["id"] for invariant in matrix["invariants"]],
        )
        planner_rows = matrix["invariants"][-7:]
        self.assertEqual(
            [f"RS-NEG-{index:02d}" for index in range(25, 32)],
            [invariant["negativeId"] for invariant in planner_rows],
        )
        for invariant in planner_rows:
            with self.subTest(invariant=invariant["id"]):
                self.assertEqual("enforced", invariant["state"])
                self.assertTrue(invariant["threat"])
                self.assertTrue(invariant["enforcementPoint"])
                self.assertTrue(invariant["refusal"])
                self.assertIn("negativeTest", invariant)

    def test_w0_crate_boundary_is_three_crates_with_opt_in_runtime(self) -> None:
        root = tomllib.loads((VALIDATOR.REPOSITORY_ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        members = root["workspace"]["members"]
        self.assertEqual(
            [
                "crates/registry-server-client",
                "crates/registry-server",
                "crates/registry-serverctl",
            ],
            [member for member in members if member.startswith("crates/registry-server")],
        )

        server = tomllib.loads(
            (VALIDATOR.REPOSITORY_ROOT / "crates/registry-server/Cargo.toml").read_text(encoding="utf-8")
        )
        self.assertEqual([], server["features"]["default"])
        self.assertEqual(
            {
                "dep:axum",
                "dep:base64",
                "dep:clap",
                "dep:chacha20poly1305",
                "dep:deadpool-postgres",
                "dep:getrandom",
                "dep:hex",
                "dep:hmac",
                "dep:ipnet",
                "dep:jsonwebtoken",
                "dep:registry-platform-audit",
                "dep:registry-platform-authcommon",
                "dep:registry-platform-buildinfo",
                "dep:registry-platform-config",
                "dep:registry-platform-crypto",
                "dep:registry-platform-httpsec",
                "dep:registry-platform-httputil",
                "dep:registry-platform-oidc",
                "dep:rustls",
                "dep:rustix",
                "dep:tokio",
                "dep:tokio-postgres",
                "dep:tokio-postgres-rustls",
                "dep:tracing",
                "dep:tracing-subscriber",
                "dep:zeroize",
            },
            set(server["features"]["runtime"]),
        )
        self.assertEqual(["runtime"], server["bin"][0]["required-features"])
        for dependency in (
            "axum",
            "base64",
            "chacha20poly1305",
            "clap",
            "deadpool-postgres",
            "getrandom",
            "hex",
            "hmac",
            "ipnet",
            "jsonwebtoken",
            "registry-platform-audit",
            "registry-platform-authcommon",
            "registry-platform-buildinfo",
            "registry-platform-config",
            "registry-platform-crypto",
            "registry-platform-httpsec",
            "registry-platform-httputil",
            "registry-platform-oidc",
            "rustls",
            "rustix",
            "tokio",
            "tokio-postgres",
            "tokio-postgres-rustls",
            "tracing",
            "tracing-subscriber",
            "zeroize",
        ):
            self.assertTrue(server["dependencies"][dependency]["optional"])

        ctl = tomllib.loads(
            (VALIDATOR.REPOSITORY_ROOT / "crates/registry-serverctl/Cargo.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(
            ["runtime", "tooling"],
            ctl["dependencies"]["registry-server"]["features"],
        )

    def test_postgres_entrypoint_refuses_to_silently_skip_without_database_url(self) -> None:
        script = VALIDATOR.POSTGRES_ENTRYPOINT
        self.assertTrue(os.access(script, os.X_OK))
        environment = os.environ.copy()
        environment.pop("REGISTRY_SERVER_TEST_DATABASE_URL", None)
        result = subprocess.run(
            [str(script)],
            cwd=VALIDATOR.REPOSITORY_ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(2, result.returncode)
        self.assertIn("REGISTRY_SERVER_TEST_DATABASE_URL must be set", result.stderr)
        self.assertNotIn("cargo test", result.stdout + result.stderr)

    def test_postgres_entrypoint_keeps_its_exact_owned_command(self) -> None:
        errors: list[str] = []
        VALIDATOR.validate_postgres_entrypoint(errors)
        self.assertEqual([], errors)

    def test_postgres_rhai_planner_follows_the_existing_pilot_acceptance_gate(self) -> None:
        commands = list(VALIDATOR.POSTGRES_TEST_COMMANDS)
        pilot = (
            "cargo test --locked -p registry-server --features postgres-test "
            "--test postgres_pilot_acceptance"
        )
        rhai = (
            "cargo test --locked -p registry-server --features postgres-test "
            "--test postgres_rhai_planner"
        )
        self.assertEqual(commands.index(pilot) + 1, commands.index(rhai))

    def test_postgres_constraint_races_follow_partial_unique_in_the_owned_gate(self) -> None:
        commands = list(VALIDATOR.POSTGRES_TEST_COMMANDS)
        partial_unique = (
            "cargo test --locked -p registry-server --features postgres-test "
            "--test postgres_partial_unique"
        )
        constraint_races = (
            "cargo test --locked -p registry-server --features postgres-test "
            "--test postgres_constraint_races"
        )
        self.assertEqual(
            commands.index(partial_unique) + 1,
            commands.index(constraint_races),
        )

    def test_postgres_migration_requires_tooling_and_follows_package_in_the_owned_gate(self) -> None:
        commands = list(VALIDATOR.POSTGRES_TEST_COMMANDS)
        package = "cargo test --locked -p registry-server --features postgres-test,tooling --test postgres_package"
        migration = (
            "cargo test --locked -p registry-server --features postgres-test,tooling "
            "--test postgres_migration"
        )
        self.assertEqual(commands.index(package) + 1, commands.index(migration))

    def test_postgres_webhook_outbox_follows_mutation_in_the_owned_gate(self) -> None:
        commands = list(VALIDATOR.POSTGRES_TEST_COMMANDS)
        immediate_activation = (
            "cargo test --locked -p registry-server --features postgres-test,tooling "
            "--test postgres_immediate_action_activation"
        )
        webhook_outbox = (
            "cargo test --locked -p registry-server --features postgres-test "
            "--test postgres_webhook_outbox"
        )
        self.assertEqual(commands.index(immediate_activation) + 1, commands.index(webhook_outbox))

    def test_postgres_immediate_action_examples_are_registered_after_core_action_gate(self) -> None:
        commands = list(VALIDATOR.POSTGRES_TEST_COMMANDS)
        mutation = "cargo test --locked -p registry-server --features postgres-test --test postgres_mutation"
        mutation_logical_names = (
            "cargo test --locked -p registry-server --features postgres-test "
            "--test postgres_mutation_logical_names"
        )
        immediate_actions = (
            "cargo test --locked -p registry-server --features postgres-test "
            "--test postgres_immediate_actions"
        )
        immediate_examples = (
            "cargo test --locked -p registry-server --features postgres-test,tooling "
            "--test postgres_immediate_action_examples"
        )
        immediate_activation = (
            "cargo test --locked -p registry-server --features postgres-test,tooling "
            "--test postgres_immediate_action_activation"
        )
        webhook_outbox = (
            "cargo test --locked -p registry-server --features postgres-test "
            "--test postgres_webhook_outbox"
        )
        self.assertEqual(commands.index(mutation) + 1, commands.index(mutation_logical_names))
        self.assertEqual(commands.index(mutation_logical_names) + 1, commands.index(immediate_actions))
        self.assertEqual(commands.index(immediate_actions) + 1, commands.index(immediate_examples))
        self.assertEqual(commands.index(immediate_examples) + 1, commands.index(immediate_activation))
        self.assertEqual(commands.index(immediate_activation) + 1, commands.index(webhook_outbox))

    def test_postgres_webhook_delivery_follows_atomic_capture_in_the_owned_gate(self) -> None:
        commands = list(VALIDATOR.POSTGRES_TEST_COMMANDS)
        webhook_outbox = (
            "cargo test --locked -p registry-server --features postgres-test "
            "--test postgres_webhook_outbox"
        )
        webhook_delivery = (
            "cargo test --locked -p registry-server --features postgres-test "
            "--test postgres_webhook_delivery"
        )
        self.assertEqual(commands.index(webhook_outbox) + 1, commands.index(webhook_delivery))

    def test_postgres_data_journeys_follow_batch_in_the_owned_gate(self) -> None:
        commands = list(VALIDATOR.POSTGRES_TEST_COMMANDS)
        batch = "cargo test --locked -p registry-server --features postgres-test --test postgres_batch"
        facility = (
            "cargo test --locked -p registry-server --features postgres-test "
            "--test postgres_data_facility"
        )
        export = (
            "cargo test --locked -p registry-server --features postgres-test "
            "--test postgres_data_export"
        )
        self.assertEqual(commands.index(batch) + 1, commands.index(facility))
        self.assertEqual(commands.index(facility) + 1, commands.index(export))

    def test_postgres_tls_entrypoint_refuses_to_silently_skip_without_container_id(self) -> None:
        script = VALIDATOR.POSTGRES_TLS_ENTRYPOINT
        self.assertTrue(os.access(script, os.X_OK))
        environment = os.environ.copy()
        environment.pop("REGISTRY_SERVER_TEST_TLS_POSTGRES_CONTAINER_ID", None)
        result = subprocess.run(
            [str(script)],
            cwd=VALIDATOR.REPOSITORY_ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(2, result.returncode)
        self.assertIn("REGISTRY_SERVER_TEST_TLS_POSTGRES_CONTAINER_ID must be set", result.stderr)
        self.assertNotIn("docker", result.stdout + result.stderr)

    def test_postgres_tls_entrypoint_keeps_its_exact_owned_command_and_ci_invocation(self) -> None:
        errors: list[str] = []
        VALIDATOR.validate_postgres_tls_entrypoint(errors)
        self.assertEqual([], errors)

    def test_planned_invariant_cannot_claim_an_executable_test(self) -> None:
        original = VALIDATOR.load_yaml

        def load_with_test(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "security-invariant-matrix.yaml":
                row = value["invariants"][0]
                row["state"] = "planned"
            return value

        errors: list[str] = []
        with mock.patch.object(VALIDATOR, "load_yaml", side_effect=load_with_test):
            VALIDATOR.validate_security({"W0", "W1", "W2", "W3", "W4", "W5"}, errors)
        self.assertTrue(any("unknown keys negativeTest" in error for error in errors), errors)

    def test_planned_invariant_requires_real_refusal(self) -> None:
        original = VALIDATOR.load_yaml

        def load_without_refusal(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "security-invariant-matrix.yaml":
                value["invariants"][0].pop("refusal")
            return value

        errors: list[str] = []
        with mock.patch.object(VALIDATOR, "load_yaml", side_effect=load_without_refusal):
            VALIDATOR.validate_security({"W0", "W1", "W2", "W3", "W4", "W5"}, errors)
        self.assertTrue(any("missing keys refusal" in error for error in errors), errors)

    def test_duplicate_security_identifier_is_rejected(self) -> None:
        original = VALIDATOR.load_yaml

        def load_with_duplicate(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "security-invariant-matrix.yaml":
                value["invariants"][1]["id"] = "RS-SEC-01"
            return value

        errors: list[str] = []
        with mock.patch.object(VALIDATOR, "load_yaml", side_effect=load_with_duplicate):
            VALIDATOR.validate_security({"W0", "W1", "W2", "W3", "W4", "W5"}, errors)
        self.assertTrue(any("duplicate identifier" in error for error in errors), errors)

    def test_closed_security_range_rejects_a_missing_rhai_invariant(self) -> None:
        original = VALIDATOR.load_yaml

        def load_without_final_invariant(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "security-invariant-matrix.yaml":
                value["invariants"] = value["invariants"][:-1]
            elif path.name == "security-test-traceability.yaml":
                value["traceability"] = value["traceability"][:-1]
            return value

        errors: list[str] = []
        with mock.patch.object(VALIDATOR, "load_yaml", side_effect=load_without_final_invariant):
            VALIDATOR.validate_security({"W0", "W1", "W2", "W3", "W4", "W5"}, errors)
        self.assertIn(
            "security matrix: must contain the complete closed product invariant identifiers",
            errors,
        )

    def test_enforced_invariant_must_bind_one_resolving_test(self) -> None:
        original = VALIDATOR.load_yaml

        def load_enforced_without_test(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "security-invariant-matrix.yaml":
                row = next(row for row in value["invariants"] if row["state"] == "enforced")
                row.pop("negativeTest")
            return value

        errors: list[str] = []
        with mock.patch.object(VALIDATOR, "load_yaml", side_effect=load_enforced_without_test):
            VALIDATOR.validate_security({"W0", "W1", "W2", "W3", "W4", "W5"}, errors)
        self.assertTrue(any("missing keys negativeTest" in error for error in errors), errors)

    def test_helper_named_like_a_test_is_not_an_executable_test(self) -> None:
        def test_nested_helper() -> None:
            return None

        errors: list[str] = []
        VALIDATOR.executable_test_resolves(
            {
                "path": "products/registry-server/scripts/test_validate_product.py",
                "name": "test_nested_helper",
            },
            "negative test",
            errors,
        )
        self.assertTrue(any("does not resolve" in error for error in errors), errors)

    def test_unresolved_acceptance_reference_is_rejected(self) -> None:
        original = VALIDATOR.load_yaml

        def load_unknown_journey(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "definition-of-done.yaml":
                value["requirements"][0]["journeys"] = ["RS-J99"]
            return value

        with mock.patch.object(VALIDATOR, "load_yaml", side_effect=load_unknown_journey):
            errors = VALIDATOR.validate_all()
        self.assertTrue(any("references unknown journey" in error for error in errors), errors)

    def test_definition_of_done_cannot_omit_a_v1_requirement(self) -> None:
        original = VALIDATOR.load_yaml

        def load_without_requirement(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "definition-of-done.yaml":
                value["requirements"] = [
                    row for row in value["requirements"] if row["id"] != "RS-V1-44"
                ]
            return value

        errors: list[str] = []
        with mock.patch.object(VALIDATOR, "load_yaml", side_effect=load_without_requirement):
            VALIDATOR.validate_definition_of_done({f"W{index}" for index in range(6)}, errors)
        self.assertIn(
            "definition of done: must contain RS-V1-01 through RS-V1-44 exactly once in order",
            errors,
        )

    def test_definition_of_done_rejects_a_duplicate_v1_requirement(self) -> None:
        original = VALIDATOR.load_yaml

        def load_with_duplicate_requirement(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "definition-of-done.yaml":
                row = next(row for row in value["requirements"] if row["id"] == "RS-V1-01")
                index = value["requirements"].index(row)
                value["requirements"].insert(index + 1, copy.deepcopy(row))
            return value

        errors: list[str] = []
        with mock.patch.object(VALIDATOR, "load_yaml", side_effect=load_with_duplicate_requirement):
            VALIDATOR.validate_definition_of_done({f"W{index}" for index in range(6)}, errors)
        self.assertTrue(any("duplicate identifier RS-V1-01" in error for error in errors), errors)

    def test_definition_of_done_rejects_a_nonexistent_evidence_test(self) -> None:
        original = VALIDATOR.load_yaml

        def load_with_nonexistent_test(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "definition-of-done.yaml":
                row = next(row for row in value["requirements"] if row["id"] == "RS-V1-01")
                row["evidence"][0]["name"] = "test_that_does_not_exist"
            return value

        errors: list[str] = []
        with mock.patch.object(VALIDATOR, "load_yaml", side_effect=load_with_nonexistent_test):
            VALIDATOR.validate_definition_of_done({f"W{index}" for index in range(6)}, errors)
        self.assertTrue(any("exact executable test does not resolve" in error for error in errors), errors)

    def test_enforced_requirement_cannot_retain_a_partial_gap(self) -> None:
        original = VALIDATOR.load_yaml

        def load_with_stale_gap(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "definition-of-done.yaml":
                row = next(row for row in value["requirements"] if row["state"] == "enforced")
                row["gap"] = "stale gap"
            return value

        errors: list[str] = []
        with mock.patch.object(VALIDATOR, "load_yaml", side_effect=load_with_stale_gap):
            VALIDATOR.validate_definition_of_done({f"W{index}" for index in range(6)}, errors)
        self.assertTrue(any("unknown keys gap" in error for error in errors), errors)

    def test_acceptance_matrix_cannot_omit_a_required_journey(self) -> None:
        original = VALIDATOR.load_yaml

        def load_without_journey(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "acceptance-scenario-matrix.yaml":
                value["scenarios"].pop()
            return value

        errors: list[str] = []
        with mock.patch.object(VALIDATOR, "load_yaml", side_effect=load_without_journey):
            VALIDATOR.validate_acceptance(errors)
        self.assertIn(
            "acceptance matrix: must contain RS-J01 through RS-J19 exactly once in order",
            errors,
        )

    def test_contract_state_vocabulary_is_closed(self) -> None:
        original = VALIDATOR.load_yaml

        def load_with_unknown_state(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "acceptance-scenario-matrix.yaml":
                value["scenarios"][0]["state"] = "complete"
            return value

        errors: list[str] = []
        with mock.patch.object(VALIDATOR, "load_yaml", side_effect=load_with_unknown_state):
            VALIDATOR.validate_acceptance(errors)
        self.assertTrue(any("expected enforced, partial, or planned" in error for error in errors), errors)

    def test_shell_evidence_name_must_match_the_executable_filename(self) -> None:
        errors: list[str] = []
        VALIDATOR.executable_test_resolves(
            {
                "path": "products/registry-server/scripts/check-source-neutrality.sh",
                "name": "different-script.sh",
            },
            "shell evidence",
            errors,
        )
        self.assertTrue(any("exact executable test does not resolve" in error for error in errors), errors)

    def test_schedule_exit_criterion_must_resolve(self) -> None:
        original = VALIDATOR.load_yaml

        def load_unknown_criterion(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "implementation-schedule.yaml":
                value["waves"][0]["exitCriteria"] = ["RS-NOT-DECLARED"]
            return value

        with mock.patch.object(VALIDATOR, "load_yaml", side_effect=load_unknown_criterion):
            errors = VALIDATOR.validate_all()
        self.assertTrue(any("exit criterion does not resolve" in error for error in errors), errors)

    def test_asset_fixture_cannot_gain_a_business_entity(self) -> None:
        original = VALIDATOR.load_yaml

        def load_with_hardcoding(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "registry.yaml" and path.parent.name == "asset-site-placement":
                value["entities"].append({"id": "business", "route": "businesses"})
            return value

        errors: list[str] = []
        with mock.patch.object(VALIDATOR, "load_yaml", side_effect=load_with_hardcoding):
            VALIDATOR.validate_fixture(errors)
        self.assertTrue(any("complete non-person entity set" in error for error in errors), errors)

    def test_asset_fixture_package_has_only_the_production_identity_keys(self) -> None:
        original = VALIDATOR.load_yaml

        def load_with_unknown_package_key(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "registry.yaml" and path.parent.name == "asset-site-placement":
                value["package"]["repairMissingIdentity"] = True
            return value

        errors: list[str] = []
        with mock.patch.object(VALIDATOR, "load_yaml", side_effect=load_with_unknown_package_key):
            VALIDATOR.validate_fixture(errors)
        self.assertTrue(
            any("asset fixture.package: unknown keys repairMissingIdentity" in error for error in errors),
            errors,
        )

    def test_asset_fixture_package_identity_and_sequence_are_exact(self) -> None:
        original = VALIDATOR.load_yaml

        def load_with_implicit_sequence(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "registry.yaml" and path.parent.name == "asset-site-placement":
                value["package"]["sequence"] = True
            return value

        errors: list[str] = []
        with mock.patch.object(VALIDATOR, "load_yaml", side_effect=load_with_implicit_sequence):
            VALIDATOR.validate_fixture(errors)
        self.assertIn("asset fixture.package.sequence: expected integer", errors)

    def test_package_layout_cannot_drop_a_required_entry(self) -> None:
        original = VALIDATOR.load_yaml

        def load_without_entry(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "package-layout.yaml":
                value["entries"].pop()
            return value

        errors: list[str] = []
        with mock.patch.object(VALIDATOR, "load_yaml", side_effect=load_without_entry):
            VALIDATOR.validate_package_layout(errors)
        self.assertTrue(any("missing required entry tuples" in error for error in errors), errors)

    def test_package_layout_binds_fixture_journeys_as_required_reviewed_source(self) -> None:
        original = VALIDATOR.load_yaml

        def load_with_wrong_fixture_role(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "package-layout.yaml":
                for entry in value["entries"]:
                    if entry["path"] == "tests/journeys.yaml":
                        entry["role"] = "generated-test-receipt"
            return value

        errors: list[str] = []
        with mock.patch.object(VALIDATOR, "load_yaml", side_effect=load_with_wrong_fixture_role):
            VALIDATOR.validate_package_layout(errors)
        self.assertTrue(any("missing required entry tuples" in error for error in errors), errors)
        self.assertTrue(any("unexpected entry tuples" in error for error in errors), errors)

    def test_package_layout_binds_action_inventory_and_schemas_as_optional_generated_outputs(self) -> None:
        original = VALIDATOR.load_yaml

        def load_without_action_entries(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "package-layout.yaml":
                value["entries"] = [
                    entry
                    for entry in value["entries"]
                    if entry["path"] not in {"inventories/actions.json", "action-schemas"}
                ]
            return value

        errors: list[str] = []
        with mock.patch.object(VALIDATOR, "load_yaml", side_effect=load_without_action_entries):
            VALIDATOR.validate_package_layout(errors)
        self.assertTrue(any("missing required entry tuples" in error for error in errors), errors)

    def test_package_layout_cannot_allow_embedded_signing_key(self) -> None:
        original = VALIDATOR.load_yaml

        def load_without_signing_key(path: Path):
            value = copy.deepcopy(original(path))
            if path.name == "package-layout.yaml":
                value["forbiddenEmbeddedRoles"].remove("signing-key")
            return value

        errors: list[str] = []
        with mock.patch.object(VALIDATOR, "load_yaml", side_effect=load_without_signing_key):
            VALIDATOR.validate_package_layout(errors)
        self.assertTrue(any("complete forbidden role set" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
