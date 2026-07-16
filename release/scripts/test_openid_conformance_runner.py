#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tempfile
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch


SCRIPT_DIR = Path(__file__).resolve().parent
RUNNER_PATH = SCRIPT_DIR / "openid-conformance-runner.py"


def load_runner():
    spec = importlib.util.spec_from_file_location(
        "openid_conformance_runner", RUNNER_PATH
    )
    if not spec or not spec.loader:
        raise RuntimeError(f"could not load {RUNNER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class OpenIdConformanceRunnerTest(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = load_runner()
        cls.plan_map = cls.runner.load_plan_map()

    def test_plan_map_has_unique_scenarios_and_pinned_suite_ref(self) -> None:
        scenarios = self.plan_map["scenarios"]
        self.assertEqual(len(scenarios), len({scenario["id"] for scenario in scenarios}))
        suite = self.plan_map["suite"]
        self.assertEqual(40, len(suite["ref"]))
        self.assertEqual(
            "https://gitlab.com/openid/conformance-suite.git", suite["repo"]
        )
        self.assertEqual(
            "registry.release.openid_conformance_plan_map.v1",
            self.plan_map["schema_version"],
        )

    def test_release_defaults_do_not_reference_retired_lab_paths(self) -> None:
        self.assertEqual(
            self.runner.REPO_ROOT / "release" / "conformance" / "openid",
            self.runner.CONFIG_DIR,
        )
        self.assertTrue(
            self.runner.DEFAULT_OUTPUT_ROOT.is_relative_to(
                self.runner.REPO_ROOT / "target"
            )
        )
        serialized = json.dumps(self.plan_map)
        self.assertNotIn("REGISTRY_LAB_", serialized)
        self.assertNotIn("blocked-by-lab", serialized)

    def test_builder_override_pins_maven_image_by_digest(self) -> None:
        override = self.runner.BUILDER_COMPOSE_OVERRIDE_PATH.read_text(
            encoding="utf-8"
        )
        self.assertIn("maven:3-eclipse-temurin-21@sha256:", override)
        self.assertIn(
            str(self.runner.BUILDER_COMPOSE_OVERRIDE_PATH),
            self.runner.builder_command(Path("/suite"), "run", "builder"),
        )

    def test_runtime_override_pins_built_image_bases(self) -> None:
        override = self.runner.COMPOSE_OVERRIDE_PATH.read_text(encoding="utf-8")
        nginx = (self.runner.CONFIG_DIR / "nginx.Dockerfile").read_text(
            encoding="utf-8"
        )
        server = (self.runner.CONFIG_DIR / "server-dev.Dockerfile").read_text(
            encoding="utf-8"
        )
        self.assertIn("REGISTRY_OPENID_CONFORMANCE_CONFIG_DIR", override)
        self.assertIn("nginx:1.27.3@sha256:", nginx)
        self.assertIn("eclipse-temurin:21@sha256:", server)

    def test_metadata_scenario_cli_selects_single_oid4vci_module(self) -> None:
        scenario = self.runner.find_scenario(
            self.plan_map, "notary-oid4vci-issuer-metadata"
        )
        plan_arg = self.runner.scenario_plan_arg(scenario)
        self.assertTrue(plan_arg.startswith("oid4vci-1_0-issuer-test-plan["))
        self.assertIn("[client_auth_type=private_key_jwt]", plan_arg)
        self.assertIn("[sender_constrain=dpop]", plan_arg)
        self.assertIn("[fapi_profile=vci]", plan_arg)
        self.assertIn("[fapi_request_method=unsigned]", plan_arg)
        self.assertIn("[authorization_request_type=simple]", plan_arg)
        self.assertIn("[credential_format=sd_jwt_vc]", plan_arg)
        self.assertIn("[vci_credential_encryption=plain]", plan_arg)
        self.assertTrue(plan_arg.endswith(":oid4vci-1_0-issuer-metadata-test"))

    def test_rendered_config_is_valid_json_and_uses_supplied_issuer(self) -> None:
        scenario = self.runner.find_scenario(
            self.plan_map, "notary-oid4vci-issuer-metadata"
        )
        rendered = self.runner.render_config(
            scenario,
            {
                "issuer_url": "https://issuer.example.test",
                "authorization_server": "https://issuer.example.test/auth",
                "credential_configuration_id": "person_is_alive_sd_jwt",
                "static_tx_code": "1234",
                "client_id": "client-a",
                "client2_id": "client-b",
            },
        )
        config = json.loads(rendered)
        self.assertEqual(
            "registry-stack-notary-oid4vci-issuer", config["alias"]
        )
        self.assertEqual(
            "https://issuer.example.test", config["vci"]["credential_issuer_url"]
        )
        self.assertEqual(
            "person_is_alive_sd_jwt",
            config["vci"]["credential_configuration_id"],
        )
        self.assertEqual("client-a", config["client"]["client_id"])
        self.assertNotIn("${", rendered)

    def test_build_run_uses_export_dir_and_conformance_environment(self) -> None:
        scenario = self.runner.find_scenario(
            self.plan_map, "notary-oid4vci-issuer-metadata"
        )
        with tempfile.TemporaryDirectory() as tmp:
            args = self.runner.parse_args(
                [
                    "run",
                    "notary-oid4vci-issuer-metadata",
                    "--issuer-url",
                    "https://issuer.example.test",
                    "--output-dir",
                    tmp,
                    "--suite-dir",
                    str(Path(tmp) / "suite"),
                    "--no-prepare",
                    "--dry-run",
                ]
            )
            output_dir, env, command = self.runner.build_run(
                self.plan_map, scenario, args
            )
            self.assertEqual(Path(tmp).resolve(), output_dir)
            self.assertEqual(
                self.plan_map["suite"]["base_url"], env["CONFORMANCE_SERVER"]
            )
            self.assertEqual("1", env["CONFORMANCE_DEV_MODE"])
            self.assertIn("--export-dir", command)
            self.assertIn(str(output_dir), command)
            self.assertIn("oid4vci-1_0-issuer-metadata-test", " ".join(command))
            self.assertTrue(
                (output_dir / "notary-oid4vci-issuer-metadata.config.json").exists()
            )

    def test_suite_artifact_build_uses_docker_builder_and_maven_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checkout = Path(tmp) / "suite"
            jar = checkout / self.runner.SUITE_JAR
            jar.parent.mkdir(parents=True)
            args = self.runner.parse_args(
                [
                    "prepare",
                    "--suite-dir",
                    str(checkout),
                    "--maven-cache-dir",
                    str(Path(tmp) / "maven"),
                ]
            )
            calls = []

            def fake_run_checked(command, cwd=None, env=None):
                calls.append((command, cwd, env))
                jar.write_text("jar", encoding="utf-8")

            with patch.object(shutil, "which", return_value="/usr/bin/docker"):
                with patch.object(self.runner, "suite_checkout_ref", return_value="a" * 40):
                    with patch.object(
                        self.runner, "run_checked", side_effect=fake_run_checked
                    ):
                        self.runner.ensure_suite_artifact(checkout, args)

            self.assertEqual(
                self.runner.builder_command(checkout, "run", "--rm", "builder"),
                calls[0][0],
            )
            self.assertEqual(checkout, calls[0][1])
            self.assertEqual(
                str((Path(tmp) / "maven").resolve()), calls[0][2]["MAVEN_CACHE"]
            )
            stamp = json.loads(
                (checkout / self.runner.SUITE_JAR_STAMP).read_text(encoding="utf-8")
            )
            self.assertEqual("a" * 40, stamp["source_ref"])
            self.assertEqual(
                self.runner.file_sha256(jar), stamp["jar_sha256"]
            )
            self.assertEqual(
                self.runner.file_sha256(
                    self.runner.BUILDER_COMPOSE_OVERRIDE_PATH
                ),
                stamp["builder_override_sha256"],
            )

    def test_existing_suite_artifact_skips_build_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checkout = Path(tmp) / "suite"
            jar = checkout / self.runner.SUITE_JAR
            jar.parent.mkdir(parents=True)
            jar.write_text("jar", encoding="utf-8")
            stamp = checkout / self.runner.SUITE_JAR_STAMP
            with patch.object(self.runner, "suite_checkout_ref", return_value="a" * 40):
                stamp.write_text(
                    json.dumps(
                        self.runner.expected_suite_artifact_stamp(checkout, jar),
                        sort_keys=True,
                    )
                    + "\n",
                    encoding="utf-8",
                )
            args = self.runner.parse_args(["prepare", "--suite-dir", str(checkout)])

            with patch.object(self.runner, "suite_checkout_ref", return_value="a" * 40):
                with patch.object(self.runner, "run_checked") as run_checked:
                    self.runner.ensure_suite_artifact(checkout, args)

            run_checked.assert_not_called()

    def test_suite_artifact_rebuilds_when_checkout_ref_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checkout = Path(tmp) / "suite"
            jar = checkout / self.runner.SUITE_JAR
            jar.parent.mkdir(parents=True)
            jar.write_text("old", encoding="utf-8")
            stamp = checkout / self.runner.SUITE_JAR_STAMP
            with patch.object(self.runner, "suite_checkout_ref", return_value="a" * 40):
                stamp.write_text(
                    json.dumps(
                        self.runner.expected_suite_artifact_stamp(checkout, jar),
                        sort_keys=True,
                    )
                    + "\n",
                    encoding="utf-8",
                )
            args = self.runner.parse_args(["prepare", "--suite-dir", str(checkout)])

            def fake_run_checked(command, cwd=None, env=None):
                jar.write_text("new", encoding="utf-8")

            with patch.object(self.runner, "suite_checkout_ref", return_value="b" * 40):
                with patch.object(
                    self.runner, "run_checked", side_effect=fake_run_checked
                ) as run_checked:
                    self.runner.ensure_suite_artifact(checkout, args)

            run_checked.assert_called_once()
            self.assertEqual("new", jar.read_text(encoding="utf-8"))
            self.assertEqual(
                "b" * 40,
                json.loads(stamp.read_text(encoding="utf-8"))["source_ref"],
            )

    def test_suite_python_venv_installs_requirements_and_records_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checkout = Path(tmp) / "suite"
            requirements = checkout / "scripts" / "requirements.txt"
            requirements.parent.mkdir(parents=True)
            requirements.write_bytes(
                self.runner.SUITE_REQUIREMENTS_INPUT_PATH.read_bytes()
            )
            venv_dir = Path(tmp) / "venv"
            args = self.runner.parse_args(
                [
                    "prepare",
                    "--suite-dir",
                    str(checkout),
                    "--python-venv-dir",
                    str(venv_dir),
                ]
            )

            calls = []

            def fake_run_checked(command, cwd=None, env=None):
                calls.append(command)
                if command[1:3] == ["-m", "venv"]:
                    Path(command[-1]).mkdir(parents=True)

            with patch.object(
                self.runner, "run_checked", side_effect=fake_run_checked
            ):
                python = self.runner.ensure_suite_python(checkout, args)

            self.assertEqual(venv_dir.resolve(), python.parents[2])
            self.assertTrue(python.parent.parent.name.startswith("py"))
            self.assertEqual(
                [sys.executable, "-m", "venv", str(python.parents[1])], calls[0]
            )
            self.assertEqual(str(python), calls[1][0])
            self.assertIn("--require-hashes", calls[1])
            self.assertIn("--only-binary=:all:", calls[1])
            self.assertEqual("-r", calls[1][-2])
            self.assertEqual(
                str(self.runner.SUITE_REQUIREMENTS_LOCK_PATH), calls[1][-1]
            )
            self.assertEqual(
                self.runner.requirements_digest(
                    self.runner.SUITE_REQUIREMENTS_INPUT_PATH,
                    self.runner.SUITE_REQUIREMENTS_LOCK_PATH,
                ),
                (python.parents[1] / ".requirements.sha256")
                .read_text(encoding="utf-8")
                .strip(),
            )

    def test_suite_python_cache_key_changes_with_lock_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = self.runner.parse_args(
                ["prepare", "--python-venv-dir", str(Path(tmp) / "venvs")]
            )
            first = self.runner.suite_python(args)
            with patch.object(
                self.runner, "requirements_digest", return_value="b" * 64
            ):
                second = self.runner.suite_python(args)
            self.assertNotEqual(first, second)

    def test_suite_python_recreates_incomplete_digest_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checkout = Path(tmp) / "suite"
            requirements = checkout / "scripts" / "requirements.txt"
            requirements.parent.mkdir(parents=True)
            requirements.write_bytes(
                self.runner.SUITE_REQUIREMENTS_INPUT_PATH.read_bytes()
            )
            args = self.runner.parse_args(
                [
                    "prepare",
                    "--suite-dir",
                    str(checkout),
                    "--python-venv-dir",
                    str(Path(tmp) / "venvs"),
                ]
            )
            python = self.runner.suite_python(args)
            python.parent.mkdir(parents=True)
            python.touch()
            stale = python.parents[1] / "stale-package"
            stale.touch()

            def fake_run_checked(command, cwd=None, env=None):
                if command[1:3] == ["-m", "venv"]:
                    Path(command[-1]).mkdir(parents=True)

            with patch.object(
                self.runner, "run_checked", side_effect=fake_run_checked
            ):
                self.runner.ensure_suite_python(checkout, args)

            self.assertFalse(stale.exists())
            self.assertTrue(
                (python.parents[1] / ".requirements.sha256").is_file()
            )

    def test_suite_python_rejects_changed_upstream_requirements(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checkout = Path(tmp) / "suite"
            requirements = checkout / "scripts" / "requirements.txt"
            requirements.parent.mkdir(parents=True)
            requirements.write_text("httpx\npyparsing\nunreviewed\n", encoding="utf-8")
            args = self.runner.parse_args(
                ["prepare", "--suite-dir", str(checkout)]
            )

            with self.assertRaisesRegex(
                self.runner.RunnerError, "differ from the checked-in locked input"
            ):
                self.runner.ensure_suite_python(checkout, args)

    def test_blocked_full_scenario_requires_explicit_override(self) -> None:
        args = self.runner.parse_args(
            [
                "run",
                "notary-oid4vci-issuer-full",
                "--issuer-url",
                "https://issuer.example.test",
                "--no-prepare",
                "--dry-run",
            ]
        )
        with self.assertRaisesRegex(
            self.runner.RunnerError, "blocked-by-credential-offer-adapter"
        ):
            self.runner.cmd_run(args)


if __name__ == "__main__":
    main()
