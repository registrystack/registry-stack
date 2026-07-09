#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
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
    spec = importlib.util.spec_from_file_location("openid_conformance_runner", RUNNER_PATH)
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
        self.assertEqual("https://gitlab.com/openid/conformance-suite.git", suite["repo"])

    def test_metadata_scenario_cli_selects_single_oid4vci_module(self) -> None:
        scenario = self.runner.find_scenario(self.plan_map, "notary-oid4vci-issuer-metadata")
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
        scenario = self.runner.find_scenario(self.plan_map, "notary-oid4vci-issuer-metadata")
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
        self.assertEqual("https://issuer.example.test", config["vci"]["credential_issuer_url"])
        self.assertEqual("person_is_alive_sd_jwt", config["vci"]["credential_configuration_id"])
        self.assertEqual("client-a", config["client"]["client_id"])
        self.assertNotIn("${", rendered)

    def test_build_run_uses_export_dir_and_conformance_environment(self) -> None:
        scenario = self.runner.find_scenario(self.plan_map, "notary-oid4vci-issuer-metadata")
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
            output_dir, env, command = self.runner.build_run(self.plan_map, scenario, args)
            self.assertEqual(Path(tmp).resolve(), output_dir)
            self.assertEqual(self.plan_map["suite"]["base_url"], env["CONFORMANCE_SERVER"])
            self.assertEqual("1", env["CONFORMANCE_DEV_MODE"])
            self.assertIn("--export-dir", command)
            self.assertIn(str(output_dir), command)
            self.assertIn("oid4vci-1_0-issuer-metadata-test", " ".join(command))
            self.assertTrue((output_dir / "notary-oid4vci-issuer-metadata.config.json").exists())

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
                with patch.object(self.runner, "run_checked", side_effect=fake_run_checked):
                    self.runner.ensure_suite_artifact(checkout, args)

            self.assertEqual(
                self.runner.builder_command(checkout, "run", "--rm", "builder"),
                calls[0][0],
            )
            self.assertEqual(checkout, calls[0][1])
            self.assertEqual(str((Path(tmp) / "maven").resolve()), calls[0][2]["MAVEN_CACHE"])

    def test_existing_suite_artifact_skips_build_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checkout = Path(tmp) / "suite"
            jar = checkout / self.runner.SUITE_JAR
            jar.parent.mkdir(parents=True)
            jar.write_text("jar", encoding="utf-8")
            args = self.runner.parse_args(["prepare", "--suite-dir", str(checkout)])

            with patch.object(self.runner, "run_checked") as run_checked:
                self.runner.ensure_suite_artifact(checkout, args)

            run_checked.assert_not_called()

    def test_suite_python_venv_installs_requirements_and_records_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checkout = Path(tmp) / "suite"
            requirements = checkout / "scripts" / "requirements.txt"
            requirements.parent.mkdir(parents=True)
            requirements.write_text("httpx\npyparsing\n", encoding="utf-8")
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
                    venv_dir.mkdir(parents=True)

            with patch.object(self.runner, "run_checked", side_effect=fake_run_checked):
                python = self.runner.ensure_suite_python(checkout, args)

            self.assertEqual(venv_dir.resolve() / "bin" / "python", python)
            self.assertEqual([sys.executable, "-m", "venv", str(venv_dir.resolve())], calls[0])
            self.assertEqual(str(python), calls[1][0])
            self.assertEqual("-r", calls[1][-2])
            self.assertEqual(str(requirements), calls[1][-1])
            self.assertEqual(
                self.runner.requirements_digest(requirements),
                (venv_dir / ".requirements.sha256").read_text(encoding="utf-8").strip(),
            )

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
        scenario = self.runner.find_scenario(self.plan_map, args.scenario)
        self.assertNotEqual("applicable", scenario["status"])


if __name__ == "__main__":
    main()
