#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import re
import shlex
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import urllib.parse
import warnings
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import MagicMock, patch


SCRIPT_DIR = Path(__file__).resolve().parent
RUNNER_PATH = SCRIPT_DIR / "openid-conformance-runner.py"
NGINX_DOCKERFILE = SCRIPT_DIR.parent / "conformance" / "openid" / "nginx.Dockerfile"
TEST_RSA_N = int(
    "db2a64f46dd9923ff3b52759ded5af43f36ac62ed1c71e889156ea8359d894"
    "cb80734c311c42dfac407feb6c2cb34c28e2906dd4c5af7b5ee2146e60eb5"
    "77f786c5ab5fbbe05171cd5214cb4cc7ac9eed3706c74d376beb4cb1404692"
    "95ace0d72a1fb8024f9978132e3943142314b8e2ed1f2af28df57f1e48955"
    "5ff59056637bafe88fe5e77074d61f2e9a7e89b93d765e2ca59b93e1b47c"
    "6662b2dbb7faf37610102e01fc3560555799785afe3963f63939e8cd2654a"
    "2587fd4828b54724eb7714830dba1e784cd0729e2d90cc8c54da61771022e"
    "4af010de8aa45555c9eca47f6b757c358bb5b0e5a0bffe0d26aa17ff1e0f"
    "571c9ade855064cb9d1bfb3f",
    16,
)
TEST_RSA_D = int(
    "02cffb75ab87343a3fdd5e40e7fc2400a23a078b08441edf2fc646c222c005"
    "c0cac82ffd1d58ba581287d1b494aa445aedf55e837179fc024eb2666c35f8"
    "ec78d6231fdcb82686926725c33f3ab484acdce7bf6c8c5e24ba5b34c98db"
    "3eb2763c2c9d35964a01352a41d89844c4e27a30e74c141802bc58c241ba3"
    "0dd52fe1fbe4c0ca9876497f1bf7d623c9dc0f58fd6089b45746c6799b9da"
    "cb42b01fe5b964127d92e7c1d20bb8fee227a835e5b524d26debd01f5139a"
    "a8ce3cfa571b5284bf8332df8c94e65ba1173c33113d47f40a653d408f427"
    "a70573a7e77dbfd31f5c0d1caf1e53acc5cbae17e2de2b36ba7a7382987e7"
    "3277ad8105aeb575a680c9",
    16,
)
sys.path.insert(0, str(SCRIPT_DIR))


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


def nginx_certificate_command(certificate: Path, private_key: Path) -> list[str]:
    dockerfile = NGINX_DOCKERFILE.read_text(encoding="utf-8")
    recipe = dockerfile.split("RUN ", 1)[1].split("\nCOPY ", 1)[0]
    command = shlex.split(recipe.replace("\\\n", " "))
    command[command.index("-out") + 1] = str(certificate)
    command[command.index("-keyout") + 1] = str(private_key)
    return command


class EmptyHttpsHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(204)
        self.end_headers()

    def log_message(self, _format: str, *_args) -> None:
        return


class OpenIdConformanceRunnerTest(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = load_runner()
        cls.plan_map = cls.runner.load_plan_map()

    def offer_uri(
        self, issuer: str = "https://issuer.example.test"
    ) -> tuple[str, str]:
        grant = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
        inline = json.dumps(
            {
                "credential_issuer": issuer,
                "credential_configuration_ids": ["person_is_alive_sd_jwt"],
                "grants": {grant: {"pre-authorized_code": "owner-only-code"}},
            }
        )
        return inline, "openid-credential-offer://?" + urllib.parse.urlencode(
            {"credential_offer": inline}
        )

    def suite_jwks(self) -> dict[str, object]:
        def encoded_integer(value: int) -> str:
            raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
            return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

        return {
            "keys": [
                {
                    "alg": "RS256",
                    "e": encoded_integer(65_537),
                    "kid": "suite-test-key",
                    "kty": "RSA",
                    "n": encoded_integer(TEST_RSA_N),
                    "use": "sig",
                }
            ]
        }

    def sign_suite_export(self, content: bytes) -> str:
        encoded_size = (TEST_RSA_N.bit_length() + 7) // 8
        digest_info = (
            self.runner.SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(content).digest()
        )
        padding_size = encoded_size - len(digest_info) - 3
        encoded = b"\x00\x01" + b"\xff" * padding_size + b"\x00" + digest_info
        signature = pow(int.from_bytes(encoded), TEST_RSA_D, TEST_RSA_N).to_bytes(
            encoded_size, "big"
        )
        return base64.urlsafe_b64encode(signature).decode("ascii")

    def suite_jwks_sha256(self) -> str:
        return self.runner.canonical_sha256(self.suite_jwks())

    def write_private_jwks(self, directory: Path) -> Path:
        path = directory / "suite-jwks.json"
        path.write_text(json.dumps(self.suite_jwks()), encoding="utf-8")
        path.chmod(0o600)
        return path

    def candidate(self) -> dict[str, object]:
        return {
            "release_id": "beta-17",
            "version": "1.0.0",
            "source_repo": "registrystack/registry-stack",
            "source_ref": "a" * 40,
            "source_tag": "v1.0.0",
            "tag_target": "b" * 40,
            "manifest_sha256": f"sha256:{'c' * 64}",
            "image_lock_sha256": f"sha256:{'d' * 64}",
            "release_capsule_sha256": f"sha256:{'e' * 64}",
            "notary_image": (
                "ghcr.io/registrystack/registry-notary@sha256:" + "f" * 64
            ),
            "relay_image": ("ghcr.io/registrystack/registry-relay@sha256:" + "1" * 64),
            "topology": "release-owned",
            "solmara_source_ref": None,
        }

    def suite_export(
        self,
        *,
        result: str = "FAILED",
        terminal_result: str | None = None,
        secret: str = "RS_OPENID_SECRET_CANARY_6d5a1f0bc2",
        transaction_code: str | None = None,
        warning_source: str = "CredentialMetadataWarning",
        test_info_version: str = "5.2.0",
        exported_version: str = "5.2.0",
        exported_from: str = "https://localhost.emobix.co.uk:8443",
        issuer_url: str = "https://issuer.example.test",
    ) -> tuple[str, bytes]:
        scenario = self.runner.find_scenario(
            self.plan_map, "notary-oid4vci-issuer-metadata"
        )
        module = scenario["suite_modules"][0]
        test_id = "Ab3dE5fG7hI9jK1"
        terminal_result = terminal_result or result
        payload = {
            "testInfo": {
                "_id": test_id,
                "testId": test_id,
                "testName": module,
                "variant": scenario["variants"],
                "started": "2026-07-25T04:00:00.123456Z",
                "config": {
                    "alias": "registry-stack-notary-oid4vci-issuer",
                    "description": (
                        "Registry Stack Notary OID4VCI issuer conformance slice "
                        f"[{module}]"
                    ),
                    "vci": {
                        "credential_issuer_url": issuer_url,
                        "authorization_server": "https://issuer.example.test",
                        "credential_configuration_id": "person_is_alive_sd_jwt",
                        "credential_proof_type_hint": "jwt",
                        "static_tx_code": transaction_code or secret,
                    },
                    "client": {"client_id": "client-a"},
                    "client2": {"client_id": "client-b"},
                },
                "description": "private suite description",
                "alias": "registry-stack-notary-oid4vci-issuer",
                "owner": {"sub": "private-owner"},
                "planId": "private-plan-id",
                "status": "FINISHED",
                "version": test_info_version,
                "summary": "private suite summary",
                "publish": "private",
                "result": result,
            },
            "exportedFrom": exported_from,
            "exportedBy": {"sub": "private-owner"},
            "exportedVersion": exported_version,
            "exportedAt": "Jul 25, 2026, 4:01:00 AM",
            "results": [
                {
                    "src": "MetadataCondition",
                    "result": "SUCCESS",
                    "testId": test_id,
                    "time": 1_784_952_001_000,
                },
                {
                    "src": "MetadataContext",
                    "result": "INFO",
                    "testId": test_id,
                    "time": 1_784_952_001_500,
                },
                {
                    "src": "CredentialMetadataFailure",
                    "result": "FAILURE",
                    "testId": test_id,
                    "msg": "private failure message",
                    "access_token": secret,
                    "time": 1_784_952_002_000,
                },
                {
                    "src": warning_source,
                    "result": "WARNING",
                    "testId": test_id,
                    "proof": f"{secret}.proof.payload",
                    "civil_id": secret,
                    "time": 1_784_952_003_000,
                },
                {
                    "src": "CredentialMetadataReview",
                    "result": "REVIEW",
                    "testId": test_id,
                    "msg": "private review message",
                    "time": 1_784_952_004_000,
                },
                {
                    "src": module,
                    "result": "FINISHED",
                    "testId": test_id,
                    "testmodule_result": terminal_result,
                    "time": 1_784_952_060_000,
                },
            ],
        }
        encoded_payload = json.dumps(payload).encode("utf-8")
        json_name = f"test-log-{module}-{test_id}.json"
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(json_name, encoded_payload)
            archive.writestr(
                json_name.removesuffix(".json") + ".sig",
                self.sign_suite_export(encoded_payload),
            )
        return json_name, buffer.getvalue()

    def write_private_export(self, directory: Path, content: bytes) -> Path:
        path = directory / "suite-export.zip"
        path.write_bytes(content)
        path.chmod(0o600)
        return path

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

    def test_list_does_not_require_candidate_yaml_dependencies(self) -> None:
        result = subprocess.run(
            [sys.executable, "-S", str(RUNNER_PATH), "list"],
            cwd=self.runner.REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("notary-oid4vci-issuer-metadata", result.stdout)

    def test_readme_documents_the_required_suite_jwks_trust_flow(self) -> None:
        readme = (
            self.runner.CONFIG_DIR / "README.md"
        ).read_text(encoding="utf-8")
        self.assertIn("export-suite-jwks", readme)
        self.assertIn("--suite-ca-certificate", readme)
        self.assertIn("--suite-jwks", readme)
        self.assertIn("/jwks", readme)
        self.assertIn("canonical", readme)
        self.assertIn("signature", readme)
        self.assertIn("--output-dir", readme)
        self.assertIn("--export-dir", readme)
        self.assertIn("operator-attested", readme)
        self.assertIn("no separate\nUI download step", readme)

    def test_evidence_schema_matches_the_builder_contract(self) -> None:
        schema = json.loads(
            self.runner.EVIDENCE_SCHEMA_PATH.read_text(encoding="utf-8")
        )
        properties = schema["properties"]
        self.assertEqual(
            self.runner.EVIDENCE_SCHEMA_VERSION,
            properties["schema_version"]["const"],
        )
        self.assertEqual(
            self.runner.EVIDENCE_CLASSIFICATION,
            properties["classification"]["const"],
        )
        self.assertEqual(
            self.runner.SUITE_RESULTS,
            set(schema["$defs"]["run"]["properties"]["result"]["enum"]),
        )
        self.assertEqual(
            [
                {"scenario_id": scenario_id, "status": status}
                for scenario_id, status in self.runner.EVIDENCE_UNSUPPORTED_SCENARIOS
            ],
            properties["unsupported_scenarios"]["const"],
        )
        scenario = self.runner.find_scenario(
            self.plan_map, self.runner.EVIDENCE_SCENARIO_ID
        )
        scenario_schema = schema["$defs"]["scenario"]["properties"]
        self.assertEqual(scenario["id"], scenario_schema["scenario_id"]["const"])
        self.assertEqual(
            scenario["suite_plan"], scenario_schema["expected_plan"]["const"]
        )
        self.assertEqual(
            scenario["suite_modules"], scenario_schema["modules"]["const"]
        )
        self.assertEqual(
            scenario["variants"],
            {
                name: definition["const"]
                for name, definition in scenario_schema["variants"][
                    "properties"
                ].items()
            },
        )
        self.assertEqual(
            self.plan_map["suite"]["repo"],
            schema["$defs"]["suite"]["properties"]["repository"]["const"],
        )
        suite_properties = schema["$defs"]["suite"]["properties"]
        self.assertEqual(
            self.plan_map["suite"]["release_tag"],
            suite_properties["release_tag"]["const"],
        )
        self.assertEqual(
            self.plan_map["suite"]["release_tag"].removeprefix("release-v"),
            suite_properties["reported_version"]["const"],
        )
        self.assertEqual(
            self.plan_map["suite"]["base_url"],
            suite_properties["exported_from"]["const"],
        )
        self.assertEqual(
            self.runner.EVIDENCE_ASSOCIATION,
            schema["$defs"]["deployment"]["properties"][
                "candidate_association"
            ]["const"],
        )
        self.assertEqual(
            self.runner.EVIDENCE_ASSOCIATION,
            scenario_schema["plan_association"]["const"],
        )
        self.assertEqual(
            self.runner.EVIDENCE_ASSOCIATION,
            schema["$defs"]["suite"]["properties"]["commit_association"]["const"],
        )
    def test_notary_mapping_is_candidate_only_and_matches_the_1_0_profile(self) -> None:
        metadata = self.runner.find_scenario(
            self.plan_map, "notary-oid4vci-issuer-metadata"
        )
        full = self.runner.find_scenario(
            self.plan_map, "notary-oid4vci-issuer-full"
        )

        self.assertEqual("candidate-only", metadata["status"])
        self.assertEqual(
            "pre_authorization_code", metadata["variants"]["vci_grant_type"]
        )
        self.assertIn("registry-backed", metadata["surface"])
        metadata_notes = " ".join(metadata["notes"])
        self.assertIn("does not support or claim DPoP", metadata_notes)
        self.assertIn("frozen candidate artifact", metadata_notes)

        self.assertEqual("blocked-by-suite-profile", full["status"])
        self.assertEqual(
            "pre_authorization_code", full["variants"]["vci_grant_type"]
        )
        full_contract = " ".join(full["requires"] + full["notes"])
        self.assertIn("pre-authorized offer", full_contract)
        self.assertIn("is not a wallet grant", full_contract)
        self.assertIn("adapter now closes that transport gap", full_contract)
        self.assertNotIn(
            "blocked by the suite callback adapter", json.dumps(self.plan_map)
        )
        self.assertNotIn(
            "policy decision on whether the first full run targets",
            full_contract,
        )
        verifier = next(
            item
            for item in self.plan_map["non_oidf_surfaces"]
            if item["surface"] == "Registry Notary Rust SD-JWT verifier"
        )
        self.assertIn("not an OID4VP endpoint", verifier["reason"])

    def test_promote_evidence_emits_only_candidate_bound_allowlisted_summary(
        self,
    ) -> None:
        secret = "RS_OPENID_SECRET_CANARY_6d5a1f0bc2"
        _, raw_export = self.suite_export(secret=secret)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            suite_export = self.write_private_export(root, raw_export)
            suite_jwks = self.write_private_jwks(root)
            output = root / "review" / "summary.json"
            manifest = (
                self.runner.REPO_ROOT / "release" / "manifests" / "candidate.yaml"
            )
            image_lock = root / "registryctl-v1.0.0-image-lock.json"
            args = self.runner.parse_args(
                [
                    "promote-evidence",
                    "--suite-export",
                    str(suite_export),
                    "--suite-jwks",
                    str(suite_jwks),
                    "--release-manifest",
                    str(manifest),
                    "--image-lock",
                    str(image_lock),
                    "--output",
                    str(output),
                ]
            )
            candidate = self.candidate()
            with patch.object(
                self.runner, "load_authenticated_candidate", return_value=candidate
            ) as load_candidate:
                with patch("builtins.print"):
                    self.assertEqual(0, self.runner.cmd_promote_evidence(args))

            load_candidate.assert_called_once_with(manifest, image_lock)
            summary_bytes = output.read_bytes()
            summary = json.loads(summary_bytes)
            self.assertEqual(0o600, output.stat().st_mode & 0o777)
            self.assertEqual("FAILED", summary["run"]["result"])
            self.assertEqual("FINISHED", summary["run"]["terminal_status"])
            self.assertEqual(
                "2026-07-25T04:00:00.123456Z", summary["run"]["started_at"]
            )
            self.assertEqual("2026-07-25T04:01:00.000Z", summary["run"]["completed_at"])
            self.assertEqual(
                {
                    "info": 1,
                    "success": 1,
                    "review": 1,
                    "warning": 1,
                    "failure": 1,
                },
                summary["run"]["conditions"]["counts"],
            )
            self.assertEqual(
                candidate["tag_target"], summary["candidate"]["tag_target"]
            )
            self.assertEqual(
                candidate["notary_image"], summary["candidate"]["notary_image"]
            )
            self.assertTrue(
                summary["candidate"]["release_assets_authenticity_verified"]
            )
            self.assertEqual(
                "https://issuer.example.test",
                summary["deployment"]["issuer_url"],
            )
            self.assertEqual(
                self.runner.EVIDENCE_ASSOCIATION,
                summary["deployment"]["candidate_association"],
            )
            self.assertEqual(self.plan_map["suite"]["ref"], summary["suite"]["commit"])
            self.assertEqual(
                self.plan_map["suite"]["release_tag"],
                summary["suite"]["release_tag"],
            )
            self.assertEqual("5.2.0", summary["suite"]["reported_version"])
            self.assertEqual(
                self.runner.EVIDENCE_ASSOCIATION,
                summary["suite"]["commit_association"],
            )
            self.assertEqual(
                self.suite_jwks_sha256(), summary["suite"]["jwks_sha256"]
            )
            self.assertTrue(summary["suite"]["export_signature_verified"])
            self.assertEqual(
                "oid4vci-1_0-issuer-test-plan",
                summary["scenario"]["expected_plan"],
            )
            self.assertEqual(
                self.runner.EVIDENCE_ASSOCIATION,
                summary["scenario"]["plan_association"],
            )
            self.assertEqual(
                ["oid4vci-1_0-issuer-metadata-test"],
                summary["scenario"]["modules"],
            )
            self.assertEqual(
                [
                    {
                        "scenario_id": "notary-oid4vci-issuer-full",
                        "status": "blocked-by-suite-profile",
                    }
                ],
                summary["unsupported_scenarios"],
            )
            schema = json.loads(
                self.runner.EVIDENCE_SCHEMA_PATH.read_text(encoding="utf-8")
            )
            self.assertFalse(schema["additionalProperties"])
            self.assertEqual(set(schema["required"]), set(summary))
            for definition, field in (
                ("candidate", "candidate"),
                ("deployment", "deployment"),
                ("suite", "suite"),
                ("scenario", "scenario"),
                ("configuration", "configuration"),
                ("run", "run"),
            ):
                self.assertEqual(
                    set(schema["$defs"][definition]["required"]),
                    set(summary[field]),
                )
            self.assertEqual(
                set(schema["$defs"]["conditions"]["required"]),
                set(summary["run"]["conditions"]),
            )
            self.assertEqual(
                set(
                    schema["$defs"]["conditions"]["properties"]["counts"]["required"]
                ),
                set(summary["run"]["conditions"]["counts"]),
            )
            self.assertEqual(
                set(
                    schema["$defs"]["scenario"]["properties"]["variants"][
                        "required"
                    ]
                ),
                set(summary["scenario"]["variants"]),
            )
            self.assertNotIn(secret.encode(), summary_bytes)
            self.assertNotIn(b"private failure message", summary_bytes)
            self.assertNotIn(b"private review message", summary_bytes)
            self.assertNotIn(b"Ab3dE5fG7hI9jK1", summary_bytes)
            self.assertNotIn(b"private-plan-id", summary_bytes)
            self.assertFalse(summary["raw_suite_export_included"])
            self.assertFalse(summary["contains_sensitive_material"])

    def test_promote_evidence_reports_excessive_nesting_as_runner_error(self) -> None:
        _, raw_export = self.suite_export()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = self.runner.parse_args(
                [
                    "promote-evidence",
                    "--suite-export",
                    str(self.write_private_export(root, raw_export)),
                    "--suite-jwks",
                    str(self.write_private_jwks(root)),
                    "--release-manifest",
                    str(root / "candidate.yaml"),
                    "--image-lock",
                    str(root / "image-lock.json"),
                    "--output",
                    str(root / "summary.json"),
                ]
            )
            with patch.object(
                self.runner,
                "load_authenticated_candidate",
                return_value=self.candidate(),
            ):
                with patch.object(
                    self.runner,
                    "collect_sensitive_raw_values",
                    side_effect=RecursionError,
                ):
                    with self.assertRaisesRegex(
                        self.runner.RunnerError, "too deeply nested"
                    ):
                        self.runner.cmd_promote_evidence(args)

    def test_promote_evidence_rejects_schema_invalid_generated_summary(
        self,
    ) -> None:
        _, raw_export = self.suite_export()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "summary.json"
            args = self.runner.parse_args(
                [
                    "promote-evidence",
                    "--suite-export",
                    str(self.write_private_export(root, raw_export)),
                    "--suite-jwks",
                    str(self.write_private_jwks(root)),
                    "--release-manifest",
                    str(root / "candidate.yaml"),
                    "--image-lock",
                    str(root / "image-lock.json"),
                    "--output",
                    str(output),
                ]
            )
            build_summary = self.runner.build_evidence_summary

            def schema_invalid_summary(*arguments):
                summary, sensitive = build_summary(*arguments)
                summary["run"]["conditions"]["counts"]["failure"] = -1
                return summary, sensitive

            with patch.object(
                self.runner,
                "load_authenticated_candidate",
                return_value=self.candidate(),
            ):
                with patch.object(
                    self.runner,
                    "build_evidence_summary",
                    side_effect=schema_invalid_summary,
                ):
                    with self.assertRaisesRegex(
                        self.runner.RunnerError, "does not match its schema"
                    ):
                        self.runner.cmd_promote_evidence(args)
            self.assertFalse(output.exists())

    def test_promote_evidence_preserves_each_terminal_suite_result(self) -> None:
        scenario = self.runner.find_scenario(
            self.plan_map, "notary-oid4vci-issuer-metadata"
        )
        for suite_result in sorted(self.runner.SUITE_RESULTS):
            with self.subTest(suite_result=suite_result):
                _, raw_export = self.suite_export(result=suite_result)
                with tempfile.TemporaryDirectory() as tmp:
                    suite_export = self.write_private_export(Path(tmp), raw_export)
                    exported = self.runner.load_suite_export(
                        suite_export,
                        scenario["suite_modules"][0],
                        self.suite_jwks(),
                    )
                    summary, _ = self.runner.build_evidence_summary(
                        self.plan_map,
                        scenario,
                        exported,
                        self.candidate(),
                        self.suite_jwks_sha256(),
                    )
                self.assertEqual(suite_result, summary["run"]["result"])

    def test_promote_evidence_rejects_mismatched_suite_provenance(self) -> None:
        scenario = self.runner.find_scenario(
            self.plan_map, "notary-oid4vci-issuer-metadata"
        )
        cases = {
            "testInfo.version": {"test_info_version": "5.2.1"},
            "exportedVersion": {"exported_version": "5.2.1"},
            "exportedFrom": {"exported_from": "https://other.example.test"},
        }
        for label, overrides in cases.items():
            with self.subTest(label=label):
                _, raw_export = self.suite_export(**overrides)
                with tempfile.TemporaryDirectory() as tmp:
                    suite_export = self.write_private_export(Path(tmp), raw_export)
                    exported = self.runner.load_suite_export(
                        suite_export,
                        scenario["suite_modules"][0],
                        self.suite_jwks(),
                    )
                with self.assertRaisesRegex(
                    self.runner.RunnerError, "version|identity"
                ):
                    self.runner.build_evidence_summary(
                        self.plan_map,
                        scenario,
                        exported,
                        self.candidate(),
                        self.suite_jwks_sha256(),
                    )

    def test_issuer_url_runtime_and_schema_reject_the_same_unsafe_shapes(
        self,
    ) -> None:
        scenario = self.runner.find_scenario(
            self.plan_map, "notary-oid4vci-issuer-metadata"
        )
        schema = json.loads(
            self.runner.EVIDENCE_SCHEMA_PATH.read_text(encoding="utf-8")
        )
        _, valid_raw_export = self.suite_export()
        with tempfile.TemporaryDirectory() as tmp:
            exported = self.runner.load_suite_export(
                self.write_private_export(Path(tmp), valid_raw_export),
                scenario["suite_modules"][0],
                self.suite_jwks(),
            )
        valid_summary, _ = self.runner.build_evidence_summary(
            self.plan_map,
            scenario,
            exported,
            self.candidate(),
            self.suite_jwks_sha256(),
        )

        for unsafe_url in (
            "https://user:secret@issuer.example.test",
            "https://issuer.example.test/path\ninjected",
            "https://issuer.example.test/path\\confused",
            "https://issuer.example.test:65536",
            "https://[:::]/path",
            "https://issuer.example.test/" + ("a" * 2048),
        ):
            with self.subTest(unsafe_url=repr(unsafe_url)):
                _, raw_export = self.suite_export(issuer_url=unsafe_url)
                with tempfile.TemporaryDirectory() as tmp:
                    exported = self.runner.load_suite_export(
                        self.write_private_export(Path(tmp), raw_export),
                        scenario["suite_modules"][0],
                        self.suite_jwks(),
                    )
                with self.assertRaisesRegex(
                    self.runner.RunnerError, "issuer URL is invalid"
                ):
                    self.runner.build_evidence_summary(
                        self.plan_map,
                        scenario,
                        exported,
                        self.candidate(),
                        self.suite_jwks_sha256(),
                    )

                invalid_summary = json.loads(json.dumps(valid_summary))
                invalid_summary["deployment"]["issuer_url"] = unsafe_url
                with self.assertRaises(self.runner.SchemaValidationError):
                    self.runner.validate_against_schema(
                        invalid_summary,
                        schema,
                        schema,
                        "evidence summary",
                    )

        ipv6_summary = json.loads(json.dumps(valid_summary))
        ipv6_summary["deployment"]["issuer_url"] = (
            "https://[2001:db8::1]:443/issuer"
        )
        self.runner.validate_against_schema(
            ipv6_summary,
            schema,
            schema,
            "evidence summary",
        )

    def test_promote_evidence_rejects_changed_terminal_result(self) -> None:
        scenario = self.runner.find_scenario(
            self.plan_map, "notary-oid4vci-issuer-metadata"
        )
        _, raw_export = self.suite_export(result="FAILED", terminal_result="PASSED")
        with tempfile.TemporaryDirectory() as tmp:
            suite_export = self.write_private_export(Path(tmp), raw_export)
            exported = self.runner.load_suite_export(
                suite_export,
                scenario["suite_modules"][0],
                self.suite_jwks(),
            )
        with self.assertRaisesRegex(
            self.runner.RunnerError, "matching terminal module record"
        ):
            self.runner.build_evidence_summary(
                self.plan_map,
                scenario,
                exported,
                self.candidate(),
                self.suite_jwks_sha256(),
            )

    def test_suite_export_rejects_invalid_signature(self) -> None:
        scenario = self.runner.find_scenario(
            self.plan_map, "notary-oid4vci-issuer-metadata"
        )
        module = scenario["suite_modules"][0]
        json_name, raw_export = self.suite_export()
        signature_name = json_name.removesuffix(".json") + ".sig"
        with zipfile.ZipFile(io.BytesIO(raw_export)) as source:
            payload = source.read(json_name)
            signature = bytearray(source.read(signature_name))
        signature[0] = ord("A") if signature[0] != ord("A") else ord("B")
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(json_name, payload)
            archive.writestr(signature_name, signature)

        with tempfile.TemporaryDirectory() as tmp:
            path = self.write_private_export(Path(tmp), buffer.getvalue())
            with self.assertRaisesRegex(
                self.runner.RunnerError, "exactly one trusted suite key"
            ):
                self.runner.load_suite_export(path, module, self.suite_jwks())

    def test_suite_jwks_rejects_invalid_rsa_key(self) -> None:
        jwks = self.suite_jwks()
        jwks["keys"][0]["e"] = "Ag"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "suite-jwks.json"
            path.write_text(json.dumps(jwks), encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaisesRegex(
                self.runner.RunnerError, "invalid RSA signing key"
            ):
                self.runner.load_suite_jwks(path)

    def test_suite_export_rejects_nonmatching_valid_shape_key(self) -> None:
        scenario = self.runner.find_scenario(
            self.plan_map, "notary-oid4vci-issuer-metadata"
        )
        module = scenario["suite_modules"][0]
        _, raw_export = self.suite_export()
        jwks = self.suite_jwks()
        nonmatching_modulus = TEST_RSA_N - 2
        raw_modulus = nonmatching_modulus.to_bytes(
            (nonmatching_modulus.bit_length() + 7) // 8, "big"
        )
        jwks["keys"][0]["n"] = (
            base64.urlsafe_b64encode(raw_modulus).decode("ascii").rstrip("=")
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            export_path = self.write_private_export(root, raw_export)
            jwks_path = root / "nonmatching-jwks.json"
            jwks_path.write_text(json.dumps(jwks), encoding="utf-8")
            jwks_path.chmod(0o600)
            validated_jwks, _ = self.runner.load_suite_jwks(jwks_path)
            with self.assertRaisesRegex(
                self.runner.RunnerError, "exactly one trusted suite key"
            ):
                self.runner.load_suite_export(
                    export_path, module, validated_jwks
                )

    def test_suite_export_rejects_multiple_matching_jwks_keys(self) -> None:
        scenario = self.runner.find_scenario(
            self.plan_map, "notary-oid4vci-issuer-metadata"
        )
        module = scenario["suite_modules"][0]
        _, raw_export = self.suite_export()
        jwks = self.suite_jwks()
        duplicate = dict(jwks["keys"][0])
        duplicate["kid"] = "duplicate-suite-test-key"
        jwks["keys"].append(duplicate)
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write_private_export(Path(tmp), raw_export)
            with self.assertRaisesRegex(
                self.runner.RunnerError, "exactly one trusted suite key"
            ):
                self.runner.load_suite_export(path, module, jwks)

    def test_suite_export_binds_run_identifiers_and_considered_logs(self) -> None:
        scenario = self.runner.find_scenario(
            self.plan_map, "notary-oid4vci-issuer-metadata"
        )
        module = scenario["suite_modules"][0]
        json_name, raw_export = self.suite_export()
        signature_name = json_name.removesuffix(".json") + ".sig"
        with zipfile.ZipFile(io.BytesIO(raw_export)) as source:
            original = json.loads(source.read(json_name))

        def repack(payload: dict[str, object]) -> bytes:
            encoded = json.dumps(payload).encode("utf-8")
            buffer = io.BytesIO()
            with zipfile.ZipFile(
                buffer, "w", compression=zipfile.ZIP_DEFLATED
            ) as archive:
                archive.writestr(json_name, encoded)
                archive.writestr(signature_name, self.sign_suite_export(encoded))
            return buffer.getvalue()

        changed_id = json.loads(json.dumps(original))
        changed_id["testInfo"]["_id"] = "Zm9xN8pL2rS4tV6"
        long_plan_id = json.loads(json.dumps(original))
        long_plan_id["testInfo"]["planId"] = "p" * 129
        for label, payload in {
            "mismatched test id": changed_id,
            "oversized plan id": long_plan_id,
        }.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                path = self.write_private_export(Path(tmp), repack(payload))
                with self.assertRaisesRegex(
                    self.runner.RunnerError, "run identifiers do not match"
                ):
                    self.runner.load_suite_export(path, module, self.suite_jwks())

        changed_log = json.loads(json.dumps(original))
        changed_log["results"][0]["testId"] = "Zm9xN8pL2rS4tV6"
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write_private_export(Path(tmp), repack(changed_log))
            exported = self.runner.load_suite_export(
                path, module, self.suite_jwks()
            )
        with self.assertRaisesRegex(
            self.runner.RunnerError, "log entry does not match"
        ):
            self.runner.build_evidence_summary(
                self.plan_map,
                scenario,
                exported,
                self.candidate(),
                self.suite_jwks_sha256(),
            )

    def test_suite_export_zip_rejects_unsafe_or_unexpected_entries(self) -> None:
        scenario = self.runner.find_scenario(
            self.plan_map, "notary-oid4vci-issuer-metadata"
        )
        module = scenario["suite_modules"][0]
        json_name, raw_export = self.suite_export()

        def mutate(
            entries: list[tuple[zipfile.ZipInfo | str, bytes | str]],
            *,
            compression: int = zipfile.ZIP_DEFLATED,
        ) -> bytes:
            buffer = io.BytesIO()
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
                    for name, content in entries:
                        archive.writestr(name, content)
            return buffer.getvalue()

        with zipfile.ZipFile(io.BytesIO(raw_export)) as archive:
            payload = archive.read(json_name)
        signature_name = json_name.removesuffix(".json") + ".sig"
        symlink = zipfile.ZipInfo(signature_name)
        symlink.create_system = 3
        symlink.external_attr = stat.S_IFLNK << 16
        cases = {
            "path traversal": mutate(
                [(json_name, payload), ("../" + signature_name, "signature")]
            ),
            "symlink": mutate([(json_name, payload), (symlink, "target")]),
            "duplicate": mutate(
                [
                    (json_name, payload),
                    (json_name, payload),
                ]
            ),
            "unexpected": mutate(
                [
                    (json_name, payload),
                    (signature_name, "signature"),
                    ("raw.log", "private"),
                ]
            ),
        }
        encrypted = bytearray(raw_export)
        local_header = encrypted.find(b"PK\x03\x04")
        central_header = encrypted.find(b"PK\x01\x02")
        self.assertNotEqual(-1, local_header)
        self.assertNotEqual(-1, central_header)
        encrypted[local_header + 6] |= 0x01
        encrypted[central_header + 8] |= 0x01
        cases["encrypted"] = bytes(encrypted)

        for label, content in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                path = self.write_private_export(Path(tmp), content)
                with self.assertRaises(self.runner.RunnerError):
                    self.runner.load_suite_export(path, module, self.suite_jwks())

    def test_suite_export_zip_rejects_corrupt_member_data_as_runner_error(self) -> None:
        scenario = self.runner.find_scenario(
            self.plan_map, "notary-oid4vci-issuer-metadata"
        )
        module = scenario["suite_modules"][0]
        json_name, raw_export = self.suite_export()
        signature_name = json_name.removesuffix(".json") + ".sig"
        with zipfile.ZipFile(io.BytesIO(raw_export)) as source:
            payload = source.read(json_name)
            signature = source.read(signature_name)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr(json_name, payload)
            archive.writestr(signature_name, signature)
        stored = buffer.getvalue()
        for target_name in (json_name, signature_name):
            with self.subTest(target_name=target_name):
                corrupt = bytearray(stored)
                with zipfile.ZipFile(io.BytesIO(corrupt)) as archive:
                    entry = archive.getinfo(target_name)
                name_size = int.from_bytes(
                    corrupt[
                        entry.header_offset + 26 : entry.header_offset + 28
                    ],
                    "little",
                )
                extra_size = int.from_bytes(
                    corrupt[
                        entry.header_offset + 28 : entry.header_offset + 30
                    ],
                    "little",
                )
                data_offset = entry.header_offset + 30 + name_size + extra_size
                corrupt[data_offset] ^= 0x01

                with tempfile.TemporaryDirectory() as tmp:
                    path = self.write_private_export(Path(tmp), bytes(corrupt))
                    with self.assertRaisesRegex(
                        self.runner.RunnerError, "invalid compressed data"
                    ):
                        self.runner.load_suite_export(
                            path, module, self.suite_jwks()
                        )

    def test_suite_export_zip_rejects_size_and_compression_bombs(self) -> None:
        scenario = self.runner.find_scenario(
            self.plan_map, "notary-oid4vci-issuer-metadata"
        )
        module = scenario["suite_modules"][0]
        json_name, _ = self.suite_export()
        signature_name = json_name.removesuffix(".json") + ".sig"

        aggregate = io.BytesIO()
        with zipfile.ZipFile(aggregate, "w") as archive:
            archive.writestr(json_name, "{}" + " " * 70)
            archive.writestr(signature_name, "s" * 70)
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write_private_export(Path(tmp), aggregate.getvalue())
            with patch.object(
                self.runner,
                "read_owner_only_file",
                return_value=aggregate.getvalue(),
            ):
                with patch.object(self.runner, "MAX_SUITE_EXPORT_BYTES", 100):
                    with self.assertRaisesRegex(
                        self.runner.RunnerError, "uncompressed size"
                    ):
                        self.runner.load_suite_export(path, module, self.suite_jwks())

        compressed = io.BytesIO()
        with zipfile.ZipFile(
            compressed, "w", compression=zipfile.ZIP_DEFLATED
        ) as archive:
            archive.writestr(json_name, " " * (2 * 1024 * 1024))
            archive.writestr(signature_name, "signature")
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write_private_export(Path(tmp), compressed.getvalue())
            with self.assertRaisesRegex(
                self.runner.RunnerError, "suspicious compression ratio"
            ):
                self.runner.load_suite_export(path, module, self.suite_jwks())

    def test_evidence_summary_rejects_unsupported_scenario_contract_drift(self) -> None:
        scenario = self.runner.find_scenario(
            self.plan_map, "notary-oid4vci-issuer-metadata"
        )
        _, raw_export = self.suite_export()
        with tempfile.TemporaryDirectory() as tmp:
            suite_export = self.write_private_export(Path(tmp), raw_export)
            exported = self.runner.load_suite_export(
                suite_export,
                scenario["suite_modules"][0],
                self.suite_jwks(),
            )
        changed_plan_map = json.loads(json.dumps(self.plan_map))
        changed_plan_map["scenarios"].append(
            {"id": "unreviewed-scenario", "status": "blocked"}
        )
        with self.assertRaisesRegex(
            self.runner.RunnerError, "unsupported scenario contract changed"
        ):
            self.runner.build_evidence_summary(
                changed_plan_map,
                scenario,
                exported,
                self.candidate(),
                self.suite_jwks_sha256(),
            )

    def test_public_summary_guard_rejects_raw_sensitive_fields(self) -> None:
        scenario = self.runner.find_scenario(
            self.plan_map, "notary-oid4vci-issuer-metadata"
        )
        _, raw_export = self.suite_export()
        with tempfile.TemporaryDirectory() as tmp:
            suite_export = self.write_private_export(Path(tmp), raw_export)
            exported = self.runner.load_suite_export(
                suite_export,
                scenario["suite_modules"][0],
                self.suite_jwks(),
            )
        summary, sensitive = self.runner.build_evidence_summary(
            self.plan_map,
            scenario,
            exported,
            self.candidate(),
            self.suite_jwks_sha256(),
        )
        summary["run"]["access_token"] = "copied-private-token"
        with self.assertRaisesRegex(self.runner.RunnerError, "forbidden field"):
            self.runner.assert_public_summary_safe(summary, sensitive)

    def test_public_summary_omits_condition_identifiers_and_transaction_code(
        self,
    ) -> None:
        transaction_code = "LeakyCode123"
        scenario = self.runner.find_scenario(
            self.plan_map, "notary-oid4vci-issuer-metadata"
        )
        _, raw_export = self.suite_export(
            transaction_code=transaction_code,
            warning_source=transaction_code,
        )
        with tempfile.TemporaryDirectory() as tmp:
            suite_export = self.write_private_export(Path(tmp), raw_export)
            exported = self.runner.load_suite_export(
                suite_export,
                scenario["suite_modules"][0],
                self.suite_jwks(),
            )
        summary, sensitive = self.runner.build_evidence_summary(
            self.plan_map,
            scenario,
            exported,
            self.candidate(),
            self.suite_jwks_sha256(),
        )
        self.assertEqual(1, summary["run"]["conditions"]["counts"]["warning"])
        self.assertNotIn(transaction_code, json.dumps(summary))
        self.assertIn(transaction_code, sensitive)
        self.runner.assert_public_summary_safe(summary, sensitive)

    def test_export_suite_jwks_uses_authenticated_origin_and_owner_only_output(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "suite-jwks.json"
            ca_certificate = root / "suite-ca.pem"
            args = self.runner.parse_args(
                [
                    "export-suite-jwks",
                    "--conformance-server",
                    "https://suite.example.test",
                    "--suite-ca-certificate",
                    str(ca_certificate),
                    "--output",
                    str(output),
                ]
            )
            response = MagicMock()
            response.status = 200
            response.read.return_value = json.dumps(self.suite_jwks()).encode("utf-8")
            response.__enter__.return_value = response
            opener = MagicMock()
            opener.open.return_value = response
            tls_context = MagicMock()
            with patch.object(
                self.runner,
                "suite_tls_context",
                return_value=tls_context,
            ) as suite_tls_context:
                with patch.object(
                    self.runner.urllib.request,
                    "build_opener",
                    return_value=opener,
                ) as build_opener:
                    with patch("builtins.print"):
                        self.assertEqual(0, self.runner.cmd_export_suite_jwks(args))

            suite_tls_context.assert_called_once_with(ca_certificate)
            opener.open.assert_called_once_with(
                "https://suite.example.test/jwks", timeout=10
            )
            handlers = build_opener.call_args.args
            self.assertEqual({}, handlers[0].proxies)
            self.assertIsInstance(handlers[1], self.runner.urllib.request.HTTPSHandler)
            self.assertIsInstance(handlers[2], self.runner.NoRedirect)
            response.read.assert_called_once_with(
                self.runner.MAX_SUITE_JWKS_BYTES + 1
            )
            self.assertEqual(self.suite_jwks(), json.loads(output.read_bytes()))
            self.assertEqual(0o600, output.stat().st_mode & 0o777)

    def test_submit_offer_forwards_only_the_real_notary_preauthorized_offer(
        self,
    ) -> None:
        issuer = "https://issuer.example.test"
        inline, offer_uri = self.offer_uri(issuer)
        with tempfile.TemporaryDirectory() as tmp:
            offer_file = Path(tmp) / "offer.txt"
            offer_file.write_text(offer_uri, encoding="utf-8")
            offer_file.chmod(0o600)
            args = self.runner.parse_args(
                [
                    "submit-offer",
                    "--offer-file",
                    str(offer_file),
                    "--issuer-url",
                    issuer,
                    "--suite-offer-endpoint",
                    "https://suite.example.test/run/credential_offer",
                    "--conformance-server",
                    "https://suite.example.test",
                ]
            )
            response = MagicMock()
            response.__enter__.return_value.status = 204
            opener = MagicMock()
            opener.open.return_value = response
            tls_context = MagicMock()
            with patch.object(
                self.runner.ssl,
                "create_default_context",
                return_value=tls_context,
            ) as create_context:
                with patch.object(
                    self.runner.ssl,
                    "_create_unverified_context",
                    side_effect=AssertionError("unverified TLS must not be used"),
                ):
                    with patch.object(
                        self.runner.urllib.request,
                        "build_opener",
                        return_value=opener,
                    ) as build_opener:
                        with patch("builtins.print") as printed:
                            self.assertEqual(0, self.runner.cmd_submit_offer(args))

            submitted = urllib.parse.urlsplit(opener.open.call_args.args[0])
            self.assertEqual(
                [inline],
                urllib.parse.parse_qs(submitted.query)["credential_offer"],
            )
            create_context.assert_called_once_with()
            https_handler = next(
                handler
                for handler in build_opener.call_args.args
                if isinstance(handler, self.runner.urllib.request.HTTPSHandler)
            )
            self.assertIs(tls_context, https_handler._context)
            printed.assert_called_once_with("credential offer submitted")

            opener.open.side_effect = self.runner.urllib.error.URLError(inline)
            with patch.object(
                self.runner.urllib.request, "build_opener", return_value=opener
            ):
                with self.assertRaisesRegex(
                    self.runner.RunnerError, "submission failed"
                ) as caught:
                    self.runner.cmd_submit_offer(args)
            self.assertNotIn("owner-only-code", str(caught.exception))

    def test_submit_offer_rejects_untrusted_remote_tls(self) -> None:
        issuer = "https://issuer.example.test"
        inline, offer_uri = self.offer_uri(issuer)
        with tempfile.TemporaryDirectory() as tmp:
            offer_file = Path(tmp) / "offer.txt"
            offer_file.write_text(offer_uri, encoding="utf-8")
            offer_file.chmod(0o600)
            args = self.runner.parse_args(
                [
                    "submit-offer",
                    "--offer-file",
                    str(offer_file),
                    "--issuer-url",
                    issuer,
                    "--suite-offer-endpoint",
                    "https://suite.example.test/run/credential_offer",
                    "--conformance-server",
                    "https://suite.example.test",
                ]
            )
            opener = MagicMock()
            opener.open.side_effect = self.runner.urllib.error.URLError(
                self.runner.ssl.SSLCertVerificationError(
                    1, "self-signed certificate"
                )
            )
            with patch.object(
                self.runner.urllib.request, "build_opener", return_value=opener
            ):
                with self.assertRaisesRegex(
                    self.runner.RunnerError, "submission failed"
                ) as caught:
                    self.runner.cmd_submit_offer(args)

            self.assertNotIn(inline, str(caught.exception))

    def test_submit_offer_accepts_an_explicit_local_suite_ca(self) -> None:
        issuer = "https://issuer.example.test"
        _, offer_uri = self.offer_uri(issuer)
        with tempfile.TemporaryDirectory() as tmp:
            offer_file = Path(tmp) / "offer.txt"
            offer_file.write_text(offer_uri, encoding="utf-8")
            offer_file.chmod(0o600)
            suite_ca = Path(tmp) / "suite-ca.pem"
            suite_ca.write_text("local test CA", encoding="utf-8")
            args = self.runner.parse_args(
                [
                    "submit-offer",
                    "--offer-file",
                    str(offer_file),
                    "--issuer-url",
                    issuer,
                    "--suite-offer-endpoint",
                    "https://localhost.emobix.co.uk:8443/run/credential_offer",
                    "--conformance-server",
                    "https://localhost.emobix.co.uk:8443",
                    "--suite-ca-certificate",
                    str(suite_ca),
                ]
            )
            response = MagicMock()
            response.__enter__.return_value.status = 204
            opener = MagicMock()
            opener.open.return_value = response
            tls_context = MagicMock()
            with patch.object(
                self.runner.ssl,
                "SSLContext",
                return_value=tls_context,
            ) as create_context:
                with patch.object(
                    self.runner.urllib.request,
                    "build_opener",
                    return_value=opener,
                ):
                    with patch("builtins.print"):
                        self.assertEqual(0, self.runner.cmd_submit_offer(args))

            create_context.assert_called_once_with(
                self.runner.ssl.PROTOCOL_TLS_CLIENT
            )
            tls_context.load_verify_locations.assert_called_once_with(
                cadata=b"local test CA"
            )

    def test_suite_ca_read_holds_one_descriptor_across_path_replacement(
        self,
    ) -> None:
        original = (
            b"-----BEGIN CERTIFICATE-----\n"
            b"captured-original\n"
            b"-----END CERTIFICATE-----\n"
        )
        replacement = (
            b"-----BEGIN CERTIFICATE-----\n"
            b"replacement\n"
            b"-----END CERTIFICATE-----\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            ca_path = Path(tmp) / "suite-ca.pem"
            replacement_path = Path(tmp) / "replacement.pem"
            ca_path.write_bytes(original)
            replacement_path.write_bytes(replacement)
            real_open = self.runner.os.open

            def open_then_replace(path, flags):
                descriptor = real_open(path, flags)
                self.runner.os.replace(replacement_path, ca_path)
                return descriptor

            tls_context = MagicMock()
            with patch.object(
                self.runner.os, "open", side_effect=open_then_replace
            ) as secure_open:
                with patch.object(
                    self.runner.ssl,
                    "SSLContext",
                    return_value=tls_context,
                ):
                    self.runner.suite_tls_context(ca_path)

            self.assertEqual(replacement, ca_path.read_bytes())
            secure_open.assert_called_once()
            flags = secure_open.call_args.args[1]
            for required_flag in ("O_NOFOLLOW", "O_CLOEXEC"):
                value = getattr(self.runner.os, required_flag, 0)
                if value:
                    self.assertEqual(value, flags & value)
            tls_context.load_verify_locations.assert_called_once_with(
                cadata=original.decode("ascii")
            )

    def test_suite_ca_loader_preserves_der_bytes(self) -> None:
        tls_context = MagicMock()
        certificate = b"\x30\x82\x01\x00\xff"

        self.runner.add_suite_ca(tls_context, certificate)

        tls_context.load_verify_locations.assert_called_once_with(
            cadata=certificate
        )

    def test_suite_ca_read_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "suite-ca.pem"
            target.write_text("certificate", encoding="utf-8")
            link = Path(tmp) / "suite-ca-link.pem"
            link.symlink_to(target)

            with self.assertRaisesRegex(
                self.runner.RunnerError, "opened securely"
            ):
                self.runner.read_suite_ca_certificate(link)

    def test_exported_certificate_recipe_authenticates_documented_suite_host(
        self,
    ) -> None:
        openssl = shutil.which("openssl")
        if not openssl:
            self.skipTest("openssl is required for the checked-in certificate recipe")
        issuer = "https://issuer.example.test"
        _, offer_uri = self.offer_uri(issuer)
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            certificate = work / "recipe.crt"
            private_key = work / "recipe.key"
            command = nginx_certificate_command(certificate, private_key)
            self.assertEqual(openssl, shutil.which(command[0]))
            self.assertIn(
                (
                    "subjectAltName=DNS:localhost.emobix.co.uk,DNS:localhost,"
                    "IP:127.0.0.1,IP:::1"
                ),
                command,
            )
            subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
            )

            suite_dir = work / "suite"
            suite_dir.mkdir()
            exported = work / "conformance-suite-ca.pem"
            export_args = self.runner.parse_args(
                [
                    "export-suite-ca",
                    "--suite-dir",
                    str(suite_dir),
                    "--output",
                    str(exported),
                ]
            )
            compose_commands: list[list[str]] = []

            def copy_container_certificate(
                compose_command: list[str], **_kwargs
            ) -> None:
                compose_commands.append(compose_command)
                Path(compose_command[-1]).write_bytes(certificate.read_bytes())

            with patch.object(
                self.runner,
                "run_checked",
                side_effect=copy_container_certificate,
            ):
                with patch("builtins.print"):
                    self.assertEqual(0, self.runner.cmd_export_suite_ca(export_args))

            self.assertEqual(certificate.read_bytes(), exported.read_bytes())
            self.assertEqual(0o600, exported.stat().st_mode & 0o777)
            self.assertEqual(
                f"nginx:{self.runner.SUITE_CA_CONTAINER_PATH}",
                compose_commands[0][-2],
            )

            offer_file = work / "offer.txt"
            offer_file.write_text(offer_uri, encoding="utf-8")
            offer_file.chmod(0o600)
            server = ThreadingHTTPServer(("127.0.0.1", 0), EmptyHttpsHandler)
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.minimum_version = ssl.TLSVersion.TLSv1_2
            server_context.load_cert_chain(certificate, private_key)
            server.socket = server_context.wrap_socket(
                server.socket, server_side=True
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            host = "localhost.emobix.co.uk"
            port = server.server_port
            submit_args = self.runner.parse_args(
                [
                    "submit-offer",
                    "--offer-file",
                    str(offer_file),
                    "--issuer-url",
                    issuer,
                    "--suite-offer-endpoint",
                    f"https://{host}:{port}/run/credential_offer",
                    "--conformance-server",
                    f"https://{host}:{port}",
                    "--suite-ca-certificate",
                    str(exported),
                ]
            )
            real_getaddrinfo = socket.getaddrinfo

            def loopback_suite(hostname, *args, **kwargs):
                if hostname == host:
                    hostname = "127.0.0.1"
                return real_getaddrinfo(hostname, *args, **kwargs)

            try:
                with patch.object(
                    socket, "getaddrinfo", side_effect=loopback_suite
                ):
                    with patch("builtins.print"):
                        self.assertEqual(
                            0, self.runner.cmd_submit_offer(submit_args)
                        )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_submit_offer_rejects_cleartext_suite_endpoint(self) -> None:
        issuer = "https://issuer.example.test"
        _, offer_uri = self.offer_uri(issuer)
        with tempfile.TemporaryDirectory() as tmp:
            offer_file = Path(tmp) / "offer.txt"
            offer_file.write_text(offer_uri, encoding="utf-8")
            offer_file.chmod(0o600)
            args = self.runner.parse_args(
                [
                    "submit-offer",
                    "--offer-file",
                    str(offer_file),
                    "--issuer-url",
                    issuer,
                    "--suite-offer-endpoint",
                    "http://suite.example.test/run/credential_offer",
                    "--conformance-server",
                    "http://suite.example.test",
                ]
            )
            with patch.object(
                self.runner.urllib.request, "build_opener"
            ) as build_opener:
                with self.assertRaisesRegex(self.runner.RunnerError, "HTTPS"):
                    self.runner.cmd_submit_offer(args)

            build_opener.assert_not_called()

    def test_read_offer_uses_one_no_follow_descriptor(self) -> None:
        issuer = "https://issuer.example.test"
        inline, offer_uri = self.offer_uri(issuer)
        with tempfile.TemporaryDirectory() as tmp:
            offer_file = Path(tmp) / "offer.txt"
            offer_file.write_text(offer_uri, encoding="utf-8")
            offer_file.chmod(0o600)
            real_open = self.runner.os.open
            with patch.object(Path, "read_text", side_effect=AssertionError):
                with patch.object(
                    self.runner.os, "open", wraps=real_open
                ) as secure_open:
                    self.assertEqual(
                        inline, self.runner.read_offer(offer_file, issuer)
                    )

        secure_open.assert_called_once_with(
            offer_file,
            self.runner.os.O_RDONLY
            | self.runner.os.O_CLOEXEC
            | self.runner.os.O_NOFOLLOW,
        )

    def test_read_offer_rejects_symlink(self) -> None:
        issuer = "https://issuer.example.test"
        _, offer_uri = self.offer_uri(issuer)
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "offer.txt"
            target.write_text(offer_uri, encoding="utf-8")
            target.chmod(0o600)
            link = Path(tmp) / "offer-link.txt"
            link.symlink_to(target)
            with self.assertRaisesRegex(
                self.runner.RunnerError, "could not be opened securely"
            ):
                self.runner.read_offer(link, issuer)

    def test_builder_override_pins_maven_image_by_digest(self) -> None:
        override = self.runner.BUILDER_COMPOSE_OVERRIDE_PATH.read_text(
            encoding="utf-8"
        )
        self.assertIn("maven:3-eclipse-temurin-21@sha256:", override)
        self.assertIn(
            str(self.runner.BUILDER_COMPOSE_OVERRIDE_PATH),
            self.runner.builder_command(Path("/suite"), "run", "builder"),
        )

    def test_dependency_inputs_are_dependabot_discoverable(self) -> None:
        compose_filename = re.compile(
            r"(docker-)?compose(-[\w]+)?(?:\.[\w-]+)?\.ya?ml",
            re.IGNORECASE,
        )
        self.assertIsNotNone(
            compose_filename.fullmatch(
                self.runner.BUILDER_COMPOSE_OVERRIDE_PATH.name
            )
        )
        self.assertEqual(".txt", self.runner.SUITE_REQUIREMENTS_LOCK_PATH.suffix)
        dependabot_path = self.runner.REPO_ROOT / ".github" / "dependabot.yml"
        dependabot = dependabot_path.read_text(encoding="utf-8")
        self.assertIn("package-ecosystem: docker-compose", dependabot)
        self.assertIn("package-ecosystem: pip", dependabot)

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
            self.assertEqual(
                0o600,
                (
                    output_dir / "notary-oid4vci-issuer-metadata.config.json"
                ).stat().st_mode
                & 0o777,
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

            with patch.object(shutil, "which", return_value="/usr/bin/docker"):
                with patch.object(
                    self.runner, "suite_checkout_ref", return_value="b" * 40
                ):
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
            self.runner.RunnerError, "blocked-by-suite-profile"
        ):
            self.runner.cmd_run(args)

    def test_candidate_only_metadata_scenario_runs_without_blocked_override(self) -> None:
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
            with patch("builtins.print") as printed:
                self.assertEqual(0, self.runner.cmd_run(args))
            invocation = json.loads(printed.call_args.args[0])
            self.assertIn(
                "oid4vci-1_0-issuer-metadata-test", " ".join(invocation["command"])
            )


if __name__ == "__main__":
    main()
