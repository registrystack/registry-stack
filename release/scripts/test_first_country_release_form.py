#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import platform
import subprocess
import tempfile
from pathlib import Path
from unittest import TestCase, main, mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release" / "scripts" / "first-country-release-form.py"
WORKFLOW = ROOT / ".github" / "workflows" / "release-candidate.yml"


def load_module():
    spec = importlib.util.spec_from_file_location("first_country_release_form", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError("could not load first-country release-form module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FirstCountryReleaseFormTest(TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.assets = self.root / "assets"
        self.assets.mkdir()
        self.tag = "v1.2.3"
        self.binary = f"registryctl-{self.tag}-linux-amd64"
        self.installer = f"registryctl-{self.tag}-install.sh"
        self.lock = f"registryctl-{self.tag}-image-lock.json"
        self.relay = "ghcr.io/registrystack/registry-relay@sha256:" + "a" * 64
        self.notary = "ghcr.io/registrystack/registry-notary@sha256:" + "b" * 64
        self.postgresql = "docker.io/library/postgres@sha256:" + "c" * 64
        (self.assets / self.binary).write_text("binary\n", encoding="utf-8")
        (self.assets / self.installer).write_text("#!/bin/bash\n", encoding="utf-8")
        (self.assets / self.lock).write_text(
            json.dumps(
                {
                    "schema_version": "registryctl.release_image_lock.v2",
                    "release_tag": self.tag,
                    "manifest_source_ref": "1" * 40,
                    "tag_target": "2" * 40,
                    "platform": "linux/amd64",
                    "images": {
                        "registry-relay": self.relay,
                        "registry-notary": self.notary,
                        "postgresql": self.postgresql,
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        checksums = []
        for name in (self.installer, self.binary, self.lock):
            digest = hashlib.sha256((self.assets / name).read_bytes()).hexdigest()
            checksums.append(f"{digest}  {name}")
        (self.assets / "SHA256SUMS").write_text(
            "\n".join(checksums) + "\n", encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def verify_assets(self):
        with (
            mock.patch.object(platform, "system", return_value="Linux"),
            mock.patch.object(platform, "machine", return_value="x86_64"),
        ):
            return self.module.verify_asset_set(self.assets, self.tag)

    def write_valid_report_evidence(self):
        verified = self.verify_assets()
        evidence = self.root / "evidence"
        logs = evidence / "logs"
        logs.mkdir(parents=True)
        commands = []
        for name in self.module.COMMAND_ORDER:
            if name == "allowed":
                contents = (
                    json.dumps(self.module.ALLOWED_EVIDENCE, sort_keys=True) + "\n"
                )
            else:
                contents = f"{name} completed\n"
            log = logs / f"{name}.log"
            log.write_text(contents, encoding="utf-8")
            commands.append(
                {
                    "name": name,
                    "status": "passed",
                    "exit_code": 0,
                    "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
                }
            )
        report = {
            "schema_version": self.module.SCHEMA,
            "status": "passed",
            "release_tag": self.tag,
            "manifest_source_ref": "1" * 40,
            "tag_target": "2" * 40,
            "platform_asset": self.binary,
            "asset_sha256": verified["assets"],
            "release_image_lock_sha256": verified["assets"][self.lock],
            "relay_image": self.relay,
            "notary_image": self.notary,
            "postgresql_image": self.postgresql,
            "staging_transport": None,
            "notary_staging_transport": None,
            "commands": commands,
            "listeners": {
                "relay": self.module.RELAY_LISTENER,
                "notary": self.module.NOTARY_LISTENER,
            },
            "permissions": {
                "runtime_secrets_directory": "0700",
                **{name: "0600" for name in self.module.SECRET_FILES},
            },
            "runtime": {
                "relay_config_sha256": "d" * 64,
                "runtime_manifest_sha256": "e" * 64,
                "compose_sha256": "f" * 64,
                "notary_config_sha256": "a" * 64,
                "topology": "combined_notary",
                "workbook_classification": "operator_owned_source_data",
            },
            "smoke": json.loads(json.dumps(self.module.SMOKE_EVIDENCE)),
            "redaction": {"status": "passed", "generated_files_scanned": 20},
        }
        path = evidence / "first-country-release-form.json"
        path.write_text(json.dumps(report), encoding="utf-8")
        return path, report, logs

    def verify_report(self, path: Path) -> None:
        with (
            mock.patch.object(platform, "system", return_value="Linux"),
            mock.patch.object(platform, "machine", return_value="x86_64"),
        ):
            self.module.verify_report(path, self.assets, self.tag)

    def write_smoke_report(self, topology: str) -> Path:
        outcomes = dict(self.module.RELAY_SMOKE_OUTCOMES)
        if topology == "combined_notary":
            outcomes.update(self.module.NOTARY_SMOKE_OUTCOMES)
        runtime = self.root / ".registry-stack/runtime/local"
        runtime.mkdir(parents=True, exist_ok=True)
        report = {
            "schema_version": "registryctl.smoke.v1",
            "base_url": "http://127.0.0.1:4242",
            "passed": True,
            "checks": [
                {
                    "name": name,
                    "method": "GET",
                    "path": "/bounded",
                    "expected_status": status,
                    "actual_status": status,
                    "passed": True,
                    "error": None,
                }
                for name, status in outcomes.items()
            ],
        }
        path = runtime / "smoke-results.json"
        path.write_text(json.dumps(report), encoding="utf-8")
        return path

    def write_combined_runtime(self) -> Path:
        files = {
            ".registry-stack/build/local/private/relay/config/relay.yaml": "relay\n",
            ".registry-stack/build/local/private/notary/config/notary.yaml": (
                "notary\n"
            ),
            ".registry-stack/build/local/artifact-manifest.json": "artifacts\n",
            "data/public_works_projects.xlsx": "workbook\n",
            ".registry-stack/runtime/local/compose.yaml": "services: {}\n",
            ".registry-stack/runtime/local/secrets/local.env": "secret\n",
        }
        for relative, contents in files.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents, encoding="utf-8")
        manifest = {
            "schema_version": "registryctl.local_runtime.v2",
            "environment": "local",
            "relay_image": self.relay,
            "compose_digest": self.module.digest_uri(
                self.root / ".registry-stack/runtime/local/compose.yaml"
            ),
            "artifact_manifest_digest": self.module.digest_uri(
                self.root / ".registry-stack/build/local/artifact-manifest.json"
            ),
            "relay_config_digest": self.module.digest_uri(
                self.root
                / ".registry-stack/build/local/private/relay/config/relay.yaml"
            ),
            "workbook_digest": self.module.digest_uri(
                self.root / "data/public_works_projects.xlsx"
            ),
            "workbook_classification": "operator_owned_source_data",
            "workbook_project_file": "data/public_works_projects.xlsx",
            "workbook_runtime_path": "/data/public_works_projects.xlsx",
            "match_principal": "district-7",
            "runtime_uid": "1000",
            "runtime_gid": "1000",
            "runtime_files": {
                "compose.yaml": self.module.digest_uri(
                    self.root / ".registry-stack/runtime/local/compose.yaml"
                )
            },
            "topology": "combined_notary",
            "notary": {
                "notary_image": self.notary,
                "postgresql_image": self.postgresql,
            },
        }
        path = self.root / ".registry-stack/runtime/local/manifest.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return path

    def test_closed_assets_bind_installer_binary_and_lock(self) -> None:
        verified = self.verify_assets()
        self.assertEqual(verified["installer_name"], self.installer)
        self.assertEqual(verified["binary_name"], self.binary)
        self.assertEqual(verified["relay_image"], self.relay)
        self.assertEqual(verified["notary_image"], self.notary)
        self.assertEqual(verified["postgresql_image"], self.postgresql)

    def test_command_order_proves_relay_then_notary_continuation(self) -> None:
        self.assertEqual(
            self.module.COMMAND_ORDER,
            (
                "install",
                "version",
                "init",
                "preflight",
                "relay_start",
                "relay_smoke",
                "add_notary",
                "combined_test",
                "combined_restart",
                "combined_smoke",
                "denied",
                "allowed",
                "inspect",
                "listeners",
                "stop",
            ),
        )

    def test_image_lock_without_notary_fails_closed(self) -> None:
        lock = json.loads((self.assets / self.lock).read_text(encoding="utf-8"))
        del lock["images"]["registry-notary"]
        (self.assets / self.lock).write_text(json.dumps(lock), encoding="utf-8")
        digest = hashlib.sha256((self.assets / self.lock).read_bytes()).hexdigest()
        lines = (self.assets / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
        (self.assets / "SHA256SUMS").write_text(
            "\n".join(
                f"{digest}  {self.lock}" if self.lock in line else line
                for line in lines
            )
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            self.module.ReleaseFormError, "image set is not closed"
        ):
            self.verify_assets()

    def test_missing_installer_checksum_fails_closed(self) -> None:
        lines = (self.assets / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
        (self.assets / "SHA256SUMS").write_text(
            "\n".join(line for line in lines if self.installer not in line) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            self.module.ReleaseFormError, "does not bind exact asset"
        ):
            self.verify_assets()

    def test_symlinked_asset_fails_closed(self) -> None:
        external = self.root / "external"
        external.write_text("binary\n", encoding="utf-8")
        (self.assets / self.binary).unlink()
        (self.assets / self.binary).symlink_to(external)
        with self.assertRaisesRegex(self.module.ReleaseFormError, "non-symlink"):
            self.verify_assets()

    def test_mismatched_staging_digest_fails_closed(self) -> None:
        mismatch = "ghcr.io/registrystack/registry-relay-candidate@sha256:" + "b" * 64
        with self.assertRaisesRegex(self.module.ReleaseFormError, "does not match"):
            self.module.validate_relay_override(self.relay, mismatch)

    def test_non_candidate_staging_repository_fails_closed(self) -> None:
        override = "ghcr.io/registrystack/registry-relay@sha256:" + "a" * 64
        with self.assertRaisesRegex(
            self.module.ReleaseFormError, "private candidate repository"
        ):
            self.module.validate_relay_override(self.relay, override)

    def test_mismatched_notary_staging_digest_fails_closed(self) -> None:
        mismatch = (
            "ghcr.io/registrystack/registry-notary-candidate@sha256:" + "d" * 64
        )
        with self.assertRaisesRegex(self.module.ReleaseFormError, "does not match"):
            self.module.validate_notary_override(self.notary, mismatch)

    def test_non_candidate_notary_staging_repository_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            self.module.ReleaseFormError, "private candidate repository"
        ):
            self.module.validate_notary_override(self.notary, self.notary)

    def test_complete_runtime_rejects_cli_only_platforms(self) -> None:
        with (
            mock.patch.object(platform, "system", return_value="Darwin"),
            mock.patch.object(platform, "machine", return_value="arm64"),
            self.assertRaisesRegex(
                self.module.ReleaseFormError,
                "release-gated only on Linux amd64",
            ),
        ):
            self.module.beginner_runtime_asset(self.tag)

    def test_authenticated_evidence_rejects_duplicate_match_rows(self) -> None:
        body = json.dumps(
            {
                "data": [
                    {
                        "project_id": "project-1",
                        "district_code": "D-01",
                        "sector": "transport",
                        "status": "active",
                    },
                    {
                        "project_id": "project-2",
                        "district_code": "D-02",
                        "sector": "water",
                        "status": "planned",
                    },
                ]
            }
        )
        with self.assertRaisesRegex(
            self.module.ReleaseFormError, "unexpected row count"
        ):
            self.module.summarize_records_response(
                "match",
                200,
                body,
                expected_rows=1,
                expected_fields=self.module.MATCH_FIELDS,
            )

    def test_authenticated_evidence_rejects_extra_match_field(self) -> None:
        body = json.dumps(
            {
                "data": [
                    {
                        "project_id": "project-1",
                        "district_code": "D-01",
                        "sector": "transport",
                        "status": "active",
                        "unexpected": "value",
                    }
                ]
            }
        )
        with self.assertRaisesRegex(
            self.module.ReleaseFormError, "unexpected disclosed fields"
        ):
            self.module.summarize_records_response(
                "match",
                200,
                body,
                expected_rows=1,
                expected_fields=self.module.MATCH_FIELDS,
            )

    def test_authenticated_evidence_rejects_nonempty_no_match(self) -> None:
        body = json.dumps({"data": [{"project_id": "unexpected"}]})
        with self.assertRaisesRegex(
            self.module.ReleaseFormError, "unexpected row count"
        ):
            self.module.summarize_records_response(
                "no-match",
                200,
                body,
                expected_rows=0,
                expected_fields=None,
            )

    def test_authenticated_evidence_rejects_non_success_status(self) -> None:
        with self.assertRaisesRegex(
            self.module.ReleaseFormError, "did not return HTTP 200"
        ):
            self.module.summarize_records_response(
                "match",
                403,
                json.dumps({"data": []}),
                expected_rows=1,
                expected_fields=self.module.MATCH_FIELDS,
            )

    def test_smoke_requires_all_notary_negative_and_positive_outcomes(self) -> None:
        path = self.write_smoke_report("combined_notary")
        report = json.loads(path.read_text(encoding="utf-8"))
        report["checks"] = [
            check
            for check in report["checks"]
            if check["name"]
            != "matching evaluation returns the accepted predicate"
        ]
        path.write_text(json.dumps(report), encoding="utf-8")

        with self.assertRaisesRegex(
            self.module.ReleaseFormError, "exact required outcomes"
        ):
            self.module.smoke_outcomes(self.root, "combined_notary")

    def test_smoke_rejects_failed_notary_denial(self) -> None:
        path = self.write_smoke_report("combined_notary")
        report = json.loads(path.read_text(encoding="utf-8"))
        denial = next(
            check
            for check in report["checks"]
            if check["name"] == "denied under-scoped Notary caller"
        )
        denial["actual_status"] = 200
        denial["passed"] = False
        denial["error"] = "bounded failure"
        report["passed"] = False
        path.write_text(json.dumps(report), encoding="utf-8")

        with self.assertRaisesRegex(
            self.module.ReleaseFormError, "check is invalid"
        ):
            self.module.smoke_outcomes(self.root, "combined_notary")

    def test_runtime_inspection_accepts_current_combined_manifest(self) -> None:
        self.write_combined_runtime()

        inspected = self.module.read_runtime_inspection(
            self.root,
            expected_relay_image=self.relay,
            expected_notary_image=self.notary,
            expected_postgresql_image=self.postgresql,
        )

        self.assertEqual(inspected["topology"], "combined_notary")
        self.assertEqual(
            inspected["workbook_classification"],
            "operator_owned_source_data",
        )
        self.assertRegex(inspected["notary_config_sha256"], r"^[0-9a-f]{64}$")

    def test_runtime_inspection_accepts_current_relay_only_manifest(self) -> None:
        path = self.write_combined_runtime()
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["topology"] = "relay_only"
        del manifest["notary"]
        path.write_text(json.dumps(manifest), encoding="utf-8")

        inspected = self.module.read_runtime_inspection(
            self.root,
            expected_relay_image=self.relay,
            expected_notary_image=None,
            expected_postgresql_image=None,
        )

        self.assertEqual(inspected["topology"], "relay_only")
        self.assertEqual(inspected["notary_config_sha256"], "")

    def test_runtime_inspection_rejects_wrong_workbook_classification(self) -> None:
        path = self.write_combined_runtime()
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["workbook_classification"] = "authored_project_input"
        path.write_text(json.dumps(manifest), encoding="utf-8")

        with self.assertRaisesRegex(
            self.module.ReleaseFormError, "workbook classification is invalid"
        ):
            self.module.read_runtime_inspection(
                self.root,
                expected_relay_image=self.relay,
                expected_notary_image=self.notary,
                expected_postgresql_image=self.postgresql,
            )

    def test_runtime_inspection_rejects_missing_notary_manifest(self) -> None:
        path = self.write_combined_runtime()
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["notary"] = None
        path.write_text(json.dumps(manifest), encoding="utf-8")

        with self.assertRaisesRegex(
            self.module.ReleaseFormError, "Notary manifest is incomplete"
        ):
            self.module.read_runtime_inspection(
                self.root,
                expected_relay_image=self.relay,
                expected_notary_image=self.notary,
                expected_postgresql_image=self.postgresql,
            )

    def test_runtime_inspection_rejects_wrong_notary_image(self) -> None:
        path = self.write_combined_runtime()
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["notary"]["notary_image"] = (
            "ghcr.io/registrystack/registry-notary@sha256:" + "0" * 64
        )
        path.write_text(json.dumps(manifest), encoding="utf-8")

        with self.assertRaisesRegex(
            self.module.ReleaseFormError,
            "Notary manifest is incomplete",
        ):
            self.module.read_runtime_inspection(
                self.root,
                expected_relay_image=self.relay,
                expected_notary_image=self.notary,
                expected_postgresql_image=self.postgresql,
            )

    def test_listener_verification_requires_notary_loopback(self) -> None:
        logs = self.root / "logs"
        logs.mkdir()
        responses = [
            subprocess.CompletedProcess([], 0, self.module.RELAY_LISTENER),
            subprocess.CompletedProcess([], 0, "0.0.0.0:4255"),
        ]
        with (
            mock.patch.object(
                self.module.subprocess, "run", side_effect=responses
            ) as run,
            self.assertRaisesRegex(
                self.module.ReleaseFormError,
                "Notary is not published on the exact IPv4 loopback",
            ),
        ):
            self.module.verify_loopback_listeners(self.root, {}, logs)

        self.assertEqual(run.call_args_list[1].args[0][-2:], ["notary-network", "8081"])

    def test_authenticated_evidence_uses_distinct_credentials_and_redacted_log(
        self,
    ) -> None:
        logs = self.root / "logs"
        logs.mkdir()
        match_key = "match-key-sentinel"
        no_match_key = "no-match-key-sentinel"
        match_row = {
            "project_id": "private-project-value",
            "district_code": "private-district-value",
            "sector": "private-sector-value",
            "status": "private-status-value",
        }
        responses = [
            subprocess.CompletedProcess(
                [],
                0,
                json.dumps({"data": [match_row]}) + "\nREGISTRYCTL_HTTP_STATUS:200",
            ),
            subprocess.CompletedProcess(
                [],
                0,
                json.dumps({"data": []}) + "\nREGISTRYCTL_HTTP_STATUS:200",
            ),
        ]
        with mock.patch.object(
            self.module.subprocess, "run", side_effect=responses
        ) as run:
            self.module.run_authenticated_records_evidence(
                project=self.root,
                env={},
                logs=logs,
                match_key=match_key,
                no_match_key=no_match_key,
            )

        self.assertEqual(run.call_count, 2)
        match_command = run.call_args_list[0].args[0]
        no_match_command = run.call_args_list[1].args[0]
        match_headers = run.call_args_list[0].kwargs["input"]
        no_match_headers = run.call_args_list[1].kwargs["input"]
        self.assertIn(f"Authorization: Bearer {match_key}", match_headers)
        self.assertIn(f"Authorization: Bearer {no_match_key}", no_match_headers)
        self.assertIn(f"Data-Purpose: {self.module.RECORDS_PURPOSE}", match_headers)
        self.assertIn(f"Data-Purpose: {self.module.RECORDS_PURPOSE}", no_match_headers)
        self.assertNotIn(match_key, " ".join(match_command))
        self.assertNotIn(no_match_key, " ".join(no_match_command))
        self.assertEqual(match_command[-1], self.module.RECORDS_URL)
        self.assertEqual(no_match_command[-1], self.module.RECORDS_URL)
        self.assertNotIn("?", self.module.RECORDS_URL)
        retained = (logs / "allowed.log").read_text(encoding="utf-8")
        for secret in [match_key, no_match_key, *match_row.values()]:
            self.assertNotIn(secret, retained)
        self.assertEqual(
            json.loads(retained),
            [
                {
                    "field_names": [
                        "district_code",
                        "project_id",
                        "sector",
                        "status",
                    ],
                    "http_status": 200,
                    "request": "match",
                    "row_count": 1,
                },
                {
                    "field_names": [],
                    "http_status": 200,
                    "request": "no-match",
                    "row_count": 0,
                },
            ],
        )

    def test_log_redaction_removes_credentials_and_private_paths(self) -> None:
        logs = self.root / "logs"
        logs.mkdir()
        private_root = self.root / "private-work"
        redaction_marker = b"redaction-marker"
        (logs / "install.log").write_bytes(
            b"installed "
            + os.fsencode(str(private_root / "install" / "registryctl"))
            + b" with "
            + redaction_marker
            + b"\n"
        )

        self.module.redact_logs(
            logs,
            [redaction_marker],
            private_paths=[private_root],
        )

        retained = (logs / "install.log").read_bytes()
        self.assertNotIn(redaction_marker, retained)
        self.assertNotIn(os.fsencode(str(private_root)), retained)
        self.assertIn(b"[REDACTED]", retained)
        self.assertIn(b"[PRIVATE_PATH]", retained)

    def test_env_redaction_collects_credentials_not_public_runtime_values(self) -> None:
        env_file = self.root / "postgres.env"
        env_file.write_bytes(
            b"POSTGRES_USER=registryctl_bootstrap\n"
            b"PGDATA=/var/lib/postgresql/data/pgdata\n"
            b"REGISTRYCTL_LOCAL_WORKLOAD_PUBLIC_JWK=public-jwk\n"
            b"REGISTRYCTL_LOCAL_RELAY_MATCH_KEY_HASH=public-fingerprint\n"
            b"POSTGRES_PASSWORD=private-password\n"
            b"REGISTRY_RELAY_AUDIT_HASH_SECRET=private-audit-secret\n"
        )

        values = self.module.credential_env_values(env_file)

        self.assertIn(b"private-password", values)
        self.assertIn(b"private-audit-secret", values)
        self.assertNotIn(b"registryctl_bootstrap", values)
        self.assertNotIn(b"/var/lib/postgresql/data/pgdata", values)
        self.assertNotIn(b"public-jwk", values)
        self.assertNotIn(b"public-fingerprint", values)

    def test_partial_secret_directory_still_yields_failure_redaction_values(
        self,
    ) -> None:
        secrets = self.root / "secrets"
        secrets.mkdir()
        (secrets / "local.env").write_text(
            "REGISTRYCTL_LOCAL_RELAY_MATCH_KEY_RAW=private-key\n",
            encoding="utf-8",
        )
        (secrets / "relay-workload-token").write_text(
            "private-token\n",
            encoding="utf-8",
        )

        values = self.module.available_secret_values(secrets)

        self.assertIn(b"private-key", values)
        self.assertIn(b"private-token", values)

    def test_local_evidence_credentials_must_be_distinct(self) -> None:
        local_env = self.root / "local.env"
        local_env.write_text(
            "\n".join(
                [
                    f"{self.module.MATCH_KEY_ENV}=same-key",
                    f"{self.module.NO_MATCH_KEY_ENV}=same-key",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(self.module.ReleaseFormError, "must be distinct"):
            self.module.required_local_credentials(local_env)

    def test_report_verifies_closed_sibling_evidence_logs(self) -> None:
        path, _, _ = self.write_valid_report_evidence()

        self.verify_report(path)

    def test_report_rejects_duplicate_json_keys(self) -> None:
        path, _, _ = self.write_valid_report_evidence()
        contents = path.read_text(encoding="utf-8")
        path.write_text(
            contents.replace(
                '"status": "passed"',
                '"status": "passed", "status": "passed"',
                1,
            ),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            self.module.ReleaseFormError, "not valid closed JSON"
        ):
            self.verify_report(path)

    def test_report_rejects_missing_evidence_log(self) -> None:
        path, _, logs = self.write_valid_report_evidence()
        (logs / "combined_smoke.log").unlink()

        with self.assertRaisesRegex(
            self.module.ReleaseFormError, "log set is not closed"
        ):
            self.verify_report(path)

    def test_report_rejects_extra_evidence_log(self) -> None:
        path, _, logs = self.write_valid_report_evidence()
        (logs / "unclaimed.log").write_text("unclaimed\n", encoding="utf-8")

        with self.assertRaisesRegex(
            self.module.ReleaseFormError, "log set is not closed"
        ):
            self.verify_report(path)

    def test_report_rejects_forged_evidence_log_hash(self) -> None:
        path, report, _ = self.write_valid_report_evidence()
        report["commands"][0]["log_sha256"] = "0" * 64
        path.write_text(json.dumps(report), encoding="utf-8")

        with self.assertRaisesRegex(
            self.module.ReleaseFormError, "log digest does not match"
        ):
            self.verify_report(path)

    def test_report_rejects_wrong_allowed_summary(self) -> None:
        path, report, logs = self.write_valid_report_evidence()
        allowed = json.loads((logs / "allowed.log").read_text(encoding="utf-8"))
        allowed[0]["row_count"] = 2
        (logs / "allowed.log").write_text(
            json.dumps(allowed, sort_keys=True) + "\n", encoding="utf-8"
        )
        allowed_command = next(
            command for command in report["commands"] if command["name"] == "allowed"
        )
        allowed_command["log_sha256"] = hashlib.sha256(
            (logs / "allowed.log").read_bytes()
        ).hexdigest()
        path.write_text(json.dumps(report), encoding="utf-8")

        with self.assertRaisesRegex(self.module.ReleaseFormError, "exact value-free"):
            self.verify_report(path)

    def test_report_rejects_missing_notary_smoke_outcome(self) -> None:
        path, report, _ = self.write_valid_report_evidence()
        report["smoke"]["combined_notary"] = report["smoke"][
            "combined_notary"
        ][:-1]
        path.write_text(json.dumps(report), encoding="utf-8")

        with self.assertRaisesRegex(
            self.module.ReleaseFormError, "does not prove"
        ):
            self.verify_report(path)

    def test_report_rejects_malformed_allowed_summary(self) -> None:
        path, report, logs = self.write_valid_report_evidence()
        (logs / "allowed.log").write_text("{not-json}\n", encoding="utf-8")
        allowed_command = next(
            command for command in report["commands"] if command["name"] == "allowed"
        )
        allowed_command["log_sha256"] = hashlib.sha256(
            (logs / "allowed.log").read_bytes()
        ).hexdigest()
        path.write_text(json.dumps(report), encoding="utf-8")

        with self.assertRaisesRegex(
            self.module.ReleaseFormError, "not valid closed JSON"
        ):
            self.verify_report(path)

    def test_report_rejects_value_bearing_allowed_summary(self) -> None:
        path, report, logs = self.write_valid_report_evidence()
        allowed = json.loads((logs / "allowed.log").read_text(encoding="utf-8"))
        allowed[0]["record_values"] = {"project_id": "private-project-value"}
        (logs / "allowed.log").write_text(
            json.dumps(allowed, sort_keys=True) + "\n", encoding="utf-8"
        )
        allowed_command = next(
            command for command in report["commands"] if command["name"] == "allowed"
        )
        allowed_command["log_sha256"] = hashlib.sha256(
            (logs / "allowed.log").read_bytes()
        ).hexdigest()
        path.write_text(json.dumps(report), encoding="utf-8")

        with self.assertRaisesRegex(self.module.ReleaseFormError, "exact value-free"):
            self.verify_report(path)

    def test_report_rejects_reordered_or_failed_journey(self) -> None:
        verified = self.verify_assets()
        report = {
            "schema_version": self.module.SCHEMA,
            "status": "passed",
            "release_tag": self.tag,
            "manifest_source_ref": "1" * 40,
            "tag_target": "2" * 40,
            "platform_asset": self.binary,
            "asset_sha256": verified["assets"],
            "release_image_lock_sha256": verified["assets"][self.lock],
            "relay_image": self.relay,
            "notary_image": self.notary,
            "postgresql_image": self.postgresql,
            "staging_transport": None,
            "notary_staging_transport": None,
            "commands": [
                {
                    "name": name,
                    "status": "passed",
                    "exit_code": 0,
                    "log_sha256": "c" * 64,
                }
                for name in reversed(self.module.COMMAND_ORDER)
            ],
            "listeners": {
                "relay": self.module.RELAY_LISTENER,
                "notary": self.module.NOTARY_LISTENER,
            },
            "permissions": {
                "runtime_secrets_directory": "0700",
                **{name: "0600" for name in self.module.SECRET_FILES},
            },
            "runtime": {
                "relay_config_sha256": "d" * 64,
                "runtime_manifest_sha256": "e" * 64,
                "compose_sha256": "f" * 64,
                "notary_config_sha256": "a" * 64,
                "topology": "combined_notary",
                "workbook_classification": "operator_owned_source_data",
            },
            "smoke": json.loads(json.dumps(self.module.SMOKE_EVIDENCE)),
            "redaction": {"status": "passed", "generated_files_scanned": 20},
        }
        path = self.root / "report.json"
        path.write_text(json.dumps(report), encoding="utf-8")
        with (
            self.assertRaisesRegex(self.module.ReleaseFormError, "does not prove"),
            mock.patch.object(platform, "system", return_value="Linux"),
            mock.patch.object(platform, "machine", return_value="x86_64"),
        ):
            self.module.verify_report(path, self.assets, self.tag)

    def test_report_rejects_unknown_field(self) -> None:
        verified = self.verify_assets()
        report = {
            "schema_version": self.module.SCHEMA,
            "status": "passed",
            "release_tag": self.tag,
            "manifest_source_ref": "1" * 40,
            "tag_target": "2" * 40,
            "platform_asset": self.binary,
            "asset_sha256": verified["assets"],
            "release_image_lock_sha256": verified["assets"][self.lock],
            "relay_image": self.relay,
            "notary_image": self.notary,
            "postgresql_image": self.postgresql,
            "staging_transport": None,
            "notary_staging_transport": None,
            "commands": [
                {
                    "name": name,
                    "status": "passed",
                    "exit_code": 0,
                    "log_sha256": "c" * 64,
                }
                for name in self.module.COMMAND_ORDER
            ],
            "listeners": {
                "relay": self.module.RELAY_LISTENER,
                "notary": self.module.NOTARY_LISTENER,
            },
            "permissions": {
                "runtime_secrets_directory": "0700",
                **{name: "0600" for name in self.module.SECRET_FILES},
            },
            "runtime": {
                "relay_config_sha256": "d" * 64,
                "runtime_manifest_sha256": "e" * 64,
                "compose_sha256": "f" * 64,
                "notary_config_sha256": "a" * 64,
                "topology": "combined_notary",
                "workbook_classification": "operator_owned_source_data",
            },
            "smoke": json.loads(json.dumps(self.module.SMOKE_EVIDENCE)),
            "redaction": {"status": "passed", "generated_files_scanned": 20},
            "unexpected": True,
        }
        path = self.root / "report-with-extra-field.json"
        path.write_text(json.dumps(report), encoding="utf-8")
        with (
            self.assertRaisesRegex(
                self.module.ReleaseFormError, "fields are not closed"
            ),
            mock.patch.object(platform, "system", return_value="Linux"),
            mock.patch.object(platform, "machine", return_value="x86_64"),
        ):
            self.module.verify_report(path, self.assets, self.tag)

    def test_workflow_runs_one_linux_install_and_authoring_smoke_after_assembly(
        self,
    ) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(
            "Assemble public payload and run install and authoring smoke", workflow
        )
        self.assertIn("first-country-release-form.py run", workflow)
        self.assertIn("first-country-release-form.py verify", workflow)
        self.assertIn("> SHA256SUMS", workflow)
        self.assertIn("rm candidate/bundle-root/SHA256SUMS", workflow)
        self.assertNotIn(
            "Verify candidate beginner journey on ${{ matrix.asset }}", workflow
        )
        self.assertNotIn("DOCKER_DEFAULT_PLATFORM=linux/amd64", workflow)


if __name__ == "__main__":
    main()
