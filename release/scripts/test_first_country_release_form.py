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
        (self.assets / self.binary).write_text("binary\n", encoding="utf-8")
        (self.assets / self.installer).write_text("#!/bin/bash\n", encoding="utf-8")
        (self.assets / self.lock).write_text(
            json.dumps(
                {
                    "release_tag": self.tag,
                    "manifest_source_ref": "1" * 40,
                    "tag_target": "2" * 40,
                    "images": {"registry-relay": self.relay},
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
            "staging_transport": None,
            "commands": commands,
            "listener": "127.0.0.1:4242",
            "permissions": {
                "runtime_secrets_directory": "0700",
                "relay_env": "0600",
                "local_env": "0600",
            },
            "runtime": {
                "relay_config_sha256": "d" * 64,
                "runtime_manifest_sha256": "e" * 64,
                "compose_sha256": "f" * 64,
            },
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

    def test_closed_assets_bind_installer_binary_and_lock(self) -> None:
        verified = self.verify_assets()
        self.assertEqual(verified["installer_name"], self.installer)
        self.assertEqual(verified["binary_name"], self.binary)
        self.assertEqual(verified["relay_image"], self.relay)

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
        secret = b"credential-sentinel"
        (logs / "install.log").write_bytes(
            b"installed "
            + os.fsencode(str(private_root / "install" / "registryctl"))
            + b" with "
            + secret
            + b"\n"
        )

        self.module.redact_logs(
            logs,
            [secret],
            private_paths=[private_root],
        )

        retained = (logs / "install.log").read_bytes()
        self.assertNotIn(secret, retained)
        self.assertNotIn(os.fsencode(str(private_root)), retained)
        self.assertIn(b"[REDACTED]", retained)
        self.assertIn(b"[PRIVATE_PATH]", retained)

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
        (logs / "smoke.log").unlink()

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
            "staging_transport": None,
            "commands": [
                {
                    "name": name,
                    "status": "passed",
                    "exit_code": 0,
                    "log_sha256": "c" * 64,
                }
                for name in reversed(self.module.COMMAND_ORDER)
            ],
            "listener": "127.0.0.1:4242",
            "permissions": {
                "runtime_secrets_directory": "0700",
                "relay_env": "0600",
                "local_env": "0600",
            },
            "runtime": {
                "relay_config_sha256": "d" * 64,
                "runtime_manifest_sha256": "e" * 64,
                "compose_sha256": "f" * 64,
            },
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
            "staging_transport": None,
            "commands": [
                {
                    "name": name,
                    "status": "passed",
                    "exit_code": 0,
                    "log_sha256": "c" * 64,
                }
                for name in self.module.COMMAND_ORDER
            ],
            "listener": "127.0.0.1:4242",
            "permissions": {
                "runtime_secrets_directory": "0700",
                "relay_env": "0600",
                "local_env": "0600",
            },
            "runtime": {
                "relay_config_sha256": "d" * 64,
                "runtime_manifest_sha256": "e" * 64,
                "compose_sha256": "f" * 64,
            },
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

    def test_workflow_separates_beginner_runtime_from_additional_cli_assets(
        self,
    ) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(
            "Run exact first-country release-form journey before sealing", workflow
        )
        self.assertIn("first-country-release-form.py run", workflow)
        self.assertIn("Verify candidate CLI install on ${{ matrix.asset }}", workflow)
        self.assertIn("Install exact candidate CLI and verify authoring path", workflow)
        self.assertNotIn(
            "Verify candidate beginner journey on ${{ matrix.asset }}", workflow
        )
        self.assertNotIn("DOCKER_DEFAULT_PLATFORM=linux/amd64", workflow)


if __name__ == "__main__":
    main()
