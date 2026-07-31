#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import os
import platform
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from unittest import TestCase, main, mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release" / "scripts" / "first-country-release-form.py"
WORKFLOW = ROOT / ".github" / "workflows" / "release-candidate.yml"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"


def load_module():
    spec = importlib.util.spec_from_file_location("first_country_release_form", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError("could not load first-country release-form module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixture_text(identifier: str) -> str:
    return hashlib.sha256(f"first-country-fixture:{identifier}".encode()).hexdigest()


def fixture_bytes(identifier: str) -> bytes:
    return fixture_text(identifier).encode()


def write_report_fixture(path: Path, report: dict) -> None:
    path.write_text(json.dumps(report), encoding="utf-8")


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
        self.release_lock = "registry-release-lock.v1.json"
        self.docs_archive = f"registry-docs-{self.tag}.tar.gz"
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
                    "tag_target": "1" * 40,
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
        (self.assets / self.release_lock).write_text(
            '{"signed_payload":"fixture"}\n', encoding="utf-8"
        )
        opencrvs_name = "opencrvs-events-api-overlay-v1.sh"
        public_source_name = "jsonplaceholder-todo-live-overlay-v1.sh"
        opencrvs_overlay = b"#!/bin/sh\nprintf 'opencrvs fixture\\n'\n"
        public_source_overlay = b"#!/bin/sh\nprintf 'public source fixture\\n'\n"
        self.docs_files = {
            "configure/oauth-client-credentials.md": b"# OAuth fixture\n",
            "examples/registryctl/opencrvs-events-api-overlay-v1.sh": (
                opencrvs_overlay
            ),
            "examples/registryctl/opencrvs-events-api-overlay-v1.sh.sha256": (
                f"{hashlib.sha256(opencrvs_overlay).hexdigest()}  {opencrvs_name}\n".encode()
            ),
            "examples/registryctl/jsonplaceholder-todo-live-overlay-v1.sh": (
                public_source_overlay
            ),
            "examples/registryctl/jsonplaceholder-todo-live-overlay-v1.sh.sha256": (
                f"{hashlib.sha256(public_source_overlay).hexdigest()}  {public_source_name}\n".encode()
            ),
            "operate/approve-initial-baseline.md": b"# Approval fixture\n",
            "tutorials/author-registry-project.md": b"# HTTP fixture\n",
            "tutorials/publish-spreadsheet-secured-registry-api.md": (
                b"# Spreadsheet fixture\n"
            ),
            "tutorials/configure-project-script-adapter.md": (
                b"# Script adapter fixture\n"
            ),
            "tutorials/verify-opencrvs-claims.md": b"# OpenCRVS fixture\n",
        }
        self.write_docs_archive()
        self.write_checksums()

    @staticmethod
    def docs_tree_digest(files):
        digest = hashlib.sha256()
        for name, contents in sorted(files.items()):
            digest.update(f"{name}\0-\0".encode())
            digest.update(contents)
            digest.update(b"\0")
        return digest.hexdigest()

    def write_docs_archive(self, *, files=None, unsafe_member=None) -> None:
        files = dict(self.docs_files if files is None else files)
        metadata = {
            "schema_version": "registry-docs.archive-bundle.v3",
            "release_tag": self.tag,
            "root_tree_sha256": self.docs_tree_digest(files),
            "version_path": f"/v/{self.tag.removeprefix('v')}/",
            "version_tree_sha256": self.docs_tree_digest(files),
        }
        archive_path = self.assets / self.docs_archive
        with tarfile.open(archive_path, "w:gz") as archive:
            metadata_bytes = (json.dumps(metadata, sort_keys=True) + "\n").encode()
            metadata_entry = tarfile.TarInfo("metadata.json")
            metadata_entry.mode = 0o644
            metadata_entry.size = len(metadata_bytes)
            archive.addfile(metadata_entry, io.BytesIO(metadata_bytes))
            for tree in ("root", "version"):
                directories = {tree}
                for name in files:
                    parts = Path(name).parts
                    directories.update(
                        f"{tree}/{'/'.join(parts[:index])}"
                        for index in range(1, len(parts))
                    )
                for directory in sorted(directories):
                    entry = tarfile.TarInfo(directory)
                    entry.type = tarfile.DIRTYPE
                    entry.mode = 0o755
                    archive.addfile(entry)
                for name, contents in sorted(files.items()):
                    entry = tarfile.TarInfo(f"{tree}/{name}")
                    entry.mode = 0o644
                    entry.size = len(contents)
                    archive.addfile(entry, io.BytesIO(contents))
            if unsafe_member is not None:
                archive.addfile(unsafe_member)

    def write_checksums(self) -> None:
        checksums = []
        for name in (
            self.installer,
            self.binary,
            self.lock,
            self.release_lock,
            self.docs_archive,
        ):
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

    def secret_staging_models(self):
        volume_prefix = "release"
        def stagers(contract):
            return {
                service_name: {
                    "network_mode": "none",
                    "user": "0:0",
                    "read_only": True,
                    "cap_add": ["CHOWN", "DAC_READ_SEARCH"],
                    "cap_drop": ["ALL"],
                    "security_opt": ["no-new-privileges:true"],
                    "tmpfs": ["/tmp"],
                    "restart": "no",
                    "volumes": [
                        {
                            "type": "volume",
                            "source": (
                                f"{volume_prefix}-operator-files-{stage_id}"
                            ),
                            "target": f"/registryctl-stage/output/{stage_id}",
                            "volume": {},
                        }
                        for stage_id in projection["outputs"]
                    ],
                    "secrets": [
                        {
                            "source": f"registry-{file_id}",
                            "target": f"/run/secrets/{file_id}",
                        }
                        for file_id in projection["sources"]
                    ],
                }
                for service_name, projection in contract.items()
            }

        def consumer(stager, stage_id):
            return {
                "volumes": [
                    {
                        "type": "volume",
                        "source": (f"{volume_prefix}-operator-files-{stage_id}"),
                        "target": "/run/secrets",
                        "read_only": True,
                        "volume": {},
                    }
                ],
                "depends_on": {
                    stager: {
                        "condition": "service_completed_successfully",
                        "required": True,
                    }
                },
            }

        ordinary = {
            "services": {
                **stagers(self.module.SERVING_SECRET_STAGER_CONTRACT),
                **{
                    service_name: consumer(*contract)
                    for service_name, contract in (
                        self.module.SERVING_SECRET_STAGE_CONSUMERS.items()
                    )
                },
            }
        }
        initialization = copy.deepcopy(ordinary)
        initialization["services"].update(
            stagers(self.module.ACTION_SECRET_STAGER_CONTRACT)
        )
        initialization["services"].update(
            {
                service_name: consumer(*contract)
                for service_name, contract in (
                    self.module.ACTION_SECRET_STAGE_CONSUMERS.items()
                )
            }
        )
        initialization["services"].update(
            {
                f"registry-{lane}-{action}-state": {
                    "network_mode": "none",
                    "depends_on": {},
                    "volumes": [
                        {
                            "type": "volume",
                            "source": f"{volume_prefix}-{lane}-state",
                            "target": "/var/lib/registry/state",
                            "read_only": True,
                            "volume": {},
                        }
                    ],
                }
                for lane in self.module.GOVERNED_LANES
                for action in ("preview", "verify")
            }
        )
        for lane in self.module.GOVERNED_LANES:
            initialization["services"][f"registry-{lane}-accept-state"] = {
                "network_mode": "none",
                "depends_on": {},
                "volumes": [],
                "env_file": [f"/fixture/operator/secrets/{lane}-environment"],
            }
        initialization["services"].update(
            {
                "registry-relay-public-prepare-state": {
                    "network_mode": "none",
                    "depends_on": {},
                    "volumes": [],
                },
                "registry-relay-public-initialize": {
                    "network_mode": "none",
                    "depends_on": {},
                    "volumes": [],
                },
                "registry-notary-initialize": {
                    "network_mode": "none",
                    "depends_on": {},
                    "volumes": [],
                },
            }
        )
        return ordinary, initialization, volume_prefix

    def write_valid_stable_report_evidence(self):
        verified = self.verify_assets()
        evidence = self.root / "stable-evidence"
        logs = evidence / "logs"
        reader = evidence / "reader-journeys"
        public_source = evidence / "public-source-live"
        logs.mkdir(parents=True)
        public_source.mkdir()
        (reader / "http").mkdir(parents=True)
        (reader / "spreadsheet").mkdir()
        (reader / "spreadsheet-evidence").mkdir()
        (reader / "opencrvs").mkdir()
        reader_manifest = {
            "schema_version": "registryctl.tutorial_reader_journeys.v1",
            "status": "passed",
            "mode": "sealed",
            "registryctl_version": "1.2.3",
            "projects": [
                {
                    "id": "http",
                    "source": "embedded-http-template",
                    "reports": [
                        "http/init.txt",
                        "http/test.txt",
                        "http/trace.txt",
                        "http/build.txt",
                        "http/test.json",
                        "http/check.json",
                        "http/build.json",
                    ],
                },
                {
                    "id": "spreadsheet",
                    "source": "embedded-spreadsheet-template",
                    "covers": [
                        "starter",
                        "evidence-rule-change",
                        "offline-fixtures",
                        "reviewed-build",
                    ],
                    "reports": [
                        "spreadsheet/init.txt",
                        "spreadsheet/test.txt",
                        "spreadsheet/trace.txt",
                        "spreadsheet/build.txt",
                        "spreadsheet/test.json",
                        "spreadsheet/check.json",
                        "spreadsheet/build.json",
                        "spreadsheet-evidence/before-trace.txt",
                        "spreadsheet-evidence/after-trace.txt",
                        "spreadsheet-evidence/test.txt",
                        "spreadsheet-evidence/test.json",
                        "spreadsheet-evidence/check.json",
                        "spreadsheet-evidence/build.json",
                        "spreadsheet-evidence/dev-start.txt",
                        "spreadsheet-evidence/records-denied.json",
                        "spreadsheet-evidence/records-request.json",
                        "spreadsheet-evidence/evidence-request.json",
                        "spreadsheet-evidence/dev-smoke.txt",
                        "spreadsheet-evidence/dev-down.txt",
                    ],
                },
                {
                    "id": "opencrvs-events-api",
                    "source": "public-docs-overlay-v1",
                    "covers": [
                        "oauth-client-credentials",
                        "bounded-http",
                        "rhai",
                        "opencrvs-shaped-search",
                    ],
                    "reports": [
                        "opencrvs/test.json",
                        "opencrvs/check.json",
                        "opencrvs/build.json",
                    ],
                },
            ],
            "release_boundary": "sealed fixture",
            "retained_project": "[PRIVATE_PATH]",
            "retained_oauth_project": "[PRIVATE_PATH]",
        }
        (reader / "manifest.json").write_text(
            json.dumps(reader_manifest), encoding="utf-8"
        )
        for relative in self.module.STABLE_READER_EVIDENCE_FILES - {
            "manifest.json"
        }:
            (reader / relative).write_text('{"status":"passed"}\n', encoding="utf-8")
        reader_summary = {
            "schema_version": "registryctl.tutorial_reader_journeys.v1",
            "status": "passed",
            "mode": "sealed",
            "registryctl_version": "1.2.3",
            "projects": [
                "http",
                "spreadsheet",
                "opencrvs-events-api",
            ],
            "evidence_sha256": self.module.closed_tree_digests(reader),
        }
        for relative in self.module.PUBLIC_SOURCE_LIVE_EVIDENCE_FILES:
            contents = (
                "Development smoke: passed.\n"
                "status=authorized; passed=true\n"
                if relative.endswith("-smoke.txt")
                else "public-source evidence\n"
            )
            (public_source / relative).write_text(contents, encoding="utf-8")
        public_source_summary = self.module.stable_public_source_live_summary(
            public_source
        )
        doctor = {
            "schema_version": "registryctl.doctor.v1",
            "status": "ready",
            "environment": "local",
            "profile": "local",
            "checks": sorted(
                {
                    "authored_environment",
                    "installed_release_lock",
                    "docker_cli",
                    "docker_daemon",
                    "docker_compose",
                    "locked_images",
                }
            ),
        }
        status = {
            "schema_version": "registryctl.dev_status.v1",
            "source_mode": "synthetic",
            "workloads": [
                {"workload": name, "state": "running"}
                for name in sorted(self.module.STABLE_WORKLOAD_IMAGES)
            ],
        }
        smoke = {
            "schema_version": "registryctl.dev_smoke.v1",
            "project": "my-registry",
            "environment": "local",
            "passed": True,
            "results": [
                {
                    "scenario_id": "authorized",
                    "status": "authorized",
                    "token_counter_delta": 0,
                    "source_counter_delta": 1,
                    "minimized_claim_ids": self.module.HTTP_MINIMIZED_CLAIMS,
                    "passed": True,
                },
                {
                    "scenario_id": "denied",
                    "status": "denied",
                    "token_counter_delta": 0,
                    "source_counter_delta": 0,
                    "minimized_claim_ids": [],
                    "passed": True,
                },
            ],
        }
        product_logs = {
            "schema_version": "registryctl.dev_logs.v1",
            "products": [
                {"workload": name, "available": True}
                for name in sorted(
                    {
                        "relay-public",
                        "relay-consultation",
                        "notary",
                        "synthetic-source",
                    }
                )
            ]
        }
        runtime = {
            "release_tag": self.tag,
            "source_mode": "synthetic",
            "plan_sha256": "3" * 64,
            "plan_digest": "sha256:" + "4" * 64,
            "build_manifest_digest": "sha256:" + "5" * 64,
            "compose_digest": "sha256:" + "6" * 64,
            "request_digest": "sha256:" + "7" * 64,
            "listeners": dict(self.module.STABLE_LISTENERS),
            "workloads": {
                name: verified[image_key]
                for name, image_key in sorted(
                    self.module.STABLE_WORKLOAD_IMAGES.items()
                )
            },
            "permissions": {"runtime_root": "0700", "credentials": "0700"},
        }
        opencrvs_smoke = json.loads(json.dumps(smoke))
        opencrvs_smoke["project"] = "synthetic-opencrvs-events-api"
        opencrvs_smoke["results"][0]["token_counter_delta"] = 1
        opencrvs_smoke["results"][0][
            "minimized_claim_ids"
        ] = self.module.OPENCRVS_MINIMIZED_CLAIM_IDS
        governed_phase = {
            "schema_version": "registryctl.deployment_generate.v1",
            "approved_set_sha256": "sha256:" + "8" * 64,
            "externally_recorded_closure_sha256": "sha256:" + "9" * 64,
            "ownership": "managed",
            "package_freshness": "current",
            "verification_scope": "package",
            "in_place_regeneration_safe": True,
        }
        governed = {
            "schema_version": "registry-stack.governed-deployment-proof.v1",
            "operator_file_count": len(self.module.GOVERNED_OPERATOR_SOURCES),
            "initial": governed_phase,
            "parent_include": "passed",
            "explicit_initialization": "passed",
            "functional_evidence": copy.deepcopy(
                self.module.GOVERNED_EVIDENCE_SUMMARY
            ),
            "ordinary_restart": "passed",
            "backup_restore": "passed",
            "anchor_rotation": "passed",
            "compatible_update": {
                **governed_phase,
                "approved_set_sha256": "sha256:" + "a" * 64,
                "externally_recorded_closure_sha256": "sha256:" + "b" * 64,
            },
            "failed_activation_recovery": "passed",
            "rollback_rejection": "passed",
            "isolated_teardown": "passed",
        }
        normalized = {
            "public_source_live": public_source_summary,
            "oauth_dev_up": runtime,
            "oauth_dev_smoke": opencrvs_smoke,
            "oauth_dev_down": {
                "outcome": "passed",
                "runtime_state": "absent",
            },
            "dev_down": {"outcome": "passed", "runtime_state": "absent"},
            "doctor": doctor,
            "dev_status": status,
            "dev_smoke": smoke,
            "dev_logs": product_logs,
            "inspect": runtime,
            "inspect_secret_stagers": {"outcome": "passed"},
            "governed_evidence": copy.deepcopy(
                self.module.GOVERNED_EVIDENCE_SUMMARY
            ),
        }
        commands = []
        for name in self.module.STABLE_COMMAND_ORDER:
            log = logs / f"{name}.log"
            if name in normalized:
                log.write_text(
                    json.dumps(normalized[name], sort_keys=True) + "\n",
                    encoding="utf-8",
                )
            else:
                log.write_text(f"{name} passed\n", encoding="utf-8")
            commands.append(
                {
                    "name": name,
                    "status": "passed",
                    "exit_code": 0,
                    "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
                }
            )
        report = {
            "schema_version": self.module.STABLE_SCHEMA,
            "status": "passed",
            "release_tag": self.tag,
            "manifest_source_ref": "1" * 40,
            "tag_target": "1" * 40,
            "platform_asset": self.binary,
            "asset_sha256": verified["assets"],
            "release_image_lock_sha256": verified["assets"][self.lock],
            "release_lock_sha256": verified["assets"][self.release_lock],
            "relay_image": self.relay,
            "notary_image": self.notary,
            "postgresql_image": self.postgresql,
            "commands": commands,
            "reader_journeys": reader_summary,
            "public_source_live": public_source_summary,
            "oauth_runtime": runtime,
            "opencrvs_smoke": opencrvs_smoke,
            "doctor": doctor,
            "runtime": runtime,
            "dev_status": status,
            "smoke": smoke,
            "product_logs": product_logs,
            "governed_deployment": governed,
            "redaction": {"status": "passed", "generated_files_scanned": 20},
        }
        path = evidence / "first-country-release-form.json"
        write_report_fixture(path, report)
        self.module.protect_evidence_tree(evidence)
        return path, report, logs

    def test_closed_assets_bind_installer_binary_and_lock(self) -> None:
        verified = self.verify_assets()
        self.assertEqual(verified["installer_name"], self.installer)
        self.assertEqual(verified["binary_name"], self.binary)
        self.assertEqual(verified["relay_image"], self.relay)
        self.assertEqual(verified["notary_image"], self.notary)
        self.assertEqual(verified["postgresql_image"], self.postgresql)
        self.assertEqual(verified["release_lock_name"], self.release_lock)
        self.assertEqual(verified["docs_archive_name"], self.docs_archive)

    def test_closed_assets_reject_a_distinct_tag_target(self) -> None:
        lock_path = self.assets / self.lock
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        lock["tag_target"] = "2" * 40
        lock_path.write_text(json.dumps(lock), encoding="utf-8")
        digest = hashlib.sha256(lock_path.read_bytes()).hexdigest()
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
            self.module.ReleaseFormError, "one exact candidate and tag revision"
        ):
            self.verify_assets()

    def test_released_docs_archive_extracts_exact_public_reader_inputs(self) -> None:
        verified = self.verify_assets()
        destination = self.root / "released-docs"
        version_root = self.module.extract_released_docs_archive(
            self.assets / verified["docs_archive_name"],
            destination,
            tag=self.tag,
        )
        self.assertEqual(version_root, destination / "version")
        self.assertEqual(
            {
                path.relative_to(version_root).as_posix()
                for path in version_root.rglob("*")
                if path.is_file()
            },
            set(self.docs_files),
        )

    def test_released_docs_archive_is_checksum_bound(self) -> None:
        with (self.assets / self.docs_archive).open("ab") as archive:
            archive.write(b"altered transport\n")
        with self.assertRaisesRegex(
            self.module.ReleaseFormError,
            f"release checksum does not bind exact asset {self.docs_archive}",
        ):
            self.verify_assets()

    def test_released_docs_archive_rejects_missing_archived_overlay(self) -> None:
        files = dict(self.docs_files)
        files.pop(
            "examples/registryctl/opencrvs-events-api-overlay-v1.sh"
        )
        self.write_docs_archive(files=files)
        self.write_checksums()
        self.verify_assets()
        with self.assertRaisesRegex(
            self.module.ReleaseFormError,
            "missing required public reader input",
        ):
            self.module.extract_released_docs_archive(
                self.assets / self.docs_archive,
                self.root / "missing-overlay",
                tag=self.tag,
            )

    def test_released_docs_archive_rejects_nonempty_destination(self) -> None:
        destination = self.root / "nonempty-destination"
        destination.mkdir()
        (destination / "existing").write_text("do not replace\n", encoding="utf-8")
        with self.assertRaisesRegex(
            self.module.ReleaseFormError,
            "absent or an empty real directory",
        ):
            self.module.extract_released_docs_archive(
                self.assets / self.docs_archive,
                destination,
                tag=self.tag,
            )
        self.assertEqual(
            (destination / "existing").read_text(encoding="utf-8"),
            "do not replace\n",
        )

    def test_released_docs_archive_enforces_path_and_size_bounds(self) -> None:
        unsafe = tarfile.TarInfo("../escaped")
        unsafe.mode = 0o644
        self.write_docs_archive(unsafe_member=unsafe)
        self.write_checksums()
        with self.assertRaisesRegex(
            self.module.ReleaseFormError,
            "unsafe path",
        ):
            self.module.extract_released_docs_archive(
                self.assets / self.docs_archive,
                self.root / "unsafe-path",
                tag=self.tag,
            )

        self.write_docs_archive()
        self.write_checksums()
        with (
            mock.patch.object(
                self.module,
                "DOCS_ARCHIVE_MAX_ENTRY_BYTES",
                1,
            ),
            self.assertRaisesRegex(
                self.module.ReleaseFormError,
                "entry exceeds its size bound",
            ),
        ):
            self.module.extract_released_docs_archive(
                self.assets / self.docs_archive,
                self.root / "oversized-entry",
                tag=self.tag,
            )

    def test_released_docs_archive_rejects_altered_archived_overlay(self) -> None:
        files = dict(self.docs_files)
        files[
            "examples/registryctl/jsonplaceholder-todo-live-overlay-v1.sh"
        ] += b"altered\n"
        self.write_docs_archive(files=files)
        self.write_checksums()
        self.verify_assets()
        with self.assertRaisesRegex(
            self.module.ReleaseFormError,
            "checksum does not bind exact asset",
        ):
            self.module.extract_released_docs_archive(
                self.assets / self.docs_archive,
                self.root / "altered-overlay",
                tag=self.tag,
            )

    def test_released_docs_archive_rejects_symlink_entry(self) -> None:
        symlink = tarfile.TarInfo("version/unsafe-link")
        symlink.type = tarfile.SYMTYPE
        symlink.linkname = "../metadata.json"
        self.write_docs_archive(unsafe_member=symlink)
        self.write_checksums()
        with self.assertRaisesRegex(
            self.module.ReleaseFormError,
            "non-regular entry",
        ):
            self.module.extract_released_docs_archive(
                self.assets / self.docs_archive,
                self.root / "symlink-entry",
                tag=self.tag,
            )

    def test_v1_asset_set_requires_signed_release_lock(self) -> None:
        (self.assets / self.release_lock).unlink()
        with self.assertRaisesRegex(
            self.module.ReleaseFormError, "required file is unavailable"
        ):
            self.verify_assets()


    def test_stable_command_order_covers_governed_release_lifecycle(self) -> None:
        required = (
            "reader_journeys",
            "public_source_live",
            "oauth_dev_up",
            "oauth_dev_smoke",
            "oauth_dev_down",
            "dev_smoke",
            "governed_build",
            "deploy_generate",
            "dev_down",
            "deploy_verify",
            "parent_include_config",
            "initialize_config",
            "inspect_secret_stagers",
            "initialize_stage_relay_consultation_action_secrets",
            "initialize_stage_notary_action_secrets",
            "initialize_stage_postgresql_action_secrets",
            "initialize_postgresql",
            "initialize_relay_public",
            "initialize_relay_consultation",
            "initialize_notary",
            "reject_postgresql_data_reinitialization",
            "reject_postgresql_bootstrap_reinitialization",
            "governed_start",
            "governed_evidence",
            "governed_restart",
            "backup_restore",
            "rotate_relay_consultation",
            "update_generate",
            "failed_activation",
            "failed_activation_recovery",
            "update_verify_current",
            "update_verify_current_relay_public_state",
            "update_verify_current_relay_consultation_state",
            "update_verify_current_notary_state",
            "update_preview_relay_public",
            "update_preview_relay_consultation",
            "update_preview_notary",
            "update_stop_current",
            "update_accept_relay_consultation",
            "update_accept_notary",
            "update_verify_relay_public_state",
            "update_verify_relay_consultation_state",
            "update_verify_notary_state",
            "update_stage_relay_consultation_serving_secrets",
            "update_stage_notary_serving_secrets",
            "update_stage_postgresql_serving_secrets",
            "updated_start",
            "updated_stop",
            "rollback_rejected",
            "final_start",
            "isolated_teardown",
        )
        self.assertEqual(
            sorted(self.module.STABLE_COMMAND_ORDER),
            sorted(set(self.module.STABLE_COMMAND_ORDER)),
        )
        positions = [self.module.STABLE_COMMAND_ORDER.index(name) for name in required]
        self.assertEqual(positions, sorted(positions))
        update_start = self.module.STABLE_COMMAND_ORDER.index("update_generate")
        updated_start = self.module.STABLE_COMMAND_ORDER.index("updated_start")
        update_order = (
            "update_generate",
            "update_verify",
            "failed_activation",
            "failed_activation_recovery",
            "update_verify_current",
            "update_verify_current_relay_public_state",
            "update_verify_current_relay_consultation_state",
            "update_verify_current_notary_state",
            "update_preview_relay_public",
            "update_preview_relay_consultation",
            "update_preview_notary",
            "update_stop_current",
            "update_accept_relay_consultation",
            "update_accept_notary",
            "update_verify_relay_public_state",
            "update_verify_relay_consultation_state",
            "update_verify_notary_state",
            "update_stage_relay_consultation_serving_secrets",
            "update_stage_notary_serving_secrets",
            "update_stage_postgresql_serving_secrets",
            "updated_start",
        )
        self.assertEqual(
            self.module.STABLE_COMMAND_ORDER[update_start : updated_start + 1],
            update_order,
        )
        stable_source = SCRIPT.read_text(encoding="utf-8").split(
            "def run_stable_release_form", 1
        )[1].split("def run_release_form", 1)[0]
        emitted_update_markers = {
            "failed_activation": "run_failed_activation(",
        }
        emitted_update_positions = [
            stable_source.index(emitted_update_markers.get(name, f'"{name}"'))
            for name in update_order
        ]
        self.assertEqual(
            emitted_update_positions,
            sorted(emitted_update_positions),
            "the implemented update dispatch must preserve the tested command order",
        )
        for command_name in (
            "update_verify_current",
            "update_verify_current_relay_public_state",
            "update_verify_current_relay_consultation_state",
            "update_verify_current_notary_state",
        ):
            self.assertIn(f'"{command_name}"', stable_source)
        self.assertIn('"--expected-closure-sha256"', stable_source)
        self.assertNotIn('"--parent-compose"', stable_source)
        self.assertIn(
            '"REGISTRYCTL_PUBLIC_SOURCE_LIVE": "1"', stable_source
        )
        self.assertIn(
            "check-registryctl-public-source-live.sh", stable_source
        )
        self.assertNotIn("git clone", stable_source)
        self.assertIn("reader-http-project", stable_source)
        self.assertIn(
            "shutil.copytree(package, candidate_package)",
            stable_source,
        )
        self.assertNotIn(
            "copy_governed_operator_inputs(\n                candidate_package",
            stable_source,
        )
        self.assertIn(
            "compose_preview_state_commands(candidate_package)", stable_source
        )
        self.assertIn(
            '"update_stop_current",\n                    [*compose_base(package), "stop"]',
            stable_source,
        )
        cleanup_source = stable_source.split("        finally:", 1)[1]
        self.assertLess(
            cleanup_source.index("available_secret_values"),
            cleanup_source.index("for governed_package in"),
        )

    def test_retired_pre_1_0_live_contract_markers_are_absent(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        retired_markers = (
            ".registry-stack/runtime/local",
            "registryctl.local_runtime.v2",
            "registryctl.smoke.v1",
            "/v1/datasets/projects/entities/projects/records",
            "REGISTRYCTL_LOCAL_RELAY_MATCH_KEY_RAW",
            "REGISTRYCTL_LOCAL_RELAY_NO_MATCH_KEY_RAW",
            '"notary-network", "8081"',
        )
        for marker in retired_markers:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, source)

    def test_expected_failure_requires_its_value_free_classification(self) -> None:
        logs = self.root / "logs"
        logs.mkdir(mode=0o700)
        rejected = subprocess.CompletedProcess(
            ["fixture"],
            1,
            "registry_stack_bootstrap_marker already exists",
            "",
        )
        with mock.patch.object(
            self.module.subprocess,
            "run",
            return_value=rejected,
        ):
            self.module.run_expected_failure(
                "bootstrap_rejected",
                ["fixture"],
                cwd=self.root,
                env={},
                logs=logs,
                expected_output_fragment="registry_stack_bootstrap_marker",
                observed_exit_class="postgresql_bootstrap_marker_exists",
            )
        recorded = json.loads(
            (logs / "bootstrap_rejected.log").read_text(encoding="utf-8")
        )
        self.assertEqual(
            recorded,
            {
                "observed_exit_class": "postgresql_bootstrap_marker_exists",
                "outcome": "rejected",
            },
        )

        with (
            mock.patch.object(
                self.module.subprocess,
                "run",
                return_value=subprocess.CompletedProcess(
                    ["fixture"],
                    1,
                    "unclassified failure",
                    "",
                ),
            ),
            self.assertRaisesRegex(
                self.module.ReleaseFormError,
                "without the expected classification",
            ),
        ):
            self.module.run_expected_failure(
                "bootstrap_unclassified",
                ["fixture"],
                cwd=self.root,
                env={},
                logs=logs,
                expected_output_fragment="registry_stack_bootstrap_marker",
            )

    def test_failed_activation_rejects_unrelated_nonzero_failure(self) -> None:
        logs = self.root / "failed-activation-logs"
        logs.mkdir(mode=0o700)
        with (
            mock.patch.object(
                self.module.subprocess,
                "run",
                return_value=subprocess.CompletedProcess(
                    ["fixture"],
                    1,
                    "unrelated runtime failure",
                    "",
                ),
            ),
            self.assertRaisesRegex(
                self.module.ReleaseFormError,
                "without the expected classification",
            ),
        ):
            self.module.run_failed_activation(
                ["fixture"],
                cwd=self.root,
                env={},
                logs=logs,
            )
        self.assertFalse((logs / "failed_activation.log").exists())

    def test_governed_start_uses_exact_fail_closed_order(self) -> None:
        package = self.root / "package"
        commands = self.module.compose_governed_start_commands(
            package,
            include_ps=True,
        )

        def operation(command: list[str]) -> str:
            if "run" in command:
                return command[-1]
            if "up" in command:
                return "up"
            if "ps" in command:
                return "ps"
            self.fail(f"unexpected governed-start command: {command}")

        self.assertEqual(
            [operation(command) for command in commands],
            [
                "registry-relay-public-verify-state",
                "registry-relay-consultation-verify-state",
                "registry-notary-verify-state",
                "registry-relay-consultation-stage-secrets",
                "registry-notary-stage-secrets",
                "registry-postgresql-stage-secrets",
                "up",
                "registry-relay-public-verify-state",
                "registry-relay-consultation-verify-state",
                "registry-notary-verify-state",
                "ps",
            ],
        )
        self.assertEqual(
            commands[6][-5:],
            ["up", "--detach", "--wait", "--wait-timeout", "120"],
        )
        post_accept = self.module.compose_start_and_verify_commands(
            package,
            include_ps=True,
        )
        self.assertEqual(commands[6:], post_accept)
        self.assertEqual(
            [operation(command) for command in post_accept],
            [
                "up",
                "registry-relay-public-verify-state",
                "registry-relay-consultation-verify-state",
                "registry-notary-verify-state",
                "ps",
            ],
        )

    def test_action_and_state_commands_use_the_initialization_model(self) -> None:
        package = self.root / "package"
        action_stagers = (
            "registry-relay-consultation-actions-stage-secrets",
            "registry-notary-actions-stage-secrets",
        )
        actions = self.module.compose_action_secret_stage_commands(
            package,
            action_stagers,
        )
        self.assertEqual(
            tuple(command[-1] for command in actions),
            action_stagers,
        )
        for command in actions:
            self.assertIn(
                str(package / "generated/compose.initialize.yaml"), command
            )

        consumers = self.module.compose_verify_state_commands(package)
        self.assertEqual(
            [command[-1] for command in consumers],
            [
                "registry-relay-public-verify-state",
                "registry-relay-consultation-verify-state",
                "registry-notary-verify-state",
            ],
        )
        for command in consumers:
            self.assertIn(
                str(package / "generated/compose.initialize.yaml"), command
            )

    def test_candidate_inputs_must_match_the_copied_current_package(self) -> None:
        candidate = self.root / "candidate"
        generated = candidate / "generated.previous"
        operator = candidate / "operator"
        generated.mkdir(parents=True)
        operator.mkdir()
        (generated / "compose.yaml").write_text(
            "services: {}\n",
            encoding="utf-8",
        )
        (operator / "notary-signing-key").write_text(
            fixture_text("notary-signing-key"),
            encoding="utf-8",
        )
        current_generated = {
            "compose.yaml": hashlib.sha256(b"services: {}\n").hexdigest()
        }
        current_operator = {
            "notary-signing-key": hashlib.sha256(
                fixture_bytes("notary-signing-key")
            ).hexdigest()
        }

        self.module.require_preserved_candidate_inputs(
            candidate,
            current_generated_digests=current_generated,
            current_operator_digests=current_operator,
        )

        (operator / "notary-signing-key").write_text(
            fixture_text("replacement-notary-signing-key"),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            self.module.ReleaseFormError,
            "exact current operator files",
        ):
            self.module.require_preserved_candidate_inputs(
                candidate,
                current_generated_digests=current_generated,
                current_operator_digests=current_operator,
            )
        (operator / "notary-signing-key").write_text(
            fixture_text("notary-signing-key"),
            encoding="utf-8",
        )
        (generated / "compose.yaml").write_text(
            "services:\n  changed: {}\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            self.module.ReleaseFormError,
            "exact current generated closure",
        ):
            self.module.require_preserved_candidate_inputs(
                candidate,
                current_generated_digests=current_generated,
                current_operator_digests=current_operator,
            )

    def test_secret_staging_models_enforce_exact_lane_authority(self) -> None:
        ordinary, initialization, volume_prefix = self.secret_staging_models()
        self.assertEqual(
            self.module.stable_secret_staging_summary(
                ordinary,
                initialization,
                volume_prefix=volume_prefix,
            ),
            self.module.expected_secret_staging_summary(),
        )

        wrong_roster = copy.deepcopy(ordinary)
        wrong_roster["services"]["registry-runtime-stage-secrets"] = wrong_roster[
            "services"
        ].pop("registry-relay-consultation-stage-secrets")
        with self.assertRaisesRegex(
            self.module.ReleaseFormError, "wrong serving stager roster"
        ):
            self.module.stable_secret_staging_summary(
                wrong_roster,
                initialization,
                volume_prefix=volume_prefix,
            )

        cross_lane_source_ordinary = copy.deepcopy(ordinary)
        cross_lane_source_initialization = copy.deepcopy(initialization)
        cross_lane_secret = {
            "source": "registry-notary-signing-key",
            "target": "/run/secrets/notary-signing-key",
        }
        cross_lane_source_ordinary["services"][
            "registry-relay-consultation-stage-secrets"
        ]["secrets"].append(cross_lane_secret)
        cross_lane_source_initialization["services"][
            "registry-relay-consultation-stage-secrets"
        ]["secrets"].append(cross_lane_secret)
        with self.assertRaisesRegex(self.module.ReleaseFormError, "source authority"):
            self.module.stable_secret_staging_summary(
                cross_lane_source_ordinary,
                cross_lane_source_initialization,
                volume_prefix=volume_prefix,
            )

        cross_lane_output_ordinary = copy.deepcopy(ordinary)
        cross_lane_output_initialization = copy.deepcopy(initialization)
        cross_lane_output_ordinary["services"][
            "registry-relay-consultation-stage-secrets"
        ]["volumes"][0]["source"] = f"{volume_prefix}-operator-files-notary-serve"
        cross_lane_output_initialization["services"][
            "registry-relay-consultation-stage-secrets"
        ]["volumes"][0]["source"] = f"{volume_prefix}-operator-files-notary-serve"
        with self.assertRaisesRegex(self.module.ReleaseFormError, "output authority"):
            self.module.stable_secret_staging_summary(
                cross_lane_output_ordinary,
                cross_lane_output_initialization,
                volume_prefix=volume_prefix,
            )

        wrong_consumer = copy.deepcopy(initialization)
        wrong_consumer["services"]["registry-relay-consultation"]["volumes"][0][
            "source"
        ] = f"{volume_prefix}-operator-files-notary-serve"
        with self.assertRaisesRegex(self.module.ReleaseFormError, "consumer authority"):
            self.module.stable_secret_staging_summary(
                ordinary,
                wrong_consumer,
                volume_prefix=volume_prefix,
            )

        wrong_dependency = copy.deepcopy(initialization)
        wrong_dependency["services"]["registry-relay-consultation"]["depends_on"] = {
            "registry-notary-stage-secrets": {
                "condition": "service_completed_successfully",
                "required": True,
            }
        }
        with self.assertRaisesRegex(
            self.module.ReleaseFormError, "exact isolated stager"
        ):
            self.module.stable_secret_staging_summary(
                ordinary,
                wrong_dependency,
                volume_prefix=volume_prefix,
            )

        missing_consumer = copy.deepcopy(initialization)
        missing_consumer["services"].pop("registry-notary-accept-state")
        with self.assertRaisesRegex(
            self.module.ReleaseFormError, "exact lane environment"
        ):
            self.module.stable_secret_staging_summary(
                ordinary,
                missing_consumer,
                volume_prefix=volume_prefix,
            )

        preview_with_secret = copy.deepcopy(initialization)
        preview_with_secret["services"]["registry-notary-preview-state"][
            "volumes"
        ].append(
            {
                "type": "volume",
                "source": f"{volume_prefix}-operator-files-notary-accept",
                "target": "/run/secrets",
                "read_only": True,
                "volume": {},
            }
        )
        with self.assertRaisesRegex(
            self.module.ReleaseFormError, "unowned staged-secret authority"
        ):
            self.module.stable_secret_staging_summary(
                ordinary,
                preview_with_secret,
                volume_prefix=volume_prefix,
            )

        accept_with_wrong_environment = copy.deepcopy(initialization)
        accept_with_wrong_environment["services"]["registry-notary-accept-state"][
            "env_file"
        ] = ["relay-public-environment"]
        with self.assertRaisesRegex(
            self.module.ReleaseFormError, "exact lane environment"
        ):
            self.module.stable_secret_staging_summary(
                ordinary,
                accept_with_wrong_environment,
                volume_prefix=volume_prefix,
            )

    def test_stable_release_rejects_pre_v3_evidence_schema(self) -> None:
        path, report, _ = self.write_valid_stable_report_evidence()
        report["schema_version"] = "registry-stack.first-country-release-form.v1"
        write_report_fixture(path, report)
        with (
            self.assertRaisesRegex(
                self.module.ReleaseFormError, "maintained release-form"
            ),
            mock.patch.object(platform, "system", return_value="Linux"),
            mock.patch.object(platform, "machine", return_value="x86_64"),
        ):
            self.module.verify_report(path, self.assets, self.tag)

    def test_pre_v1_release_form_is_not_supported(self) -> None:
        with self.assertRaisesRegex(
            self.module.ReleaseFormError, "v1 and later"
        ):
            self.module.verify_asset_set(self.assets, "v0.15.2")

    def test_stable_report_verifies_maintained_reader_and_runtime_evidence(
        self,
    ) -> None:
        path, _, _ = self.write_valid_stable_report_evidence()
        with (
            mock.patch.object(platform, "system", return_value="Linux"),
            mock.patch.object(platform, "machine", return_value="x86_64"),
        ):
            self.module.verify_report(path, self.assets, self.tag)

    def test_stable_report_rejects_world_readable_evidence(self) -> None:
        if os.name != "posix":
            self.skipTest("POSIX mode contract")
        path, _, _ = self.write_valid_stable_report_evidence()
        path.chmod(0o644)
        with (
            self.assertRaisesRegex(
                self.module.ReleaseFormError, "not owner-only"
            ),
            mock.patch.object(platform, "system", return_value="Linux"),
            mock.patch.object(platform, "machine", return_value="x86_64"),
        ):
            self.module.verify_report(path, self.assets, self.tag)

    def test_stable_report_rejects_runtime_image_outside_signed_lock(self) -> None:
        path, report, _ = self.write_valid_stable_report_evidence()
        report["runtime"]["workloads"]["relay-public"] = (
            "ghcr.io/registrystack/registry-relay@sha256:" + "9" * 64
        )
        write_report_fixture(path, report)
        with (
            self.assertRaisesRegex(
                self.module.ReleaseFormError, "does not prove"
            ),
            mock.patch.object(platform, "system", return_value="Linux"),
            mock.patch.object(platform, "machine", return_value="x86_64"),
        ):
            self.module.verify_report(path, self.assets, self.tag)

    def test_governed_summary_rejects_update_without_new_closure(self) -> None:
        path, report, _ = self.write_valid_stable_report_evidence()
        report["governed_deployment"]["compatible_update"][
            "externally_recorded_closure_sha256"
        ] = report["governed_deployment"]["initial"][
            "externally_recorded_closure_sha256"
        ]
        write_report_fixture(path, report)
        with (
            self.assertRaisesRegex(
                self.module.ReleaseFormError, "did not change closure"
            ),
            mock.patch.object(platform, "system", return_value="Linux"),
            mock.patch.object(platform, "machine", return_value="x86_64"),
        ):
            self.module.verify_report(path, self.assets, self.tag)

    def test_governed_summary_requires_the_exact_functional_evidence(self) -> None:
        path, report, logs = self.write_valid_stable_report_evidence()
        unexpected = {
            "http_status": 200,
            "claims": [
                {
                    "claim_id": "todo-completed",
                    "satisfied": True,
                    "disclosure": "value",
                }
            ],
        }
        report["governed_deployment"]["functional_evidence"] = unexpected
        log = logs / "governed_evidence.log"
        log.chmod(0o600)
        log.write_text(json.dumps(unexpected) + "\n", encoding="utf-8")
        command = next(
            command
            for command in report["commands"]
            if command["name"] == "governed_evidence"
        )
        command["log_sha256"] = hashlib.sha256(log.read_bytes()).hexdigest()
        write_report_fixture(path, report)
        path.chmod(0o600)

        with (
            self.assertRaisesRegex(
                self.module.ReleaseFormError, "governed deployment summary"
            ),
            mock.patch.object(platform, "system", return_value="Linux"),
            mock.patch.object(platform, "machine", return_value="x86_64"),
        ):
            self.module.verify_report(path, self.assets, self.tag)

    def test_deploy_verify_summary_accepts_simplified_ownership_report(self) -> None:
        summary = self.module.stable_deploy_verify_summary(
            {
                "schema_id": "io.registrystack.deployment_ownership_report",
                "schema_version": "1.0",
                "ownership": "managed",
                "package_freshness": "current",
                "verification_scope": "package",
                "violations": [],
                "verified_guarantees": [
                    "generator-owned closure matches its manifest",
                    (
                        "ordinary and initialization effective models match "
                        "the generated package"
                    ),
                ],
                "operator_owned_guarantees": [
                    (
                        "operator files satisfy the signed isolation, mode, owner, "
                        "and consumer inventory"
                    )
                ],
                "in_place_regeneration_safe": True,
            }
        )

        self.assertEqual(summary["ownership"], "managed")
        self.assertNotIn("adapted_files", summary)

    def test_update_build_requires_consultation_and_notary_lanes(self) -> None:
        report = {
            "schema_version": "registryctl.reviewed_project_build_report.v1",
            "affected_lanes": ["relay-consultation", "notary"],
            "reviewed_build_record_digest": "sha256:" + "a" * 64,
        }

        self.assertEqual(
            self.module.stable_update_build_summary(report)["affected_lanes"],
            ["relay-consultation", "notary"],
        )
        report["affected_lanes"] = ["relay-public", "relay-consultation", "notary"]
        with self.assertRaisesRegex(
            self.module.ReleaseFormError, "did not affect exactly"
        ):
            self.module.stable_update_build_summary(report)

    def test_operator_copy_filters_dotenv_to_the_signed_required_keys(self) -> None:
        package = self.root / "package"
        credentials = self.root / "credentials"
        inventory = package / "generated/operator-files.v1.json"
        inventory.parent.mkdir(parents=True)
        credentials.mkdir()
        files = []
        for file_id, source_names in self.module.GOVERNED_OPERATOR_SOURCES.items():
            required_keys = ["KEEP"] if file_id == "postgresql-bootstrap-environment" else []
            file_format = "dotenv" if file_id.endswith("environment") else "opaque"
            dotenv_value = fixture_bytes(f"{file_id}-dotenv")
            ignored_value = fixture_bytes(f"{file_id}-ignored")
            opaque_value = fixture_bytes(f"{file_id}-opaque")
            for source_name in source_names:
                (credentials / source_name).write_bytes(
                    b"KEEP=" + dotenv_value + b"\nEXTRA=" + ignored_value + b"\n"
                    if file_format == "dotenv"
                    else opaque_value + b"\n"
                )
            files.append(
                {
                    "id": file_id,
                    "path": f"operator/{file_id}",
                    "consumers": ["fixture"],
                    "format": file_format,
                    "mode": "0600",
                    "allowed_owners": ["root:root"],
                    "required_keys": required_keys,
                }
            )
        inventory.write_text(
            json.dumps(
                {
                    "schema_id": "io.registrystack.deployment_operator_files",
                    "schema_version": "1.0",
                    "files": files,
                }
            ),
            encoding="utf-8",
        )

        copied = self.module.copy_governed_operator_inputs(package, credentials)

        self.assertEqual(copied, len(self.module.GOVERNED_OPERATOR_SOURCES))
        filtered = package / "operator/postgresql-bootstrap-environment"
        self.assertEqual(
            filtered.read_bytes(),
            b"KEEP="
            + fixture_bytes("postgresql-bootstrap-environment-dotenv")
            + b"\n",
        )
        if os.name == "posix":
            self.assertEqual(filtered.stat().st_mode & 0o777, 0o600)

    def test_lane_signing_keys_are_private_and_distinct(self) -> None:
        if shutil.which("openssl") is None:
            self.skipTest("openssl is unavailable")
        keys = self.module.create_lane_signing_keys(self.root / "keys")

        self.assertEqual(set(keys), set(self.module.GOVERNED_LANES))
        public_values = []
        for private_path, public_path in keys.values():
            private = json.loads(private_path.read_text(encoding="utf-8"))
            public = json.loads(public_path.read_text(encoding="utf-8"))
            self.assertEqual(private["x"], public["x"])
            self.assertIn("d", private)
            self.assertNotIn("d", public)
            public_values.append(public["x"])
            if os.name == "posix":
                self.assertEqual(private_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(public_values), len(set(public_values)))

    def test_stable_smoke_requires_zero_denied_source_access(self) -> None:
        path, report, logs = self.write_valid_stable_report_evidence()
        report["smoke"]["results"][1]["source_counter_delta"] = 1
        (logs / "dev_smoke.log").write_text(
            json.dumps(report["smoke"], sort_keys=True) + "\n", encoding="utf-8"
        )
        command = next(
            command
            for command in report["commands"]
            if command["name"] == "dev_smoke"
        )
        command["log_sha256"] = hashlib.sha256(
            (logs / "dev_smoke.log").read_bytes()
        ).hexdigest()
        write_report_fixture(path, report)
        with (
            self.assertRaisesRegex(
                self.module.ReleaseFormError, "counters or minimized"
            ),
            mock.patch.object(platform, "system", return_value="Linux"),
            mock.patch.object(platform, "machine", return_value="x86_64"),
        ):
            self.module.verify_report(path, self.assets, self.tag)

    def test_opencrvs_smoke_requires_authorized_token_request(self) -> None:
        path, report, logs = self.write_valid_stable_report_evidence()
        report["opencrvs_smoke"]["results"][0]["token_counter_delta"] = 0
        (logs / "oauth_dev_smoke.log").write_text(
            json.dumps(report["opencrvs_smoke"], sort_keys=True) + "\n",
            encoding="utf-8",
        )
        command = next(
            command
            for command in report["commands"]
            if command["name"] == "oauth_dev_smoke"
        )
        command["log_sha256"] = hashlib.sha256(
            (logs / "oauth_dev_smoke.log").read_bytes()
        ).hexdigest()
        write_report_fixture(path, report)

        with (
            self.assertRaisesRegex(
                self.module.ReleaseFormError, "counters or minimized"
            ),
            mock.patch.object(platform, "system", return_value="Linux"),
            mock.patch.object(platform, "machine", return_value="x86_64"),
        ):
            self.module.verify_report(path, self.assets, self.tag)

    def test_oauth_teardown_requires_absent_runtime_state(self) -> None:
        path, report, logs = self.write_valid_stable_report_evidence()
        log = logs / "oauth_dev_down.log"
        log.write_text(
            json.dumps({"outcome": "passed", "runtime_state": "retained"}) + "\n",
            encoding="utf-8",
        )
        command = next(
            command
            for command in report["commands"]
            if command["name"] == "oauth_dev_down"
        )
        command["log_sha256"] = hashlib.sha256(log.read_bytes()).hexdigest()
        write_report_fixture(path, report)
        with (
            self.assertRaisesRegex(
                self.module.ReleaseFormError, "OAuth development teardown"
            ),
            mock.patch.object(platform, "system", return_value="Linux"),
            mock.patch.object(platform, "machine", return_value="x86_64"),
        ):
            self.module.verify_report(path, self.assets, self.tag)

    def test_public_source_live_requires_both_environment_smokes(self) -> None:
        path, report, _ = self.write_valid_stable_report_evidence()
        evidence = path.parent / "public-source-live"
        (evidence / "public-demo-missing-smoke.txt").unlink()
        report["public_source_live"]["evidence_sha256"].pop(
            "public-demo-missing-smoke.txt"
        )
        write_report_fixture(path, report)

        with (
            self.assertRaisesRegex(
                self.module.ReleaseFormError, "evidence set is not closed"
            ),
            mock.patch.object(platform, "system", return_value="Linux"),
            mock.patch.object(platform, "machine", return_value="x86_64"),
        ):
            self.module.verify_report(path, self.assets, self.tag)

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

    def test_governed_evidence_uses_stdin_for_token_and_records_minimized_summary(
        self,
    ) -> None:
        token = "governed-caller-secret"
        token_file = self.root / "caller-token"
        token_file.write_text(token, encoding="ascii")
        logs = self.root / "governed-logs"
        logs.mkdir()
        body = json.dumps(
            {
                "results": [
                    {
                        "claim_id": "todo-record-exists",
                        "value": True,
                        "satisfied": True,
                        "disclosure": "predicate",
                        "provenance": {"used": {"relay_consultation_count": 1}},
                    }
                ]
            }
        )
        completed = subprocess.CompletedProcess(
            [], 0, body + "\nREGISTRYCTL_HTTP_STATUS:200", ""
        )

        with mock.patch.object(
            self.module.subprocess, "run", return_value=completed
        ) as run:
            record = self.module.governed_evidence_request(
                notary_port=43422,
                caller_token_file=token_file,
                cwd=self.root,
                env={},
                logs=logs,
            )

        command = run.call_args.args[0]
        self.assertNotIn(token, " ".join(command))
        self.assertIn(token, run.call_args.kwargs["input"])
        self.assertEqual(record["name"], "governed_evidence")
        summary = json.loads(
            (logs / "governed_evidence.log").read_text(encoding="utf-8")
        )
        self.assertEqual(summary, self.module.GOVERNED_EVIDENCE_SUMMARY)
        self.assertEqual(summary["relay_consultation_count"], 1)

    def test_governed_evidence_rejects_an_unexpected_claim(self) -> None:
        token_file = self.root / "caller-token"
        token_file.write_text("governed-caller-secret", encoding="ascii")
        logs = self.root / "governed-logs"
        logs.mkdir()
        completed = subprocess.CompletedProcess(
            [],
            0,
            json.dumps(
                {
                    "results": [
                        {
                            "claim_id": "todo-completed",
                            "value": True,
                            "satisfied": True,
                            "disclosure": "value",
                        }
                    ]
                }
            )
            + "\nREGISTRYCTL_HTTP_STATUS:200",
            "",
        )

        with (
            mock.patch.object(
                self.module.subprocess, "run", return_value=completed
            ),
            self.assertRaisesRegex(
                self.module.ReleaseFormError, "unexpected claim"
            ),
        ):
            self.module.governed_evidence_request(
                notary_port=43422,
                caller_token_file=token_file,
                cwd=self.root,
                env={},
                logs=logs,
            )

    def test_governed_evidence_requires_one_relay_consultation(self) -> None:
        token_file = self.root / "caller-token"
        token_file.write_text("governed-caller-secret", encoding="ascii")
        logs = self.root / "governed-logs"
        logs.mkdir()
        completed = subprocess.CompletedProcess(
            [],
            0,
            json.dumps(
                {
                    "results": [
                        {
                            "claim_id": "todo-record-exists",
                            "value": True,
                            "satisfied": True,
                            "disclosure": "predicate",
                            "provenance": {
                                "used": {"relay_consultation_count": 0}
                            },
                        }
                    ]
                }
            )
            + "\nREGISTRYCTL_HTTP_STATUS:200",
            "",
        )

        with (
            mock.patch.object(
                self.module.subprocess, "run", return_value=completed
            ),
            self.assertRaisesRegex(
                self.module.ReleaseFormError,
                "exactly one Relay consultation",
            ),
        ):
            self.module.governed_evidence_request(
                notary_port=43422,
                caller_token_file=token_file,
                cwd=self.root,
                env={},
                logs=logs,
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
        postgres_material = fixture_bytes("postgres-env-material")
        audit_material = fixture_bytes("audit-env-material")
        env_file.write_bytes(
            b"POSTGRES_USER=registryctl_bootstrap\n"
            b"PGDATA=/var/lib/postgresql/data/pgdata\n"
            b"REGISTRYCTL_LOCAL_WORKLOAD_PUBLIC_JWK=public-jwk\n"
            b"REGISTRYCTL_LOCAL_RELAY_MATCH_KEY_HASH=public-fingerprint\n"
            b"POSTGRES_PASSWORD=" + postgres_material + b"\n"
            b"REGISTRY_RELAY_AUDIT_HASH_SECRET=" + audit_material + b"\n"
        )

        values = self.module.credential_env_values(env_file)

        self.assertIn(postgres_material, values)
        self.assertIn(audit_material, values)
        self.assertNotIn(b"registryctl_bootstrap", values)
        self.assertNotIn(b"/var/lib/postgresql/data/pgdata", values)
        self.assertNotIn(b"public-jwk", values)
        self.assertNotIn(b"public-fingerprint", values)

    def test_partial_secret_directory_still_yields_failure_redaction_values(
        self,
    ) -> None:
        secrets = self.root / "secrets"
        secrets.mkdir()
        relay_material = fixture_text("relay-raw-material")
        workload_material = fixture_text("relay-workload-material")
        (secrets / "relay-consultation-serve.env").write_text(
            f"REGISTRY_RELAY_AUDIT_HASH_SECRET={relay_material}\n",
            encoding="utf-8",
        )
        (secrets / "notary.private.jwk").write_text(
            workload_material + "\n",
            encoding="utf-8",
        )

        values = self.module.available_secret_values(secrets)

        self.assertIn(relay_material.encode(), values)
        self.assertIn(workload_material.encode(), values)

    def test_recursive_secret_collection_uses_explicit_public_allowlist(
        self,
    ) -> None:
        credentials = self.root / "credentials"
        credentials.mkdir(mode=0o700)
        api_material = fixture_bytes("recursive-api-env")
        tls_material = fixture_bytes("recursive-tls-key")
        signing_material = fixture_bytes("recursive-signing-key")
        public_jwk_material = fixture_bytes("recursive-public-jwk")
        certificate_material = fixture_bytes("recursive-public-certificate")
        unlisted_certificate_material = fixture_bytes("recursive-unlisted-certificate")
        values = {
            "relay-public-serve.env": b"API_SECRET=" + api_material + b"\n",
            "postgres-tls.key": tls_material + b"\n",
            "relay-public.private.jwk": signing_material + b"\n",
            "relay-public.public.jwk": public_jwk_material + b"\n",
            "postgres-tls.crt": certificate_material + b"\n",
            "unlisted.crt": unlisted_certificate_material + b"\n",
        }
        for name, value in values.items():
            path = credentials / name
            path.write_bytes(value)
            path.chmod(0o600)

        observed = self.module.recursive_secret_values(credentials)

        self.assertIn(api_material, observed)
        self.assertIn(tls_material, observed)
        self.assertIn(signing_material, observed)
        self.assertIn(unlisted_certificate_material, observed)
        self.assertNotIn(public_jwk_material, observed)
        self.assertNotIn(certificate_material, observed)

    def test_dev_credentials_reject_non_private_and_symlinked_files(self) -> None:
        credentials = self.root / "credentials"
        credentials.mkdir(mode=0o700)
        operator_env = credentials / "relay-public-serve.env"
        operator_env.write_text(
            f"API_SECRET={fixture_text('dev-credential-env')}\n",
            encoding="utf-8",
        )
        operator_env.chmod(0o644)
        with self.assertRaisesRegex(
            self.module.ReleaseFormError, "not owner-only"
        ):
            self.module.validate_dev_credentials(credentials)

        operator_env.chmod(0o600)
        (credentials / "linked-private-key").symlink_to(operator_env)
        with self.assertRaisesRegex(
            self.module.ReleaseFormError, "regular and non-symlink"
        ):
            self.module.validate_dev_credentials(credentials)

    def test_release_environment_drops_all_unowned_control_variables(self) -> None:
        observed = self.module.sealed_release_environment(
            {
                "PATH": "/usr/bin",
                "CI": "1",
                "REGISTRYCTL_ASSET_DIR": "/attacker",
                "REGISTRYCTL_RELEASE_LOCK_BYPASS": "1",
                "COMPOSE_PROJECT_NAME": "attacker",
                "COMPOSE_FILE": "/attacker/compose.yaml",
            }
        )
        self.assertEqual(observed, {"PATH": "/usr/bin", "CI": "1"})

    def test_release_form_project_identity_is_unique_and_closed(self) -> None:
        project_file = self.root / "registry-stack.yaml"
        project_file.write_text(
            "version: 1\nregistry:\n  id: fictional-citizen-registry\n",
            encoding="utf-8",
        )
        project_id = "first-country-release-form-0123456789abcdef"

        self.module.bind_release_form_project_identity(project_file, project_id)

        self.assertEqual(
            project_file.read_text(encoding="utf-8"),
            f"version: 1\nregistry:\n  id: {project_id}\n",
        )
        with self.assertRaisesRegex(
            self.module.ReleaseFormError, "project identity is invalid"
        ):
            self.module.bind_release_form_project_identity(
                project_file, "fictional-citizen-registry"
            )

    def test_governed_loopback_ports_are_nonzero_and_distinct(self) -> None:
        relay_port, notary_port = self.module.available_governed_loopback_ports()

        self.assertNotEqual(relay_port, notary_port)
        for port in (relay_port, notary_port):
            self.assertGreater(port, 0)

    def test_dev_status_and_logs_require_exact_current_schemas(self) -> None:
        status = {
            "schema_version": "registryctl.dev_status.v1",
            "binding": {
                "project": "fixture",
                "environment": "local",
                "project_root_digest": "sha256:" + "a" * 64,
            },
            "source_mode": "synthetic",
            "relay_api_url": "http://127.0.0.1:4242",
            "evidence_api_url": "http://127.0.0.1:4243",
            "records_denied_command": None,
            "records_request_command": None,
            "evidence_request_command": "curl --config '<owner-only-request-config>'",
            "workloads": [
                {"workload": name, "state": "running"}
                for name in sorted(self.module.STABLE_WORKLOAD_IMAGES)
            ],
        }
        logs = {
            "schema_version": "registryctl.dev_logs.v1",
            "binding": {
                "project": "fixture",
                "environment": "local",
                "project_root_digest": "sha256:" + "a" * 64,
            },
            "products": [
                {"workload": name, "available": True}
                for name in sorted(
                    {
                        "relay-public",
                        "relay-consultation",
                        "notary",
                        "synthetic-source",
                    }
                )
            ],
        }
        self.assertEqual(
            self.module.stable_status_summary(status)["schema_version"],
            "registryctl.dev_status.v1",
        )
        self.assertEqual(
            self.module.stable_logs_summary(logs)["schema_version"],
            "registryctl.dev_logs.v1",
        )
        status["schema_version"] = "registryctl.dev_status.v0"
        logs["schema_version"] = "registryctl.dev_logs.v0"
        with self.assertRaises(self.module.ReleaseFormError):
            self.module.stable_status_summary(status)
        with self.assertRaises(self.module.ReleaseFormError):
            self.module.stable_logs_summary(logs)

    def test_governed_binding_uses_signed_identity_and_unique_volume_prefix(
        self,
    ) -> None:
        project_id = "first-country-release-form-0123456789abcdef"
        bundle = self.root / "relay-public"
        (bundle / "bundle").mkdir(parents=True)
        manifest = {
            "acceptance_identity": {
                "trust_domain": "governed",
                "project": project_id,
                "environment": "local",
                "lane": "relay-public",
                "product": "registry-relay",
                "stream": project_id,
                "instance": "relay-public",
            }
        }
        (bundle / "bundle/manifest.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )
        destination = self.root / "private/binding.json"

        package_id, volume_prefix = self.module.governed_deployment_binding(
            bundle,
            destination,
            expected_project=project_id,
            expected_environment="local",
            ports=(43421, 43422),
        )
        binding = json.loads(destination.read_text(encoding="utf-8"))

        identity_bytes = (
            b'{"environment":"local","project":'
            b'"first-country-release-form-0123456789abcdef"}'
        )
        self.assertEqual(
            package_id,
            "registry-" + hashlib.sha256(identity_bytes).hexdigest()[:24],
        )
        self.assertEqual(binding["package_id"], package_id)
        self.assertEqual(volume_prefix, project_id)
        self.assertEqual(binding["durable_volume_prefix"], volume_prefix)
        self.assertEqual(
            set(binding["secret_files"]),
            set(self.module.GOVERNED_OPERATOR_SOURCES),
        )
        self.assertEqual(
            binding["ports"], {"relay_public": 43421, "notary": 43422}
        )
        self.assertNotIn("edge_network_name", binding)
        if os.name == "posix":
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)

        manifest["acceptance_identity"]["stream"] = "shared-stream"
        (bundle / "bundle/manifest.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )
        with self.assertRaisesRegex(
            self.module.ReleaseFormError, "expected closed value"
        ):
            self.module.governed_deployment_binding(
                bundle,
                destination,
                expected_project=project_id,
                expected_environment="local",
                ports=(43421, 43422),
            )

    def test_governed_binding_rejects_preexisting_docker_resources(self) -> None:
        empty = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.object(
            self.module.subprocess,
            "run",
            side_effect=[
                subprocess.CompletedProcess([], 0, "container-id\n", ""),
                empty,
                empty,
            ],
        ):
            with self.assertRaisesRegex(
                self.module.ReleaseFormError, "preexisting Docker resources"
            ):
                self.module.assert_governed_resources_absent(
                    "registry-package",
                    "release-volume",
                    cwd=self.root,
                    env={},
                )

        with mock.patch.object(
            self.module.subprocess,
            "run",
            side_effect=[
                empty,
                empty,
                subprocess.CompletedProcess(
                    [], 0, "release-volume-postgresql-data\n", ""
                ),
            ],
        ):
            with self.assertRaisesRegex(
                self.module.ReleaseFormError, "preexisting Docker resources"
            ):
                self.module.assert_governed_resources_absent(
                    "registry-package",
                    "release-volume",
                    cwd=self.root,
                    env={},
                )

    def test_rollback_evidence_requires_typed_rejection_for_both_lanes(
        self,
    ) -> None:
        logs = self.root / "logs"
        logs.mkdir(mode=0o700)
        def typed(component, stream_id):
            return json.dumps(
                {
                    "schema": "registry.platform.config_apply_report.v1",
                    "attempt_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
                    "component": component,
                    "stream_id": stream_id,
                    "source": "signed_bundle_file",
                    "bundle_id": None,
                    "bundle_sequence": None,
                    "previous_config_hash": None,
                    "config_hash": None,
                    "result": "rejected_rollback",
                    "restart_required": False,
                    "change_classes": [],
                    "affected_components": [],
                    "warnings": [],
                    "errors": [
                        {
                            "code": "rejected_rollback",
                            "message": self.module.ROLLBACK_SAFE_MESSAGE,
                        }
                    ],
                },
                indent=2,
            )

        relay_typed = typed("registry-relay", None)
        notary_typed = typed("registry-notary", "unknown")
        with mock.patch.object(
            self.module.subprocess,
            "run",
            side_effect=[
                subprocess.CompletedProcess([], 1, relay_typed),
                subprocess.CompletedProcess([], 1, notary_typed),
            ],
        ):
            self.module.run_expected_rollbacks(
                "rollback",
                [("relay-consultation", ["relay"]), ("notary", ["notary"])],
                cwd=self.root,
                env={},
                logs=logs,
            )
        self.assertEqual(
            json.loads((logs / "rollback.log").read_text(encoding="utf-8")),
            {
                "outcome": "rejected",
                "classification": "rejected_rollback",
                "lanes": ["relay-consultation", "notary"],
            },
        )

        with (
            mock.patch.object(
                self.module.subprocess,
                "run",
                side_effect=[
                    subprocess.CompletedProcess([], 1, relay_typed),
                    subprocess.CompletedProcess(
                        [],
                        1,
                        notary_typed.replace(
                            '"stream_id": "unknown"',
                            '"stream_id": "country-sensitive-stream"',
                        ),
                    ),
                ],
            ),
            self.assertRaisesRegex(
                self.module.ReleaseFormError, "value-free rejected_rollback"
            ),
        ):
            self.module.run_expected_rollbacks(
                "invalid-rollback",
                [("relay-consultation", ["relay"]), ("notary", ["notary"])],
                cwd=self.root,
                env={},
                logs=logs,
            )

        with self.assertRaisesRegex(
            self.module.ReleaseFormError, "every affected lane"
        ):
            self.module.run_expected_rollbacks(
                "incomplete-rollback",
                [("relay-consultation", ["relay"])],
                cwd=self.root,
                env={},
                logs=logs,
            )

    def test_backup_selects_exactly_seven_durable_volumes(self) -> None:
        package = self.root / "package"
        package.mkdir()
        volume_prefix = "release"
        durable = {
            "registry-postgres": {
                "/var/lib/postgresql/data": "release-postgresql-data"
            },
            "registry-relay-public": {
                "/var/lib/registry/state": "release-relay-public-state",
                "/var/lib/registry/audit": "release-relay-public-audit",
            },
            "registry-relay-consultation": {
                "/var/lib/registry/state": "release-relay-consultation-state",
                "/var/lib/registry/audit": "release-relay-consultation-audit",
            },
            "registry-notary": {
                "/var/lib/registry/state": "release-notary-state",
                "/var/lib/registry/audit": "release-notary-audit",
            },
        }
        services = {
            service: {
                "volumes": [
                    {"type": "volume", "source": source, "target": target}
                    for target, source in targets.items()
                ]
            }
            for service, targets in durable.items()
        }
        for stager_name, contract in (
            self.module.SERVING_SECRET_STAGER_CONTRACT.items()
        ):
            services[stager_name] = {
                "volumes": [
                    {
                        "type": "volume",
                        "source": (f"{volume_prefix}-operator-files-{stage_id}"),
                        "target": f"/registryctl-stage/output/{stage_id}",
                    }
                    for stage_id in contract["outputs"]
                ]
            }
        sources = {
            source for targets in durable.values() for source in targets.values()
        }
        staged_sources = {
            mount["source"]
            for stager_name in self.module.SERVING_SECRET_STAGER_CONTRACT
            for mount in services[stager_name]["volumes"]
        }
        project_name = "governed-fixture"
        volume_names = {
            source: f"{project_name}_{source}"
            for source in sources | staged_sources
        }
        document = {
            "name": project_name,
            "services": services,
            "volumes": {
                source: {"name": volume_names[source]}
                for source in sources | staged_sources
            },
        }

        def completed(command, **_kwargs):
            if "config" in command:
                return subprocess.CompletedProcess(
                    command, 0, json.dumps(document), ""
                )
            if command[:3] == ["docker", "volume", "ls"]:
                return subprocess.CompletedProcess(
                    command,
                    0,
                    "\n".join(sorted(volume_names.values())) + "\n",
                    "",
                )
            return subprocess.CompletedProcess(command, 0, "", "")

        logs = self.root / "logs"
        logs.mkdir(mode=0o700)
        with mock.patch.object(
            self.module.subprocess, "run", side_effect=completed
        ) as run:
            self.module.backup_and_restore_governed_volumes(
                package,
                postgresql_image=self.postgresql,
                volume_prefix=volume_prefix,
                backup_root=self.root / "backup",
                env={},
                logs=logs,
            )
        backup_commands = [
            call.args[0]
            for call in run.call_args_list
            if call.args[0][:2] == ["docker", "run"]
            and "-cf" in call.args[0]
        ]
        self.assertEqual(len(backup_commands), 7)
        self.assertTrue(
            all(
                any(
                    argument == f"{volume_names[source]}:/source:ro"
                    for source in sources
                    for argument in command
                )
                for command in backup_commands
            )
        )
        self.assertFalse(
            any(
                volume_names[staged_source] in argument
                for command in backup_commands
                for argument in command
                for staged_source in staged_sources
            )
        )
        self.assertEqual(
            json.loads((logs / "backup_restore.log").read_text(encoding="utf-8"))[
                "consistency_group_volumes"
            ],
            7,
        )

        consultation_stage = services["registry-relay-consultation-stage-secrets"]
        consultation_stage["volumes"][0]["source"] = (
            f"{volume_prefix}-operator-files-notary-serve"
        )
        with (
            mock.patch.object(self.module.subprocess, "run", side_effect=completed),
            self.assertRaisesRegex(
                self.module.ReleaseFormError,
                "wrong backup-excluded output authority",
            ),
        ):
            self.module.backup_and_restore_governed_volumes(
                package,
                postgresql_image=self.postgresql,
                volume_prefix=volume_prefix,
                backup_root=self.root / "cross-lane-backup",
                env={},
                logs=logs,
            )
        consultation_stage["volumes"][0]["source"] = (
            f"{volume_prefix}-operator-files-relay-consultation-serve"
        )

        postgresql_source = "release-postgresql-data"
        document["volumes"][postgresql_source] = {
            "name": "country-shared-postgresql-data"
        }
        with (
            mock.patch.object(self.module.subprocess, "run", side_effect=completed),
            self.assertRaisesRegex(
                self.module.ReleaseFormError,
                "durable volume identity is unexpected",
            ),
        ):
            self.module.backup_and_restore_governed_volumes(
                package,
                postgresql_image=self.postgresql,
                volume_prefix=volume_prefix,
                backup_root=self.root / "aliased-backup",
                env={},
                logs=logs,
            )
        document["volumes"][postgresql_source] = {
            "name": volume_names[postgresql_source]
        }

        services["registry-postgres"]["volumes"][0]["source"] = (
            "country-shared-postgresql-data"
        )
        with (
            mock.patch.object(self.module.subprocess, "run", side_effect=completed),
            self.assertRaisesRegex(
                self.module.ReleaseFormError,
                "identity is incomplete or unexpected",
            ),
        ):
            self.module.backup_and_restore_governed_volumes(
                package,
                postgresql_image=self.postgresql,
                volume_prefix=volume_prefix,
                backup_root=self.root / "wrong-source-backup",
                env={},
                logs=logs,
            )
        services["registry-postgres"]["volumes"][0]["source"] = postgresql_source

        document["volumes"]["unexpected-durable"] = {}
        with (
            mock.patch.object(
                self.module.subprocess, "run", side_effect=completed
            ),
            self.assertRaisesRegex(
                self.module.ReleaseFormError, "unexpected durable volume"
            ),
        ):
            self.module.backup_and_restore_governed_volumes(
                package,
                postgresql_image=self.postgresql,
                volume_prefix=volume_prefix,
                backup_root=self.root / "second-backup",
                env={},
                logs=logs,
            )

    def test_workflows_keep_candidate_authoring_and_released_runtime_proofs_separate(
        self,
    ) -> None:
        candidate = WORKFLOW.read_text(encoding="utf-8")
        release = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        binary = candidate.index("name: Build canonical Linux payload once")
        docs = candidate.index("name: Package exact release docs archive")
        authoring = candidate.index(
            "name: Run exact candidate Registryctl against archived authoring journeys"
        )
        stage = candidate.index("name: Stage canonical build products")
        seal = candidate.index("name: Seal compact candidate manifest and bundle")
        self.assertLess(binary, docs)
        self.assertLess(docs, authoring)
        self.assertLess(authoring, stage)
        self.assertLess(stage, seal)
        self.assertIn(
            "REGISTRYCTL_BIN: ${{ github.workspace }}/dist/bin/"
            "registryctl-${{ needs.validate.outputs.tag }}-linux-amd64",
            candidate,
        )
        self.assertIn(
            "REGISTRYCTL_RELEASED_DOCS_ARCHIVE: ${{ runner.temp }}/"
            "registry-docs-${{ needs.validate.outputs.tag }}.tar.gz",
            candidate,
        )
        self.assertIn(
            "REGISTRYCTL_RELEASED_DOCS_ROOT: "
            "${{ runner.temp }}/candidate-released-docs/version",
            candidate,
        )
        self.assertIn(
            "bash docs/site/scripts/check-registryctl-tutorials.sh", candidate
        )
        self.assertIn("validate version-appropriate install inputs", candidate)
        self.assertIn("if ((major >= 1)); then", candidate)
        self.assertNotIn("first-country-release-form.py run", candidate)
        self.assertIn("registry_release_lock.py create-payload", candidate)
        self.assertNotIn("REGISTRYCTL_RELEASE_LOCK_BYPASS", candidate)
        self.assertNotIn("REGISTRYCTL_ASSET_DIR", candidate)
        self.assertNotIn("registry-release-lock.v1.json", candidate)
        self.assertIn("if ((major >= 1)); then", release)
        self.assertIn("first-country-release-form.py run", release)
        self.assertIn("registry-release-lock.v1.json", release)
        self.assertIn("REGISTRYCTL_ASSET_DIR", SCRIPT.read_text(encoding="utf-8"))
        self.assertNotIn("--relay-image-override", release)
        self.assertNotIn("--notary-image-override", release)
        self.assertNotIn("--relay-image-override", candidate)
        self.assertNotIn("--notary-image-override", candidate)
        self.assertNotIn(
            "Verify candidate beginner journey on ${{ matrix.asset }}", candidate
        )
        self.assertNotIn("DOCKER_DEFAULT_PLATFORM=linux/amd64", candidate)


if __name__ == "__main__":
    main()
