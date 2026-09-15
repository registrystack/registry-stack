#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import ast
import copy
import datetime as dt
import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tarfile
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import TestCase, main


SCRIPTS = Path(__file__).resolve().parent
TOOL = SCRIPTS / "registry-release"
VERSION = "0.32.0"
IMAGES = ("breg", "casework", "discovery", "evidence", "relay")
SOURCE = "https://github.com/registrystack/registry-stack"
OLD_REVISION = "a" * 40
NEW_REVISION = "b" * 40
BASE_LAYERS = ["sha256:" + "1" * 64, "sha256:" + "2" * 64]
OLD_APP_LAYER = "sha256:" + "3" * 64
NEW_APP_LAYER = "sha256:" + "4" * 64
LIBC = "/usr/lib/x86_64-linux-gnu/libc.so.6"
TODAY = dt.date(2026, 9, 15)
RUNTIME_CONFIG = {
    "user": "65532",
    "entrypoint": ["/usr/local/bin/service"],
    "command": ["serve"],
    "working_dir": "/",
    "environment": ["PATH=/usr/local/bin:/usr/bin:/bin"],
    "healthcheck": None,
    "args_escaped": False,
    "exposed_ports": ["8080/tcp"],
    "stop_signal": "",
}
PINS = '''# SPDX-License-Identifier: Apache-2.0
LIVE_BASELINES = ()
LIVE_REFERENCE_IMAGE_DIGESTS = {
{digests}}
LIVE_REFERENCE_SOURCE_REVISION = "{revision}"
# Move it forward by hand when the baselines are renewed.
LIVE_REVIEW_EVALUATION_DATE = "2026-09-01"
LIVE_REFERENCE_PROVENANCE = {
{provenance}}
LIVE_EXECUTABLES = {
    "relay": "/usr/local/bin/relay",
}
'''


def load_module(name: str, path: Path):
    sys.path.insert(0, str(SCRIPTS))
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise ImportError(f"could not load module spec from {path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


renewal = load_module("advisory_renewal", SCRIPTS / "advisory_renewal.py")
release_candidate = load_module("release_candidate", SCRIPTS / "release_candidate.py")
checker = renewal.checker


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def image_digest(name: str, generation: str) -> str:
    return sha256(f"{generation}-{name}-image".encode())


def with_digest(definition: dict) -> dict:
    definition["definition_digest"] = checker.definition_digest(definition)
    return definition


class AdvisoryRenewalTest(TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.repo = base / "repo"
        self.evidence = base / "evidence"
        for directory in ("grype", "syft", "oci-config", "rootfs"):
            (self.evidence / directory).mkdir(parents=True)
        self.pins = self.repo / "release/scripts/test_check_advisory_baselines.py"
        self.pins.parent.mkdir(parents=True)
        self.pins.write_text(
            PINS.replace(
                "{digests}",
                "".join(
                    f'    "{name}": "{image_digest(name, "old")}",\n'
                    for name in reversed(IMAGES)
                ),
            )
            .replace("{revision}", OLD_REVISION)
            .replace(
                "{provenance}",
                "".join(
                    f'    "{name}": "local_reproduction",\n'
                    for name in reversed(IMAGES)
                ),
            ),
            encoding="utf-8",
        )
        self.collection = {
            "schema_version": "registry-stack.rehearsal-advisory-evidence.v1",
            "purpose": "review_only",
            "publication_eligible": False,
            "advisory_accepted": False,
            "version": VERSION,
            "source": SOURCE,
            "revision": NEW_REVISION,
            "images": [
                {"name": name, "digest": image_digest(name, "new")} for name in IMAGES
            ],
        }
        self.write_collection()
        for name in IMAGES:
            self.write_image(name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def files(self, name: str, generation: str) -> dict[str, bytes]:
        return {
            f"/usr/local/bin/{name}": f"{generation} {name} executable".encode(),
            LIBC: b"libc bytes",
        }

    def baseline_path(self, name: str) -> Path:
        return release_candidate.advisory_baseline_path(self.repo, name)

    def write_collection(self) -> None:
        (self.evidence / "collection.json").write_text(
            json.dumps(self.collection, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def write_json(self, path: Path, value: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", "utf-8")

    def read_json(self, path: Path) -> dict:
        return json.loads(path.read_text(encoding="utf-8"))

    def write_image(self, name: str) -> None:
        old_files = self.files(name, "old")
        new_files = self.files(name, "new")
        runtime = with_digest(
            {
                "image": "gcr.io/distroless/cc-debian13@sha256:" + "9" * 64,
                "layer_ids": list(BASE_LAYERS),
                "application_layer_ids": [OLD_APP_LAYER],
                "config": copy.deepcopy(RUNTIME_CONFIG),
            }
        )
        assertion = with_digest(
            {
                "kind": "whole_image_fingerprint_equals",
                "reference_image_digest": image_digest(name, "old"),
                "reference_source_revision": OLD_REVISION,
                "reference_provenance": "local_reproduction",
                "runtime_definition_digest": runtime["definition_digest"],
                "files": [
                    {"path": path, "sha256": sha256(data)}
                    for path, data in sorted(old_files.items())
                ],
            }
        )
        baseline = {
            "version": 4,
            "service": name,
            "runtime": runtime,
            "policies": [
                {"tool": "zizmor", "minimum_severity": "high", "action": "block_unreviewed"},
                {
                    "tool": "grype",
                    "minimum_severity": "high",
                    "action": "block_unreviewed",
                    "block_fixable": True,
                },
            ],
            "exceptions": [
                {
                    "vulnerability_id": "CVE-2026-0001",
                    "package": "libc6",
                    "installed_version": "2.41-12",
                    "severity": "High",
                    "status": "accepted_risk",
                    "owner": "@maintainers",
                    "rationale": "Reviewed v0.31.0 local reproduction evidence.",
                    "reviewed_at": "2026-09-01",
                    "expires_at": "2026-09-18",
                    "invalidation_triggers": sorted(
                        checker.REQUIRED_INVALIDATION_TRIGGERS
                    ),
                    "runtime_definition_digest": runtime["definition_digest"],
                    "component_layer_id": OLD_APP_LAYER,
                    "exposure_assertion": assertion,
                }
            ],
        }
        self.write_json(self.baseline_path(name), baseline)

        digest = image_digest(name, "new")
        layers = BASE_LAYERS + [NEW_APP_LAYER]
        target = {
            "userInput": f"localhost:5000/{name}@{digest}",
            "repoDigests": [f"localhost:5000/{name}@{digest}"],
            "architecture": "amd64",
            "os": "linux",
            "layers": [{"digest": layer} for layer in layers],
        }
        artifact = {
            "id": "libc6-artifact",
            "name": "libc6",
            "version": "2.41-12",
            "type": "deb",
            "locations": [
                {"path": "/var/lib/dpkg/status.d/libc6", "layerID": NEW_APP_LAYER}
            ],
        }
        self.write_json(
            self.evidence / f"grype/{name}.grype.json",
            {
                "descriptor": {"name": "grype", "version": "0.104.0"},
                "source": {"type": "image", "target": copy.deepcopy(target)},
                "matches": [
                    {
                        "vulnerability": {
                            "id": "CVE-2026-0001",
                            "severity": "High",
                            "fix": {"versions": [], "state": "not-fixed"},
                        },
                        "artifact": copy.deepcopy(artifact),
                    }
                ],
            },
        )
        self.write_json(
            self.evidence / f"syft/{name}.syft.json",
            {
                "descriptor": {"name": "syft", "version": "1.45.1"},
                "schema": {"version": "16.1.3"},
                "source": {"type": "image", "metadata": copy.deepcopy(target)},
                "artifacts": [copy.deepcopy(artifact)],
                "files": [
                    {
                        "id": f"file-{index}",
                        "location": {"path": path, "layerID": NEW_APP_LAYER},
                        "digests": [
                            {
                                "algorithm": "sha256",
                                "value": hashlib.sha256(data).hexdigest(),
                            }
                        ],
                    }
                    for index, (path, data) in enumerate(sorted(new_files.items()))
                ],
            },
        )
        self.write_json(
            self.evidence / f"oci-config/{name}.json",
            {
                "architecture": "amd64",
                "os": "linux",
                "rootfs": {"type": "layers", "diff_ids": layers},
                "config": {
                    "User": "65532",
                    "Entrypoint": ["/usr/local/bin/service"],
                    "Cmd": ["serve"],
                    "WorkingDir": "/",
                    "Env": ["PATH=/usr/local/bin:/usr/bin:/bin"],
                    "ArgsEscaped": False,
                    "ExposedPorts": {"8080/tcp": {}},
                    "Labels": {
                        "org.opencontainers.image.source": SOURCE,
                        "org.opencontainers.image.revision": NEW_REVISION,
                        "org.opencontainers.image.version": VERSION,
                        "org.registrystack.runtime.uid": "65532",
                        "org.registrystack.runtime.gid": "65532",
                    },
                },
            },
        )
        self.write_rootfs(name, new_files)

    def write_rootfs(
        self, name: str, files: dict[str, bytes], *, fifo: str | None = None
    ) -> None:
        with tarfile.open(self.evidence / f"rootfs/{name}.tar", "w") as archive:
            for path, data in sorted(files.items()):
                info = tarfile.TarInfo(path.lstrip("/"))
                info.size = len(data)
                info.mode = 0o755
                archive.addfile(info, io.BytesIO(data))
            if fifo is not None:
                info = tarfile.TarInfo(fifo.lstrip("/"))
                info.type = tarfile.FIFOTYPE
                archive.addfile(info)

    def edit_json(self, path: Path, edit) -> None:
        value = self.read_json(path)
        edit(value)
        self.write_json(path, value)

    def renew(self, *, write: bool = False, reviewed_at: str = "2026-09-15"):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = renewal.run(
                self.repo,
                self.evidence,
                version=VERSION,
                source_revision=NEW_REVISION,
                reviewed_at=reviewed_at,
                write=write,
                today=TODAY.isoformat(),
            )
        return status, stdout.getvalue(), stderr.getvalue()

    def snapshot(self) -> dict[Path, bytes]:
        paths = [self.baseline_path(name) for name in IMAGES] + [self.pins]
        return {path: path.read_bytes() for path in paths}

    def assert_refused(self, message: str, **kwargs) -> str:
        before = self.snapshot()
        status, _stdout, stderr = self.renew(write=True, **kwargs)
        self.assertEqual(1, status, stderr)
        self.assertIn(message, stderr)
        self.assertEqual(before, self.snapshot())
        return stderr

    def test_baseline_path_follows_the_release_image_layout(self) -> None:
        root = Path("/repo")
        self.assertEqual(
            root / "products/relay-v2/security/advisory-baseline.json",
            release_candidate.advisory_baseline_path(root, "relay"),
        )
        self.assertEqual(
            root / "release/security/breg-advisory-baseline.json",
            release_candidate.advisory_baseline_path(root, "breg"),
        )

    def test_dry_run_reports_every_change_and_writes_nothing(self) -> None:
        before = self.snapshot()

        status, stdout, stderr = self.renew()

        self.assertEqual(0, status, stderr)
        self.assertEqual(before, self.snapshot())
        self.assertIn(
            "exceptions[CVE-2026-0001 libc6].component_layer_id: "
            f"{OLD_APP_LAYER} -> {NEW_APP_LAYER}",
            stdout,
        )
        self.assertIn(
            "exceptions[CVE-2026-0001 libc6].exposure_assertion.files[/usr/local/bin/breg].sha256",
            stdout,
        )
        self.assertIn(
            "exceptions[CVE-2026-0001 libc6].exposure_assertion.reference_source_revision: "
            f"{OLD_REVISION} -> {NEW_REVISION}",
            stdout,
        )
        self.assertIn("runtime.application_layer_ids", stdout)
        self.assertNotIn(f"files[{LIBC}]", stdout)
        self.assertIn("rationale is unchanged", stdout)
        self.assertIn("dry run", stdout)
        self.assertIn("invalid=0", stdout)

    def test_write_renews_every_binding_and_passes_the_strict_checker(self) -> None:
        status, stdout, stderr = self.renew(write=True)

        self.assertEqual(0, status, stderr)
        for name in IMAGES:
            with self.subTest(name=name):
                path = self.baseline_path(name)
                baseline = checker.load_baseline(path)
                text = path.read_text(encoding="utf-8")
                self.assertEqual(
                    json.dumps(baseline, indent=2, ensure_ascii=False) + "\n", text
                )
                runtime = baseline["runtime"]
                self.assertEqual([NEW_APP_LAYER], runtime["application_layer_ids"])
                self.assertEqual(BASE_LAYERS, runtime["layer_ids"])
                exception = baseline["exceptions"][0]
                self.assertEqual("2026-09-15", exception["reviewed_at"])
                self.assertEqual("2026-09-18", exception["expires_at"])
                self.assertEqual(
                    "Reviewed v0.31.0 local reproduction evidence.",
                    exception["rationale"],
                )
                self.assertEqual(NEW_APP_LAYER, exception["component_layer_id"])
                self.assertEqual(
                    runtime["definition_digest"], exception["runtime_definition_digest"]
                )
                assertion = exception["exposure_assertion"]
                self.assertEqual(image_digest(name, "new"), assertion["reference_image_digest"])
                self.assertEqual(NEW_REVISION, assertion["reference_source_revision"])
                self.assertEqual("local_reproduction", assertion["reference_provenance"])
                self.assertEqual(
                    runtime["definition_digest"], assertion["runtime_definition_digest"]
                )
                self.assertEqual(
                    [
                        {"path": path, "sha256": sha256(data)}
                        for path, data in sorted(self.files(name, "new").items())
                    ],
                    assertion["files"],
                )
        self.assertIn("wrote", stdout)

    def test_write_moves_the_live_test_pins_forward(self) -> None:
        status, _stdout, stderr = self.renew(write=True)

        self.assertEqual(0, status, stderr)
        text = self.pins.read_text(encoding="utf-8")
        values = {
            node.targets[0].id: ast.literal_eval(node.value)
            for node in ast.parse(text).body
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
        }
        self.assertEqual(
            {name: image_digest(name, "new") for name in IMAGES},
            values["LIVE_REFERENCE_IMAGE_DIGESTS"],
        )
        self.assertEqual(
            list(reversed(IMAGES)), list(values["LIVE_REFERENCE_IMAGE_DIGESTS"])
        )
        self.assertEqual(NEW_REVISION, values["LIVE_REFERENCE_SOURCE_REVISION"])
        self.assertEqual("2026-09-15", values["LIVE_REVIEW_EVALUATION_DATE"])
        self.assertEqual(
            {name: "local_reproduction" for name in IMAGES},
            values["LIVE_REFERENCE_PROVENANCE"],
        )
        self.assertIn("# Move it forward by hand when the baselines are renewed.", text)
        self.assertIn('"relay": "/usr/local/bin/relay",', text)

    def test_renewal_is_idempotent(self) -> None:
        self.assertEqual(0, self.renew(write=True)[0])
        before = self.snapshot()

        status, stdout, stderr = self.renew(write=True)

        self.assertEqual(0, status, stderr)
        self.assertEqual(before, self.snapshot())
        self.assertIn("breg: no baseline changes", stdout)

    def test_registry_release_exposes_the_subcommand(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "renew-advisory-baselines",
                "--repo",
                str(self.repo),
                "--evidence-dir",
                str(self.evidence),
                "--version",
                VERSION,
                "--source-revision",
                NEW_REVISION,
                "--reviewed-at",
                "2026-09-15",
                "--today",
                TODAY.isoformat(),
                "--write",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(0, result.returncode, result.stderr)
        baseline = checker.load_baseline(self.baseline_path("relay"))
        self.assertEqual(
            NEW_REVISION,
            baseline["exceptions"][0]["exposure_assertion"]["reference_source_revision"],
        )

    def test_refuses_collection_that_is_not_review_only_rehearsal_evidence(self) -> None:
        cases = {
            "purpose": ("purpose", "publication"),
            "publication_eligible": ("publication_eligible", True),
            "advisory_accepted": ("advisory_accepted", True),
            "version": ("version", "0.31.0"),
            "source": ("source", "https://github.com/example/registry-stack"),
            "schema_version": ("schema_version", "registry-stack.other.v1"),
        }
        original = copy.deepcopy(self.collection)
        for message, (field, value) in cases.items():
            with self.subTest(field=field):
                self.collection = copy.deepcopy(original)
                self.collection[field] = value
                self.write_collection()
                self.assert_refused(message)

    def test_refuses_revision_that_does_not_match_the_independent_copy(self) -> None:
        self.collection["revision"] = "c" * 40
        self.write_collection()

        self.assert_refused("does not match --source-revision")

    def test_refuses_image_set_that_differs_from_the_release_roster(self) -> None:
        original = copy.deepcopy(self.collection)
        for label, images in {
            "missing": original["images"][:-1],
            "duplicate": original["images"] + original["images"][:1],
            "unknown": original["images"]
            + [{"name": "mint", "digest": image_digest("mint", "new")}],
        }.items():
            with self.subTest(label=label):
                self.collection = copy.deepcopy(original)
                self.collection["images"] = images
                self.write_collection()
                self.assert_refused("release image roster")

    def test_refuses_scan_of_a_different_image(self) -> None:
        self.collection["images"][0]["digest"] = "sha256:" + "e" * 64
        self.write_collection()

        self.assert_refused("breg: candidate image identity mismatch")

    def test_refuses_changed_runtime_base(self) -> None:
        other_base = "sha256:" + "5" * 64
        for suffix in ("grype/breg.grype.json", "syft/breg.syft.json"):
            key = "target" if suffix.startswith("grype") else "metadata"
            self.edit_json(
                self.evidence / suffix,
                lambda value, key=key: value["source"][key]["layers"].__setitem__(
                    0, {"digest": other_base}
                ),
            )
        self.edit_json(
            self.evidence / "oci-config/breg.json",
            lambda value: value["rootfs"]["diff_ids"].__setitem__(0, other_base),
        )

        self.assert_refused("breg: runtime base changed")

    def test_refuses_changed_process_contract(self) -> None:
        self.edit_json(
            self.evidence / "oci-config/casework.json",
            lambda value: value["config"]["Env"].append("DEBUG=1"),
        )

        self.assert_refused("casework: OCI process configuration changed: environment")

    def test_refuses_revision_label_that_does_not_name_the_source(self) -> None:
        self.edit_json(
            self.evidence / "oci-config/relay.json",
            lambda value: value["config"]["Labels"].__setitem__(
                "org.opencontainers.image.revision", OLD_REVISION
            ),
        )

        self.assert_refused("revision label does not match protected source")

    def test_refuses_excepted_finding_that_became_fixable(self) -> None:
        self.edit_json(
            self.evidence / "grype/discovery.grype.json",
            lambda value: value["matches"][0]["vulnerability"].__setitem__(
                "fix", {"versions": ["2.41-13"], "state": "fixed"}
            ),
        )

        self.assert_refused("fixable finding cannot be excepted")

    def test_refuses_excepted_finding_that_disappeared(self) -> None:
        self.edit_json(
            self.evidence / "grype/evidence.grype.json",
            lambda value: value.__setitem__("matches", []),
        )

        self.assert_refused("evidence: CVE-2026-0001 libc6 2.41-12 has no matching finding")

    def test_refuses_new_unreviewed_blocking_finding(self) -> None:
        def add_finding(value: dict) -> None:
            match = copy.deepcopy(value["matches"][0])
            match["vulnerability"]["id"] = "CVE-2026-0002"
            match["vulnerability"]["severity"] = "Critical"
            value["matches"].append(match)

        self.edit_json(self.evidence / "grype/relay.grype.json", add_finding)

        self.assert_refused("unreviewed blocking finding: CVE-2026-0002")

    def test_refuses_rootfs_file_that_differs_from_syft(self) -> None:
        files = self.files("breg", "new")
        files["/usr/local/bin/breg"] = b"tampered"
        self.write_rootfs("breg", files)

        self.assert_refused("does not match native Syft evidence")

    def test_refuses_rootfs_with_special_files(self) -> None:
        self.write_rootfs("breg", self.files("breg", "new"), fifo="/run/pipe")

        self.assert_refused("forbidden special file")

    def test_refuses_assertion_kinds_other_than_whole_image_fingerprint(self) -> None:
        def replace_assertion(value: dict) -> None:
            exception = value["exceptions"][0]
            exception["exposure_assertion"] = with_digest(
                {
                    "kind": "file_digest_equals",
                    "reference_image_digest": image_digest("breg", "old"),
                    "reference_source_revision": OLD_REVISION,
                    "reference_provenance": "local_reproduction",
                    "files": copy.deepcopy(
                        exception["exposure_assertion"]["files"]
                    ),
                }
            )

        self.edit_json(self.baseline_path("breg"), replace_assertion)

        self.assert_refused("breg: renew file_digest_equals assertions by hand")

    def test_refuses_review_dates_that_move_backwards_or_outlive_expiry(self) -> None:
        self.assert_refused("precedes the recorded reviewed_at", reviewed_at="2026-08-31")
        self.assert_refused("future-dated exception", reviewed_at="2026-09-16")
        self.assert_refused("not an ISO date", reviewed_at="15/09/2026")

    def test_refuses_expired_exception_instead_of_extending_it(self) -> None:
        self.edit_json(
            self.baseline_path("evidence"),
            lambda value: value["exceptions"][0].__setitem__("expires_at", "2026-09-14"),
        )

        self.assert_refused("expired exception")

    def test_refuses_to_write_anything_when_a_later_image_fails(self) -> None:
        self.edit_json(
            self.evidence / "oci-config/relay.json",
            lambda value: value["config"].__setitem__("User", "0"),
        )

        self.assert_refused("relay: OCI process configuration changed: user")

    def test_refuses_live_pins_that_do_not_cover_the_renewed_roster(self) -> None:
        text = self.pins.read_text(encoding="utf-8")
        self.pins.write_text(
            text.replace(f'    "casework": "{image_digest("casework", "old")}",\n', ""),
            encoding="utf-8",
        )

        self.assert_refused("LIVE_REFERENCE_IMAGE_DIGESTS must pin exactly")

    def test_refuses_to_bootstrap_a_missing_baseline(self) -> None:
        self.baseline_path("casework").unlink()
        others = {
            path: path.read_bytes()
            for path in [self.baseline_path(name) for name in IMAGES if name != "casework"]
            + [self.pins]
        }

        status, _stdout, stderr = self.renew(write=True)

        self.assertEqual(1, status, stderr)
        self.assertIn("missing required file", stderr)
        self.assertIn("casework: recorded baseline", stderr)
        self.assertEqual(others, {path: path.read_bytes() for path in others})
        self.assertFalse(self.baseline_path("casework").exists())


if __name__ == "__main__":
    main()
