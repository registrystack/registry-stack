"""Nightly identity, complete payload, advisory and immutable recovery tests."""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
import nightly_release as nightly  # noqa: E402
import release_candidate  # noqa: E402

_merge_spec = importlib.util.spec_from_file_location(
    "merge_release_binary_shards", SCRIPTS / "merge-release-binary-shards.py"
)
merge_shards = importlib.util.module_from_spec(_merge_spec)
_merge_spec.loader.exec_module(merge_shards)

SHA = "a" * 40
BASE = "0.39.0"
TAG = f"v{BASE}-nightly.20261002.{SHA}"


class NightlyTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.plan = self.root / "plan.json"
        self.record = {
            "schema_version": nightly.SCHEMA,
            "tag": TAG,
            "version": TAG[1:],
            "base_version": BASE,
            "source_sha": SHA,
            "created_at": "2026-10-02T00:19:00+00:00",
            "channel_head": None,
            "skip": False,
        }
        self.record["roster"] = nightly.current_roster(BASE, TAG)
        self.plan.write_text(json.dumps(self.record))

    def scan(self, severity=None, age=0):
        return {
            "matches": []
            if severity is None
            else [{"vulnerability": {"severity": severity}}],
            "descriptor": {
                "db": {
                    "built": (
                        dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=age)
                    ).isoformat()
                }
            },
        }

    def payload(self):
        # Mirror the directories the workflow's prepare job passes to assemble:
        # the merged canonical Linux bin, the arm64 artifact and merged macOS.
        suffix = "1-1"
        directories = [
            self.root / f"inputs/nightly-canonical-{suffix}/bin",
            self.root / f"inputs/nightly-arm64-{suffix}",
            self.root / "macos/platform",
        ]
        for directory in directories:
            directory.mkdir(parents=True)
        for name, kind in release_candidate._release_payload_inventory(BASE).items():
            if kind != "binary":
                continue
            directory = (
                directories[2]
                if "macos-arm64" in name
                else directories[1]
                if "linux-arm64" in name
                else directories[0]
            )
            binary = name.split(f"-v{BASE}-", 1)[0]
            asset = directory / name.replace(f"v{BASE}", TAG)
            version = f"{binary} {TAG[1:]}"
            if binary == "registry-render":
                source = (nightly.ROOT / "crates/registry-render/src/lib.rs").read_text()
                typst = re.search(r'pub const TYPST_PIN: &str = "([^"]+)";', source)[1]
                version += f" (typst {typst})"
            asset.write_text(f"#!/bin/sh\nprintf '%s\\n' '{version}'\n")
            asset.chmod(0o755)
        # The canonical shard merge always lists its binaries in SHA256SUMS.
        merge_shards.write_sums(
            directories[0], sorted(path.name for path in directories[0].iterdir())
        )
        images = self.root / "images"
        images.mkdir()
        for name in nightly.image_names(BASE):
            (images / f"{name}.digest").write_text(
                f"ghcr.io/registrystack/{name}-candidate@sha256:{'1' * 64}\n"
            )
            (images / f"{name}.grype.json").write_text(json.dumps(self.scan()))
            (images / f"{name}.sbom.spdx.json").write_text('{"spdxVersion":"SPDX-2.3"}')
        return directories, images

    def assembled(self):
        directories, images = self.payload()
        output = self.root / "public"
        nightly.assemble(self.plan, directories, images, output)
        return output

    def manifest_for_roster(self, roster=None):
        manifest = json.loads(json.dumps(self.record))
        manifest.pop("skip")
        manifest["roster"] = roster or manifest["roster"]
        manifest["assets"] = [
            {"name": name, "sha256": "0" * 64}
            for name in manifest["roster"]["payloads"]
        ]
        for product in manifest["roster"]["installers"]:
            for name in (f"{product}-{TAG}-install.sh", f"{product}-install.sh"):
                manifest["assets"].append({"name": name, "sha256": "0" * 64})
        for image in manifest["roster"]["images"]:
            for suffix in ("grype.json", "sbom.spdx.json"):
                manifest["assets"].append(
                    {"name": f"{image}.{suffix}", "sha256": "0" * 64}
                )
        manifest["images"] = {
            name: f"ghcr.io/registrystack/{name}@sha256:{'1' * 64}"
            for name in manifest["roster"]["images"]
        }
        return manifest

    def test_identity_rejects_invalid_date_source_and_version(self):
        self.assertEqual(nightly.identity(TAG), (BASE, SHA))
        for tag in (
            f"v{BASE}-nightly.20260230.{SHA}",
            TAG.replace(SHA, "a" * 7),
            TAG.replace(BASE, "00.39.0"),
            "nightly",
            TAG + "/file",
        ):
            with self.subTest(tag=tag), self.assertRaises(nightly.NightlyError):
                nightly.identity(tag)

    def test_old_v1_0_39_manifest_with_relay_remains_readable(self):
        path = self.root / "old-nightly.json"
        manifest = {
            "schema_version": nightly.SCHEMA_V1,
            "tag": TAG,
            "version": TAG[1:],
            "base_version": BASE,
            "source_sha": SHA,
            "assets": [{"name": "relay-old", "sha256": "0" * 64}],
            "images": {
                name: f"ghcr.io/registrystack/{name}@sha256:{'1' * 64}"
                for name in nightly.historical_image_names(BASE)
            },
        }
        self.assertEqual(
            {
                "breg", "breg-mcp", "breg-review", "casework", "discovery",
                "evidence", "evidence-oid4vci", "messaging", "registry-render",
                "relay", "scheduling",
            },
            set(manifest["images"]),
        )
        path.write_text(json.dumps(manifest))
        self.assertEqual(manifest, nightly.read_manifest(path))

    def test_v2_roster_refuses_incomplete_self_declared_closures(self):
        path = self.root / "nightly.json"
        complete = nightly.current_roster(BASE, TAG)
        cases = {
            "missing image": {**complete, "images": complete["images"][:-1]},
            "missing installer": {
                **complete,
                "installers": complete["installers"][:-1],
            },
            "missing payload": {**complete, "payloads": complete["payloads"][:-1]},
            "known subset": {
                **complete,
                "images": ["breg"],
                "installers": ["breg"],
                "payloads": ["THIRD_PARTY_NOTICES"],
            },
        }
        for name, roster in cases.items():
            with self.subTest(name=name):
                path.write_text(json.dumps(self.manifest_for_roster(roster)))
                with self.assertRaisesRegex(nightly.NightlyError, "frozen profile"):
                    nightly.read_manifest(path)

    def test_v2_roster_refuses_retired_or_extra_valid_looking_assets(self):
        path = self.root / "nightly.json"
        complete = nightly.current_roster(BASE, TAG)
        cases = {
            "retired mint image": {
                **complete,
                "images": sorted([*complete["images"], "mint"]),
            },
            "extra platform archive": {
                **complete,
                "payloads": sorted(
                    [*complete["payloads"], f"breg-{TAG}-linux-arm64.tar.gz"]
                ),
            },
        }
        for name, roster in cases.items():
            with self.subTest(name=name):
                path.write_text(json.dumps(self.manifest_for_roster(roster)))
                with self.assertRaisesRegex(nightly.NightlyError, "frozen profile"):
                    nightly.read_manifest(path)

    def test_complete_payload_hashes_and_pins_installers(self):
        output = self.assembled()
        manifest = nightly.read_manifest(output / "nightly.json")
        closure = nightly.require_file_closure(output, manifest)
        self.assertEqual(len(closure), len(manifest["assets"]) + 2)
        self.assertEqual(set(manifest["images"]), set(nightly.image_names(BASE)))
        for product in nightly.INSTALLERS:
            self.assertIn(
                f'default_version="{TAG}"',
                (output / f"{product}-{TAG}-install.sh").read_text(),
            )

    def test_missing_platform_binary_cannot_advance_channel(self):
        directories, images = self.payload()
        next(directories[2].iterdir()).unlink()
        with self.assertRaisesRegex(nightly.NightlyError, "roster"):
            nightly.assemble(self.plan, directories, images, self.root / "public")

    def test_artifact_transport_modes_are_restored_for_standalone_binaries(self):
        directories, images = self.payload()
        for directory in directories:
            for asset in directory.iterdir():
                asset.chmod(0o644)
        output = self.root / "public"
        nightly.assemble(self.plan, directories, images, output)
        for name, kind in release_candidate._release_payload_inventory(BASE).items():
            asset = output / name.replace(f"v{BASE}", TAG)
            if kind == "binary" and not name.endswith(".tar.gz"):
                self.assertEqual(asset.stat().st_mode & 0o777, 0o755)

    def test_duplicate_or_unexpected_binary_is_refused(self):
        directories, images = self.payload()
        (directories[0] / "unexpected").write_text("bad")
        with self.assertRaisesRegex(nightly.NightlyError, "unexpected"):
            nightly.assemble(self.plan, directories, images, self.root / "public")

    def test_canonical_shard_checksums_are_not_published(self):
        output = self.assembled()
        manifest = nightly.read_manifest(output / "nightly.json")
        self.assertNotIn("SHA256SUMS", {asset["name"] for asset in manifest["assets"]})
        nightly.require_file_closure(output, manifest)

    def test_binary_changed_after_canonical_merge_is_refused(self):
        directories, images = self.payload()
        (directories[0] / f"breg-{TAG}-linux-amd64").write_text("changed in transit")
        with self.assertRaisesRegex(nightly.NightlyError, "shard checksums"):
            nightly.assemble(self.plan, directories, images, self.root / "public")

    def test_mismatched_hash_fails_before_public_writes(self):
        output = self.assembled()
        (output / f"breg-{TAG}-linux-amd64").write_text("wrong")
        with (
            patch.object(nightly, "api") as api,
            self.assertRaisesRegex(nightly.NightlyError, "checksum"),
        ):
            nightly.publish(output, self.root / "layouts")
        api.assert_not_called()

    def test_smoke_rejects_manifest_cli_with_another_build_identity(self):
        output = self.assembled()
        (output / f"registry-manifest-{TAG}-linux-amd64").write_text(
            "#!/bin/sh\necho 'registry-manifest 0.39.0-dev'\n"
        )
        with self.assertRaisesRegex(nightly.NightlyError, "registry-manifest"):
            nightly.smoke(output)

    def test_nightly_advisory_policy_and_database_age(self):
        report = self.root / "scan.json"
        for severity in (None, "Low", "Medium"):
            report.write_text(json.dumps(self.scan(severity)))
            nightly.check_scan(report)
        for severity, age in (
            ("High", 0),
            ("Critical", 0),
            ("Unknown", 0),
            (None, 4),
            (None, -1),
        ):
            report.write_text(json.dumps(self.scan(severity, age)))
            with (
                self.subTest(severity=severity, age=age),
                self.assertRaises(nightly.NightlyError),
            ):
                nightly.check_scan(report)

    def test_channel_compare_and_swap_refuses_stale_builder(self):
        record = self.record | {"assets": [], "images": {}}
        with (
            patch.object(
                nightly,
                "channel_metadata",
                return_value=({"source_sha": "b" * 40}, "b" * 40),
            ),
            patch.object(nightly, "api") as api,
        ):
            with self.assertRaisesRegex(nightly.NightlyError, "advanced"):
                nightly.advance_channel(record, json.dumps(record))
            api.assert_not_called()

    def test_channel_retry_is_idempotent(self):
        record = self.record | {"assets": [], "images": {}}
        with (
            patch.object(nightly, "channel_metadata", return_value=(record, "b" * 40)),
            patch.object(nightly, "api") as api,
        ):
            nightly.advance_channel(record, json.dumps(record))
            api.assert_not_called()

    def test_channel_update_is_a_nonforced_commit(self):
        record = self.record | {"channel_head": "b" * 40}
        with (
            patch.object(nightly, "channel_metadata", return_value=({}, "b" * 40)),
            patch.object(
                nightly,
                "api",
                side_effect=[
                    {"tree": {"sha": "c" * 40}},
                    {"sha": "d" * 40},
                    {"sha": "e" * 40},
                ],
            ),
            patch.object(nightly, "run") as run,
        ):
            nightly.advance_channel(record, json.dumps(record))
            self.assertEqual(
                json.loads(run.call_args.kwargs["input"]),
                {"sha": "e" * 40, "force": False},
            )

    def test_refuses_existing_tag_mismatch_before_image_writes(self):
        output = self.assembled()
        environment = {"GITHUB_SHA": SHA, "GITHUB_REF": "refs/heads/main"}
        with (
            patch.dict(os.environ, environment),
            patch.object(nightly, "run", return_value=SHA),
            patch.object(
                nightly,
                "optional_api",
                return_value={"object": {"sha": "b" * 40, "type": "commit"}},
            ),
            patch.object(nightly, "api") as api,
        ):
            with self.assertRaisesRegex(nightly.NightlyError, "tag"):
                nightly.publish(output, self.root / "layouts")
            api.assert_not_called()

    def test_non404_lookup_failure_is_not_absence(self):
        failure = subprocess.CompletedProcess([], 1, "HTTP/2.0 403 Forbidden\n\n{}", "")
        with (
            patch.object(subprocess, "run", return_value=failure),
            self.assertRaises(nightly.NightlyError),
        ):
            nightly.optional_api("repos/example/missing")
        failure.stdout = "HTTP/2.0 404 Not Found\n\n{}"
        with patch.object(subprocess, "run", return_value=failure):
            self.assertIsNone(nightly.optional_api("repos/example/missing"))

    def publication_fixture(
        self, output, existing=None, corrupt=None, fail_upload=False
    ):
        remote = {}
        calls = []
        manifest = nightly.read_manifest(output / "nightly.json")
        if existing:
            remote = {name: (output / name).read_bytes() for name in existing}
        if corrupt:
            remote[corrupt] = b"incompatible public bytes"

        def api(path, payload=None):
            calls.append(("api", path, payload))
            if "/packages/container/" in path:
                return {"name": path.rsplit("/", 1)[1], "visibility": "public"}
            if path.endswith("/releases"):
                return {"draft": True, "assets": []}
            return {}

        def run(*arguments, **kwargs):
            calls.append(arguments)
            if arguments[:3] == ("git", "rev-parse", "HEAD"):
                return SHA
            if arguments[:2] == ("crane", "digest"):
                return "sha256:" + "1" * 64
            if arguments[:3] == ("gh", "release", "upload"):
                if fail_upload:
                    raise subprocess.CalledProcessError(1, arguments)
                path = Path(arguments[4])
                remote[path.name] = path.read_bytes()
            if arguments[:3] == ("gh", "release", "download"):
                directory = Path(arguments[arguments.index("--dir") + 1])
                names = (
                    [arguments[arguments.index("--pattern") + 1]]
                    if "--pattern" in arguments
                    else list(remote)
                )
                for name in names:
                    (directory / name).write_bytes(remote[name])
            return ""

        release = (
            None
            if not existing
            else {
                "tag_name": TAG,
                "draft": True,
                "prerelease": True,
                "assets": [{"name": name} for name in existing],
            }
        )
        return manifest, calls, api, run, release

    def test_clean_publication_advances_channel_only_after_public_verification(self):
        output = self.assembled()
        manifest, calls, api, run, release = self.publication_fixture(output)
        missing_image = subprocess.CompletedProcess([], 1, "", "MANIFEST_UNKNOWN")
        with (
            patch.dict(
                os.environ, {"GITHUB_SHA": SHA, "GITHUB_REF": "refs/heads/main"}
            ),
            patch.object(nightly, "api", side_effect=api),
            patch.object(nightly, "optional_api", side_effect=[None, release]),
            patch.object(nightly, "run", side_effect=run),
            patch.object(subprocess, "run", return_value=missing_image),
            patch.object(nightly, "advance_channel") as advance,
        ):
            nightly.publish(output, self.root / "layouts")
            advance.assert_called_once_with(
                manifest, (output / "nightly.json").read_text()
            )
        uploads = [call for call in calls if call[:3] == ("gh", "release", "upload")]
        self.assertEqual(Path(uploads[0][4]).name, "nightly.json")
        self.assertTrue(
            any(
                call[:3] == ("gh", "release", "edit") and "--latest=false" in call
                for call in calls
            )
        )
        self.assertEqual(calls[-1][:3], ("gh", "release", "download"))
        self.assertEqual(
            sum(call[:2] == ("oras", "cp") for call in calls), len(manifest["images"])
        )
        self.assertFalse(any("--clobber" in call for call in calls))

    def test_matching_partial_draft_uploads_only_missing_assets(self):
        output = self.assembled()
        existing = ["nightly.json", f"breg-{TAG}-linux-amd64"]
        _, calls, api, run, release = self.publication_fixture(
            output, existing=existing
        )
        current_image = subprocess.CompletedProcess([], 0, "sha256:" + "1" * 64, "")
        ref = {"object": {"sha": SHA, "type": "commit"}}
        with (
            patch.dict(
                os.environ, {"GITHUB_SHA": SHA, "GITHUB_REF": "refs/heads/main"}
            ),
            patch.object(nightly, "api", side_effect=api),
            patch.object(nightly, "optional_api", side_effect=[ref, release]),
            patch.object(nightly, "run", side_effect=run),
            patch.object(subprocess, "run", return_value=current_image),
            patch.object(nightly, "advance_channel") as advance,
        ):
            nightly.publish(output, self.root / "layouts")
            advance.assert_called_once()
        uploaded = {
            Path(call[4]).name
            for call in calls
            if call[:3] == ("gh", "release", "upload")
        }
        self.assertFalse(uploaded & set(existing))
        self.assertFalse(any(call[:2] == ("oras", "cp") for call in calls))

    def test_incompatible_partial_publication_never_overwrites_bytes(self):
        output = self.assembled()
        existing = ["nightly.json"]
        _, calls, api, run, release = self.publication_fixture(
            output, existing, corrupt="nightly.json"
        )
        with (
            patch.dict(
                os.environ, {"GITHUB_SHA": SHA, "GITHUB_REF": "refs/heads/main"}
            ),
            patch.object(nightly, "api", side_effect=api),
            patch.object(nightly, "optional_api", side_effect=[None, release]),
            patch.object(nightly, "run", side_effect=run),
            patch.object(nightly, "advance_channel") as advance,
        ):
            with self.assertRaisesRegex(nightly.NightlyError, "fix forward"):
                nightly.publish(output, self.root / "layouts")
            advance.assert_not_called()
        self.assertFalse(
            any(
                call[:2] == ("oras", "cp") or call[:3] == ("gh", "release", "upload")
                for call in calls
            )
        )

    def test_failed_asset_upload_leaves_channel_unchanged(self):
        output = self.assembled()
        _, _, api, run, release = self.publication_fixture(output, fail_upload=True)
        current_image = subprocess.CompletedProcess([], 0, "sha256:" + "1" * 64, "")
        with (
            patch.dict(
                os.environ, {"GITHUB_SHA": SHA, "GITHUB_REF": "refs/heads/main"}
            ),
            patch.object(nightly, "api", side_effect=api),
            patch.object(nightly, "optional_api", side_effect=[None, release]),
            patch.object(nightly, "run", side_effect=run),
            patch.object(subprocess, "run", return_value=current_image),
            patch.object(nightly, "advance_channel") as advance,
        ):
            with self.assertRaises(subprocess.CalledProcessError):
                nightly.publish(output, self.root / "layouts")
            advance.assert_not_called()

    def test_plan_skips_a_successful_source_without_build_destinations(self):
        (self.root / "Cargo.toml").write_text(
            f'[workspace.package]\nversion = "{BASE}"\n'
        )
        environment = {
            "GITHUB_SHA": SHA,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "schedule",
            "GITHUB_REPOSITORY": nightly.REPOSITORY,
            "GITHUB_OUTPUT": str(self.root / "outputs"),
        }

        def api(path, payload=None):
            if path == f"repos/{nightly.REPOSITORY}/branches/main":
                return {"commit": {"sha": SHA}}
            package = path.rsplit("/", 1)[-1]
            return {
                "name": package,
                "visibility": "private" if package.endswith("-candidate") else "public",
            }

        with (
            patch.dict(os.environ, environment),
            patch.object(nightly, "ROOT", self.root),
            patch.object(nightly, "run", return_value=SHA),
            patch.object(nightly, "api", return_value={"commit": {"sha": SHA}}) as api,
            patch.object(
                nightly, "channel_metadata", return_value=(self.record, "b" * 40)
            ),
            patch.object(nightly, "optional_api") as lookup,
        ):
            nightly.plan(self.plan)
            lookup.assert_not_called()
            self.assertEqual(api.call_count, 1)
        self.assertTrue(json.loads(self.plan.read_text())["skip"])

    def test_plan_advances_from_a_frozen_v1_head_with_relay(self):
        (self.root / "Cargo.toml").write_text(
            f'[workspace.package]\nversion = "{BASE}"\n'
        )
        old_path = self.root / "old-head.json"
        old_tag = f"v{BASE}-nightly.20261001.{'b' * 40}"
        old_path.write_text(
            json.dumps(
                {
                    "schema_version": nightly.SCHEMA_V1,
                    "tag": old_tag,
                    "version": old_tag[1:],
                    "base_version": BASE,
                    "source_sha": "b" * 40,
                    "assets": [{"name": "relay-old", "sha256": "0" * 64}],
                    "images": {
                        name: f"ghcr.io/registrystack/{name}@sha256:{'1' * 64}"
                        for name in nightly.historical_image_names(BASE)
                    },
                }
            )
        )
        previous = nightly.read_manifest(old_path)
        environment = {
            "GITHUB_SHA": SHA,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "schedule",
            "GITHUB_REPOSITORY": nightly.REPOSITORY,
            "GITHUB_OUTPUT": str(self.root / "outputs"),
        }
        def current_api(path, payload=None):
            if path == f"repos/{nightly.REPOSITORY}/branches/main":
                return {"commit": {"sha": SHA}}
            package = path.rsplit("/", 1)[-1]
            return {
                "name": package,
                "visibility": "private" if package.endswith("-candidate") else "public",
            }
        with (
            patch.dict(os.environ, environment),
            patch.object(nightly, "ROOT", self.root),
            patch.object(nightly, "run", return_value=SHA),
            patch.object(nightly, "api", side_effect=current_api),
            patch.object(
                nightly, "channel_metadata", return_value=(previous, "c" * 40)
            ),
            patch.object(nightly, "optional_api", return_value=None),
        ):
            nightly.plan(self.plan)

        planned = json.loads(self.plan.read_text())
        self.assertEqual(nightly.SCHEMA_V2, planned["schema_version"])
        self.assertEqual("c" * 40, planned["channel_head"])
        self.assertFalse(planned["skip"])
        self.assertNotIn("relay", planned["roster"]["images"])
        self.assertNotIn("relay", planned["roster"]["installers"])
        self.assertFalse(
            any("relay" in name for name in planned["roster"]["payloads"])
        )

    def test_source_ref_rejection_precedes_network_calls(self):
        with (
            patch.dict(os.environ, {"GITHUB_REF": "refs/heads/untrusted"}),
            patch.object(nightly, "api") as api,
        ):
            with self.assertRaisesRegex(nightly.NightlyError, "protected main"):
                nightly.plan(self.plan)
            api.assert_not_called()

    def test_assembled_nightly_installs_through_the_real_channel_resolver(self):
        output = self.assembled()
        commands = self.root / "commands"
        commands.mkdir()
        scripts = {
            "uname": '#!/bin/sh\ncase "$1" in -s) echo Linux;; -m) echo x86_64;; *) exit 1;; esac\n',
            "getconf": '#!/bin/sh\necho "glibc 2.35"\n',
            "ldd": '#!/bin/sh\necho "ldd (GNU libc) 2.35"\n',
            # Emulate GNU mv's atomic replacement on macOS as well as Linux.
            "mv": "#!/usr/bin/env python3\nimport os,sys\nos.replace(sys.argv[-2], sys.argv[-1])\n",
            "curl": """#!/usr/bin/env bash
set -euo pipefail
url=""; destination=""
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    -o) destination="$2"; shift 2;;
    https://*) url="$1"; shift;;
    *) shift;;
  esac
done
case "$url" in
  */nightly-channel/nightly.json) source="$NIGHTLY_FIXTURE/nightly.json";;
  */releases/download/"$NIGHTLY_FIXTURE_TAG"/*) source="$NIGHTLY_FIXTURE/${url##*/}";;
  *) exit 22;;
esac
cp "$source" "$destination"
""",
        }
        for name, script in scripts.items():
            (commands / name).write_text(script)
            (commands / name).chmod(0o755)
        for product, (crate, prefix, binaries) in nightly.INSTALLERS.items():
            with self.subTest(product=product):
                destination = self.root / f"installed-{product}"
                environment = os.environ | {
                    "PATH": str(commands) + os.pathsep + os.environ["PATH"],
                    "NIGHTLY_FIXTURE": str(output),
                    "NIGHTLY_FIXTURE_TAG": TAG,
                    f"{prefix}_INSTALL_DIR": str(destination),
                }
                environment.pop(f"{prefix}_VERSION", None)
                environment.pop(f"{prefix}_ASSET_DIR", None)
                result = subprocess.run(
                    [
                        "bash",
                        str(nightly.ROOT / "crates" / crate / "install.sh"),
                        "--channel",
                        "nightly",
                    ],
                    env=environment,
                    text=True,
                    capture_output=True,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(f"/blob/{TAG}/release/NIGHTLY.md", result.stdout)
                self.assertNotIn(f"/blob/{TAG}/release/VERIFY.md", result.stdout)
                for binary in binaries:
                    self.assertEqual(
                        subprocess.check_output(
                            [str(destination / binary), "--version"], text=True
                        ).strip(),
                        f"{binary} {TAG[1:]}",
                    )
        with patch.dict(os.environ, {"PATH": environment["PATH"]}):
            nightly.smoke(output)

    def test_pinned_installers_follow_the_arm64_platform_rosters(self):
        output = self.assembled()
        names = {path.name for path in output.iterdir()}
        # Each installer installs the toolset its platform publishes, or
        # refuses the platform (None). Scheduling's runtime is Linux amd64
        # only, so arm64 gets schedulingctl alone. Real macOS bundle installs
        # are covered by test_macos_installers.py.
        toolsets = {
            ("Linux", "aarch64", "linux-arm64"): {
                "breg": ("breg", "bregctl"),
                "evidencectl": ("evidence", "evidencectl", "evidence-oid4vci"),
                "casework": ("casework", "caseworkctl"),
                "scheduling": ("schedulingctl",),
            },
        }
        for (os_name, arch, platform), products in toolsets.items():
            commands = self.root / f"commands-{platform}"
            commands.mkdir()
            scripts = {
                "uname": f'#!/bin/sh\ncase "$1" in -s) echo {os_name};; -m) echo {arch};; *) exit 1;; esac\n',
                "getconf": '#!/bin/sh\necho "glibc 2.35"\n',
                "ldd": '#!/bin/sh\necho "ldd (GNU libc) 2.35"\n',
                # Emulate GNU mv's atomic replacement on macOS as well as Linux.
                "mv": "#!/usr/bin/env python3\nimport os,sys\nos.replace(sys.argv[-2], sys.argv[-1])\n",
            }
            for name, script in scripts.items():
                (commands / name).write_text(script)
                (commands / name).chmod(0o755)
            for product, binaries in products.items():
                prefix = nightly.INSTALLERS[product][1]
                with self.subTest(product=product, platform=platform):
                    destination = self.root / f"installed-{product}-{platform}"
                    environment = os.environ | {
                        "PATH": str(commands) + os.pathsep + os.environ["PATH"],
                        f"{prefix}_ASSET_DIR": str(output),
                        f"{prefix}_INSTALL_DIR": str(destination),
                    }
                    environment.pop(f"{prefix}_VERSION", None)
                    result = subprocess.run(
                        ["bash", str(output / f"{product}-{TAG}-install.sh")],
                        env=environment,
                        text=True,
                        capture_output=True,
                    )
                    if binaries is None:
                        # A refused platform is rejected before any asset is
                        # read or the install directory is touched.
                        self.assertEqual(result.returncode, 1, result.stderr)
                        self.assertIn("No prebuilt", result.stderr)
                        self.assertFalse(destination.exists())
                        continue
                    self.assertEqual(
                        result.returncode, 0, result.stdout + result.stderr
                    )
                    self.assertEqual(
                        {
                            path.name
                            for path in destination.iterdir()
                            if not path.name.startswith(".")
                        },
                        set(binaries),
                    )
                    for binary in binaries:
                        self.assertIn(f"{binary}-{TAG}-{platform}", names)
                        self.assertEqual(
                            subprocess.check_output(
                                [str(destination / binary), "--version"],
                                text=True,
                            ).strip(),
                            f"{binary} {TAG[1:]}",
                        )

if __name__ == "__main__":
    unittest.main()
