#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import tempfile
from pathlib import Path
from unittest import TestCase, main, mock


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "release/scripts/collect-rehearsal-advisory-evidence.py"
SPEC = importlib.util.spec_from_file_location("collect_rehearsal_evidence", HELPER)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class FakeCommands:
    digest = "sha256:" + "a" * 64
    revision = "b" * 40
    source = "https://github.com/registrystack/registry-stack"
    version = "0.26.1"
    roster = ("breg", "discovery", "evidence", "mint", "relay")

    def __init__(
        self,
        fail_tool: str | None = None,
        fail_prefix: tuple[str, ...] | None = None,
        wrong_source: bool = False,
        wrong_grype_layers: bool = False,
    ):
        self.calls: list[tuple[list[str], dict]] = []
        self.fail_tool = fail_tool
        self.fail_prefix = fail_prefix
        self.wrong_source = wrong_source
        self.wrong_grype_layers = wrong_grype_layers

    def image_target(self, image_ref: str) -> dict:
        return {
            "userInput": image_ref,
            "repoDigests": [image_ref.removeprefix("docker:")],
            "architecture": "amd64",
            "os": "linux",
            "layers": [{"digest": "sha256:" + "c" * 64}],
        }

    def __call__(
        self,
        command,
        *,
        env=None,
        stdout_path=None,
        check=True,
    ):
        command = list(command)
        details = {"env": env, "stdout_path": stdout_path, "check": check}
        self.calls.append((command, details))
        executable = Path(command[0]).name
        if (
            self.fail_tool == executable
            or (
                self.fail_prefix is not None
                and command[: len(self.fail_prefix)] == list(self.fail_prefix)
            )
        ) and check:
            raise subprocess.CalledProcessError(17, command, stderr="synthetic failure")

        stdout = ""
        if command[:3] == ["git", "rev-parse", "HEAD"]:
            stdout = self.revision + "\n"
        elif len(command) > 1 and "release_candidate.py" in command[1]:
            stdout = " ".join(self.roster) + "\n"
        elif command[:2] == ["docker", "port"]:
            stdout = "127.0.0.1:49152\n"
        elif command[:3] == ["crane", "digest", "--insecure"]:
            stdout = self.digest + "\n"
        elif command[:3] == ["docker", "image", "inspect"]:
            stdout = json.dumps([command[-1]]) + "\n"
        elif executable == "build-release-image.sh":
            metadata = Path(command[-1])
            metadata.parent.mkdir(parents=True, exist_ok=True)
            metadata.write_text(
                json.dumps({"containerimage.digest": self.digest}), encoding="utf-8"
            )
        elif command[:3] == ["crane", "config", "--insecure"]:
            config = {
                "architecture": "amd64",
                "os": "linux",
                "rootfs": {"type": "layers", "diff_ids": ["sha256:" + "c" * 64]},
                "config": {
                    "User": "65532",
                    "Labels": {
                        "org.opencontainers.image.source": (
                            "https://github.com/wrong/repository"
                            if self.wrong_source
                            else self.source
                        ),
                        "org.opencontainers.image.revision": self.revision,
                        "org.opencontainers.image.version": self.version,
                        "org.registrystack.runtime.uid": "65532",
                        "org.registrystack.runtime.gid": "65532",
                    },
                },
            }
            Path(stdout_path).write_text(json.dumps(config), encoding="utf-8")
        elif executable == "syft":
            target = self.image_target(command[1])
            path = Path(
                next(
                    value for value in command if value.startswith("syft-json=")
                ).split("=", 1)[1]
            )
            path.write_text(
                json.dumps(
                    {
                        "descriptor": {"name": "syft", "version": "1.45.1"},
                        "schema": {"version": "16.1.3"},
                        "source": {"type": "image", "metadata": target},
                        "artifacts": [],
                        "files": [],
                    }
                ),
                encoding="utf-8",
            )
        elif (
            executable == "grype"
            and len(command) > 1
            and command[1].startswith("docker:")
        ):
            target = self.image_target(command[1])
            if self.wrong_grype_layers:
                target["layers"] = [{"digest": "sha256:" + "e" * 64}]
            Path(stdout_path).write_text(
                json.dumps(
                    {
                        "descriptor": {"name": "grype", "version": "0.114.0"},
                        "source": {"type": "image", "target": target},
                        "matches": [],
                    }
                ),
                encoding="utf-8",
            )
        elif command[:4] == ["grype", "db", "status", "-o"]:
            Path(stdout_path).write_text(json.dumps({"built": "now"}), encoding="utf-8")
        elif command[:3] == ["crane", "export", "--insecure"]:
            Path(command[-1]).write_bytes(b"synthetic tar")
        elif executable == "tar":
            directory = Path(
                next(
                    value for value in command if value.startswith("--directory=")
                ).split("=", 1)[1]
            )
            (directory / "app").write_text("synthetic rootfs", encoding="utf-8")

        if stdout_path is not None and not Path(stdout_path).exists():
            Path(stdout_path).write_text(stdout or "{}", encoding="utf-8")
            stdout = ""
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")


class CollectRehearsalAdvisoryEvidenceTest(TestCase):
    def arguments(self, output: Path) -> argparse.Namespace:
        return argparse.Namespace(
            version=FakeCommands.version,
            source=FakeCommands.source,
            revision=FakeCommands.revision,
            output=output,
            registry_image="registry:3.1.1@" + FakeCommands.digest,
            buildx_builder="rehearsal-builder",
        )

    def test_rejects_invalid_duplicate_or_unsupported_rosters(self) -> None:
        for roster in ("", "relay relay", "relay surprise"):
            with self.subTest(roster=roster):
                with self.assertRaises(MODULE.EvidenceError):
                    MODULE.parse_roster(roster)

    def test_v0_26_roster_is_owned_and_complete(self) -> None:
        result = subprocess.run(
            [
                "python3",
                str(ROOT / "release/scripts/release_candidate.py"),
                "image-names",
                "--version",
                "0.26.1",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(MODULE.parse_roster(result.stdout), FakeCommands.roster)

    def test_collects_every_owned_image_with_exact_daemon_context(self) -> None:
        fake = FakeCommands()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "evidence"
            with mock.patch.object(MODULE, "run_command", side_effect=fake):
                MODULE.collect(self.arguments(output))

            manifest = json.loads((output / "collection.json").read_text())
            self.assertEqual(
                [image["name"] for image in manifest["images"]], list(fake.roster)
            )
            self.assertFalse(manifest["publication_eligible"])
            self.assertFalse(manifest["advisory_accepted"])
            self.assertEqual(fake.revision, manifest["revision"])
            self.assertEqual(
                sorted(path.name for path in (output / "rootfs").glob("*.tar")),
                [f"{name}.tar" for name in sorted(fake.roster)],
            )
            builds = [
                (command, details)
                for command, details in fake.calls
                if Path(command[0]).name == "build-release-image.sh"
            ]
            self.assertEqual([command[1] for command, _ in builds], list(fake.roster))
            for command, details in builds:
                self.assertEqual(fake.source, command[3])
                self.assertEqual(fake.revision, command[4])
                self.assertEqual(fake.version, command[5])
                self.assertEqual(
                    "rehearsal-builder", details["env"]["RELEASE_BUILDX_BUILDER"]
                )
                self.assertTrue(
                    details["env"]["RELEASE_IMAGE_OCI_LAYOUT"].endswith(".oci")
                )
            syft_calls = [
                (command, details)
                for command, details in fake.calls
                if command[0] == "syft"
            ]
            syft = [command for command, _ in syft_calls]
            grype = [
                command
                for command, _ in fake.calls
                if command[0] == "grype" and command[1].startswith("docker:")
            ]
            self.assertEqual(len(syft), len(fake.roster))
            self.assertEqual(len(grype), len(fake.roster))
            self.assertTrue(
                all(
                    command[1].startswith("docker:127.0.0.1:")
                    for command in syft + grype
                )
            )
            self.assertTrue(
                all(command[1].endswith("@" + fake.digest) for command in syft + grype)
            )
            for _command, details in syft_calls:
                self.assertEqual(details["env"]["SYFT_FILE_METADATA_SELECTION"], "all")
                self.assertEqual(details["env"]["SYFT_FILE_METADATA_DIGESTS"], "sha256")

    def test_command_failure_propagates_and_cleans_local_resources(self) -> None:
        fake = FakeCommands(fail_tool="syft")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "evidence"
            with mock.patch.object(MODULE, "run_command", side_effect=fake):
                with self.assertRaises(subprocess.CalledProcessError):
                    MODULE.collect(self.arguments(output))
        calls = [command for command, _ in fake.calls]
        self.assertTrue(
            any(command[:3] == ["docker", "image", "rm"] for command in calls)
        )
        self.assertTrue(
            any(command[:3] == ["docker", "rm", "--force"] for command in calls)
        )
        builds = [
            command
            for command in calls
            if Path(command[0]).name == "build-release-image.sh"
        ]
        self.assertEqual([command[1] for command in builds], ["breg"])

    def test_checked_out_source_mismatch_fails_before_local_resources(self) -> None:
        fake = FakeCommands()
        fake.revision = "d" * 40
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "evidence"
            with mock.patch.object(MODULE, "run_command", side_effect=fake):
                with self.assertRaisesRegex(MODULE.EvidenceError, "checked-out source"):
                    MODULE.collect(self.arguments(output))
        self.assertFalse(
            any(command[:2] == ["docker", "run"] for command, _ in fake.calls)
        )

    def test_post_pull_inspection_failure_removes_the_pulled_digest(self) -> None:
        fake = FakeCommands(fail_prefix=("docker", "image", "inspect"))
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "evidence"
            with mock.patch.object(MODULE, "run_command", side_effect=fake):
                with self.assertRaises(subprocess.CalledProcessError):
                    MODULE.collect(self.arguments(output))
        calls = [command for command, _ in fake.calls]
        pull = next(command for command in calls if command[:2] == ["docker", "pull"])
        self.assertIn(
            ["docker", "image", "rm", "--force", pull[-1]],
            calls,
        )

    def test_authoritative_config_identity_mismatch_fails_closed(self) -> None:
        fake = FakeCommands(wrong_source=True)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "evidence"
            with mock.patch.object(MODULE, "run_command", side_effect=fake):
                with self.assertRaisesRegex(MODULE.EvidenceError, "image.source"):
                    MODULE.collect(self.arguments(output))
        self.assertTrue(
            any(command[:3] == ["docker", "rm", "--force"] for command, _ in fake.calls)
        )

    def test_scanner_image_identity_mismatch_fails_closed(self) -> None:
        fake = FakeCommands(wrong_grype_layers=True)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "evidence"
            with mock.patch.object(MODULE, "run_command", side_effect=fake):
                with self.assertRaisesRegex(
                    MODULE.EvidenceError, "different image layers"
                ):
                    MODULE.collect(self.arguments(output))


if __name__ == "__main__":
    main()
