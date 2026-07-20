#!/usr/bin/env python3
"""Focused tests for the release image OCI label checker."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import subprocess
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("check-release-image-oci-labels.py")
IMAGE_REF = "example.invalid/registry-relay@sha256:" + "a" * 64
SOURCE = "https://github.com/registrystack/registry-stack"
REVISION = "b" * 40
VERSION = "v0.12.0"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "check_release_image_oci_labels", SCRIPT
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def config_json(labels: object) -> str:
    return json.dumps({"User": "65532", "Labels": labels})


class ReleaseImageOciLabelsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.argv = [
            IMAGE_REF,
            "--source",
            SOURCE,
            "--revision",
            REVISION,
            "--version",
            VERSION,
        ]

    def run_with_inspect(
        self,
        *,
        stdout: str = "",
        stderr: str = "",
        returncode: int = 0,
        extra_args: list[str] | None = None,
    ) -> tuple[int, str, str, mock.Mock]:
        completed = subprocess.CompletedProcess(
            args=[], returncode=returncode, stdout=stdout, stderr=stderr
        )
        run = mock.Mock(return_value=completed)
        captured_stdout = io.StringIO()
        captured_stderr = io.StringIO()
        with (
            mock.patch.object(self.module.subprocess, "run", run),
            contextlib.redirect_stdout(captured_stdout),
            contextlib.redirect_stderr(captured_stderr),
        ):
            result = self.module.main(self.argv + (extra_args or []))
        return result, captured_stdout.getvalue(), captured_stderr.getvalue(), run

    def test_default_inspection_reads_full_image_config_and_accepts_exact_labels(
        self,
    ) -> None:
        labels = {
            "org.opencontainers.image.source": SOURCE,
            "org.opencontainers.image.revision": REVISION,
            "org.opencontainers.image.version": VERSION,
        }

        result, stdout, stderr, run = self.run_with_inspect(
            stdout=config_json(labels)
        )

        self.assertEqual(0, result, stderr)
        self.assertIn("verified release image OCI labels", stdout)
        run.assert_called_once_with(
            [
                "docker",
                "buildx",
                "imagetools",
                "inspect",
                "--format",
                "{{json .Image.Config}}",
                IMAGE_REF,
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_inspection_command_failure_is_rejected(self) -> None:
        result, _, stderr, _ = self.run_with_inspect(
            returncode=1, stderr="template evaluation failed"
        )

        self.assertEqual(1, result)
        self.assertIn("imagetools inspect failed", stderr)
        self.assertIn("template evaluation failed", stderr)

    def test_invalid_json_is_rejected(self) -> None:
        result, _, stderr, _ = self.run_with_inspect(stdout="not json")

        self.assertEqual(1, result)
        self.assertIn("invalid image config JSON", stderr)

    def test_missing_labels_object_is_rejected(self) -> None:
        result, _, stderr, _ = self.run_with_inspect(stdout=json.dumps({}))

        self.assertEqual(1, result)
        self.assertIn("missing the Labels object", stderr)

    def test_non_object_labels_are_rejected(self) -> None:
        result, _, stderr, _ = self.run_with_inspect(stdout=config_json(None))

        self.assertEqual(1, result)
        self.assertIn("Labels", stderr)
        self.assertIn("must be a JSON object", stderr)

    def test_missing_required_label_is_rejected(self) -> None:
        labels = {
            "org.opencontainers.image.source": SOURCE,
            "org.opencontainers.image.revision": REVISION,
        }

        result, _, stderr, _ = self.run_with_inspect(stdout=config_json(labels))

        self.assertEqual(1, result)
        self.assertIn("missing required OCI label", stderr)
        self.assertIn("org.opencontainers.image.version", stderr)

    def test_wrong_label_value_is_rejected(self) -> None:
        labels = {
            "org.opencontainers.image.source": SOURCE,
            "org.opencontainers.image.revision": "wrong",
            "org.opencontainers.image.version": VERSION,
        }

        result, _, stderr, _ = self.run_with_inspect(stdout=config_json(labels))

        self.assertEqual(1, result)
        self.assertIn("org.opencontainers.image.revision", stderr)
        self.assertIn("expected exactly", stderr)

    def test_format_template_override_is_passed_to_docker(self) -> None:
        result, _, stderr, run = self.run_with_inspect(
            returncode=1,
            stderr="cannot evaluate field config",
            extra_args=["--format-template", "{{json .Image.config}}"],
        )

        self.assertEqual(1, result)
        self.assertIn("cannot evaluate field config", stderr)
        self.assertEqual("{{json .Image.config}}", run.call_args.args[0][5])


if __name__ == "__main__":
    unittest.main()
