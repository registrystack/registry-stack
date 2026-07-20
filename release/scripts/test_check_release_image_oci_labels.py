#!/usr/bin/env python3
"""Focused tests for the release image OCI label checker."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import subprocess
import tempfile
import unittest
import unittest.mock
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-release-image-oci-labels.py")
SMOKE_SCRIPT = Path(__file__).with_name("smoke-release-image-oci-labels.sh")
ROOT = SCRIPT.parents[2]
IMAGE_REF = "example.invalid/registry-relay@sha256:" + "a" * 64
SOURCE = "https://github.com/registrystack/registry-stack"
REVISION = "b" * 40
VERSION = "v0.12.0"
BUILDKIT_IMAGE = (
    "moby/buildkit:v0.30.0@sha256:"
    "0168606be2315b7c807a03b3d8aa79beefdb31c98740cebdffdfeebf31190c9f"
)
BUILDKIT_REPO_DIGEST = "moby/buildkit@sha256:0168606be2315b7c807a03b3d8aa79beefdb31c98740cebdffdfeebf31190c9f"


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
    ) -> tuple[int, str, str, unittest.mock.Mock]:
        completed = subprocess.CompletedProcess(
            args=[], returncode=returncode, stdout=stdout, stderr=stderr
        )
        run = unittest.mock.Mock(return_value=completed)
        captured_stdout = io.StringIO()
        captured_stderr = io.StringIO()
        with (
            unittest.mock.patch.object(self.module.subprocess, "run", run),
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

    def test_default_inspection_falls_back_from_index_to_linux_amd64_manifest(
        self,
    ) -> None:
        application_digest = "sha256:" + "c" * 64
        labels = {
            "org.opencontainers.image.source": SOURCE,
            "org.opencontainers.image.revision": REVISION,
            "org.opencontainers.image.version": VERSION,
        }
        run = unittest.mock.Mock(
            side_effect=[
                subprocess.CompletedProcess(
                    args=[],
                    returncode=1,
                    stdout="",
                    stderr='template: :1: executing "" at <.Image.Config>: cannot evaluate field Config',
                ),
                subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout=json.dumps(
                        {
                            "manifests": [
                                {
                                    "digest": application_digest,
                                    "platform": {
                                        "os": "linux",
                                        "architecture": "amd64",
                                    },
                                }
                            ]
                        }
                    ),
                    stderr="",
                ),
                subprocess.CompletedProcess(
                    args=[], returncode=0, stdout=config_json(labels), stderr=""
                ),
            ]
        )

        with unittest.mock.patch.object(self.module.subprocess, "run", run):
            config = self.module.inspect_image_config(
                IMAGE_REF, self.module.DEFAULT_FORMAT_TEMPLATE
            )

        self.assertEqual(labels, config["Labels"])
        self.assertEqual(3, run.call_count)
        self.assertEqual(
            ["docker", "buildx", "imagetools", "inspect", "--raw", IMAGE_REF],
            run.call_args_list[1].args[0],
        )
        self.assertEqual(
            f"example.invalid/registry-relay@{application_digest}",
            run.call_args_list[2].args[0][-1],
        )

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


class ReleaseImageBuildWrapperTest(unittest.TestCase):
    def run_wrapper(
        self,
        *,
        builder_inspect: str,
        builder_containers: str,
        builder_container_image: str,
        buildkit_repo_digests: str = BUILDKIT_REPO_DIGEST,
    ) -> subprocess.CompletedProcess[str]:
        image_builder = ROOT / "release/scripts/build-release-image.sh"
        with tempfile.TemporaryDirectory() as temporary:
            fake_bin = Path(temporary) / "bin"
            fake_bin.mkdir()
            fake_docker = fake_bin / "docker"
            fake_docker.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "case \"${1:-} ${2:-}\" in\n"
                "  'buildx version') echo 'github.com/docker/buildx v0.33.0 test' ;;\n"
                "  'buildx inspect') printf '%s\\n' \"${BUILDER_INSPECT}\" ;;\n"
                "  'ps --all') printf '%s\\n' \"${BUILDER_CONTAINERS}\" ;;\n"
                "  'inspect --format') printf '%s\\n' \"${BUILDER_CONTAINER_IMAGE}\" ;;\n"
                "  'image inspect') printf '%s\\n' \"${BUILDKIT_REPO_DIGESTS}\" ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_docker.chmod(0o755)
            metadata = Path(temporary) / "metadata.json"
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{fake_bin}{os.pathsep}{environment['PATH']}",
                    "RELEASE_BUILDX_BUILDER": "release-builder",
                    "BUILDER_INSPECT": builder_inspect,
                    "BUILDER_CONTAINERS": builder_containers,
                    "BUILDER_CONTAINER_IMAGE": builder_container_image,
                    "BUILDKIT_REPO_DIGESTS": buildkit_repo_digests,
                }
            )
            return subprocess.run(
                [
                    str(image_builder),
                    "registry-relay",
                    "example.invalid/registry-relay:test",
                    SOURCE,
                    REVISION,
                    VERSION,
                    str(metadata),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
                env=environment,
            )

    def test_reused_builder_requires_pinned_standard_buildkit_container(self) -> None:
        result = self.run_wrapper(
            builder_inspect="Driver: docker-container\nBuildKit version: v0.30.0",
            builder_containers="buildx_buildkit_release-builder0",
            builder_container_image=BUILDKIT_IMAGE,
        )

        self.assertEqual(0, result.returncode, result.stderr)

    def test_reused_builder_rejects_non_container_driver(self) -> None:
        result = self.run_wrapper(
            builder_inspect="Driver: docker\nBuildKit version: v0.30.0",
            builder_containers="buildx_buildkit_release-builder0",
            builder_container_image=BUILDKIT_IMAGE,
        )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("must use the docker-container driver", result.stderr)

    def test_reused_builder_rejects_unpinned_container_image(self) -> None:
        result = self.run_wrapper(
            builder_inspect="Driver: docker-container\nBuildKit version: v0.30.0",
            builder_containers="buildx_buildkit_release-builder0",
            builder_container_image="moby/buildkit:v0.30.0",
        )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("must use", result.stderr)
        self.assertIn("must use", result.stderr)

    def test_reused_builder_rejects_wrong_repo_digest(self) -> None:
        result = self.run_wrapper(
            builder_inspect="Driver: docker-container\nBuildKit version: v0.30.0",
            builder_containers="buildx_buildkit_release-builder0",
            builder_container_image=BUILDKIT_IMAGE,
            buildkit_repo_digests="moby/buildkit@sha256:" + "0" * 64,
        )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("must resolve", result.stderr)

    def test_reused_builder_rejects_nonstandard_container_shape(self) -> None:
        result = self.run_wrapper(
            builder_inspect="Driver: docker-container\nBuildKit version: v0.30.0",
            builder_containers="buildx_buildkit_release-builder0\nbuildx_buildkit_release-builder1",
            builder_container_image=BUILDKIT_IMAGE,
        )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("must have exactly one standard BuildKit container", result.stderr)


class ReleaseImageOciLabelsSmokeTest(unittest.TestCase):
    def test_smoke_builds_both_release_dockerfiles_via_ephemeral_registry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fake_bin = Path(temporary) / "bin"
            fake_bin.mkdir()
            docker_log = Path(temporary) / "docker.log"
            checker_log = Path(temporary) / "checker.log"
            fake_docker = fake_bin / "docker"
            fake_docker.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "{ printf 'BEGIN\\n'; printf '%s\\n' \"$@\"; printf 'END\\n'; } "
                '>> "${DOCKER_LOG}"\n'
                "case \"$*\" in\n"
                "  'buildx version') echo 'github.com/docker/buildx v0.33.0 test' ;;\n"
                "  'buildx create '* )\n"
                "    for ((argument = 1; argument <= $#; argument++)); do\n"
                "      if [[ \"${!argument}\" == '--name' ]]; then\n"
                "        next=$((argument + 1))\n"
                "        printf 'buildx_buildkit_%s0\\n' \"${!next}\" > \"${DOCKER_STATE}\"\n"
                "      fi\n"
                "    done ;;\n"
                "  'buildx inspect '* ) printf 'Driver: docker-container\\nBuildKit version: v0.30.0\\n' ;;\n"
                "  'ps --all '* ) cat \"${DOCKER_STATE}\" ;;\n"
                "  'inspect --format '* )\n"
                "    echo 'moby/buildkit:v0.30.0@sha256:0168606be2315b7c807a03b3d8aa79beefdb31c98740cebdffdfeebf31190c9f' ;;\n"
                "  'image inspect '* ) echo 'moby/buildkit@sha256:0168606be2315b7c807a03b3d8aa79beefdb31c98740cebdffdfeebf31190c9f' ;;\n"
                "  'port '* ) echo '127.0.0.1:5000' ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_docker.chmod(0o755)
            fake_python = fake_bin / "python3"
            fake_python.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "{ printf 'BEGIN\\n'; printf '%s\\n' \"$@\"; printf 'END\\n'; } "
                '>> "${CHECKER_LOG}"\n'
                "case \"$*\" in\n"
                "  *missing-version*|*wrong-revision*|*'{{json .Image.config}}'*) "
                "exit 1 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_python.chmod(0o755)
            environment = os.environ.copy()
            environment["PATH"] = f"{fake_bin}{os.pathsep}{environment['PATH']}"
            environment["DOCKER_LOG"] = str(docker_log)
            environment["DOCKER_STATE"] = str(Path(temporary) / "docker-state")
            environment["CHECKER_LOG"] = str(checker_log)

            result = subprocess.run(
                [str(SMOKE_SCRIPT)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
                env=environment,
            )

            self.assertEqual(0, result.returncode, result.stderr)

            def read_calls(path: Path) -> list[list[str]]:
                calls: list[list[str]] = []
                current: list[str] | None = None
                for line in path.read_text(encoding="utf-8").splitlines():
                    if line == "BEGIN":
                        current = []
                    elif line == "END":
                        self.assertIsNotNone(current)
                        calls.append(current or [])
                        current = None
                    else:
                        self.assertIsNotNone(current)
                        current.append(line)
                self.assertIsNone(current)
                return calls

            build_calls = [
                call for call in read_calls(docker_log) if call[:2] == ["buildx", "build"]
            ]
            self.assertEqual(6, len(build_calls))
            dockerfiles = []
            published_builds = []
            negative_builds = []
            for call in build_calls:
                self.assertEqual(["buildx", "build"], call[:2])
                self.assertIn("--platform", call)
                self.assertEqual("linux/amd64", call[call.index("--platform") + 1])
                output = call[call.index("--output") + 1]
                if output.startswith("type=registry,"):
                    published_builds.append(call)
                    self.assertIn("--builder", call)
                    self.assertIn("--no-cache", call)
                    self.assertIn("--build-arg", call)
                    self.assertEqual(
                        "SOURCE_DATE_EPOCH=0", call[call.index("--build-arg") + 1]
                    )
                    self.assertEqual(
                        "type=registry,push=true,rewrite-timestamp=true,compatibility-version=20,registry.insecure=true",
                        output,
                    )
                else:
                    negative_builds.append(call)
                    self.assertIn("--provenance=false", call)
                    self.assertTrue(output.startswith("type=oci,dest="), output)
                    self.assertTrue(output.endswith(",tar=false"), output)
                dockerfiles.append(call[call.index("--file") + 1])

            self.assertEqual(4, len(published_builds))
            self.assertEqual(2, len(negative_builds))

            self.assertEqual(
                {
                    str(ROOT / "release/docker/Dockerfile.registry-notary"),
                    str(ROOT / "release/docker/Dockerfile.registry-relay"),
                },
                set(dockerfiles),
            )
            inspected_layouts = {
                call[1]
                for call in read_calls(checker_log)
                if len(call) > 1 and ":correct" in call[1]
            }
            self.assertEqual(
                {"registry-notary:correct", "registry-relay:correct"},
                {
                    Path(layout).name
                    for layout in inspected_layouts
                },
            )


if __name__ == "__main__":
    unittest.main()
