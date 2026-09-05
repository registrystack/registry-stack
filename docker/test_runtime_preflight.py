#!/usr/bin/env python3
"""Focused tests for the supported Compose runtime preflight."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import unittest
import unittest.mock
from pathlib import Path


SCRIPT = Path(__file__).with_name("runtime-preflight.py")
DIGEST = "a" * 64
COMPOSE_DIRECTORY = SCRIPT.parent / "compose"
COLD_FIXTURE_FILES = (
    COMPOSE_DIRECTORY / "docker-compose.yaml",
    COMPOSE_DIRECTORY / "docker-compose.mint.yaml",
)
# Compose interpolates these without touching the host paths they name, so the
# rendered fixture stays identical wherever the suite runs.
COLD_FIXTURE_ENVIRONMENT = {
    "EVIDENCE_CANDIDATE_DIR": "/srv/registry-stack/evidence/candidate",
    "EVIDENCE_RUNTIME_FILE": "/srv/registry-stack/evidence/runtime.docker.yaml",
    "EVIDENCE_SECRET_ROOT": "/srv/registry-stack/evidence/secrets",
    "EVIDENCE_TRANSIT_SOCKET_DIR": "/srv/registry-stack/evidence/transit",
    "EVIDENCE_IMAGE": f"ghcr.io/registrystack/evidence@sha256:{DIGEST}",
    "MINT_CONFIG_DIR": "/srv/registry-stack/mint/config",
    "MINT_SECRET_ROOT": "/srv/registry-stack/mint/secrets",
    "MINT_TRANSIT_SOCKET_DIR": "/srv/registry-stack/mint/transit",
    "MINT_HEALTHCHECK_URL": "http://127.0.0.1:8081/ready",
    "MINT_IMAGE": f"ghcr.io/registrystack/mint@sha256:{DIGEST}",
}


def compose_is_available() -> bool:
    try:
        result = subprocess.run(
            ["docker", "compose", "version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def render_cold_fixture() -> dict[str, object]:
    command = ["docker", "compose"]
    for compose_file in COLD_FIXTURE_FILES:
        command.extend(["--file", str(compose_file)])
    command.extend(["config", "--format", "json"])
    result = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, **COLD_FIXTURE_ENVIRONMENT},
        timeout=120,
    )
    return json.loads(result.stdout)


def load_module():
    spec = importlib.util.spec_from_file_location("runtime_preflight", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def service(product: str) -> dict[str, object]:
    audit = {
        "evidence": "/var/lib/registry-evidence",
        "mint": "/var/lib/registry-mint",
        "relay": "/var/lib/relay/audit",
    }[product]
    return {
        "image": f"ghcr.io/registrystack/{product}@sha256:{DIGEST}",
        "user": "65532:65532",
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "secrets": [
            {
                "source": "runtime-secret",
                "target": "/run/secrets/runtime-secret",
                "uid": "65532",
                "gid": "65532",
                "mode": 0o400,
            }
        ],
        "volumes": [
            {"type": "bind", "target": f"/etc/{product}", "read_only": True},
            {
                "type": "volume",
                "source": f"{product}-audit",
                "target": audit,
                "read_only": False,
            },
            {
                "type": "tmpfs",
                "target": "/dev/shm",
                "read_only": True,
            },
        ],
    }


def deployment(services: dict[str, dict[str, object]]) -> dict[str, object]:
    return {
        "services": services,
        "volumes": {f"{product}-audit": {} for product in services},
    }


def completed(returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout="sensitive", stderr="sensitive"
    )


def cold_deployment() -> dict[str, object]:
    document = deployment({"evidence": service("evidence"), "mint": service("mint")})
    document["services"]["evidence"]["depends_on"] = {  # type: ignore[index]
        "mint": {"condition": "service_started"}
    }
    return document


class RuntimePreflightTest(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.argv = [
            "--compose-file",
            "compose.yaml",
            "--env-file",
            "operator.env",
            "--service",
            "evidence=evidence",
            "--service",
            "mint=mint",
            "--service",
            "relay=relay",
        ]

    def run_main(
        self,
        document: dict[str, object],
        *,
        native_returncode: int = 0,
        argv: list[str] | None = None,
    ) -> tuple[int, str, str, unittest.mock.Mock]:
        render = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(document), stderr=""
        )
        native = subprocess.CompletedProcess(
            args=[],
            returncode=native_returncode,
            stdout="sensitive",
            stderr="sensitive",
        )
        run = unittest.mock.Mock(side_effect=[render, native, native, native])
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            unittest.mock.patch.object(self.module.subprocess, "run", run),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            result = self.module.main(self.argv if argv is None else argv)
        return result, stdout.getvalue(), stderr.getvalue(), run

    def run_orchestration(
        self,
        document: dict[str, object],
        effects: list[object],
        argv: list[str],
    ) -> tuple[int, str, str, unittest.mock.Mock]:
        render = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(document), stderr=""
        )
        run = unittest.mock.Mock(side_effect=[render, *effects])
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            unittest.mock.patch.object(self.module.subprocess, "run", run),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            result = self.module.main(argv)
        return result, stdout.getvalue(), stderr.getvalue(), run

    def test_all_products_use_native_checks_after_complete_static_preflight(
        self,
    ) -> None:
        document = deployment(
            {
                "evidence": service("evidence"),
                "mint": service("mint"),
                "relay": service("relay"),
            }
        )
        result, stdout, stderr, run = self.run_main(document)
        self.assertEqual(0, result, stderr)
        self.assertEqual("runtime preflight passed for 3 service(s)\n", stdout)
        self.assertEqual(4, run.call_count)
        calls = [call.args[0] for call in run.call_args_list]
        self.assertEqual(
            [
                "docker",
                "compose",
                "--env-file",
                "operator.env",
                "--file",
                "compose.yaml",
                "config",
                "--format",
                "json",
            ],
            calls[0],
        )
        self.assertIn("--require-runtime-dependencies", calls[1])
        self.assertIn("--require-runtime-dependencies", calls[2])
        self.assertEqual("check", calls[3][-3])
        self.assertEqual("evidence", calls[1][calls[1].index("--no-deps") + 1])
        self.assertEqual("mint", calls[2][calls[2].index("--no-deps") + 1])
        self.assertEqual("relay", calls[3][calls[3].index("--no-deps") + 1])
        for call in run.call_args_list[1:]:
            self.assertIn("--no-deps", call.args[0])
            self.assertEqual(["docker", "compose", "--file", "-"], call.args[0][:4])
            self.assertEqual(self.module.subprocess.DEVNULL, call.kwargs["stdout"])
            self.assertEqual(self.module.subprocess.DEVNULL, call.kwargs["stderr"])
            self.assertNotIn("capture_output", call.kwargs)
            self.assertEqual(
                self.module.DEFAULT_NATIVE_CHECK_TIMEOUT_SECONDS,
                call.kwargs["timeout"],
            )
            self.assertEqual(document, json.loads(call.kwargs["input"]))

    def test_every_static_posture_failure_precedes_native_execution(self) -> None:
        mutations = {
            "tagged image": lambda item: item.update(
                image="ghcr.io/registrystack/evidence:v1"
            ),
            "replacement build": lambda item: item.update(build={"context": "."}),
            "root user": lambda item: item.update(user="0:0"),
            "supplementary group": lambda item: item.update(group_add=["0"]),
            "host device": lambda item: item.update(devices=["/dev/kvm:/dev/kvm"]),
            "host GPU": lambda item: item.update(gpus="all"),
            "device cgroup rule": lambda item: item.update(
                device_cgroup_rules=["c 1:3 rwm"]
            ),
            "two deploy replicas": lambda item: item.update(deploy={"replicas": 2}),
            "boolean deploy replicas": lambda item: item.update(
                deploy={"replicas": True}
            ),
            "two scaled replicas": lambda item: item.update(scale=2),
            "boolean scale": lambda item: item.update(scale=True),
            "writable root": lambda item: item.update(read_only=False),
            "privileged container": lambda item: item.update(privileged=True),
            "post-start hook": lambda item: item.update(
                post_start=[{"command": "/usr/local/bin/evidence", "privileged": True}]
            ),
            "pre-stop hook": lambda item: item.update(
                pre_stop=[{"command": "/usr/local/bin/evidence", "user": "0"}]
            ),
            "capabilities": lambda item: item.update(cap_drop=[]),
            "added capability": lambda item: item.update(cap_add=["SYS_ADMIN"]),
            "privilege escalation": lambda item: item.update(security_opt=[]),
            "unconfined seccomp": lambda item: item.update(
                security_opt=["no-new-privileges:true", "seccomp=unconfined"]
            ),
            "unconfined AppArmor": lambda item: item.update(
                security_opt=["no-new-privileges:true", "apparmor=unconfined"]
            ),
            "unconfined system paths": lambda item: item.update(
                security_opt=["no-new-privileges:true", "systempaths=unconfined"]
            ),
            "duplicate security option": lambda item: item.update(
                security_opt=[
                    "no-new-privileges:true",
                    "no-new-privileges:true",
                ]
            ),
            "unrelated security option": lambda item: item.update(
                security_opt=["no-new-privileges:true", "label=disable"]
            ),
            "entrypoint override": lambda item: item.update(entrypoint=["/bin/true"]),
            "command override": lambda item: item.update(command=["serve"]),
            "host network": lambda item: item.update(network_mode="host"),
            "shared service network": lambda item: item.update(
                network_mode="service:proxy"
            ),
            "shared container network": lambda item: item.update(
                network_mode="container:proxy"
            ),
            "inherited mounts": lambda item: item.update(volumes_from=["proxy"]),
            "runtime path override": lambda item: item.update(
                environment={"REGISTRY_EVIDENCE_RUNTIME": "/tmp/runtime.yaml"}
            ),
            "dynamic loader override": lambda item: item.update(
                environment={"LD_PRELOAD": "/run/secrets/replacement.so"}
            ),
            "public port": lambda item: item.update(
                ports=[{"target": 8080, "published": 8080}]
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                selected = service("evidence")
                mutate(selected)
                render = subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout=json.dumps(deployment({"evidence": selected})),
                    stderr="",
                )
                run = unittest.mock.Mock(return_value=render)
                with unittest.mock.patch.object(self.module.subprocess, "run", run):
                    result = self.module.main(
                        [
                            "--compose-file",
                            "compose.yaml",
                            "--service",
                            "evidence=evidence",
                        ]
                    )
                self.assertEqual(1, result)
                run.assert_called_once()

    def test_secret_modes_are_exact_and_audit_must_be_writable(self) -> None:
        for mode in (0o400, 0o600, "0400", "0600"):
            selected = service("evidence")
            selected["secrets"][0]["mode"] = mode  # type: ignore[index]
            self.module.validate_service(
                self.module.ServiceSelection("evidence", "evidence"),
                deployment({"evidence": selected}),
            )
        for mode in (0o440, 0o604, "0640"):
            selected = service("evidence")
            selected["secrets"][0]["mode"] = mode  # type: ignore[index]
            with self.assertRaises(self.module.PreflightError):
                self.module.validate_service(
                    self.module.ServiceSelection("evidence", "evidence"),
                    deployment({"evidence": selected}),
                )
        selected = service("evidence")
        selected["volumes"][1]["read_only"] = True  # type: ignore[index]
        with self.assertRaises(self.module.PreflightError):
            self.module.validate_service(
                self.module.ServiceSelection("evidence", "evidence"),
                deployment({"evidence": selected}),
            )
        selected = service("evidence")
        selected["volumes"][1]["type"] = "tmpfs"  # type: ignore[index]
        with self.assertRaises(self.module.PreflightError):
            self.module.validate_service(
                self.module.ServiceSelection("evidence", "evidence"),
                deployment({"evidence": selected}),
            )
        selected = service("evidence")
        selected["volumes"][1].pop("source")  # type: ignore[index]
        with self.assertRaises(self.module.PreflightError):
            self.module.validate_service(
                self.module.ServiceSelection("evidence", "evidence"),
                deployment({"evidence": selected}),
            )

        selected = service("evidence")
        ephemeral = deployment({"evidence": selected})
        ephemeral["volumes"]["evidence-audit"] = {  # type: ignore[index]
            "driver": "local",
            "driver_opts": {"type": "tmpfs", "device": "tmpfs"},
        }
        with self.assertRaises(self.module.PreflightError):
            self.module.validate_service(
                self.module.ServiceSelection("evidence", "evidence"), ephemeral
            )

    def test_audit_sink_can_only_succeed_on_the_one_durable_mount(self) -> None:
        selected = service("evidence")
        selected["volumes"][1] = {  # type: ignore[index]
            "type": "bind",
            "source": "/srv/registry-stack/evidence-audit",
            "target": "/var/lib/registry-evidence",
            "read_only": False,
        }
        selected["group_add"] = []
        selected["devices"] = []
        selected["deploy"] = {"replicas": 1}
        selected["scale"] = 1
        self.module.validate_service(
            self.module.ServiceSelection("evidence", "evidence"),
            deployment({"evidence": selected}),
        )

        for source in (
            "/dev/shm/evidence-audit",
            "/run/evidence-audit",
            "/tmp/evidence-audit",
            "/var/tmp/evidence-audit",
            "/private/tmp/evidence-audit",
            "/private/var/folders/cache/evidence-audit",
            "/tmp/../srv/evidence-audit",
            "/srv//evidence-audit",
        ):
            with self.subTest(source=source):
                selected = service("evidence")
                selected["volumes"][1] = {  # type: ignore[index]
                    "type": "bind",
                    "source": source,
                    "target": "/var/lib/registry-evidence",
                    "read_only": False,
                }
                with self.assertRaises(self.module.PreflightError):
                    self.module.validate_service(
                        self.module.ServiceSelection("evidence", "evidence"),
                        deployment({"evidence": selected}),
                    )

        selected = service("evidence")
        selected["volumes"].append(  # type: ignore[union-attr]
            {
                "type": "tmpfs",
                "target": "/actual-audit",
                "read_only": False,
            }
        )
        with self.assertRaises(self.module.PreflightError):
            self.module.validate_service(
                self.module.ServiceSelection("evidence", "evidence"),
                deployment({"evidence": selected}),
            )

        for name, mutate in {
            "absent read-only shm": lambda item: item["volumes"].pop(),  # type: ignore[union-attr]
            "writable shm": lambda item: item["volumes"][-1].update(  # type: ignore[index]
                read_only=False
            ),
            "alternate tmpfs target": lambda item: item["volumes"][-1].update(  # type: ignore[index]
                target="/tmp"
            ),
            "duplicate read-only shm": lambda item: item["volumes"].append(  # type: ignore[union-attr]
                {
                    "type": "tmpfs",
                    "target": "/dev/shm",
                    "read_only": True,
                }
            ),
            "service-level tmpfs": lambda item: item.update(tmpfs=["/dev/shm:ro"]),
        }.items():
            with self.subTest(name=name):
                selected = service("evidence")
                mutate(selected)
                with self.assertRaises(self.module.PreflightError):
                    self.module.validate_service(
                        self.module.ServiceSelection("evidence", "evidence"),
                        deployment({"evidence": selected}),
                    )

        selected = service("evidence")
        selected["volumes"][1]["target"] = (  # type: ignore[index]
            "/var/lib/registry-evidence/alternate"
        )
        with self.assertRaises(self.module.PreflightError):
            self.module.validate_service(
                self.module.ServiceSelection("evidence", "evidence"),
                deployment({"evidence": selected}),
            )

    def test_named_audit_volume_cannot_masquerade_as_a_bind(self) -> None:
        declarations = (
            {
                "driver": "local",
                "driver_opts": {
                    "type": "none",
                    "o": "bind",
                    "device": "/srv/registry-stack/evidence-audit",
                },
            },
            {"driver": "local", "external": True},
            {"driver": "operator-storage"},
        )
        for declaration in declarations:
            with self.subTest(declaration=declaration):
                selected = service("evidence")
                document = deployment({"evidence": selected})
                document["volumes"]["evidence-audit"] = declaration  # type: ignore[index]
                with self.assertRaises(self.module.PreflightError):
                    self.module.validate_service(
                        self.module.ServiceSelection("evidence", "evidence"),
                        document,
                    )

    def test_mounts_cannot_shadow_official_executables_or_libraries(self) -> None:
        for product in ("evidence", "mint", "relay"):
            executable = f"/usr/local/bin/{product}"
            for target in (
                "/",
                "/usr",
                "/usr/local",
                "/usr/local/bin",
                executable,
                f"//usr/local/bin/{product}",
                f"/usr/local/bin/../bin/{product}",
                "/lib",
                "/lib/replacement",
                "/usr/lib",
                "/usr/local/lib/replacement",
                "/etc/ld.so.preload",
                "/etc/ld.so.cache",
            ):
                with self.subTest(product=product, target=target):
                    selected = service(product)
                    selected["volumes"].append(  # type: ignore[union-attr]
                        {
                            "type": "bind",
                            "source": "/srv/replacement",
                            "target": target,
                            "read_only": True,
                        }
                    )
                    with self.assertRaises(self.module.PreflightError):
                        self.module.validate_service(
                            self.module.ServiceSelection(product, product),
                            deployment({product: selected}),
                        )

            selected = service(product)
            selected["configs"] = [
                {"source": "replacement", "target": executable, "mode": "0555"}
            ]
            with self.assertRaises(self.module.PreflightError):
                self.module.validate_service(
                    self.module.ServiceSelection(product, product),
                    deployment({product: selected}),
                )

            selected = service(product)
            selected["configs"] = [
                {
                    "source": "replacement",
                    "target": "/etc/ld.so.preload",
                    "mode": "0444",
                }
            ]
            with self.assertRaises(self.module.PreflightError):
                self.module.validate_service(
                    self.module.ServiceSelection(product, product),
                    deployment({product: selected}),
                )

            selected = service(product)
            selected["secrets"][0]["target"] = executable  # type: ignore[index]
            with self.assertRaises(self.module.PreflightError):
                self.module.validate_service(
                    self.module.ServiceSelection(product, product),
                    deployment({product: selected}),
                )

            selected = service(product)
            selected["secrets"][0]["target"] = "/etc/ld.so.preload"  # type: ignore[index]
            with self.assertRaises(self.module.PreflightError):
                self.module.validate_service(
                    self.module.ServiceSelection(product, product),
                    deployment({product: selected}),
                )

    def test_writable_mounts_cannot_overlap_configuration_or_secrets(self) -> None:
        for target in ["/", "/etc", "/etc/registry-evidence", "/run", "/run/secrets"]:
            with self.subTest(target=target):
                selected = service("evidence")
                selected["volumes"].append(  # type: ignore[union-attr]
                    {
                        "type": "volume",
                        "source": "unsafe",
                        "target": target,
                        "read_only": False,
                    }
                )
                with self.assertRaises(self.module.PreflightError):
                    self.module.validate_service(
                        self.module.ServiceSelection("evidence", "evidence"),
                        deployment({"evidence": selected}),
                    )

    def test_official_configuration_paths_may_not_be_overridden(self) -> None:
        fixed = {
            "evidence": (
                "REGISTRY_EVIDENCE_RUNTIME",
                "/etc/registry-evidence/runtime.yaml",
            ),
            "mint": ("MINT_CONFIG", "/etc/registry-mint/config.yaml"),
        }
        for product, (name, expected) in fixed.items():
            with self.subTest(product=product):
                selected = service(product)
                selected["environment"] = {name: expected}
                self.module.validate_service(
                    self.module.ServiceSelection(product, product),
                    deployment({product: selected}),
                )
                selected["environment"] = {name: "/tmp/alternate.yaml"}
                with self.assertRaises(self.module.PreflightError):
                    self.module.validate_service(
                        self.module.ServiceSelection(product, product),
                        deployment({product: selected}),
                    )

    def test_native_failure_is_value_free(self) -> None:
        document = deployment(
            {
                "evidence": service("evidence"),
                "mint": service("mint"),
                "relay": service("relay"),
            }
        )
        result, stdout, stderr, _ = self.run_main(document, native_returncode=1)
        self.assertEqual(1, result)
        self.assertEqual("", stdout)
        self.assertNotIn("sensitive", stderr)
        self.assertIn("native runtime check", stderr)

    def test_native_check_deadline_is_bounded_and_operator_configurable(self) -> None:
        document = deployment(
            {
                "evidence": service("evidence"),
                "mint": service("mint"),
                "relay": service("relay"),
            }
        )
        minimum = self.module.MINIMUM_NATIVE_CHECK_TIMEOUT_SECONDS
        maximum = self.module.MAXIMUM_NATIVE_CHECK_TIMEOUT_SECONDS
        default = self.module.DEFAULT_NATIVE_CHECK_TIMEOUT_SECONDS
        self.assertLessEqual(minimum, default)
        self.assertLessEqual(default, maximum)
        for selected in (minimum, default, maximum):
            with self.subTest(selected=selected):
                result, _, stderr, run = self.run_main(
                    document,
                    argv=[
                        *self.argv,
                        "--native-check-timeout-seconds",
                        str(selected),
                    ],
                )
                self.assertEqual(0, result, stderr)
                for call in run.call_args_list[1:]:
                    self.assertEqual(selected, call.kwargs["timeout"])
        for raw in (
            str(minimum - 1),
            str(maximum + 1),
            "0",
            "-1",
            "1.5",
            "not-a-number",
        ):
            with self.subTest(raw=raw):
                rejected = io.StringIO()
                with (
                    contextlib.redirect_stderr(rejected),
                    self.assertRaises(SystemExit),
                ):
                    self.module.parse_args(
                        [
                            "--compose-file",
                            "compose.yaml",
                            "--service",
                            "evidence=evidence",
                            "--native-check-timeout-seconds",
                            raw,
                        ]
                    )

    def test_an_expired_native_check_deadline_fails_without_output(self) -> None:
        document = deployment({"evidence": service("evidence")})
        render = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(document), stderr=""
        )
        expired = subprocess.TimeoutExpired(
            cmd=["docker", "compose"],
            timeout=30,
            output="sensitive",
            stderr="sensitive",
        )
        run = unittest.mock.Mock(side_effect=[render, expired])
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            unittest.mock.patch.object(self.module.subprocess, "run", run),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            result = self.module.main(
                ["--compose-file", "compose.yaml", "--service", "evidence=evidence"]
            )
        self.assertEqual(1, result)
        self.assertEqual("", stdout.getvalue())
        self.assertNotIn("sensitive", stderr.getvalue())
        self.assertIn("native runtime check deadline", stderr.getvalue())

    def test_cold_mint_dependency_is_checked_started_probed_then_consumed(self) -> None:
        document = deployment(
            {
                "evidence": service("evidence"),
                "mint": service("mint"),
                "unrelated": {"image": "example.invalid/unrelated:latest"},
            }
        )
        document["services"]["evidence"]["depends_on"] = {  # type: ignore[index]
            "mint": {"condition": "service_healthy", "required": True}
        }
        complete = lambda returncode=0: subprocess.CompletedProcess(  # noqa: E731
            args=[], returncode=returncode, stdout="sensitive", stderr="sensitive"
        )
        render = complete()
        render.stdout = json.dumps(document)
        run = unittest.mock.Mock(
            side_effect=[render, complete(), complete(), complete(), complete()]
        )
        argv = [
            "--compose-file",
            "compose.yaml",
            "--service",
            "evidence=evidence",
            "--service",
            "mint=mint",
            "--native-check-timeout-seconds",
            "600",
            "--dependency-timeout-seconds",
            "240",
        ]
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            unittest.mock.patch.object(self.module.subprocess, "run", run),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            result = self.module.main(argv)

        self.assertEqual(0, result, stderr.getvalue())
        calls = [call.args[0] for call in run.call_args_list]
        self.assertEqual("mint", calls[1][calls[1].index("--no-deps") + 1])
        self.assertEqual(["up", "--detach", "--no-deps", "mint"], calls[2][-4:])
        self.assertEqual(
            [
                "exec",
                "--no-TTY",
                "mint",
                "/usr/local/bin/mint",
                "healthcheck",
            ],
            calls[3][-5:],
        )
        self.assertEqual("evidence", calls[4][calls[4].index("--no-deps") + 1])
        self.assertEqual(600, run.call_args_list[1].kwargs["timeout"])
        self.assertEqual(240, run.call_args_list[2].kwargs["timeout"])
        self.assertEqual(600, run.call_args_list[4].kwargs["timeout"])
        self.assertFalse(any("unrelated" in call for call in calls))
        for call in run.call_args_list[1:]:
            self.assertEqual(document, json.loads(call.kwargs["input"]))
            self.assertEqual(self.module.subprocess.DEVNULL, call.kwargs["stdout"])
            self.assertEqual(self.module.subprocess.DEVNULL, call.kwargs["stderr"])

    def test_unhealthy_mint_blocks_the_dependent_native_check(self) -> None:
        document = deployment(
            {"evidence": service("evidence"), "mint": service("mint")}
        )
        document["services"]["evidence"]["depends_on"] = ["mint"]  # type: ignore[index]
        render = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(document), stderr=""
        )
        complete = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        failed = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr=""
        )
        run = unittest.mock.Mock(side_effect=[render, complete, complete, failed])
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            unittest.mock.patch.object(self.module.subprocess, "run", run),
            unittest.mock.patch.object(
                self.module.time,
                "monotonic",
                side_effect=[0.0, 0.0, 0.0, 0.0, 6.0],
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            result = self.module.main(
                [
                    "--compose-file",
                    "compose.yaml",
                    "--service",
                    "evidence=evidence",
                    "--service",
                    "mint=mint",
                    "--dependency-timeout-seconds",
                    "5",
                ]
            )

        self.assertEqual(1, result)
        self.assertEqual("", stdout.getvalue())
        self.assertIn("did not become ready", stderr.getvalue())
        self.assertIn("docker compose stop mint", stderr.getvalue())
        self.assertEqual(4, run.call_count)
        self.assertFalse(
            any(
                "evidence" in call.args[0] and "run" in call.args[0]
                for call in run.call_args_list
            )
        )

    def test_dependency_order_is_deterministic_across_selection_order(self) -> None:
        document = deployment(
            {
                "evidence": service("evidence"),
                "mint": service("mint"),
                "relay": service("relay"),
            }
        )
        document["services"]["evidence"]["depends_on"] = ["mint"]  # type: ignore[index]
        selections = [
            self.module.ServiceSelection("evidence", "evidence"),
            self.module.ServiceSelection("mint", "mint"),
            self.module.ServiceSelection("relay", "relay"),
        ]
        for selected in (selections, list(reversed(selections))):
            with self.subTest(selected=[item.service for item in selected]):
                ordered, dependencies = self.module.native_check_plan(
                    list(selected), document
                )
                names = [item.service for item in ordered]
                self.assertCountEqual(
                    [item.service for item in selected], names, names
                )
                self.assertLess(names.index("mint"), names.index("evidence"))
                self.assertEqual({"mint"}, dependencies)
                repeated, _ = self.module.native_check_plan(list(selected), document)
                self.assertEqual(names, [item.service for item in repeated])

    def test_an_unselected_dependency_is_never_started(self) -> None:
        document = cold_deployment()
        result, stdout, stderr, run = self.run_orchestration(
            document,
            [completed()],
            ["--compose-file", "compose.yaml", "--service", "evidence=evidence"],
        )
        self.assertEqual(0, result, stderr)
        self.assertEqual("runtime preflight passed for 1 service(s)\n", stdout)
        self.assertEqual(2, run.call_count)
        native = run.call_args_list[1].args[0]
        self.assertEqual("evidence", native[native.index("--no-deps") + 1])
        self.assertNotIn("up", native)
        self.assertNotIn("mint", native)

    def test_an_unavailable_mint_fails_before_the_dependent_check(self) -> None:
        document = cold_deployment()
        result, stdout, stderr, run = self.run_orchestration(
            document,
            [completed(), completed(returncode=1)],
            [
                "--compose-file",
                "compose.yaml",
                "--service",
                "evidence=evidence",
                "--service",
                "mint=mint",
            ],
        )
        self.assertEqual(1, result)
        self.assertEqual("", stdout)
        self.assertNotIn("sensitive", stderr)
        self.assertIn("could not be started", stderr)
        self.assertEqual(3, run.call_count)
        self.assertEqual(
            ["up", "--detach", "--no-deps", "mint"],
            run.call_args_list[2].args[0][-4:],
        )

    def test_started_dependencies_are_reported_for_operator_recovery(self) -> None:
        document = cold_deployment()
        argv = [
            "--compose-file",
            "compose.yaml",
            "--service",
            "evidence=evidence",
            "--service",
            "mint=mint",
        ]
        result, stdout, stderr, _ = self.run_orchestration(
            document,
            [completed(), completed(), completed(), completed()],
            argv,
        )
        self.assertEqual(0, result, stderr)
        self.assertIn("docker compose stop mint", stdout)
        self.assertIn("remain running", stdout)

        result, stdout, stderr, _ = self.run_orchestration(
            document,
            [completed(), completed(), completed(), completed(returncode=1)],
            argv,
        )
        self.assertEqual(1, result)
        self.assertEqual("", stdout)
        self.assertIn("native runtime check", stderr)
        self.assertIn("docker compose stop mint", stderr)

        result, stdout, stderr, _ = self.run_orchestration(
            document,
            [completed(), completed(returncode=1)],
            argv,
        )
        self.assertEqual(1, result)
        self.assertNotIn("docker compose stop", stderr)

    def test_the_cold_fixture_passes_without_publishing_a_host_port(self) -> None:
        if not compose_is_available():
            self.skipTest("docker compose renders the shipped cold fixture")
        document = render_cold_fixture()
        for name in ("evidence", "mint"):
            self.assertIsNone(document["services"][name].get("ports"))  # type: ignore[index]
        argv: list[str] = []
        for compose_file in COLD_FIXTURE_FILES:
            argv.extend(["--compose-file", str(compose_file)])
        argv.extend(["--service", "evidence=evidence", "--service", "mint=mint"])
        result, stdout, stderr, run = self.run_orchestration(
            document,
            [completed(), completed(), completed(), completed()],
            argv,
        )
        self.assertEqual(0, result, stderr)
        self.assertNotIn("sensitive", stdout)
        calls = [call.args[0] for call in run.call_args_list]
        self.assertEqual("mint", calls[1][calls[1].index("--no-deps") + 1])
        self.assertEqual(["up", "--detach", "--no-deps", "mint"], calls[2][-4:])
        self.assertEqual(
            ["exec", "--no-TTY", "mint", "/usr/local/bin/mint", "healthcheck"],
            calls[3][-5:],
        )
        self.assertEqual("evidence", calls[4][calls[4].index("--no-deps") + 1])

    def test_probe_success_after_the_shared_deadline_is_rejected(self) -> None:
        complete = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        selection = self.module.ServiceSelection("mint", "mint")
        with (
            unittest.mock.patch.object(
                self.module, "run_compose", return_value=complete
            ),
            unittest.mock.patch.object(
                self.module.time, "monotonic", side_effect=[0.0, 6.0]
            ),
        ):
            with self.assertRaisesRegex(self.module.PreflightError, "ready"):
                self.module.wait_for_dependency(selection, 5.0, "{}")

    def test_only_mint_may_be_started_as_a_dependency(self) -> None:
        selections = [
            self.module.ServiceSelection("evidence", "evidence"),
            self.module.ServiceSelection("relay", "relay"),
        ]
        document = deployment(
            {"evidence": service("evidence"), "relay": service("relay")}
        )
        document["services"]["evidence"]["depends_on"] = ["relay"]  # type: ignore[index]
        with self.assertRaisesRegex(self.module.PreflightError, "only Mint"):
            self.module.native_check_plan(selections, document)

    def test_selected_dependency_cycles_fail_before_native_checks(self) -> None:
        selections = [
            self.module.ServiceSelection("evidence", "evidence"),
            self.module.ServiceSelection("mint", "mint"),
        ]
        document = deployment(
            {
                "evidence": service("evidence"),
                "mint": service("mint"),
            }
        )
        document["services"]["evidence"]["depends_on"] = ["mint"]  # type: ignore[index]
        document["services"]["mint"]["depends_on"] = ["evidence"]  # type: ignore[index]
        with self.assertRaises(self.module.PreflightError):
            self.module.native_check_plan(selections, document)

    def test_parser_rejects_duplicates_and_unsafe_service_names(self) -> None:
        with self.assertRaises(self.module.PreflightError):
            self.module.closed_json('{"services":{},"services":{}}')
        for value in ["other=service", "relay=../service", "relay=", "relay=a b"]:
            with self.assertRaises(self.module.PreflightError):
                self.module.parse_service(value)
        with self.assertRaises(self.module.argparse.ArgumentTypeError):
            self.module.bounded_seconds("4", minimum=5, maximum=600)
        self.assertEqual(
            600,
            self.module.bounded_seconds("600", minimum=5, maximum=600),
        )


if __name__ == "__main__":
    unittest.main()
