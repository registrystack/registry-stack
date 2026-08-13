#!/usr/bin/env python3
"""Focused tests for the supported Compose runtime preflight."""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import unittest
import unittest.mock
from pathlib import Path


SCRIPT = Path(__file__).with_name("runtime-preflight.py")
DIGEST = "a" * 64


def audit_root(product: str) -> str:
    return {
        "evidence": "/var/lib/registry-evidence",
        "mint": "/var/lib/registry-mint",
        "relay": "/var/lib/relay/audit",
    }[product]


def load_module():
    spec = importlib.util.spec_from_file_location("runtime_preflight", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def service(product: str) -> dict[str, object]:
    audit = audit_root(product)
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
        ],
    }


def deployment(services: dict[str, dict[str, object]]) -> dict[str, object]:
    return {
        "services": services,
        "volumes": {f"{product}-audit": {} for product in services},
    }


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
            "--audit-root",
            "evidence=/var/lib/registry-evidence",
            "--audit-root",
            "mint=/var/lib/registry-mint",
            "--audit-root",
            "relay=/var/lib/relay/audit",
        ]

    def run_main(
        self, document: dict[str, object], *, native_returncode: int = 0
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
            result = self.module.main(self.argv)
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
        self.assertIn("check", calls[3])
        expected_roots = [
            "/var/lib/registry-evidence",
            "/var/lib/registry-mint",
            "/var/lib/relay/audit",
        ]
        for call, expected_root in zip(calls[1:], expected_roots, strict=True):
            self.assertEqual(expected_root, call[-1])
            self.assertEqual("--require-audit-under", call[-2])
            self.assertEqual(90, run.call_args_list[calls.index(call)].kwargs["timeout"])
        for call in run.call_args_list[1:]:
            self.assertEqual(self.module.subprocess.DEVNULL, call.kwargs["stdout"])
            self.assertEqual(self.module.subprocess.DEVNULL, call.kwargs["stderr"])
            self.assertNotIn("capture_output", call.kwargs)

    def test_every_static_posture_failure_precedes_native_execution(self) -> None:
        mutations = {
            "tagged image": lambda item: item.update(
                image="ghcr.io/registrystack/evidence:v1"
            ),
            "root user": lambda item: item.update(user="0:0"),
            "writable root": lambda item: item.update(read_only=False),
            "privileged container": lambda item: item.update(privileged=True),
            "capabilities": lambda item: item.update(cap_drop=[]),
            "added capability": lambda item: item.update(cap_add=["SYS_ADMIN"]),
            "privilege escalation": lambda item: item.update(security_opt=[]),
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
                            "--audit-root",
                            "evidence=/var/lib/registry-evidence",
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
                audit_root("evidence"),
            )
        for mode in (0o440, 0o604, "0640"):
            selected = service("evidence")
            selected["secrets"][0]["mode"] = mode  # type: ignore[index]
            with self.assertRaises(self.module.PreflightError):
                self.module.validate_service(
                    self.module.ServiceSelection("evidence", "evidence"),
                    deployment({"evidence": selected}),
                    audit_root("evidence"),
                )
        selected = service("evidence")
        selected["volumes"][1]["read_only"] = True  # type: ignore[index]
        with self.assertRaises(self.module.PreflightError):
            self.module.validate_service(
                self.module.ServiceSelection("evidence", "evidence"),
                deployment({"evidence": selected}),
                audit_root("evidence"),
            )
        selected = service("evidence")
        selected["volumes"][1]["type"] = "tmpfs"  # type: ignore[index]
        with self.assertRaises(self.module.PreflightError):
            self.module.validate_service(
                self.module.ServiceSelection("evidence", "evidence"),
                deployment({"evidence": selected}),
                audit_root("evidence"),
            )
        selected = service("evidence")
        selected["volumes"][1].pop("source")  # type: ignore[index]
        with self.assertRaises(self.module.PreflightError):
            self.module.validate_service(
                self.module.ServiceSelection("evidence", "evidence"),
                deployment({"evidence": selected}),
                audit_root("evidence"),
            )

        selected = service("evidence")
        ephemeral = deployment({"evidence": selected})
        ephemeral["volumes"]["evidence-audit"] = {  # type: ignore[index]
            "driver": "local",
            "driver_opts": {"type": "tmpfs", "device": "tmpfs"},
        }
        with self.assertRaises(self.module.PreflightError):
            self.module.validate_service(
                self.module.ServiceSelection("evidence", "evidence"),
                ephemeral,
                audit_root("evidence"),
            )

    def test_audit_root_is_explicit_and_cannot_be_shadowed(self) -> None:
        selected = service("evidence")
        document = deployment({"evidence": selected})
        with self.assertRaises(self.module.PreflightError):
            self.module.validate_service(
                self.module.ServiceSelection("evidence", "evidence"),
                document,
                "/tmp/actual-audit",
            )

        selected["volumes"][1]["target"] = "/operator/audit"  # type: ignore[index]
        self.module.validate_service(
            self.module.ServiceSelection("evidence", "evidence"),
            document,
            "/operator/audit",
        )

        for shadow in [
            {"tmpfs": ["/operator/audit/active:size=64m"]},
            {
                "volumes": [
                    {
                        "type": "tmpfs",
                        "target": "/operator/audit/active",
                        "read_only": False,
                    }
                ]
            },
        ]:
            with self.subTest(shadow=shadow):
                shadowed = service("evidence")
                shadowed["volumes"][1]["target"] = "/operator/audit"  # type: ignore[index]
                for key, values in shadow.items():
                    if key == "volumes":
                        shadowed["volumes"].extend(values)  # type: ignore[union-attr]
                    else:
                        shadowed[key] = values
                with self.assertRaises(self.module.PreflightError):
                    self.module.validate_service(
                        self.module.ServiceSelection("evidence", "evidence"),
                        deployment({"evidence": shadowed}),
                        "/operator/audit",
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
                        audit_root("evidence"),
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
                    audit_root(product),
                )
                selected["environment"] = {name: "/tmp/alternate.yaml"}
                with self.assertRaises(self.module.PreflightError):
                    self.module.validate_service(
                        self.module.ServiceSelection(product, product),
                        deployment({product: selected}),
                        audit_root(product),
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

    def test_decoy_persistent_mount_cannot_validate_an_ephemeral_real_sink(self) -> None:
        selected = service("evidence")
        selected["tmpfs"] = ["/runtime-audit:size=64m"]
        document = deployment({"evidence": selected})
        render = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(document), stderr=""
        )
        native = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="configured path", stderr="secret"
        )
        run = unittest.mock.Mock(side_effect=[render, native])
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            unittest.mock.patch.object(self.module.subprocess, "run", run),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            result = self.module.main(
                [
                    "--compose-file",
                    "compose.yaml",
                    "--service",
                    "evidence=evidence",
                    "--audit-root",
                    "evidence=/var/lib/registry-evidence",
                ]
            )

        self.assertEqual(1, result)
        self.assertEqual("", stdout.getvalue())
        self.assertNotIn("configured path", stderr.getvalue())
        self.assertNotIn("secret", stderr.getvalue())
        native_command = run.call_args_list[1].args[0]
        self.assertEqual(
            ["--require-audit-under", "/var/lib/registry-evidence"],
            native_command[-2:],
        )

    def test_cold_mint_dependency_is_checked_started_probed_then_consumed(self) -> None:
        document = deployment(
            {
                "evidence": service("evidence"),
                "mint": service("mint"),
                "unrelated": {"image": "example.invalid/unrelated:latest"},
            }
        )
        complete = lambda returncode=0: subprocess.CompletedProcess(  # noqa: E731
            args=[], returncode=returncode, stdout="sensitive", stderr="sensitive"
        )
        render = complete()
        render.stdout = json.dumps(document)
        run = unittest.mock.Mock(
            side_effect=[
                render,
                complete(),
                complete(),
                complete(1),
                complete(),
                complete(),
            ]
        )
        argv = [
            "--compose-file",
            "compose.yaml",
            "--service",
            "evidence=evidence",
            "--service",
            "mint=mint",
            "--audit-root",
            "evidence=/var/lib/registry-evidence",
            "--audit-root",
            "mint=/var/lib/registry-mint",
            "--dependency-service",
            "mint",
            "--native-check-timeout-seconds",
            "600",
            "--dependency-timeout-seconds",
            "30",
        ]
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            unittest.mock.patch.object(self.module.subprocess, "run", run),
            unittest.mock.patch.object(self.module.time, "sleep"),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            result = self.module.main(argv)

        self.assertEqual(0, result, stderr.getvalue())
        calls = [call.args[0] for call in run.call_args_list]
        self.assertEqual("mint", calls[1][calls[1].index("--no-deps") + 1])
        self.assertEqual(
            ["up", "--detach", "--no-deps", "mint"], calls[2][-4:]
        )
        self.assertEqual(
            ["exec", "--no-TTY", "mint", "/usr/local/bin/mint", "healthcheck"],
            calls[3][-5:],
        )
        self.assertEqual(calls[3], calls[4])
        self.assertEqual("evidence", calls[5][calls[5].index("--no-deps") + 1])
        self.assertEqual(600, run.call_args_list[1].kwargs["timeout"])
        self.assertEqual(600, run.call_args_list[5].kwargs["timeout"])
        self.assertFalse(
            any(command in call for call in calls for command in ("stop", "down"))
        )
        self.assertFalse(any("unrelated" in call for call in calls))
        for call in run.call_args_list[1:]:
            self.assertEqual(self.module.subprocess.DEVNULL, call.kwargs["stdout"])
            self.assertEqual(self.module.subprocess.DEVNULL, call.kwargs["stderr"])

    def test_unhealthy_dependency_fails_without_running_the_dependent_check(self) -> None:
        document = deployment(
            {"evidence": service("evidence"), "mint": service("mint")}
        )
        render = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(document), stderr=""
        )
        complete = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="sensitive", stderr="sensitive"
        )
        failed = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="sensitive", stderr="sensitive"
        )
        run = unittest.mock.Mock(side_effect=[render, complete, complete, failed])
        argv = [
            "--compose-file",
            "compose.yaml",
            "--service",
            "evidence=evidence",
            "--service",
            "mint=mint",
            "--audit-root",
            "evidence=/var/lib/registry-evidence",
            "--audit-root",
            "mint=/var/lib/registry-mint",
            "--dependency-service",
            "mint",
            "--dependency-timeout-seconds",
            "5",
        ]
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            unittest.mock.patch.object(self.module.subprocess, "run", run),
            unittest.mock.patch.object(
                self.module.time, "monotonic", side_effect=[0.0, 0.0, 6.0]
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            result = self.module.main(argv)

        self.assertEqual(1, result)
        self.assertEqual("", stdout.getvalue())
        self.assertNotIn("sensitive", stderr.getvalue())
        self.assertIn("did not become ready", stderr.getvalue())
        self.assertEqual(4, run.call_count)
        self.assertFalse(
            any("evidence" in call.args[0] and "run" in call.args[0] for call in run.call_args_list)
        )

    def test_dependency_selection_order_is_operator_declared(self) -> None:
        document = deployment(
            {
                "evidence": service("evidence"),
                "mint": service("mint"),
                "relay": service("relay"),
            }
        )
        render = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(document), stderr=""
        )
        complete = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        run = unittest.mock.Mock(side_effect=[render, *([complete] * 7)])
        argv = [
            "--compose-file",
            "compose.yaml",
            "--service",
            "evidence=evidence",
            "--service",
            "mint=mint",
            "--service",
            "relay=relay",
            "--audit-root",
            "evidence=/var/lib/registry-evidence",
            "--audit-root",
            "mint=/var/lib/registry-mint",
            "--audit-root",
            "relay=/var/lib/relay/audit",
            "--dependency-service",
            "relay",
            "--dependency-service",
            "mint",
        ]
        with unittest.mock.patch.object(self.module.subprocess, "run", run):
            result = self.module.main(argv)

        self.assertEqual(0, result)
        calls = [call.args[0] for call in run.call_args_list]
        selected_services = []
        for call in calls[1:]:
            if "run" in call:
                selected_services.append(("check", call[call.index("--no-deps") + 1]))
            elif "up" in call:
                selected_services.append(("start", call[-1]))
            elif "exec" in call:
                selected_services.append(("probe", call[call.index("--no-TTY") + 1]))
        self.assertEqual(
            [
                ("check", "relay"),
                ("start", "relay"),
                ("probe", "relay"),
                ("check", "mint"),
                ("start", "mint"),
                ("probe", "mint"),
                ("check", "evidence"),
            ],
            selected_services,
        )

    def test_parser_rejects_duplicates_and_unsafe_service_names(self) -> None:
        with self.assertRaises(self.module.PreflightError):
            self.module.closed_json('{"services":{},"services":{}}')
        for value in ["other=service", "relay=../service", "relay=", "relay=a b"]:
            with self.assertRaises(self.module.PreflightError):
                self.module.parse_service(value)
        for value in [
            "relay=relative",
            "relay=/",
            "relay=/var/lib/../tmp",
            "../relay=/var/lib/relay",
        ]:
            with self.assertRaises(self.module.PreflightError):
                self.module.parse_audit_root(value)
        with self.assertRaises(argparse.ArgumentTypeError):
            self.module.bounded_seconds("29", minimum=30, maximum=86_400)
        self.assertEqual(
            86_400,
            self.module.bounded_seconds("86400", minimum=30, maximum=86_400),
        )


if __name__ == "__main__":
    unittest.main()
