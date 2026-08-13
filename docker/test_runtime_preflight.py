#!/usr/bin/env python3
"""Focused tests for the supported Compose runtime preflight."""

from __future__ import annotations

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
        ],
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
        document = {
            "services": {
                "evidence": service("evidence"),
                "mint": service("mint"),
                "relay": service("relay"),
            }
        }
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
            "capabilities": lambda item: item.update(cap_drop=[]),
            "added capability": lambda item: item.update(cap_add=["SYS_ADMIN"]),
            "privilege escalation": lambda item: item.update(security_opt=[]),
            "entrypoint override": lambda item: item.update(entrypoint=["/bin/true"]),
            "host network": lambda item: item.update(network_mode="host"),
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
                    stdout=json.dumps({"services": {"evidence": selected}}),
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
                {"services": {"evidence": selected}},
            )
        for mode in (0o440, 0o604, "0640"):
            selected = service("evidence")
            selected["secrets"][0]["mode"] = mode  # type: ignore[index]
            with self.assertRaises(self.module.PreflightError):
                self.module.validate_service(
                    self.module.ServiceSelection("evidence", "evidence"),
                    {"services": {"evidence": selected}},
                )
        selected = service("evidence")
        selected["volumes"][1]["read_only"] = True  # type: ignore[index]
        with self.assertRaises(self.module.PreflightError):
            self.module.validate_service(
                self.module.ServiceSelection("evidence", "evidence"),
                {"services": {"evidence": selected}},
            )
        selected = service("evidence")
        selected["volumes"][1]["type"] = "tmpfs"  # type: ignore[index]
        with self.assertRaises(self.module.PreflightError):
            self.module.validate_service(
                self.module.ServiceSelection("evidence", "evidence"),
                {"services": {"evidence": selected}},
            )
        selected = service("evidence")
        selected["volumes"][1].pop("source")  # type: ignore[index]
        with self.assertRaises(self.module.PreflightError):
            self.module.validate_service(
                self.module.ServiceSelection("evidence", "evidence"),
                {"services": {"evidence": selected}},
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
                        {"services": {"evidence": selected}},
                    )

    def test_native_failure_is_value_free(self) -> None:
        document = {
            "services": {
                "evidence": service("evidence"),
                "mint": service("mint"),
                "relay": service("relay"),
            }
        }
        result, stdout, stderr, _ = self.run_main(document, native_returncode=1)
        self.assertEqual(1, result)
        self.assertEqual("", stdout)
        self.assertNotIn("sensitive", stderr)
        self.assertIn("native runtime check", stderr)

    def test_parser_rejects_duplicates_and_unsafe_service_names(self) -> None:
        with self.assertRaises(self.module.PreflightError):
            self.module.closed_json('{"services":{},"services":{}}')
        for value in ["other=service", "relay=../service", "relay=", "relay=a b"]:
            with self.assertRaises(self.module.PreflightError):
                self.module.parse_service(value)


if __name__ == "__main__":
    unittest.main()
