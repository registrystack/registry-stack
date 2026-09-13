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


def emitting(effects: list[object]):
    """Fake `subprocess.run` that writes each effect's stderr to its capture file.

    The preflight captures a native check's stderr to classify the failure, so
    the fake has to produce that stream for the value-free pins to mean anything.
    """
    remaining = iter(effects)

    def run(*args: object, **kwargs: object) -> object:
        effect = next(remaining)
        if isinstance(effect, BaseException):
            raise effect
        sink = kwargs.get("stderr")
        if hasattr(sink, "write") and effect.stderr:
            sink.write(effect.stderr.encode("utf-8"))
        return effect

    return run


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
            "relay=relay",
        ]

    def run_main(
        self,
        document: dict[str, object],
        *,
        native_returncode: int = 0,
        native_stderr: str = "sensitive",
        argv: list[str] | None = None,
    ) -> tuple[int, str, str, unittest.mock.Mock]:
        render = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(document), stderr=""
        )
        native = subprocess.CompletedProcess(
            args=[],
            returncode=native_returncode,
            stdout="sensitive",
            stderr=native_stderr,
        )
        run = unittest.mock.Mock(
            side_effect=emitting([render, native, native])
        )
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            unittest.mock.patch.object(self.module.subprocess, "run", run),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            result = self.module.main(self.argv if argv is None else argv)
        return result, stdout.getvalue(), stderr.getvalue(), run

    def test_all_products_use_native_checks_after_complete_static_preflight(
        self,
    ) -> None:
        document = deployment(
            {
                "evidence": service("evidence"),
                "relay": service("relay"),
            }
        )
        result, stdout, stderr, run = self.run_main(document)
        self.assertEqual(0, result, stderr)
        self.assertEqual(
            "runtime preflight passed for 2 service(s)", stdout.splitlines()[0]
        )
        self.assertEqual(3, run.call_count)
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
        self.assertEqual("check", calls[2][-5])
        self.assertEqual("evidence", calls[1][calls[1].index("--no-deps") + 1])
        self.assertEqual("relay", calls[2][calls[2].index("--no-deps") + 1])
        for call in run.call_args_list[1:]:
            self.assertIn("--no-deps", call.args[0])
            self.assertEqual(["docker", "compose", "--file", "-"], call.args[0][:4])
            self.assertEqual(self.module.subprocess.DEVNULL, call.kwargs["stdout"])
            self.assertTrue(hasattr(call.kwargs["stderr"], "write"))
            self.assertNotIn("capture_output", call.kwargs)
            self.assertEqual(
                self.module.DEFAULT_NATIVE_CHECK_TIMEOUT_SECONDS,
                call.kwargs["timeout"],
            )
            self.assertEqual(document, json.loads(call.kwargs["input"]))

    def test_every_native_check_asserts_the_validated_audit_prefix(self) -> None:
        # The adapter proves the mount is durable container storage and the
        # product proves its own configured sink resolves inside it. The root
        # handed to the product is the exact mount target already validated, so
        # neither side has to read the other's configuration.
        document = deployment(
            {
                "evidence": service("evidence"),
                "relay": service("relay"),
            }
        )
        result, _, stderr, run = self.run_main(document)
        self.assertEqual(0, result, stderr)
        calls = [call.args[0] for call in run.call_args_list]
        for index, product in enumerate(("evidence", "relay"), start=1):
            with self.subTest(product=product):
                prefix = self.module.AUDIT_PREFIXES[product]
                self.assertEqual(
                    ["--require-audit-under", prefix], calls[index][-2:]
                )
                persistent = [
                    volume
                    for volume in document["services"][product]["volumes"]
                    if volume["type"] in ("volume", "bind")
                    and not volume["read_only"]
                ]
                self.assertEqual([prefix], [volume["target"] for volume in persistent])

    def test_a_decoy_persistent_volume_cannot_rescue_an_ephemeral_sink(self) -> None:
        # The whole deployment posture is correct: a durable named volume is
        # mounted writable at the conventional audit prefix. Only the product
        # can see that its configured sink resolves somewhere ephemeral instead,
        # and it refuses the containment assertion the adapter passed in.
        document = deployment({"relay": service("relay")})
        argv = [
            "--compose-file",
            "compose.yaml",
            "--env-file",
            "operator.env",
            "--service",
            "relay=relay",
        ]
        result, stdout, stderr, run = self.run_main(
            document, native_returncode=1, argv=argv
        )

        self.assertEqual(1, result)
        self.assertEqual("", stdout)
        self.assertIn("native runtime check", stderr)
        self.assertNotIn("sensitive", stderr)
        calls = [call.args[0] for call in run.call_args_list]
        self.assertEqual(
            ["--require-audit-under", self.module.AUDIT_PREFIXES["relay"]],
            calls[1][-2:],
        )

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
            "shell healthcheck": lambda item: item.update(
                healthcheck={"test": ["CMD-SHELL", "curl -fsS http://localhost/health"]}
            ),
            "string healthcheck": lambda item: item.update(
                healthcheck={"test": "curl -fsS http://localhost/health"}
            ),
            "foreign healthcheck command": lambda item: item.update(
                healthcheck={"test": ["CMD", "/usr/bin/curl", "-fsS", "http://x"]}
            ),
            "healthcheck without a command": lambda item: item.update(
                healthcheck={"test": ["CMD"]}
            ),
            "invalid healthcheck": lambda item: item.update(healthcheck=["CMD"]),
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
                reported = io.StringIO()
                with (
                    unittest.mock.patch.object(self.module.subprocess, "run", run),
                    contextlib.redirect_stderr(reported),
                ):
                    result = self.module.main(
                        [
                            "--compose-file",
                            "compose.yaml",
                            "--service",
                            "evidence=evidence",
                        ]
                    )
                self.assertEqual(1, result)
                self.assertEqual(
                    1, len(reported.getvalue().splitlines()), reported.getvalue()
                )
                self.assertTrue(
                    reported.getvalue().startswith("runtime preflight failed: "),
                    reported.getvalue(),
                )
                run.assert_called_once()

    def test_a_healthcheck_may_only_run_the_official_product_command(self) -> None:
        # Docker runs a healthcheck as the service identity on its own
        # schedule, so it is a command lane into the container. The official
        # images declare none, and the preflight owns readiness.
        argv = [
            "--compose-file",
            "compose.yaml",
            "--service",
            "evidence=evidence",
        ]
        for accepted in (
            None,
            {"disable": True},
            {"test": ["NONE"]},
            {"test": ["CMD", "/usr/local/bin/evidence", "check"], "interval": "30s"},
        ):
            with self.subTest(healthcheck=accepted):
                selected = service("evidence")
                if accepted is not None:
                    selected["healthcheck"] = accepted
                result, _, stderr, _ = self.run_main(
                    deployment({"evidence": selected}), argv=argv
                )
                self.assertEqual(0, result, stderr)

    def test_an_audit_root_that_proves_nothing_is_refused(self) -> None:
        # Containment proves where a configured sink resolves, so a root every
        # path resolves under asserts nothing. Such a root is refused before
        # any native check receives it, rather than passed on as a proof that
        # cannot fail.
        document = deployment({"relay": service("relay")})
        for root in ("/", "", "var/lib/relay", "/var/lib/relay/../audit"):
            with self.subTest(root=root):
                with unittest.mock.patch.dict(
                    self.module.AUDIT_PREFIXES, {"relay": root}
                ):
                    with self.assertRaises(self.module.PreflightError) as raised:
                        self.module.validate_service(
                            self.module.ServiceSelection("relay", "relay"), document
                        )
                self.assertIn("audit root", str(raised.exception))

    def test_a_passing_run_states_that_persistence_is_not_proven(self) -> None:
        document = deployment({"relay": service("relay")})
        result, stdout, stderr, _ = self.run_main(
            document,
            argv=["--compose-file", "compose.yaml", "--service", "relay=relay"],
        )
        self.assertEqual(0, result, stderr)
        self.assertIn("not proven", stdout)

    def test_compose_dependencies_are_not_started_by_the_preflight(self) -> None:
        document = deployment({"evidence": service("evidence")})
        document["services"]["proxy"] = {"image": "example.invalid/proxy:latest"}
        document["services"]["evidence"]["depends_on"] = ["proxy"]  # type: ignore[index]
        result, stdout, stderr, run = self.run_main(
            document,
            argv=["--compose-file", "compose.yaml", "--service", "evidence=evidence"],
        )
        self.assertEqual(0, result, stderr)
        self.assertEqual(2, run.call_count)
        native = run.call_args_list[1].args[0]
        self.assertEqual("evidence", native[native.index("--no-deps") + 1])
        self.assertNotIn("up", native)
        self.assertNotIn("proxy", native)

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
        for product in ("evidence", "relay"):
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
        # The preflight reads the failing check's stderr to classify it and
        # holds the operator's rendered configuration. It prints neither.
        document = deployment(
            {
                "evidence": service("evidence"),
                "relay": service("relay"),
            }
        )
        document["services"]["evidence"]["environment"] = {  # type: ignore[index]
            "EVIDENCE_MARKER": "rendered-value"
        }
        result, stdout, stderr, _ = self.run_main(
            document,
            native_returncode=1,
            native_stderr="sensitive child stderr naming /srv/operator/audit",
        )
        self.assertEqual(1, result)
        self.assertEqual("", stdout)
        self.assertNotIn("sensitive", stderr)
        self.assertNotIn("/srv/operator/audit", stderr)
        self.assertNotIn("rendered-value", stderr)
        self.assertIn("native runtime check", stderr)

    def test_an_image_without_the_containment_flag_is_named_as_the_cause(self) -> None:
        # An image built before the flag existed cannot make the persistent
        # audit root assertion. The preflight stays closed and says which
        # service needs a newer image instead of reporting a generic failure.
        document = deployment({"relay": service("relay")})
        result, stdout, stderr, _ = self.run_main(
            document,
            native_returncode=2,
            native_stderr=(
                "error: unexpected argument '--require-audit-under' found\n"
                "\nUsage: relay check --runtime <RUNTIME>\n"
            ),
            argv=[
                "--compose-file",
                "compose.yaml",
                "--env-file",
                "operator.env",
                "--service",
                "relay=relay",
            ],
        )
        self.assertEqual(1, result)
        self.assertEqual("", stdout)
        self.assertIn("service relay", stderr)
        self.assertIn("--require-audit-under", stderr)
        self.assertIn("does not support", stderr)
        self.assertIn("requires an image", stderr)
        for suggestion in ("disable", "omit", "without", "skip", "Usage"):
            self.assertNotIn(suggestion, stderr)

    def test_a_chatty_native_check_still_fails_value_free(self) -> None:
        # A child that writes far more than the captured bound is read without
        # error and reported with the same value-free message as any other
        # failing check.
        noisy = "".join(f"line {index:04d} " + "x" * 200 + "\n" for index in range(500))
        document = deployment({"relay": service("relay")})
        result, stdout, stderr, _ = self.run_main(
            document,
            native_returncode=1,
            native_stderr=noisy,
            argv=[
                "--compose-file",
                "compose.yaml",
                "--service",
                "relay=relay",
            ],
        )
        self.assertEqual(1, result)
        self.assertEqual("", stdout)
        self.assertEqual(
            "runtime preflight failed: relay service relay failed its native "
            "runtime check\n",
            stderr,
        )

    def test_a_child_that_outwrites_the_cap_is_captured_without_blocking(
        self,
    ) -> None:
        # A pipe holds about 64 KiB, so a child that keeps writing blocks once
        # it fills unless something reads the pipe while the child runs. The
        # capture keeps the cap and discards the rest, so this child writes a
        # thousand times the cap and still exits on its own.
        cap = self.module.MAXIMUM_NATIVE_CHECK_STDERR_BYTES
        program = (
            "import sys\n"
            "sys.stderr.write("
            "\"error: unexpected argument '--require-audit-under' found\\n\")\n"
            "chunk = 'x' * 1024\n"
            "for _ in range(4096):\n"
            "    sys.stderr.write(chunk)\n"
        )
        with self.module.BoundedStderr() as sink:
            result = subprocess.run(
                [sys.executable, "-c", program],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=sink,
                timeout=120,
            )

        self.assertEqual(0, result.returncode)
        captured = sink.captured()
        self.assertLessEqual(len(captured), cap)
        self.assertTrue(self.module.rejects_audit_containment_flag(captured))

    def test_the_captured_stderr_is_bounded_and_still_classifies(self) -> None:
        # An argument parser refuses before the command it fronts does anything,
        # so its message is the first thing on the stream. A wrapper entrypoint
        # that keeps printing afterwards must not push it out of the capture,
        # and the classification searches everything the capture kept.
        cap = self.module.MAXIMUM_NATIVE_CHECK_STDERR_BYTES
        with self.module.BoundedStderr() as sink:
            sink.write(b"error: unexpected argument '--require-audit-under' found\n")
            sink.write(b"x" * (cap * 4))
        captured = sink.captured()
        self.assertLessEqual(len(captured), cap)
        self.assertTrue(self.module.rejects_audit_containment_flag(captured))

    def test_native_check_deadline_is_bounded_and_operator_configurable(self) -> None:
        document = deployment(
            {
                "evidence": service("evidence"),
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

    def test_parser_rejects_duplicates_and_unsafe_service_names(self) -> None:
        with self.assertRaises(self.module.PreflightError):
            self.module.closed_json('{"services":{},"services":{}}')
        for value in [
            "mint=service",
            "other=service",
            "relay=../service",
            "relay=",
            "relay=a b",
        ]:
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
