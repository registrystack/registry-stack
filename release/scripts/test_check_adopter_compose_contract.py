#!/usr/bin/env python3
"""Focused tests for the adopter-runtime Compose conformance checker."""

from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check_adopter_compose_contract.py")
SPEC = importlib.util.spec_from_file_location("adopter_compose_contract", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)
SYNTHETIC_ROOT = Path("/fixture")
SYNTHETIC_PACKAGE_ROOT = SYNTHETIC_ROOT / "package"


def expected_images() -> dict[str, str]:
    return {
        "registry-relay-public": "example.invalid/relay@sha256:" + "a" * 64,
        "registry-relay-consultation": ("example.invalid/relay@sha256:" + "a" * 64),
        "registry-notary": "example.invalid/notary@sha256:" + "b" * 64,
        "registry-postgres": "example.invalid/postgres@sha256:" + "c" * 64,
    }


def dependency_model(dependencies: dict[str, str]) -> dict[str, dict]:
    return {
        name: {"condition": condition, "required": True}
        for name, condition in dependencies.items()
    }


def volume(source: str, target: str, *, read_only: bool = False) -> dict:
    result = {
        "source": source,
        "target": target,
        "type": "volume",
        "volume": {},
    }
    if read_only:
        result["read_only"] = True
    return result


def bind(kind: str, lane: str, target: str) -> dict:
    return {
        "type": "bind",
        "source": f"/fixture/package/generated/{kind}/{lane}",
        "target": target,
        "read_only": True,
        "bind": {"create_host_path": False},
    }


def product_hardening() -> dict:
    return {
        "platform": "linux/amd64",
        "user": "65532:65532",
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "tmpfs": ["/tmp"],
        "logging": copy.deepcopy(CHECKER.BOUNDED_LOCAL_LOGGING),
    }


def postgresql_hardening() -> dict:
    return {
        "platform": "linux/amd64",
        "user": "999:999",
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "tmpfs": [
            "/tmp",
            "/var/run/postgresql:uid=999,gid=999,mode=0750",
        ],
        "logging": copy.deepcopy(CHECKER.BOUNDED_LOCAL_LOGGING),
    }


def healthcheck() -> dict:
    return {
        "test": ["CMD", "/conformance-only-healthcheck"],
        "interval": "30s",
        "timeout": "5s",
        "retries": 3,
    }


def product_mounts(lane: str, action: str) -> list[dict]:
    result = [
        bind("bundles", lane, "/run/registry/bundle"),
        bind("anchors", lane, "/run/registry/anchor"),
    ]
    if action != "prepare":
        result.append(
            volume(
                f"registry-{lane}-state",
                "/var/lib/registry/state",
                read_only=action in {"serve", "preview", "verify"},
            )
        )
    if action not in {"preview", "verify"}:
        result.append(volume(f"registry-{lane}-audit", "/var/lib/registry/audit"))
    secret_volume = f"registry-operator-files-{lane}-{action}"
    if secret_volume in CHECKER.STAGED_SECRET_VOLUMES:
        result.append(volume(secret_volume, "/run/secrets", read_only=True))
    return result


def stager(name: str, *, action: bool = False) -> dict:
    specs = CHECKER.ACTION_STAGER_SPECS if action else CHECKER.STAGER_SPECS
    spec = specs[name]
    return {
        "image": expected_images()["registry-postgres"],
        "platform": "linux/amd64",
        "entrypoint": ["/bin/sh", "-ceu"],
        "command": CHECKER.STAGER_COMMAND,
        "user": "0:0",
        "read_only": True,
        "cap_drop": ["ALL"],
        "cap_add": ["CHOWN", "DAC_READ_SEARCH"],
        "security_opt": ["no-new-privileges:true"],
        "tmpfs": ["/tmp"],
        "network_mode": "none",
        "restart": "no",
        "volumes": [
            volume(
                source,
                f"/registryctl-stage/output/{action}",
            )
            for action, source in spec["outputs"].items()
        ],
        "secrets": [
            {
                "source": source,
                "target": source.removeprefix("registry-"),
            }
            for source in sorted(spec["secrets"])
        ],
    }


def ordinary_model() -> dict:
    images = expected_images()
    services = {name: stager(name) for name in CHECKER.STAGER_SERVICES}
    services["registry-postgres"] = {
        **postgresql_hardening(),
        "image": images["registry-postgres"],
        "command": CHECKER.ORDINARY_COMMANDS["registry-postgres"],
        "restart": "unless-stopped",
        "networks": {CHECKER.NETWORK_RUNTIME: {}},
        "depends_on": dependency_model(
            CHECKER.ORDINARY_DEPENDENCIES["registry-postgres"]
        ),
        "entrypoint": ["/bin/sh", "data directory is empty"],
        "env_file": [
            "/fixture/package/generated/postgresql-server.env",
        ],
        "healthcheck": healthcheck(),
        "volumes": [
            volume(
                "registry-postgresql-data",
                "/var/lib/postgresql/data",
            ),
            volume(
                "registry-operator-files-postgresql-serve",
                "/run/secrets",
                read_only=True,
            ),
        ],
    }
    for name, lane in (
        ("registry-relay-public", "relay-public"),
        ("registry-relay-consultation", "relay-consultation"),
        ("registry-notary", "notary"),
    ):
        services[name] = {
            **product_hardening(),
            "image": images[name],
            "command": CHECKER.ORDINARY_COMMANDS[name],
            "restart": "unless-stopped",
            "networks": {CHECKER.NETWORK_RUNTIME: {}},
            "depends_on": dependency_model(CHECKER.ORDINARY_DEPENDENCIES[name]),
            "env_file": [
                (f"/fixture/package/operator/secrets/{CHECKER.LANE_ENVIRONMENTS[name]}")
            ],
            "healthcheck": healthcheck(),
            "volumes": product_mounts(lane, "serve"),
        }
    services["registry-relay-public"]["ports"] = [
        {
            "host_ip": "127.0.0.1",
            "mode": "ingress",
            "protocol": "tcp",
            "published": "4242",
            "target": 8080,
        }
    ]
    services["registry-notary"]["ports"] = [
        {
            "host_ip": "127.0.0.1",
            "mode": "ingress",
            "protocol": "tcp",
            "published": "4255",
            "target": 8081,
        }
    ]
    return {
        "name": CHECKER.PROJECT_NAME,
        "services": services,
        "networks": {
            CHECKER.NETWORK_RUNTIME: {
                "name": f"{CHECKER.PROJECT_NAME}_{CHECKER.NETWORK_RUNTIME}"
            }
        },
        "volumes": {
            name: {"name": f"{CHECKER.PROJECT_NAME}_{name}"}
            for name in CHECKER.EXPECTED_VOLUMES
        },
        "secrets": {
            f"registry-{name}": {
                "file": f"/fixture/package/operator/secrets/{name}",
                "name": f"{CHECKER.PROJECT_NAME}_registry-{name}",
            }
            for name in CHECKER.OPERATOR_SECRET_FILES
        },
    }


def initialization_model(ordinary: dict) -> dict:
    initialized = copy.deepcopy(ordinary)
    project_name = initialized["name"]
    for name in CHECKER.ACTION_STAGER_SERVICES:
        initialized["services"][name] = stager(name, action=True)
    for name in CHECKER.INITIALIZATION_STAGED_SECRET_VOLUMES:
        initialized["volumes"][name] = {"name": f"{project_name}_{name}"}
    initialized["services"]["registry-postgres"]["entrypoint"] = list(
        CHECKER.POSTGRESQL_INITIALIZATION_ENTRYPOINT
    )
    initialized["services"]["registry-postgres-bootstrap"] = {
        **postgresql_hardening(),
        "image": expected_images()["registry-postgres"],
        "command": CHECKER.INITIALIZATION_COMMANDS["registry-postgres-bootstrap"],
        "restart": "no",
        "networks": {CHECKER.NETWORK_RUNTIME: {}},
        "depends_on": dependency_model(
            {
                "registry-postgres": "service_healthy",
                "registry-postgresql-actions-stage-secrets": (
                    "service_completed_successfully"
                ),
            }
        ),
        "env_file": [
            "/fixture/package/generated/postgresql-server.env",
            ("/fixture/package/operator/secrets/postgresql-bootstrap-environment"),
        ],
        "volumes": [
            volume(
                "registry-operator-files-postgresql-bootstrap",
                "/run/secrets",
                read_only=True,
            )
        ],
    }
    for name, (ordinary_name, lane, action) in CHECKER.INITIALIZATION_METADATA.items():
        service = {
            **product_hardening(),
            "image": expected_images()[ordinary_name],
            "command": CHECKER.INITIALIZATION_COMMANDS[name],
            "restart": "no",
            "volumes": product_mounts(lane, action),
        }
        requires_postgresql = (
            lane == "relay-consultation"
            and action in {"prepare", "initialize"}
        ) or (lane == "notary" and action == "prepare")
        if requires_postgresql:
            service["networks"] = {CHECKER.NETWORK_RUNTIME: {}}
        else:
            service["network_mode"] = "none"
        if action in {"prepare", "initialize", "accept"}:
            service["env_file"] = [
                (
                    "/fixture/package/operator/secrets/"
                    f"{CHECKER.LANE_ENVIRONMENTS[ordinary_name]}"
                )
            ]
        dependencies = CHECKER.INITIALIZATION_DEPENDENCIES[name]
        if dependencies:
            service["depends_on"] = dependency_model(dependencies)
        initialized["services"][name] = service
    return initialized


def assert_ordinary(model: dict) -> None:
    CHECKER.assert_ordinary_model(
        model,
        expected_images(),
        SYNTHETIC_ROOT,
    )


def assert_initialization(model: dict, ordinary: dict) -> None:
    CHECKER.assert_initialization_model(
        model,
        ordinary,
        expected_images(),
        package_root=SYNTHETIC_PACKAGE_ROOT,
    )


class AdopterComposeContractTests(unittest.TestCase):
    def test_ordinary_model_accepts_closed_package(self) -> None:
        assert_ordinary(ordinary_model())

    def test_ordinary_model_rejects_namespace_holder(self) -> None:
        model = ordinary_model()
        model["services"]["registry-private-namespace"] = {}
        with self.assertRaisesRegex(
            CHECKER.ContractError,
            "four workloads and four lane stagers",
        ):
            assert_ordinary(model)

    def test_ordinary_model_excludes_action_stagers_and_scratch_volumes(self) -> None:
        model = ordinary_model()
        self.assertTrue(CHECKER.ACTION_STAGER_SERVICES.isdisjoint(model["services"]))
        self.assertTrue(
            CHECKER.INITIALIZATION_STAGED_SECRET_VOLUMES.isdisjoint(model["volumes"])
        )

        action_stager = "registry-relay-consultation-actions-stage-secrets"
        model["services"][action_stager] = stager(action_stager, action=True)
        with self.assertRaisesRegex(
            CHECKER.ContractError,
            "four workloads and four lane stagers",
        ):
            assert_ordinary(model)

    def test_ordinary_model_requires_each_closed_runtime_field(self) -> None:
        mutations = {
            "workload-image": lambda model: model["services"]["registry-notary"].pop(
                "image"
            ),
            "workload-command": lambda model: model["services"]["registry-notary"].pop(
                "command"
            ),
            "hardening": lambda model: model["services"]["registry-relay-public"].pop(
                "read_only"
            ),
            "publication": lambda model: model["services"]["registry-notary"].pop(
                "ports"
            ),
            "unauthorized-publication": lambda model: model["services"][
                "registry-relay-consultation"
            ].update(
                {
                    "ports": [
                        {
                            "host_ip": "127.0.0.1",
                            "published": "9999",
                            "target": 9999,
                        }
                    ]
                }
            ),
            "network": lambda model: model["services"][
                "registry-relay-consultation"
            ].pop("networks"),
            "network-policy": lambda model: model["networks"][
                CHECKER.NETWORK_RUNTIME
            ].update({"internal": True}),
            "dependency": lambda model: model["services"][
                "registry-relay-consultation"
            ]["depends_on"].pop("registry-postgres"),
            "privileged": lambda model: model["services"][
                "registry-relay-public"
            ].update({"privileged": True}),
            "environment": lambda model: model["services"]["registry-relay-public"].pop(
                "env_file"
            ),
            "bundle": lambda model: model["services"]["registry-relay-public"][
                "volumes"
            ].pop(0),
            "anchor": lambda model: model["services"]["registry-relay-public"][
                "volumes"
            ].pop(1),
            "state": lambda model: model["services"]["registry-notary"]["volumes"].pop(
                2
            ),
            "audit": lambda model: model["services"]["registry-notary"]["volumes"].pop(
                3
            ),
            "staged-secret": lambda model: model["services"]["registry-postgres"][
                "volumes"
            ].pop(),
            "volume-inventory": lambda model: model["volumes"].pop(
                "registry-notary-state"
            ),
            "operator-secret": lambda model: model["secrets"].pop(
                "registry-notary-signing-key"
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                model = ordinary_model()
                mutate(model)
                with self.assertRaises(CHECKER.ContractError):
                    assert_ordinary(model)

    def test_ordinary_rejects_removal_of_each_workload_protection(self) -> None:
        hardening_fields = (
            "user",
            "read_only",
            "cap_drop",
            "security_opt",
            "tmpfs",
            "healthcheck",
            "logging",
        )
        for service_name in CHECKER.WORKLOAD_SERVICES:
            fields = hardening_fields + (
                ("entrypoint",) if service_name == "registry-postgres" else ()
            )
            for field in fields:
                with self.subTest(service=service_name, protection=field):
                    model = ordinary_model()
                    model["services"][service_name].pop(field)
                    with self.assertRaises(CHECKER.ContractError):
                        assert_ordinary(model)

    def test_ordinary_requires_every_command_restart_and_dependency(self) -> None:
        for service_name in CHECKER.WORKLOAD_SERVICES:
            for field in ("command", "restart"):
                with self.subTest(service=service_name, field=field):
                    model = ordinary_model()
                    model["services"][service_name].pop(field)
                    with self.assertRaises(CHECKER.ContractError):
                        assert_ordinary(model)
            for dependency in CHECKER.ORDINARY_DEPENDENCIES[service_name]:
                with self.subTest(service=service_name, dependency=dependency):
                    model = ordinary_model()
                    model["services"][service_name]["depends_on"].pop(dependency)
                    with self.assertRaises(CHECKER.ContractError):
                        assert_ordinary(model)

    def test_ordinary_requires_every_protected_workload_mount(self) -> None:
        baseline = ordinary_model()
        for service_name in CHECKER.WORKLOAD_SERVICES:
            targets = [
                mount["target"]
                for mount in baseline["services"][service_name]["volumes"]
            ]
            for target in targets:
                with self.subTest(service=service_name, target=target):
                    model = ordinary_model()
                    service = model["services"][service_name]
                    service["volumes"] = [
                        mount
                        for mount in service["volumes"]
                        if mount["target"] != target
                    ]
                    with self.assertRaises(CHECKER.ContractError):
                        assert_ordinary(model)
                with self.subTest(service=service_name, target=target, mode="changed"):
                    model = ordinary_model()
                    mount = next(
                        mount
                        for mount in model["services"][service_name]["volumes"]
                        if mount["target"] == target
                    )
                    if mount.get("read_only") is True:
                        mount.pop("read_only")
                    else:
                        mount["read_only"] = True
                    with self.assertRaises(CHECKER.ContractError):
                        assert_ordinary(model)

    def test_ordinary_publications_are_exact_and_private_services_stay_private(
        self,
    ) -> None:
        for service_name in ("registry-relay-public", "registry-notary"):
            with self.subTest(service=service_name, mutation="missing"):
                model = ordinary_model()
                model["services"][service_name].pop("ports")
                with self.assertRaises(CHECKER.ContractError):
                    assert_ordinary(model)
            with self.subTest(service=service_name, mutation="non-loopback"):
                model = ordinary_model()
                model["services"][service_name]["ports"][0]["host_ip"] = "0.0.0.0"
                with self.assertRaises(CHECKER.ContractError):
                    assert_ordinary(model)
        for service_name in CHECKER.ORDINARY_SERVICES - {
            "registry-relay-public",
            "registry-notary",
        }:
            with self.subTest(service=service_name, mutation="published"):
                model = ordinary_model()
                model["services"][service_name]["ports"] = [
                    {
                        "host_ip": "127.0.0.1",
                        "mode": "ingress",
                        "protocol": "tcp",
                        "published": "9999",
                        "target": 9999,
                    }
                ]
                with self.assertRaises(CHECKER.ContractError):
                    assert_ordinary(model)

    def test_product_inputs_must_be_owned_by_the_exact_lane_and_package(
        self,
    ) -> None:
        lanes = {
            "registry-relay-public": "relay-public",
            "registry-relay-consultation": "relay-consultation",
            "registry-notary": "notary",
        }
        for service_name, lane in lanes.items():
            other_lane = next(
                candidate for candidate in lanes.values() if candidate != lane
            )
            mutations = {
                "environment": lambda service: service["env_file"].__setitem__(
                    0,
                    f"/fixture/package/operator/secrets/{other_lane}-environment",
                ),
                "bundle-lane": lambda service: service["volumes"][0].update(
                    {"source": (f"/fixture/package/generated/bundles/{other_lane}")}
                ),
                "bundle-package": lambda service: service["volumes"][0].update(
                    {"source": f"/outside/generated/bundles/{lane}"}
                ),
                "anchor-lane": lambda service: service["volumes"][1].update(
                    {"source": (f"/fixture/package/generated/anchors/{other_lane}")}
                ),
                "state": lambda service: service["volumes"][2].update(
                    {"source": f"registry-{other_lane}-state"}
                ),
                "audit": lambda service: service["volumes"][3].update(
                    {"source": f"registry-{other_lane}-audit"}
                ),
            }
            if f"registry-operator-files-{lane}-serve" in CHECKER.STAGED_SECRET_VOLUMES:
                mutations["operator-secret"] = lambda service: service["volumes"][
                    -1
                ].update({"source": f"registry-operator-files-{other_lane}-serve"})
            for mutation_name, mutate in mutations.items():
                with self.subTest(service=service_name, mutation=mutation_name):
                    model = ordinary_model()
                    mutate(model["services"][service_name])
                    with self.assertRaises(CHECKER.ContractError):
                        assert_ordinary(model)

    def test_stagers_reject_cross_lane_authority_and_missing_fields(
        self,
    ) -> None:
        def add_cross_lane_input(model: dict) -> None:
            model["services"]["registry-relay-public-stage-secrets"]["secrets"].append(
                {
                    "source": "registry-notary-signing-key",
                    "target": "/run/secrets/notary-signing-key",
                }
            )

        def add_cross_lane_output(model: dict) -> None:
            model["services"]["registry-relay-public-stage-secrets"]["volumes"].append(
                volume(
                    "registry-operator-files-notary-serve",
                    "/registryctl-stage/cross-lane",
                )
            )

        mutations = {
            "cross-lane-input": add_cross_lane_input,
            "cross-lane-output": add_cross_lane_output,
            "image": lambda model: model["services"][
                "registry-relay-public-stage-secrets"
            ].pop("image"),
            "command": lambda model: model["services"][
                "registry-relay-public-stage-secrets"
            ].pop("command"),
            "network": lambda model: model["services"][
                "registry-relay-public-stage-secrets"
            ].update({"network_mode": "service:registry-postgres"}),
            "capability": lambda model: model["services"][
                "registry-relay-public-stage-secrets"
            ].update({"cap_add": ["CHOWN", "DAC_OVERRIDE"]}),
            "secret-target": lambda model: model["services"][
                "registry-relay-public-stage-secrets"
            ]["secrets"][0].update({"target": "/tmp/escaped"}),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                model = ordinary_model()
                mutate(model)
                with self.assertRaises(CHECKER.ContractError):
                    assert_ordinary(model)

    def test_each_stager_requires_its_closed_isolated_contract(self) -> None:
        fields = (
            "image",
            "entrypoint",
            "command",
            "user",
            "read_only",
            "cap_drop",
            "cap_add",
            "security_opt",
            "tmpfs",
            "network_mode",
            "restart",
        )
        baseline = ordinary_model()
        for service_name in CHECKER.STAGER_SERVICES:
            for field in fields:
                with self.subTest(service=service_name, field=field):
                    model = ordinary_model()
                    model["services"][service_name].pop(field)
                    with self.assertRaises(CHECKER.ContractError):
                        assert_ordinary(model)
            with self.subTest(service=service_name, field="privileged"):
                model = ordinary_model()
                model["services"][service_name]["privileged"] = True
                with self.assertRaises(CHECKER.ContractError):
                    assert_ordinary(model)
            for projection in baseline["services"][service_name]["secrets"]:
                with self.subTest(
                    service=service_name,
                    secret=projection["source"],
                ):
                    model = ordinary_model()
                    model["services"][service_name]["secrets"] = [
                        item
                        for item in model["services"][service_name]["secrets"]
                        if item["source"] != projection["source"]
                    ]
                    with self.assertRaises(CHECKER.ContractError):
                        assert_ordinary(model)
            for mount in baseline["services"][service_name]["volumes"]:
                with self.subTest(service=service_name, output=mount["target"]):
                    model = ordinary_model()
                    model["services"][service_name]["volumes"] = [
                        item
                        for item in model["services"][service_name]["volumes"]
                        if item["target"] != mount["target"]
                    ]
                    with self.assertRaises(CHECKER.ContractError):
                        assert_ordinary(model)

    def test_operator_files_must_stay_under_operator_directory(self) -> None:
        model = ordinary_model()
        model["secrets"]["registry-notary-signing-key"]["file"] = (
            "/fixture/generated/notary-signing-key"
        )
        with self.assertRaisesRegex(
            CHECKER.ContractError,
            "escaped package/operator/secrets",
        ):
            assert_ordinary(model)

    def test_value_free_model_rejects_resolved_sentinel(self) -> None:
        model = ordinary_model()
        model["services"]["registry-notary"]["environment"] = {
            "REGISTRY_CONFORMANCE_SENTINEL": ("notary-value-must-not-enter-compose")
        }
        with self.assertRaisesRegex(CHECKER.ContractError, "sentinel value"):
            assert_ordinary(model)

    def test_initialization_model_accepts_explicit_actions(self) -> None:
        ordinary = ordinary_model()
        initialized = initialization_model(ordinary)
        assert_initialization(initialized, ordinary)

    def test_initialization_keeps_ordinary_stagers_unchanged(self) -> None:
        ordinary = ordinary_model()
        initialized = initialization_model(ordinary)
        for name in CHECKER.STAGER_SERVICES:
            self.assertEqual(initialized["services"][name], ordinary["services"][name])

        changed = initialization_model(ordinary)
        changed["services"]["registry-relay-public-stage-secrets"]["command"] = [
            "changed"
        ]
        with self.assertRaisesRegex(
            CHECKER.ContractError,
            "changed ordinary service registry-relay-public-stage-secrets",
        ):
            assert_initialization(changed, ordinary)

    def test_initialization_action_stagers_are_closed_and_isolated(self) -> None:
        ordinary = ordinary_model()
        baseline = initialization_model(ordinary)
        fields = (
            "image",
            "platform",
            "entrypoint",
            "command",
            "user",
            "read_only",
            "cap_drop",
            "cap_add",
            "security_opt",
            "tmpfs",
            "network_mode",
            "restart",
        )
        for service_name in CHECKER.ACTION_STAGER_SERVICES:
            for field in fields:
                with self.subTest(service=service_name, field=field):
                    initialized = initialization_model(ordinary)
                    initialized["services"][service_name].pop(field)
                    with self.assertRaises(CHECKER.ContractError):
                        assert_initialization(initialized, ordinary)
            for projection in baseline["services"][service_name]["secrets"]:
                with self.subTest(
                    service=service_name,
                    secret=projection["source"],
                ):
                    initialized = initialization_model(ordinary)
                    initialized["services"][service_name]["secrets"] = [
                        item
                        for item in initialized["services"][service_name]["secrets"]
                        if item["source"] != projection["source"]
                    ]
                    with self.assertRaises(CHECKER.ContractError):
                        assert_initialization(initialized, ordinary)
            for mount in baseline["services"][service_name]["volumes"]:
                with self.subTest(service=service_name, output=mount["target"]):
                    initialized = initialization_model(ordinary)
                    initialized["services"][service_name]["volumes"] = [
                        item
                        for item in initialized["services"][service_name]["volumes"]
                        if item["target"] != mount["target"]
                    ]
                    with self.assertRaises(CHECKER.ContractError):
                        assert_initialization(initialized, ordinary)

    def test_state_checks_are_non_mutating_and_accept_has_only_lane_environment(
        self,
    ) -> None:
        ordinary = ordinary_model()
        initialized = initialization_model(ordinary)
        for lane in ("relay-public", "relay-consultation", "notary"):
            accept_name = f"registry-{lane}-accept-state"
            accept = initialized["services"][accept_name]
            self.assertEqual(
                accept["env_file"],
                [
                    (
                        "/fixture/package/operator/secrets/"
                        f"{CHECKER.LANE_ENVIRONMENTS['registry-' + lane]}"
                    )
                ],
            )
            self.assertEqual(accept["network_mode"], "none")
            accept_secrets = [
                mount
                for mount in accept["volumes"]
                if mount["target"] == "/run/secrets"
            ]
            self.assertEqual(accept_secrets, [])
            self.assertEqual(CHECKER._dependencies(accept), {})
            for action in ("preview", "verify"):
                service = initialized["services"][f"registry-{lane}-{action}-state"]
                self.assertNotIn("env_file", service)
                self.assertNotIn("secrets", service)
                self.assertEqual(service["network_mode"], "none")
                self.assertNotIn(
                    "/run/secrets",
                    {mount["target"] for mount in service["volumes"]},
                )

        changed = initialization_model(ordinary)
        changed["services"]["registry-notary-accept-state"]["env_file"] = [
            "/fixture/package/operator/secrets/relay-public-environment"
        ]
        with self.assertRaises(CHECKER.ContractError):
            assert_initialization(changed, ordinary)

        changed = initialization_model(ordinary)
        changed["services"]["registry-notary-accept-state"]["volumes"].append(
            volume(
                "registry-operator-files-notary-serve",
                "/run/secrets",
                read_only=True,
            )
        )
        with self.assertRaises(CHECKER.ContractError):
            assert_initialization(changed, ordinary)

        changed = initialization_model(ordinary)
        changed["services"]["registry-relay-public-preview-state"]["volumes"].append(
            volume(
                "registry-operator-files-relay-public-accept",
                "/run/secrets",
                read_only=True,
            )
        )
        with self.assertRaises(CHECKER.ContractError):
            assert_initialization(changed, ordinary)

    def test_preparation_and_bootstrap_use_only_action_stagers(self) -> None:
        ordinary = ordinary_model()
        initialized = initialization_model(ordinary)
        expected = {
            "registry-postgres-bootstrap": (
                "registry-postgresql-actions-stage-secrets"
            ),
            "registry-relay-consultation-prepare-state": (
                "registry-relay-consultation-actions-stage-secrets"
            ),
            "registry-relay-consultation-initialize": (
                "registry-relay-consultation-actions-stage-secrets"
            ),
            "registry-notary-prepare-state": (
                "registry-notary-actions-stage-secrets"
            ),
        }
        for service_name, stager_name in expected.items():
            dependencies = initialized["services"][service_name]["depends_on"]
            self.assertIn(stager_name, dependencies)
            self.assertTrue(CHECKER.STAGER_SERVICES.isdisjoint(dependencies))

        changed = initialization_model(ordinary)
        dependencies = changed["services"]["registry-postgres-bootstrap"]["depends_on"]
        dependencies["registry-postgresql-stage-secrets"] = dependencies.pop(
            "registry-postgresql-actions-stage-secrets"
        )
        with self.assertRaises(CHECKER.ContractError):
            assert_initialization(changed, ordinary)

    def test_initialization_requires_exact_postgresql_delta(self) -> None:
        ordinary = ordinary_model()
        initialized = initialization_model(ordinary)
        initialized["services"]["registry-postgres"]["entrypoint"] = [
            "/bin/sh",
            "implicit",
        ]
        with self.assertRaisesRegex(
            CHECKER.ContractError,
            "not an explicit delta",
        ):
            assert_initialization(initialized, ordinary)

    def test_initialization_requires_each_closed_action_field(self) -> None:
        mutations = {
            "service": lambda model: model["services"].pop(
                "registry-notary-initialize"
            ),
            "image": lambda model: model["services"]["registry-notary-initialize"].pop(
                "image"
            ),
            "command": lambda model: model["services"][
                "registry-notary-initialize"
            ].pop("command"),
            "hardening": lambda model: model["services"][
                "registry-postgres-bootstrap"
            ].pop("user"),
            "network": lambda model: model["services"][
                "registry-relay-consultation-prepare-state"
            ].pop("networks"),
            "dependency": lambda model: model["services"][
                "registry-notary-prepare-state"
            ]["depends_on"].pop("registry-postgres"),
            "restart": lambda model: model["services"][
                "registry-relay-public-initialize"
            ].pop("restart"),
            "environment": lambda model: model["services"][
                "registry-relay-public-prepare-state"
            ].pop("env_file"),
            "bundle": lambda model: model["services"][
                "registry-relay-public-prepare-state"
            ]["volumes"].pop(0),
            "anchor": lambda model: model["services"]["registry-notary-initialize"][
                "volumes"
            ].pop(1),
            "state": lambda model: model["services"]["registry-notary-initialize"][
                "volumes"
            ].pop(2),
            "audit": lambda model: model["services"]["registry-notary-initialize"][
                "volumes"
            ].pop(3),
            "staged-secret": lambda model: model["services"][
                "registry-notary-initialize"
            ]["volumes"].pop(),
        }
        ordinary = ordinary_model()
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                initialized = initialization_model(ordinary)
                mutate(initialized)
                with self.assertRaises(CHECKER.ContractError):
                    assert_initialization(initialized, ordinary)

    def test_initialization_rejects_removal_of_each_hardening_field(self) -> None:
        ordinary = ordinary_model()
        hardening_fields = (
            "user",
            "read_only",
            "cap_drop",
            "security_opt",
            "tmpfs",
        )
        for service_name in CHECKER.INITIALIZATION_SERVICES:
            for field in hardening_fields:
                with self.subTest(service=service_name, protection=field):
                    initialized = initialization_model(ordinary)
                    initialized["services"][service_name].pop(field)
                    with self.assertRaises(CHECKER.ContractError):
                        assert_initialization(initialized, ordinary)
            with self.subTest(service=service_name, protection="privileged"):
                initialized = initialization_model(ordinary)
                initialized["services"][service_name]["privileged"] = True
                with self.assertRaises(CHECKER.ContractError):
                    assert_initialization(initialized, ordinary)

    def test_initialization_requires_each_command_restart_network_and_dependency(
        self,
    ) -> None:
        ordinary = ordinary_model()
        baseline = initialization_model(ordinary)
        for service_name in CHECKER.INITIALIZATION_SERVICES:
            metadata = CHECKER.INITIALIZATION_METADATA.get(service_name)
            requires_postgresql = metadata is None or (
                (
                    metadata[1] == "relay-consultation"
                    and metadata[2] in {"prepare", "initialize"}
                )
                or (metadata[1] == "notary" and metadata[2] == "prepare")
            )
            network_field = "networks" if requires_postgresql else "network_mode"
            for field in ("command", "restart", network_field):
                with self.subTest(service=service_name, field=field):
                    initialized = initialization_model(ordinary)
                    initialized["services"][service_name].pop(field)
                    with self.assertRaises(CHECKER.ContractError):
                        assert_initialization(initialized, ordinary)
            dependencies = baseline["services"][service_name].get("depends_on", {})
            if dependencies:
                for dependency in dependencies:
                    with self.subTest(service=service_name, dependency=dependency):
                        initialized = initialization_model(ordinary)
                        initialized["services"][service_name]["depends_on"].pop(
                            dependency
                        )
                        with self.assertRaises(CHECKER.ContractError):
                            assert_initialization(initialized, ordinary)
            else:
                with self.subTest(service=service_name, dependency="unexpected"):
                    initialized = initialization_model(ordinary)
                    initialized["services"][service_name]["depends_on"] = (
                        dependency_model({"registry-postgres": "service_healthy"})
                    )
                    with self.assertRaises(CHECKER.ContractError):
                        assert_initialization(initialized, ordinary)

    def test_initialization_services_are_unpublished_and_keep_every_mount(
        self,
    ) -> None:
        ordinary = ordinary_model()
        baseline = initialization_model(ordinary)
        for service_name in CHECKER.INITIALIZATION_SERVICES:
            with self.subTest(service=service_name, protection="publication"):
                initialized = initialization_model(ordinary)
                initialized["services"][service_name]["ports"] = [
                    {
                        "host_ip": "127.0.0.1",
                        "mode": "ingress",
                        "protocol": "tcp",
                        "published": "9999",
                        "target": 9999,
                    }
                ]
                with self.assertRaises(CHECKER.ContractError):
                    assert_initialization(initialized, ordinary)
            targets = [
                mount["target"]
                for mount in baseline["services"][service_name]["volumes"]
            ]
            for target in targets:
                with self.subTest(service=service_name, target=target):
                    initialized = initialization_model(ordinary)
                    service = initialized["services"][service_name]
                    service["volumes"] = [
                        mount
                        for mount in service["volumes"]
                        if mount["target"] != target
                    ]
                    with self.assertRaises(CHECKER.ContractError):
                        assert_initialization(initialized, ordinary)
                with self.subTest(service=service_name, target=target, mode="changed"):
                    initialized = initialization_model(ordinary)
                    mount = next(
                        mount
                        for mount in initialized["services"][service_name]["volumes"]
                        if mount["target"] == target
                    )
                    if mount.get("read_only") is True:
                        mount.pop("read_only")
                    else:
                        mount["read_only"] = True
                    with self.assertRaises(CHECKER.ContractError):
                        assert_initialization(initialized, ordinary)

    def test_initialization_delta_cannot_change_ordinary_service(self) -> None:
        ordinary = ordinary_model()
        initialized = initialization_model(ordinary)
        initialized["services"]["registry-notary"]["command"] = ["changed"]
        with self.assertRaisesRegex(
            CHECKER.ContractError,
            "changed ordinary service registry-notary",
        ):
            assert_initialization(initialized, ordinary)

    def test_plan_probe_is_closed_and_complete(self) -> None:
        images = CHECKER.validate_plan(
            CHECKER.FIXTURE_ROOT / "deployment-plan.probe.v1.json"
        )
        self.assertEqual(set(images), set(expected_images()))

    def test_plan_probe_rejects_every_missing_workload_field(self) -> None:
        baseline = json.loads(
            (CHECKER.FIXTURE_ROOT / "deployment-plan.probe.v1.json").read_text(
                encoding="utf-8"
            )
        )
        fields = list(baseline["workloads"][0])
        for field in fields:
            with self.subTest(field=field):
                plan = copy.deepcopy(baseline)
                plan["workloads"][0].pop(field)
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "plan.json"
                    path.write_text(json.dumps(plan), encoding="utf-8")
                    with self.assertRaisesRegex(
                        CHECKER.ContractError,
                        "wrong closed workload",
                    ):
                        CHECKER.validate_plan(path)

    def test_plan_probe_rejects_extra_and_stale_fields(self) -> None:
        baseline = json.loads(
            (CHECKER.FIXTURE_ROOT / "deployment-plan.probe.v1.json").read_text(
                encoding="utf-8"
            )
        )
        mutations = {
            "missing-root": lambda plan: plan.pop("schema_version"),
            "root": lambda plan: plan.update({"private_co_location_groups": []}),
            "workload": lambda plan: plan["workloads"][0].update(
                {"managed_ingress": True}
            ),
            "relay-image": lambda plan: plan["workloads"][1].update(
                {
                    "image_identity": (
                        "example.invalid/registrystack/"
                        "registry-relay@sha256:" + "d" * 64
                    )
                }
            ),
            "action": lambda plan: plan["initialization_actions"][0].pop("id"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                plan = copy.deepcopy(baseline)
                mutate(plan)
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "plan.json"
                    path.write_text(json.dumps(plan), encoding="utf-8")
                    with self.assertRaises(CHECKER.ContractError):
                        CHECKER.validate_plan(path)

    def test_plan_probe_rejects_duplicate_json_object_fields(self) -> None:
        baseline = (CHECKER.FIXTURE_ROOT / "deployment-plan.probe.v1.json").read_text(
            encoding="utf-8"
        )
        duplicate_root = baseline.replace(
            '  "single_instance": true,\n',
            '  "single_instance": true,\n  "single_instance": true,\n',
            1,
        )
        duplicate_workload = baseline.replace(
            '      "id": "relay-public",\n',
            ('      "id": "relay-public",\n      "id": "relay-public",\n'),
            1,
        )
        for name, text in (
            ("root", duplicate_root),
            ("workload", duplicate_workload),
        ):
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "plan.json"
                    path.write_text(text, encoding="utf-8")
                    with self.assertRaisesRegex(
                        CHECKER.ContractError,
                        "repeats object field",
                    ):
                        CHECKER.validate_plan(path)

    def test_plan_probe_rejects_unknown_and_duplicate_semantic_entries(
        self,
    ) -> None:
        baseline = json.loads(
            (CHECKER.FIXTURE_ROOT / "deployment-plan.probe.v1.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            baseline["workloads"][0]["mount_roles"].count("certificate"),
            1,
        )
        mutations = {
            "duplicate-workload": lambda plan: plan["workloads"].append(
                copy.deepcopy(plan["workloads"][0])
            ),
            "unknown-workload": lambda plan: plan["workloads"][0].update(
                {"id": "unknown"}
            ),
            "duplicate-certificate-role": lambda plan: plan["workloads"][0][
                "mount_roles"
            ].append("certificate"),
            "unknown-mount-role": lambda plan: plan["workloads"][0][
                "mount_roles"
            ].append("unknown"),
            "duplicate-initialization": lambda plan: plan[
                "initialization_actions"
            ].append(copy.deepcopy(plan["initialization_actions"][0])),
            "duplicate-recovery-group": lambda plan: plan[
                "recovery_consistency_groups"
            ].append(copy.deepcopy(plan["recovery_consistency_groups"][0])),
            "duplicate-exposure": lambda plan: plan["exposure_requirements"].append(
                copy.deepcopy(plan["exposure_requirements"][0])
            ),
            "unknown-exposure": lambda plan: plan["exposure_requirements"][0].update(
                {"endpoint_class": "unknown"}
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                plan = copy.deepcopy(baseline)
                mutate(plan)
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "plan.json"
                    path.write_text(json.dumps(plan), encoding="utf-8")
                    with self.assertRaises(CHECKER.ContractError):
                        CHECKER.validate_plan(path)

    def test_parent_include_keeps_package_and_adds_one_service(self) -> None:
        ordinary = ordinary_model()
        parent = copy.deepcopy(ordinary)
        parent_name = "parent-adopter"
        parent["name"] = parent_name
        parent["networks"][CHECKER.NETWORK_RUNTIME] = {
            "name": f"{parent_name}_{CHECKER.NETWORK_RUNTIME}"
        }
        for name in CHECKER.ORDINARY_STAGED_SECRET_VOLUMES:
            parent["volumes"][name] = {"name": f"{parent_name}_{name}"}
        for name in parent["secrets"]:
            parent["secrets"][name]["name"] = f"{parent_name}_{name}"
        parent["services"]["parent-runtime-client"] = {
            "image": (
                "example.invalid/registrystack/conformance-probe@sha256:" + "d" * 64
            ),
            "networks": {CHECKER.NETWORK_RUNTIME: {}},
        }
        CHECKER.assert_parent_include(parent, ordinary)

    def test_parent_include_rejects_renamed_durable_volume(self) -> None:
        ordinary = ordinary_model()
        parent = copy.deepcopy(ordinary)
        parent_name = "parent-adopter"
        parent["name"] = parent_name
        parent["networks"][CHECKER.NETWORK_RUNTIME] = {
            "name": f"{parent_name}_{CHECKER.NETWORK_RUNTIME}"
        }
        for name in CHECKER.ORDINARY_STAGED_SECRET_VOLUMES:
            parent["volumes"][name] = {"name": f"{parent_name}_{name}"}
        for name in parent["secrets"]:
            parent["secrets"][name]["name"] = f"{parent_name}_{name}"
        parent["volumes"]["registry-notary-state"] = {
            "name": f"{parent_name}_registry-notary-state"
        }
        parent["services"]["parent-runtime-client"] = {
            "image": (
                "example.invalid/registrystack/conformance-probe@sha256:" + "d" * 64
            ),
            "networks": {CHECKER.NETWORK_RUNTIME: {}},
        }
        with self.assertRaisesRegex(
            CHECKER.ContractError,
            "renamed durable volume registry-notary-state",
        ):
            CHECKER.assert_parent_include(parent, ordinary)

    def test_minimum_compose_download_is_checksum_pinned(self) -> None:
        wrapper = SCRIPT.with_suffix(".sh").read_text(encoding="utf-8")
        self.assertIn('COMPOSE_MINIMUM_VERSION="2.35.0"', wrapper)
        self.assertIn(
            "dba1915cf2f282527f5df0cd7a94b9503047ed200317801853abe8f22c8cd493",
            wrapper,
        )
        self.assertIn("actual != expected", wrapper)


if __name__ == "__main__":
    unittest.main()
