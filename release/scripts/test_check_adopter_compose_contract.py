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
        "user": "65532:65532",
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "tmpfs": ["/tmp"],
    }


def postgresql_hardening() -> dict:
    return {
        "user": "999:999",
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "tmpfs": [
            "/tmp",
            "/var/run/postgresql:uid=999,gid=999,mode=0750",
        ],
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
        result.append(volume(f"registry-{lane}-state", "/var/lib/registry/state"))
    result.append(volume(f"registry-{lane}-audit", "/var/lib/registry/audit"))
    secret_volume = f"registry-operator-files-{lane}-{action}"
    if secret_volume in CHECKER.STAGED_SECRET_VOLUMES:
        result.append(volume(secret_volume, "/run/secrets", read_only=True))
    return result


def stager(name: str) -> dict:
    spec = CHECKER.STAGER_SPECS[name]
    return {
        "image": expected_images()["registry-postgres"],
        "entrypoint": ["/bin/sh", "-ceu"],
        "command": CHECKER.STAGER_COMMAND,
        "user": "0:0",
        "read_only": True,
        "cap_drop": ["ALL"],
        "cap_add": ["CHOWN"],
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
            "target": 4242,
        }
    ]
    services["registry-notary"]["ports"] = [
        {
            "host_ip": "127.0.0.1",
            "mode": "ingress",
            "protocol": "tcp",
            "published": "4255",
            "target": 4255,
        }
    ]
    return {
        "services": services,
        "networks": {
            CHECKER.NETWORK_RUNTIME: {
                "name": f"{CHECKER.PROJECT_NAME}_{CHECKER.NETWORK_RUNTIME}"
            }
        },
        "volumes": {name: {} for name in CHECKER.EXPECTED_VOLUMES},
        "secrets": {
            f"registry-{name}": {
                "file": f"/fixture/package/operator/secrets/{name}",
            }
            for name in CHECKER.OPERATOR_SECRET_FILES
        },
    }


def initialization_model(ordinary: dict) -> dict:
    initialized = copy.deepcopy(ordinary)
    initialized["services"]["registry-postgres"]["entrypoint"] = [
        "docker-entrypoint.sh"
    ]
    initialized["services"]["registry-postgres-bootstrap"] = {
        **postgresql_hardening(),
        "image": expected_images()["registry-postgres"],
        "command": CHECKER.INITIALIZATION_COMMANDS["registry-postgres-bootstrap"],
        "restart": "no",
        "networks": {CHECKER.NETWORK_RUNTIME: {}},
        "depends_on": dependency_model(
            {
                "registry-postgres": "service_healthy",
                "registry-postgresql-stage-secrets": ("service_completed_successfully"),
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
            "networks": {CHECKER.NETWORK_RUNTIME: {}},
            "env_file": [
                (
                    "/fixture/package/operator/secrets/"
                    f"{CHECKER.LANE_ENVIRONMENTS[ordinary_name]}"
                )
            ],
            "volumes": product_mounts(lane, action),
        }
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
            ].pop("cap_add"),
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
        CHECKER.assert_initialization_model(
            initialized,
            ordinary,
            expected_images(),
        )

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
            CHECKER.assert_initialization_model(
                initialized,
                ordinary,
                expected_images(),
            )

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
                    CHECKER.assert_initialization_model(
                        initialized,
                        ordinary,
                        expected_images(),
                    )

    def test_initialization_delta_cannot_change_ordinary_service(self) -> None:
        ordinary = ordinary_model()
        initialized = initialization_model(ordinary)
        initialized["services"]["registry-notary"]["command"] = ["changed"]
        with self.assertRaisesRegex(
            CHECKER.ContractError,
            "changed ordinary service registry-notary",
        ):
            CHECKER.assert_initialization_model(
                initialized,
                ordinary,
                expected_images(),
            )

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

    def test_parent_include_keeps_package_and_adds_one_service(self) -> None:
        ordinary = ordinary_model()
        parent = copy.deepcopy(ordinary)
        parent["services"]["parent-runtime-client"] = {
            "image": (
                "example.invalid/registrystack/conformance-probe@sha256:" + "d" * 64
            ),
            "networks": {CHECKER.NETWORK_RUNTIME: {}},
        }
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
