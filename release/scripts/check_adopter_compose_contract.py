#!/usr/bin/env python3
"""Validate the adopter-runtime Compose conformance fixtures.

This is a pre-renderer proof over deliberately inert fixtures. It validates
effective Compose models; it does not implement rendering or trust decisions.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = REPO_ROOT / "release/conformance/adopter-runtime"
PRODUCT_SERVICES = frozenset(
    {
        "registry-private-namespace",
        "registry-postgres",
        "registry-relay-public",
        "registry-relay-consultation",
        "registry-notary",
    }
)
INITIALIZATION_SERVICES = frozenset(
    {
        "registry-relay-public-prepare-state",
        "registry-relay-consultation-prepare-state",
        "registry-notary-prepare-state",
        "registry-relay-public-initialize",
        "registry-relay-consultation-initialize",
        "registry-notary-initialize",
    }
)
INITIALIZATION_IMAGE_SERVICE = {
    "registry-relay-public-prepare-state": "registry-relay-public",
    "registry-relay-consultation-prepare-state": "registry-relay-consultation",
    "registry-notary-prepare-state": "registry-notary",
    "registry-relay-public-initialize": "registry-relay-public",
    "registry-relay-consultation-initialize": "registry-relay-consultation",
    "registry-notary-initialize": "registry-notary",
}
PRIVATE_NETWORK = "registry-private"
PRIVATE_NAMESPACE = "service:registry-private-namespace"
IMAGE_IDENTITY_PATTERN = re.compile(
    r"^[^@\s]+@sha256:[0-9a-f]{64}$"
)
COMPOSE_SERVICE_FOR_WORKLOAD = {
    "relay-public": "registry-relay-public",
    "relay-consultation": "registry-relay-consultation",
    "notary": "registry-notary",
    "postgresql-state-plane": "registry-postgres",
    "private-namespace-holder": "registry-private-namespace",
}
EXPECTED_PLAN_WORKLOADS = {
    "relay-public": {
        "kind": "product",
        "product_lane": "relay-public",
        "action": "serve",
        "dependencies": [],
    },
    "relay-consultation": {
        "kind": "product",
        "product_lane": "relay-consultation",
        "action": "serve",
        "dependencies": [
            "postgresql-state-plane",
            "private-namespace-holder",
        ],
    },
    "notary": {
        "kind": "product",
        "product_lane": "notary",
        "action": "serve",
        "dependencies": [
            "relay-consultation",
            "postgresql-state-plane",
            "private-namespace-holder",
        ],
    },
    "postgresql-state-plane": {
        "kind": "supporting",
        "recipe": "postgresql_state_plane",
        "dependencies": ["private-namespace-holder"],
    },
    "private-namespace-holder": {
        "kind": "supporting",
        "recipe": "private_namespace_holder",
        "dependencies": [],
    },
}
EXPECTED_INITIALIZATION_ACTIONS = (
    ("prepare-relay-public-state", "relay-public", "prepare_state_store"),
    (
        "prepare-relay-consultation-state",
        "relay-consultation",
        "prepare_state_store",
    ),
    ("prepare-notary-state", "notary", "prepare_state_store"),
    ("initialize-relay-public", "relay-public", "initialize_state"),
    (
        "initialize-relay-consultation",
        "relay-consultation",
        "initialize_state",
    ),
    ("initialize-notary", "notary", "initialize_state"),
)


class ContractError(RuntimeError):
    """Raised when a rendered model violates the conformance contract."""


def _compose_config(
    compose_command: Sequence[str], fixture_root: Path, *files: str
) -> dict[str, Any]:
    empty_env = fixture_root / "package/generated/compose.empty.env"
    command = [
        *compose_command,
        "--project-name",
        "registry-adopter-probe",
        "--env-file",
        str(empty_env),
    ]
    for relative_file in files:
        command.extend(("-f", str(fixture_root / relative_file)))
    command.extend(
        (
            "config",
            "--no-interpolate",
            "--no-env-resolution",
            "--format",
            "json",
        )
    )
    result = subprocess.run(
        command,
        cwd=fixture_root,
        env={
            **os.environ,
            "COMPOSE_IGNORE_ORPHANS": "true",
        },
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        diagnostic = (result.stderr or result.stdout).strip()
        raise ContractError(
            f"Compose normalization failed for {', '.join(files)}: "
            f"{diagnostic[:1200]}"
        )
    try:
        model = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ContractError(
            f"Compose returned invalid JSON for {', '.join(files)}"
        ) from error
    if not isinstance(model, dict):
        raise ContractError("Compose effective model must be an object")
    return model


def _services(model: dict[str, Any]) -> dict[str, Any]:
    services = model.get("services")
    if not isinstance(services, dict):
        raise ContractError("Compose effective model has no services object")
    return services


def _labels(service: dict[str, Any]) -> dict[str, str]:
    raw = service.get("labels", {})
    if isinstance(raw, dict):
        return {str(key): str(value) for key, value in raw.items()}
    if isinstance(raw, list):
        labels: dict[str, str] = {}
        for item in raw:
            key, separator, value = str(item).partition("=")
            labels[key] = value if separator else ""
        return labels
    raise ContractError("service labels must be a mapping or list")


def assert_ordinary_model(
    model: dict[str, Any],
    expected_images: dict[str, str] | None = None,
) -> None:
    services = _services(model)
    if set(services) != PRODUCT_SERVICES:
        raise ContractError(
            "ordinary model must contain exactly the five governed services"
        )
    leaked = INITIALIZATION_SERVICES.intersection(services)
    if leaked:
        raise ContractError(
            "ordinary model contains initialization services: "
            + ", ".join(sorted(leaked))
        )
    for name in PRODUCT_SERVICES:
        labels = _labels(services[name])
        if labels.get("io.registrystack.probe.owner") != "renderer":
            raise ContractError(f"{name} lost its renderer ownership label")
        healthcheck = services[name].get("healthcheck")
        if not isinstance(healthcheck, dict) or healthcheck.get("test") != [
            "CMD",
            "/conformance-only-healthcheck",
        ]:
            raise ContractError(f"{name} lost its conformance health shape")
        if (
            expected_images is not None
            and services[name].get("image") != expected_images[name]
        ):
            raise ContractError(f"{name} does not use its plan image identity")

    expected_dependencies = {
        "registry-private-namespace": set(),
        "registry-postgres": {"registry-private-namespace"},
        "registry-relay-public": set(),
        "registry-relay-consultation": {
            "registry-private-namespace",
            "registry-postgres",
        },
        "registry-notary": {
            "registry-private-namespace",
            "registry-postgres",
            "registry-relay-consultation",
        },
    }
    for name, expected in expected_dependencies.items():
        dependencies = services[name].get("depends_on", {})
        if set(dependencies) != expected:
            raise ContractError(f"{name} has the wrong dependency inventory")
        if any(
            dependency.get("condition") != "service_healthy"
            for dependency in dependencies.values()
        ):
            raise ContractError(f"{name} has a non-health dependency")


def assert_initialization_model(
    model: dict[str, Any],
    ordinary_model: dict[str, Any],
    expected_images: dict[str, str],
) -> None:
    services = _services(model)
    ordinary_services = _services(ordinary_model)
    expected = PRODUCT_SERVICES | INITIALIZATION_SERVICES
    if set(services) != expected:
        raise ContractError(
            "explicit initialization model must contain exactly the governed "
            "ordinary and initialization services"
        )
    for service_name in PRODUCT_SERVICES:
        if services[service_name] != ordinary_services[service_name]:
            raise ContractError(
                "initialization file changed ordinary service "
                f"{service_name}"
            )
    for service_name, ordinary_service in INITIALIZATION_IMAGE_SERVICE.items():
        if services[service_name].get("image") != expected_images[ordinary_service]:
            raise ContractError(
                f"{service_name} does not use its plan image identity"
            )
    initialization_dependencies = {
        "registry-relay-public-prepare-state": {},
        "registry-relay-consultation-prepare-state": {
            "registry-private-namespace": "service_started",
            "registry-postgres": "service_healthy",
        },
        "registry-notary-prepare-state": {
            "registry-private-namespace": "service_started",
            "registry-postgres": "service_healthy",
        },
        "registry-relay-public-initialize": {},
        "registry-relay-consultation-initialize": {
            "registry-private-namespace": "service_started",
            "registry-postgres": "service_healthy",
        },
        "registry-notary-initialize": {
            "registry-private-namespace": "service_started",
            "registry-postgres": "service_healthy",
        },
    }
    for service_name, expected_conditions in initialization_dependencies.items():
        dependencies = services[service_name].get("depends_on", {})
        actual_conditions = {
            dependency_name: dependency.get("condition")
            for dependency_name, dependency in dependencies.items()
        }
        if actual_conditions != expected_conditions:
            raise ContractError(
                f"{service_name} has the wrong initialization dependency"
            )


def assert_parent_boundary(
    model: dict[str, Any],
    baseline: dict[str, Any],
    *,
    expected_parent: str | None,
) -> None:
    services = _services(model)
    baseline_services = _services(baseline)
    if PRODUCT_SERVICES.difference(services):
        raise ContractError("included model lost a governed product service")
    for name in PRODUCT_SERVICES:
        if services[name] != baseline_services[name]:
            raise ContractError(f"parent changed renderer-owned service {name}")

    parent_services = set(services).difference(PRODUCT_SERVICES)
    expected = {expected_parent} if expected_parent else set()
    if parent_services != expected:
        raise ContractError(
            "unexpected parent-owned service set: "
            + ", ".join(sorted(parent_services))
        )
    for name in parent_services:
        service = services[name]
        networks = service.get("networks", {})
        if isinstance(networks, list):
            network_names = set(networks)
        elif isinstance(networks, dict):
            network_names = set(networks)
        else:
            network_names = set()
        if PRIVATE_NETWORK in network_names:
            raise ContractError(f"parent service {name} joined the private network")
        if service.get("network_mode") == PRIVATE_NAMESPACE:
            raise ContractError(f"parent service {name} joined the private namespace")


def assert_edge_parent(model: dict[str, Any]) -> None:
    service = _services(model).get("parent-edge-client")
    if not isinstance(service, dict):
        raise ContractError("positive parent has no edge client")
    networks = service.get("networks", {})
    names = set(networks) if isinstance(networks, (dict, list)) else set()
    if "registry-edge" not in names:
        raise ContractError("positive parent edge client did not join registry-edge")


def assert_relative_paths_match(
    baseline: dict[str, Any], included: dict[str, Any]
) -> None:
    baseline_services = _services(baseline)
    included_services = _services(included)
    for service_name in PRODUCT_SERVICES:
        baseline_mounts = baseline_services[service_name].get("volumes", [])
        included_mounts = included_services[service_name].get("volumes", [])
        if baseline_mounts != included_mounts:
            raise ContractError(
                f"relative mount resolution changed for {service_name}"
            )
    if baseline.get("secrets") != included.get("secrets"):
        raise ContractError("relative secret-file resolution changed under include")


def assert_negative_boundary(
    model: dict[str, Any],
    baseline: dict[str, Any],
    expected_reason: str,
) -> None:
    services = _services(model)
    baseline_services = _services(baseline)
    if PRODUCT_SERVICES.difference(services):
        raise ContractError("negative fixture lost a governed product service")

    changed_products = {
        name
        for name in PRODUCT_SERVICES
        if services[name] != baseline_services[name]
    }
    if expected_reason == "cross-owner-mutation":
        if set(services) != PRODUCT_SERVICES:
            raise ContractError("cross-owner fixture introduced an unrelated service")
        if changed_products != {"registry-notary"}:
            raise ContractError(
                "cross-owner fixture must change only the governed Notary service"
            )
        expected_parent = None
    else:
        if changed_products:
            raise ContractError(
                "private-access fixture unexpectedly changed a governed service"
            )
        if set(services).difference(PRODUCT_SERVICES) != {
            "parent-private-client"
        }:
            raise ContractError("private-access fixture has the wrong parent service")
        parent = services["parent-private-client"]
        networks = parent.get("networks", {})
        network_names = (
            set(networks) if isinstance(networks, (dict, list)) else set()
        )
        if (
            expected_reason == "private-network"
            and PRIVATE_NETWORK not in network_names
        ):
            raise ContractError("private-network fixture did not join private network")
        if (
            expected_reason == "private-network"
            and parent.get("network_mode") == PRIVATE_NAMESPACE
        ):
            raise ContractError(
                "private-network fixture also joined the private namespace"
            )
        if (
            expected_reason == "private-namespace"
            and parent.get("network_mode") != PRIVATE_NAMESPACE
        ):
            raise ContractError(
                "private-namespace fixture did not join private namespace"
            )
        if (
            expected_reason == "private-namespace"
            and PRIVATE_NETWORK in network_names
        ):
            raise ContractError(
                "private-namespace fixture also joined the private network"
            )
        expected_parent = "parent-private-client"

    try:
        assert_parent_boundary(
            model,
            baseline,
            expected_parent=expected_parent,
        )
    except ContractError as error:
        expected_message = {
            "private-network": "joined the private network",
            "private-namespace": "joined the private namespace",
            "cross-owner-mutation": (
                "parent changed renderer-owned service registry-notary"
            ),
        }[expected_reason]
        if expected_message not in str(error):
            raise ContractError(
                f"negative fixture failed for the wrong reason: {error}"
            ) from error
        return
    raise ContractError(f"negative fixture was accepted: {expected_reason}")


def validate_plan(plan_path: Path) -> dict[str, str]:
    try:
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ContractError(f"invalid deployment-plan probe: {error}") from error
    if plan.get("schema") != "io.registrystack.deployment-plan.probe.v1":
        raise ContractError("deployment-plan probe has the wrong schema")
    workloads = plan.get("workloads")
    if not isinstance(workloads, list) or len(workloads) != len(PRODUCT_SERVICES):
        raise ContractError("deployment-plan probe must describe all five workloads")
    workload_by_id = {workload.get("id"): workload for workload in workloads}
    if set(workload_by_id) != set(EXPECTED_PLAN_WORKLOADS):
        raise ContractError("deployment-plan probe workload inventory is incomplete")
    for workload_id, expected in EXPECTED_PLAN_WORKLOADS.items():
        workload = workload_by_id[workload_id]
        for field, expected_value in expected.items():
            if workload.get(field) != expected_value:
                raise ContractError(
                    f"deployment-plan probe has the wrong {field} for {workload_id}"
                )
        for field in (
            "image_identity",
            "secret_consumers",
            "state_roles",
            "endpoint_classes",
            "network_relationships",
            "dependencies",
            "health_semantics",
            "restart_action",
            "reactivation_action",
        ):
            if field not in workload:
                raise ContractError(
                    f"deployment-plan probe omits {field} for {workload_id}"
                )
        if (
            not isinstance(workload["image_identity"], str)
            or not IMAGE_IDENTITY_PATTERN.fullmatch(workload["image_identity"])
            or not workload["health_semantics"]
        ):
            raise ContractError(
                "deployment-plan probe has an invalid image or health identity "
                f"for {workload_id}"
            )
        if workload["kind"] == "product":
            immutable_inputs = workload.get("immutable_inputs")
            if not isinstance(immutable_inputs, list) or len(immutable_inputs) != 2:
                raise ContractError(
                    f"product workload {workload_id} must bind its bundle and anchor"
                )
            mount_roles = workload.get("mount_roles")
            if not isinstance(mount_roles, list) or set(mount_roles) - {
                "bundle",
                "anchor",
                "anti-rollback-state",
                "secret",
                "certificate",
                "audit",
            }:
                raise ContractError(
                    f"product workload {workload_id} has invalid mount roles"
                )

    def inventory(field: str) -> set[str]:
        return {
            item
            for workload in workloads
            for item in workload.get(field, [])
        }

    expected_inventories = {
        "immutable_inputs": {
            "relay-public-bundle",
            "relay-public-anchor",
            "relay-consultation-bundle",
            "relay-consultation-anchor",
            "notary-bundle",
            "notary-anchor",
        },
        "secret_consumers": {
            "relay-public-tls",
            "relay-consultation-tls",
            "notary-tls",
            "notary-signing-key",
            "postgresql-tls",
            "postgresql-credentials",
        },
        "state_roles": {
            "relay-public-anti-rollback",
            "relay-public-audit",
            "relay-consultation-anti-rollback",
            "relay-consultation-audit",
            "notary-anti-rollback",
            "notary-audit",
            "postgresql-data",
        },
        "endpoint_classes": {
            "public-application",
            "private-application",
            "administration",
            "metrics",
            "posture",
        },
        "network_relationships": {
            "edge",
            "private",
            "private-consultation-namespace",
        },
        "mount_roles": {
            "bundle",
            "anchor",
            "anti-rollback-state",
            "secret",
            "certificate",
            "audit",
        },
    }
    for field, expected_inventory in expected_inventories.items():
        if inventory(field) != expected_inventory:
            raise ContractError(
                f"deployment-plan probe {field} inventory is incomplete"
            )

    initialization_actions = plan.get("initialization_actions")
    if not isinstance(initialization_actions, list):
        raise ContractError("deployment-plan probe omits initialization actions")
    actual_initialization_actions = tuple(
        (action.get("id"), action.get("workload"), action.get("action"))
        for action in initialization_actions
    )
    if actual_initialization_actions != EXPECTED_INITIALIZATION_ACTIONS:
        raise ContractError("deployment-plan probe initialization inventory is wrong")

    private_groups = plan.get("private_co_location_groups")
    if private_groups != [
        {
            "id": "private-consultation-namespace",
            "members": [
                "relay-consultation",
                "notary",
                "postgresql-state-plane",
                "private-namespace-holder",
            ],
        }
    ]:
        raise ContractError("deployment-plan probe private group is incomplete")
    recovery_groups = plan.get("recovery_consistency_groups")
    if recovery_groups != [
        {
            "id": "consultation-state",
            "members": [
                "relay-consultation",
                "notary",
                "postgresql-state-plane",
            ],
        },
        {
            "id": "relay-public-state",
            "members": ["relay-public"],
        },
    ]:
        raise ContractError("deployment-plan probe recovery groups are incomplete")
    exposure_requirements = plan.get("exposure_requirements")
    if not isinstance(exposure_requirements, list) or {
        item.get("endpoint_class") for item in exposure_requirements
    } != {
        "public-application",
        "private-application",
        "administration",
        "metrics",
        "posture",
    }:
        raise ContractError("deployment-plan probe endpoint inventory is incomplete")
    forbidden_keys = {
        "command",
        "entrypoint",
        "environment",
        "mounts",
        "networks",
        "ports",
        "secrets",
    }

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            forbidden = forbidden_keys.intersection(value)
            if forbidden:
                raise ContractError(
                    "deployment-plan probe contains renderer syntax: "
                    + ", ".join(sorted(forbidden))
                )
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(plan)
    return {
        COMPOSE_SERVICE_FOR_WORKLOAD[workload_id]: workload["image_identity"]
        for workload_id, workload in workload_by_id.items()
    }


def run_contract(compose_command: Sequence[str], fixture_root: Path) -> None:
    expected_images = validate_plan(
        fixture_root / "deployment-plan.probe.v1.json"
    )
    empty_env = fixture_root / "package/generated/compose.empty.env"
    if not empty_env.is_file() or empty_env.stat().st_size != 0:
        raise ContractError("compose.empty.env must exist and contain zero bytes")
    baseline = _compose_config(
        compose_command, fixture_root, "package/generated/compose.yaml"
    )
    assert_ordinary_model(baseline, expected_images)

    initialized = _compose_config(
        compose_command,
        fixture_root,
        "package/generated/compose.yaml",
        "package/generated/compose.initialize.yaml",
    )
    assert_initialization_model(initialized, baseline, expected_images)

    short_parent = _compose_config(
        compose_command, fixture_root, "parent-short/compose.yaml"
    )
    assert_parent_boundary(
        short_parent, baseline, expected_parent="parent-edge-client"
    )
    assert_edge_parent(short_parent)
    assert_relative_paths_match(baseline, short_parent)

    override_parent = _compose_config(
        compose_command, fixture_root, "parent-override/compose.yaml"
    )
    override_baseline = _compose_config(
        compose_command,
        fixture_root,
        "package/generated/compose.yaml",
        "package/operator-override.yaml",
    )
    assert_parent_boundary(
        override_parent, override_baseline, expected_parent="parent-edge-client"
    )
    assert_edge_parent(override_parent)
    assert_relative_paths_match(override_baseline, override_parent)
    override_labels = _labels(
        _services(override_parent)["registry-relay-public"]
    )
    if (
        override_labels.get("io.registrystack.probe.operator-override")
        != "enabled"
    ):
        raise ContractError("explicit include did not load the operator override")

    private_network = _compose_config(
        compose_command, fixture_root, "negative-private-network/compose.yaml"
    )
    assert_negative_boundary(private_network, baseline, "private-network")
    private_namespace = _compose_config(
        compose_command, fixture_root, "negative-private-namespace/compose.yaml"
    )
    assert_negative_boundary(private_namespace, baseline, "private-namespace")
    cross_owner = _compose_config(
        compose_command,
        fixture_root,
        "negative-cross-owner-mutation/compose.yaml",
    )
    assert_negative_boundary(cross_owner, baseline, "cross-owner-mutation")


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--compose-binary",
        type=Path,
        help="standalone Compose binary; default is the Docker Compose plugin",
    )
    parser.add_argument("--label", default="current")
    parser.add_argument("--fixture-root", type=Path, default=FIXTURE_ROOT)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    compose_command = (
        [str(args.compose_binary)]
        if args.compose_binary is not None
        else ["docker", "compose"]
    )
    try:
        run_contract(compose_command, args.fixture_root.resolve())
    except ContractError as error:
        print(f"adopter Compose conformance probe ({args.label}): FAIL: {error}")
        return 1
    print(f"adopter Compose conformance probe ({args.label}): PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
