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
COMPOSE_SECRET_FOR_CONSUMER = {
    "relay-public-tls": "registry-relay-public-tls",
    "relay-consultation-tls": "registry-relay-consultation-tls",
    "notary-tls": "registry-notary-tls",
    "notary-signing-key": "registry-notary-signing-key",
    "postgresql-tls": "registry-postgres-tls",
    "postgresql-credentials": "registry-postgres-credentials",
}
COMPOSE_STATE_FOR_ROLE = {
    "relay-public-anti-rollback": (
        "registry-relay-public-state",
        "/var/lib/registry/state",
    ),
    "relay-public-audit": (
        "registry-relay-public-audit",
        "/var/lib/registry/audit",
    ),
    "relay-consultation-anti-rollback": (
        "registry-relay-consultation-state",
        "/var/lib/registry/state",
    ),
    "relay-consultation-audit": (
        "registry-relay-consultation-audit",
        "/var/lib/registry/audit",
    ),
    "notary-anti-rollback": (
        "registry-notary-state",
        "/var/lib/registry/state",
    ),
    "notary-audit": (
        "registry-notary-audit",
        "/var/lib/registry/audit",
    ),
    "postgresql-data": (
        "registry-postgres-data",
        "/var/lib/postgresql/data",
    ),
}
EXPECTED_PLAN_WORKLOADS = {
    "relay-public": {
        "kind": "product",
        "product_lane": "relay-public",
        "action": "serve",
        "dependencies": [],
        "restart_action": "restart",
        "reactivation_action": "verify_state",
    },
    "relay-consultation": {
        "kind": "product",
        "product_lane": "relay-consultation",
        "action": "serve",
        "dependencies": [
            "postgresql-state-plane",
            "private-namespace-holder",
        ],
        "restart_action": "restart",
        "reactivation_action": "verify_state",
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
        "restart_action": "restart",
        "reactivation_action": "verify_state",
    },
    "postgresql-state-plane": {
        "kind": "supporting",
        "recipe": "postgresql_state_plane",
        "dependencies": ["private-namespace-holder"],
        "restart_action": "restart",
        "reactivation_action": "restore_consistency_group",
    },
    "private-namespace-holder": {
        "kind": "supporting",
        "recipe": "private_namespace_holder",
        "dependencies": [],
        "restart_action": "restart",
        "reactivation_action": "restart_consistency_group",
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
    expected_secrets: dict[str, set[str]] | None = None,
    expected_state_mounts: dict[str, set[tuple[str, str]]] | None = None,
    expected_generated_dir: Path | None = None,
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
        service = services[name]
        if (
            service.get("read_only") is not True
            or service.get("user") != "65532:65532"
            or service.get("cap_drop") != ["ALL"]
            or service.get("security_opt") != ["no-new-privileges:true"]
            or service.get("tmpfs") != ["/tmp"]
        ):
            raise ContractError(f"{name} does not use the product hardening profile")
        if (
            expected_images is not None
            and service.get("image") != expected_images[name]
        ):
            raise ContractError(f"{name} does not use its plan image identity")
        if expected_secrets is not None:
            actual_secrets = {
                secret.get("source")
                for secret in service.get("secrets", [])
                if isinstance(secret, dict)
            }
            if actual_secrets != expected_secrets[name]:
                raise ContractError(
                    f"{name} does not use its plan secret consumers"
                )
        if expected_state_mounts is not None:
            actual_state_mounts = {
                (mount.get("source"), mount.get("target"))
                for mount in service.get("volumes", [])
                if isinstance(mount, dict)
                and mount.get("type") == "volume"
                and mount.get("read_only") is not True
            }
            if actual_state_mounts != expected_state_mounts[name]:
                raise ContractError(f"{name} does not use its plan state roles")

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

    networks = model.get("networks")
    if not isinstance(networks, dict):
        raise ContractError("ordinary model has no networks object")
    private_network = networks.get(PRIVATE_NETWORK)
    if (
        not isinstance(private_network, dict)
        or private_network.get("internal") is not True
    ):
        raise ContractError("registry-private must remain an internal network")
    if private_network.get("name") != "registry-adopter-probe-private":
        raise ContractError("registry-private has the wrong stable name")
    edge_network = networks.get("registry-edge")
    if (
        not isinstance(edge_network, dict)
        or edge_network.get("name") != "registry-adopter-probe-edge"
        or edge_network.get("internal") is True
    ):
        raise ContractError("registry-edge has the wrong exposure contract")

    expected_network_modes = {
        "registry-postgres": PRIVATE_NAMESPACE,
        "registry-relay-consultation": PRIVATE_NAMESPACE,
        "registry-notary": PRIVATE_NAMESPACE,
    }
    for service_name, expected_mode in expected_network_modes.items():
        if services[service_name].get("network_mode") != expected_mode:
            raise ContractError(
                f"{service_name} left the private product namespace"
            )
    holder_networks = services["registry-private-namespace"].get("networks", {})
    if set(holder_networks) != {PRIVATE_NETWORK}:
        raise ContractError("private namespace holder has the wrong network")
    public_networks = services["registry-relay-public"].get("networks", {})
    if set(public_networks) != {"registry-edge"}:
        raise ContractError("public Relay has the wrong network")

    if expected_generated_dir is not None:
        if expected_secrets is None or expected_state_mounts is None:
            raise ContractError("ordinary model plan projections are incomplete")
        expected_inputs = {
            "registry-relay-public": "relay-public",
            "registry-relay-consultation": "relay-consultation",
            "registry-notary": "notary",
        }
        for service_name, lane in expected_inputs.items():
            input_mounts = {
                mount.get("target"): mount
                for mount in services[service_name].get("volumes", [])
                if isinstance(mount, dict)
                and mount.get("target")
                in {"/run/registry/bundle", "/run/registry/anchor"}
            }
            expected_mounts = {
                "/run/registry/bundle": expected_generated_dir
                / "bundles"
                / lane,
                "/run/registry/anchor": expected_generated_dir
                / "anchors"
                / lane,
            }
            if set(input_mounts) != set(expected_mounts):
                raise ContractError(
                    f"{service_name} has the wrong immutable input mounts"
                )
            for target, expected_source in expected_mounts.items():
                mount = input_mounts[target]
                if (
                    mount.get("type") != "bind"
                    or mount.get("source") != str(expected_source)
                    or mount.get("read_only") is not True
                    or mount.get("bind", {}).get("create_host_path") is not False
                ):
                    raise ContractError(
                        f"{service_name} has an unsafe {target} mount"
                    )

        declared_secrets = model.get("secrets")
        expected_secret_names = {
            secret_name
            for service_secrets in expected_secrets.values()
            for secret_name in service_secrets
        }
        if (
            not isinstance(declared_secrets, dict)
            or set(declared_secrets) != expected_secret_names
        ):
            raise ContractError(
                "ordinary model secret definitions do not match the plan"
            )
        declared_volumes = model.get("volumes")
        expected_volume_names = {
            source
            for service_mounts in expected_state_mounts.values()
            for source, _target in service_mounts
        }
        if (
            not isinstance(declared_volumes, dict)
            or set(declared_volumes) != expected_volume_names
        ):
            raise ContractError(
                "ordinary model volume definitions do not match the plan"
            )


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
        if services[service_name].get("restart") != "no":
            raise ContractError(f"{service_name} is not a one-shot service")
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
    protected_secret_names = {
        definition.get("name")
        for definition in baseline.get("secrets", {}).values()
        if isinstance(definition, dict)
    } - {None}
    protected_volume_names = {
        definition.get("name")
        for definition in baseline.get("volumes", {}).values()
        if isinstance(definition, dict)
    } - {None}
    private_network_definition = baseline.get("networks", {}).get(PRIVATE_NETWORK, {})
    private_network_name = (
        private_network_definition.get("name")
        if isinstance(private_network_definition, dict)
        else None
    )
    private_namespace_members = {
        "registry-private-namespace",
        "registry-postgres",
        "registry-relay-consultation",
        "registry-notary",
    }
    for name in parent_services:
        service = services[name]
        networks = service.get("networks", {})
        if isinstance(networks, list):
            network_names = set(networks)
        elif isinstance(networks, dict):
            network_names = set(networks)
        else:
            network_names = set()
        effective_network_names = {
            model.get("networks", {}).get(network, {}).get("name")
            for network in network_names
            if isinstance(model.get("networks", {}).get(network), dict)
        } - {None}
        if (
            PRIVATE_NETWORK in network_names
            or private_network_name in effective_network_names
        ):
            raise ContractError(f"parent service {name} joined the private network")
        network_mode = service.get("network_mode")
        shared_service = (
            network_mode.removeprefix("service:")
            if isinstance(network_mode, str) and network_mode.startswith("service:")
            else None
        )
        if shared_service in private_namespace_members or (
            isinstance(network_mode, str)
            and network_mode.startswith("container:")
        ):
            raise ContractError(f"parent service {name} joined the private namespace")
        inherited_services = {
            str(source).split(":", 1)[0]
            for source in service.get("volumes_from", [])
        }
        if inherited_services.intersection(PRODUCT_SERVICES):
            raise ContractError(
                f"parent service {name} inherited renderer-owned volumes"
            )
        consumed_secret_names = {
            model.get("secrets", {}).get(secret.get("source"), {}).get("name")
            for secret in service.get("secrets", [])
            if isinstance(secret, dict)
            and isinstance(model.get("secrets", {}).get(secret.get("source")), dict)
        } - {None}
        if consumed_secret_names.intersection(protected_secret_names):
            raise ContractError(
                f"parent service {name} consumed a renderer-owned secret"
            )
        consumed_volume_names = {
            model.get("volumes", {}).get(mount.get("source"), {}).get("name")
            for mount in service.get("volumes", [])
            if isinstance(mount, dict)
            and mount.get("type") == "volume"
            and isinstance(model.get("volumes", {}).get(mount.get("source")), dict)
        } - {None}
        if consumed_volume_names.intersection(protected_volume_names):
            raise ContractError(
                f"parent service {name} consumed a renderer-owned volume"
            )


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


def assert_parent_rejected(
    model: dict[str, Any],
    baseline: dict[str, Any],
    expected_message: str,
) -> None:
    try:
        assert_parent_boundary(
            model,
            baseline,
            expected_parent="parent-private-client",
        )
    except ContractError as error:
        if expected_message not in str(error):
            raise ContractError(
                f"negative fixture failed for the wrong reason: {error}"
            ) from error
        return
    raise ContractError(
        f"negative fixture was accepted instead of reporting: {expected_message}"
    )


def validate_plan(
    plan_path: Path,
) -> tuple[
    dict[str, str],
    dict[str, set[str]],
    dict[str, set[tuple[str, str]]],
]:
    try:
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ContractError(f"invalid deployment-plan probe: {error}") from error
    if plan.get("schema") != "io.registrystack.deployment-plan.probe.v1":
        raise ContractError("deployment-plan probe has the wrong schema")
    expected_root_fields = {
        "schema",
        "single_instance",
        "workloads",
        "initialization_actions",
        "private_co_location_groups",
        "recovery_consistency_groups",
        "exposure_requirements",
    }
    if set(plan) != expected_root_fields:
        raise ContractError("deployment-plan probe has unsupported root fields")
    if plan.get("single_instance") is not True:
        raise ContractError("deployment-plan probe must remain single-instance")
    workloads = plan.get("workloads")
    if not isinstance(workloads, list) or len(workloads) != len(PRODUCT_SERVICES):
        raise ContractError("deployment-plan probe must describe all five workloads")
    workload_by_id = {workload.get("id"): workload for workload in workloads}
    if set(workload_by_id) != set(EXPECTED_PLAN_WORKLOADS):
        raise ContractError("deployment-plan probe workload inventory is incomplete")
    for workload_id, expected in EXPECTED_PLAN_WORKLOADS.items():
        workload = workload_by_id[workload_id]
        expected_workload_fields = {
            "id",
            "kind",
            "image_identity",
            "secret_consumers",
            "state_roles",
            "endpoint_classes",
            "network_relationships",
            "dependencies",
            "health_semantics",
            "restart_action",
            "reactivation_action",
        }
        if workload.get("kind") == "product":
            expected_workload_fields.update(
                {"product_lane", "action", "immutable_inputs", "mount_roles"}
            )
        elif workload.get("kind") == "supporting":
            expected_workload_fields.add("recipe")
        if set(workload) != expected_workload_fields:
            unexpected = set(workload).difference(expected_workload_fields)
            missing = expected_workload_fields.difference(workload)
            raise ContractError(
                f"deployment-plan probe has unsupported fields for {workload_id}: "
                f"unexpected={','.join(sorted(unexpected)) or 'none'}; "
                f"missing={','.join(sorted(missing)) or 'none'}"
            )
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
    if any(
        not isinstance(action, dict)
        or set(action) != {"id", "workload", "action"}
        for action in initialization_actions
    ):
        raise ContractError("deployment-plan probe initialization fields are wrong")
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
    expected_exposure_requirements = {
        "public-application": "operator-bound",
        "private-application": "private-namespace-only",
        "administration": "loopback-only",
        "metrics": "loopback-only",
        "posture": "loopback-only",
    }
    if (
        not isinstance(exposure_requirements, list)
        or any(
            not isinstance(item, dict)
            or set(item) != {"endpoint_class", "exposure"}
            for item in exposure_requirements
        )
        or {
        item.get("endpoint_class"): item.get("exposure")
        for item in exposure_requirements
        if isinstance(item, dict)
        }
        != expected_exposure_requirements
    ):
        raise ContractError("deployment-plan probe endpoint inventory is incomplete")
    forbidden_keys = {
        "command",
        "entrypoint",
        "environment",
        "mounts",
        "networks",
        "ports",
        "secrets",
        "volumes",
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
    expected_images = {
        COMPOSE_SERVICE_FOR_WORKLOAD[workload_id]: workload["image_identity"]
        for workload_id, workload in workload_by_id.items()
    }
    expected_secrets = {
        COMPOSE_SERVICE_FOR_WORKLOAD[workload_id]: {
            COMPOSE_SECRET_FOR_CONSUMER[consumer]
            for consumer in workload.get("secret_consumers", [])
        }
        for workload_id, workload in workload_by_id.items()
    }
    expected_state_mounts = {
        COMPOSE_SERVICE_FOR_WORKLOAD[workload_id]: {
            COMPOSE_STATE_FOR_ROLE[role]
            for role in workload.get("state_roles", [])
        }
        for workload_id, workload in workload_by_id.items()
    }
    return expected_images, expected_secrets, expected_state_mounts


def run_contract(compose_command: Sequence[str], fixture_root: Path) -> None:
    expected_images, expected_secrets, expected_state_mounts = validate_plan(
        fixture_root / "deployment-plan.probe.v1.json"
    )
    empty_env = fixture_root / "package/generated/compose.empty.env"
    if not empty_env.is_file() or empty_env.stat().st_size != 0:
        raise ContractError("compose.empty.env must exist and contain zero bytes")
    baseline = _compose_config(
        compose_command, fixture_root, "package/generated/compose.yaml"
    )
    assert_ordinary_model(
        baseline,
        expected_images,
        expected_secrets,
        expected_state_mounts,
        (fixture_root / "package/generated").resolve(),
    )

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
    private_alias = _compose_config(
        compose_command,
        fixture_root,
        "negative-private-network-alias/compose.yaml",
    )
    assert_parent_rejected(private_alias, baseline, "joined the private network")
    private_service = _compose_config(
        compose_command,
        fixture_root,
        "negative-private-service-namespace/compose.yaml",
    )
    assert_parent_rejected(private_service, baseline, "joined the private namespace")
    owned_resources = _compose_config(
        compose_command,
        fixture_root,
        "negative-owned-resources/compose.yaml",
    )
    assert_parent_rejected(
        owned_resources,
        baseline,
        "consumed a renderer-owned secret",
    )
    owned_volume = _compose_config(
        compose_command,
        fixture_root,
        "negative-owned-volume/compose.yaml",
    )
    assert_parent_rejected(
        owned_volume,
        baseline,
        "consumed a renderer-owned volume",
    )
    container_namespace = _compose_config(
        compose_command,
        fixture_root,
        "negative-container-namespace/compose.yaml",
    )
    assert_parent_rejected(
        container_namespace,
        baseline,
        "joined the private namespace",
    )
    volumes_from = _compose_config(
        compose_command,
        fixture_root,
        "negative-volumes-from/compose.yaml",
    )
    assert_parent_rejected(
        volumes_from,
        baseline,
        "inherited renderer-owned volumes",
    )


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
