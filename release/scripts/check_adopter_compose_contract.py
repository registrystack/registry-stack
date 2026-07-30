#!/usr/bin/env python3
"""Validate the package-only adopter Compose conformance fixtures."""

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
PROJECT_NAME = "registry-adopter-probe"
NETWORK_RUNTIME = "registry-runtime"
IMAGE_IDENTITY = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
SENTINEL_FRAGMENT = "value-must-not-enter-compose"

WORKLOAD_SERVICES = frozenset(
    {
        "registry-postgres",
        "registry-relay-public",
        "registry-relay-consultation",
        "registry-notary",
    }
)
STAGER_SERVICES = frozenset(
    {
        "registry-postgresql-stage-secrets",
        "registry-relay-public-stage-secrets",
        "registry-relay-consultation-stage-secrets",
        "registry-notary-stage-secrets",
    }
)
ORDINARY_SERVICES = WORKLOAD_SERVICES | STAGER_SERVICES
INITIALIZATION_SERVICES = frozenset(
    {
        "registry-postgres-bootstrap",
        "registry-relay-public-prepare-state",
        "registry-relay-consultation-prepare-state",
        "registry-notary-prepare-state",
        "registry-relay-public-initialize",
        "registry-relay-consultation-initialize",
        "registry-notary-initialize",
    }
)

OPERATOR_ENVIRONMENT_FILES = frozenset(
    {
        "relay-public-environment",
        "relay-consultation-environment",
        "notary-environment",
        "postgresql-bootstrap-environment",
    }
)
OPERATOR_SECRET_FILES = frozenset(
    {
        "notary-relay-workload-credential",
        "notary-signing-key",
        "notary-tls-certificate",
        "notary-tls-private-key",
        "postgresql-admin-password",
        "postgresql-tls-certificate",
        "postgresql-tls-private-key",
        "relay-consultation-tls-certificate",
        "relay-consultation-tls-private-key",
        "relay-public-tls-certificate",
        "relay-public-tls-private-key",
    }
)
EXPECTED_OPERATOR_FILES = OPERATOR_ENVIRONMENT_FILES | OPERATOR_SECRET_FILES

LANE_ENVIRONMENTS = {
    "registry-relay-public": "relay-public-environment",
    "registry-relay-consultation": "relay-consultation-environment",
    "registry-notary": "notary-environment",
}
ORDINARY_COMMANDS = {
    "registry-postgres": ["postgres"],
    "registry-relay-public": ["product-action", "relay-public", "serve"],
    "registry-relay-consultation": [
        "product-action",
        "relay-consultation",
        "serve",
    ],
    "registry-notary": ["product-action", "serve"],
}
ORDINARY_DEPENDENCIES = {
    "registry-postgres": {
        "registry-postgresql-stage-secrets": "service_completed_successfully"
    },
    "registry-relay-public": {
        "registry-relay-public-stage-secrets": "service_completed_successfully"
    },
    "registry-relay-consultation": {
        "registry-postgres": "service_healthy",
        "registry-relay-consultation-stage-secrets": ("service_completed_successfully"),
    },
    "registry-notary": {
        "registry-postgres": "service_healthy",
        "registry-relay-consultation": "service_healthy",
        "registry-notary-stage-secrets": "service_completed_successfully",
    },
}
INITIALIZATION_COMMANDS = {
    "registry-postgres-bootstrap": ["postgresql-action", "bootstrap"],
    "registry-relay-public-prepare-state": [
        "product-action",
        "relay-public",
        "prepare_state_store",
    ],
    "registry-relay-consultation-prepare-state": [
        "product-action",
        "relay-consultation",
        "prepare_state_store",
    ],
    "registry-notary-prepare-state": [
        "product-action",
        "prepare_state_store",
    ],
    "registry-relay-public-initialize": [
        "product-action",
        "relay-public",
        "initialize_state",
    ],
    "registry-relay-consultation-initialize": [
        "product-action",
        "relay-consultation",
        "initialize_state",
    ],
    "registry-notary-initialize": ["product-action", "initialize_state"],
}
INITIALIZATION_METADATA = {
    "registry-relay-public-prepare-state": (
        "registry-relay-public",
        "relay-public",
        "prepare",
    ),
    "registry-relay-consultation-prepare-state": (
        "registry-relay-consultation",
        "relay-consultation",
        "prepare",
    ),
    "registry-notary-prepare-state": (
        "registry-notary",
        "notary",
        "prepare",
    ),
    "registry-relay-public-initialize": (
        "registry-relay-public",
        "relay-public",
        "initialize",
    ),
    "registry-relay-consultation-initialize": (
        "registry-relay-consultation",
        "relay-consultation",
        "initialize",
    ),
    "registry-notary-initialize": (
        "registry-notary",
        "notary",
        "initialize",
    ),
}
INITIALIZATION_DEPENDENCIES = {
    "registry-relay-public-prepare-state": {},
    "registry-relay-public-initialize": {},
    "registry-relay-consultation-prepare-state": {
        "registry-postgres": "service_healthy",
        "registry-relay-consultation-stage-secrets": ("service_completed_successfully"),
    },
    "registry-relay-consultation-initialize": {
        "registry-postgres": "service_healthy",
        "registry-relay-consultation-stage-secrets": ("service_completed_successfully"),
    },
    "registry-notary-prepare-state": {
        "registry-postgres": "service_healthy",
        "registry-notary-stage-secrets": "service_completed_successfully",
    },
    "registry-notary-initialize": {
        "registry-postgres": "service_healthy",
        "registry-notary-stage-secrets": "service_completed_successfully",
    },
}

STAGER_COMMAND = ["umask 077\nexit 0\n"]
STAGER_SPECS = {
    "registry-postgresql-stage-secrets": {
        "outputs": {
            "postgresql-serve": "registry-operator-files-postgresql-serve",
            "postgresql-bootstrap": ("registry-operator-files-postgresql-bootstrap"),
        },
        "secrets": {
            "registry-postgresql-admin-password",
            "registry-postgresql-tls-certificate",
            "registry-postgresql-tls-private-key",
        },
    },
    "registry-relay-public-stage-secrets": {
        "outputs": {
            "relay-public-serve": ("registry-operator-files-relay-public-serve"),
        },
        "secrets": {
            "registry-relay-public-tls-certificate",
            "registry-relay-public-tls-private-key",
        },
    },
    "registry-relay-consultation-stage-secrets": {
        "outputs": {
            "relay-consultation-serve": (
                "registry-operator-files-relay-consultation-serve"
            ),
            "relay-consultation-prepare": (
                "registry-operator-files-relay-consultation-prepare"
            ),
            "relay-consultation-initialize": (
                "registry-operator-files-relay-consultation-initialize"
            ),
        },
        "secrets": {
            "registry-postgresql-tls-certificate",
            "registry-relay-consultation-tls-certificate",
            "registry-relay-consultation-tls-private-key",
        },
    },
    "registry-notary-stage-secrets": {
        "outputs": {
            "notary-serve": "registry-operator-files-notary-serve",
            "notary-prepare": "registry-operator-files-notary-prepare",
            "notary-initialize": "registry-operator-files-notary-initialize",
        },
        "secrets": {
            "registry-notary-relay-workload-credential",
            "registry-notary-signing-key",
            "registry-notary-tls-certificate",
            "registry-notary-tls-private-key",
            "registry-postgresql-tls-certificate",
            "registry-relay-consultation-tls-certificate",
        },
    },
}

DURABLE_VOLUMES = frozenset(
    {
        "registry-postgresql-data",
        "registry-relay-public-state",
        "registry-relay-public-audit",
        "registry-relay-consultation-state",
        "registry-relay-consultation-audit",
        "registry-notary-state",
        "registry-notary-audit",
    }
)
STAGED_SECRET_VOLUMES = frozenset(
    volume for spec in STAGER_SPECS.values() for volume in spec["outputs"].values()
)
EXPECTED_VOLUMES = DURABLE_VOLUMES | STAGED_SECRET_VOLUMES

EXPECTED_PLAN_WORKLOADS = {
    "relay-public": {
        "kind": "product",
        "product_lane": "relay-public",
        "action": "serve",
        "immutable_inputs": [
            "relay-public-bundle",
            "relay-public-anchor",
        ],
        "mount_roles": [
            "bundle",
            "anchor",
            "anti-rollback-state",
            "certificate",
            "audit",
        ],
        "secret_consumers": ["relay-public-tls"],
        "state_roles": [
            "relay-public-anti-rollback",
            "relay-public-audit",
        ],
        "endpoint_classes": ["public-application", "posture"],
        "network_relationships": ["runtime"],
        "dependencies": [],
        "health_semantics": "relay-public-health",
        "restart_action": "restart",
        "reactivation_action": "verify_state",
    },
    "relay-consultation": {
        "kind": "product",
        "product_lane": "relay-consultation",
        "action": "serve",
        "immutable_inputs": [
            "relay-consultation-bundle",
            "relay-consultation-anchor",
        ],
        "mount_roles": [
            "bundle",
            "anchor",
            "anti-rollback-state",
            "certificate",
            "audit",
        ],
        "secret_consumers": ["relay-consultation-tls"],
        "state_roles": [
            "relay-consultation-anti-rollback",
            "relay-consultation-audit",
        ],
        "endpoint_classes": ["private-application", "posture"],
        "network_relationships": ["runtime"],
        "dependencies": ["postgresql-state-plane"],
        "health_semantics": "relay-consultation-health",
        "restart_action": "restart",
        "reactivation_action": "verify_state",
    },
    "notary": {
        "kind": "product",
        "product_lane": "notary",
        "action": "serve",
        "immutable_inputs": ["notary-bundle", "notary-anchor"],
        "mount_roles": [
            "bundle",
            "anchor",
            "anti-rollback-state",
            "secret",
            "certificate",
            "audit",
        ],
        "secret_consumers": ["notary-tls", "notary-signing-key"],
        "state_roles": ["notary-anti-rollback", "notary-audit"],
        "endpoint_classes": [
            "public-application",
            "administration",
            "posture",
        ],
        "network_relationships": ["runtime"],
        "dependencies": [
            "relay-consultation",
            "postgresql-state-plane",
        ],
        "health_semantics": "notary-health",
        "restart_action": "restart",
        "reactivation_action": "verify_state",
    },
    "postgresql-state-plane": {
        "kind": "supporting",
        "recipe": "postgresql_state_plane",
        "secret_consumers": [
            "postgresql-tls",
            "postgresql-credentials",
        ],
        "state_roles": ["postgresql-data"],
        "endpoint_classes": ["private-application"],
        "network_relationships": ["runtime"],
        "dependencies": [],
        "health_semantics": "postgresql-health",
        "restart_action": "restart",
        "reactivation_action": "restore_consistency_group",
    },
}
EXPECTED_INITIALIZATION_ACTIONS = [
    {
        "id": "bootstrap-postgresql-state-plane",
        "workload": "postgresql-state-plane",
        "action": "bootstrap_state_plane",
    },
    {
        "id": "prepare-relay-public-state",
        "workload": "relay-public",
        "action": "prepare_state_store",
    },
    {
        "id": "prepare-relay-consultation-state",
        "workload": "relay-consultation",
        "action": "prepare_state_store",
    },
    {
        "id": "prepare-notary-state",
        "workload": "notary",
        "action": "prepare_state_store",
    },
    {
        "id": "initialize-relay-public",
        "workload": "relay-public",
        "action": "initialize_state",
    },
    {
        "id": "initialize-relay-consultation",
        "workload": "relay-consultation",
        "action": "initialize_state",
    },
    {
        "id": "initialize-notary",
        "workload": "notary",
        "action": "initialize_state",
    },
]
EXPECTED_RECOVERY_GROUPS = [
    {
        "id": "consultation-state",
        "members": [
            "relay-consultation",
            "notary",
            "postgresql-state-plane",
        ],
    },
    {"id": "relay-public-state", "members": ["relay-public"]},
]
EXPECTED_EXPOSURES = [
    {
        "endpoint_class": "public-application",
        "exposure": "operator-bound",
    },
    {
        "endpoint_class": "private-application",
        "exposure": "private-network-only",
    },
    {
        "endpoint_class": "administration",
        "exposure": "private-network-only",
    },
    {
        "endpoint_class": "posture",
        "exposure": "private-network-only",
    },
]


class ContractError(RuntimeError):
    """Raised when a normalized fixture violates the package contract."""


def _compose_config(
    compose_command: Sequence[str], fixture_root: Path, *files: str
) -> dict[str, Any]:
    command = [
        *compose_command,
        "--project-name",
        PROJECT_NAME,
        "--env-file",
        str(fixture_root / "package/generated/compose.empty.env"),
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
        env={**os.environ, "COMPOSE_IGNORE_ORPHANS": "true"},
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        diagnostic = (result.stderr or result.stdout).strip()
        raise ContractError(
            f"Compose normalization failed for {', '.join(files)}: {diagnostic[:1200]}"
        )
    try:
        model = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ContractError("Compose returned invalid JSON") from error
    if not isinstance(model, dict):
        raise ContractError("Compose effective model must be an object")
    return model


def _services(model: dict[str, Any]) -> dict[str, Any]:
    services = model.get("services")
    if not isinstance(services, dict):
        raise ContractError("Compose effective model has no services object")
    return services


def _env_file_paths(service: dict[str, Any]) -> list[Path]:
    env_files = service.get("env_file", [])
    if not isinstance(env_files, list):
        raise ContractError("service env_file must remain a list")
    paths = []
    for entry in env_files:
        path = entry.get("path") if isinstance(entry, dict) else entry
        if not isinstance(path, str):
            raise ContractError("service env_file entry has no path")
        paths.append(Path(path))
    return paths


def _dependencies(service: dict[str, Any]) -> dict[str, str]:
    dependencies = service.get("depends_on", {})
    if not isinstance(dependencies, dict):
        raise ContractError("service dependencies must remain an object")
    observed: dict[str, str] = {}
    for name, dependency in dependencies.items():
        if (
            not isinstance(dependency, dict)
            or dependency.get("required") is not True
            or not isinstance(dependency.get("condition"), str)
        ):
            raise ContractError("service dependency lost its required condition")
        observed[name] = dependency["condition"]
    return observed


def _mounts(service: dict[str, Any]) -> dict[str, dict[str, Any]]:
    volumes = service.get("volumes", [])
    if not isinstance(volumes, list):
        raise ContractError("service volumes must remain a list")
    mounts: dict[str, dict[str, Any]] = {}
    for mount in volumes:
        target = mount.get("target") if isinstance(mount, dict) else None
        if not isinstance(target, str) or target in mounts:
            raise ContractError("service mount targets are invalid or duplicated")
        mounts[target] = mount
    return mounts


def _secret_projections(service: dict[str, Any]) -> dict[str, str]:
    secrets = service.get("secrets", [])
    if not isinstance(secrets, list):
        raise ContractError("service secrets must remain a list")
    projections = {}
    for secret in secrets:
        source = secret.get("source") if isinstance(secret, dict) else None
        target = secret.get("target") if isinstance(secret, dict) else None
        if (
            not isinstance(source, str)
            or not isinstance(target, str)
            or source in projections
        ):
            raise ContractError("service secret sources are invalid or duplicated")
        projections[source] = target
    return projections


def _assert_product_hardening(
    name: str, service: dict[str, Any], *, healthcheck: bool
) -> None:
    if (
        service.get("user") != "65532:65532"
        or service.get("read_only") is not True
        or service.get("cap_drop") != ["ALL"]
        or service.get("security_opt") != ["no-new-privileges:true"]
        or service.get("tmpfs") != ["/tmp"]
        or "cap_add" in service
    ):
        raise ContractError(f"{name} lost product hardening")
    expected_healthcheck = (
        {
            "test": ["CMD", "/conformance-only-healthcheck"],
            "interval": "30s",
            "timeout": "5s",
            "retries": 3,
        }
        if healthcheck
        else None
    )
    if service.get("healthcheck") != expected_healthcheck:
        raise ContractError(f"{name} has the wrong healthcheck boundary")


def _assert_postgresql_hardening(
    name: str, service: dict[str, Any], *, healthcheck: bool
) -> None:
    if (
        service.get("user") != "999:999"
        or service.get("read_only") is not True
        or service.get("cap_drop") != ["ALL"]
        or service.get("security_opt") != ["no-new-privileges:true"]
        or service.get("tmpfs")
        != ["/tmp", "/var/run/postgresql:uid=999,gid=999,mode=0750"]
        or "cap_add" in service
    ):
        raise ContractError(f"{name} lost PostgreSQL hardening")
    expected_healthcheck = (
        {
            "test": ["CMD", "/conformance-only-healthcheck"],
            "interval": "30s",
            "timeout": "5s",
            "retries": 3,
        }
        if healthcheck
        else None
    )
    if service.get("healthcheck") != expected_healthcheck:
        raise ContractError(f"{name} has the wrong healthcheck boundary")


def _assert_volume_mount(
    mount: dict[str, Any], source: str, *, read_only: bool
) -> None:
    if (
        mount.get("type") != "volume"
        or mount.get("source") != source
        or bool(mount.get("read_only", False)) is not read_only
    ):
        raise ContractError("managed volume mount contract changed")


def _assert_product_mounts(
    name: str,
    service: dict[str, Any],
    lane: str,
    *,
    action: str,
) -> None:
    mounts = _mounts(service)
    expected_targets = {
        "/run/registry/bundle",
        "/run/registry/anchor",
        "/var/lib/registry/audit",
    }
    if action != "prepare":
        expected_targets.add("/var/lib/registry/state")
    secret_volume = f"registry-operator-files-{lane}-{action}"
    if secret_volume in STAGED_SECRET_VOLUMES:
        expected_targets.add("/run/secrets")
    if set(mounts) != expected_targets:
        raise ContractError(f"{name} has the wrong protected mount inventory")
    for target, kind in (
        ("/run/registry/bundle", "bundles"),
        ("/run/registry/anchor", "anchors"),
    ):
        mount = mounts[target]
        source = mount.get("source")
        path_parts = Path(source).parts if isinstance(source, str) else ()
        if kind == "bundles":
            lane_owned = path_parts[-2:] == ("bundles", lane) or (
                len(path_parts) >= 3
                and path_parts[-3:-1] == ("bundles", lane)
                and re.fullmatch(r"[0-9a-f]{64}", path_parts[-1]) is not None
            )
        else:
            lane_owned = path_parts[-2:] == ("anchors", lane)
        if (
            mount.get("type") != "bind"
            or mount.get("read_only") is not True
            or mount.get("bind") != {"create_host_path": False}
            or not lane_owned
        ):
            raise ContractError(f"{name} lost its lane-owned {kind} bind")
    if "/var/lib/registry/state" in mounts:
        _assert_volume_mount(
            mounts["/var/lib/registry/state"],
            f"registry-{lane}-state",
            read_only=False,
        )
    _assert_volume_mount(
        mounts["/var/lib/registry/audit"],
        f"registry-{lane}-audit",
        read_only=False,
    )
    if "/run/secrets" in mounts:
        _assert_volume_mount(
            mounts["/run/secrets"],
            secret_volume,
            read_only=True,
        )


def _assert_stager(
    name: str,
    service: dict[str, Any],
    *,
    postgresql_image: str,
) -> None:
    spec = STAGER_SPECS[name]
    if (
        service.get("image") != postgresql_image
        or service.get("entrypoint") != ["/bin/sh", "-ceu"]
        or service.get("command") != STAGER_COMMAND
        or service.get("user") != "0:0"
        or service.get("read_only") is not True
        or service.get("cap_drop") != ["ALL"]
        or service.get("cap_add") != ["CHOWN"]
        or service.get("security_opt") != ["no-new-privileges:true"]
        or service.get("tmpfs") != ["/tmp"]
        or service.get("network_mode") != "none"
        or service.get("restart") != "no"
        or service.get("privileged", False) is not False
    ):
        raise ContractError(f"{name} lost its isolated CHOWN contract")
    for forbidden in (
        "depends_on",
        "env_file",
        "healthcheck",
        "networks",
        "ports",
    ):
        if forbidden in service:
            raise ContractError(f"{name} gained forbidden {forbidden} authority")
    expected_mounts = {
        f"/registryctl-stage/output/{action}": volume
        for action, volume in spec["outputs"].items()
    }
    mounts = _mounts(service)
    if set(mounts) != set(expected_mounts):
        raise ContractError(f"{name} gained cross-lane output authority")
    for target, source in expected_mounts.items():
        _assert_volume_mount(mounts[target], source, read_only=False)
    expected_secrets = {
        source: source.removeprefix("registry-") for source in spec["secrets"]
    }
    if _secret_projections(service) != expected_secrets:
        raise ContractError(f"{name} gained cross-lane input authority")


def _assert_operator_file_inventory(model: dict[str, Any], fixture_root: Path) -> None:
    expected_directory = (fixture_root / "package/operator/secrets").resolve()
    observed_environment_files = set()
    for service in _services(model).values():
        if not isinstance(service, dict):
            raise ContractError("service is not an object")
        for path in _env_file_paths(service):
            if path.parent == expected_directory:
                observed_environment_files.add(path.name)
    ordinary_environments = OPERATOR_ENVIRONMENT_FILES - {
        "postgresql-bootstrap-environment"
    }
    if observed_environment_files != ordinary_environments:
        raise ContractError("package has the wrong operator environment files")
    declared_secrets = model.get("secrets")
    expected_names = {f"registry-{name}" for name in OPERATOR_SECRET_FILES}
    if (
        not isinstance(declared_secrets, dict)
        or set(declared_secrets) != expected_names
    ):
        raise ContractError("package has the wrong operator secret definitions")
    observed_secret_files = set()
    for name, definition in declared_secrets.items():
        path = definition.get("file") if isinstance(definition, dict) else None
        if (
            not isinstance(path, str)
            or Path(path).parent != expected_directory
            or Path(path).name != name.removeprefix("registry-")
        ):
            raise ContractError("operator secret escaped package/operator/secrets")
        observed_secret_files.add(Path(path).name)
    if observed_environment_files | observed_secret_files != (
        EXPECTED_OPERATOR_FILES - {"postgresql-bootstrap-environment"}
    ):
        raise ContractError("package operator-file inventory is incomplete")


def _assert_top_level_resources(model: dict[str, Any]) -> None:
    networks = model.get("networks")
    if not isinstance(networks, dict) or set(networks) != {NETWORK_RUNTIME}:
        raise ContractError("package must use exactly one ordinary runtime network")
    network = networks[NETWORK_RUNTIME]
    if (
        not isinstance(network, dict)
        or network.get("internal") is True
        or network.get("external") is True
        or set(network) - {"name"}
        or network.get("name") != f"{PROJECT_NAME}_{NETWORK_RUNTIME}"
    ):
        raise ContractError("runtime network gained managed isolation")
    volumes = model.get("volumes")
    if not isinstance(volumes, dict) or set(volumes) != EXPECTED_VOLUMES:
        raise ContractError("package has the wrong closed volume inventory")


def assert_value_free(model: dict[str, Any]) -> None:
    rendered = json.dumps(model, sort_keys=True)
    if SENTINEL_FRAGMENT in rendered:
        raise ContractError("Compose config resolved an operator sentinel value")
    for name, service in _services(model).items():
        if not isinstance(service, dict):
            raise ContractError(f"service {name} is not an object")
        if "environment" in service:
            raise ContractError(f"service {name} resolved environment values")


def validate_plan(path: Path) -> dict[str, str]:
    try:
        plan = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ContractError("deployment plan probe is not valid JSON") from error
    expected_root_fields = {
        "schema_id",
        "schema_version",
        "single_instance",
        "workloads",
        "initialization_actions",
        "recovery_consistency_groups",
        "exposure_requirements",
    }
    if (
        not isinstance(plan, dict)
        or set(plan) != expected_root_fields
        or plan.get("schema_id") != "io.registrystack.deployment_plan"
        or plan.get("schema_version") != "1.0"
        or plan.get("single_instance") is not True
    ):
        raise ContractError("deployment plan probe has the wrong closed schema")
    workloads = plan.get("workloads")
    if not isinstance(workloads, list) or len(workloads) != 4:
        raise ContractError("deployment plan must contain exactly four workloads")
    images: dict[str, str] = {}
    services = {
        "relay-public": "registry-relay-public",
        "relay-consultation": "registry-relay-consultation",
        "notary": "registry-notary",
        "postgresql-state-plane": "registry-postgres",
    }
    observed_ids = set()
    for workload in workloads:
        if not isinstance(workload, dict):
            raise ContractError("deployment plan workload is not an object")
        workload_id = workload.get("id")
        expected = EXPECTED_PLAN_WORKLOADS.get(workload_id)
        image = workload.get("image_identity")
        if (
            expected is None
            or workload_id in observed_ids
            or set(workload) != {"id", "image_identity", *expected}
            or {key: workload.get(key) for key in expected} != expected
            or not isinstance(image, str)
            or IMAGE_IDENTITY.fullmatch(image) is None
        ):
            raise ContractError(
                f"deployment plan has the wrong closed workload {workload_id}"
            )
        observed_ids.add(workload_id)
        images[services[workload_id]] = image
    if observed_ids != set(EXPECTED_PLAN_WORKLOADS):
        raise ContractError("deployment plan workload inventory is incomplete")
    if images["registry-relay-public"] != images["registry-relay-consultation"]:
        raise ContractError("deployment plan Relay workloads use different images")
    if plan.get("initialization_actions") != EXPECTED_INITIALIZATION_ACTIONS:
        raise ContractError("deployment plan initialization inventory is stale")
    if plan.get("recovery_consistency_groups") != EXPECTED_RECOVERY_GROUPS:
        raise ContractError("deployment plan recovery inventory is stale")
    if plan.get("exposure_requirements") != EXPECTED_EXPOSURES:
        raise ContractError("deployment plan exposure inventory is stale")
    return images


def assert_ordinary_model(
    model: dict[str, Any],
    expected_images: dict[str, str],
    fixture_root: Path = FIXTURE_ROOT,
) -> None:
    assert_value_free(model)
    services = _services(model)
    if set(services) != ORDINARY_SERVICES:
        raise ContractError(
            "ordinary model must contain four workloads and four lane stagers"
        )
    if INITIALIZATION_SERVICES.intersection(services):
        raise ContractError("ordinary model exposes initialization services")
    for name in STAGER_SERVICES:
        _assert_stager(
            name,
            services[name],
            postgresql_image=expected_images["registry-postgres"],
        )
    for name in WORKLOAD_SERVICES:
        service = services[name]
        if service.get("image") != expected_images[name]:
            raise ContractError(f"{name} does not use its exact plan image")
        if service.get("command") != ORDINARY_COMMANDS[name]:
            raise ContractError(f"{name} has the wrong ordinary command")
        if service.get("restart") != "unless-stopped":
            raise ContractError(f"{name} has the wrong ordinary restart policy")
        if set(service.get("networks", {})) != {NETWORK_RUNTIME}:
            raise ContractError(f"{name} has the wrong ordinary network")
        if _dependencies(service) != ORDINARY_DEPENDENCIES[name]:
            raise ContractError(f"{name} has the wrong ordinary dependencies")
        if service.get("privileged", False) is not False:
            raise ContractError(f"{name} gained privileged execution")
        for forbidden in ("network_mode", "secrets"):
            if forbidden in service:
                raise ContractError(f"{name} gained forbidden {forbidden}")
    for name in (
        "registry-relay-public",
        "registry-relay-consultation",
        "registry-notary",
    ):
        _assert_product_hardening(name, services[name], healthcheck=True)
    _assert_postgresql_hardening(
        "registry-postgres",
        services["registry-postgres"],
        healthcheck=True,
    )
    for name, environment in LANE_ENVIRONMENTS.items():
        if [path.name for path in _env_file_paths(services[name])] != [environment]:
            raise ContractError(f"{name} does not use its lane environment")
    if [path.name for path in _env_file_paths(services["registry-postgres"])] != [
        "postgresql-server.env"
    ]:
        raise ContractError("PostgreSQL does not use its package server environment")
    postgres_entrypoint = services["registry-postgres"].get("entrypoint")
    if not isinstance(
        postgres_entrypoint, list
    ) or "data directory is empty" not in " ".join(postgres_entrypoint):
        raise ContractError("ordinary PostgreSQL no longer fails closed before init")
    postgres_mounts = _mounts(services["registry-postgres"])
    if set(postgres_mounts) != {"/var/lib/postgresql/data", "/run/secrets"}:
        raise ContractError("PostgreSQL has the wrong protected mount inventory")
    _assert_volume_mount(
        postgres_mounts["/var/lib/postgresql/data"],
        "registry-postgresql-data",
        read_only=False,
    )
    _assert_volume_mount(
        postgres_mounts["/run/secrets"],
        "registry-operator-files-postgresql-serve",
        read_only=True,
    )
    for name, lane in (
        ("registry-relay-public", "relay-public"),
        ("registry-relay-consultation", "relay-consultation"),
        ("registry-notary", "notary"),
    ):
        _assert_product_mounts(
            name,
            services[name],
            lane,
            action="serve",
        )
    expected_ports = {
        "registry-relay-public": [
            {
                "host_ip": "127.0.0.1",
                "mode": "ingress",
                "protocol": "tcp",
                "published": "4242",
                "target": 4242,
            }
        ],
        "registry-notary": [
            {
                "host_ip": "127.0.0.1",
                "mode": "ingress",
                "protocol": "tcp",
                "published": "4255",
                "target": 4255,
            }
        ],
    }
    for name, service in services.items():
        if service.get("ports") != expected_ports.get(name):
            raise ContractError(f"{name} has the wrong host publication boundary")
    _assert_top_level_resources(model)
    _assert_operator_file_inventory(model, fixture_root)


def assert_initialization_model(
    model: dict[str, Any],
    ordinary: dict[str, Any],
    expected_images: dict[str, str],
) -> None:
    assert_value_free(model)
    services = _services(model)
    if set(services) != ORDINARY_SERVICES | INITIALIZATION_SERVICES:
        raise ContractError("initialization model has the wrong explicit services")
    ordinary_services = _services(ordinary)
    for name in ORDINARY_SERVICES - {"registry-postgres"}:
        if services[name] != ordinary_services[name]:
            raise ContractError(f"initialization delta changed ordinary service {name}")
    postgres_delta = {
        key: value
        for key, value in services["registry-postgres"].items()
        if ordinary_services["registry-postgres"].get(key) != value
    }
    removed_postgres_fields = set(ordinary_services["registry-postgres"]) - set(
        services["registry-postgres"]
    )
    if (
        postgres_delta != {"entrypoint": ["docker-entrypoint.sh"]}
        or removed_postgres_fields
    ):
        raise ContractError("PostgreSQL initialization is not an explicit delta")
    bootstrap = services["registry-postgres-bootstrap"]
    bootstrap_env_files = _env_file_paths(bootstrap)
    ordinary_operator_directory = _env_file_paths(ordinary_services["registry-notary"])[
        0
    ].parent
    if (
        bootstrap.get("image") != expected_images["registry-postgres"]
        or bootstrap.get("command")
        != INITIALIZATION_COMMANDS["registry-postgres-bootstrap"]
        or bootstrap.get("restart") != "no"
        or [path.name for path in bootstrap_env_files]
        != ["postgresql-server.env", "postgresql-bootstrap-environment"]
        or bootstrap_env_files[1].parent != ordinary_operator_directory
        or set(bootstrap.get("networks", {})) != {NETWORK_RUNTIME}
        or _dependencies(bootstrap)
        != {
            "registry-postgres": "service_healthy",
            "registry-postgresql-stage-secrets": ("service_completed_successfully"),
        }
        or "network_mode" in bootstrap
        or "secrets" in bootstrap
        or "ports" in bootstrap
    ):
        raise ContractError("PostgreSQL bootstrap has the wrong initialization inputs")
    _assert_postgresql_hardening(
        "registry-postgres-bootstrap",
        bootstrap,
        healthcheck=False,
    )
    bootstrap_mounts = _mounts(bootstrap)
    if set(bootstrap_mounts) != {"/run/secrets"}:
        raise ContractError("PostgreSQL bootstrap has the wrong protected mounts")
    _assert_volume_mount(
        bootstrap_mounts["/run/secrets"],
        "registry-operator-files-postgresql-bootstrap",
        read_only=True,
    )
    for name, (ordinary_name, lane, action) in INITIALIZATION_METADATA.items():
        service = services[name]
        environment = LANE_ENVIRONMENTS[ordinary_name]
        if (
            service.get("image") != expected_images[ordinary_name]
            or service.get("command") != INITIALIZATION_COMMANDS[name]
            or service.get("restart") != "no"
            or set(service.get("networks", {})) != {NETWORK_RUNTIME}
            or _dependencies(service) != INITIALIZATION_DEPENDENCIES[name]
            or [path.name for path in _env_file_paths(service)] != [environment]
            or "network_mode" in service
            or "secrets" in service
            or "ports" in service
        ):
            raise ContractError(f"{name} has the wrong initialization contract")
        _assert_product_hardening(name, service, healthcheck=False)
        _assert_product_mounts(name, service, lane, action=action)
    if model.get("networks") != ordinary.get("networks"):
        raise ContractError("initialization delta changed package networks")
    if model.get("volumes") != ordinary.get("volumes"):
        raise ContractError("initialization delta changed package volumes")
    if model.get("secrets") != ordinary.get("secrets"):
        raise ContractError("initialization delta changed operator secrets")


def assert_parent_include(model: dict[str, Any], ordinary: dict[str, Any]) -> None:
    assert_value_free(model)
    services = _services(model)
    if set(services) != ORDINARY_SERVICES | {"parent-runtime-client"}:
        raise ContractError("parent include did not normalize the package exactly once")
    for name in ORDINARY_SERVICES:
        if services[name] != _services(ordinary)[name]:
            raise ContractError(f"parent include changed package service {name}")
    parent = services["parent-runtime-client"]
    if set(parent.get("networks", {})) != {NETWORK_RUNTIME} or parent.get("image") != (
        "example.invalid/registrystack/conformance-probe@sha256:" + "d" * 64
    ):
        raise ContractError("operator parent service lost its runtime model")
    for field in ("networks", "volumes", "secrets"):
        if model.get(field) != ordinary.get(field):
            raise ContractError(f"parent include changed package {field}")


def run_contract(compose_command: Sequence[str], fixture_root: Path) -> None:
    expected_images = validate_plan(fixture_root / "deployment-plan.probe.v1.json")
    ordinary = _compose_config(
        compose_command,
        fixture_root,
        "package/generated/compose.yaml",
    )
    assert_ordinary_model(ordinary, expected_images, fixture_root)
    initialized = _compose_config(
        compose_command,
        fixture_root,
        "package/generated/compose.yaml",
        "package/generated/compose.initialize.yaml",
    )
    assert_initialization_model(initialized, ordinary, expected_images)
    parent = _compose_config(
        compose_command,
        fixture_root,
        "parent-short/compose.yaml",
    )
    assert_parent_include(parent, ordinary)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--compose-command", nargs="+", default=None)
    parser.add_argument("--compose-binary", type=Path)
    parser.add_argument("--label", default="current")
    parser.add_argument("--fixture-root", type=Path, default=FIXTURE_ROOT)
    args = parser.parse_args(argv)
    if args.compose_command is not None and args.compose_binary is not None:
        parser.error("--compose-command and --compose-binary are mutually exclusive")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    compose_command = (
        args.compose_command
        if args.compose_command is not None
        else [str(args.compose_binary)]
        if args.compose_binary is not None
        else ["docker", "compose"]
    )
    try:
        run_contract(compose_command, args.fixture_root.resolve())
    except ContractError as error:
        print(f"adopter Compose conformance failed: {error}", file=sys.stderr)
        return 1
    print(f"adopter Compose conformance ({args.label}): PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
