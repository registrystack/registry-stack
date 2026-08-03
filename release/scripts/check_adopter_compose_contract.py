#!/usr/bin/env python3
"""Validate the package-only adopter Compose conformance fixtures."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = REPO_ROOT / "release/conformance/adopter-runtime"
PROJECT_NAME = "registry-adopter-probe"
NETWORK_RUNTIME = "registry-runtime"
IMAGE_IDENTITY = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
SENTINEL_FRAGMENT = "value-must-not-enter-compose"
BOUNDED_LOCAL_LOGGING = {
    "driver": "local",
    "options": {
        "max-size": "10m",
        "max-file": "3",
    },
}

WORKLOAD_SERVICES = frozenset(
    {
        "registry-postgres",
        "registry-relay-public",
        "registry-relay-consultation",
    }
)
STAGER_SERVICES = frozenset(
    {
        "registry-postgresql-stage-secrets",
        "registry-relay-consultation-stage-secrets",
    }
)
ACTION_STAGER_SERVICES = frozenset(
    {
        "registry-postgresql-actions-stage-secrets",
        "registry-relay-consultation-actions-stage-secrets",
    }
)
ORDINARY_SERVICES = WORKLOAD_SERVICES | STAGER_SERVICES
INITIALIZATION_SERVICES = frozenset(
    {
        "registry-postgres-bootstrap",
        "registry-relay-public-prepare-state",
        "registry-relay-consultation-prepare-state",
        "registry-relay-public-initialize",
        "registry-relay-consultation-initialize",
        "registry-relay-public-preview-state",
        "registry-relay-consultation-preview-state",
        "registry-relay-public-accept-state",
        "registry-relay-consultation-accept-state",
        "registry-relay-public-verify-state",
        "registry-relay-consultation-verify-state",
    }
)

OPERATOR_ENVIRONMENT_FILES = frozenset(
    {
        "relay-public-environment",
        "relay-consultation-environment",
        "postgresql-bootstrap-environment",
    }
)
OPERATOR_SECRET_FILES = frozenset(
    {
        "postgresql-admin-password",
        "postgresql-tls-certificate",
        "postgresql-tls-private-key",
    }
)
EXPECTED_OPERATOR_FILES = OPERATOR_ENVIRONMENT_FILES | OPERATOR_SECRET_FILES

LANE_ENVIRONMENTS = {
    "registry-relay-public": "relay-public-environment",
    "registry-relay-consultation": "relay-consultation-environment",
}
ORDINARY_COMMANDS = {
    "registry-postgres": ["postgres"],
    "registry-relay-public": ["product-action", "relay-public", "serve"],
    "registry-relay-consultation": [
        "product-action",
        "relay-consultation",
        "serve",
    ],
}
POSTGRESQL_ORDINARY_ENTRYPOINT = [
    "/bin/bash",
    "-ceu",
    (
        'test -s "$${PGDATA:-/var/lib/postgresql/data}/PG_VERSION" '
        "|| { echo 'PostgreSQL data directory is empty; run the explicit "
        "initialization workflow first' >&2; exit 1; }\n"
        'exec "$@"'
    ),
    "--",
]
POSTGRESQL_INITIALIZATION_ENTRYPOINT = [
    "/bin/bash",
    "-ceu",
    (
        'pgdata="$${PGDATA:-/var/lib/postgresql/data}"\n'
        'test -z "$$(find "$$pgdata" -mindepth 1 -maxdepth 1 -print -quit)" '
        "|| { echo 'PostgreSQL data directory is not empty; refusing explicit "
        "initialization' >&2; exit 1; }\n"
        'exec /usr/local/bin/docker-entrypoint.sh "$@"'
    ),
    "--",
]
ORDINARY_DEPENDENCIES = {
    "registry-postgres": {
        "registry-postgresql-stage-secrets": "service_completed_successfully"
    },
    "registry-relay-public": {},
    "registry-relay-consultation": {
        "registry-postgres": "service_healthy",
        "registry-relay-consultation-stage-secrets": ("service_completed_successfully"),
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
    "registry-relay-public-preview-state": [
        "product-action",
        "relay-public",
        "preview_state",
    ],
    "registry-relay-consultation-preview-state": [
        "product-action",
        "relay-consultation",
        "preview_state",
    ],
    "registry-relay-public-accept-state": [
        "product-action",
        "relay-public",
        "accept_state",
    ],
    "registry-relay-consultation-accept-state": [
        "product-action",
        "relay-consultation",
        "accept_state",
    ],
    "registry-relay-public-verify-state": [
        "product-action",
        "relay-public",
        "verify_state",
    ],
    "registry-relay-consultation-verify-state": [
        "product-action",
        "relay-consultation",
        "verify_state",
    ],
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
    "registry-relay-public-preview-state": (
        "registry-relay-public",
        "relay-public",
        "preview",
    ),
    "registry-relay-consultation-preview-state": (
        "registry-relay-consultation",
        "relay-consultation",
        "preview",
    ),
    "registry-relay-public-accept-state": (
        "registry-relay-public",
        "relay-public",
        "accept",
    ),
    "registry-relay-consultation-accept-state": (
        "registry-relay-consultation",
        "relay-consultation",
        "accept",
    ),
    "registry-relay-public-verify-state": (
        "registry-relay-public",
        "relay-public",
        "verify",
    ),
    "registry-relay-consultation-verify-state": (
        "registry-relay-consultation",
        "relay-consultation",
        "verify",
    ),
}
INITIALIZATION_DEPENDENCIES = {
    "registry-relay-public-prepare-state": {},
    "registry-relay-public-initialize": {},
    "registry-relay-consultation-prepare-state": {
        "registry-postgres": "service_healthy",
        "registry-relay-consultation-actions-stage-secrets": (
            "service_completed_successfully"
        ),
    },
    "registry-relay-consultation-initialize": {
        "registry-postgres": "service_healthy",
        "registry-relay-consultation-actions-stage-secrets": (
            "service_completed_successfully"
        ),
    },
    "registry-relay-public-preview-state": {},
    "registry-relay-public-accept-state": {},
    "registry-relay-consultation-preview-state": {},
    "registry-relay-consultation-accept-state": {},
    "registry-relay-public-verify-state": {},
    "registry-relay-consultation-verify-state": {},
}

STAGER_COMMAND = ["umask 077\nexit 0\n"]
STAGER_SPECS = {
    "registry-postgresql-stage-secrets": {
        "outputs": {
            "postgresql-serve": "registry-operator-files-postgresql-serve",
        },
        "secrets": {
            "registry-postgresql-admin-password",
            "registry-postgresql-tls-certificate",
            "registry-postgresql-tls-private-key",
        },
    },
    "registry-relay-consultation-stage-secrets": {
        "outputs": {
            "relay-consultation-serve": (
                "registry-operator-files-relay-consultation-serve"
            ),
        },
        "secrets": {
            "registry-postgresql-tls-certificate",
        },
    },
}

ACTION_STAGER_SPECS = {
    "registry-postgresql-actions-stage-secrets": {
        "outputs": {
            "postgresql-bootstrap": "registry-operator-files-postgresql-bootstrap",
        },
        "secrets": {
            "registry-postgresql-admin-password",
            "registry-postgresql-tls-certificate",
        },
    },
    "registry-relay-consultation-actions-stage-secrets": {
        "outputs": {
            "relay-consultation-prepare": (
                "registry-operator-files-relay-consultation-prepare"
            ),
            "relay-consultation-initialize": (
                "registry-operator-files-relay-consultation-initialize"
            ),
        },
        "secrets": {"registry-postgresql-tls-certificate"},
    },
}

ORDINARY_STAGER_RUNTIME_ACTIONS = {
    "registry-postgresql-stage-secrets": [
        ("postgresql-serve", "postgresql_state_plane", "serve"),
    ],
    "registry-relay-consultation-stage-secrets": [
        ("relay-consultation-serve", "relay_consultation", "serve"),
    ],
}

ACTION_STAGER_RUNTIME_ACTIONS = {
    "registry-postgresql-actions-stage-secrets": [
        ("postgresql-bootstrap", "postgresql_state_plane", "bootstrap"),
    ],
    "registry-relay-consultation-actions-stage-secrets": [
        (
            "relay-consultation-prepare",
            "relay_consultation",
            "prepare_state_store",
        ),
        (
            "relay-consultation-initialize",
            "relay_consultation",
            "initialize_state",
        ),
    ],
}

DURABLE_VOLUMES = frozenset(
    {
        "registry-postgresql-data",
        "registry-relay-public-state",
        "registry-relay-public-audit",
        "registry-relay-consultation-state",
        "registry-relay-consultation-audit",
    }
)
ORDINARY_STAGED_SECRET_VOLUMES = frozenset(
    volume for spec in STAGER_SPECS.values() for volume in spec["outputs"].values()
)
INITIALIZATION_STAGED_SECRET_VOLUMES = frozenset(
    volume
    for spec in ACTION_STAGER_SPECS.values()
    for volume in spec["outputs"].values()
)
STAGED_SECRET_VOLUMES = (
    ORDINARY_STAGED_SECRET_VOLUMES | INITIALIZATION_STAGED_SECRET_VOLUMES
)
EXPECTED_VOLUMES = DURABLE_VOLUMES | ORDINARY_STAGED_SECRET_VOLUMES
EXPECTED_INITIALIZATION_VOLUMES = DURABLE_VOLUMES | STAGED_SECRET_VOLUMES

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
            "audit",
        ],
        "secret_consumers": [],
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
            "audit",
        ],
        "secret_consumers": [],
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
        "id": "preview-relay-public-state",
        "workload": "relay-public",
        "action": "preview_state",
    },
    {
        "id": "preview-relay-consultation-state",
        "workload": "relay-consultation",
        "action": "preview_state",
    },
    {
        "id": "accept-relay-public-state",
        "workload": "relay-public",
        "action": "accept_state",
    },
    {
        "id": "accept-relay-consultation-state",
        "workload": "relay-consultation",
        "action": "accept_state",
    },
    {
        "id": "verify-relay-public-state",
        "workload": "relay-public",
        "action": "verify_state",
    },
    {
        "id": "verify-relay-consultation-state",
        "workload": "relay-consultation",
        "action": "verify_state",
    },
]
EXPECTED_RECOVERY_GROUPS = [
    {
        "id": "consultation-state",
        "members": [
            "relay-consultation",
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
        "endpoint_class": "posture",
        "exposure": "private-network-only",
    },
]


class ContractError(RuntimeError):
    """Raised when a normalized fixture violates the package contract."""


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ContractError(f"deployment plan probe repeats object field {name}")
        result[name] = value
    return result


def fixture_runtime_contract() -> dict[str, Any]:
    return {
        "ordinary_commands": ORDINARY_COMMANDS,
        "initialization_commands": INITIALIZATION_COMMANDS,
        "health_probes": {
            name: ["CMD", "/conformance-only-healthcheck"]
            for name in WORKLOAD_SERVICES
        },
        "ordinary_stager_commands": {
            name: STAGER_COMMAND for name in STAGER_SERVICES
        },
        "initialization_stager_commands": {
            name: STAGER_COMMAND for name in ACTION_STAGER_SERVICES
        },
        "declared_compose_files": OPERATOR_SECRET_FILES,
    }


def runtime_contract_from_payload(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        runtime = payload["runtime"]
        products = {
            "registry-relay-public": runtime["relay_public"],
            "registry-relay-consultation": runtime["relay_consultation"],
        }
        postgresql = runtime["postgresql_state_plane"]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise ContractError(
            "RegistryReleaseLockV1 parity payload is incomplete"
        ) from error

    ordinary_commands = {
        name: recipe["serve"]["command"] for name, recipe in products.items()
    }
    ordinary_commands["registry-postgres"] = postgresql["serve"]["command"]
    initialization_commands = {
        "registry-postgres-bootstrap": postgresql["bootstrap"]["command"],
        "registry-relay-public-prepare-state": (
            products["registry-relay-public"]["prepare_state_store"]["command"]
        ),
        "registry-relay-consultation-prepare-state": (
            products["registry-relay-consultation"][
                "prepare_state_store"
            ]["command"]
        ),
        "registry-relay-public-initialize": (
            products["registry-relay-public"]["initialize_state"]["command"]
        ),
        "registry-relay-consultation-initialize": (
            products["registry-relay-consultation"][
                "initialize_state"
            ]["command"]
        ),
        "registry-relay-public-preview-state": (
            products["registry-relay-public"]["preview_state"]["command"]
        ),
        "registry-relay-consultation-preview-state": (
            products["registry-relay-consultation"]["preview_state"]["command"]
        ),
        "registry-relay-public-accept-state": (
            products["registry-relay-public"]["accept_state"]["command"]
        ),
        "registry-relay-consultation-accept-state": (
            products["registry-relay-consultation"]["accept_state"]["command"]
        ),
        "registry-relay-public-verify-state": (
            products["registry-relay-public"]["verify_state"]["command"]
        ),
        "registry-relay-consultation-verify-state": (
            products["registry-relay-consultation"]["verify_state"]["command"]
        ),
    }
    health_probes = {
        name: recipe["health_probe"] for name, recipe in products.items()
    }
    health_probes["registry-postgres"] = postgresql["health_probe"]

    def stager_commands_for(
        action_inventory: dict[str, list[tuple[str, str, str]]],
    ) -> tuple[dict[str, list[str]], set[str]]:
        commands = {}
        files = set()
        for service, actions in action_inventory.items():
            script = "umask 077\n"
            for stage_id, recipe_id, action_id in actions:
                projections = runtime[recipe_id][action_id]["secret_files"]
                if not projections:
                    continue
                files.update(projection["file_id"] for projection in projections)
                output = f"/registryctl-stage/output/{stage_id}"
                script += (
                    f"/usr/bin/find {output} -mindepth 1 -maxdepth 1 -delete\n"
                )
                for projection in projections:
                    target = Path(projection["target"]).name
                    script += (
                        f"/usr/bin/install -m {projection['mode']} "
                        f"/run/secrets/{projection['file_id']} {output}/{target}\n"
                        f"/usr/bin/chown {projection['uid']}:{projection['gid']} "
                        f"{output}/{target}\n"
                    )
            commands[service] = [script]
        return commands, files

    ordinary_stager_commands, ordinary_files = stager_commands_for(
        ORDINARY_STAGER_RUNTIME_ACTIONS
    )
    initialization_stager_commands, initialization_files = stager_commands_for(
        ACTION_STAGER_RUNTIME_ACTIONS
    )
    declared_compose_files = set()
    declared_compose_files.update(ordinary_files)
    declared_compose_files.update(initialization_files)

    return {
        "ordinary_commands": ordinary_commands,
        "initialization_commands": initialization_commands,
        "health_probes": health_probes,
        "ordinary_stager_commands": ordinary_stager_commands,
        "initialization_stager_commands": initialization_stager_commands,
        "declared_compose_files": declared_compose_files,
    }


def _compose_config(
    compose_command: Sequence[str],
    fixture_root: Path,
    *files: str,
    package_root: Path | None = None,
    project_name: str | None = PROJECT_NAME,
) -> dict[str, Any]:
    package_root = package_root or fixture_root / "package"
    command = [*compose_command]
    if project_name is not None:
        command.extend(("--project-name", project_name))
    command.extend(
        (
            "--env-file",
            str(package_root / "generated/compose.empty.env"),
        )
    )
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
    name: str,
    service: dict[str, Any],
    *,
    health_probe: list[str] | None,
) -> None:
    if (
        service.get("platform") != "linux/amd64"
        or service.get("user") != "65532:65532"
        or service.get("read_only") is not True
        or service.get("cap_drop") != ["ALL"]
        or service.get("security_opt") != ["no-new-privileges:true"]
        or service.get("tmpfs") != ["/tmp"]
        or service.get("logging") != BOUNDED_LOCAL_LOGGING
        or "cap_add" in service
        or service.get("privileged", False) is not False
    ):
        raise ContractError(f"{name} lost product hardening")
    expected_healthcheck = (
        {
            "test": health_probe,
            "interval": "30s",
            "timeout": "5s",
            "retries": 3,
        }
        if health_probe is not None
        else None
    )
    if service.get("healthcheck") != expected_healthcheck:
        raise ContractError(f"{name} has the wrong healthcheck boundary")


def _assert_postgresql_hardening(
    name: str,
    service: dict[str, Any],
    *,
    health_probe: list[str] | None,
) -> None:
    if (
        service.get("platform") != "linux/amd64"
        or service.get("user") != "999:999"
        or service.get("read_only") is not True
        or service.get("cap_drop") != ["ALL"]
        or service.get("security_opt") != ["no-new-privileges:true"]
        or service.get("tmpfs")
        != ["/tmp", "/var/run/postgresql:uid=999,gid=999,mode=0750"]
        or service.get("logging") != BOUNDED_LOCAL_LOGGING
        or "cap_add" in service
        or service.get("privileged", False) is not False
    ):
        raise ContractError(f"{name} lost PostgreSQL hardening")
    expected_healthcheck = (
        {
            "test": health_probe,
            "interval": "30s",
            "timeout": "5s",
            "retries": 3,
        }
        if health_probe is not None
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
        raise ContractError(
            "managed volume mount contract changed "
            f"(expected source={source}, read_only={read_only}; "
            f"observed type={mount.get('type')}, "
            f"source={mount.get('source')}, "
            f"read_only={bool(mount.get('read_only', False))})"
        )


def _assert_product_mounts(
    name: str,
    service: dict[str, Any],
    lane: str,
    *,
    action: str,
    package_root: Path,
) -> None:
    mounts = _mounts(service)
    expected_targets = {
        "/run/registry/bundle",
        "/run/registry/anchor",
    }
    if action != "prepare":
        expected_targets.add("/var/lib/registry/state")
    if action not in {"preview", "verify"}:
        expected_targets.add("/var/lib/registry/audit")
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
        expected_source = package_root / "generated" / kind / lane
        if kind == "bundles":
            source_path = Path(source) if isinstance(source, str) else None
            lane_owned = source_path == expected_source or (
                source_path is not None
                and source_path.parent == expected_source
                and re.fullmatch(r"[0-9a-f]{64}", source_path.name) is not None
            )
        else:
            lane_owned = source == str(expected_source)
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
            read_only=action in {"serve", "preview", "verify"},
        )
    if "/var/lib/registry/audit" in mounts:
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
    command: list[str],
    spec: dict[str, Any] | None = None,
) -> None:
    spec = spec or STAGER_SPECS[name]
    if (
        service.get("image") != postgresql_image
        or service.get("platform") != "linux/amd64"
        or service.get("entrypoint") != ["/bin/sh", "-ceu"]
        or service.get("command") != command
        or service.get("user") != "0:0"
        or service.get("read_only") is not True
        or service.get("cap_drop") != ["ALL"]
        or service.get("cap_add") != ["CHOWN", "DAC_READ_SEARCH"]
        or service.get("security_opt") != ["no-new-privileges:true"]
        or service.get("tmpfs") != ["/tmp"]
        or service.get("network_mode") != "none"
        or service.get("restart") != "no"
        or service.get("privileged", False) is not False
    ):
        raise ContractError(
            f"{name} lost its isolated secret-staging capability contract"
        )
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


def _assert_operator_file_inventory(
    model: dict[str, Any],
    package_root: Path,
    declared_compose_files: set[str] | frozenset[str],
) -> None:
    expected_directory = (package_root / "operator/secrets").resolve()
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
    expected_names = {
        f"registry-{name}" for name in declared_compose_files
    }
    if (
        not isinstance(declared_secrets, dict)
        or set(declared_secrets) != expected_names
    ):
        observed_names = (
            set(declared_secrets) if isinstance(declared_secrets, dict) else set()
        )
        raise ContractError(
            "package has the wrong operator secret definitions "
            f"(missing={sorted(expected_names - observed_names)}, "
            f"unexpected={sorted(observed_names - expected_names)})"
        )
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
        ordinary_environments | declared_compose_files
    ):
        raise ContractError("package operator-file inventory is incomplete")


def _assert_top_level_resources(model: dict[str, Any]) -> None:
    project_name = model.get("name")
    if not isinstance(project_name, str) or not project_name:
        raise ContractError("package lost its Compose project identity")
    networks = model.get("networks")
    if not isinstance(networks, dict) or set(networks) != {NETWORK_RUNTIME}:
        raise ContractError("package must use exactly one ordinary runtime network")
    network = networks[NETWORK_RUNTIME]
    if (
        not isinstance(network, dict)
        or network.get("internal") is True
        or network.get("external") is True
        or set(network) - {"name"}
        or network.get("name") != f"{project_name}_{NETWORK_RUNTIME}"
    ):
        raise ContractError("runtime network gained managed isolation")
    volumes = model.get("volumes")
    if not isinstance(volumes, dict) or set(volumes) != EXPECTED_VOLUMES:
        raise ContractError("package has the wrong closed volume inventory")
    for name in DURABLE_VOLUMES:
        if volumes[name] != {"name": f"{project_name}_{name}"}:
            raise ContractError(f"durable volume {name} lost its stable physical name")
    for name in ORDINARY_STAGED_SECRET_VOLUMES:
        if volumes[name] != {"name": f"{project_name}_{name}"}:
            raise ContractError(f"scratch volume {name} lost its project scope")


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
        plan = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_object,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
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
    if not isinstance(workloads, list) or len(workloads) != 3:
        raise ContractError("deployment plan must contain exactly three workloads")
    images: dict[str, str] = {}
    services = {
        "relay-public": "registry-relay-public",
        "relay-consultation": "registry-relay-consultation",
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
            or set(workload) != {
                "id",
                "image_identity",
                "image_platform",
                *expected,
            }
            or workload.get("image_platform") != "linux-amd64"
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
    *,
    package_root: Path | None = None,
    runtime_contract: dict[str, Any] | None = None,
) -> None:
    package_root = package_root or fixture_root / "package"
    runtime_contract = runtime_contract or fixture_runtime_contract()
    assert_value_free(model)
    services = _services(model)
    if set(services) != ORDINARY_SERVICES:
        raise ContractError(
            "ordinary model must contain three workloads and two secret stagers"
        )
    if INITIALIZATION_SERVICES.intersection(services):
        raise ContractError("ordinary model exposes initialization services")
    for name in STAGER_SERVICES:
        _assert_stager(
            name,
            services[name],
            postgresql_image=expected_images["registry-postgres"],
            command=runtime_contract["ordinary_stager_commands"][name],
        )
    for name in WORKLOAD_SERVICES:
        service = services[name]
        if service.get("image") != expected_images[name]:
            raise ContractError(f"{name} does not use its exact plan image")
        if service.get("command") != runtime_contract["ordinary_commands"][name]:
            raise ContractError(f"{name} has the wrong ordinary command")
        if service.get("restart") != "unless-stopped":
            raise ContractError(f"{name} has the wrong ordinary restart policy")
        if set(service.get("networks", {})) != {NETWORK_RUNTIME}:
            raise ContractError(f"{name} has the wrong ordinary network")
        if _dependencies(service) != ORDINARY_DEPENDENCIES[name]:
            raise ContractError(f"{name} has the wrong ordinary dependencies")
        for forbidden in ("network_mode", "secrets"):
            if forbidden in service:
                raise ContractError(f"{name} gained forbidden {forbidden}")
    for name in (
        "registry-relay-public",
        "registry-relay-consultation",
    ):
        _assert_product_hardening(
            name,
            services[name],
            health_probe=runtime_contract["health_probes"][name],
        )
    _assert_postgresql_hardening(
        "registry-postgres",
        services["registry-postgres"],
        health_probe=runtime_contract["health_probes"]["registry-postgres"],
    )
    for name, environment in LANE_ENVIRONMENTS.items():
        if _env_file_paths(services[name]) != [
            package_root / "operator/secrets" / environment
        ]:
            raise ContractError(f"{name} does not use its lane environment")
    if _env_file_paths(services["registry-postgres"]) != [
        package_root / "generated/postgresql-server.env"
    ]:
        raise ContractError("PostgreSQL does not use its package server environment")
    if (
        services["registry-postgres"].get("entrypoint")
        != POSTGRESQL_ORDINARY_ENTRYPOINT
    ):
        raise ContractError("ordinary PostgreSQL has the wrong fail-closed entrypoint")
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
    ):
        _assert_product_mounts(
            name,
            services[name],
            lane,
            action="serve",
            package_root=package_root,
        )
    expected_ports = {
        "registry-relay-public": [
            {
                "host_ip": "127.0.0.1",
                "mode": "ingress",
                "protocol": "tcp",
                "published": "4242",
                "target": 8080,
            }
        ],
    }
    for name, service in services.items():
        if service.get("ports") != expected_ports.get(name):
            raise ContractError(f"{name} has the wrong host publication boundary")
    _assert_top_level_resources(model)
    _assert_operator_file_inventory(
        model,
        package_root,
        runtime_contract["declared_compose_files"],
    )


def assert_initialization_model(
    model: dict[str, Any],
    ordinary: dict[str, Any],
    expected_images: dict[str, str],
    runtime_contract: dict[str, Any] | None = None,
    *,
    package_root: Path | None = None,
) -> None:
    runtime_contract = runtime_contract or fixture_runtime_contract()
    package_root = package_root or FIXTURE_ROOT / "package"
    assert_value_free(model)
    services = _services(model)
    expected_services = (
        ORDINARY_SERVICES | ACTION_STAGER_SERVICES | INITIALIZATION_SERVICES
    )
    if set(services) != expected_services:
        raise ContractError(
            "initialization model has the wrong explicit services "
            f"(missing={sorted(expected_services - set(services))}, "
            f"unexpected={sorted(set(services) - expected_services)})"
        )
    ordinary_services = _services(ordinary)
    for name in ORDINARY_SERVICES - {"registry-postgres"}:
        if services[name] != ordinary_services[name]:
            raise ContractError(f"initialization delta changed ordinary service {name}")
    for name in ACTION_STAGER_SERVICES:
        _assert_stager(
            name,
            services[name],
            postgresql_image=expected_images["registry-postgres"],
            command=runtime_contract["initialization_stager_commands"][name],
            spec=ACTION_STAGER_SPECS[name],
        )
    postgres_delta = {
        key: value
        for key, value in services["registry-postgres"].items()
        if ordinary_services["registry-postgres"].get(key) != value
    }
    removed_postgres_fields = set(ordinary_services["registry-postgres"]) - set(
        services["registry-postgres"]
    )
    if (
        postgres_delta
        != {"entrypoint": POSTGRESQL_INITIALIZATION_ENTRYPOINT}
        or removed_postgres_fields
    ):
        raise ContractError("PostgreSQL initialization is not an explicit delta")
    bootstrap = services["registry-postgres-bootstrap"]
    bootstrap_env_files = _env_file_paths(bootstrap)
    if (
        bootstrap.get("image") != expected_images["registry-postgres"]
        or bootstrap.get("command")
        != runtime_contract["initialization_commands"][
            "registry-postgres-bootstrap"
        ]
        or bootstrap.get("restart") != "no"
        or bootstrap_env_files
        != [
            package_root / "generated/postgresql-server.env",
            package_root / "operator/secrets/postgresql-bootstrap-environment",
        ]
        or set(bootstrap.get("networks", {})) != {NETWORK_RUNTIME}
        or _dependencies(bootstrap)
        != {
            "registry-postgres": "service_healthy",
            "registry-postgresql-actions-stage-secrets": (
                "service_completed_successfully"
            ),
        }
        or "network_mode" in bootstrap
        or "secrets" in bootstrap
        or "ports" in bootstrap
    ):
        raise ContractError("PostgreSQL bootstrap has the wrong initialization inputs")
    _assert_postgresql_hardening(
        "registry-postgres-bootstrap",
        bootstrap,
        health_probe=None,
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
        requires_postgresql = (
            lane == "relay-consultation"
            and action in {"prepare", "initialize"}
        )
        expected_environment_files = (
            [package_root / "operator/secrets" / environment]
            if action in {"prepare", "initialize", "accept"}
            else []
        )
        if (
            service.get("image") != expected_images[ordinary_name]
            or service.get("command")
            != runtime_contract["initialization_commands"][name]
            or service.get("restart") != "no"
            or (
                set(service.get("networks", {})) != {NETWORK_RUNTIME}
                if requires_postgresql
                else "networks" in service
            )
            or _dependencies(service) != INITIALIZATION_DEPENDENCIES[name]
            or _env_file_paths(service) != expected_environment_files
            or (
                "network_mode" in service
                if requires_postgresql
                else service.get("network_mode") != "none"
            )
            or "secrets" in service
            or "ports" in service
        ):
            raise ContractError(f"{name} has the wrong initialization contract")
        _assert_product_hardening(name, service, health_probe=None)
        _assert_product_mounts(
            name,
            service,
            lane,
            action=action,
            package_root=package_root,
        )
    if model.get("networks") != ordinary.get("networks"):
        raise ContractError("initialization delta changed package networks")
    volumes = model.get("volumes")
    project_name = model.get("name")
    if not isinstance(volumes, dict) or set(volumes) != EXPECTED_INITIALIZATION_VOLUMES:
        raise ContractError("initialization model has the wrong volume inventory")
    for name in DURABLE_VOLUMES:
        if volumes[name] != ordinary["volumes"][name]:
            raise ContractError(f"initialization changed durable volume {name}")
    for name in STAGED_SECRET_VOLUMES:
        if volumes[name] != {"name": f"{project_name}_{name}"}:
            raise ContractError(f"initialization scratch volume {name} lost project scope")
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
    parent_name = model.get("name")
    ordinary_name = ordinary.get("name")
    if (
        not isinstance(parent_name, str)
        or not isinstance(ordinary_name, str)
        or parent_name == ordinary_name
    ):
        raise ContractError("parent include did not exercise a distinct Compose project")
    parent_secrets = model.get("secrets")
    ordinary_secrets = ordinary.get("secrets")
    if (
        not isinstance(parent_secrets, dict)
        or not isinstance(ordinary_secrets, dict)
        or set(parent_secrets) != set(ordinary_secrets)
    ):
        raise ContractError("parent include changed package secret inventory")
    for name, parent_secret in parent_secrets.items():
        ordinary_secret = ordinary_secrets[name]
        if (
            not isinstance(parent_secret, dict)
            or not isinstance(ordinary_secret, dict)
            or parent_secret.get("file") != ordinary_secret.get("file")
            or parent_secret.get("name") != f"{parent_name}_{name}"
            or ordinary_secret.get("name") != f"{ordinary_name}_{name}"
        ):
            raise ContractError(
                f"parent include changed operator secret projection {name}"
            )
    parent_networks = model.get("networks")
    ordinary_networks = ordinary.get("networks")
    if (
        not isinstance(parent_networks, dict)
        or not isinstance(ordinary_networks, dict)
        or set(parent_networks) != {NETWORK_RUNTIME}
        or set(ordinary_networks) != {NETWORK_RUNTIME}
        or parent_networks[NETWORK_RUNTIME]
        != {"name": f"{parent_name}_{NETWORK_RUNTIME}"}
        or ordinary_networks[NETWORK_RUNTIME]
        != {"name": f"{ordinary_name}_{NETWORK_RUNTIME}"}
    ):
        raise ContractError("parent include lost project-scoped networking")
    parent_volumes = model.get("volumes")
    ordinary_volumes = ordinary.get("volumes")
    if (
        not isinstance(parent_volumes, dict)
        or not isinstance(ordinary_volumes, dict)
        or set(parent_volumes) != EXPECTED_VOLUMES
        or set(ordinary_volumes) != EXPECTED_VOLUMES
    ):
        raise ContractError("parent include changed package volume inventory")
    for name in DURABLE_VOLUMES:
        if parent_volumes[name] != ordinary_volumes[name]:
            raise ContractError(f"parent include renamed durable volume {name}")
    for name in ORDINARY_STAGED_SECRET_VOLUMES:
        if (
            parent_volumes[name] != {"name": f"{parent_name}_{name}"}
            or ordinary_volumes[name] != {"name": f"{ordinary_name}_{name}"}
        ):
            raise ContractError(f"parent include lost project-scoped scratch volume {name}")


def run_contract(compose_command: Sequence[str], fixture_root: Path) -> None:
    expected_images = validate_plan(fixture_root / "deployment-plan.probe.v1.json")
    ordinary = _compose_config(
        compose_command,
        fixture_root,
        "package/generated/compose.yaml",
        project_name=None,
    )
    assert_ordinary_model(ordinary, expected_images, fixture_root)
    initialized = _compose_config(
        compose_command,
        fixture_root,
        "package/generated/compose.yaml",
        "package/generated/compose.initialize.yaml",
        project_name=None,
    )
    assert_initialization_model(
        initialized,
        ordinary,
        expected_images,
        package_root=fixture_root / "package",
    )
    parent = _compose_config(
        compose_command,
        fixture_root,
        "parent-short/compose.yaml",
        project_name=None,
    )
    assert_parent_include(parent, ordinary)


def run_rendered_package_contract(
    compose_command: Sequence[str],
    package_root: Path,
    release_lock_payload: Path,
) -> None:
    expected_images = validate_plan(
        package_root / "generated/deployment-plan.v1.json"
    )
    runtime_contract = runtime_contract_from_payload(release_lock_payload)
    ordinary = _compose_config(
        compose_command,
        package_root.parent,
        str(package_root / "generated/compose.yaml"),
        package_root=package_root,
        project_name=None,
    )
    assert_ordinary_model(
        ordinary,
        expected_images,
        package_root.parent,
        package_root=package_root,
        runtime_contract=runtime_contract,
    )
    initialized = _compose_config(
        compose_command,
        package_root.parent,
        str(package_root / "generated/compose.yaml"),
        str(package_root / "generated/compose.initialize.yaml"),
        package_root=package_root,
        project_name=None,
    )
    assert_initialization_model(
        initialized,
        ordinary,
        expected_images,
        runtime_contract,
        package_root=package_root,
    )
    with tempfile.TemporaryDirectory(
        prefix="registry-parent-include-",
        dir=package_root.parent,
    ) as parent_directory:
        parent_file = Path(parent_directory) / "compose.json"
        parent_file.write_text(
            json.dumps(
                {
                    "include": [
                        {
                            "path": str(
                                package_root / "generated/compose.yaml"
                            )
                        }
                    ],
                    "services": {
                        "parent-runtime-client": {
                            "image": (
                                "example.invalid/registrystack/"
                                "conformance-probe@sha256:" + "d" * 64
                            ),
                            "networks": [NETWORK_RUNTIME],
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        parent = _compose_config(
            compose_command,
            package_root.parent,
            str(parent_file),
            package_root=package_root,
            project_name=None,
        )
        assert_parent_include(parent, ordinary)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--compose-command", nargs="+", default=None)
    parser.add_argument("--compose-binary", type=Path)
    parser.add_argument("--label", default="current")
    parser.add_argument("--fixture-root", type=Path, default=FIXTURE_ROOT)
    parser.add_argument("--package-root", type=Path)
    parser.add_argument("--release-lock-payload", type=Path)
    args = parser.parse_args(argv)
    if args.compose_command is not None and args.compose_binary is not None:
        parser.error("--compose-command and --compose-binary are mutually exclusive")
    if (args.package_root is None) != (args.release_lock_payload is None):
        parser.error(
            "--package-root and --release-lock-payload must be provided together"
        )
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
        if args.package_root is None:
            run_contract(compose_command, args.fixture_root.resolve())
        else:
            run_rendered_package_contract(
                compose_command,
                args.package_root.resolve(),
                args.release_lock_payload.resolve(),
            )
    except ContractError as error:
        print(f"adopter Compose conformance failed: {error}", file=sys.stderr)
        return 1
    print(f"adopter Compose conformance ({args.label}): PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
