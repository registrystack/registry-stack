#!/usr/bin/env python3
"""Preflight official Registry Stack services in their Compose runtime context."""

from __future__ import annotations

import argparse
import json
import math
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Sequence, TextIO


MAXIMUM_COMPOSE_BYTES = 4 * 1024 * 1024
MINIMUM_DEPENDENCY_TIMEOUT_SECONDS = 5
MAXIMUM_DEPENDENCY_TIMEOUT_SECONDS = 10 * 60
MINIMUM_NATIVE_CHECK_TIMEOUT_SECONDS = 30
MAXIMUM_NATIVE_CHECK_TIMEOUT_SECONDS = 6 * 60 * 60
DEFAULT_NATIVE_CHECK_TIMEOUT_SECONDS = 30 * 60
PRODUCTS = ("evidence", "mint", "relay")
SERVICE_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?")
IMAGE_PATTERNS = {
    product: re.compile(rf"ghcr\.io/registrystack/{product}@sha256:[0-9a-f]{{64}}")
    for product in PRODUCTS
}
AUDIT_PREFIXES = {
    "evidence": "/var/lib/registry-evidence",
    "mint": "/var/lib/registry-mint",
    "relay": "/var/lib/relay/audit",
}
EXECUTABLE_PATHS = {product: f"/usr/local/bin/{product}" for product in PRODUCTS}
IMAGE_OWNED_ROOTS = tuple(
    PurePosixPath(path)
    for path in (
        "/bin",
        "/lib",
        "/lib64",
        "/sbin",
        "/usr/bin",
        "/usr/lib",
        "/usr/lib64",
        "/usr/local/bin",
        "/usr/local/lib",
        "/usr/sbin",
    )
)
DYNAMIC_LOADER_PATHS = tuple(
    PurePosixPath(path) for path in ("/etc/ld.so.cache", "/etc/ld.so.preload")
)
KNOWN_EPHEMERAL_BIND_ROOTS = tuple(
    PurePosixPath(path)
    for path in (
        "/dev",
        "/proc",
        "/run",
        "/sys",
        "/tmp",
        "/var/run",
        "/var/tmp",
        "/private/tmp",
        "/private/var/folders",
    )
)
NATIVE_CHECKS = {
    "evidence": [
        "--runtime",
        "/etc/registry-evidence/runtime.yaml",
        "check",
        "--require-runtime-dependencies",
    ],
    "mint": [
        "check",
        "--config",
        "/etc/registry-mint/config.yaml",
        "--require-runtime-dependencies",
    ],
    "relay": ["check", "--runtime", "/etc/relay/runtime.yaml"],
}
DEPENDENCY_HEALTHCHECKS = {"mint": ["/usr/local/bin/mint", "healthcheck"]}


class PreflightError(RuntimeError):
    """A value-free deployment preflight failure."""


@dataclass(frozen=True)
class ServiceSelection:
    product: str
    service: str


def parse_service(raw: str) -> ServiceSelection:
    product, separator, service = raw.partition("=")
    if (
        separator != "="
        or product not in PRODUCTS
        or SERVICE_PATTERN.fullmatch(service) is None
    ):
        raise PreflightError(
            "service selection must be PRODUCT=SERVICE for evidence, mint, or relay"
        )
    return ServiceSelection(product, service)


def closed_json(raw: str) -> dict[str, Any]:
    if len(raw.encode("utf-8")) > MAXIMUM_COMPOSE_BYTES:
        raise PreflightError("rendered Compose configuration exceeds the size limit")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in items:
            if key in output:
                raise PreflightError(
                    "rendered Compose configuration contains a duplicate key"
                )
            output[key] = value
        return output

    try:
        document = json.loads(raw, object_pairs_hook=pairs)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise PreflightError(
            "rendered Compose configuration is not valid JSON"
        ) from error
    if not isinstance(document, dict):
        raise PreflightError("rendered Compose configuration must be an object")
    return document


def compose_prefix(args: argparse.Namespace) -> list[str]:
    command = ["docker", "compose"]
    for env_file in args.env_file:
        command.extend(["--env-file", str(env_file)])
    for compose_file in args.compose_file:
        command.extend(["--file", str(compose_file)])
    return command


def run_compose(
    command: list[str],
    *,
    timeout: int | None,
    capture_output: bool = True,
    input_text: str | None = None,
    timeout_is_failure: bool = True,
    timeout_message: str = "Docker Compose could not complete the preflight",
) -> subprocess.CompletedProcess[str]:
    output_options: dict[str, Any]
    if capture_output:
        output_options = {"capture_output": True}
    else:
        output_options = {
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }
    try:
        return subprocess.run(
            command,
            check=False,
            text=True,
            timeout=timeout,
            input=input_text,
            **output_options,
        )
    except subprocess.TimeoutExpired as error:
        if not timeout_is_failure:
            return subprocess.CompletedProcess(command, 124, "", "")
        raise PreflightError(timeout_message) from error
    except OSError as error:
        raise PreflightError(
            "Docker Compose could not complete the preflight"
        ) from error


def render_compose(prefix: list[str]) -> dict[str, Any]:
    result = run_compose([*prefix, "config", "--format", "json"], timeout=30)
    if result.returncode != 0:
        raise PreflightError("Docker Compose could not render the deployment")
    return closed_json(result.stdout)


def require_string_list(service: dict[str, Any], key: str) -> list[str]:
    value = service.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise PreflightError(f"service container posture is missing {key}")
    return value


def container_path(raw: Any, error: str) -> PurePosixPath:
    if not isinstance(raw, str) or not raw.startswith("/"):
        raise PreflightError(error)
    path = PurePosixPath(raw)
    if (
        raw.startswith("//")
        or raw != path.as_posix()
        or any(part in (".", "..") for part in path.parts)
    ):
        raise PreflightError(error)
    return path


def shadows_executable(target: PurePosixPath, executable: PurePosixPath) -> bool:
    return target == executable or target in executable.parents


def shadows_image_content(target: PurePosixPath, executable: PurePosixPath) -> bool:
    return shadows_executable(target, executable) or any(
        target == root or target in root.parents or root in target.parents
        for root in (*IMAGE_OWNED_ROOTS, *DYNAMIC_LOADER_PATHS)
    )


def validate_secret_entries(service: dict[str, Any], executable: PurePosixPath) -> None:
    secrets = service.get("secrets", [])
    if not isinstance(secrets, list):
        raise PreflightError("service secret posture is invalid")
    for secret in secrets:
        if not isinstance(secret, dict):
            raise PreflightError("service secret posture is invalid")
        target = secret.get("target")
        uid = str(secret.get("uid", ""))
        gid = str(secret.get("gid", ""))
        mode = secret.get("mode")
        target_path = container_path(target, "service secret posture is invalid")
        if (
            uid != "65532"
            or gid != "65532"
            or mode not in (0o400, 0o600, "0400", "0600")
        ):
            raise PreflightError(
                "service secret posture is not owner-only for UID 65532"
            )
        if shadows_image_content(target_path, executable):
            raise PreflightError(
                "service mounts must not shadow official image content"
            )


def validate_config_entries(service: dict[str, Any], executable: PurePosixPath) -> None:
    configs = service.get("configs", [])
    if not isinstance(configs, list):
        raise PreflightError("service config mount posture is invalid")
    for config in configs:
        if not isinstance(config, dict):
            raise PreflightError("service config mount posture is invalid")
        target = container_path(
            config.get("target"), "service config mount posture is invalid"
        )
        if shadows_image_content(target, executable):
            raise PreflightError(
                "service mounts must not shadow official image content"
            )


def validate_named_audit_volume(document: dict[str, Any], source: str) -> None:
    volumes = document.get("volumes")
    if not isinstance(volumes, dict):
        raise PreflightError("rendered Compose configuration has no named volumes")
    declaration = volumes.get(source)
    if not isinstance(declaration, dict):
        raise PreflightError("audit volume is not declared by the Compose deployment")
    driver = declaration.get("driver", "local")
    options = declaration.get("driver_opts", {})
    if (
        not isinstance(driver, str)
        or not isinstance(options, dict)
        or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in options.items()
        )
    ):
        raise PreflightError("audit volume declaration is invalid")
    if driver != "local" or options or declaration.get("external") is True:
        raise PreflightError(
            "audit named volume must use Docker-managed local persistent storage"
        )


def bind_source_is_known_ephemeral(source: str) -> bool:
    path = PurePosixPath(source)
    if (
        source.startswith("//")
        or source != path.as_posix()
        or any(part in (".", "..") for part in path.parts)
    ):
        return True
    return any(
        path == root or root in path.parents for root in KNOWN_EPHEMERAL_BIND_ROOTS
    )


def is_one_or_absent(value: Any) -> bool:
    return value is None or (
        isinstance(value, int) and not isinstance(value, bool) and value == 1
    )


def validate_mounts(
    product: str, service: dict[str, Any], document: dict[str, Any]
) -> None:
    volumes_from = service.get("volumes_from", [])
    if not isinstance(volumes_from, list) or volumes_from:
        raise PreflightError("service must not inherit mounts through volumes_from")
    volumes = service.get("volumes")
    if not isinstance(volumes, list):
        raise PreflightError("service has no runtime mounts")
    service_tmpfs = service.get("tmpfs", [])
    if not isinstance(service_tmpfs, list) or service_tmpfs:
        raise PreflightError("service must not use service-level tmpfs mounts")
    audit_prefix = PurePosixPath(AUDIT_PREFIXES[product])
    executable = PurePosixPath(EXECUTABLE_PATHS[product])
    audit_mounts = 0
    read_only_shm_mounts = 0
    for volume in volumes:
        if not isinstance(volume, dict):
            raise PreflightError("service runtime mount posture is invalid")
        target = volume.get("target")
        read_only = volume.get("read_only") is True
        mount_type = volume.get("type")
        source = volume.get("source")
        target_path = container_path(target, "service runtime mount target is invalid")
        if shadows_image_content(target_path, executable):
            raise PreflightError(
                "service mounts must not shadow official image content"
            )
        protected_paths = (PurePosixPath("/etc"), PurePosixPath("/run/secrets"))
        overlaps_protected_path = any(
            target_path == protected
            or protected in target_path.parents
            or target_path in protected.parents
            for protected in protected_paths
        )
        if overlaps_protected_path and not read_only:
            raise PreflightError("configuration and secret mounts must be read-only")
        if mount_type == "tmpfs":
            if target_path != PurePosixPath("/dev/shm") or not read_only:
                raise PreflightError(
                    "service must mount exactly one read-only tmpfs at /dev/shm"
                )
            read_only_shm_mounts += 1
            continue
        if read_only:
            continue
        if mount_type not in ("bind", "volume") or target_path != audit_prefix:
            raise PreflightError(
                "the audit mount must be the service's only writable mount"
            )
        if not isinstance(source, str) or not source.strip():
            raise PreflightError("service has no writable persistent audit mount")
        if mount_type == "volume":
            validate_named_audit_volume(document, source)
        elif not source.startswith("/") or bind_source_is_known_ephemeral(source):
            raise PreflightError("audit bind mount source must be persistent")
        audit_mounts += 1
    if audit_mounts != 1:
        raise PreflightError(
            "service must have exactly one writable persistent audit mount"
        )
    if read_only_shm_mounts != 1:
        raise PreflightError(
            "service must mount exactly one read-only tmpfs at /dev/shm"
        )


def validate_ports(service: dict[str, Any]) -> None:
    network_mode = service.get("network_mode")
    if network_mode is not None and not isinstance(network_mode, str):
        raise PreflightError("service network namespace posture is invalid")
    if network_mode == "host" or (
        isinstance(network_mode, str)
        and network_mode.startswith(("service:", "container:"))
    ):
        raise PreflightError("service must use its own non-host network namespace")
    ports = service.get("ports", [])
    if not isinstance(ports, list):
        raise PreflightError("service published-port posture is invalid")
    for port in ports:
        if not isinstance(port, dict):
            raise PreflightError("service published-port posture is invalid")
        host_ip = port.get("host_ip")
        if host_ip not in ("127.0.0.1", "::1"):
            raise PreflightError("service ports may be published only on loopback")


def validate_service(selection: ServiceSelection, document: dict[str, Any]) -> None:
    services = document.get("services")
    if not isinstance(services, dict):
        raise PreflightError("rendered Compose configuration has no services")
    service = services.get(selection.service)
    if not isinstance(service, dict):
        raise PreflightError("selected service is absent from the Compose deployment")
    image = service.get("image")
    if (
        not isinstance(image, str)
        or IMAGE_PATTERNS[selection.product].fullmatch(image) is None
    ):
        raise PreflightError(
            "service image is not an official digest-pinned product image"
        )
    if service.get("build") is not None:
        raise PreflightError("service must not build a replacement product image")
    if str(service.get("user", "")) != "65532:65532":
        raise PreflightError("service user must be exactly 65532:65532")
    group_add = service.get("group_add", [])
    if not isinstance(group_add, list) or group_add:
        raise PreflightError("service must not add supplementary groups")
    devices = service.get("devices", [])
    if not isinstance(devices, list) or devices:
        raise PreflightError("service must not add host devices")
    gpus = service.get("gpus", [])
    if gpus not in (None, []) or isinstance(gpus, bool):
        raise PreflightError("service must not add host GPUs")
    device_cgroup_rules = service.get("device_cgroup_rules", [])
    if not isinstance(device_cgroup_rules, list) or device_cgroup_rules:
        raise PreflightError("service must not add device cgroup rules")
    deploy = service.get("deploy", {})
    if not isinstance(deploy, dict):
        raise PreflightError("service replica posture is invalid")
    if not is_one_or_absent(deploy.get("replicas")) or not is_one_or_absent(
        service.get("scale")
    ):
        raise PreflightError("service must run exactly one replica")
    if service.get("read_only") is not True:
        raise PreflightError("service root filesystem must be read-only")
    if service.get("privileged") not in (None, False):
        raise PreflightError("service must not run as a privileged container")
    for hook in ("post_start", "pre_stop"):
        value = service.get(hook, [])
        if not isinstance(value, list) or value:
            raise PreflightError("service must not declare lifecycle hooks")
    if service.get("entrypoint") is not None:
        raise PreflightError("service must not override the official image entrypoint")
    if service.get("command") is not None:
        raise PreflightError("service must not override the official image command")
    environment = service.get("environment", {})
    if not isinstance(environment, dict):
        raise PreflightError("service environment posture is invalid")
    if any(
        name in environment for name in ("LD_AUDIT", "LD_LIBRARY_PATH", "LD_PRELOAD")
    ):
        raise PreflightError("service must not override dynamic-loader behavior")
    fixed_config = {
        "evidence": (
            "REGISTRY_EVIDENCE_RUNTIME",
            "/etc/registry-evidence/runtime.yaml",
        ),
        "mint": ("MINT_CONFIG", "/etc/registry-mint/config.yaml"),
    }.get(selection.product)
    if fixed_config is not None:
        name, expected = fixed_config
        configured = environment.get(name)
        if configured is not None and configured != expected:
            raise PreflightError(
                "service must use the official runtime configuration path"
            )
    if "ALL" not in require_string_list(service, "cap_drop"):
        raise PreflightError("service must drop all Linux capabilities")
    cap_add = service.get("cap_add", [])
    if not isinstance(cap_add, list) or cap_add:
        raise PreflightError("service must not add Linux capabilities")
    security_opt = require_string_list(service, "security_opt")
    if len(security_opt) != 1 or security_opt[0] not in (
        "no-new-privileges",
        "no-new-privileges=true",
        "no-new-privileges:true",
    ):
        raise PreflightError(
            "service security options must contain only no-new-privileges"
        )
    executable = PurePosixPath(EXECUTABLE_PATHS[selection.product])
    validate_secret_entries(service, executable)
    validate_config_entries(service, executable)
    validate_mounts(selection.product, service, document)
    validate_ports(service)


def native_check(
    selection: ServiceSelection, timeout: int, frozen_compose: str
) -> None:
    result = run_compose(
        [
            "docker",
            "compose",
            "--file",
            "-",
            "run",
            "--rm",
            "--no-deps",
            selection.service,
            *NATIVE_CHECKS[selection.product],
        ],
        timeout=timeout,
        capture_output=False,
        input_text=frozen_compose,
        timeout_message=(
            f"{selection.product} service {selection.service} exceeded the "
            "native runtime check deadline"
        ),
    )
    if result.returncode != 0:
        raise PreflightError(
            f"{selection.product} service {selection.service} failed its native runtime check"
        )


def native_check_plan(
    selections: list[ServiceSelection], document: dict[str, Any]
) -> tuple[list[ServiceSelection], set[str]]:
    services = document.get("services")
    if not isinstance(services, dict):
        raise PreflightError("rendered Compose configuration has no services")
    selected_by_service = {selection.service: selection for selection in selections}
    selected_services = set(selected_by_service)
    dependencies: dict[str, set[str]] = {}
    dependency_services: set[str] = set()
    for selection in selections:
        service = services.get(selection.service)
        if not isinstance(service, dict):
            raise PreflightError(
                "selected service is absent from the Compose deployment"
            )
        raw = service.get("depends_on", {})
        if isinstance(raw, dict):
            names = raw.keys()
        elif isinstance(raw, list) and all(isinstance(item, str) for item in raw):
            names = raw
        else:
            raise PreflightError("service dependency posture is invalid")
        selected_dependencies = set(names) & selected_services
        for dependency in selected_dependencies:
            if selected_by_service[dependency].product not in DEPENDENCY_HEALTHCHECKS:
                raise PreflightError(
                    "only Mint can be started as a preflight dependency"
                )
        dependencies[selection.service] = selected_dependencies
        dependency_services.update(selected_dependencies)

    ordered: list[ServiceSelection] = []
    remaining = list(selections)
    completed: set[str] = set()
    while remaining:
        ready = next(
            (
                selection
                for selection in remaining
                if dependencies[selection.service] <= completed
            ),
            None,
        )
        if ready is None:
            raise PreflightError("selected services contain a dependency cycle")
        remaining.remove(ready)
        ordered.append(ready)
        completed.add(ready.service)
    return ordered, dependency_services


def start_dependency(
    selection: ServiceSelection, deadline: float, frozen_compose: str
) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise PreflightError(
            f"dependency service {selection.service} did not become ready"
        )
    not_started = f"dependency service {selection.service} could not be started"
    result = run_compose(
        [
            "docker",
            "compose",
            "--file",
            "-",
            "up",
            "--detach",
            "--no-deps",
            selection.service,
        ],
        timeout=max(1, math.ceil(remaining)),
        capture_output=False,
        input_text=frozen_compose,
        timeout_message=not_started,
    )
    if result.returncode != 0:
        raise PreflightError(not_started)


def wait_for_dependency(
    selection: ServiceSelection, deadline: float, frozen_compose: str
) -> None:
    healthcheck = DEPENDENCY_HEALTHCHECKS.get(selection.product)
    if healthcheck is None:
        raise PreflightError("only Mint can be started as a preflight dependency")
    not_ready = f"dependency service {selection.service} did not become ready"
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PreflightError(not_ready)
        result = run_compose(
            [
                "docker",
                "compose",
                "--file",
                "-",
                "exec",
                "--no-TTY",
                selection.service,
                *healthcheck,
            ],
            timeout=max(1, min(6, int(remaining))),
            capture_output=False,
            input_text=frozen_compose,
            timeout_is_failure=False,
        )
        remaining = deadline - time.monotonic()
        if result.returncode == 0 and remaining > 0:
            return
        if remaining <= 0:
            raise PreflightError(not_ready)
        time.sleep(min(1.0, remaining))


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Preflight official Registry Stack services through Docker Compose."
    )
    parser.add_argument(
        "--compose-file",
        action="append",
        required=True,
        type=Path,
        help="Compose file; repeat in overlay order",
    )
    parser.add_argument(
        "--env-file",
        action="append",
        default=[],
        type=Path,
        help="Operator environment file; values are never printed",
    )
    parser.add_argument(
        "--service",
        action="append",
        required=True,
        help="PRODUCT=SERVICE; repeat for each Evidence, Mint, or Relay service",
    )
    parser.add_argument(
        "--native-check-timeout-seconds",
        type=lambda raw: bounded_seconds(
            raw,
            minimum=MINIMUM_NATIVE_CHECK_TIMEOUT_SECONDS,
            maximum=MAXIMUM_NATIVE_CHECK_TIMEOUT_SECONDS,
        ),
        default=DEFAULT_NATIVE_CHECK_TIMEOUT_SECONDS,
        help=(
            "bounded deadline for each native check; defaults to "
            f"{DEFAULT_NATIVE_CHECK_TIMEOUT_SECONDS} seconds"
        ),
    )
    parser.add_argument(
        "--dependency-timeout-seconds",
        type=lambda raw: bounded_seconds(
            raw,
            minimum=MINIMUM_DEPENDENCY_TIMEOUT_SECONDS,
            maximum=MAXIMUM_DEPENDENCY_TIMEOUT_SECONDS,
        ),
        default=90,
        help="bounded deadline for each declared Mint dependency to become ready",
    )
    return parser.parse_args(argv)


def positive_integer(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a positive integer") from error
    if value <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return value


def bounded_seconds(raw: str, *, minimum: int, maximum: int) -> int:
    value = positive_integer(raw)
    if value < minimum or value > maximum:
        raise argparse.ArgumentTypeError(f"must be between {minimum} and {maximum}")
    return value


def report_started_dependencies(started: Sequence[str], stream: TextIO) -> None:
    if not started:
        return
    names = " ".join(started)
    print(
        "dependency services started by the preflight remain running under the "
        f"operator's Compose lifecycle: {names}. Stop them with the same "
        f"Compose files: docker compose stop {names}",
        file=stream,
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    started: list[str] = []
    try:
        selections = [parse_service(raw) for raw in args.service]
        if len(selections) != len({item.service for item in selections}):
            raise PreflightError("a Compose service was selected more than once")
        prefix = compose_prefix(args)
        document = render_compose(prefix)
        frozen_compose = json.dumps(document, separators=(",", ":"))
        for selection in selections:
            validate_service(selection, document)
        ordered, dependency_services = native_check_plan(selections, document)
        for selection in ordered:
            native_check(
                selection,
                args.native_check_timeout_seconds,
                frozen_compose,
            )
            if selection.service in dependency_services:
                deadline = time.monotonic() + args.dependency_timeout_seconds
                start_dependency(
                    selection,
                    deadline,
                    frozen_compose,
                )
                started.append(selection.service)
                wait_for_dependency(
                    selection,
                    deadline,
                    frozen_compose,
                )
    except PreflightError as error:
        print(f"runtime preflight failed: {error}", file=sys.stderr)
        report_started_dependencies(started, sys.stderr)
        return 1

    print(f"runtime preflight passed for {len(selections)} service(s)")
    report_started_dependencies(started, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
