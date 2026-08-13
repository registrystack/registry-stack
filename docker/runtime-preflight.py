#!/usr/bin/env python3
"""Preflight official Registry Stack services in their Compose runtime context."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence


MAXIMUM_COMPOSE_BYTES = 4 * 1024 * 1024
MINIMUM_NATIVE_CHECK_TIMEOUT_SECONDS = 30
MAXIMUM_NATIVE_CHECK_TIMEOUT_SECONDS = 24 * 60 * 60
MINIMUM_DEPENDENCY_TIMEOUT_SECONDS = 5
MAXIMUM_DEPENDENCY_TIMEOUT_SECONDS = 10 * 60
PRODUCTS = ("evidence", "mint", "relay")
SERVICE_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?")
IMAGE_PATTERNS = {
    product: re.compile(rf"ghcr\.io/registrystack/{product}@sha256:[0-9a-f]{{64}}")
    for product in PRODUCTS
}
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
DEPENDENCY_HEALTHCHECKS = {
    "mint": ["/usr/local/bin/mint", "healthcheck"],
    "relay": ["/usr/local/bin/relay", "healthcheck"],
}


class PreflightError(RuntimeError):
    """A value-free deployment preflight failure."""


@dataclass(frozen=True)
class ServiceSelection:
    product: str
    service: str


@dataclass(frozen=True)
class AuditRoot:
    service: str
    path: str


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


def normalized_container_path(raw: str) -> str:
    if not raw.startswith("/") or raw.startswith("//") or len(raw) > 512:
        raise PreflightError("container storage root must be a bounded absolute path")
    parts = raw.split("/")[1:]
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise PreflightError("container storage root must be a bounded absolute path")
    return f"/{'/'.join(parts)}"


def parse_audit_root(raw: str) -> AuditRoot:
    service, separator, path = raw.partition("=")
    if separator != "=" or SERVICE_PATTERN.fullmatch(service) is None:
        raise PreflightError("audit root must be SERVICE=ABSOLUTE_CONTAINER_PATH")
    return AuditRoot(service, normalized_container_path(path))


def parse_service_name(raw: str) -> str:
    if SERVICE_PATTERN.fullmatch(raw) is None:
        raise PreflightError("dependency service name is invalid")
    return raw


def bounded_seconds(raw: str, *, minimum: int, maximum: int) -> int:
    try:
        value = int(raw, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("timeout must be an integer number of seconds") from error
    if not minimum <= value <= maximum:
        raise argparse.ArgumentTypeError(
            f"timeout must be between {minimum} and {maximum} seconds"
        )
    return value


def path_at_or_below(path: str, root: str) -> bool:
    return path == root or path.startswith(f"{root}/")


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
    timeout: int,
    capture_output: bool = True,
    timeout_is_failure: bool = True,
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
            **output_options,
        )
    except subprocess.TimeoutExpired as error:
        if not timeout_is_failure:
            return subprocess.CompletedProcess(command, 124, "", "")
        raise PreflightError(
            "Docker Compose could not complete the preflight"
        ) from error
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


def validate_secret_entries(service: dict[str, Any]) -> None:
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
        if (
            not isinstance(target, str)
            or not target.startswith("/")
            or uid != "65532"
            or gid != "65532"
            or mode not in (0o400, 0o600, "0400", "0600")
        ):
            raise PreflightError(
                "service secret posture is not owner-only for UID 65532"
            )


def named_volume_is_ephemeral(document: dict[str, Any], source: str) -> bool:
    volumes = document.get("volumes")
    if not isinstance(volumes, dict):
        raise PreflightError("rendered Compose configuration has no named volumes")
    declaration = volumes.get(source)
    if not isinstance(declaration, dict):
        raise PreflightError("audit volume is not declared by the Compose deployment")
    driver = declaration.get("driver", "local")
    options = declaration.get("driver_opts", {})
    if not isinstance(driver, str) or not isinstance(options, dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in options.items()
    ):
        raise PreflightError("audit volume declaration is invalid")
    backend_facts = [driver, *options.keys(), *options.values()]
    return any("tmpfs" in fact.lower() for fact in backend_facts)


def validate_mounts(
    service: dict[str, Any], document: dict[str, Any], audit_root: str
) -> None:
    volumes_from = service.get("volumes_from", [])
    if not isinstance(volumes_from, list) or volumes_from:
        raise PreflightError("service must not inherit mounts through volumes_from")
    volumes = service.get("volumes")
    if not isinstance(volumes, list):
        raise PreflightError("service has no runtime mounts")
    persistent_audit_mount = False
    mount_targets: list[str] = []
    for volume in volumes:
        if not isinstance(volume, dict):
            raise PreflightError("service runtime mount posture is invalid")
        target = volume.get("target")
        read_only = volume.get("read_only") is True
        mount_type = volume.get("type")
        source = volume.get("source")
        if not isinstance(target, str):
            raise PreflightError("service runtime mount target is invalid")
        target = normalized_container_path(target)
        mount_targets.append(target)
        protected_paths = ("/etc", "/run/secrets")
        overlaps_protected_path = target == "/" or any(
            target == protected
            or target.startswith(f"{protected}/")
            or protected.startswith(f"{target.rstrip('/')}/")
            for protected in protected_paths
        )
        if overlaps_protected_path and not read_only:
            raise PreflightError("configuration and secret mounts must be read-only")
        if target == audit_root and mount_type in ("bind", "volume"):
            has_source = isinstance(source, str) and bool(source.strip())
            if mount_type == "volume" and has_source:
                if named_volume_is_ephemeral(document, source):
                    raise PreflightError("audit volume backend must be persistent")
            persistent_audit_mount = not read_only and has_source
    if not persistent_audit_mount:
        raise PreflightError("asserted audit root is not a writable persistent mount")

    if sum(target == audit_root for target in mount_targets) != 1:
        raise PreflightError("asserted audit root must resolve to exactly one mount")
    if any(
        target != audit_root and path_at_or_below(target, audit_root)
        for target in mount_targets
    ):
        raise PreflightError("asserted audit root is shadowed by another mount")

    tmpfs = service.get("tmpfs", [])
    if not isinstance(tmpfs, list) or not all(isinstance(item, str) for item in tmpfs):
        raise PreflightError("service tmpfs posture is invalid")
    for item in tmpfs:
        target = normalized_container_path(item.split(":", 1)[0])
        if path_at_or_below(target, audit_root):
            raise PreflightError("asserted audit root is shadowed by tmpfs")


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


def validate_service(
    selection: ServiceSelection, document: dict[str, Any], audit_root: str
) -> None:
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
    if str(service.get("user", "")) != "65532:65532":
        raise PreflightError("service user must be exactly 65532:65532")
    if service.get("read_only") is not True:
        raise PreflightError("service root filesystem must be read-only")
    if service.get("privileged") not in (None, False):
        raise PreflightError("service must not run as a privileged container")
    if service.get("entrypoint") is not None:
        raise PreflightError("service must not override the official image entrypoint")
    if service.get("command") is not None:
        raise PreflightError("service must not override the official image command")
    environment = service.get("environment", {})
    if not isinstance(environment, dict):
        raise PreflightError("service environment posture is invalid")
    fixed_config = {
        "evidence": ("REGISTRY_EVIDENCE_RUNTIME", "/etc/registry-evidence/runtime.yaml"),
        "mint": ("MINT_CONFIG", "/etc/registry-mint/config.yaml"),
    }.get(selection.product)
    if fixed_config is not None:
        name, expected = fixed_config
        configured = environment.get(name)
        if configured is not None and configured != expected:
            raise PreflightError("service must use the official runtime configuration path")
    if "ALL" not in require_string_list(service, "cap_drop"):
        raise PreflightError("service must drop all Linux capabilities")
    cap_add = service.get("cap_add", [])
    if not isinstance(cap_add, list) or cap_add:
        raise PreflightError("service must not add Linux capabilities")
    security_opt = require_string_list(service, "security_opt")
    if not any(
        option
        in ("no-new-privileges", "no-new-privileges=true", "no-new-privileges:true")
        for option in security_opt
    ):
        raise PreflightError("service must prohibit privilege escalation")
    validate_secret_entries(service)
    validate_mounts(service, document, audit_root)
    validate_ports(service)


def native_check(
    prefix: list[str],
    selection: ServiceSelection,
    audit_root: str,
    timeout: int,
) -> None:
    result = run_compose(
        [
            *prefix,
            "run",
            "--rm",
            "--no-deps",
            selection.service,
            *NATIVE_CHECKS[selection.product],
            "--require-audit-under",
            audit_root,
        ],
        timeout=timeout,
        capture_output=False,
    )
    if result.returncode != 0:
        raise PreflightError(
            f"{selection.product} service {selection.service} failed its native runtime check"
        )


def start_dependency(prefix: list[str], selection: ServiceSelection, timeout: int) -> None:
    result = run_compose(
        [
            *prefix,
            "up",
            "--detach",
            "--no-deps",
            selection.service,
        ],
        timeout=min(timeout, 30),
        capture_output=False,
    )
    if result.returncode != 0:
        raise PreflightError("a declared dependency service could not be started")


def wait_for_dependency(
    prefix: list[str], selection: ServiceSelection, timeout: int
) -> None:
    healthcheck = DEPENDENCY_HEALTHCHECKS.get(selection.product)
    if healthcheck is None:
        raise PreflightError("the selected product cannot be a preflight dependency")
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PreflightError("a declared dependency service did not become ready")
        result = run_compose(
            [
                *prefix,
                "exec",
                "--no-TTY",
                selection.service,
                *healthcheck,
            ],
            timeout=max(1, min(6, int(remaining))),
            capture_output=False,
            timeout_is_failure=False,
        )
        if result.returncode == 0:
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PreflightError("a declared dependency service did not become ready")
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
        "--audit-root",
        action="append",
        required=True,
        help="SERVICE=ABSOLUTE_CONTAINER_PATH for the service's persistent audit mount",
    )
    parser.add_argument(
        "--dependency-service",
        action="append",
        default=[],
        help="selected internal service to check, start, and probe; repeat in dependency order",
    )
    parser.add_argument(
        "--native-check-timeout-seconds",
        type=lambda raw: bounded_seconds(
            raw,
            minimum=MINIMUM_NATIVE_CHECK_TIMEOUT_SECONDS,
            maximum=MAXIMUM_NATIVE_CHECK_TIMEOUT_SECONDS,
        ),
        default=90,
        help="bounded deadline for each native product check",
    )
    parser.add_argument(
        "--dependency-timeout-seconds",
        type=lambda raw: bounded_seconds(
            raw,
            minimum=MINIMUM_DEPENDENCY_TIMEOUT_SECONDS,
            maximum=MAXIMUM_DEPENDENCY_TIMEOUT_SECONDS,
        ),
        default=90,
        help="bounded deadline for each declared dependency to become ready",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        selections = [parse_service(raw) for raw in args.service]
        if len(selections) != len({item.service for item in selections}):
            raise PreflightError("a Compose service was selected more than once")
        audit_roots = [parse_audit_root(raw) for raw in args.audit_root]
        if len(audit_roots) != len({item.service for item in audit_roots}):
            raise PreflightError("a Compose service received more than one audit root")
        roots_by_service = {item.service: item.path for item in audit_roots}
        selected_by_service = {item.service: item for item in selections}
        if set(roots_by_service) != set(selected_by_service):
            raise PreflightError("every selected service must have exactly one audit root")
        dependency_names = [parse_service_name(raw) for raw in args.dependency_service]
        if len(dependency_names) != len(set(dependency_names)):
            raise PreflightError("a dependency service was selected more than once")
        if any(name not in selected_by_service for name in dependency_names):
            raise PreflightError("every dependency service must also be selected for preflight")
        dependencies = [selected_by_service[name] for name in dependency_names]
        if any(item.product not in DEPENDENCY_HEALTHCHECKS for item in dependencies):
            raise PreflightError("the selected product cannot be a preflight dependency")
        prefix = compose_prefix(args)
        document = render_compose(prefix)
        for selection in selections:
            validate_service(selection, document, roots_by_service[selection.service])
        checked: set[str] = set()
        for selection in dependencies:
            native_check(
                prefix,
                selection,
                roots_by_service[selection.service],
                args.native_check_timeout_seconds,
            )
            checked.add(selection.service)
            start_dependency(prefix, selection, args.dependency_timeout_seconds)
            wait_for_dependency(prefix, selection, args.dependency_timeout_seconds)
        for selection in selections:
            if selection.service not in checked:
                native_check(
                    prefix,
                    selection,
                    roots_by_service[selection.service],
                    args.native_check_timeout_seconds,
                )
    except PreflightError as error:
        print(f"runtime preflight failed: {error}", file=sys.stderr)
        return 1

    print(f"runtime preflight passed for {len(selections)} service(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
