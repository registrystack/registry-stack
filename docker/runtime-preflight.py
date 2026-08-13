#!/usr/bin/env python3
"""Preflight official Registry Stack services in their Compose runtime context."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence


MAXIMUM_COMPOSE_BYTES = 4 * 1024 * 1024
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
    command: list[str], *, timeout: int, capture_output: bool = True
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
    except (OSError, subprocess.TimeoutExpired) as error:
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


def validate_mounts(product: str, service: dict[str, Any]) -> None:
    volumes = service.get("volumes")
    if not isinstance(volumes, list):
        raise PreflightError("service has no runtime mounts")
    audit_prefix = AUDIT_PREFIXES[product]
    audit_writable = False
    for volume in volumes:
        if not isinstance(volume, dict):
            raise PreflightError("service runtime mount posture is invalid")
        target = volume.get("target")
        read_only = volume.get("read_only") is True
        mount_type = volume.get("type")
        source = volume.get("source")
        if not isinstance(target, str) or not target.startswith("/"):
            raise PreflightError("service runtime mount target is invalid")
        protected_paths = ("/etc", "/run/secrets")
        overlaps_protected_path = target == "/" or any(
            target == protected
            or target.startswith(f"{protected}/")
            or protected.startswith(f"{target.rstrip('/')}/")
            for protected in protected_paths
        )
        if overlaps_protected_path and not read_only:
            raise PreflightError("configuration and secret mounts must be read-only")
        if mount_type in ("bind", "volume") and (
            target == audit_prefix or target.startswith(f"{audit_prefix}/")
        ):
            audit_writable = (
                not read_only and isinstance(source, str) and bool(source.strip())
            )
    if not audit_writable:
        raise PreflightError("service has no writable persistent audit mount")


def validate_ports(service: dict[str, Any]) -> None:
    if service.get("network_mode") == "host":
        raise PreflightError("service must not use the host network namespace")
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
    if str(service.get("user", "")) != "65532:65532":
        raise PreflightError("service user must be exactly 65532:65532")
    if service.get("read_only") is not True:
        raise PreflightError("service root filesystem must be read-only")
    if service.get("entrypoint") is not None:
        raise PreflightError("service must not override the official image entrypoint")
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
    validate_mounts(selection.product, service)
    validate_ports(service)


def native_check(prefix: list[str], selection: ServiceSelection) -> None:
    result = run_compose(
        [
            *prefix,
            "run",
            "--rm",
            "--no-deps",
            selection.service,
            *NATIVE_CHECKS[selection.product],
        ],
        timeout=90,
        capture_output=False,
    )
    if result.returncode != 0:
        raise PreflightError(
            f"{selection.product} service {selection.service} failed its native runtime check"
        )


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
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        selections = [parse_service(raw) for raw in args.service]
        if len(selections) != len({item.service for item in selections}):
            raise PreflightError("a Compose service was selected more than once")
        prefix = compose_prefix(args)
        document = render_compose(prefix)
        for selection in selections:
            validate_service(selection, document)
        for selection in selections:
            native_check(prefix, selection)
    except PreflightError as error:
        print(f"runtime preflight failed: {error}", file=sys.stderr)
        return 1

    print(f"runtime preflight passed for {len(selections)} service(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
