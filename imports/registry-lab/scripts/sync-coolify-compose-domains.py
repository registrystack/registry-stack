#!/usr/bin/env python3
"""Merge required Coolify Docker Compose service domains into an app."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


DOMAIN_FIELDS = ("docker_compose_domains", "dockerComposeDomains")


class DomainSyncError(RuntimeError):
    """A recoverable domain sync failure."""


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError as exc:
        raise DomainSyncError("PyYAML is required to read hosted compose files") from exc

    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise DomainSyncError(f"{path}: expected a YAML mapping")
    return loaded


def parse_domain_specs(specs: list[str]) -> dict[str, str]:
    domains: dict[str, str] = {}
    for spec in specs:
        service, sep, domain = spec.partition("=")
        service = service.strip()
        domain = domain.strip()
        if sep != "=" or not service or not domain:
            raise DomainSyncError(f"invalid --domain {spec!r}; expected SERVICE=URL")
        if "://" not in domain:
            raise DomainSyncError(f"{service}: domain must include http:// or https://")
        domains[service] = domain
    return domains


def require_compose_hosts(compose: dict[str, Any], desired: dict[str, str]) -> None:
    hosted_domains = compose.get("x-hosted-domains")
    if not isinstance(hosted_domains, dict):
        raise DomainSyncError("compose file is missing x-hosted-domains")

    for service, domain in sorted(desired.items()):
        expected = hosted_domains.get(service)
        if not isinstance(expected, str) or not expected.strip():
            raise DomainSyncError(f"{service}: compose x-hosted-domains entry is missing")

        expected_host = hostname(expected)
        desired_host = hostname(domain)
        if expected_host != desired_host:
            raise DomainSyncError(
                f"{service}: --domain host {desired_host!r} does not match compose host {expected_host!r}"
            )


def hostname(domain: str) -> str:
    text = domain.strip()
    parsed = urllib.parse.urlsplit(text if "://" in text else f"https://{text}")
    host = parsed.hostname
    if not host:
        raise DomainSyncError(f"domain {domain!r} has no hostname")
    return host.lower()


def extract_stored_domains(payload: Any) -> dict[str, str]:
    if isinstance(payload, dict):
        for field in DOMAIN_FIELDS:
            if field in payload:
                return normalize_domain_mapping(payload[field])
    return normalize_domain_mapping(payload)


def normalize_domain_mapping(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return {}
        try:
            return normalize_domain_mapping(json.loads(text))
        except json.JSONDecodeError:
            return {}
    if isinstance(value, list):
        domains: dict[str, str] = {}
        for item in value:
            domains.update(normalize_domain_mapping(item))
        return domains
    if isinstance(value, dict):
        name = value.get("name")
        domain = value.get("domain")
        if isinstance(name, str) and isinstance(domain, str):
            return {name: domain}

        domains = {}
        for service, entry in value.items():
            if isinstance(entry, dict) and isinstance(entry.get("domain"), str):
                domains[str(service)] = entry["domain"]
            elif isinstance(entry, str) and entry.strip():
                domains[str(service)] = entry
        return domains
    return {}


def as_patch_entries(domains: dict[str, str]) -> list[dict[str, str]]:
    return [{"name": service, "domain": domains[service]} for service in sorted(domains)]


def assert_desired_stored(stored: dict[str, str], desired: dict[str, str]) -> None:
    missing = {service: domain for service, domain in desired.items() if stored.get(service) != domain}
    if missing:
        details = ", ".join(f"{service}={domain}" for service, domain in sorted(missing.items()))
        raise DomainSyncError(f"Coolify did not persist required compose domain(s): {details}")


def fetch_application(api_base_url: str, app_uuid: str, token: str) -> Any:
    return request_json(
        "GET",
        f"{api_base_url.rstrip('/')}/applications/{urllib.parse.quote(app_uuid, safe='')}",
        token,
    )


def patch_compose_domains(api_base_url: str, app_uuid: str, token: str, domains: dict[str, str]) -> Any:
    return request_json(
        "PATCH",
        f"{api_base_url.rstrip('/')}/applications/{urllib.parse.quote(app_uuid, safe='')}",
        token,
        {"docker_compose_domains": as_patch_entries(domains)},
    )


def request_json(method: str, url: str, token: str, body: Any | None = None) -> Any:
    data = None
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
    }
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")[:500]
        raise DomainSyncError(
            f"Coolify API returned HTTP {exc.code} for {safe_url(url)}: {error_body}"
        ) from exc
    except urllib.error.URLError as exc:
        raise DomainSyncError(f"Coolify API request failed for {safe_url(url)}: {exc.reason}") from exc

    if not raw:
        return {}
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DomainSyncError(f"Coolify API returned invalid JSON for {safe_url(url)}") from exc


def safe_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", parsed.fragment))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose", type=Path, default=Path("compose.coolify.yaml"))
    parser.add_argument("--api-base-url", required=True)
    parser.add_argument("--app-uuid", required=True)
    parser.add_argument(
        "--domain",
        action="append",
        required=True,
        help="required service domain mapping, in SERVICE=https://host:port form",
    )
    parser.add_argument(
        "--token-env",
        default="COOLIFY_API_TOKEN",
        help="environment variable that contains the Coolify API token",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    token = os.environ.get(args.token_env)
    if not token:
        raise DomainSyncError(f"{args.token_env} is not configured")

    desired = parse_domain_specs(args.domain)
    require_compose_hosts(load_yaml_mapping(args.compose), desired)

    current = extract_stored_domains(fetch_application(args.api_base_url, args.app_uuid, token))
    merged = {**current, **desired}
    response = patch_compose_domains(args.api_base_url, args.app_uuid, token, merged)
    stored = extract_stored_domains(response)
    if not stored:
        stored = extract_stored_domains(fetch_application(args.api_base_url, args.app_uuid, token))
    assert_desired_stored(stored, desired)

    services = ", ".join(f"{service}={domain}" for service, domain in sorted(desired.items()))
    print(f"Coolify compose domains include required service domain(s): {services}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DomainSyncError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
