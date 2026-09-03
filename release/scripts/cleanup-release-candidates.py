#!/usr/bin/env python3
"""Delete expired versions from exact private release-candidate packages."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any


OWNER = "registrystack"
RETENTION_DAYS = 8
CANDIDATE_PACKAGES = (
    # Listing an absent package fails closed, so a candidate name joins this
    # allowlist with the release that first publishes it.
    "discovery-candidate",
    "evidence-candidate",
    "mint-candidate",
    "relay-candidate",
)
PUBLIC_PACKAGES = (
    # Retired public names stay denylisted so cleanup can never delete history.
    "registry-notary",
    "registry-relay",
    "discovery",
    "evidence",
    "mint",
    "registry-server",
    "relay",
)


class CleanupError(ValueError):
    """Raised when cleanup cannot prove that a version is safe to delete."""


class GitHubApiError(CleanupError):
    """An HTTP response from GitHub with a preserved status code."""

    def __init__(self, method: str, url: str, status: int, detail: str) -> None:
        self.status = status
        super().__init__(f"GitHub API {method} {url} failed with {status}: {detail}")


def parse_rfc3339(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str):
        raise CleanupError(f"{field} must be an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise CleanupError(f"{field} must be an RFC 3339 timestamp") from error
    if parsed.tzinfo is None:
        raise CleanupError(f"{field} must include a timezone")
    return parsed.astimezone(UTC)


def next_link(value: str | None) -> str | None:
    if not value:
        return None
    for part in value.split(","):
        match = re.match(r'\s*<([^>]+)>;\s*rel="([^"]+)"\s*$', part)
        if match and match.group(2) == "next":
            return match.group(1)
    return None


class GitHubClient:
    def __init__(
        self,
        token: str,
        *,
        api_url: str = "https://api.github.com",
    ) -> None:
        if not token:
            raise CleanupError("GH_TOKEN is required")
        self.api_url = api_url.rstrip("/")
        self.headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "registry-stack-release-candidate-cleanup",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def request(
        self, path_or_url: str, *, method: str = "GET"
    ) -> tuple[Any, dict[str, str]]:
        url = (
            path_or_url
            if path_or_url.startswith("https://")
            else f"{self.api_url}{path_or_url}"
        )
        request = urllib.request.Request(url, headers=self.headers, method=method)
        try:
            with urllib.request.urlopen(request) as response:
                payload = response.read()
                value = json.loads(payload) if payload else None
                headers = {key.lower(): val for key, val in response.headers.items()}
                return value, headers
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            raise GitHubApiError(method, url, error.code, detail) from error
        except (urllib.error.URLError, json.JSONDecodeError) as error:
            raise CleanupError(f"GitHub API {method} {url} failed: {error}") from error

    def server_now(self) -> datetime:
        _value, headers = self.request("/rate_limit")
        date = headers.get("date")
        if not date:
            raise CleanupError("GitHub API response omitted its server Date header")
        try:
            parsed = parsedate_to_datetime(date)
        except (TypeError, ValueError) as error:
            raise CleanupError(
                "GitHub API returned an invalid server Date header"
            ) from error
        if parsed.tzinfo is None:
            raise CleanupError("GitHub API server Date header omitted its timezone")
        return parsed.astimezone(UTC)

    def package_versions(self, package: str) -> list[dict[str, Any]]:
        assert_candidate_package(package)
        encoded = urllib.parse.quote(package, safe="")
        path: str | None = (
            f"/orgs/{OWNER}/packages/container/{encoded}/versions?per_page=100"
        )
        visited: set[str] = set()
        versions: list[dict[str, Any]] = []
        while path is not None:
            if path in visited:
                raise CleanupError("GitHub pagination repeated a versions page")
            visited.add(path)
            value, headers = self.request(path)
            if not isinstance(value, list):
                raise CleanupError(f"GitHub returned invalid versions for {package}")
            if not all(isinstance(item, dict) for item in value):
                raise CleanupError(f"GitHub returned a malformed version for {package}")
            versions.extend(value)
            path = next_link(headers.get("link"))
            if path is not None:
                parsed = urllib.parse.urlparse(path)
                base = urllib.parse.urlparse(self.api_url)
                if parsed.scheme != base.scheme or parsed.netloc != base.netloc:
                    raise CleanupError("GitHub pagination link changed API origin")
        return versions

    def delete_package_version(self, package: str, version_id: int) -> None:
        assert_candidate_package(package)
        if (
            not isinstance(version_id, int)
            or isinstance(version_id, bool)
            or version_id <= 0
        ):
            raise CleanupError("package version id must be a positive integer")
        encoded = urllib.parse.quote(package, safe="")
        self.request(
            f"/orgs/{OWNER}/packages/container/{encoded}/versions/{version_id}",
            method="DELETE",
        )


def assert_candidate_package(package: str) -> None:
    if package in PUBLIC_PACKAGES:
        raise CleanupError(f"refusing to touch public package {package}")
    if package not in CANDIDATE_PACKAGES:
        raise CleanupError(
            f"package is not in the exact candidate allowlist: {package}"
        )


def cleanup(
    client: Any,
    *,
    packages: list[str],
    server_now: datetime,
    apply: bool,
) -> dict[str, Any]:
    if server_now.tzinfo is None:
        raise CleanupError("server time must include a timezone")
    selected = list(dict.fromkeys(packages))
    if not selected:
        raise CleanupError("at least one candidate package is required")
    for package in selected:
        assert_candidate_package(package)
    cutoff = server_now.astimezone(UTC) - timedelta(days=RETENTION_DAYS)
    actions: list[dict[str, Any]] = []
    for package in selected:
        for version in client.package_versions(package):
            version_id = version.get("id")
            if (
                not isinstance(version_id, int)
                or isinstance(version_id, bool)
                or version_id <= 0
            ):
                raise CleanupError(f"{package} returned an invalid package version id")
            updated_at = parse_rfc3339(
                version.get("updated_at"), field=f"{package}/{version_id}.updated_at"
            )
            if updated_at > server_now:
                raise CleanupError(
                    f"{package}/{version_id} has a future server timestamp"
                )
            if updated_at >= cutoff:
                continue
            metadata = version.get("metadata")
            container = (
                metadata.get("container") if isinstance(metadata, dict) else None
            )
            tags = container.get("tags") if isinstance(container, dict) else None
            if not isinstance(tags, list) or not all(
                isinstance(tag, str) for tag in tags
            ):
                raise CleanupError(f"{package}/{version_id} has malformed tag metadata")
            action = {
                "package": package,
                "version_id": version_id,
                "updated_at": updated_at.isoformat().replace("+00:00", "Z"),
                "tags": sorted(tags),
                "action": "delete" if apply else "would_delete",
            }
            actions.append(action)
    if apply:
        for action in actions:
            client.delete_package_version(action["package"], action["version_id"])
    return {
        "schema_version": "registry-stack.release-candidate-cleanup.v1",
        "owner": OWNER,
        "retention_days": RETENTION_DAYS,
        "server_now": server_now.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "dry_run": not apply,
        "packages": selected,
        "actions": actions,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Clean only the exact Registry Stack release-candidate packages. "
            "The default is a dry run; --apply is required to delete."
        )
    )
    parser.add_argument(
        "--package",
        action="append",
        choices=CANDIDATE_PACKAGES,
        dest="packages",
        help="candidate package to clean; defaults to all exact allowlisted packages",
    )
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--output")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        repository = os.environ.get("GITHUB_REPOSITORY")
        if repository is not None and repository != f"{OWNER}/registry-stack":
            raise CleanupError(
                f"cleanup must run in {OWNER}/registry-stack, got {repository}"
            )
        client = GitHubClient(os.environ.get("GH_TOKEN", ""))
        result = cleanup(
            client,
            packages=args.packages or list(CANDIDATE_PACKAGES),
            server_now=client.server_now(),
            apply=args.apply,
        )
    except CleanupError as error:
        print(f"release candidate cleanup failed: {error}", file=sys.stderr)
        return 1
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(rendered)
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
