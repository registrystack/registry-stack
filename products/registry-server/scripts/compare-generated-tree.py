#!/usr/bin/env python3
"""Compare frozen Registry Server generated baselines without traversing links."""

from __future__ import annotations

import stat
import sys
from pathlib import Path


ASSET_SITE_PLACEMENT_PATHS = (
    "generated/manifest/registry-manifest.json",
    "generated/manifest/dcat.jsonld",
    "generated/metadata/registry.json",
    "generated/openapi.json",
    "generated/postgres/schema.sql",
    "generated/schemas/asset-item.schema.json",
    "generated/schemas/asset-placement.schema.json",
    "generated/schemas/asset-site.schema.json",
    "generated/schemas/inspection-event.schema.json",
)
BUSINESS_ESTABLISHMENTS_PATHS = (
    "generated/manifest/registry-manifest.json",
    "generated/manifest/dcat.jsonld",
    "generated/metadata/registry.json",
    "generated/openapi.json",
    "generated/postgres/schema.sql",
    "generated/schemas/operator-assignment.schema.json",
    "generated/schemas/business.schema.json",
    "generated/schemas/establishment.schema.json",
)
PUBLICSCHEMA_HOUSEHOLD_PATHS = (
    "generated/manifest/registry-manifest.json",
    "generated/manifest/dcat.jsonld",
    "generated/metadata/registry.json",
    "generated/openapi.json",
    "generated/postgres/schema.sql",
    "generated/schemas/group-membership.schema.json",
    "generated/schemas/household.schema.json",
    "generated/schemas/person.schema.json",
)
ASSET_SITE_PLACEMENT_CHANGE_REQUEST_PATHS = ASSET_SITE_PLACEMENT_PATHS + (
    "generated/schemas/placement-correction-request.schema.json",
)
PUBLICSCHEMA_HOUSEHOLD_CHANGE_REQUEST_PATHS = PUBLICSCHEMA_HOUSEHOLD_PATHS + (
    "generated/schemas/register-household-contact-request.schema.json",
)
PERSON_NAME_CHANGE_RHAI_PATHS = (
    "generated/manifest/registry-manifest.json",
    "generated/manifest/dcat.jsonld",
    "generated/metadata/registry.json",
    "generated/openapi.json",
    "generated/postgres/schema.sql",
    "generated/schemas/person.schema.json",
    "generated/schemas/person-name-change-request.schema.json",
)
ASSET_REGISTRATION_ACTIONS_PATHS = (
    "compiled/actions.json",
    "generated/action-schemas/register-asset-with-inspection.invoke.input.schema.json",
    "generated/action-schemas/register-asset-with-inspection.invoke.response.schema.json",
    "generated/manifest/dcat.jsonld",
    "generated/manifest/registry-manifest.json",
    "generated/metadata/registry.json",
    "generated/openapi.json",
    "generated/postgres/schema.sql",
    "generated/schemas/asset-inspection.schema.json",
    "generated/schemas/asset.schema.json",
)
HOUSEHOLD_CONTACT_ACTIONS_PATHS = (
    "compiled/actions.json",
    "generated/action-schemas/register-household-contact.invoke.input.schema.json",
    "generated/action-schemas/register-household-contact.invoke.response.schema.json",
    "generated/action-schemas/register-household-contact.target-conditions.input.schema.json",
    "generated/action-schemas/register-household-contact.target-conditions.response.schema.json",
    "generated/manifest/dcat.jsonld",
    "generated/manifest/registry-manifest.json",
    "generated/metadata/registry.json",
    "generated/openapi.json",
    "generated/postgres/schema.sql",
    "generated/schemas/group-membership.schema.json",
    "generated/schemas/household.schema.json",
    "generated/schemas/person.schema.json",
    "generated/schemas/service-center.schema.json",
)

EXPECTED_PATHS_BY_BASELINE = {
    "asset-site-placement": ASSET_SITE_PLACEMENT_PATHS,
    "business-establishments": BUSINESS_ESTABLISHMENTS_PATHS,
    "asset-site-placement-change-requests": ASSET_SITE_PLACEMENT_CHANGE_REQUEST_PATHS,
    "publicschema-household-change-requests": PUBLICSCHEMA_HOUSEHOLD_CHANGE_REQUEST_PATHS,
    "person-name-change-rhai": PERSON_NAME_CHANGE_RHAI_PATHS,
    "asset-registration-actions": ASSET_REGISTRATION_ACTIONS_PATHS,
    "household-contact-actions": HOUSEHOLD_CONTACT_ACTIONS_PATHS,
}
EXPECTED_PATHS = ASSET_SITE_PLACEMENT_PATHS


def regular_tree(root: Path) -> dict[str, bytes]:
    try:
        root_status = root.lstat()
    except FileNotFoundError as exc:
        raise ValueError(f"missing tree: {root}") from exc
    if stat.S_ISLNK(root_status.st_mode) or not stat.S_ISDIR(root_status.st_mode):
        raise ValueError(f"tree root must be a real directory: {root}")

    files: dict[str, bytes] = {}
    directories = [root]
    while directories:
        directory = directories.pop()
        for child in directory.iterdir():
            status = child.lstat()
            relative = child.relative_to(root).as_posix()
            if stat.S_ISLNK(status.st_mode):
                raise ValueError(f"symbolic link is not permitted: {relative}")
            if stat.S_ISDIR(status.st_mode):
                directories.append(child)
            elif stat.S_ISREG(status.st_mode):
                files[relative] = child.read_bytes()
            else:
                raise ValueError(f"non-regular generated entry is not permitted: {relative}")
    return files


def compare(baseline: Path, candidate: Path) -> list[str]:
    baseline_tree = regular_tree(baseline)
    candidate_tree = regular_tree(candidate)
    expected = set(
        EXPECTED_PATHS_BY_BASELINE.get(baseline.name, ASSET_SITE_PLACEMENT_PATHS)
    )
    errors: list[str] = []
    for label, tree in (("baseline", baseline_tree), ("candidate", candidate_tree)):
        paths = set(tree)
        if paths != expected:
            missing = sorted(expected - paths)
            unexpected = sorted(paths - expected)
            if missing:
                errors.append(f"{label} is missing expected artifacts: {', '.join(missing)}")
            if unexpected:
                errors.append(f"{label} has unexpected artifacts: {', '.join(unexpected)}")
    for path in expected:
        if path in baseline_tree and path in candidate_tree and baseline_tree[path] != candidate_tree[path]:
            errors.append(f"generated bytes differ: {path}")
    return errors


def main(arguments: list[str]) -> int:
    if len(arguments) != 2:
        print("usage: compare-generated-tree.py BASELINE CANDIDATE", file=sys.stderr)
        return 2
    try:
        errors = compare(Path(arguments[0]), Path(arguments[1]))
    except ValueError as exc:
        print(f"generated tree comparison failed: {exc}", file=sys.stderr)
        return 1
    if errors:
        print("generated tree comparison failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(f"generated tree matches the committed {Path(arguments[0]).name} baseline")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
