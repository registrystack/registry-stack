#!/usr/bin/env python3
"""Load the closed registry of independently releasable product units."""

from __future__ import annotations

import json
import fnmatch
import re
from pathlib import Path
from string import Formatter
from typing import NamedTuple


REGISTRY_PATH = Path(__file__).resolve().parents[1] / "units.yaml"
REGISTRY_SCHEMA = "registry-stack.release-units.v1"
VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
UNIT_NAME = re.compile(r"^[a-z][a-z0-9-]*$")
ASSET_PREFIX = re.compile(r"^[a-z][a-z0-9-]*$")
PAYLOAD_KINDS = {"binary", "installer", "notice", "sbom", "security-evidence"}
UNIT_FIELDS = {
    "display_name",
    "status",
    "tag_prefix",
    "asset_prefix",
    "members",
    "artifact_patterns",
    "dependencies",
    "candidate",
}


class UnitRegistryError(ValueError):
    """The release-unit registry or a requested unit identity is invalid."""


class CandidatePayload(NamedTuple):
    template: str
    kind: str


class CandidateDefinition(NamedTuple):
    payloads: tuple[CandidatePayload, ...]
    images: tuple[str, ...]


class ReleaseUnit(NamedTuple):
    name: str
    display_name: str
    status: str
    tag_prefix: str
    asset_prefix: str
    members: tuple[str, ...]
    artifact_patterns: tuple[str, ...]
    dependencies: tuple[str, ...]
    candidate: CandidateDefinition | None


class ReleaseUnitRegistry:
    def __init__(
        self,
        units: dict[str, ReleaseUnit],
        distribution_members: tuple[str, ...],
        distribution_artifact_patterns: tuple[str, ...],
    ) -> None:
        self._units = units
        self.distribution_members = distribution_members
        self.distribution_artifact_patterns = distribution_artifact_patterns

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._units))

    def get(self, name: str) -> ReleaseUnit:
        try:
            return self._units[name]
        except KeyError as exc:
            raise UnitRegistryError(f"unknown release unit {name!r}") from exc

    def require_pilot(self, name: str) -> ReleaseUnit:
        unit = self.get(name)
        if unit.status != "pilot" or unit.candidate is None:
            raise UnitRegistryError(
                f"release unit {name!r} is not enabled for the release pilot"
            )
        return unit

    def artifact_owner(self, name: str) -> str:
        if not isinstance(name, str) or Path(name).name != name:
            raise UnitRegistryError("artifact name must be a basename")
        matches = [
            unit.name
            for unit in self._units.values()
            if any(fnmatch.fnmatchcase(name, pattern) for pattern in unit.artifact_patterns)
        ]
        if any(
            fnmatch.fnmatchcase(name, pattern)
            for pattern in self.distribution_artifact_patterns
        ):
            matches.append("distribution")
        if len(matches) != 1:
            raise UnitRegistryError(
                f"artifact {name!r} must have exactly one owner, got {matches!r}"
            )
        return matches[0]


def _require_exact_object(
    value: object, label: str, fields: set[str]
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise UnitRegistryError(
            f"{label} must contain exactly {sorted(fields)!r}"
        )
    return value


def _require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise UnitRegistryError(f"{label} must be a non-empty string")
    return value


def _require_unique_strings(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise UnitRegistryError(f"{label} must be a non-empty list")
    result = tuple(_require_string(item, f"{label}[]") for item in value)
    if len(set(result)) != len(result):
        raise UnitRegistryError(f"{label} must not contain duplicates")
    return result


def _parse_candidate(value: object, label: str) -> CandidateDefinition | None:
    if value is None:
        return None
    candidate = _require_exact_object(value, label, {"payloads", "images"})
    raw_payloads = candidate["payloads"]
    if not isinstance(raw_payloads, list) or not raw_payloads:
        raise UnitRegistryError(f"{label}.payloads must be a non-empty list")
    payloads: list[CandidatePayload] = []
    for index, raw in enumerate(raw_payloads):
        payload = _require_exact_object(
            raw, f"{label}.payloads[{index}]", {"template", "kind"}
        )
        template = _require_string(
            payload["template"], f"{label}.payloads[{index}].template"
        )
        fields = {
            field_name
            for _, field_name, _, _ in Formatter().parse(template)
            if field_name is not None
        }
        if not fields <= {"asset_tag", "asset_prefix"}:
            raise UnitRegistryError(
                f"{label}.payloads[{index}].template has unsupported fields"
            )
        kind = _require_string(payload["kind"], f"{label}.payloads[{index}].kind")
        if kind not in PAYLOAD_KINDS:
            raise UnitRegistryError(f"{label}.payloads[{index}].kind is unsupported")
        payloads.append(CandidatePayload(template, kind))
    images = _require_unique_strings(candidate["images"], f"{label}.images")
    return CandidateDefinition(tuple(payloads), images)


def load_registry(path: Path = REGISTRY_PATH) -> ReleaseUnitRegistry:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise UnitRegistryError(f"could not load release unit registry {path}: {exc}") from exc
    root = _require_exact_object(
        document,
        "release unit registry",
        {"schema_version", "distribution", "units"},
    )
    if root["schema_version"] != REGISTRY_SCHEMA:
        raise UnitRegistryError(f"release unit registry schema must be {REGISTRY_SCHEMA}")
    distribution = _require_exact_object(
        root["distribution"],
        "release unit registry distribution",
        {"members", "artifact_patterns"},
    )
    distribution_members = _require_unique_strings(
        distribution["members"], "release unit registry distribution.members"
    )
    distribution_artifact_patterns = _require_unique_strings(
        distribution["artifact_patterns"],
        "release unit registry distribution.artifact_patterns",
    )
    raw_units = root["units"]
    if not isinstance(raw_units, dict) or not raw_units:
        raise UnitRegistryError("release unit registry units must be a non-empty object")
    units: dict[str, ReleaseUnit] = {}
    for name, raw in raw_units.items():
        if not isinstance(name, str) or UNIT_NAME.fullmatch(name) is None:
            raise UnitRegistryError(f"invalid release unit name {name!r}")
        record = _require_exact_object(raw, f"units.{name}", UNIT_FIELDS)
        display_name = _require_string(record["display_name"], f"units.{name}.display_name")
        status = _require_string(record["status"], f"units.{name}.status")
        if status not in {"held", "pilot"}:
            raise UnitRegistryError(f"units.{name}.status must be held or pilot")
        tag_prefix = _require_string(record["tag_prefix"], f"units.{name}.tag_prefix")
        if tag_prefix != f"{name}/":
            raise UnitRegistryError(f"units.{name}.tag_prefix must be {name}/")
        asset_prefix = _require_string(record["asset_prefix"], f"units.{name}.asset_prefix")
        if ASSET_PREFIX.fullmatch(asset_prefix) is None:
            raise UnitRegistryError(f"units.{name}.asset_prefix is invalid")
        members = _require_unique_strings(record["members"], f"units.{name}.members")
        artifact_patterns = _require_unique_strings(
            record["artifact_patterns"], f"units.{name}.artifact_patterns"
        )
        dependencies_value = record["dependencies"]
        if not isinstance(dependencies_value, list):
            raise UnitRegistryError(f"units.{name}.dependencies must be a list")
        dependencies = tuple(
            _require_string(item, f"units.{name}.dependencies[]")
            for item in dependencies_value
        )
        if len(set(dependencies)) != len(dependencies):
            raise UnitRegistryError(f"units.{name}.dependencies must not contain duplicates")
        candidate = _parse_candidate(record["candidate"], f"units.{name}.candidate")
        if (status == "pilot") != (candidate is not None):
            raise UnitRegistryError(
                f"units.{name} must define a candidate exactly when status is pilot"
            )
        units[name] = ReleaseUnit(
            name,
            display_name,
            status,
            tag_prefix,
            asset_prefix,
            members,
            artifact_patterns,
            dependencies,
            candidate,
        )
    for unit in units.values():
        unknown = sorted(set(unit.dependencies) - set(units))
        if unknown:
            raise UnitRegistryError(
                f"units.{unit.name}.dependencies contains unknown units {unknown!r}"
            )
        if unit.name in unit.dependencies:
            raise UnitRegistryError(f"units.{unit.name} must not depend on itself")
    return ReleaseUnitRegistry(
        units,
        distribution_members,
        distribution_artifact_patterns,
    )


def asset_tag(version: str) -> str:
    if not isinstance(version, str) or VERSION.fullmatch(version) is None:
        raise UnitRegistryError("version must be canonical semantic version text")
    return f"v{version}"


def _pilot_unit(name: str) -> ReleaseUnit:
    return load_registry().require_pilot(name)


def release_tag(unit: str, version: str) -> str:
    definition = load_registry().get(unit)
    return f"{definition.tag_prefix}{asset_tag(version)}"


def candidate_bundle_name(unit: str, version: str) -> str:
    definition = _pilot_unit(unit)
    return f"{definition.asset_prefix}-{asset_tag(version)}-candidate.tar.gz"


def public_manifest_name(unit: str, version: str) -> str:
    definition = _pilot_unit(unit)
    return f"{definition.asset_prefix}-{asset_tag(version)}-release-manifest.json"


def sbom_name(unit: str, version: str) -> str:
    definition = _pilot_unit(unit)
    return f"{definition.asset_prefix}-{asset_tag(version)}.sbom.spdx.json"


def security_evidence_name(unit: str, version: str) -> str:
    definition = _pilot_unit(unit)
    return f"{definition.asset_prefix}-{asset_tag(version)}-security-evidence.tar.gz"


def payload_inventory(unit: str, version: str) -> dict[str, str]:
    definition = _pilot_unit(unit)
    assert definition.candidate is not None
    values: dict[str, str] = {}
    substitutions = {
        "asset_tag": asset_tag(version),
        "asset_prefix": definition.asset_prefix,
    }
    for payload in definition.candidate.payloads:
        name = payload.template.format(**substitutions)
        if Path(name).name != name or not name:
            raise UnitRegistryError(
                f"release unit {unit!r} produced invalid payload name {name!r}"
            )
        if name in values:
            raise UnitRegistryError(
                f"release unit {unit!r} produced duplicate payload name {name!r}"
            )
        values[name] = payload.kind
    return values


def image_names(unit: str) -> set[str]:
    definition = _pilot_unit(unit)
    assert definition.candidate is not None
    return set(definition.candidate.images)
