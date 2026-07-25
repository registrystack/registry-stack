#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail CI when advisory security tools report unreviewed blocking findings."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASELINE = ROOT / "security" / "advisory-baseline.json"

SEVERITY_ORDER = {
    "unknown": 0,
    "undefined": 0,
    "informational": 0,
    "negligible": 0,
    "low": 1,
    "medium": 2,
    "moderate": 2,
    "high": 3,
    "critical": 4,
}

REQUIRED_REVIEW_FIELDS = {
    "tool",
    "fingerprint",
    "rule_id",
    "severity",
    "status",
    "owner",
    "reason",
    "reviewed_at",
    "expires_at",
}
REQUIRED_GRYPE_REVIEW_FIELDS = {
    "component_layer_id",
    "runtime_base",
    "exposure_assertion",
    "evidence_image_digest",
    "evidence_revision",
    "rereview_triggers",
}
FIELD_SEMANTICS = {
    "reviewed_findings[].tool": "enforced",
    "reviewed_findings[].fingerprint": "enforced",
    "reviewed_findings[].rule_id": "enforced",
    "reviewed_findings[].severity": "enforced",
    "reviewed_findings[].status": "enforced",
    "reviewed_findings[].component_layer_id": "enforced",
    "reviewed_findings[].runtime_base": "enforced",
    "reviewed_findings[].exposure_assertion": "enforced",
    "reviewed_findings[].reviewed_at": "enforced",
    "reviewed_findings[].expires_at": "enforced",
    "reviewed_findings[].owner": "recorded",
    "reviewed_findings[].reason": "recorded",
    "reviewed_findings[].evidence_image_digest": "recorded",
    "reviewed_findings[].evidence_revision": "recorded",
    "reviewed_findings[].rereview_triggers": "recorded",
}
REQUIRED_REREVIEW_TRIGGERS = {
    "component_layer_changed",
    "runtime_base_changed",
    "severity_changed",
    "fix_available",
    "exposure_assertion_changed",
    "exposure_assertion_false",
    "exposure_assertion_unevaluable",
    "expired",
}
ASSERTION_FIELDS = {
    "dynamic_symbol_absent": {
        "kind",
        "definition_digest",
        "executables",
        "symbols",
    },
    "package_absent_from_executable_closure": {
        "kind",
        "definition_digest",
        "executables",
        "package",
    },
    "file_digest_equals": {
        "kind",
        "definition_digest",
        "files",
    },
}
GRYPE_FIX_STATES = {"fixed", "not-fixed", "wont-fix"}

SHA256_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
GIT_REVISION_RE = re.compile(r"[0-9a-f]{40}")
PACKAGE_NAME_RE = re.compile(r"[a-z0-9][a-z0-9+.-]*")
SYMBOL_RE = re.compile(r"[A-Za-z_.$][A-Za-z0-9_.$]*")


@dataclass(frozen=True)
class Finding:
    tool: str
    fingerprint: str
    rule_id: str
    severity: str
    location: str
    summary: str
    fix_versions: tuple[str, ...] = ()
    fix_state: str = ""
    image_digest: str = ""
    source_revision: str = ""
    layer_ids: tuple[str, ...] = ()
    component_layer_id: str = ""
    component_layer_error: str = ""
    syft_file_paths: frozenset[str] = frozenset()
    syft_file_digests: tuple[tuple[str, str], ...] = ()

    @property
    def fixable(self) -> bool:
        return bool(self.fix_versions) or self.fix_state.casefold() == "fixed"

    def to_json(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "location": self.location,
            "summary": self.summary,
            "fixable": self.fixable,
            "fix_versions": list(self.fix_versions),
            "fix_state": self.fix_state,
            "image_digest": self.image_digest,
            "source_revision": self.source_revision,
            "component_layer_id": self.component_layer_id,
            "component_layer_error": self.component_layer_error,
        }


@dataclass(frozen=True)
class AssertionResult:
    evaluable: bool
    passed: bool
    detail: str


@dataclass(frozen=True)
class ElfMetadata:
    undefined_dynamic_symbols: frozenset[str]
    needed: tuple[str, ...]
    runpaths: tuple[str, ...]


def fail(message: str) -> None:
    print(f"advisory baseline check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"missing required file: {display_path(path)}")
    except json.JSONDecodeError as exc:
        fail(f"{display_path(path)} is not valid JSON: {exc}")


def severity_rank(value: str) -> int:
    try:
        return SEVERITY_ORDER[value.lower()]
    except KeyError:
        fail(f"unknown severity value: {value}")


def normalize_path(value: str | None) -> str:
    if not value:
        return "<unknown>"
    if value.startswith("./"):
        return value[2:]
    return value


def route_key(route: Any) -> str:
    if not isinstance(route, dict):
        return ""
    route_list = route.get("route")
    if not isinstance(route_list, list):
        return ""
    parts = []
    for entry in route_list:
        if isinstance(entry, dict) and "Key" in entry:
            parts.append(f"k:{entry['Key']}")
        elif isinstance(entry, dict) and "Index" in entry:
            parts.append(f"i:{entry['Index']}")
    return "/".join(parts)


def primary_location(locations: Any) -> dict[str, Any]:
    if not isinstance(locations, list):
        return {}
    for location in locations:
        if not isinstance(location, dict):
            continue
        symbolic = location.get("symbolic", {})
        if isinstance(symbolic, dict) and symbolic.get("kind") == "Primary":
            return location
    return locations[0] if locations and isinstance(locations[0], dict) else {}


def normalize_zizmor(report: Any) -> list[Finding]:
    if not isinstance(report, list):
        fail("zizmor report must be a JSON list")
    findings: list[Finding] = []
    for item in report:
        if not isinstance(item, dict) or item.get("ignored"):
            continue
        determinations = item.get("determinations")
        if not isinstance(determinations, dict):
            determinations = {}
        severity = str(determinations.get("severity", "informational")).lower()
        ident = str(item.get("ident", "<unknown>"))
        location = primary_location(item.get("locations"))
        symbolic = location.get("symbolic", {}) if isinstance(location, dict) else {}
        concrete = location.get("concrete", {}) if isinstance(location, dict) else {}
        key = symbolic.get("key", {}) if isinstance(symbolic, dict) else {}
        local = key.get("Local", {}) if isinstance(key, dict) else {}
        path = normalize_path(
            local.get("given_path") if isinstance(local, dict) else None
        )
        annotation = (
            str(symbolic.get("annotation", "")) if isinstance(symbolic, dict) else ""
        )
        feature = str(concrete.get("feature", "")) if isinstance(concrete, dict) else ""
        route = route_key(symbolic.get("route") if isinstance(symbolic, dict) else None)
        detail = (
            feature if ident == "unpinned-uses" and feature else annotation or feature
        )
        fingerprint = "|".join(["zizmor", ident, path, route, detail])
        summary = str(item.get("desc") or annotation or feature or ident)
        findings.append(
            Finding(
                tool="zizmor",
                fingerprint=fingerprint,
                rule_id=ident,
                severity=severity,
                location=path,
                summary=summary,
            )
        )
    return findings


def image_source_context(
    report: Any, report_name: str
) -> tuple[str, str, tuple[str, ...]]:
    if not isinstance(report, dict):
        fail(f"{report_name} report must be a JSON object")
    source = report.get("source")
    if not isinstance(source, dict):
        fail(f"{report_name} report source must describe an image")
    if report_name == "grype":
        if source.get("type") != "image":
            fail("grype report source must describe an image")
        target = source.get("target")
    else:
        if source.get("type") != "image":
            fail("syft report source must describe an image")
        target = source.get("metadata")
    if not isinstance(target, dict):
        fail(f"{report_name} report source must contain image metadata")
    user_input = target.get("userInput")
    if not isinstance(user_input, str) or "@" not in user_input:
        fail(f"{report_name} image target must be pinned by digest")
    image_digest = user_input.rsplit("@", 1)[1]
    if SHA256_DIGEST_RE.fullmatch(image_digest) is None:
        fail(f"{report_name} image target must use a sha256 digest")
    repo_digests = target.get("repoDigests")
    if not isinstance(repo_digests, list) or user_input not in repo_digests:
        fail(f"{report_name} image target digest must appear in repoDigests")
    if target.get("architecture") != "amd64" or target.get("os") != "linux":
        fail(f"{report_name} image target must be linux/amd64")
    layers = target.get("layers")
    if not isinstance(layers, list) or not layers:
        fail(f"{report_name} image target must contain rootfs layers")
    layer_ids: list[str] = []
    for layer in layers:
        digest = layer.get("digest") if isinstance(layer, dict) else None
        if not isinstance(digest, str) or SHA256_DIGEST_RE.fullmatch(digest) is None:
            fail(f"{report_name} image target layers must use sha256 digests")
        layer_ids.append(digest)
    labels = target.get("labels")
    if not isinstance(labels, dict):
        fail(f"{report_name} image target must contain OCI labels")
    source_revision = labels.get("org.opencontainers.image.revision")
    if (
        not isinstance(source_revision, str)
        or GIT_REVISION_RE.fullmatch(source_revision) is None
    ):
        fail(f"{report_name} image target must contain a full Git revision label")
    return image_digest, source_revision, tuple(layer_ids)


def syft_artifacts(report: Any) -> dict[str, dict[str, Any]]:
    artifacts = report.get("artifacts") if isinstance(report, dict) else None
    if not isinstance(artifacts, list):
        fail("syft report must contain an artifacts list")
    by_id: dict[str, dict[str, Any]] = {}
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            fail("syft report artifacts must be objects")
        artifact_id = artifact.get("id")
        if not isinstance(artifact_id, str) or not artifact_id:
            fail("syft report artifacts must carry non-blank ids")
        if artifact_id in by_id:
            fail(f"syft report contains duplicate artifact id: {artifact_id}")
        by_id[artifact_id] = artifact
    return by_id


def syft_files(report: Any) -> tuple[frozenset[str], tuple[tuple[str, str], ...]]:
    files = report.get("files") if isinstance(report, dict) else None
    if not isinstance(files, list):
        fail("syft report must contain a files list")
    paths: set[str] = set()
    sha256_digests: dict[str, str] = {}
    for entry in files:
        location = entry.get("location") if isinstance(entry, dict) else None
        path = location.get("path") if isinstance(location, dict) else None
        if not isinstance(path, str) or not path.startswith("/"):
            fail("syft report files must carry absolute location paths")
        if path in paths:
            fail(f"syft report contains duplicate file path: {path}")
        paths.add(path)
        digests = entry.get("digests")
        if digests is None:
            continue
        if not isinstance(digests, list):
            fail(f"syft report file digests are malformed: {path}")
        for digest in digests:
            if not isinstance(digest, dict):
                fail(f"syft report file digest is malformed: {path}")
            if str(digest.get("algorithm", "")).casefold() != "sha256":
                continue
            value = digest.get("value")
            normalized = f"sha256:{value}"
            if (
                not isinstance(value, str)
                or SHA256_DIGEST_RE.fullmatch(normalized) is None
                or path in sha256_digests
            ):
                fail(
                    f"syft report sha256 file digest is malformed or duplicate: {path}"
                )
            sha256_digests[path] = normalized
    return frozenset(paths), tuple(sorted(sha256_digests.items()))


def component_layer(
    artifact: dict[str, Any], layer_ids: tuple[str, ...]
) -> tuple[str, str]:
    locations = artifact.get("locations")
    if not isinstance(locations, list) or not locations:
        return "", "artifact locations are missing"
    ids: set[str] = set()
    for location in locations:
        layer_id = location.get("layerID") if isinstance(location, dict) else None
        if (
            not isinstance(layer_id, str)
            or SHA256_DIGEST_RE.fullmatch(layer_id) is None
        ):
            return "", "artifact location layerID is missing or malformed"
        ids.add(layer_id)
    if len(ids) != 1:
        return "", "artifact locations span multiple component layers"
    layer_id = next(iter(ids))
    if layer_id not in layer_ids:
        return "", "artifact component layer is absent from image layers"
    return layer_id, ""


def normalize_grype(
    report: Any, subject: str, syft_report: Any | None = None
) -> list[Finding]:
    image_digest, source_revision, layer_ids = image_source_context(report, "grype")
    syft_by_id: dict[str, dict[str, Any]] | None = None
    syft_file_paths: frozenset[str] = frozenset()
    syft_file_digests: tuple[tuple[str, str], ...] = ()
    if syft_report is not None:
        syft_context = image_source_context(syft_report, "syft")
        if syft_context != (image_digest, source_revision, layer_ids):
            fail("grype and syft reports do not describe the same image evidence")
        syft_by_id = syft_artifacts(syft_report)
        syft_file_paths, syft_file_digests = syft_files(syft_report)
    matches = report.get("matches")
    if not isinstance(matches, list):
        fail("grype report must contain a matches list")
    findings: list[Finding] = []
    for item in matches:
        if not isinstance(item, dict):
            fail("grype report matches must be objects")
        vulnerability = item.get("vulnerability")
        artifact = item.get("artifact")
        if not isinstance(vulnerability, dict) or not isinstance(artifact, dict):
            fail("grype report matches must contain vulnerability and artifact objects")
        if syft_by_id is not None:
            artifact_id = artifact.get("id")
            if not isinstance(artifact_id, str) or artifact_id not in syft_by_id:
                fail("grype finding artifact is absent from the syft report")
            syft_artifact = syft_by_id[artifact_id]
            compared_fields = ("id", "name", "version", "type", "locations")
            if any(
                artifact.get(field) != syft_artifact.get(field)
                for field in compared_fields
            ):
                fail("grype finding artifact does not match the syft package model")
        vuln_id = str(vulnerability.get("id", "<unknown>"))
        severity = str(vulnerability.get("severity", "negligible")).lower()
        package_name = str(artifact.get("name", "<unknown>"))
        package_version = str(artifact.get("version", "<unknown>"))
        package_type = str(artifact.get("type", "<unknown>"))
        fix = vulnerability.get("fix")
        if not isinstance(fix, dict):
            fail(f"grype finding {vuln_id} must contain a fix object")
        fix_versions_value = fix.get("versions", [])
        if fix_versions_value is None:
            fix_versions_value = []
        if not isinstance(fix_versions_value, list) or any(
            not isinstance(version, str) for version in fix_versions_value
        ):
            fail(f"grype finding {vuln_id} has malformed fix versions")
        fix_versions = tuple(
            version.strip() for version in fix_versions_value if version.strip()
        )
        fix_state_value = fix.get("state", "")
        if not isinstance(fix_state_value, str):
            fail(f"grype finding {vuln_id} has a malformed fix state")
        fix_state = fix_state_value.strip().casefold()
        if fix_state not in GRYPE_FIX_STATES:
            fail(
                f"grype finding {vuln_id} has unsupported fix state: {fix_state_value}"
            )
        fingerprint = "|".join(
            [
                "grype",
                subject,
                vuln_id,
                package_name,
                package_version,
                package_type,
            ]
        )
        component_layer_id, component_layer_error = component_layer(artifact, layer_ids)
        findings.append(
            Finding(
                tool="grype",
                fingerprint=fingerprint,
                rule_id=vuln_id,
                severity=severity,
                location=subject,
                summary=f"{vuln_id} in {package_name} {package_version}",
                fix_versions=fix_versions,
                fix_state=fix_state,
                image_digest=image_digest,
                source_revision=source_revision,
                layer_ids=layer_ids,
                component_layer_id=component_layer_id,
                component_layer_error=component_layer_error,
                syft_file_paths=syft_file_paths,
                syft_file_digests=syft_file_digests,
            )
        )
    return findings


def load_baseline(path: Path) -> dict[str, Any]:
    data = load_json(path)
    if not isinstance(data, dict):
        fail("baseline must be a JSON object")
    if data.get("version") != 2:
        fail("baseline version must be 2")
    if data.get("field_semantics") != FIELD_SEMANTICS:
        fail(
            "baseline field_semantics must state the schema v2 enforced/recorded contract"
        )
    policies = data.get("policies")
    if not isinstance(policies, list) or not policies:
        fail("baseline must contain non-empty policies")
    reviewed = data.get("reviewed_findings")
    if not isinstance(reviewed, list):
        fail("baseline reviewed_findings must be a list")
    for policy in policies:
        if not isinstance(policy, dict):
            fail("baseline policies must be objects")
        for field in ("tool", "minimum_severity", "action"):
            if field not in policy:
                fail(f"baseline policy missing {field}")
        severity_rank(str(policy["minimum_severity"]))
        if policy["action"] != "block_unreviewed":
            fail(f"unsupported policy action: {policy['action']}")
        if policy["tool"] == "grype" and policy.get("block_fixable") is not True:
            fail("grype policy must set block_fixable to true")
    seen_reviews: set[str] = set()
    for review in reviewed:
        validate_review_entry(review)
        fingerprint = str(review["fingerprint"])
        if fingerprint in seen_reviews:
            fail(f"duplicate reviewed finding fingerprint: {fingerprint}")
        seen_reviews.add(fingerprint)
    return data


def validate_review_entry(review: Any) -> None:
    if not isinstance(review, dict):
        fail("reviewed findings must be objects")
    missing = REQUIRED_REVIEW_FIELDS - set(review)
    if missing:
        fail(f"reviewed finding missing fields: {sorted(missing)}")
    if review["status"] not in {"accepted_risk", "false_positive", "tool_noise"}:
        fail(f"unsupported reviewed finding status: {review['status']}")
    severity_rank(str(review["severity"]))
    for field in ("reviewed_at", "expires_at"):
        parse_date(str(review[field]), field)
    for field in ("tool", "fingerprint", "rule_id", "owner", "reason"):
        value = review.get(field)
        if not isinstance(value, str) or not value.strip():
            fail(f"reviewed finding {field} must be a non-blank string")
    if review["tool"] == "grype":
        missing_grype = REQUIRED_GRYPE_REVIEW_FIELDS - set(review)
        if missing_grype:
            fail(f"grype reviewed finding missing fields: {sorted(missing_grype)}")
        validate_grype_review_entry(review)
    reviewed_at = parse_date(str(review["reviewed_at"]), "reviewed_at")
    expires_at = parse_date(str(review["expires_at"]), "expires_at")
    if expires_at < reviewed_at:
        fail("reviewed finding expires_at must not precede reviewed_at")


def validate_grype_review_entry(review: dict[str, Any]) -> None:
    if SHA256_DIGEST_RE.fullmatch(str(review["evidence_image_digest"])) is None:
        fail("grype reviewed finding evidence_image_digest must be a sha256 digest")
    if GIT_REVISION_RE.fullmatch(str(review["evidence_revision"])) is None:
        fail("grype reviewed finding evidence_revision must be a full Git revision")
    if SHA256_DIGEST_RE.fullmatch(str(review["component_layer_id"])) is None:
        fail("grype reviewed finding component_layer_id must be a sha256 digest")
    runtime_base = review["runtime_base"]
    if not isinstance(runtime_base, dict) or set(runtime_base) != {
        "image",
        "layer_ids",
    }:
        fail("grype reviewed finding runtime_base must contain image and layer_ids")
    image = runtime_base["image"]
    if (
        not isinstance(image, str)
        or "@" not in image
        or SHA256_DIGEST_RE.fullmatch(image.rsplit("@", 1)[1]) is None
    ):
        fail(
            "grype reviewed finding runtime_base.image must be pinned by sha256 digest"
        )
    layer_ids = runtime_base["layer_ids"]
    if (
        not isinstance(layer_ids, list)
        or not layer_ids
        or any(
            not isinstance(layer, str) or SHA256_DIGEST_RE.fullmatch(layer) is None
            for layer in layer_ids
        )
        or len(set(layer_ids)) != len(layer_ids)
    ):
        fail(
            "grype reviewed finding runtime_base.layer_ids must be unique sha256 digests"
        )
    if review["component_layer_id"] not in layer_ids:
        fail("grype reviewed finding component layer must belong to the runtime base")
    validate_exposure_assertion(review["exposure_assertion"])
    triggers = review["rereview_triggers"]
    if (
        not isinstance(triggers, list)
        or any(not isinstance(trigger, str) or not trigger for trigger in triggers)
        or len(set(triggers)) != len(triggers)
        or not REQUIRED_REREVIEW_TRIGGERS.issubset(triggers)
    ):
        fail("grype reviewed finding rereview_triggers must contain every v2 trigger")


def validate_image_path(value: Any, field: str) -> None:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or value == "/"
        or "\x00" in value
        or any(part in {"", ".", ".."} for part in value.split("/")[1:])
    ):
        fail(f"exposure assertion {field} must be a normalized absolute image path")


def assertion_definition_digest(assertion: dict[str, Any]) -> str:
    definition = {
        key: value for key, value in assertion.items() if key != "definition_digest"
    }
    payload = json.dumps(
        definition, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def validate_exposure_assertion(assertion: Any) -> None:
    if not isinstance(assertion, dict):
        fail("grype reviewed finding exposure_assertion must be an object")
    kind = assertion.get("kind")
    if kind not in ASSERTION_FIELDS:
        fail(f"unknown exposure assertion kind: {kind}")
    if set(assertion) != ASSERTION_FIELDS[kind]:
        fail(f"exposure assertion {kind} has missing or unknown fields")
    if assertion.get("definition_digest") != assertion_definition_digest(assertion):
        fail("exposure assertion definition changed without re-review")
    if kind in {"dynamic_symbol_absent", "package_absent_from_executable_closure"}:
        executables = assertion["executables"]
        if (
            not isinstance(executables, list)
            or not executables
            or len(set(executables)) != len(executables)
        ):
            fail(
                f"exposure assertion {kind} executables must be a unique non-empty list"
            )
        for executable in executables:
            validate_image_path(executable, "executables[]")
    if kind == "dynamic_symbol_absent":
        symbols = assertion["symbols"]
        if (
            not isinstance(symbols, list)
            or not symbols
            or len(set(symbols)) != len(symbols)
            or any(
                not isinstance(symbol, str) or SYMBOL_RE.fullmatch(symbol) is None
                for symbol in symbols
            )
        ):
            fail("dynamic_symbol_absent symbols must be unique ELF symbol names")
        if {"dlsym", "dlvsym"} & set(symbols):
            fail(
                "dynamic_symbol_absent cannot treat dynamic lookup APIs as absent targets"
            )
    elif kind == "package_absent_from_executable_closure":
        package = assertion["package"]
        if not isinstance(package, str) or PACKAGE_NAME_RE.fullmatch(package) is None:
            fail("package_absent_from_executable_closure package is malformed")
    else:
        files = assertion["files"]
        if not isinstance(files, list) or not files:
            fail("file_digest_equals files must be a non-empty list")
        seen_paths: set[str] = set()
        for entry in files:
            if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
                fail("file_digest_equals files must contain path and sha256")
            validate_image_path(entry["path"], "files[].path")
            if entry["path"] in seen_paths:
                fail("file_digest_equals files must use unique paths")
            seen_paths.add(entry["path"])
            if SHA256_DIGEST_RE.fullmatch(str(entry["sha256"])) is None:
                fail("file_digest_equals files[].sha256 must be a sha256 digest")


def parse_date(value: str, field: str) -> dt.date:
    try:
        return dt.date.fromisoformat(value)
    except ValueError:
        fail(f"{field} must be an ISO date: {value}")


def rootfs_file(rootfs: Path, image_path: str) -> tuple[Path | None, str]:
    try:
        root = rootfs.resolve(strict=True)
    except OSError as exc:
        return None, f"rootfs is unavailable: {exc}"
    candidate = root.joinpath(*image_path.lstrip("/").split("/"))
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        return None, f"{image_path} is unavailable or escapes the rootfs: {exc}"
    if not resolved.is_file():
        return None, f"{image_path} is not a regular file"
    return resolved, ""


def bounded_slice(data: bytes, offset: int, size: int, label: str) -> bytes:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ValueError(f"ELF {label} is outside the file")
    return data[offset : offset + size]


def c_string(table: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(table):
        raise ValueError("ELF string offset is outside its table")
    end = table.find(b"\0", offset)
    if end < 0:
        raise ValueError("ELF string is not terminated")
    return table[offset:end].decode("utf-8")


def parse_elf(path: Path) -> ElfMetadata:
    data = path.read_bytes()
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    elf_class = data[4]
    byte_order = data[5]
    if byte_order == 1:
        endian = "<"
    elif byte_order == 2:
        endian = ">"
    else:
        raise ValueError("unsupported ELF byte order")
    if elf_class == 2:
        section_offset = struct.unpack_from(endian + "Q", data, 40)[0]
        section_size, section_count = struct.unpack_from(endian + "HH", data, 58)
        section_format = endian + "IIQQQQIIQQ"
        symbol_format = endian + "IBBHQQ"
        dynamic_format = endian + "qQ"
    elif elf_class == 1:
        section_offset = struct.unpack_from(endian + "I", data, 32)[0]
        section_size, section_count = struct.unpack_from(endian + "HH", data, 46)
        section_format = endian + "IIIIIIIIII"
        symbol_format = endian + "IIIBBH"
        dynamic_format = endian + "iI"
    else:
        raise ValueError("unsupported ELF class")
    expected_section_size = struct.calcsize(section_format)
    if section_size != expected_section_size or section_count == 0:
        raise ValueError("malformed ELF section table")
    sections: list[tuple[int, ...]] = []
    for index in range(section_count):
        offset = section_offset + index * section_size
        raw = bounded_slice(data, offset, section_size, "section header")
        sections.append(struct.unpack(section_format, raw))

    def section_data(section: tuple[int, ...]) -> bytes:
        return bounded_slice(data, section[4], section[5], "section")

    undefined: set[str] = set()
    needed: list[str] = []
    runpaths: list[str] = []
    saw_dynamic_symbols = False
    for section in sections:
        section_type = section[1]
        link = section[6]
        entry_size = section[9]
        if link >= len(sections):
            raise ValueError("ELF section has an invalid string-table link")
        if section_type == 11:
            saw_dynamic_symbols = True
            symbol_size = struct.calcsize(symbol_format)
            if entry_size != symbol_size or section[5] % entry_size:
                raise ValueError("malformed ELF dynamic symbol table")
            strings = section_data(sections[link])
            symbols = section_data(section)
            for offset in range(0, len(symbols), entry_size):
                values = struct.unpack(
                    symbol_format, symbols[offset : offset + entry_size]
                )
                name_offset = values[0]
                section_index = values[3] if elf_class == 2 else values[5]
                if name_offset and section_index == 0:
                    undefined.add(c_string(strings, name_offset))
        elif section_type == 6:
            dynamic_size = struct.calcsize(dynamic_format)
            if entry_size != dynamic_size or section[5] % entry_size:
                raise ValueError("malformed ELF dynamic table")
            strings = section_data(sections[link])
            entries = section_data(section)
            for offset in range(0, len(entries), entry_size):
                tag, value = struct.unpack(
                    dynamic_format, entries[offset : offset + entry_size]
                )
                if tag == 1:
                    needed.append(c_string(strings, value))
                elif tag in {15, 29}:
                    runpaths.extend(
                        path for path in c_string(strings, value).split(":") if path
                    )
    if not saw_dynamic_symbols:
        raise ValueError("ELF has no dynamic symbol table")
    return ElfMetadata(frozenset(undefined), tuple(needed), tuple(runpaths))


def dynamic_symbol_absent(
    assertion: dict[str, Any], rootfs: Path, syft_file_paths: frozenset[str]
) -> AssertionResult:
    forbidden = set(assertion["symbols"])
    for image_path in assertion["executables"]:
        if image_path not in syft_file_paths:
            return AssertionResult(
                False, False, f"{image_path} is absent from native Syft file evidence"
            )
        path, error = rootfs_file(rootfs, image_path)
        if path is None:
            return AssertionResult(False, False, error)
        try:
            metadata = parse_elf(path)
        except (OSError, UnicodeError, ValueError, struct.error) as exc:
            return AssertionResult(False, False, f"cannot inspect {image_path}: {exc}")
        dynamic_lookup = {"dlsym", "dlvsym"} & metadata.undefined_dynamic_symbols
        if dynamic_lookup:
            return AssertionResult(
                False,
                False,
                f"{image_path} imports dynamic lookup API(s): {sorted(dynamic_lookup)}",
            )
        present = forbidden & metadata.undefined_dynamic_symbols
        if present:
            return AssertionResult(
                True,
                False,
                f"{image_path} imports forbidden symbol(s): {sorted(present)}",
            )
    return AssertionResult(True, True, "all forbidden dynamic symbols are absent")


def image_path_for(rootfs: Path, path: Path) -> str:
    return "/" + str(path.resolve().relative_to(rootfs.resolve()))


def resolve_needed(
    rootfs: Path, parent: Path, needed: str, runpaths: tuple[str, ...]
) -> tuple[Path | None, str]:
    origin = image_path_for(rootfs, parent.parent)
    if "/" in needed:
        candidates = [needed if needed.startswith("/") else f"{origin}/{needed}"]
    else:
        search = [origin]
        for entry in runpaths:
            expanded = entry.replace("${ORIGIN}", origin).replace("$ORIGIN", origin)
            search.append(expanded)
        search.extend(
            [
                "/lib/x86_64-linux-gnu",
                "/usr/lib/x86_64-linux-gnu",
                "/lib64",
                "/usr/lib64",
                "/lib",
                "/usr/lib",
            ]
        )
        candidates = [f"{directory.rstrip('/')}/{needed}" for directory in search]
    for candidate in candidates:
        if not candidate.startswith("/"):
            continue
        resolved, _ = rootfs_file(rootfs, candidate)
        if resolved is not None:
            return resolved, ""
    return (
        None,
        f"cannot resolve ELF dependency {needed} from {image_path_for(rootfs, parent)}",
    )


def package_files(rootfs: Path, package: str) -> tuple[set[Path] | None, str]:
    metadata_path = f"/var/lib/dpkg/status.d/{package}.md5sums"
    path, error = rootfs_file(rootfs, metadata_path)
    if path is None:
        return None, error
    owned: set[Path] = set()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        return None, f"cannot read {metadata_path}: {exc}"
    for line in lines:
        match = re.fullmatch(r"[0-9a-f]{32}\s+(.+)", line)
        if match is None:
            return (
                None,
                f"{metadata_path} contains malformed package ownership evidence",
            )
        image_path = "/" + match.group(1).lstrip("/")
        owned_path, _ = rootfs_file(rootfs, image_path)
        if owned_path is not None:
            owned.add(owned_path)
    if not owned:
        return None, f"{metadata_path} establishes no package-owned files"
    return owned, ""


def package_absent_from_executable_closure(
    assertion: dict[str, Any], rootfs: Path, syft_file_paths: frozenset[str]
) -> AssertionResult:
    owned, error = package_files(rootfs, assertion["package"])
    if owned is None:
        return AssertionResult(False, False, error)
    queue: list[Path] = []
    for image_path in assertion["executables"]:
        if image_path not in syft_file_paths:
            return AssertionResult(
                False, False, f"{image_path} is absent from native Syft file evidence"
            )
        path, path_error = rootfs_file(rootfs, image_path)
        if path is None:
            return AssertionResult(False, False, path_error)
        queue.append(path)
    visited: set[Path] = set()
    while queue:
        path = queue.pop()
        if path in visited:
            continue
        visited.add(path)
        if path in owned:
            return AssertionResult(
                True,
                False,
                f"{assertion['package']} file is present in executable closure: "
                f"{image_path_for(rootfs, path)}",
            )
        try:
            metadata = parse_elf(path)
        except (OSError, UnicodeError, ValueError, struct.error) as exc:
            return AssertionResult(
                False,
                False,
                f"cannot inspect executable closure file {image_path_for(rootfs, path)}: {exc}",
            )
        if {"dlsym", "dlvsym"} & metadata.undefined_dynamic_symbols:
            return AssertionResult(
                False,
                False,
                f"{image_path_for(rootfs, path)} can extend its closure with dynamic lookup",
            )
        for needed in metadata.needed:
            dependency, dependency_error = resolve_needed(
                rootfs, path, needed, metadata.runpaths
            )
            if dependency is None:
                return AssertionResult(False, False, dependency_error)
            queue.append(dependency)
    return AssertionResult(
        True,
        True,
        f"{assertion['package']} is absent from the evaluated executable closure",
    )


def file_digest_equals(
    assertion: dict[str, Any],
    rootfs: Path,
    syft_file_paths: frozenset[str],
    syft_file_digests: tuple[tuple[str, str], ...],
) -> AssertionResult:
    syft_digests = dict(syft_file_digests)
    for entry in assertion["files"]:
        if entry["path"] not in syft_file_paths:
            return AssertionResult(
                False,
                False,
                f"{entry['path']} is absent from native Syft file evidence",
            )
        syft_digest = syft_digests.get(entry["path"])
        if syft_digest is not None and syft_digest != entry["sha256"]:
            return AssertionResult(
                True,
                False,
                f"{entry['path']} native Syft digest is {syft_digest}, "
                f"expected {entry['sha256']}",
            )
        path, error = rootfs_file(rootfs, entry["path"])
        if path is None:
            return AssertionResult(False, False, error)
        try:
            digest = f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"
        except OSError as exc:
            return AssertionResult(False, False, f"cannot hash {entry['path']}: {exc}")
        if digest != entry["sha256"]:
            return AssertionResult(
                True,
                False,
                f"{entry['path']} digest is {digest}, expected {entry['sha256']}",
            )
    return AssertionResult(
        True,
        True,
        f"all {len(assertion['files'])} reviewed file digests match",
    )


def evaluate_exposure_assertion(
    assertion: dict[str, Any],
    rootfs: Path | None,
    syft_file_paths: frozenset[str],
    syft_file_digests: tuple[tuple[str, str], ...],
) -> AssertionResult:
    if rootfs is None:
        return AssertionResult(
            False, False, "candidate rootfs evidence was not supplied"
        )
    kind = assertion["kind"]
    if kind == "dynamic_symbol_absent":
        return dynamic_symbol_absent(assertion, rootfs, syft_file_paths)
    if kind == "package_absent_from_executable_closure":
        return package_absent_from_executable_closure(
            assertion, rootfs, syft_file_paths
        )
    if kind == "file_digest_equals":
        return file_digest_equals(assertion, rootfs, syft_file_paths, syft_file_digests)
    return AssertionResult(False, False, f"unknown exposure assertion kind: {kind}")


def policy_threshold(baseline: dict[str, Any], tool: str) -> str:
    matches = [p for p in baseline["policies"] if p.get("tool") == tool]
    if not matches:
        fail(f"baseline has no policy for {tool}")
    return str(matches[0]["minimum_severity"]).lower()


def finding_is_blocking(finding: Finding, tool: str, threshold_rank: int) -> bool:
    return (tool == "grype" and finding.fixable) or severity_rank(
        finding.severity
    ) >= threshold_rank


def runtime_base_mismatch(finding: Finding, review: dict[str, Any]) -> str:
    expected = tuple(review["runtime_base"]["layer_ids"])
    if finding.layer_ids[: len(expected)] != expected:
        return (
            f"candidate layers do not begin with pinned base "
            f"{review['runtime_base']['image']}"
        )
    if finding.component_layer_id not in expected:
        return "candidate component layer is not part of the pinned runtime base"
    return ""


def check_findings(
    tool: str,
    findings: list[Finding],
    baseline: dict[str, Any],
    today: dt.date,
    review_scope: str | None = None,
    rootfs: Path | None = None,
) -> int:
    threshold = policy_threshold(baseline, tool)
    threshold_rank = severity_rank(threshold)
    blocking = [
        finding
        for finding in findings
        if finding_is_blocking(finding, tool, threshold_rank)
    ]
    fixable = [finding for finding in blocking if tool == "grype" and finding.fixable]
    reviewable = [finding for finding in blocking if finding not in fixable]
    active_fingerprints = {finding.fingerprint for finding in reviewable}
    reviews = {
        str(review["fingerprint"]): review
        for review in baseline["reviewed_findings"]
        if review.get("tool") == tool
        and (
            review_scope is None
            or str(review["fingerprint"]).startswith(f"{tool}|{review_scope}|")
        )
    }
    active_reviews = {
        finding.fingerprint: reviews[finding.fingerprint]
        for finding in reviewable
        if finding.fingerprint in reviews
    }
    expired = [
        review
        for review in active_reviews.values()
        if parse_date(str(review["expires_at"]), "expires_at") < today
    ]
    future_reviewed = [
        review
        for review in active_reviews.values()
        if parse_date(str(review["reviewed_at"]), "reviewed_at") > today
    ]
    mismatched: list[tuple[Finding, str]] = []
    assertion_invalid: list[tuple[Finding, AssertionResult]] = []
    for finding in reviewable:
        review = active_reviews.get(finding.fingerprint)
        if review is None:
            continue
        reasons: list[str] = []
        if str(review["rule_id"]) != finding.rule_id:
            reasons.append("rule id changed")
        if str(review["severity"]).casefold() != finding.severity.casefold():
            reasons.append("severity changed")
        if tool == "grype":
            if finding.component_layer_error:
                reasons.append(finding.component_layer_error)
            elif review["component_layer_id"] != finding.component_layer_id:
                reasons.append("component layer changed")
            base_error = runtime_base_mismatch(finding, review)
            if base_error:
                reasons.append(base_error)
            result = evaluate_exposure_assertion(
                review["exposure_assertion"],
                rootfs,
                finding.syft_file_paths,
                finding.syft_file_digests,
            )
            if not result.evaluable or not result.passed:
                assertion_invalid.append((finding, result))
        if reasons:
            mismatched.append((finding, "; ".join(reasons)))

    for finding in fixable:
        print(
            "fixable finding cannot be dispositioned: "
            f"{finding.tool} {finding.rule_id} {finding.severity} "
            f"{finding.location} fixes={list(finding.fix_versions)} "
            f"fingerprint={finding.fingerprint}",
            file=sys.stderr,
        )
    for review in expired:
        print(
            f"expired reviewed finding: {review['tool']} {review['fingerprint']} "
            f"expired_at={review['expires_at']}",
            file=sys.stderr,
        )
    for review in future_reviewed:
        print(
            f"future-dated reviewed finding: {review['tool']} {review['fingerprint']} "
            f"reviewed_at={review['reviewed_at']}",
            file=sys.stderr,
        )
    for finding, reason in mismatched:
        print(
            f"reviewed finding invariant mismatch: {finding.fingerprint}: {reason}",
            file=sys.stderr,
        )
    for finding, result in assertion_invalid:
        state = "false" if result.evaluable else "unevaluable"
        print(
            f"reviewed finding exposure assertion {state}: "
            f"{finding.fingerprint}: {result.detail}",
            file=sys.stderr,
        )

    unreviewed = [
        finding for finding in reviewable if finding.fingerprint not in reviews
    ]
    for finding in unreviewed:
        print(
            "unreviewed blocking finding: "
            f"{finding.tool} {finding.rule_id} {finding.severity} "
            f"{finding.location} fingerprint={finding.fingerprint}",
            file=sys.stderr,
        )
    stale = sorted(set(reviews) - active_fingerprints)
    invalid_count = len(future_reviewed) + len(mismatched) + len(assertion_invalid)
    print(
        "advisory baseline: "
        f"{tool} threshold={threshold} blocking={len(blocking)} "
        f"fixable={len(fixable)} reviewed={len(active_reviews)} "
        f"unreviewed={len(unreviewed)} expired={len(expired)} "
        f"invalid={invalid_count} stale={len(stale)}"
    )
    if stale:
        print(f"advisory baseline: {tool} has stale reviewed entries: {len(stale)}")
    return int(
        bool(
            fixable
            or expired
            or future_reviewed
            or mismatched
            or assertion_invalid
            or unreviewed
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("tool", choices=["zizmor", "grype"])
    parser.add_argument("report", type=Path)
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--subject", default="image")
    parser.add_argument("--today", default=dt.date.today().isoformat())
    parser.add_argument(
        "--syft-report",
        type=Path,
        help="Native Syft JSON for the same digest-bound candidate image.",
    )
    parser.add_argument(
        "--rootfs",
        type=Path,
        help="Exported candidate image rootfs used to evaluate exposure assertions.",
    )
    parser.add_argument(
        "--dump-blocking-findings",
        action="store_true",
        help="Print normalized findings at or above the configured threshold.",
    )
    args = parser.parse_args()

    report = load_json(args.report)
    baseline = load_baseline(args.baseline)
    today = parse_date(args.today, "today")
    if args.tool == "zizmor":
        if args.syft_report is not None or args.rootfs is not None:
            fail("--syft-report and --rootfs are only valid for grype")
        findings = normalize_zizmor(report)
    else:
        if args.syft_report is None:
            fail("grype checks require --syft-report native Syft JSON evidence")
        syft_report = load_json(args.syft_report)
        findings = normalize_grype(report, args.subject, syft_report)

    if args.dump_blocking_findings:
        threshold = policy_threshold(baseline, args.tool)
        threshold_rank = severity_rank(threshold)
        blocking = [
            finding.to_json()
            for finding in findings
            if finding_is_blocking(finding, args.tool, threshold_rank)
        ]
        print(json.dumps(blocking, indent=2, sort_keys=True))
        return

    review_scope = args.subject if args.tool == "grype" else None
    raise SystemExit(
        check_findings(
            args.tool,
            findings,
            baseline,
            today,
            review_scope,
            args.rootfs,
        )
    )


if __name__ == "__main__":
    main()
