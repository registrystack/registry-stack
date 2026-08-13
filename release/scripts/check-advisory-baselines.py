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


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASELINE = ROOT / "products" / "relay-v2" / "security" / "advisory-baseline.json"

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
GRYPE_FIX_STATES = {"fixed", "not-fixed", "wont-fix"}
SHA256_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
GIT_REVISION_RE = re.compile(r"[0-9a-f]{40}")
SEMVER_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?")
SUPPORTED_SYFT_SCHEMA_MAJOR = 16
REQUIRED_INVALIDATION_TRIGGERS = {
    "candidate_image_identity_mismatch",
    "candidate_rootfs_changed",
    "component_layer_changed",
    "exposure_assertion_changed",
    "exposure_assertion_false",
    "exposure_assertion_unevaluable",
    "package_version_changed",
    "fix_available",
    "expired",
    "material_finding_changed",
    "rootfs_evidence_mismatch",
    "runtime_config_changed",
    "runtime_base_changed",
}
V4_TOP_LEVEL_FIELDS = {"version", "service", "runtime", "policies", "exceptions"}
V4_RUNTIME_FIELDS = {
    "image",
    "layer_ids",
    "application_layer_ids",
    "config",
    "definition_digest",
}
REQUIRED_RUNTIME_CONFIG_FIELDS = {
    "user",
    "entrypoint",
    "command",
    "working_dir",
    "environment",
    "healthcheck",
    "args_escaped",
    "exposed_ports",
    "stop_signal",
}
REQUIRED_HEALTHCHECK_FIELDS = {
    "test",
    "interval",
    "timeout",
    "start_period",
    "start_interval",
    "retries",
}
V4_EXCEPTION_FIELDS = {
    "vulnerability_id",
    "package",
    "installed_version",
    "severity",
    "status",
    "owner",
    "rationale",
    "reviewed_at",
    "expires_at",
    "invalidation_triggers",
    "runtime_definition_digest",
    "component_layer_id",
    "exposure_assertion",
}
V4_EXCEPTION_STATUSES = {"accepted_risk", "false_positive", "tool_noise"}
ASSERTION_FIELDS = {
    "executable_closure_equals": {
        "kind",
        "definition_digest",
        "reference_image_digest",
        "reference_source_revision",
        "reference_provenance",
        "executables",
        "files",
    },
    "dynamic_symbol_absent": {
        "kind",
        "definition_digest",
        "reference_image_digest",
        "reference_source_revision",
        "reference_provenance",
        "executables",
        "symbols",
    },
    "file_digest_equals": {
        "kind",
        "definition_digest",
        "reference_image_digest",
        "reference_source_revision",
        "reference_provenance",
        "files",
    },
    "whole_image_fingerprint_equals": {
        "kind",
        "definition_digest",
        "reference_image_digest",
        "reference_source_revision",
        "reference_provenance",
        "runtime_definition_digest",
        "files",
    },
    "package_absent_from_executable_closure": {
        "kind",
        "definition_digest",
        "reference_image_digest",
        "reference_source_revision",
        "reference_provenance",
        "executables",
        "package",
    },
}
REFERENCE_PROVENANCE_KINDS = {"official_candidate", "local_reproduction"}
PACKAGE_NAME_RE = re.compile(r"[a-z0-9][a-z0-9+.-]*")
SYMBOL_RE = re.compile(r"[A-Za-z_.$][A-Za-z0-9_.$]*")
ELF_DEFAULT_LIBRARY_DIRS = {
    62: (
        "/lib/x86_64-linux-gnu",
        "/usr/lib/x86_64-linux-gnu",
        "/lib64",
        "/usr/lib64",
        "/lib",
        "/usr/lib",
    ),
    183: (
        "/lib/aarch64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu",
        "/lib64",
        "/usr/lib64",
        "/lib",
        "/usr/lib",
    ),
}
UNSUPPORTED_GLOBAL_LOADER_INPUTS = ("/etc/ld.so.preload", "/etc/ld.so.cache")
UNSUPPORTED_LOADER_ENVIRONMENT = {"GLIBC_TUNABLES"}
DYNAMIC_LOADING_APIS = {"dlopen", "dlmopen", "dlsym", "dlvsym"}
OCI_IDENTITY_LABELS = {
    "org.opencontainers.image.source",
    "org.opencontainers.image.revision",
    "org.opencontainers.image.version",
    "org.registrystack.runtime.uid",
    "org.registrystack.runtime.gid",
}
OCI_RUNTIME_IDENTITY_LABELS = {
    "org.registrystack.runtime.uid": "65532",
    "org.registrystack.runtime.gid": "65532",
}
REQUIRED_OCI_RUNTIME_CONFIG_FIELDS = {
    "ArgsEscaped",
    "Cmd",
    "Entrypoint",
    "Env",
    "ExposedPorts",
    "Labels",
    "User",
    "WorkingDir",
}
OPTIONAL_OCI_RUNTIME_CONFIG_FIELDS = {"Healthcheck", "StopSignal"}
OCI_HEALTHCHECK_FIELDS = {
    "Test",
    "Interval",
    "Timeout",
    "StartPeriod",
    "StartInterval",
    "Retries",
}


@dataclass(frozen=True)
class Finding:
    tool: str
    fingerprint: str
    rule_id: str
    severity: str
    location: str
    summary: str
    package: str = ""
    installed_version: str = ""
    package_type: str = ""
    fix_versions: tuple[str, ...] = ()
    fix_state: str = ""
    image_digest: str = ""
    layer_ids: tuple[str, ...] = ()
    component_layer_id: str = ""
    component_layer_error: str = ""
    syft_file_paths: frozenset[str] = frozenset()
    syft_file_digests: tuple[tuple[str, str], ...] = ()

    @property
    def fixable(self) -> bool:
        return bool(self.fix_versions) or self.fix_state == "fixed"

    @property
    def exception_key(self) -> tuple[str, str, str]:
        return (self.rule_id, self.package, self.installed_version)

    @property
    def advisory_key(self) -> tuple[str, str]:
        return (self.rule_id, self.package)

    def to_json(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "vulnerability_id": self.rule_id,
            "package": self.package,
            "installed_version": self.installed_version,
            "severity": self.severity,
            "location": self.location,
            "summary": self.summary,
            "fixable": self.fixable,
            "fix_versions": list(self.fix_versions),
            "fix_state": self.fix_state,
            "image_digest": self.image_digest,
            "component_layer_id": self.component_layer_id,
            "component_layer_error": self.component_layer_error,
        }


@dataclass(frozen=True)
class ImageEvidence:
    digest: str
    layer_ids: tuple[str, ...]


@dataclass(frozen=True)
class NormalizedGrype:
    image: ImageEvidence
    findings: tuple[Finding, ...]


@dataclass(frozen=True)
class OciImageConfigEvidence:
    layer_ids: tuple[str, ...]
    runtime_config: dict[str, Any]


@dataclass(frozen=True)
class AssertionResult:
    evaluable: bool
    passed: bool
    detail: str


@dataclass(frozen=True)
class ElfMetadata:
    machine: int
    undefined_dynamic_symbols: frozenset[str]
    needed: tuple[str, ...]
    rpaths: tuple[str, ...]
    runpaths: tuple[str, ...]
    interpreter: str | None
    unsupported_loader_tags: frozenset[str]


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


def nonblank(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        fail(f"{field} must be a non-blank string")
    return value.strip()


def severity_rank(value: Any) -> int:
    if not isinstance(value, str) or value.casefold() not in SEVERITY_ORDER:
        fail(f"unknown severity value: {value}")
    return SEVERITY_ORDER[value.casefold()]


def parse_date(value: Any, field: str) -> dt.date:
    if not isinstance(value, str):
        fail(f"{field} must be an ISO date")
    try:
        return dt.date.fromisoformat(value)
    except ValueError:
        fail(f"{field} must be an ISO date: {value}")


def normalize_path(value: str | None) -> str:
    if not value:
        return "<unknown>"
    return value[2:] if value.startswith("./") else value


def route_key(route: Any) -> str:
    if not isinstance(route, dict) or not isinstance(route.get("route"), list):
        return ""
    parts = []
    for entry in route["route"]:
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
        if not isinstance(item, dict):
            fail("zizmor findings must be objects")
        if item.get("ignored"):
            continue
        determinations = item.get("determinations")
        if not isinstance(determinations, dict):
            fail("zizmor finding determinations must be an object")
        severity = nonblank(determinations.get("severity"), "zizmor severity").lower()
        severity_rank(severity)
        ident = nonblank(item.get("ident"), "zizmor ident")
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
        findings.append(
            Finding(
                tool="zizmor",
                fingerprint="|".join(["zizmor", ident, path, route, detail]),
                rule_id=ident,
                severity=severity,
                location=path,
                summary=str(item.get("desc") or annotation or feature or ident),
            )
        )
    return findings


def validate_descriptor(report: dict[str, Any], tool: str) -> None:
    descriptor = report.get("descriptor")
    if not isinstance(descriptor, dict):
        fail(f"{tool} report must contain a descriptor object")
    if descriptor.get("name") != tool:
        fail(f"unsupported {tool} report descriptor name: {descriptor.get('name')}")
    version = nonblank(descriptor.get("version"), f"{tool} descriptor version")
    if SEMVER_RE.fullmatch(version.lstrip("v")) is None:
        fail(f"{tool} descriptor version is unsupported: {version}")
    if tool == "syft":
        schema = report.get("schema")
        if not isinstance(schema, dict):
            fail("syft report must contain a schema object")
        schema_version = nonblank(schema.get("version"), "syft schema version")
        if (
            SEMVER_RE.fullmatch(schema_version) is None
            or int(schema_version.split(".", 1)[0]) != SUPPORTED_SYFT_SCHEMA_MAJOR
        ):
            fail(f"unsupported syft schema version: {schema_version}")


def image_evidence(report: Any, tool: str, target_key: str) -> ImageEvidence:
    if not isinstance(report, dict):
        fail(f"{tool} report must be a JSON object")
    validate_descriptor(report, tool)
    source = report.get("source")
    if not isinstance(source, dict) or source.get("type") != "image":
        fail(f"{tool} report source must describe an image")
    target = source.get(target_key)
    if not isinstance(target, dict):
        fail(f"{tool} report source must contain image metadata")
    user_input = target.get("userInput")
    if not isinstance(user_input, str) or "@" not in user_input:
        fail(f"{tool} image target must be pinned by digest")
    digest = user_input.rsplit("@", 1)[1]
    if SHA256_DIGEST_RE.fullmatch(digest) is None:
        fail(f"{tool} image target must use a sha256 digest")
    repo_digests = target.get("repoDigests")
    if (
        not isinstance(repo_digests, list)
        or not any(
            isinstance(repo_digest, str)
            and "@" in repo_digest
            and repo_digest.rsplit("@", 1)[1] == digest
            for repo_digest in repo_digests
        )
    ):
        fail(f"{tool} image target digest must appear in repoDigests")
    if target.get("architecture") != "amd64" or target.get("os") != "linux":
        fail(f"{tool} image target must be linux/amd64")
    layers = target.get("layers")
    if not isinstance(layers, list) or not layers:
        fail(f"{tool} image target must contain rootfs layers")
    layer_ids: list[str] = []
    for layer in layers:
        layer_id = layer.get("digest") if isinstance(layer, dict) else None
        if not isinstance(layer_id, str) or SHA256_DIGEST_RE.fullmatch(layer_id) is None:
            fail(f"{tool} image target layers must use sha256 digests")
        layer_ids.append(layer_id)
    if len(layer_ids) != len(set(layer_ids)):
        fail(f"{tool} image target contains duplicate rootfs layers")
    return ImageEvidence(digest=digest, layer_ids=tuple(layer_ids))


def syft_artifacts(report: Any) -> dict[str, dict[str, Any]]:
    artifacts = report.get("artifacts") if isinstance(report, dict) else None
    if not isinstance(artifacts, list):
        fail("syft report must contain an artifacts list")
    indexed: dict[str, dict[str, Any]] = {}
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            fail("syft report artifacts must be objects")
        artifact_id = nonblank(artifact.get("id"), "syft artifact id")
        if artifact_id in indexed:
            fail(f"syft report contains duplicate artifact id: {artifact_id}")
        for field in ("name", "version", "type"):
            nonblank(artifact.get(field), f"syft artifact {field}")
        indexed[artifact_id] = artifact
    return indexed


def validate_image_path(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or value == "/"
        or "\x00" in value
        or any(part in {"", ".", ".."} for part in value.split("/")[1:])
    ):
        fail(f"{field} must be a normalized absolute image path")
    return value


def syft_files(report: Any) -> tuple[frozenset[str], tuple[tuple[str, str], ...]]:
    files = report.get("files") if isinstance(report, dict) else None
    if not isinstance(files, list) or not files:
        fail("syft report must contain native file evidence")
    paths: set[str] = set()
    sha256_digests: dict[str, str] = {}
    for entry in files:
        location = entry.get("location") if isinstance(entry, dict) else None
        path = validate_image_path(
            location.get("path") if isinstance(location, dict) else None,
            "syft file location path",
        )
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
        if not isinstance(layer_id, str) or SHA256_DIGEST_RE.fullmatch(layer_id) is None:
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
) -> NormalizedGrype:
    if syft_report is None:
        fail("grype checks require native Syft JSON evidence")
    image = image_evidence(report, "grype", "target")
    syft_image = image_evidence(syft_report, "syft", "metadata")
    if image != syft_image:
        fail("Grype and Syft reports do not describe the same image evidence")
    artifacts = syft_artifacts(syft_report)
    syft_file_paths, syft_file_digests = syft_files(syft_report)
    matches = report.get("matches") if isinstance(report, dict) else None
    if not isinstance(matches, list):
        fail("grype report must contain a matches list")
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for item in matches:
        if not isinstance(item, dict):
            fail("grype report matches must be objects")
        vulnerability = item.get("vulnerability")
        artifact = item.get("artifact")
        if not isinstance(vulnerability, dict) or not isinstance(artifact, dict):
            fail("grype report matches must contain vulnerability and artifact objects")
        artifact_id = nonblank(artifact.get("id"), "grype artifact id")
        syft_artifact = artifacts.get(artifact_id)
        if syft_artifact is None or any(
            artifact.get(field) != syft_artifact.get(field)
            for field in ("id", "name", "version", "type", "locations")
        ):
            fail("grype finding artifact does not match the Syft package model")
        vulnerability_id = nonblank(
            vulnerability.get("id"), "grype vulnerability id"
        )
        package = nonblank(artifact.get("name"), "grype package name")
        installed_version = nonblank(
            artifact.get("version"), "grype installed package version"
        )
        package_type = nonblank(artifact.get("type"), "grype package type")
        severity = nonblank(
            vulnerability.get("severity"), "grype vulnerability severity"
        ).lower()
        severity_rank(severity)
        fix = vulnerability.get("fix")
        if not isinstance(fix, dict):
            fail(f"grype finding {vulnerability_id} must contain a fix object")
        versions = fix.get("versions")
        if not isinstance(versions, list) or any(
            not isinstance(version, str) for version in versions
        ):
            fail(f"grype finding {vulnerability_id} has malformed fix versions")
        fix_versions = tuple(version.strip() for version in versions if version.strip())
        fix_state = fix.get("state")
        if (
            not isinstance(fix_state, str)
            or fix_state.casefold() not in GRYPE_FIX_STATES
        ):
            fail(f"grype finding {vulnerability_id} has unsupported fix state")
        key = (vulnerability_id, package, installed_version)
        if key in seen:
            fail(
                "grype report contains duplicate stable finding identity: "
                f"{vulnerability_id} {package} {installed_version}"
            )
        seen.add(key)
        component_layer_id, component_layer_error = component_layer(
            artifact, image.layer_ids
        )
        findings.append(
            Finding(
                tool="grype",
                fingerprint="|".join(
                    [
                        "grype",
                        subject,
                        vulnerability_id,
                        package,
                        installed_version,
                        package_type,
                    ]
                ),
                rule_id=vulnerability_id,
                severity=severity,
                location=subject,
                summary=f"{vulnerability_id} in {package} {installed_version}",
                package=package,
                installed_version=installed_version,
                package_type=package_type,
                fix_versions=fix_versions,
                fix_state=fix_state.casefold(),
                image_digest=image.digest,
                layer_ids=image.layer_ids,
                component_layer_id=component_layer_id,
                component_layer_error=component_layer_error,
                syft_file_paths=syft_file_paths,
                syft_file_digests=syft_file_digests,
            )
        )
    return NormalizedGrype(image=image, findings=tuple(findings))


def validate_policies(policies: Any) -> None:
    if not isinstance(policies, list) or not policies:
        fail("baseline must contain non-empty policies")
    seen_tools: set[str] = set()
    for policy in policies:
        if not isinstance(policy, dict):
            fail("baseline policies must be objects")
        tool = nonblank(policy.get("tool"), "baseline policy tool")
        expected_fields = {"tool", "minimum_severity", "action"}
        if tool == "grype":
            expected_fields.add("block_fixable")
        if set(policy) != expected_fields:
            fail(f"baseline policy for {tool} has missing or unknown fields")
        if tool not in {"zizmor", "grype"} or tool in seen_tools:
            fail(f"unsupported or duplicate baseline policy tool: {tool}")
        seen_tools.add(tool)
        severity_rank(policy["minimum_severity"])
        if policy["action"] != "block_unreviewed":
            fail(f"unsupported policy action: {policy['action']}")
        if tool == "grype" and policy["block_fixable"] is not True:
            fail("grype policy must set block_fixable to true")
    if seen_tools != {"zizmor", "grype"}:
        fail("baseline must define exactly the zizmor and grype policies")


def definition_digest(definition: dict[str, Any]) -> str:
    payload = json.dumps(
        {key: value for key, value in definition.items() if key != "definition_digest"},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def validate_exposure_assertion(assertion: Any) -> None:
    if not isinstance(assertion, dict):
        fail("advisory exception exposure_assertion must be an object")
    kind = assertion.get("kind")
    if kind not in ASSERTION_FIELDS:
        fail(f"unknown exposure assertion kind: {kind}")
    if set(assertion) != ASSERTION_FIELDS[kind]:
        fail(f"exposure assertion {kind} has missing or unknown fields")
    if assertion.get("definition_digest") != definition_digest(assertion):
        fail("exposure assertion definition changed without re-review")
    if SHA256_DIGEST_RE.fullmatch(str(assertion["reference_image_digest"])) is None:
        fail("exposure assertion reference_image_digest must be a sha256 digest")
    if GIT_REVISION_RE.fullmatch(str(assertion["reference_source_revision"])) is None:
        fail("exposure assertion reference_source_revision must be a full Git revision")
    if assertion["reference_provenance"] not in REFERENCE_PROVENANCE_KINDS:
        fail("exposure assertion reference_provenance is unsupported")
    if kind in {
        "executable_closure_equals",
        "dynamic_symbol_absent",
        "package_absent_from_executable_closure",
    }:
        executables = assertion["executables"]
        if (
            not isinstance(executables, list)
            or not executables
            or len(executables) != len(set(executables))
        ):
            fail(f"exposure assertion {kind} executables must be a unique non-empty list")
        for executable in executables:
            validate_image_path(executable, "exposure assertion executables[]")
    if kind == "dynamic_symbol_absent":
        symbols = assertion["symbols"]
        if (
            not isinstance(symbols, list)
            or not symbols
            or len(symbols) != len(set(symbols))
            or any(
                not isinstance(symbol, str) or SYMBOL_RE.fullmatch(symbol) is None
                for symbol in symbols
            )
        ):
            fail("dynamic_symbol_absent symbols must be unique ELF symbol names")
        if DYNAMIC_LOADING_APIS & set(symbols):
            fail("dynamic loading APIs cannot be absent-symbol targets")
    elif kind == "package_absent_from_executable_closure":
        package = assertion["package"]
        if not isinstance(package, str) or PACKAGE_NAME_RE.fullmatch(package) is None:
            fail("package_absent_from_executable_closure package is malformed")
    elif kind in {
        "executable_closure_equals",
        "file_digest_equals",
        "whole_image_fingerprint_equals",
    }:
        files = assertion["files"]
        if not isinstance(files, list) or not files:
            fail(f"{kind} files must be a non-empty list")
        seen_paths: set[str] = set()
        for entry in files:
            if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
                fail(f"{kind} files must contain path and sha256")
            path = validate_image_path(entry["path"], "exposure assertion files[].path")
            if path in seen_paths:
                fail(f"{kind} files must use unique paths")
            seen_paths.add(path)
            if SHA256_DIGEST_RE.fullmatch(str(entry["sha256"])) is None:
                fail(f"{kind} files[].sha256 must be a sha256 digest")
        if kind == "executable_closure_equals":
            if not set(assertion["executables"]).issubset(seen_paths):
                fail("executable_closure_equals must include every executable file")
            basenames = [Path(path).name for path in seen_paths]
            if len(basenames) != len(set(basenames)):
                fail("executable_closure_equals file basenames must be unique")
        if kind == "whole_image_fingerprint_equals":
            if SHA256_DIGEST_RE.fullmatch(
                str(assertion["runtime_definition_digest"])
            ) is None:
                fail(
                    "whole_image_fingerprint_equals runtime_definition_digest "
                    "must be a sha256 digest"
                )


def validate_runtime(runtime: Any) -> None:
    if not isinstance(runtime, dict) or set(runtime) != V4_RUNTIME_FIELDS:
        fail("v4 runtime must have the exact stable field set")
    image = runtime["image"]
    if (
        not isinstance(image, str)
        or "@" not in image
        or SHA256_DIGEST_RE.fullmatch(image.rsplit("@", 1)[1]) is None
    ):
        fail("v4 runtime image must be pinned by sha256 digest")
    layer_ids = runtime["layer_ids"]
    if (
        not isinstance(layer_ids, list)
        or not layer_ids
        or len(layer_ids) != len(set(layer_ids))
        or any(
            not isinstance(layer, str) or SHA256_DIGEST_RE.fullmatch(layer) is None
            for layer in layer_ids
        )
    ):
        fail("v4 runtime layer_ids must be unique sha256 digests")
    application_layer_ids = runtime["application_layer_ids"]
    if (
        not isinstance(application_layer_ids, list)
        or not application_layer_ids
        or len(application_layer_ids) != len(set(application_layer_ids))
        or any(
            not isinstance(layer, str) or SHA256_DIGEST_RE.fullmatch(layer) is None
            for layer in application_layer_ids
        )
        or set(application_layer_ids) & set(layer_ids)
    ):
        fail("v4 runtime application_layer_ids must be unique sha256 digests")
    config = runtime["config"]
    if (
        not isinstance(config, dict)
        or set(config) != REQUIRED_RUNTIME_CONFIG_FIELDS
        or not isinstance(config["user"], str)
        or not config["user"]
        or not isinstance(config["working_dir"], str)
        or not config["working_dir"].startswith("/")
        or any(
            not isinstance(config[field], list)
            or any(not isinstance(value, str) for value in config[field])
            for field in ("entrypoint", "command", "environment")
        )
        or not config["entrypoint"]
        or any("=" not in entry for entry in config["environment"])
        or not isinstance(config["args_escaped"], bool)
        or not isinstance(config["stop_signal"], str)
        or not isinstance(config["exposed_ports"], list)
        or len(config["exposed_ports"]) != len(set(config["exposed_ports"]))
        or any(
            not isinstance(port, str)
            or re.fullmatch(r"[1-9][0-9]{0,4}/(?:tcp|udp|sctp)", port) is None
            or int(port.partition("/")[0]) > 65535
            for port in config["exposed_ports"]
        )
    ):
        fail("v4 runtime config must be an exact safe process contract")
    loader_environment = sorted(
        entry.partition("=")[0]
        for entry in config["environment"]
        if entry.partition("=")[0].startswith("LD_")
        or entry.partition("=")[0] in UNSUPPORTED_LOADER_ENVIRONMENT
    )
    if loader_environment:
        fail(
            "v4 runtime config contains unsupported loader environment: "
            f"{loader_environment}"
        )
    healthcheck = config["healthcheck"]
    if healthcheck is not None and (
        not isinstance(healthcheck, dict)
        or set(healthcheck) != REQUIRED_HEALTHCHECK_FIELDS
        or not isinstance(healthcheck["test"], list)
        or len(healthcheck["test"]) < 2
        or healthcheck["test"][0] != "CMD"
        or any(not isinstance(value, str) for value in healthcheck["test"])
        or any(
            not isinstance(healthcheck[field], int) or healthcheck[field] < 0
            for field in REQUIRED_HEALTHCHECK_FIELDS - {"test"}
        )
    ):
        fail("v4 runtime healthcheck must be an exact exec-form contract")
    if runtime["definition_digest"] != definition_digest(runtime):
        fail("runtime definition changed without re-review")


def validate_v4_exception(exception: Any, runtime: dict[str, Any]) -> None:
    if not isinstance(exception, dict) or set(exception) != V4_EXCEPTION_FIELDS:
        fail("v4 advisory exceptions must have the exact stable field set")
    for field in (
        "vulnerability_id",
        "package",
        "installed_version",
        "owner",
        "rationale",
    ):
        nonblank(exception.get(field), f"advisory exception {field}")
    if severity_rank(exception["severity"]) < SEVERITY_ORDER["high"]:
        fail("advisory exception severity must be high or critical")
    if exception["status"] not in V4_EXCEPTION_STATUSES:
        fail(f"unsupported advisory exception status: {exception['status']}")
    reviewed_at = parse_date(exception["reviewed_at"], "reviewed_at")
    expires_at = parse_date(exception["expires_at"], "expires_at")
    if expires_at < reviewed_at:
        fail("advisory exception expires_at must not precede reviewed_at")
    triggers = exception["invalidation_triggers"]
    if (
        not isinstance(triggers, list)
        or len(triggers) != len(set(triggers))
        or set(triggers) != REQUIRED_INVALIDATION_TRIGGERS
    ):
        fail(
            "advisory exception must contain exactly the required invalidation triggers"
        )
    if exception["runtime_definition_digest"] != runtime["definition_digest"]:
        fail("advisory exception is not bound to the reviewed runtime definition")
    component_layer_id = exception["component_layer_id"]
    if (
        not isinstance(component_layer_id, str)
        or SHA256_DIGEST_RE.fullmatch(component_layer_id) is None
        or component_layer_id not in runtime["layer_ids"]
    ):
        fail("advisory exception component layer must belong to the reviewed runtime")
    validate_exposure_assertion(exception["exposure_assertion"])


def validate_v4_baseline(data: dict[str, Any]) -> None:
    if set(data) != V4_TOP_LEVEL_FIELDS:
        fail("v4 baseline must have the exact top-level field set")
    nonblank(data.get("service"), "baseline service")
    validate_runtime(data.get("runtime"))
    validate_policies(data.get("policies"))
    exceptions = data.get("exceptions")
    if not isinstance(exceptions, list):
        fail("v4 baseline exceptions must be a list")
    seen: set[tuple[str, str, str]] = set()
    for exception in exceptions:
        validate_v4_exception(exception, data["runtime"])
        key = exception_key(exception)
        if key in seen:
            fail(f"duplicate advisory exception identity: {' '.join(key)}")
        seen.add(key)


def load_baseline(path: Path) -> dict[str, Any]:
    data = load_json(path)
    if not isinstance(data, dict):
        fail("baseline must be a JSON object")
    version = data.get("version")
    if version != 4:
        fail(f"unsupported baseline version: {version}; expected 4")
    validate_v4_baseline(data)
    return data


def exception_key(exception: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(exception["vulnerability_id"]),
        str(exception["package"]),
        str(exception["installed_version"]),
    )


def baseline_exceptions(baseline: dict[str, Any]) -> list[dict[str, Any]]:
    return baseline["exceptions"]


def rootfs_file(
    rootfs: Path,
    image_path: str,
    syft_file_digests: tuple[tuple[str, str], ...],
) -> tuple[Path | None, str]:
    try:
        root = rootfs.resolve(strict=True)
    except OSError as exc:
        return None, f"rootfs is unavailable: {exc}"
    if not root.is_dir():
        return None, "rootfs evidence is not a directory"
    expected_digest = dict(syft_file_digests).get(image_path)
    if expected_digest is None:
        return None, f"{image_path} has no native Syft sha256 evidence"
    candidate = root.joinpath(*image_path.lstrip("/").split("/"))
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        return None, f"{image_path} is unavailable or escapes the rootfs: {exc}"
    if not resolved.is_file():
        return None, f"{image_path} is not a regular file"
    try:
        observed_digest = f"sha256:{hashlib.sha256(resolved.read_bytes()).hexdigest()}"
    except OSError as exc:
        return None, f"cannot hash {image_path}: {exc}"
    if observed_digest != expected_digest:
        return (
            None,
            f"{image_path} rootfs digest {observed_digest} does not match "
            f"native Syft evidence {expected_digest}",
        )
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
    if len(data) < 20 or data[:4] != b"\x7fELF":
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
        if len(data) < 64:
            raise ValueError("truncated ELF64 header")
        program_offset = struct.unpack_from(endian + "Q", data, 32)[0]
        section_offset = struct.unpack_from(endian + "Q", data, 40)[0]
        program_size, program_count = struct.unpack_from(endian + "HH", data, 54)
        section_size, section_count = struct.unpack_from(endian + "HH", data, 58)
        program_format = endian + "IIQQQQQQ"
        section_format = endian + "IIQQQQIIQQ"
        symbol_format = endian + "IBBHQQ"
        dynamic_format = endian + "qQ"
    elif elf_class == 1:
        if len(data) < 52:
            raise ValueError("truncated ELF32 header")
        program_offset = struct.unpack_from(endian + "I", data, 28)[0]
        section_offset = struct.unpack_from(endian + "I", data, 32)[0]
        program_size, program_count = struct.unpack_from(endian + "HH", data, 42)
        section_size, section_count = struct.unpack_from(endian + "HH", data, 46)
        program_format = endian + "IIIIIIII"
        section_format = endian + "IIIIIIIIII"
        symbol_format = endian + "IIIBBH"
        dynamic_format = endian + "iI"
    else:
        raise ValueError("unsupported ELF class")
    machine = struct.unpack_from(endian + "H", data, 18)[0]
    expected_program_size = struct.calcsize(program_format)
    if program_count and (
        program_size != expected_program_size
        or program_offset == 0
        or program_count > 4096
    ):
        raise ValueError("malformed ELF program-header table")
    interpreter: str | None = None
    for index in range(program_count):
        offset = program_offset + index * program_size
        raw = bounded_slice(data, offset, program_size, "program header")
        program = struct.unpack(program_format, raw)
        if program[0] != 3:
            continue
        if interpreter is not None:
            raise ValueError("ELF has multiple PT_INTERP entries")
        interpreter_offset = program[2] if elf_class == 2 else program[1]
        interpreter_size = program[5] if elf_class == 2 else program[4]
        encoded = bounded_slice(
            data, interpreter_offset, interpreter_size, "PT_INTERP value"
        )
        if not encoded or encoded[-1:] != b"\0" or b"\0" in encoded[:-1]:
            raise ValueError("ELF PT_INTERP value is malformed")
        interpreter = encoded[:-1].decode("utf-8")

    expected_section_size = struct.calcsize(section_format)
    if (
        section_size != expected_section_size
        or section_count == 0
        or section_count > 4096
    ):
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
    rpaths: list[str] = []
    runpaths: list[str] = []
    unsupported_loader_tags: set[str] = set()
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
                elif tag == 15:
                    rpaths.extend(c_string(strings, value).split(":"))
                elif tag == 29:
                    runpaths.extend(c_string(strings, value).split(":"))
                elif tag == 0x7FFFFFFF:
                    unsupported_loader_tags.add("DT_FILTER")
                elif tag == 0x7FFFFFFD:
                    unsupported_loader_tags.add("DT_AUXILIARY")
                elif tag == 0x6FFFFEFB:
                    unsupported_loader_tags.add("DT_DEPAUDIT")
                elif tag == 0x6FFFFEFC:
                    unsupported_loader_tags.add("DT_AUDIT")
    if not saw_dynamic_symbols:
        raise ValueError("ELF has no dynamic symbol table")
    return ElfMetadata(
        machine,
        frozenset(undefined),
        tuple(needed),
        tuple(rpaths),
        tuple(runpaths),
        interpreter,
        frozenset(unsupported_loader_tags),
    )


def dynamic_symbol_absent(
    assertion: dict[str, Any],
    rootfs: Path,
    syft_file_paths: frozenset[str],
    syft_file_digests: tuple[tuple[str, str], ...],
) -> AssertionResult:
    forbidden = set(assertion["symbols"])
    closure, error = executable_closure(
        assertion["executables"], rootfs, syft_file_paths, syft_file_digests
    )
    if closure is None:
        return AssertionResult(False, False, error)
    for image_path, (_, metadata) in closure.items():
        present = forbidden & metadata.undefined_dynamic_symbols
        if present:
            return AssertionResult(
                True,
                False,
                f"{image_path} has forbidden undefined dynamic symbol(s): "
                f"{sorted(present)}",
            )
    return AssertionResult(
        True,
        True,
        f"all forbidden undefined dynamic symbols are absent from "
        f"{len(closure)} closure files",
    )


def image_path_for(rootfs: Path, path: Path) -> str:
    return "/" + str(path.resolve().relative_to(rootfs.resolve()))


def normalize_absolute_image_path(path: str) -> str:
    parts: list[str] = []
    for part in path.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/" + "/".join(parts)


def loader_search_directories(
    rootfs: Path,
    parent: Path,
    metadata: ElfMetadata,
) -> tuple[tuple[str, ...] | None, str]:
    origin = image_path_for(rootfs, parent.parent)
    parent_image_path = image_path_for(rootfs, parent)
    if metadata.rpaths:
        return (
            None,
            f"{parent_image_path} uses unsupported DT_RPATH loader semantics",
        )
    search: list[str] = []
    for entry in metadata.runpaths:
        if not entry:
            return (
                None,
                f"{parent_image_path} has an empty DT_RUNPATH entry",
            )
        expanded = entry.replace("${ORIGIN}", origin).replace("$ORIGIN", origin)
        if "$" in expanded:
            return (
                None,
                f"{parent_image_path} has unsupported DT_RUNPATH token in {entry}",
            )
        if not expanded.startswith("/"):
            return (
                None,
                f"{parent_image_path} has unsupported relative DT_RUNPATH {entry}",
            )
        search.append(normalize_absolute_image_path(expanded))
    default_search = ELF_DEFAULT_LIBRARY_DIRS.get(metadata.machine)
    if default_search is None:
        return (
            None,
            f"{parent_image_path} has unsupported ELF machine {metadata.machine}",
        )
    search.extend(default_search)
    return tuple(search), ""


def resolve_needed(
    rootfs: Path,
    parent: Path,
    needed: str,
    metadata: ElfMetadata,
    syft_file_digests: tuple[tuple[str, str], ...],
) -> tuple[Path | None, str]:
    parent_image_path = image_path_for(rootfs, parent)
    search, search_error = loader_search_directories(rootfs, parent, metadata)
    if search is None:
        return None, search_error
    if "/" in needed:
        if not needed.startswith("/"):
            return (
                None,
                f"{parent_image_path} uses unsupported relative dependency {needed}",
            )
        candidates = [normalize_absolute_image_path(needed)]
    else:
        candidates = [f"{directory.rstrip('/')}/{needed}" for directory in search]
    for candidate in candidates:
        if not candidate.startswith("/"):
            continue
        resolved, _ = rootfs_file(rootfs, candidate, syft_file_digests)
        if resolved is not None:
            try:
                dependency_metadata = parse_elf(resolved)
            except (OSError, UnicodeError, ValueError, struct.error) as exc:
                return None, f"cannot inspect ELF dependency {candidate}: {exc}"
            if dependency_metadata.machine != metadata.machine:
                return (
                    None,
                    f"ELF dependency {candidate} machine "
                    f"{dependency_metadata.machine} does not match "
                    f"{parent_image_path} machine {metadata.machine}",
                )
            return resolved, ""
    return (
        None,
        f"cannot resolve ELF dependency {needed} from {parent_image_path}",
    )


def resolve_interpreter(
    rootfs: Path,
    interpreter: str,
    machine: int,
    syft_file_digests: tuple[tuple[str, str], ...],
) -> tuple[Path | None, str]:
    if (
        not interpreter.startswith("/")
        or normalize_absolute_image_path(interpreter) != interpreter
    ):
        return None, f"unsupported PT_INTERP path {interpreter!r}"
    try:
        root = rootfs.resolve(strict=True)
        candidate = root.joinpath(*interpreter.lstrip("/").split("/"))
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        return None, f"PT_INTERP {interpreter} is unavailable or escapes the rootfs: {exc}"
    canonical_path = image_path_for(rootfs, resolved)
    bound_path, error = rootfs_file(rootfs, canonical_path, syft_file_digests)
    if bound_path is None:
        return None, f"PT_INTERP {interpreter} is not Syft-bound: {error}"
    try:
        metadata = parse_elf(bound_path)
    except (OSError, UnicodeError, ValueError, struct.error) as exc:
        return None, f"cannot inspect PT_INTERP {interpreter}: {exc}"
    if metadata.machine != machine:
        return (
            None,
            f"PT_INTERP {interpreter} machine {metadata.machine} "
            f"does not match executable machine {machine}",
        )
    return bound_path, ""


def unsupported_global_loader_input(
    rootfs: Path,
    syft_file_paths: frozenset[str],
) -> str:
    for image_path in UNSUPPORTED_GLOBAL_LOADER_INPUTS:
        candidate = rootfs.joinpath(*image_path.lstrip("/").split("/"))
        try:
            present_in_rootfs = candidate.exists() or candidate.is_symlink()
        except OSError:
            present_in_rootfs = True
        if image_path in syft_file_paths or present_in_rootfs:
            return f"candidate has unsupported global loader input {image_path}"
    return ""


def executable_closure(
    executables: list[str],
    rootfs: Path,
    syft_file_paths: frozenset[str],
    syft_file_digests: tuple[tuple[str, str], ...],
) -> tuple[dict[str, tuple[Path, ElfMetadata]] | None, str]:
    loader_error = unsupported_global_loader_input(rootfs, syft_file_paths)
    if loader_error:
        return None, loader_error
    queue: list[Path] = []
    entry_paths: set[str] = set()
    for image_path in executables:
        path, error = rootfs_file(rootfs, image_path, syft_file_digests)
        if path is None:
            return None, error
        queue.append(path)
        entry_paths.add(image_path_for(rootfs, path))
    closure: dict[str, tuple[Path, ElfMetadata]] = {}
    while queue:
        path = queue.pop()
        image_path = image_path_for(rootfs, path)
        if image_path in closure:
            continue
        try:
            metadata = parse_elf(path)
        except (OSError, UnicodeError, ValueError, struct.error) as exc:
            return None, f"cannot inspect closure file {image_path}: {exc}"
        if metadata.unsupported_loader_tags:
            return (
                None,
                f"{image_path} uses unsupported dynamic loader tag(s): "
                f"{sorted(metadata.unsupported_loader_tags)}",
            )
        dynamic_loading = DYNAMIC_LOADING_APIS & metadata.undefined_dynamic_symbols
        if dynamic_loading:
            return (
                None,
                f"{image_path} imports dynamic loading API(s) "
                f"{sorted(dynamic_loading)}; executable closure is open",
            )
        _, loader_error = loader_search_directories(rootfs, path, metadata)
        if loader_error:
            return None, loader_error
        closure[image_path] = (path, metadata)
        if image_path in entry_paths and metadata.interpreter is not None:
            interpreter, interpreter_error = resolve_interpreter(
                rootfs,
                metadata.interpreter,
                metadata.machine,
                syft_file_digests,
            )
            if interpreter is None:
                return None, interpreter_error
            queue.append(interpreter)
        for needed in metadata.needed:
            dependency, dependency_error = resolve_needed(
                rootfs, path, needed, metadata, syft_file_digests
            )
            if dependency is None:
                return None, dependency_error
            queue.append(dependency)
    return dict(sorted(closure.items())), ""


def executable_closure_equals(
    assertion: dict[str, Any],
    rootfs: Path,
    syft_file_paths: frozenset[str],
    syft_file_digests: tuple[tuple[str, str], ...],
) -> AssertionResult:
    expected = {entry["path"]: entry["sha256"] for entry in assertion["files"]}
    syft_digests = dict(syft_file_digests)
    closure, error = executable_closure(
        assertion["executables"], rootfs, syft_file_paths, syft_file_digests
    )
    if closure is None:
        return AssertionResult(False, False, error)
    observed_paths = set(closure)
    expected_paths = set(expected)
    if observed_paths != expected_paths:
        return AssertionResult(
            True,
            False,
            "executable closure paths changed: "
            f"added={sorted(observed_paths - expected_paths)} "
            f"removed={sorted(expected_paths - observed_paths)}",
        )
    for image_path, expected_digest in expected.items():
        if syft_digests.get(image_path) != expected_digest:
            return AssertionResult(
                True,
                False,
                f"{image_path} native Syft digest is "
                f"{syft_digests.get(image_path, '<missing>')}, "
                f"expected reviewed digest {expected_digest}",
            )
        path, error = rootfs_file(rootfs, image_path, syft_file_digests)
        if path is None:
            return AssertionResult(False, False, error)
        try:
            digest = f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"
        except OSError as exc:
            return AssertionResult(False, False, f"cannot hash {image_path}: {exc}")
        if digest != expected_digest:
            return AssertionResult(
                True,
                False,
                f"{image_path} closure digest is {digest}, "
                f"expected {expected_digest}",
            )
    return AssertionResult(
        True,
        True,
        f"all {len(closure)} reviewed executable closure files match",
    )


def package_files(
    rootfs: Path,
    package: str,
    syft_file_digests: tuple[tuple[str, str], ...],
) -> tuple[set[Path] | None, str]:
    metadata_path = f"/var/lib/dpkg/status.d/{package}.md5sums"
    path, error = rootfs_file(rootfs, metadata_path, syft_file_digests)
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
            return None, f"{metadata_path} contains malformed package ownership evidence"
        image_path = "/" + match.group(1).lstrip("/")
        owned_path, _ = rootfs_file(rootfs, image_path, syft_file_digests)
        if owned_path is not None:
            owned.add(owned_path)
    if not owned:
        return None, f"{metadata_path} establishes no package-owned files"
    return owned, ""


def package_absent_from_executable_closure(
    assertion: dict[str, Any],
    rootfs: Path,
    syft_file_paths: frozenset[str],
    syft_file_digests: tuple[tuple[str, str], ...],
) -> AssertionResult:
    owned, error = package_files(rootfs, assertion["package"], syft_file_digests)
    if owned is None:
        return AssertionResult(False, False, error)
    closure, closure_error = executable_closure(
        assertion["executables"], rootfs, syft_file_paths, syft_file_digests
    )
    if closure is None:
        return AssertionResult(False, False, closure_error)
    for image_path, (path, _) in closure.items():
        if path in owned:
            return AssertionResult(
                True,
                False,
                f"{assertion['package']} file is present in executable closure: "
                f"{image_path}",
            )
    return AssertionResult(
        True,
        True,
        f"{assertion['package']} is absent from the evaluated executable closure",
    )


def file_digest_equals(
    assertion: dict[str, Any],
    rootfs: Path,
    syft_file_digests: tuple[tuple[str, str], ...],
) -> AssertionResult:
    for entry in assertion["files"]:
        path, error = rootfs_file(rootfs, entry["path"], syft_file_digests)
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
                f"{entry['path']} digest is {digest}, expected {entry['sha256']}; "
                "review the file, then renew its digest and the assertion "
                "definition digest",
            )
    return AssertionResult(
        True,
        True,
        f"all {len(assertion['files'])} reviewed file digests match",
    )


def whole_image_fingerprint_equals(
    assertion: dict[str, Any],
    runtime: dict[str, Any],
    candidate_layer_ids: tuple[str, ...],
    candidate_runtime_config: dict[str, Any],
    rootfs: Path,
    syft_file_digests: tuple[tuple[str, str], ...],
) -> AssertionResult:
    runtime_digest = definition_digest(runtime)
    if (
        assertion["runtime_definition_digest"] != runtime_digest
        or runtime["definition_digest"] != runtime_digest
    ):
        return AssertionResult(
            False,
            False,
            "image fingerprint is not bound to the current runtime definition; "
            "renew the runtime and assertion definition digests",
        )
    expected_layers = tuple(runtime["layer_ids"] + runtime["application_layer_ids"])
    if candidate_layer_ids != expected_layers:
        return AssertionResult(
            True,
            False,
            "ordered OCI rootfs.diff_ids changed; review the candidate, then update "
            "runtime.layer_ids/application_layer_ids and renew the runtime and "
            "assertion definition digests",
        )
    if candidate_runtime_config != runtime["config"]:
        return AssertionResult(
            True,
            False,
            "OCI runtime config changed; review the candidate, then update "
            "runtime.config and renew the runtime and assertion definition digests",
        )
    result = file_digest_equals(assertion, rootfs, syft_file_digests)
    if not result.evaluable or not result.passed:
        return result
    return AssertionResult(
        True,
        True,
        f"ordered OCI rootfs.diff_ids, OCI config, and {len(assertion['files'])} "
        "reviewed files match",
    )


def normalize_runtime_config(
    config: Any,
    expected_source_revision: str,
) -> dict[str, Any]:
    if not isinstance(config, dict):
        fail("candidate OCI config must be a JSON object")
    fields = set(config)
    missing = REQUIRED_OCI_RUNTIME_CONFIG_FIELDS - fields
    unknown = fields - (
        REQUIRED_OCI_RUNTIME_CONFIG_FIELDS | OPTIONAL_OCI_RUNTIME_CONFIG_FIELDS
    )
    if missing or unknown:
        fail(
            "candidate OCI config has an unsupported field set: "
            f"missing={sorted(missing)} unknown={sorted(unknown)}"
        )
    labels = config.get("Labels")
    if (
        not isinstance(labels, dict)
        or set(labels) != OCI_IDENTITY_LABELS
        or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in labels.items()
        )
    ):
        fail(
            "candidate OCI config Labels must contain exactly the release "
            "identity labels"
        )
    for label in (
        "org.opencontainers.image.source",
        "org.opencontainers.image.revision",
        "org.opencontainers.image.version",
    ):
        nonblank(labels.get(label), f"candidate OCI config label {label}")
    if labels["org.opencontainers.image.source"] != (
        "https://github.com/registrystack/registry-stack"
    ):
        fail("candidate OCI config source label is not the release repository")
    if labels["org.opencontainers.image.revision"] != expected_source_revision:
        fail("candidate OCI config revision label does not match protected source")
    for label, expected in OCI_RUNTIME_IDENTITY_LABELS.items():
        if labels[label] != expected:
            fail(f"candidate OCI config label {label} must be {expected!r}")

    def string_list(field: str) -> list[str]:
        value = config.get(field)
        if value is None:
            return []
        if not isinstance(value, list) or any(
            not isinstance(entry, str) for entry in value
        ):
            fail(f"candidate OCI config {field} must be a string list")
        return value

    environment = string_list("Env")
    if any("=" not in entry or not entry.partition("=")[0] for entry in environment):
        fail("candidate OCI config Env entries must be NAME=VALUE strings")
    environment_names = [entry.partition("=")[0] for entry in environment]
    if len(environment_names) != len(set(environment_names)):
        fail("candidate OCI config Env names must be unique")
    loader_environment = sorted(
        entry.partition("=")[0]
        for entry in environment
        if entry.partition("=")[0].startswith("LD_")
        or entry.partition("=")[0] in UNSUPPORTED_LOADER_ENVIRONMENT
    )
    if loader_environment:
        fail(
            "candidate OCI config contains unsupported loader environment: "
            f"{loader_environment}"
        )
    args_escaped = config["ArgsEscaped"]
    if not isinstance(args_escaped, bool):
        fail("candidate OCI config ArgsEscaped must be boolean")
    raw_ports = config["ExposedPorts"]
    if not isinstance(raw_ports, dict) or any(
        not isinstance(key, str) or value != {} for key, value in raw_ports.items()
    ):
        fail("candidate OCI config ExposedPorts must map ports to empty objects")
    exposed_ports = sorted(raw_ports)
    if any(
        not isinstance(port, str)
        or re.fullmatch(r"[1-9][0-9]{0,4}/(?:tcp|udp|sctp)", port) is None
        or int(port.partition("/")[0]) > 65535
        for port in exposed_ports
    ):
        fail("candidate OCI config ExposedPorts contains an invalid port")
    stop_signal = config.get("StopSignal", "")
    if not isinstance(stop_signal, str):
        fail("candidate OCI config StopSignal must be a string")
    raw_healthcheck = config.get("Healthcheck")
    healthcheck = None
    if raw_healthcheck is not None:
        if (
            not isinstance(raw_healthcheck, dict)
            or "Test" not in raw_healthcheck
            or not set(raw_healthcheck).issubset(OCI_HEALTHCHECK_FIELDS)
        ):
            fail("candidate OCI config Healthcheck has unsupported fields")
        test = raw_healthcheck.get("Test")
        if (
            not isinstance(test, list)
            or len(test) < 2
            or test[0] != "CMD"
            or any(not isinstance(value, str) for value in test)
        ):
            fail("candidate OCI config Healthcheck must use exec-form CMD")
        healthcheck = {
            "test": test,
            "interval": raw_healthcheck.get("Interval", 0),
            "timeout": raw_healthcheck.get("Timeout", 0),
            "start_period": raw_healthcheck.get("StartPeriod", 0),
            "start_interval": raw_healthcheck.get("StartInterval", 0),
            "retries": raw_healthcheck.get("Retries", 0),
        }
        if any(
            not isinstance(healthcheck[field], int) or healthcheck[field] < 0
            for field in REQUIRED_HEALTHCHECK_FIELDS - {"test"}
        ):
            fail("candidate OCI config Healthcheck timings must be non-negative integers")
    user = config["User"]
    working_dir = config["WorkingDir"]
    if not isinstance(user, str) or not isinstance(working_dir, str):
        fail("candidate OCI config User and WorkingDir must be strings")
    return {
        "user": user,
        "entrypoint": string_list("Entrypoint"),
        "command": string_list("Cmd"),
        "working_dir": working_dir,
        "environment": environment,
        "healthcheck": healthcheck,
        "args_escaped": args_escaped,
        "exposed_ports": exposed_ports,
        "stop_signal": stop_signal,
    }


def normalize_oci_image_config(
    document: Any,
    expected_source_revision: str,
) -> OciImageConfigEvidence:
    if not isinstance(document, dict):
        fail("candidate OCI image config must be a JSON object")
    if document.get("architecture") != "amd64" or document.get("os") != "linux":
        fail("candidate OCI image config must be linux/amd64")
    rootfs = document.get("rootfs")
    if not isinstance(rootfs, dict) or set(rootfs) != {"type", "diff_ids"}:
        fail("candidate OCI image config rootfs must contain type and diff_ids")
    if rootfs["type"] != "layers":
        fail("candidate OCI image config rootfs type must be layers")
    layer_ids = rootfs["diff_ids"]
    if (
        not isinstance(layer_ids, list)
        or not layer_ids
        or len(layer_ids) != len(set(layer_ids))
        or any(
            not isinstance(layer_id, str)
            or SHA256_DIGEST_RE.fullmatch(layer_id) is None
            for layer_id in layer_ids
        )
    ):
        fail("candidate OCI image config rootfs diff_ids must be unique sha256 values")
    return OciImageConfigEvidence(
        layer_ids=tuple(layer_ids),
        runtime_config=normalize_runtime_config(
            document.get("config"), expected_source_revision
        ),
    )


def evaluate_exposure_assertion(
    assertion: dict[str, Any],
    runtime: dict[str, Any],
    candidate_layer_ids: tuple[str, ...],
    candidate_runtime_config: dict[str, Any],
    rootfs: Path | None,
    syft_file_paths: frozenset[str],
    syft_file_digests: tuple[tuple[str, str], ...],
) -> AssertionResult:
    if rootfs is None:
        return AssertionResult(False, False, "candidate rootfs evidence was not supplied")
    kind = assertion["kind"]
    if kind == "executable_closure_equals":
        return executable_closure_equals(
            assertion, rootfs, syft_file_paths, syft_file_digests
        )
    if kind == "dynamic_symbol_absent":
        return dynamic_symbol_absent(
            assertion, rootfs, syft_file_paths, syft_file_digests
        )
    if kind == "package_absent_from_executable_closure":
        return package_absent_from_executable_closure(
            assertion, rootfs, syft_file_paths, syft_file_digests
        )
    if kind == "file_digest_equals":
        return file_digest_equals(assertion, rootfs, syft_file_digests)
    if kind == "whole_image_fingerprint_equals":
        return whole_image_fingerprint_equals(
            assertion,
            runtime,
            candidate_layer_ids,
            candidate_runtime_config,
            rootfs,
            syft_file_digests,
        )
    return AssertionResult(False, False, f"unknown exposure assertion kind: {kind}")


def runtime_base_mismatch(finding: Finding, runtime: dict[str, Any]) -> str:
    expected = tuple(runtime["layer_ids"])
    if finding.layer_ids[: len(expected)] != expected:
        return f"candidate layers do not begin with pinned base {runtime['image']}"
    if finding.component_layer_id not in expected:
        return "candidate component layer is not part of the pinned runtime base"
    return ""


def reviewed_runtime_mismatch(
    finding: Finding,
    runtime: dict[str, Any],
    candidate_runtime_config: dict[str, Any],
) -> str:
    expected_layers = tuple(runtime["layer_ids"] + runtime["application_layer_ids"])
    if finding.layer_ids != expected_layers:
        return "candidate rootfs layers do not match the reviewed candidate layers"
    if candidate_runtime_config != runtime["config"]:
        return "candidate OCI process config does not match the reviewed runtime config"
    return ""


def policy_threshold(baseline: dict[str, Any], tool: str) -> str:
    matches = [policy for policy in baseline["policies"] if policy["tool"] == tool]
    if not matches:
        fail(f"baseline has no policy for {tool}")
    return str(matches[0]["minimum_severity"]).lower()


def finding_is_blocking(finding: Finding, tool: str, threshold_rank: int) -> bool:
    return (tool == "grype" and finding.fixable) or severity_rank(
        finding.severity
    ) >= threshold_rank


def check_grype_findings(
    findings: list[Finding],
    report_image: ImageEvidence,
    baseline: dict[str, Any],
    today: dt.date,
    rootfs: Path | None,
    candidate_image_digest: str,
    runtime_config: dict[str, Any],
    oci_layer_ids: tuple[str, ...],
) -> int:
    threshold = policy_threshold(baseline, "grype")
    threshold_rank = severity_rank(threshold)
    blocking = [
        finding
        for finding in findings
        if finding_is_blocking(finding, "grype", threshold_rank)
    ]
    exceptions = baseline_exceptions(baseline)
    by_key = {exception_key(exception): exception for exception in exceptions}
    finding_by_key = {finding.exception_key: finding for finding in findings}
    findings_by_advisory: dict[tuple[str, str], list[Finding]] = {}
    for finding in findings:
        findings_by_advisory.setdefault(finding.advisory_key, []).append(finding)
    reported_version_mismatches: set[tuple[str, str, str]] = set()
    invalid: list[str] = []

    if report_image.digest != candidate_image_digest:
        invalid.append(
            "candidate image identity mismatch: "
            f"report={report_image.digest} "
            f"expected={candidate_image_digest}"
        )
    if report_image.layer_ids != oci_layer_ids:
        invalid.append(
            "candidate rootfs evidence mismatch: OCI rootfs.diff_ids do not "
            "match the Grype and Syft reports"
        )

    assertion_results: dict[str, AssertionResult] = {}
    assertion_failures: dict[str, tuple[str, AssertionResult]] = {}

    for exception in exceptions:
        key = exception_key(exception)
        advisory_key = key[:2]
        finding = finding_by_key.get(key)
        if parse_date(exception["reviewed_at"], "reviewed_at") > today:
            invalid.append(f"future-dated exception: {' '.join(key)}")
        if parse_date(exception["expires_at"], "expires_at") < today:
            invalid.append(f"expired exception: {' '.join(key)}")
        if finding is None:
            changed = findings_by_advisory.get(advisory_key, [])
            if changed:
                installed_versions = sorted(
                    {candidate.installed_version for candidate in changed}
                )
                reported_version_mismatches.update(
                    candidate.exception_key for candidate in changed
                )
                invalid.append(
                    "version-mismatched exception: "
                    f"{key[0]} {key[1]} reviewed={key[2]} "
                    f"installed={installed_versions}"
                )
            else:
                invalid.append(
                    "fixed or absent finding still has an exception: " + " ".join(key)
                )
            continue
        if finding.fixable:
            invalid.append(
                "fixable finding cannot be excepted: "
                f"{finding.rule_id} {finding.package} {finding.installed_version}"
            )
        if str(exception["severity"]).casefold() != finding.severity.casefold():
            invalid.append(
                "material finding change invalidates exception: "
                f"{finding.rule_id} {finding.package} {finding.installed_version} "
                f"reviewed_severity={exception['severity']} "
                f"current_severity={finding.severity}"
            )
        if finding.component_layer_error:
            invalid.append(
                "component evidence is unevaluable: "
                f"{finding.rule_id} {finding.package} {finding.installed_version}: "
                f"{finding.component_layer_error}"
            )
        elif exception["component_layer_id"] != finding.component_layer_id:
            invalid.append(
                "component layer change invalidates exception: "
                f"{finding.rule_id} {finding.package} {finding.installed_version} "
                f"reviewed={exception['component_layer_id']} "
                f"current={finding.component_layer_id}"
            )
        assertion = exception["exposure_assertion"]
        if assertion["kind"] != "whole_image_fingerprint_equals":
            runtime_error = runtime_base_mismatch(finding, baseline["runtime"])
            if runtime_error:
                invalid.append(
                    "runtime base change invalidates exception: "
                    f"{finding.rule_id} {finding.package} "
                    f"{finding.installed_version}: {runtime_error}"
                )
            reviewed_runtime_error = reviewed_runtime_mismatch(
                finding, baseline["runtime"], runtime_config
            )
            if reviewed_runtime_error:
                invalid.append(
                    "reviewed runtime change invalidates exception: "
                    f"{finding.rule_id} {finding.package} "
                    f"{finding.installed_version}: {reviewed_runtime_error}"
                )
        assertion_digest = assertion["definition_digest"]
        assertion_result = assertion_results.get(assertion_digest)
        if assertion_result is None:
            assertion_result = evaluate_exposure_assertion(
                assertion,
                baseline["runtime"],
                oci_layer_ids,
                runtime_config,
                rootfs,
                finding.syft_file_paths,
                finding.syft_file_digests,
            )
            assertion_results[assertion_digest] = assertion_result
        if not assertion_result.evaluable or not assertion_result.passed:
            state = "false" if assertion_result.evaluable else "unevaluable"
            assertion_failures.setdefault(
                assertion_digest, (state, assertion_result)
            )

    for assertion_digest, (state, assertion_result) in assertion_failures.items():
        affected = sorted(
            exception["vulnerability_id"]
            for exception in exceptions
            if exception["exposure_assertion"]["definition_digest"]
            == assertion_digest
        )
        invalid.append(
            f"exposure assertion {state}: affected={affected}: "
            f"{assertion_result.detail}"
        )

    for finding in blocking:
        if finding.fixable:
            if finding.exception_key not in by_key:
                invalid.append(
                    "fixable finding blocks: "
                    f"{finding.rule_id} {finding.package} {finding.installed_version} "
                    f"fixes={list(finding.fix_versions)}"
                )
            continue
        if finding.exception_key not in by_key:
            reviewed_versions = [
                key[2] for key in by_key if key[:2] == finding.advisory_key
            ]
            if reviewed_versions:
                if finding.exception_key not in reported_version_mismatches:
                    invalid.append(
                        "version-mismatched finding: "
                        f"{finding.rule_id} {finding.package} "
                        f"reviewed={reviewed_versions} "
                        f"installed={finding.installed_version}"
                    )
            else:
                invalid.append(
                    "unreviewed blocking finding: "
                    f"{finding.rule_id} {finding.severity} "
                    f"{finding.package} {finding.installed_version}"
                )

    for message in invalid:
        print(message, file=sys.stderr)
    print(
        "advisory baseline: "
        f"grype image={report_image.digest} "
        f"threshold={threshold} findings={len(findings)} blocking={len(blocking)} "
        f"exceptions={len(exceptions)} invalid={len(invalid)}"
    )
    return int(bool(invalid))


def check_zizmor_findings(
    findings: list[Finding], baseline: dict[str, Any], today: dt.date
) -> int:
    threshold = policy_threshold(baseline, "zizmor")
    threshold_rank = severity_rank(threshold)
    blocking = [
        finding
        for finding in findings
        if severity_rank(finding.severity) >= threshold_rank
    ]
    invalid = []
    for finding in blocking:
        invalid.append(f"unreviewed blocking finding: {finding.fingerprint}")
    for message in invalid:
        print(message, file=sys.stderr)
    print(
        "advisory baseline: "
        f"zizmor threshold={threshold} blocking={len(blocking)} invalid={len(invalid)}"
    )
    return int(bool(invalid))


def check_findings(
    tool: str,
    findings: list[Finding],
    baseline: dict[str, Any],
    today: dt.date,
    rootfs: Path | None = None,
    candidate_image_digest: str = "",
    runtime_config: dict[str, Any] | None = None,
    oci_layer_ids: tuple[str, ...] = (),
    report_image: ImageEvidence | None = None,
) -> int:
    if tool == "grype":
        if report_image is None:
            fail("grype checks require report-level image evidence")
        return check_grype_findings(
            findings,
            report_image,
            baseline,
            today,
            rootfs,
            candidate_image_digest,
            runtime_config or {},
            oci_layer_ids,
        )
    return check_zizmor_findings(findings, baseline, today)


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
        "--source-revision",
        help="Full protected source revision used to build the candidate image.",
    )
    parser.add_argument(
        "--candidate-image-digest",
        help="Digest resolved independently for the exact candidate image.",
    )
    parser.add_argument(
        "--oci-config",
        type=Path,
        help="Full OCI image config JSON from the digest-pinned image.",
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
    report_image: ImageEvidence | None = None
    oci_evidence: OciImageConfigEvidence | None = None
    if args.tool == "zizmor":
        if (
            args.syft_report is not None
            or args.rootfs is not None
            or args.source_revision is not None
            or args.candidate_image_digest is not None
            or args.oci_config is not None
        ):
            fail("grype evidence arguments are not valid for zizmor")
        findings = normalize_zizmor(report)
    else:
        if args.syft_report is None:
            fail("grype checks require --syft-report native Syft JSON evidence")
        if args.rootfs is None:
            fail("grype checks require --rootfs candidate filesystem evidence")
        if args.oci_config is None:
            fail("grype checks require --oci-config candidate runtime evidence")
        if (
            args.candidate_image_digest is None
            or SHA256_DIGEST_RE.fullmatch(args.candidate_image_digest) is None
        ):
            fail("grype checks require --candidate-image-digest as sha256")
        if (
            args.source_revision is None
            or GIT_REVISION_RE.fullmatch(args.source_revision) is None
        ):
            fail("grype checks require --source-revision as a full Git revision")
        normalized_grype = normalize_grype(
            report, args.subject, load_json(args.syft_report)
        )
        findings = list(normalized_grype.findings)
        report_image = normalized_grype.image
        oci_evidence = normalize_oci_image_config(
            load_json(args.oci_config), args.source_revision
        )

    if args.dump_blocking_findings:
        threshold_rank = severity_rank(policy_threshold(baseline, args.tool))
        print(
            json.dumps(
                [
                    finding.to_json()
                    for finding in findings
                    if finding_is_blocking(finding, args.tool, threshold_rank)
                ],
                indent=2,
                sort_keys=True,
            )
        )
        return
    raise SystemExit(
        check_findings(
            args.tool,
            findings,
            baseline,
            today,
            args.rootfs,
            args.candidate_image_digest or "",
            oci_evidence.runtime_config if oci_evidence is not None else {},
            oci_evidence.layer_ids if oci_evidence is not None else (),
            report_image,
        )
    )


if __name__ == "__main__":
    main()
