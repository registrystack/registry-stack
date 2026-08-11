#!/usr/bin/env python3
"""Validate additive compatibility for released errors and selected metrics."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
METRICS_CONTRACT = Path("release/contracts/selected-metrics.json")
ERROR_REFERENCE = Path("docs/site/src/content/docs/reference/errors.mdx")
MAINTAINED_RELEASE_PRODUCTS = frozenset({"registry-relay"})
HISTORICAL_RELEASE_PRODUCTS = frozenset({"registry-notary"})
KNOWN_RELEASE_PRODUCTS = MAINTAINED_RELEASE_PRODUCTS | HISTORICAL_RELEASE_PRODUCTS

# v0.19.0 replaced the configuration-driven Relay 1.0 runtime with the
# contract-compiled Relay V2 runtime and retired `registryctl` alongside it.
# That release removed three published surfaces this check used to guard, so
# each removal is recorded here rather than in a commit message a reader of
# this file will not see.
#
# 1. The Relay 1.0 error taxonomy. Relay V2 answers with a closed RFC 9457
#    problem set that shares no code with it, so the error reference changed
#    both its section heading and its columns. `parse_error_registry` reads the
#    V2 problem table. A base ref written before the cutover is recognized by
#    its `## Registry Relay` heading and reported as out of scope, rather than
#    parsed as a wholesale regression.
# 2. The Relay 1.0 Prometheus families. Relay V2 exposes no metrics endpoint,
#    so the selected-metrics contract carries no family and each retired one is
#    named in RETIRED_SELECTED_METRICS below.
# 3. The `registryctl` diagnostic catalogs. The retired tool generated them
#    into `docs/site/public/generated/diagnostics/`, and nothing produces them
#    now. The catalog guard is removed with its producer. It belongs back in
#    this file when `relayctl` gains machine-readable introspection.
RELAY_V1_METRIC_RETIREMENT = (
    "Emitted by the configuration-driven Relay 1.0 runtime, which v0.19.0 "
    "replaced. Relay V2 exposes no metrics endpoint, so no maintained binary "
    "can emit this family. A future family that reuses the name is guarded "
    "again from the release that introduces it."
)
# Families a released contract carried and no maintained product now emits.
# Keyed by the exact (product, name) so the exemption reaches one family and
# never the product's other families, which stay guarded.
RETIRED_SELECTED_METRICS: dict[tuple[str, str], str] = {
    ("registry-relay", "registry_relay_http_requests_total"): RELAY_V1_METRIC_RETIREMENT,
    (
        "registry-relay",
        "registry_relay_http_request_duration_seconds",
    ): RELAY_V1_METRIC_RETIREMENT,
    ("registry-relay", "registry_relay_readiness_ready_resources"): RELAY_V1_METRIC_RETIREMENT,
    (
        "registry-relay",
        "registry_relay_readiness_not_ready_resources",
    ): RELAY_V1_METRIC_RETIREMENT,
    ("registry-relay", "registry_relay_readiness_failed_resources"): RELAY_V1_METRIC_RETIREMENT,
    (
        "registry-relay",
        "registry_relay_readiness_unresolved_entities",
    ): RELAY_V1_METRIC_RETIREMENT,
    ("registry-relay", "registry_relay_readiness_fully_ready"): RELAY_V1_METRIC_RETIREMENT,
    (
        "registry-relay",
        "registry_relay_ingest_consecutive_refresh_failures",
    ): RELAY_V1_METRIC_RETIREMENT,
    (
        "registry-relay",
        "registry_relay_ingest_last_successful_refresh_timestamp_seconds",
    ): RELAY_V1_METRIC_RETIREMENT,
}

# Relay codes carry hyphens as well as underscores (`aggregate-data.denied`).
MACHINE_CODE = re.compile(r"^[a-z][a-z0-9_-]*(?:\.[a-z0-9_-]+)+$")
RELAY_ERROR_SECTION = "## Relay"
LEGACY_RELAY_ERROR_SECTION = "## Registry Relay"
PROBLEM_TABLE_HEADER = "| Code | Status | Title | Detail |"
PROBLEM_ROW = re.compile(r"^\| `([^`]+)` \| ([1-5][0-9]{2}) \| ([^|]+) \| ([^|]+) \|\s*$")


class ContractError(ValueError):
    """A stable-surface contract is invalid or incompatible."""


@dataclass(frozen=True)
class ErrorContract:
    status: int
    title: str
    detail: str


def is_legacy_error_registry(text: str) -> bool:
    """Report the Relay 1.0 error reference that v0.19.0 retired.

    The pre-cutover page grouped codes under a per-product heading and carried a
    `Code | Meaning | Cause` table. Reading it with the V2 parser would find
    nothing, so a base ref that still carries it is out of scope for comparison
    rather than a page that lost every code.
    """
    return any(line == LEGACY_RELAY_ERROR_SECTION for line in text.splitlines())


def parse_error_registry(text: str) -> dict[str, ErrorContract]:
    """Read the closed problem set from the Relay section's problem table.

    Only that one table is a released contract. The response-shape table above
    it describes members rather than codes, and the sections for Evidence
    Gateway and Registry Mint point at the pages that carry their sets under
    their own gates.
    """
    in_relay_section = False
    in_problem_table = False
    entries: dict[str, ErrorContract] = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        if line.startswith("## "):
            in_relay_section = line == RELAY_ERROR_SECTION
            in_problem_table = False
            continue
        if not in_relay_section:
            continue
        if line == PROBLEM_TABLE_HEADER:
            in_problem_table = True
            continue
        if not in_problem_table:
            continue
        if not line.startswith("|"):
            in_problem_table = False
            continue
        if line.startswith("| ---"):
            continue
        match = PROBLEM_ROW.match(line)
        if match is None:
            raise ContractError(
                f"malformed problem row at error reference line {line_number}: {line}"
            )
        code, status, title, detail = match.groups()
        if MACHINE_CODE.fullmatch(code) is None:
            raise ContractError(
                f"{code!r} at error reference line {line_number} is not a machine code"
            )
        title = title.strip()
        detail = detail.strip()
        if not title or not detail:
            raise ContractError(f"empty title or detail for {code} at line {line_number}")
        if code in entries:
            raise ContractError(f"{code} is documented more than once")
        entries[code] = ErrorContract(int(status), title, detail)

    if not entries:
        raise ContractError("error reference contains no maintained Relay problem codes")
    return entries


def compare_error_contracts(
    base: dict[str, ErrorContract], current: dict[str, ErrorContract]
) -> list[str]:
    errors: list[str] = []
    for code, old in sorted(base.items()):
        new = current.get(code)
        if new is None:
            errors.append(f"released error code removed: {code}")
            continue
        for field in ("status", "title", "detail"):
            if getattr(new, field) != getattr(old, field):
                errors.append(
                    f"released error {code} changed {field}: "
                    f"{getattr(old, field)!r} -> {getattr(new, field)!r}"
                )
    return errors


def load_json(text: str, label: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError as error:
        raise ContractError(f"{label} is not valid JSON: {error}") from error


def validate_metrics_contract(data: Any, root: Path = ROOT) -> dict[tuple[str, str], dict[str, Any]]:
    if not isinstance(data, dict):
        raise ContractError("selected metrics contract must be an object")
    if data.get("schema") != "registry-stack.selected-metrics/v1":
        raise ContractError("selected metrics contract has an unsupported schema")
    if data.get("release_line") != 1:
        raise ContractError("selected metrics contract must target release line 1")
    metrics = data.get("metrics")
    if not isinstance(metrics, list):
        raise ContractError("selected metrics contract must contain a metrics list")

    result: dict[tuple[str, str], dict[str, Any]] = {}
    allowed = {"product", "name", "type", "meaning", "labels", "source"}
    for index, metric in enumerate(metrics):
        label = f"metrics[{index}]"
        if not isinstance(metric, dict) or set(metric) != allowed:
            raise ContractError(f"{label} must contain exactly {', '.join(sorted(allowed))}")
        product = metric["product"]
        name = metric["name"]
        metric_type = metric["type"]
        meaning = metric["meaning"]
        labels = metric["labels"]
        source = metric["source"]
        if product not in MAINTAINED_RELEASE_PRODUCTS:
            raise ContractError(f"{label}.product is not a maintained product")
        if not isinstance(name, str) or re.fullmatch(r"[a-z_:][a-z0-9_:]*", name) is None:
            raise ContractError(f"{label}.name is not a Prometheus metric name")
        if metric_type not in {"counter", "gauge", "histogram", "summary", "untyped"}:
            raise ContractError(f"{label}.type is not a Prometheus metric type")
        if not isinstance(meaning, str) or not meaning.strip():
            raise ContractError(f"{label}.meaning must be non-empty")
        if not isinstance(labels, dict) or any(
            not isinstance(key, str)
            or re.fullmatch(r"[a-z_][a-z0-9_]*", key) is None
            or not isinstance(value, str)
            or not value.strip()
            for key, value in labels.items()
        ):
            raise ContractError(f"{label}.labels must map label names to non-empty meanings")
        if not isinstance(source, str) or Path(source).is_absolute() or ".." in Path(source).parts:
            raise ContractError(f"{label}.source must be a repository-relative path")

        key = (product, name)
        if key in RETIRED_SELECTED_METRICS:
            raise ContractError(f"{label} is recorded as retired and cannot also be current")

        source_path = root / source
        if not source_path.is_file():
            raise ContractError(f"{label}.source does not exist: {source}")
        source_text = source_path.read_text(encoding="utf-8")
        type_declaration = f"# TYPE {name} {metric_type}"
        if type_declaration not in source_text:
            raise ContractError(f"{source} does not declare {type_declaration}")
        for label_name in labels:
            if f'{label_name}=\\"' not in source_text:
                raise ContractError(
                    f"{source} does not emit selected label {label_name!r} for {name}"
                )

        if key in result:
            raise ContractError(f"duplicate selected metric: {product} {name}")
        result[key] = metric
    return result


def compare_metrics_contracts(
    base: dict[tuple[str, str], dict[str, Any]],
    current: dict[tuple[str, str], dict[str, Any]],
) -> list[str]:
    errors: list[str] = []
    protected = ("type", "meaning", "labels")
    for key, old in sorted(base.items()):
        new = current.get(key)
        product, name = key
        if product in HISTORICAL_RELEASE_PRODUCTS or key in RETIRED_SELECTED_METRICS:
            continue
        if new is None:
            errors.append(f"selected metric removed: {product} {name}")
            continue
        for field in protected:
            if new[field] != old[field]:
                errors.append(
                    f"selected metric {product} {name} changed {field}: "
                    f"{old[field]!r} -> {new[field]!r}"
                )
    return errors


def verify_error_codes_have_source(
    errors: dict[str, ErrorContract], root: Path = ROOT
) -> list[str]:
    source_parts: list[str] = []
    for crate_root in (root / "crates").glob("registry-*"):
        if not crate_root.is_dir():
            continue
        for path in crate_root.rglob("*.rs"):
            source_parts.append(path.read_text(encoding="utf-8"))
    source = "\n".join(source_parts)
    return [
        f"documented error code has no Rust source literal: {code}"
        for code in sorted(errors)
        if f'"{code}"' not in source
    ]


def git_show(ref: str, path: Path, root: Path = ROOT) -> str | None:
    completed = subprocess.run(
        ["git", "show", f"{ref}:{path.as_posix()}"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode == 0:
        return completed.stdout
    return None


def valid_git_ref(ref: str, root: Path = ROOT) -> bool:
    if not ref or set(ref) == {"0"}:
        return False
    completed = subprocess.run(
        ["git", "rev-parse", "--verify", f"{ref}^{{commit}}"],
        cwd=root,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return completed.returncode == 0


def check(base_ref: str | None, root: Path = ROOT) -> list[str]:
    current_errors = parse_error_registry((root / ERROR_REFERENCE).read_text(encoding="utf-8"))
    errors = verify_error_codes_have_source(current_errors, root)
    current_metrics_data = load_json(
        (root / METRICS_CONTRACT).read_text(encoding="utf-8"), str(METRICS_CONTRACT)
    )
    current_metrics = validate_metrics_contract(current_metrics_data, root)

    if not base_ref:
        return errors
    if not valid_git_ref(base_ref, root):
        errors.append(f"stable-surface base ref is not available: {base_ref}")
        return errors

    base_metrics_text = git_show(base_ref, METRICS_CONTRACT, root)
    if base_metrics_text is None:
        print(
            f"stable-surface contract did not exist at {base_ref}; validated bootstrap contract",
            file=sys.stderr,
        )
        return errors

    base_metrics_data = load_json(base_metrics_text, f"{base_ref}:{METRICS_CONTRACT}")
    # Validate shape without requiring base sources to exist in the current tree.
    base_metrics = _validate_metrics_shape_only(base_metrics_data)
    errors.extend(compare_metrics_contracts(base_metrics, current_metrics))

    base_errors_text = git_show(base_ref, ERROR_REFERENCE, root)
    if base_errors_text is None:
        errors.append(f"base ref lacks released error registry: {ERROR_REFERENCE}")
    elif is_legacy_error_registry(base_errors_text):
        print(
            f"{base_ref} carries the Relay 1.0 error reference that v0.19.0 retired; "
            "validated the current problem set against no baseline",
            file=sys.stderr,
        )
    else:
        errors.extend(compare_error_contracts(parse_error_registry(base_errors_text), current_errors))
    return errors


def _validate_metrics_shape_only(data: Any) -> dict[tuple[str, str], dict[str, Any]]:
    if not isinstance(data, dict) or data.get("schema") != "registry-stack.selected-metrics/v1":
        raise ContractError("base selected metrics contract has an unsupported schema")
    if data.get("release_line") != 1:
        raise ContractError("base selected metrics contract must target release line 1")
    metrics = data.get("metrics")
    if not isinstance(metrics, list):
        raise ContractError("base selected metrics contract has no metrics list")
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for index, metric in enumerate(metrics):
        label = f"base metrics[{index}]"
        if not isinstance(metric, dict):
            raise ContractError(f"{label} is not an object")
        try:
            product = metric["product"]
            name = metric["name"]
            for field in ("type", "meaning", "labels"):
                metric[field]
        except (KeyError, TypeError) as error:
            raise ContractError(f"{label} is missing a protected field") from error
        if product not in KNOWN_RELEASE_PRODUCTS:
            raise ContractError(f"{label}.product is not a released product")
        if not isinstance(name, str) or re.fullmatch(r"[a-z_:][a-z0-9_:]*", name) is None:
            raise ContractError(f"{label}.name is not a Prometheus metric name")
        if metric["type"] not in {"counter", "gauge", "histogram", "summary", "untyped"}:
            raise ContractError(f"{label}.type is not a Prometheus metric type")
        if not isinstance(metric["meaning"], str) or not metric["meaning"].strip():
            raise ContractError(f"{label}.meaning must be non-empty")
        if not isinstance(metric["labels"], dict):
            raise ContractError(f"{label}.labels must be an object")
        key = (product, name)
        if key in result:
            raise ContractError(f"duplicate base selected metric: {product} {name}")
        result[key] = metric
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-ref",
        default=os.environ.get("STABLE_SURFACE_BASE_REF"),
        help="Git commit to compare against; omit for current-contract validation only",
    )
    args = parser.parse_args()
    try:
        errors = check(args.base_ref)
    except (ContractError, OSError, KeyError, TypeError) as error:
        print(f"stable-surface compatibility check failed: {error}", file=sys.stderr)
        return 1
    if errors:
        print("stable-surface compatibility check failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("stable-surface compatibility check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
