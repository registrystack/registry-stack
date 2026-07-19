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
OPENAPI_SPECS = {
    "registry-relay": Path("crates/registry-relay/openapi/registry-relay.openapi.json"),
    "registry-notary": Path("products/notary/openapi/registry-notary.openapi.json"),
}
MACHINE_CODE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+$")
ERROR_ROW = re.compile(r"^\| `([^`]+)` \| ([^|]+) \|")
HTTP_METHODS = {"delete", "get", "head", "options", "patch", "post", "put", "trace"}


class ContractError(ValueError):
    """A stable-surface contract is invalid or incompatible."""


@dataclass(frozen=True)
class ErrorContract:
    meaning: str
    products: frozenset[str]


def parse_error_registry(text: str) -> dict[str, ErrorContract]:
    product: str | None = None
    entries: dict[str, tuple[str, set[str]]] = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        if line == "## Registry Notary":
            product = "registry-notary"
            continue
        if line == "## Registry Relay":
            product = "registry-relay"
            continue
        if line.startswith("## "):
            product = None
            continue
        match = ERROR_ROW.match(line)
        if match is None or product is None:
            continue
        code, meaning = match.groups()
        if MACHINE_CODE.fullmatch(code) is None:
            continue
        meaning = meaning.strip()
        if not meaning:
            raise ContractError(f"empty meaning for {code} at error reference line {line_number}")
        if code in entries and entries[code][0] != meaning:
            raise ContractError(
                f"{code} has more than one stack-wide meaning: "
                f"{entries[code][0]!r} and {meaning!r}"
            )
        entries.setdefault(code, (meaning, set()))[1].add(product)

    if not entries:
        raise ContractError("error reference contains no Registry Relay or Registry Notary codes")
    return {
        code: ErrorContract(meaning, frozenset(products))
        for code, (meaning, products) in entries.items()
    }


def compare_error_contracts(
    base: dict[str, ErrorContract], current: dict[str, ErrorContract]
) -> list[str]:
    errors: list[str] = []
    for code, old in sorted(base.items()):
        new = current.get(code)
        if new is None:
            errors.append(f"released error code removed: {code}")
            continue
        if new.meaning != old.meaning:
            errors.append(
                f"released error meaning changed for {code}: {old.meaning!r} -> {new.meaning!r}"
            )
        removed_products = old.products - new.products
        if removed_products:
            errors.append(
                f"released error code {code} removed from: {', '.join(sorted(removed_products))}"
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
    if not isinstance(metrics, list) or not metrics:
        raise ContractError("selected metrics contract must contain a non-empty metrics list")

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
        if product not in {"registry-relay", "registry-notary"}:
            raise ContractError(f"{label}.product is not a released product")
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

        key = (product, name)
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
    for path in OPENAPI_SPECS.values():
        source_parts.append((root / path).read_text(encoding="utf-8"))
    source = "\n".join(source_parts)
    return [
        f"documented error code has no Rust or OpenAPI source literal: {code}"
        for code in sorted(errors)
        if f'"{code}"' not in source
    ]


def _resolve_local_ref(document: Any, ref: str) -> Any:
    value = document
    for raw_segment in ref[2:].split("/"):
        segment = raw_segment.replace("~1", "/").replace("~0", "~")
        value = value[segment]
    return value


def _codes_in_openapi(value: Any, document: Any, seen: frozenset[str] = frozenset()) -> set[str]:
    if isinstance(value, dict):
        ref = value.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/"):
            if ref in seen:
                return set()
            return _codes_in_openapi(_resolve_local_ref(document, ref), document, seen | {ref})
        found: set[str] = set()
        for key, nested in value.items():
            if key == "code" and isinstance(nested, str) and MACHINE_CODE.fullmatch(nested):
                found.add(nested)
            found.update(_codes_in_openapi(nested, document, seen))
        return found
    if isinstance(value, list):
        found: set[str] = set()
        for nested in value:
            found.update(_codes_in_openapi(nested, document, seen))
        return found
    return set()


def openapi_error_mappings(document: Any, product: str) -> set[tuple[str, str, str, str, str]]:
    mappings: set[tuple[str, str, str, str, str]] = set()
    if not isinstance(document, dict) or not isinstance(document.get("paths"), dict):
        raise ContractError(f"{product} OpenAPI document does not contain paths")
    for path, path_item in document["paths"].items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            responses = operation.get("responses", {})
            if not isinstance(responses, dict):
                continue
            for status, response in responses.items():
                for code in _codes_in_openapi(response, document):
                    mappings.add((product, method.upper(), path, str(status), code))
    return mappings


def compare_openapi_mappings(
    base: set[tuple[str, str, str, str, str]],
    current: set[tuple[str, str, str, str, str]],
) -> list[str]:
    return [
        "documented error mapping removed or changed: " + " ".join(mapping)
        for mapping in sorted(base - current)
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
    current_mappings: set[tuple[str, str, str, str, str]] = set()
    for product, path in OPENAPI_SPECS.items():
        document = load_json((root / path).read_text(encoding="utf-8"), str(path))
        current_mappings.update(openapi_error_mappings(document, product))

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
    else:
        errors.extend(compare_error_contracts(parse_error_registry(base_errors_text), current_errors))

    base_mappings: set[tuple[str, str, str, str, str]] = set()
    for product, path in OPENAPI_SPECS.items():
        base_text = git_show(base_ref, path, root)
        if base_text is None:
            continue
        base_mappings.update(openapi_error_mappings(load_json(base_text, f"{base_ref}:{path}"), product))
    errors.extend(compare_openapi_mappings(base_mappings, current_mappings))
    return errors


def _validate_metrics_shape_only(data: Any) -> dict[tuple[str, str], dict[str, Any]]:
    if not isinstance(data, dict) or data.get("schema") != "registry-stack.selected-metrics/v1":
        raise ContractError("base selected metrics contract has an unsupported schema")
    if data.get("release_line") != 1:
        raise ContractError("base selected metrics contract must target release line 1")
    metrics = data.get("metrics")
    if not isinstance(metrics, list) or not metrics:
        raise ContractError("base selected metrics contract has no non-empty metrics list")
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
        if product not in {"registry-relay", "registry-notary"}:
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
