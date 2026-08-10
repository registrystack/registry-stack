#!/usr/bin/env python3
"""Validate Relay V2's aligned SDMX read profile against locked official schemas.

Network access is opt-in. The fetch mode downloads locked official schemas to a
temporary directory, verifies them, validates the supplied outputs, and then
discards the upstream bytes. An external cache supports the same validation
offline. Upstream schema bytes remain outside the repository.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Any

import yaml


PRODUCT_ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = PRODUCT_ROOT / "contracts" / "sdmx-profile-lock.yaml"
SHA256_PREFIX = "sha256:"


class ConformanceFailure(Exception):
    pass


def load_lock() -> dict[str, Any]:
    lock = yaml.safe_load(LOCK_PATH.read_text(encoding="utf-8"))
    if not isinstance(lock, dict):
        raise ConformanceFailure("SDMX profile lock is not a mapping")
    if lock.get("upstreamBytesCommitted") is not False:
        raise ConformanceFailure("upstream SDMX schema bytes must not be committed")
    return lock


def locked_schema(lock: dict[str, Any], profile: str, schema_directory: Path) -> dict[str, Any]:
    try:
        definition = lock["profiles"][profile]["schema"]
        expected = definition["sha256"]
        path = schema_directory / definition["cacheFile"]
    except (KeyError, TypeError) as error:
        raise ConformanceFailure(f"{profile}: schema lock is incomplete") from error
    content = path.read_bytes()
    observed = SHA256_PREFIX + hashlib.sha256(content).hexdigest()
    if observed != expected:
        raise ConformanceFailure(f"{profile}: cached official schema digest differs")
    try:
        schema = json.loads(content)
    except json.JSONDecodeError as error:
        raise ConformanceFailure(f"{profile}: cached official schema is not JSON") from error
    if schema.get("$id") != definition["id"]:
        raise ConformanceFailure(f"{profile}: cached official schema has another $id")
    return schema


def fetch_official_schemas(lock: dict[str, Any], destination: Path) -> None:
    for profile in ("dataJson", "structureJson"):
        try:
            definition = lock["profiles"][profile]["schema"]
            url = definition["url"]
            destination_path = destination / definition["cacheFile"]
        except (KeyError, TypeError) as error:
            raise ConformanceFailure(f"{profile}: schema lock is incomplete") from error
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                content = response.read()
        except OSError as error:
            raise ConformanceFailure(f"{profile}: official schema fetch failed") from error
        destination_path.write_bytes(content)
        locked_schema(lock, profile, destination)


def validator(schema: dict[str, Any]):
    try:
        import jsonschema
    except ModuleNotFoundError as error:
        raise ConformanceFailure(
            "jsonschema is required when validating generated SDMX documents"
        ) from error
    validator_class = jsonschema.validators.validator_for(schema)
    validator_class.check_schema(schema)
    return validator_class(schema, format_checker=validator_class.FORMAT_CHECKER)


def validate_json(path: Path, schema_validator: Any) -> None:
    try:
        document = json.loads(path.read_bytes())
        schema_validator.validate(document)
    except (json.JSONDecodeError, OSError) as error:
        raise ConformanceFailure(f"{path}: SDMX document could not be read") from error
    except Exception as error:
        raise ConformanceFailure(f"{path}: official SDMX schema validation failed") from error


def validate_csv(path: Path) -> None:
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.reader(handle))
    except (OSError, UnicodeError, csv.Error) as error:
        raise ConformanceFailure(f"{path}: SDMX-CSV could not be read") from error
    if not rows or len(rows[0]) < 4 or rows[0][:3] != ["STRUCTURE", "STRUCTURE_ID", "ACTION"]:
        raise ConformanceFailure(f"{path}: SDMX-CSV fixed columns are missing")
    if any(len(row) != len(rows[0]) for row in rows[1:]):
        raise ConformanceFailure(f"{path}: SDMX-CSV rows are not rectangular")


def package_structures(package: Path, suffixes: dict[str, str]) -> list[Path]:
    generated = package / "generated" / "artifacts"
    dataflows = {
        path.name.removesuffix(suffixes["dataflow"]): path
        for path in generated.glob(f"*{suffixes['dataflow']}")
    }
    structures = {
        path.name.removesuffix(suffixes["datastructure"]): path
        for path in generated.glob(f"*{suffixes['datastructure']}")
    }
    if not dataflows or dataflows.keys() != structures.keys():
        raise ConformanceFailure(
            "package must contain exactly paired dataflow and datastructure artifacts"
        )
    return sorted([*dataflows.values(), *structures.values()])


def validate_lock_shape(lock: dict[str, Any]) -> None:
    profiles = lock.get("profiles")
    if not isinstance(profiles, dict) or set(profiles) != {
        "rest",
        "dataJson",
        "dataCsv",
        "structureJson",
    }:
        raise ConformanceFailure("SDMX profiles are not closed")
    if profiles["rest"].get("version") != "2.2.2":
        raise ConformanceFailure("SDMX REST subset must remain 2.2.2")
    for name in ("dataJson", "dataCsv", "structureJson"):
        if profiles[name].get("version") != "2.1.0":
            raise ConformanceFailure(f"{name}: format version must remain 2.1.0")
    for name in ("dataJson", "structureJson"):
        digest = profiles[name].get("schema", {}).get("sha256", "")
        if not isinstance(digest, str) or len(digest) != 71 or not digest.startswith(SHA256_PREFIX):
            raise ConformanceFailure(f"{name}: official schema digest is invalid")
    cache_names = {
        profiles[name]["schema"]["cacheFile"] for name in ("dataJson", "structureJson")
    }
    tracked_json = [path for path in PRODUCT_ROOT.rglob("*.json") if path.is_file()]
    tracked_names = {path.name for path in tracked_json}
    locked_digests = {
        profiles[name]["schema"]["sha256"] for name in ("dataJson", "structureJson")
    }
    tracked_digests = {
        SHA256_PREFIX + hashlib.sha256(path.read_bytes()).hexdigest()
        for path in tracked_json
    }
    if cache_names & tracked_names or locked_digests & tracked_digests:
        raise ConformanceFailure("upstream SDMX schema bytes are tracked in the product")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", type=Path)
    schema_source = parser.add_mutually_exclusive_group()
    schema_source.add_argument("--schema-cache", type=Path)
    schema_source.add_argument("--fetch-official-schemas", action="store_true")
    parser.add_argument("--data-json", action="append", type=Path, default=[])
    parser.add_argument("--data-csv", action="append", type=Path, default=[])
    parser.add_argument("--structure-json", action="append", type=Path, default=[])
    args = parser.parse_args()
    try:
        lock = load_lock()
        validate_lock_shape(lock)
        requested = bool(args.package or args.data_json or args.data_csv or args.structure_json)
        if args.fetch_official_schemas and not requested:
            raise ConformanceFailure("official schemas are fetched only when outputs are supplied")
        if requested:
            with tempfile.TemporaryDirectory(prefix="relay-v2-sdmx-profile-") as temporary:
                schema_directory = Path(temporary)
                if args.fetch_official_schemas:
                    fetch_official_schemas(lock, schema_directory)
                else:
                    cache = args.schema_cache
                    if cache is None:
                        configured = os.environ.get(
                            lock["validation"]["schemaCacheEnvironment"]
                        )
                        cache = Path(configured) if configured else None
                    if cache is None:
                        raise ConformanceFailure(
                            "use --fetch-official-schemas or provide an external SDMX schema cache"
                        )
                    schema_directory = cache
                data_validator = validator(locked_schema(lock, "dataJson", schema_directory))
                structure_validator = validator(
                    locked_schema(lock, "structureJson", schema_directory)
                )
                structure_paths = list(args.structure_json)
                if args.package:
                    structure_paths.extend(
                        package_structures(
                            args.package,
                            lock["validation"]["packageArtifactSuffixes"],
                        )
                    )
                for path in args.data_json:
                    validate_json(path, data_validator)
                for path in structure_paths:
                    validate_json(path, structure_validator)
                for path in args.data_csv:
                    validate_csv(path)
    except (ConformanceFailure, OSError, KeyError, TypeError, yaml.YAMLError) as error:
        print(f"relay-v2 SDMX profile validation: {error}", file=sys.stderr)
        return 1
    print("relay-v2 aligned SDMX read profile validation passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
