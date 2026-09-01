#!/usr/bin/env python3

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any


BASE_URL = "https://id.registrystack.org"
REPO_ROOT = Path(__file__).resolve().parents[3]
PRODUCT_ROOT = REPO_ROOT / "products" / "identifiers"
SOURCE_CONFIG = PRODUCT_ROOT / "contracts" / "catalog-source.json"
GENERATED_CATALOG = PRODUCT_ROOT / "generated" / "catalog.v1.json"
GENERATED_AUDIT_SCHEMA = (
    PRODUCT_ROOT
    / "generated"
    / "artifacts"
    / "registry-relay"
    / "audit-event"
    / "v2alpha1.json"
)
REFERENCE_URI_RE = re.compile(
    r"https://id\.registrystack\.org/[^\s<>{}\"'`\\]+"
)
REFERENCE_TEMPLATES = {
    f"{BASE_URL}/",
    f"{BASE_URL}/problems/...",
    f"{BASE_URL}/problems/..",
    f"{BASE_URL}/problems/",
    f"{BASE_URL}/schemas/",
}


class CatalogError(ValueError):
    pass


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CatalogError(f"could not read JSON {path}: {error}") from error


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def relative_path(repo_root: Path, path: Path) -> str:
    try:
        return path.relative_to(repo_root).as_posix()
    except ValueError as error:
        raise CatalogError(f"source path is outside the repository: {path}") from error


def source_record(repo_root: Path, path: Path) -> dict[str, str]:
    if not path.is_file():
        raise CatalogError(f"catalog source does not exist: {path}")
    return {"path": relative_path(repo_root, path), "sha256": sha256(path)}


def repository_files(repo_root: Path) -> tuple[Path, ...]:
    result = subprocess.run(
        ["git", "-C", str(repo_root), "ls-files", "-z"],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise CatalogError(f"could not enumerate tracked repository files: {message}")
    try:
        relative_paths = [
            value.decode("utf-8")
            for value in result.stdout.split(b"\0")
            if value
        ]
    except UnicodeDecodeError as error:
        raise CatalogError("tracked repository path is not valid UTF-8") from error
    return tuple(
        path
        for relative in relative_paths
        if (path := repo_root / relative).is_file()
    )


def load_source_config(config_path: Path) -> dict[str, Any]:
    config = read_json(config_path)
    if not isinstance(config, dict) or set(config) != {
        "version",
        "baseUrl",
        "problemSources",
        "referenceExclusions",
        "schemaSources",
        "records",
    }:
        raise CatalogError("catalog source has an invalid top-level shape")
    if config["version"] != 1 or config["baseUrl"] != BASE_URL:
        raise CatalogError("catalog source version or base URL is invalid")
    if (
        not isinstance(config["problemSources"], list)
        or not isinstance(config["referenceExclusions"], list)
        or not isinstance(config["schemaSources"], list)
        or not isinstance(config["records"], list)
    ):
        raise CatalogError("catalog source lists are invalid")
    problem_source_fields = {
        "owner",
        "status",
        "compatibilityLine",
        "uriPrefix",
        "sourcePath",
        "exporterPath",
        "cargoPackage",
        "cargoExample",
    }
    for index, source in enumerate(config["problemSources"]):
        if not isinstance(source, dict) or set(source) != problem_source_fields:
            raise CatalogError(f"problemSources[{index}] has an invalid shape")
        if not all(
            isinstance(source[field], str) and source[field].strip()
            for field in problem_source_fields
        ):
            raise CatalogError(f"problemSources[{index}] has a blank value")
        if source["status"] != "active":
            raise CatalogError(f"problemSources[{index}] has an invalid status")
        if not source["uriPrefix"].startswith(f"{BASE_URL}/problems/") or not source[
            "uriPrefix"
        ].endswith("/"):
            raise CatalogError(f"problemSources[{index}] has an invalid URI prefix")
    for index, exclusion in enumerate(config["referenceExclusions"]):
        if not isinstance(exclusion, dict) or set(exclusion) != {
            "glob",
            "classification",
            "reason",
        }:
            raise CatalogError(
                f"referenceExclusions[{index}] has an invalid shape"
            )
        if not all(
            isinstance(exclusion[key], str) and exclusion[key].strip()
            for key in ("glob", "classification", "reason")
        ):
            raise CatalogError(
                f"referenceExclusions[{index}] has a blank value"
            )
    return config


def path_is_excluded(
    repo_root: Path, path: Path, exclusions: list[dict[str, str]]
) -> bool:
    relative = relative_path(repo_root, path)
    return any(fnmatch.fnmatch(relative, exclusion["glob"]) for exclusion in exclusions)


def validate_reference_exclusions(
    repo_root: Path,
    repository_paths: tuple[Path, ...],
    exclusions: list[dict[str, str]],
) -> None:
    relative_paths = [relative_path(repo_root, path) for path in repository_paths]
    for index, exclusion in enumerate(exclusions):
        if not any(
            fnmatch.fnmatch(relative, exclusion["glob"])
            for relative in relative_paths
        ):
            raise CatalogError(
                f"referenceExclusions[{index}] matched no tracked files: "
                f"{exclusion['glob']}"
            )


def public_schema_files(
    repo_root: Path,
    repository_paths: tuple[Path, ...],
    exclusions: list[dict[str, str]],
) -> dict[str, Path]:
    found: dict[str, Path] = {}
    for path in repository_paths:
        if path.suffix != ".json":
            continue
        if path_is_excluded(repo_root, path, exclusions):
            continue
        try:
            document = read_json(path)
        except CatalogError:
            continue
        if not isinstance(document, dict):
            continue
        uri = document.get("$id")
        if not isinstance(uri, str) or not uri.startswith(f"{BASE_URL}/"):
            continue
        if uri in found:
            raise CatalogError(
                "public schema identifier is duplicated by "
                f"{relative_path(repo_root, found[uri])} and "
                f"{relative_path(repo_root, path)}: {uri}"
            )
        found[uri] = path
    return found


def schema_entries(
    repo_root: Path,
    groups: list[dict[str, Any]],
    repository_paths: tuple[Path, ...],
    exclusions: list[dict[str, str]],
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    covered_paths: set[Path] = set()
    for index, group in enumerate(groups):
        required = {
            "glob",
            "owner",
            "status",
            "compatibilityLine",
            "description",
        }
        keys = set(group) if isinstance(group, dict) else set()
        if (
            not isinstance(group, dict)
            or keys not in (required, required | {"sourcePath"})
        ):
            raise CatalogError(f"schemaSources[{index}] has an invalid shape")
        if group["status"] != "active":
            raise CatalogError(f"schemaSources[{index}] has an invalid status")
        if not isinstance(group["compatibilityLine"], str) or not group[
            "compatibilityLine"
        ].strip():
            raise CatalogError(
                f"schemaSources[{index}] has an invalid compatibility line"
            )
        matched = sorted(
            path
            for path in repository_paths
            if fnmatch.fnmatch(relative_path(repo_root, path), group["glob"])
        )
        if not matched:
            raise CatalogError(f"schema source glob matched no files: {group['glob']}")
        for path in matched:
            if path in covered_paths:
                raise CatalogError(
                    f"schema source belongs to multiple groups: {relative_path(repo_root, path)}"
                )
            document = read_json(path)
            uri = document.get("$id") if isinstance(document, dict) else None
            if not isinstance(uri, str) or not uri.startswith(f"{BASE_URL}/"):
                continue
            covered_paths.add(path)
            digest = sha256(path)
            source_path = (
                repo_root / group["sourcePath"]
                if "sourcePath" in group
                else path
            )
            entries.append(
                {
                    "uri": uri,
                    "kind": "schema",
                    "status": group["status"],
                    "compatibilityLine": group["compatibilityLine"],
                    "owner": group["owner"],
                    "title": document.get("title")
                    or f"Registry Stack JSON Schema: {path.name}",
                    "description": group["description"],
                    "source": source_record(repo_root, source_path),
                    "artifact": {
                        "path": relative_path(repo_root, path),
                        "sha256": digest,
                        "mediaType": "application/schema+json",
                    },
                }
            )

    all_public = public_schema_files(repo_root, repository_paths, exclusions)
    covered_uris = {entry["uri"] for entry in entries}
    missing = sorted(set(all_public) - covered_uris)
    if missing:
        paths = [relative_path(repo_root, all_public[uri]) for uri in missing]
        raise CatalogError(f"public schemas are outside the closed source groups: {paths}")
    return entries


def explicit_entries(
    repo_root: Path, records: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    required = {
        "uri",
        "kind",
        "status",
        "compatibilityLine",
        "owner",
        "title",
        "description",
        "sourcePath",
    }
    for index, record in enumerate(records):
        keys = set(record) if isinstance(record, dict) else set()
        if not isinstance(record, dict) or keys not in (
            required,
            required | {"artifactPath", "mediaType"},
        ):
            raise CatalogError(f"records[{index}] has an invalid shape")
        has_artifact = "artifactPath" in record
        if has_artifact != ("mediaType" in record):
            raise CatalogError(f"records[{index}] has an incomplete artifact")
        source_path = repo_root / record["sourcePath"]
        entry = {
            "uri": record["uri"],
            "kind": record["kind"],
            "status": record["status"],
            "compatibilityLine": record["compatibilityLine"],
            "owner": record["owner"],
            "title": record["title"],
            "description": record["description"],
            "source": source_record(repo_root, source_path),
        }
        if has_artifact:
            artifact_path = repo_root / record["artifactPath"]
            if not isinstance(record["mediaType"], str) or not record["mediaType"]:
                raise CatalogError(f"records[{index}] has an invalid artifact media type")
            entry["artifact"] = {
                "path": relative_path(repo_root, artifact_path),
                "sha256": sha256(artifact_path),
                "mediaType": record["mediaType"],
            }
        entries.append(entry)
    return entries


def problem_entries(
    repo_root: Path, source_config: dict[str, str], problem_catalog_path: Path
) -> list[dict[str, Any]]:
    catalog = read_json(problem_catalog_path)
    raw_entries = catalog.get("entries") if isinstance(catalog, dict) else None
    if not isinstance(raw_entries, list) or not raw_entries:
        raise CatalogError(f"{source_config['owner']} problem catalog has no entries")
    source = source_record(repo_root, repo_root / source_config["sourcePath"])
    entries: list[dict[str, Any]] = []
    expected = {"uri", "code", "title", "description", "httpStatuses"}
    for index, entry in enumerate(raw_entries):
        if not isinstance(entry, dict) or set(entry) != expected:
            raise CatalogError(
                f"{source_config['owner']} problem entry {index} has an invalid shape"
            )
        if entry["uri"] != source_config["uriPrefix"] + entry["code"].replace(".", "/"):
            raise CatalogError(
                f"{source_config['owner']} problem URI and code disagree: {entry}"
            )
        entries.append(
            {
                "uri": entry["uri"],
                "kind": "problem",
                "status": source_config["status"],
                "compatibilityLine": source_config["compatibilityLine"],
                "owner": source_config["owner"],
                "title": entry["title"],
                "description": entry["description"],
                "source": source,
                "problem": {
                    "code": entry["code"],
                    "httpStatuses": entry["httpStatuses"],
                },
            }
        )
    return entries


def validate_entries(repo_root: Path, entries: list[dict[str, Any]]) -> None:
    seen: dict[str, str] = {}
    for entry in entries:
        uri = entry["uri"]
        if not isinstance(uri, str) or not uri.startswith(f"{BASE_URL}/"):
            raise CatalogError(f"identifier is outside the Registry Stack domain: {uri}")
        if uri in seen:
            raise CatalogError(
                f"identifier is duplicated by {seen[uri]} and {entry['source']['path']}: {uri}"
            )
        seen[uri] = entry["source"]["path"]
        if entry["kind"] not in {
            "problem",
            "profile",
            "schema",
            "context",
            "namespace",
            "vocabulary",
            "vocabulary-term",
        }:
            raise CatalogError(f"identifier has an invalid kind: {entry}")
        if entry["status"] != "active":
            raise CatalogError(f"identifier has an invalid status: {entry}")
        if not isinstance(entry.get("compatibilityLine"), str) or not entry[
            "compatibilityLine"
        ].strip():
            raise CatalogError(
                f"identifier has an invalid compatibility line: {entry}"
            )
        source_path = repo_root / entry["source"]["path"]
        if sha256(source_path) != entry["source"]["sha256"]:
            raise CatalogError(f"source digest does not match: {entry['source']['path']}")
        artifact = entry.get("artifact")
        if artifact is not None:
            artifact_path = repo_root / artifact["path"]
            if sha256(artifact_path) != artifact["sha256"]:
                raise CatalogError(f"artifact digest does not match: {artifact['path']}")
            if entry["kind"] == "schema":
                document = read_json(artifact_path)
                if document.get("$id") != uri:
                    raise CatalogError(f"schema $id and catalog URI disagree: {uri}")


def validate_catalog_contract(catalog: dict[str, Any]) -> None:
    if set(catalog) != {"version", "baseUrl", "entries"}:
        raise CatalogError("generated catalog has an invalid top-level shape")
    if catalog["version"] != 1 or catalog["baseUrl"] != BASE_URL:
        raise CatalogError("generated catalog has an invalid version or base URL")
    entries = catalog["entries"]
    if not isinstance(entries, list):
        raise CatalogError("generated catalog entries must be an array")

    common_required = {
        "uri",
        "kind",
        "status",
        "compatibilityLine",
        "owner",
        "title",
        "description",
        "source",
    }
    allowed = common_required | {"artifact", "problem"}
    valid_kinds = {
        "problem",
        "profile",
        "schema",
        "context",
        "namespace",
        "vocabulary",
        "vocabulary-term",
    }
    digest_pattern = re.compile(r"^[0-9a-f]{64}$")

    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise CatalogError(f"generated catalog entry {index} must be an object")
        if not common_required.issubset(entry) or not set(entry).issubset(allowed):
            raise CatalogError(f"generated catalog entry {index} has an invalid shape")
        for field in (
            "uri",
            "compatibilityLine",
            "owner",
            "title",
            "description",
        ):
            if not isinstance(entry[field], str) or not entry[field]:
                raise CatalogError(
                    f"generated catalog entry {index} has an invalid {field}"
                )
        if not entry["uri"].startswith(f"{BASE_URL}/"):
            raise CatalogError(f"generated catalog entry {index} has an invalid uri")
        if entry["kind"] not in valid_kinds or entry["status"] != "active":
            raise CatalogError(
                f"generated catalog entry {index} has an invalid kind or status"
            )

        source = entry["source"]
        if not isinstance(source, dict) or set(source) != {"path", "sha256"}:
            raise CatalogError(f"generated catalog entry {index} has an invalid source")
        if not isinstance(source["path"], str) or not source["path"]:
            raise CatalogError(f"generated catalog entry {index} has an invalid source path")
        if not isinstance(source["sha256"], str) or digest_pattern.fullmatch(
            source["sha256"]
        ) is None:
            raise CatalogError(
                f"generated catalog entry {index} has an invalid source digest"
            )

        artifact = entry.get("artifact")
        if entry["kind"] in {"profile", "schema", "context"} and artifact is None:
            raise CatalogError(f"generated catalog entry {index} requires an artifact")
        if artifact is not None:
            if not isinstance(artifact, dict) or set(artifact) != {
                "path",
                "sha256",
                "mediaType",
            }:
                raise CatalogError(
                    f"generated catalog entry {index} has an invalid artifact"
                )
            for field in ("path", "mediaType"):
                if not isinstance(artifact[field], str) or not artifact[field]:
                    raise CatalogError(
                        f"generated catalog entry {index} has an invalid artifact {field}"
                    )
            if not isinstance(artifact["sha256"], str) or digest_pattern.fullmatch(
                artifact["sha256"]
            ) is None:
                raise CatalogError(
                    f"generated catalog entry {index} has an invalid artifact digest"
                )

        problem = entry.get("problem")
        if entry["kind"] == "problem" and problem is None:
            raise CatalogError(f"generated catalog entry {index} requires problem facts")
        if problem is not None:
            if not isinstance(problem, dict) or set(problem) != {
                "code",
                "httpStatuses",
            }:
                raise CatalogError(
                    f"generated catalog entry {index} has invalid problem facts"
                )
            if not isinstance(problem["code"], str) or not problem["code"]:
                raise CatalogError(
                    f"generated catalog entry {index} has an invalid problem code"
                )
            statuses = problem["httpStatuses"]
            if not isinstance(statuses, list) or not statuses:
                invalid_statuses = True
            else:
                invalid_statuses = any(
                    isinstance(status, bool)
                    or not isinstance(status, int)
                    or status < 100
                    or status > 599
                    for status in statuses
                ) or len(statuses) != len(set(statuses))
            if invalid_statuses:
                raise CatalogError(
                    f"generated catalog entry {index} has invalid HTTP statuses"
                )


def reference_uris(path: Path) -> set[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return set()
    return {
        match.group(0).rstrip(".,;:)]$")
        for match in REFERENCE_URI_RE.finditer(text)
    }


def validate_reference_closure(
    repo_root: Path,
    entries: list[dict[str, Any]],
    exclusions: list[dict[str, str]],
    problem_sources: list[dict[str, str]],
    repository_paths: tuple[Path, ...],
) -> None:
    validate_reference_exclusions(repo_root, repository_paths, exclusions)
    active_uris = {entry["uri"] for entry in entries}
    adopter_prefixes = {
        entry["uri"]
        for entry in entries
        if entry["kind"] == "vocabulary" and entry["uri"].endswith("/")
    }
    unclassified: list[str] = []
    for path in repository_paths:
        if path == GENERATED_CATALOG:
            continue
        relative = relative_path(repo_root, path)
        excluded = path_is_excluded(repo_root, path, exclusions)
        for uri in reference_uris(path):
            if (
                uri in active_uris
                or uri in REFERENCE_TEMPLATES
                or uri in {source["uriPrefix"] for source in problem_sources}
                or any(uri.startswith(prefix) for prefix in adopter_prefixes)
            ):
                continue
            if not excluded:
                unclassified.append(f"{relative}: {uri}")
    if unclassified:
        raise CatalogError(
            "identifier references are outside the active catalog and exclusion "
            f"inventory: {sorted(unclassified)}"
        )


def build_catalog(
    repo_root: Path, config_path: Path, problem_catalog_paths: dict[str, Path]
) -> dict[str, Any]:
    config = load_source_config(config_path)
    repository_paths = repository_files(repo_root)
    entries: list[dict[str, Any]] = []
    for source in config["problemSources"]:
        try:
            problem_catalog_path = problem_catalog_paths[source["sourcePath"]]
        except KeyError as error:
            raise CatalogError(
                f"problem catalog is missing for {source['sourcePath']}"
            ) from error
        entries.extend(problem_entries(repo_root, source, problem_catalog_path))
    entries.extend(
        schema_entries(
            repo_root,
            config["schemaSources"],
            repository_paths,
            config["referenceExclusions"],
        )
    )
    entries.extend(explicit_entries(repo_root, config["records"]))
    entries.sort(key=lambda entry: entry["uri"])
    validate_entries(repo_root, entries)
    catalog = {"version": 1, "baseUrl": BASE_URL, "entries": entries}
    validate_catalog_contract(catalog)
    validate_reference_closure(
        repo_root,
        entries,
        config["referenceExclusions"],
        config["problemSources"],
        repository_paths,
    )
    return catalog


def render(catalog: dict[str, Any]) -> bytes:
    return (json.dumps(catalog, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def generate_problem_catalog(
    repo_root: Path, source_config: dict[str, str], output: Path
) -> None:
    environment = os.environ.copy()
    environment.setdefault("CARGO_INCREMENTAL", "0")
    environment.setdefault("CARGO_PROFILE_DEV_DEBUG", "0")
    environment.setdefault("CARGO_PROFILE_TEST_DEBUG", "0")
    subprocess.run(
        [
            "cargo",
            "run",
            "--locked",
            "--quiet",
            "-p",
            source_config["cargoPackage"],
            "--example",
            source_config["cargoExample"],
            "--",
            "--output",
            str(output),
        ],
        cwd=repo_root,
        env=environment,
        check=True,
    )


def generate_audit_schema(repo_root: Path, output: Path) -> None:
    environment = os.environ.copy()
    environment.setdefault("CARGO_INCREMENTAL", "0")
    environment.setdefault("CARGO_PROFILE_DEV_DEBUG", "0")
    environment.setdefault("CARGO_PROFILE_TEST_DEBUG", "0")
    subprocess.run(
        [
            "cargo",
            "run",
            "--locked",
            "--quiet",
            "-p",
            "registry-relay-v2",
            "--example",
            "audit-event-schema",
            "--",
            "--output",
            str(output),
        ],
        cwd=repo_root,
        env=environment,
        check=True,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    destination = parser.add_mutually_exclusive_group()
    destination.add_argument("--write", action="store_true")
    destination.add_argument("--output", type=Path)
    destination.add_argument("--check-references", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.check_references:
        config = load_source_config(SOURCE_CONFIG)
        catalog = read_json(GENERATED_CATALOG)
        entries = catalog.get("entries") if isinstance(catalog, dict) else None
        if not isinstance(entries, list):
            raise CatalogError("generated identifier catalog has no entries")
        validate_reference_closure(
            REPO_ROOT,
            entries,
            config["referenceExclusions"],
            config["problemSources"],
            repository_files(REPO_ROOT),
        )
        print("Registry Stack identifier reference closure is complete.")
        return
    with tempfile.TemporaryDirectory(prefix="registry-identifiers-") as temp:
        generated_audit_schema = Path(temp) / "audit-event.v2alpha1.json"
        generate_audit_schema(REPO_ROOT, generated_audit_schema)
        if args.write:
            GENERATED_AUDIT_SCHEMA.parent.mkdir(parents=True, exist_ok=True)
            GENERATED_AUDIT_SCHEMA.write_bytes(generated_audit_schema.read_bytes())
        elif (
            not GENERATED_AUDIT_SCHEMA.is_file()
            or GENERATED_AUDIT_SCHEMA.read_bytes() != generated_audit_schema.read_bytes()
        ):
            raise CatalogError(
                "generated Relay V2 audit event schema is stale; run with --write"
            )

        problem_catalogs: dict[str, Path] = {}
        for index, source in enumerate(
            load_source_config(SOURCE_CONFIG)["problemSources"]
        ):
            problem_catalog = Path(temp) / f"problems-{index}.json"
            generate_problem_catalog(REPO_ROOT, source, problem_catalog)
            problem_catalogs[source["sourcePath"]] = problem_catalog
        catalog = build_catalog(REPO_ROOT, SOURCE_CONFIG, problem_catalogs)
        output = GENERATED_CATALOG if args.write else args.output
        if output is None:
            print(render(catalog).decode("utf-8"), end="")
            return
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(render(catalog))


if __name__ == "__main__":
    main()
