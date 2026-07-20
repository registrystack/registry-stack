#!/usr/bin/env python3
"""Classify a release source-ref finalization diff without weakening CI."""

from __future__ import annotations

import argparse
import copy
import json
import re
import subprocess
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Any, NamedTuple

import yaml


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "registry-stack.finalization-profile.v1"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
MANIFEST_PATH = re.compile(
    r"^release/manifests/registry-stack-(?P<release_id>[A-Za-z0-9][A-Za-z0-9._-]{0,63})\.yaml$"
)
DOCSETS_YAML = "docs/site/src/data/docsets.yaml"
DOCSETS_JSON = "docs/site/src/data/generated/docsets.json"
CONTRACTS_YAML = "docs/site/src/data/contracts.yaml"
CONTRACTS_JSON = "docs/site/src/data/generated/contracts.json"
STANDARDS_YAML = "docs/site/src/data/standards.yaml"
STANDARDS_JSON = "docs/site/src/data/generated/standards.json"
FIXED_PATHS = (
    DOCSETS_YAML,
    DOCSETS_JSON,
    CONTRACTS_YAML,
    CONTRACTS_JSON,
    STANDARDS_YAML,
    STANDARDS_JSON,
)
GATE_NAMES = (
    "rust",
    "platform",
    "platform_hygiene",
    "release_tool",
    "release_source_proof",
    "docs",
    "editors",
    "registryctl_tutorial",
)


class ProfileError(ValueError):
    """A possible finalization cannot use the reduced profile."""


class DiffEntry(NamedTuple):
    status: str
    old_path: str | None
    new_path: str | None

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(path for path in (self.old_path, self.new_path) if path is not None)


def git(repo: Path, *args: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=repo,
            check=False,
            capture_output=True,
        )
    except OSError as exc:
        raise ProfileError(f"cannot execute git: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ProfileError(f"git {' '.join(args)} failed: {detail or result.returncode}")
    return result.stdout


def resolve_commit(repo: Path, ref: str, label: str) -> str:
    resolved = git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}").decode().strip()
    if HEX40.fullmatch(resolved) is None:
        raise ProfileError(f"{label} did not resolve to one exact commit")
    return resolved


def is_ancestor(repo: Path, ancestor: str, descendant: str) -> bool:
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", ancestor, descendant],
        cwd=repo,
        check=False,
        capture_output=True,
    )
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    detail = result.stderr.decode("utf-8", errors="replace").strip()
    raise ProfileError(f"git ancestry check failed: {detail or result.returncode}")


def decode_path(value: bytes) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProfileError("changed paths must be UTF-8 text") from exc


def diff_entries(repo: Path, base: str, head: str) -> list[DiffEntry]:
    fields = git(
        repo,
        "diff",
        "--name-status",
        "-z",
        "--find-renames",
        base,
        head,
        "--",
    ).split(b"\0")
    if fields and not fields[-1]:
        fields.pop()
    entries: list[DiffEntry] = []
    index = 0
    while index < len(fields):
        status = decode_path(fields[index])
        index += 1
        if not status:
            raise ProfileError("git returned an empty diff status")
        if status[0] in {"R", "C"}:
            if index + 1 >= len(fields):
                raise ProfileError("git returned an incomplete rename or copy entry")
            old_path = decode_path(fields[index])
            new_path = decode_path(fields[index + 1])
            index += 2
        else:
            if index >= len(fields):
                raise ProfileError("git returned an incomplete changed-path entry")
            path = decode_path(fields[index])
            index += 1
            old_path = None if status[0] == "A" else path
            new_path = None if status[0] == "D" else path
        entries.append(DiffEntry(status, old_path, new_path))
    return entries


def blob(repo: Path, commit: str, path: str) -> bytes:
    return git(repo, "show", f"{commit}:{path}")


def text_blob(repo: Path, commit: str, path: str) -> str:
    data = blob(repo, commit, path)
    if b"\0" in data:
        raise ProfileError(f"binary content is not allowed in finalization path {path}")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProfileError(f"finalization path {path} must be UTF-8 text") from exc


def yaml_blob(repo: Path, commit: str, path: str) -> tuple[str, Any]:
    text = text_blob(repo, commit, path)
    try:
        return text, yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ProfileError(f"cannot parse YAML {path} at {commit}: {exc}") from exc


def json_blob(repo: Path, commit: str, path: str) -> tuple[str, Any]:
    text = text_blob(repo, commit, path)
    try:
        return text, json.loads(text)
    except json.JSONDecodeError as exc:
        raise ProfileError(f"cannot parse JSON {path} at {commit}: {exc}") from exc


def json_compatible(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): json_compatible(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_compatible(item) for item in value]
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    return value


def manifest_source(data: Any, path: str) -> str:
    stack = data.get("stack") if isinstance(data, dict) else None
    source_ref = stack.get("source_ref") if isinstance(stack, dict) else None
    if not isinstance(source_ref, str):
        raise ProfileError(f"modified release manifest {path} has no text stack.source_ref")
    return source_ref


def find_attempt(
    repo: Path,
    base: str,
    head: str,
    entries: list[DiffEntry],
) -> tuple[str, dict[str, Any], dict[str, Any]] | None:
    attempts: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    for entry in entries:
        if entry.old_path is None or entry.new_path is None:
            continue
        if MANIFEST_PATH.fullmatch(entry.old_path) is None and MANIFEST_PATH.fullmatch(
            entry.new_path
        ) is None:
            continue
        _, before = yaml_blob(repo, base, entry.old_path)
        _, after = yaml_blob(repo, head, entry.new_path)
        old_source = manifest_source(before, entry.old_path)
        new_source = manifest_source(after, entry.new_path)
        if old_source != new_source:
            if entry.old_path != entry.new_path or entry.status != "M":
                raise ProfileError(
                    "a source-ref finalization must modify one existing manifest in place"
                )
            if not isinstance(before, dict) or not isinstance(after, dict):
                raise ProfileError("release manifests must be YAML objects")
            attempts.append((entry.old_path, before, after))
    if not attempts:
        return None
    if len(attempts) != 1:
        raise ProfileError(
            f"expected exactly one manifest source_ref finalization, found {len(attempts)}"
        )
    return attempts[0]


def tree_entry(repo: Path, commit: str, path: str) -> tuple[str, str]:
    output = git(repo, "ls-tree", "-z", commit, "--", path)
    records = [record for record in output.split(b"\0") if record]
    if len(records) != 1:
        raise ProfileError(f"expected one tracked tree entry for {path} at {commit}")
    metadata, separator, found_path = records[0].partition(b"\t")
    if not separator or decode_path(found_path) != path:
        raise ProfileError(f"cannot parse tree entry for {path} at {commit}")
    fields = metadata.decode("ascii", errors="strict").split()
    if len(fields) != 3:
        raise ProfileError(f"cannot parse tree metadata for {path} at {commit}")
    return fields[0], fields[1]


def require_regular_unchanged_modes(repo: Path, base: str, head: str, paths: set[str]) -> None:
    for path in sorted(paths):
        before = tree_entry(repo, base, path)
        after = tree_entry(repo, head, path)
        if before != ("100644", "blob") or after != before:
            raise ProfileError(
                f"finalization path {path} must remain a regular 100644 file with unchanged mode"
            )


def pointer_value(document: Any, pointer: str) -> Any:
    current = document
    for raw in pointer.removeprefix("/").split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            try:
                current = current[int(token)]
            except (ValueError, IndexError) as exc:
                raise ProfileError(f"invalid planned pointer {pointer}") from exc
        elif isinstance(current, dict) and token in current:
            current = current[token]
        else:
            raise ProfileError(f"invalid planned pointer {pointer}")
    return current


def replace_pointer(document: Any, pointer: str, old: str, new: str) -> None:
    tokens = [
        raw.replace("~1", "/").replace("~0", "~")
        for raw in pointer.removeprefix("/").split("/")
    ]
    parent = document
    for token in tokens[:-1]:
        if isinstance(parent, list):
            parent = parent[int(token)]
        else:
            parent = parent[token]
    final = tokens[-1]
    actual = parent[int(final)] if isinstance(parent, list) else parent.get(final)
    if actual != old:
        raise ProfileError(
            f"planned pointer {pointer} contains {actual!r}, expected {old!r}"
        )
    if isinstance(parent, list):
        parent[int(final)] = new
    else:
        parent[final] = new


def change(path: str, pointer: str, old: str, new: str) -> dict[str, str]:
    return {
        "path": path,
        "pointer": pointer,
        "kind": "replace",
        "from": old,
        "to": new,
    }


def candidate_registry_url(value: Any, candidate: str) -> bool:
    if not isinstance(value, str):
        return False
    return (
        re.fullmatch(
            r"https://github\.com/registrystack/registry-stack/(?:blob|tree)/"
            + re.escape(candidate)
            + r"/[^?#]+",
            value,
        )
        is not None
    )


def replace_url_ref(value: str, candidate: str, promotion: str) -> str:
    marker = f"/{candidate}/"
    if value.count(marker) != 1:
        raise ProfileError(f"candidate Registry Stack URL has an ambiguous ref: {value}")
    return value.replace(marker, f"/{promotion}/", 1)


def validate_raw_changes(
    path: str,
    before: str,
    after: str,
    planned: list[dict[str, str]],
) -> None:
    before_lines = before.splitlines(keepends=True)
    after_lines = after.splitlines(keepends=True)
    if len(before_lines) != len(after_lines):
        raise ProfileError(f"finalization path {path} changed line structure")
    remaining = list(planned)
    for old_line, new_line in zip(before_lines, after_lines, strict=True):
        if old_line == new_line:
            continue
        matches = [
            item
            for item in remaining
            if old_line.count(item["from"]) == 1
            and new_line == old_line.replace(item["from"], item["to"], 1)
        ]
        if not matches:
            raise ProfileError(
                f"finalization path {path} contains content outside exact planned replacements"
            )
        remaining.remove(matches[0])
    if remaining:
        pointers = ", ".join(item["pointer"] for item in remaining)
        raise ProfileError(f"finalization path {path} is missing planned replacements: {pointers}")


def planned_documents(
    repo: Path,
    base: str,
    head: str,
    manifest_path: str,
    before_manifest: dict[str, Any],
    after_manifest: dict[str, Any],
    candidate: str,
    promotion: str,
) -> tuple[list[dict[str, str]], dict[str, tuple[str, str]]]:
    documents: dict[str, tuple[str, Any, str, Any]] = {}
    for source_path, generated_path in (
        (DOCSETS_YAML, DOCSETS_JSON),
        (CONTRACTS_YAML, CONTRACTS_JSON),
        (STANDARDS_YAML, STANDARDS_JSON),
    ):
        source_before_text, source_before = yaml_blob(repo, base, source_path)
        source_after_text, source_after = yaml_blob(repo, head, source_path)
        generated_before_text, generated_before = json_blob(repo, base, generated_path)
        generated_after_text, generated_after = json_blob(repo, head, generated_path)
        if json_compatible(source_before) != generated_before:
            raise ProfileError(f"base {generated_path} does not exactly mirror {source_path}")
        if json_compatible(source_after) != generated_after:
            raise ProfileError(f"head {generated_path} does not exactly mirror {source_path}")
        documents[source_path] = (
            source_before_text,
            source_before,
            source_after_text,
            source_after,
        )
        documents[generated_path] = (
            generated_before_text,
            generated_before,
            generated_after_text,
            generated_after,
        )

    before_manifest_text, _ = yaml_blob(repo, base, manifest_path)
    after_manifest_text, _ = yaml_blob(repo, head, manifest_path)
    documents[manifest_path] = (
        before_manifest_text,
        before_manifest,
        after_manifest_text,
        after_manifest,
    )
    expected = {path: copy.deepcopy(values[1]) for path, values in documents.items()}
    planned: list[dict[str, str]] = []

    def add(path: str, pointer: str, old: str, new: str) -> None:
        replace_pointer(expected[path], pointer, old, new)
        planned.append(change(path, pointer, old, new))

    add(manifest_path, "/stack/source_ref", candidate, promotion)

    docsets = documents[DOCSETS_YAML][1]
    if not isinstance(docsets, dict) or not isinstance(docsets.get("docsets"), list):
        raise ProfileError("docsets.yaml must contain a docsets list")
    version = before_manifest["stack"]["version"]
    selected = [
        (index, item)
        for index, item in enumerate(docsets["docsets"])
        if isinstance(item, dict) and item.get("id") == f"v{version}"
    ]
    if len(selected) != 1:
        raise ProfileError(f"expected one archived docset v{version}, found {len(selected)}")
    docset_index, docset = selected[0]
    if docset.get("status") != "archived" or not isinstance(docset.get("products"), dict):
        raise ProfileError(f"docset v{version} must be archived with products")
    external = before_manifest.get("external")
    external_names = set(external) if isinstance(external, dict) else set()
    docset_changes = 0
    for name in sorted(docset["products"]):
        product = docset["products"][name]
        if (
            name in external_names
            or not isinstance(product, dict)
            or product.get("ref") != candidate
        ):
            continue
        pointer = f"/docsets/{docset_index}/products/{name}/ref"
        add(DOCSETS_YAML, pointer, candidate, promotion)
        add(DOCSETS_JSON, pointer, candidate, promotion)
        docset_changes += 1
    if docset_changes == 0:
        raise ProfileError("selected archived docset has no candidate refs to finalize")

    contracts = documents[CONTRACTS_YAML][1]
    if not isinstance(contracts, list):
        raise ProfileError("contracts.yaml must contain a top-level list")
    contract_changes = 0
    for index, item in enumerate(contracts):
        source = item.get("source_of_truth") if isinstance(item, dict) else None
        url = source.get("url") if isinstance(source, dict) else None
        if not candidate_registry_url(url, candidate):
            continue
        replacement = replace_url_ref(url, candidate, promotion)
        pointer = f"/{index}/source_of_truth/url"
        add(CONTRACTS_YAML, pointer, url, replacement)
        add(CONTRACTS_JSON, pointer, url, replacement)
        contract_changes += 1
    if contract_changes == 0:
        raise ProfileError("contracts data has no candidate Registry Stack refs to finalize")

    standards = documents[STANDARDS_YAML][1]
    if not isinstance(standards, list):
        raise ProfileError("standards.yaml must contain a top-level list")
    standard_changes = 0
    for entry_index, standard in enumerate(standards):
        evidence = standard.get("evidence_docs") if isinstance(standard, dict) else None
        if not isinstance(evidence, list):
            continue
        for evidence_index, item in enumerate(evidence):
            url = item.get("url") if isinstance(item, dict) else None
            if not candidate_registry_url(url, candidate):
                continue
            replacement = replace_url_ref(url, candidate, promotion)
            pointer = f"/{entry_index}/evidence_docs/{evidence_index}/url"
            add(STANDARDS_YAML, pointer, url, replacement)
            add(STANDARDS_JSON, pointer, url, replacement)
            standard_changes += 1
    if standard_changes == 0:
        raise ProfileError("standards data has no candidate Registry Stack refs to finalize")

    for path, values in documents.items():
        if json_compatible(expected[path]) != json_compatible(values[3]):
            raise ProfileError(
                f"finalization path {path} does not contain only planned pointer replacements"
            )
        path_changes = [item for item in planned if item["path"] == path]
        validate_raw_changes(path, values[0], values[2], path_changes)

    texts = {path: (values[0], values[2]) for path, values in documents.items()}
    return sorted(planned, key=lambda item: (item["path"], item["pointer"])), texts


def gates(classification: str) -> dict[str, bool] | None:
    if classification == "not-applicable":
        return None
    if classification == "eligible":
        enabled = {"release_tool", "release_source_proof", "docs"}
        return {name: name in enabled for name in GATE_NAMES}
    return {name: True for name in GATE_NAMES}


def result_document(
    classification: str,
    *,
    base_commit: str | None,
    head_commit: str | None,
    changed_paths: list[str],
    candidate: str | None = None,
    promotion: str | None = None,
    release: dict[str, str] | None = None,
    planned_changes: list[dict[str, str]] | None = None,
    errors: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "classification": classification,
        "base_commit": base_commit,
        "head_commit": head_commit,
        "candidate_source_ref": candidate,
        "promotion_commit": promotion,
        "release": release,
        "changed_paths": sorted(changed_paths),
        "planned_changes": planned_changes or [],
        "selected_gates": gates(classification),
        "errors": errors or [],
    }


def classify(repo: Path, base_ref: str, head_ref: str) -> dict[str, Any]:
    base: str | None = None
    head: str | None = None
    changed_paths: list[str] = []
    candidate: str | None = None
    promotion: str | None = None
    release: dict[str, str] | None = None
    try:
        repo = repo.resolve()
        if not repo.is_dir():
            raise ProfileError(f"repository does not exist: {repo}")
        base = resolve_commit(repo, base_ref, "base ref")
        head = resolve_commit(repo, head_ref, "head ref")
        entries = diff_entries(repo, base, head)
        changed_paths = sorted({path for entry in entries for path in entry.paths})
        attempt = find_attempt(repo, base, head, entries)
        if attempt is None:
            return result_document(
                "not-applicable",
                base_commit=base,
                head_commit=head,
                changed_paths=changed_paths,
            )

        manifest_path, before_manifest, after_manifest = attempt
        match = MANIFEST_PATH.fullmatch(manifest_path)
        assert match is not None
        before_stack = before_manifest.get("stack")
        after_stack = after_manifest.get("stack")
        if not isinstance(before_stack, dict) or not isinstance(after_stack, dict):
            raise ProfileError("selected release manifests must contain stack objects")
        candidate = before_stack.get("source_ref")
        promotion = after_stack.get("source_ref")
        if not isinstance(candidate, str) or HEX40.fullmatch(candidate) is None:
            raise ProfileError("candidate source_ref must be one exact lowercase commit SHA")
        if not isinstance(promotion, str) or HEX40.fullmatch(promotion) is None:
            raise ProfileError("promotion source_ref must be one exact lowercase commit SHA")
        if promotion != base:
            raise ProfileError(
                f"promotion commit {promotion} must equal pull-request base commit {base}"
            )
        if resolve_commit(repo, candidate, "candidate source_ref") != candidate:
            raise ProfileError("candidate source_ref must resolve without abbreviation")
        if not is_ancestor(repo, candidate, promotion):
            raise ProfileError("candidate source_ref is not an ancestor of promotion commit")
        if not is_ancestor(repo, promotion, head):
            raise ProfileError("promotion commit is not an ancestor of finalization head")

        release_id = before_stack.get("release")
        version = before_stack.get("version")
        if release_id != match.group("release_id"):
            raise ProfileError("manifest filename does not match stack.release")
        if not isinstance(version, str) or SEMVER.fullmatch(version) is None:
            raise ProfileError("manifest stack.version must be canonical MAJOR.MINOR.PATCH text")
        if before_stack.get("source_repo") != "registrystack/registry-stack":
            raise ProfileError("manifest stack.source_repo is not registrystack/registry-stack")
        if before_stack.get("source_tag") != f"v{version}":
            raise ProfileError("manifest stack.source_tag does not match stack.version")
        if before_stack.get("status") != "release-candidate":
            raise ProfileError("finalization requires release-candidate status")
        release = {
            "manifest": manifest_path,
            "release_id": str(release_id),
            "version": version,
        }
        target_tags = git(repo, "tag", "--list", f"v{version}").decode().splitlines()
        if target_tags:
            raise ProfileError(f"target release tag v{version} already exists")

        expected_paths = {manifest_path, *FIXED_PATHS}
        actual_paths = set(changed_paths)
        if actual_paths != expected_paths:
            missing = sorted(expected_paths - actual_paths)
            extra = sorted(actual_paths - expected_paths)
            raise ProfileError(
                f"finalization paths are not exact; missing={missing}, extra={extra}"
            )
        if len(entries) != len(expected_paths) or any(
            entry.status != "M"
            or entry.old_path != entry.new_path
            or entry.old_path not in expected_paths
            for entry in entries
        ):
            raise ProfileError(
                "finalization allows only in-place modifications of the seven exact files"
            )
        require_regular_unchanged_modes(repo, base, head, expected_paths)
        planned, _ = planned_documents(
            repo,
            base,
            head,
            manifest_path,
            before_manifest,
            after_manifest,
            candidate,
            promotion,
        )
        return result_document(
            "eligible",
            base_commit=base,
            head_commit=head,
            changed_paths=changed_paths,
            candidate=candidate,
            promotion=promotion,
            release=release,
            planned_changes=planned,
        )
    except (OSError, UnicodeError, ValueError, yaml.YAMLError) as exc:
        return result_document(
            "full-ci",
            base_commit=base,
            head_commit=head,
            changed_paths=changed_paths,
            candidate=candidate,
            promotion=promotion,
            release=release,
            errors=[str(exc)],
        )


def render(result: dict[str, Any]) -> str:
    return json.dumps(result, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Classify an exact release source-ref finalization diff."
    )
    parser.add_argument("--repo", type=Path, default=ROOT)
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--head-ref", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = classify(args.repo, args.base_ref, args.head_ref)
    except Exception as exc:  # pragma: no cover - last-resort CI fail-closed boundary
        result = result_document(
            "full-ci",
            base_commit=None,
            head_commit=None,
            changed_paths=[],
            errors=[f"unexpected checker error: {type(exc).__name__}: {exc}"],
        )
    body = render(result)
    if args.output is not None:
        try:
            args.output.write_text(body, encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            print(f"cannot write finalization profile: {exc}", file=sys.stderr)
            return 1
    print(body, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
