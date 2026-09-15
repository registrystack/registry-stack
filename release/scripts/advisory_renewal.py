#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Renew reviewed advisory baseline bindings from review-only rehearsal evidence.

Renewal moves the machine bindings of already-reviewed exceptions onto a new
rehearsal image: application layers, component layers, definition digests,
reference image identity, and reviewed file digests. It never adds, removes, or
extends an exception, never edits a rationale, and refuses any change a human
must review: a different runtime base or process contract, a missing, fixable,
or new blocking finding, or assertion kinds other than whole-image fingerprints.
Every renewed baseline must pass the strict advisory check before anything is
written.
"""

from __future__ import annotations

import ast
import copy
import datetime as dt
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import release_candidate


SCRIPTS = Path(__file__).resolve().parent
COLLECTION_SCHEMA = "registry-stack.rehearsal-advisory-evidence.v1"
COLLECTION_FIELDS = {
    "schema_version",
    "purpose",
    "publication_eligible",
    "advisory_accepted",
    "version",
    "source",
    "revision",
    "images",
}
SOURCE = "https://github.com/registrystack/registry-stack"
PROVENANCE = "local_reproduction"
RENEWABLE_ASSERTION = "whole_image_fingerprint_equals"
PINS_PATH = Path("release/scripts/test_check_advisory_baselines.py")
ISO_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


def _load_script(name: str, filename: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


checker = _load_script("check_advisory_baselines", "check-advisory-baselines.py")
collector = _load_script(
    "collect_rehearsal_advisory_evidence", "collect-rehearsal-advisory-evidence.py"
)


class RenewalError(ValueError):
    """Evidence cannot renew the reviewed advisory baselines."""


@dataclass(frozen=True)
class Renewal:
    name: str
    path: Path
    before: dict[str, Any]
    after: dict[str, Any]
    text: str


@contextmanager
def _checker_refusal(context: str) -> Iterator[None]:
    # The checker reports its reason on stderr before exiting.
    try:
        yield
    except SystemExit as exc:
        raise RenewalError(f"{context} was refused by the advisory checker") from exc


def _iso_date(value: str, field: str) -> dt.date:
    if ISO_DATE.fullmatch(value) is None:
        raise RenewalError(f"{field} is not an ISO date (YYYY-MM-DD): {value}")
    try:
        return dt.date.fromisoformat(value)
    except ValueError as exc:
        raise RenewalError(f"{field} is not an ISO date (YYYY-MM-DD): {value}") from exc


def _evidence_file(path: Path) -> Path:
    if path.is_symlink() or not path.is_file():
        raise RenewalError(f"evidence file is missing or not a regular file: {path}")
    return path


def _same(value: Any, expected: Any) -> bool:
    return type(value) is type(expected) and value == expected


def load_collection(
    evidence_dir: Path, version: str, source_revision: str
) -> list[tuple[str, str]]:
    path = _evidence_file(evidence_dir / "collection.json")
    try:
        collection = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RenewalError(f"evidence collection is not JSON: {path}: {exc}") from exc
    if not isinstance(collection, dict) or set(collection) != COLLECTION_FIELDS:
        raise RenewalError(f"evidence collection has an unsupported field set: {path}")
    expected = {
        "schema_version": COLLECTION_SCHEMA,
        "purpose": "review_only",
        "publication_eligible": False,
        "advisory_accepted": False,
        "version": version,
        "source": SOURCE,
    }
    for field, value in expected.items():
        if not _same(collection[field], value):
            raise RenewalError(
                f"evidence collection {field} must be {value!r}, "
                f"found {collection[field]!r}"
            )
    if collection["revision"] != source_revision:
        raise RenewalError(
            f"evidence collection revision {collection['revision']!r} does not match "
            f"--source-revision {source_revision}"
        )
    try:
        roster = release_candidate._candidate_image_names(version)
    except release_candidate.CandidateError as exc:
        raise RenewalError(str(exc)) from exc
    images = collection["images"]
    if not isinstance(images, list) or any(
        not isinstance(image, dict)
        or set(image) != {"name", "digest"}
        or not isinstance(image["name"], str)
        or not isinstance(image["digest"], str)
        or checker.SHA256_DIGEST_RE.fullmatch(image["digest"]) is None
        for image in images
    ):
        raise RenewalError("evidence collection images must be name and sha256 digest pairs")
    names = [image["name"] for image in images]
    if len(names) != len(set(names)) or set(names) != roster:
        raise RenewalError(
            f"evidence collection images must match the release image roster for "
            f"{version}: expected={sorted(roster)} found={names}"
        )
    return sorted((image["name"], image["digest"]) for image in images)


@contextmanager
def extracted_rootfs(tar_path: Path) -> Iterator[Path]:
    _evidence_file(tar_path)
    with tempfile.TemporaryDirectory(prefix="advisory-renewal-") as temporary:
        rootfs = Path(temporary) / "rootfs"
        rootfs.mkdir()
        result = subprocess.run(
            [
                "tar",
                "--extract",
                f"--file={tar_path}",
                f"--directory={rootfs}",
                "--no-same-owner",
                "--no-same-permissions",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise RenewalError(f"could not extract {tar_path}: {result.stderr.strip()}")
        try:
            collector.reject_special_files(rootfs)
        except collector.EvidenceError as exc:
            raise RenewalError(f"{tar_path}: {exc}") from exc
        yield rootfs


def renew_image(
    repo: Path,
    evidence_dir: Path,
    name: str,
    digest: str,
    source_revision: str,
    reviewed_at: str,
    today: dt.date,
) -> Renewal:
    path = release_candidate.advisory_baseline_path(repo, name)
    if path.is_symlink():
        raise RenewalError(f"{name}: advisory baseline must not be a symlink: {path}")
    with _checker_refusal(f"{name}: recorded baseline {path}"):
        before = checker.load_baseline(path)
    if before["service"] != name:
        raise RenewalError(f"{name}: baseline service is {before['service']!r}")

    with _checker_refusal(f"{name}: scan evidence"):
        normalized = checker.normalize_grype(
            checker.load_json(_evidence_file(evidence_dir / f"grype/{name}.grype.json")),
            f"{name}-image",
            checker.load_json(_evidence_file(evidence_dir / f"syft/{name}.syft.json")),
        )
        oci = checker.normalize_oci_image_config(
            checker.load_json(_evidence_file(evidence_dir / f"oci-config/{name}.json")),
            source_revision,
        )
    if normalized.image.digest != digest:
        raise RenewalError(
            f"{name}: candidate image identity mismatch: "
            f"report={normalized.image.digest} collection={digest}"
        )
    if normalized.image.layer_ids != oci.layer_ids:
        raise RenewalError(
            f"{name}: candidate rootfs evidence mismatch: OCI rootfs.diff_ids do not "
            "match the Grype and Syft reports"
        )

    runtime = before["runtime"]
    base = tuple(runtime["layer_ids"])
    if oci.layer_ids[: len(base)] != base:
        raise RenewalError(
            f"{name}: runtime base changed: candidate layers do not begin with the "
            f"pinned base {runtime['image']}; review the base change by hand"
        )
    if len(oci.layer_ids) == len(base):
        raise RenewalError(f"{name}: candidate has no application layers above the base")
    changed_config = sorted(
        field
        for field in set(runtime["config"]) | set(oci.runtime_config)
        if runtime["config"].get(field) != oci.runtime_config.get(field)
    )
    if changed_config:
        raise RenewalError(
            f"{name}: OCI process configuration changed: {', '.join(changed_config)}; "
            "review it and renew runtime.config by hand"
        )

    reviewed = _iso_date(reviewed_at, "--reviewed-at")
    after = copy.deepcopy(before)
    renewed_runtime = after["runtime"]
    renewed_runtime["application_layer_ids"] = list(oci.layer_ids[len(base) :])
    renewed_runtime["definition_digest"] = checker.definition_digest(renewed_runtime)
    findings = {finding.exception_key: finding for finding in normalized.findings}

    with extracted_rootfs(evidence_dir / f"rootfs/{name}.tar") as rootfs:
        file_digests: dict[str, str] = {}

        def reviewed_file_digest(image_path: str, syft_digests: Any) -> str:
            if image_path not in file_digests:
                _resolved, error = checker.rootfs_file(rootfs, image_path, syft_digests)
                if error:
                    raise RenewalError(f"{name}: {error}")
                file_digests[image_path] = dict(syft_digests)[image_path]
            return file_digests[image_path]

        for exception in after["exceptions"]:
            key = checker.exception_key(exception)
            label = " ".join(key)
            assertion = exception["exposure_assertion"]
            if assertion["kind"] != RENEWABLE_ASSERTION:
                raise RenewalError(
                    f"{name}: renew {assertion['kind']} assertions by hand; only "
                    f"{RENEWABLE_ASSERTION} assertions are renewable"
                )
            finding = findings.get(key)
            if finding is None:
                raise RenewalError(
                    f"{name}: {label} has no matching finding in the candidate scan; "
                    "a fixed, absent, or version-changed finding needs review"
                )
            if finding.component_layer_error:
                raise RenewalError(
                    f"{name}: {label}: component evidence is unevaluable: "
                    f"{finding.component_layer_error}"
                )
            recorded = _iso_date(exception["reviewed_at"], f"{name}: {label} reviewed_at")
            if reviewed < recorded:
                raise RenewalError(
                    f"{name}: {label}: --reviewed-at {reviewed_at} precedes the "
                    f"recorded reviewed_at {exception['reviewed_at']}"
                )
            expires = _iso_date(exception["expires_at"], f"{name}: {label} expires_at")
            if expires < reviewed:
                raise RenewalError(
                    f"{name}: expired exception: {label} expired on "
                    f"{exception['expires_at']}; renewal never extends expires_at"
                )
            exception["reviewed_at"] = reviewed_at
            exception["component_layer_id"] = finding.component_layer_id
            exception["runtime_definition_digest"] = renewed_runtime["definition_digest"]
            assertion["reference_image_digest"] = digest
            assertion["reference_source_revision"] = source_revision
            assertion["reference_provenance"] = PROVENANCE
            assertion["runtime_definition_digest"] = renewed_runtime["definition_digest"]
            for entry in assertion["files"]:
                entry["sha256"] = reviewed_file_digest(
                    entry["path"], finding.syft_file_digests
                )
            assertion["definition_digest"] = checker.definition_digest(assertion)

        with _checker_refusal(f"{name}: renewed baseline"):
            checker.validate_v4_baseline(after)
            status = checker.check_grype_findings(
                list(normalized.findings),
                normalized.image,
                after,
                today,
                rootfs,
                digest,
                oci.runtime_config,
                oci.layer_ids,
            )
    if status:
        raise RenewalError(
            f"{name}: the renewed baseline does not pass the strict advisory check"
        )
    return Renewal(
        name=name,
        path=path,
        before=before,
        after=after,
        text=json.dumps(after, indent=2, ensure_ascii=False) + "\n",
    )


def _item_labels(items: list[Any]) -> list[str] | None:
    for fields in (("vulnerability_id", "package"), ("vulnerability_id", "package", "installed_version"), ("path",)):
        if all(isinstance(item, dict) and all(field in item for field in fields) for item in items):
            labels = [" ".join(str(item[field]) for field in fields) for item in items]
            if len(labels) == len(set(labels)):
                return labels
    return None


def _render(value: Any) -> str:
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)


def describe_changes(before: Any, after: Any, path: str = "") -> list[str]:
    if isinstance(before, dict) and isinstance(after, dict) and set(before) == set(after):
        return [
            line
            for key in before
            for line in describe_changes(
                before[key], after[key], f"{path}.{key}" if path else key
            )
        ]
    if isinstance(before, list) and isinstance(after, list) and before and after:
        labels = _item_labels(before)
        if labels is not None and labels == _item_labels(after):
            return [
                line
                for label, old, new in zip(labels, before, after)
                for line in describe_changes(old, new, f"{path}[{label}]")
            ]
    if before == after:
        return []
    return [f"{path}: {_render(before)} -> {_render(after)}"]


def _replace_pin_dict(text: str, name: str, values: dict[str, str]) -> str:
    pattern = re.compile(
        rf'^{name} = \{{\n((?:    "[a-z0-9-]+": "[^"\\\n]*",\n)*)\}}$', re.MULTILINE
    )
    matches = list(pattern.finditer(text))
    if len(matches) != 1:
        raise RenewalError(
            f"{PINS_PATH}: {name} must be assigned exactly once as a "
            "one-entry-per-line string dict"
        )
    keys = re.findall(r'^    "([a-z0-9-]+)": ', matches[0].group(1), re.MULTILINE)
    if len(keys) != len(set(keys)) or set(keys) != set(values):
        raise RenewalError(
            f"{PINS_PATH}: {name} must pin exactly the renewed images "
            f"{sorted(values)}, found {keys}; onboard or retire images by hand"
        )
    body = "".join(f'    "{key}": "{values[key]}",\n' for key in keys)
    start, end = matches[0].span(1)
    return text[:start] + body + text[end:]


def _replace_pin_string(text: str, name: str, value: str) -> str:
    pattern = re.compile(rf'^({name} = )"[^"\\\n]*"$', re.MULTILINE)
    text, count = pattern.subn(lambda match: f'{match.group(1)}"{value}"', text)
    if count != 1:
        raise RenewalError(f"{PINS_PATH}: {name} must be assigned exactly once")
    return text


def renew_pins(
    text: str, digests: dict[str, str], source_revision: str, reviewed_at: str
) -> str:
    expected: dict[str, Any] = {
        "LIVE_REFERENCE_IMAGE_DIGESTS": digests,
        "LIVE_REFERENCE_PROVENANCE": {name: PROVENANCE for name in digests},
        "LIVE_REFERENCE_SOURCE_REVISION": source_revision,
        "LIVE_REVIEW_EVALUATION_DATE": reviewed_at,
    }
    for name, value in expected.items():
        if isinstance(value, dict):
            text = _replace_pin_dict(text, name, value)
        else:
            text = _replace_pin_string(text, name, value)
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        raise RenewalError(f"{PINS_PATH}: renewed pins do not parse: {exc}") from exc
    assigned = {
        node.targets[0].id: ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id in expected
    }
    if assigned != expected:
        raise RenewalError(f"{PINS_PATH}: renewed pins do not hold the renewed values")
    return text


def renew(
    repo: Path,
    evidence_dir: Path,
    *,
    version: str,
    source_revision: str,
    reviewed_at: str,
    write: bool,
    today: str | None = None,
) -> None:
    if release_candidate.VERSION.fullmatch(version) is None:
        raise RenewalError("--version must be canonical semantic version text")
    if checker.GIT_REVISION_RE.fullmatch(source_revision) is None:
        raise RenewalError("--source-revision must be a full lowercase Git revision")
    _iso_date(reviewed_at, "--reviewed-at")
    evaluation_date = (
        dt.date.today() if today is None else _iso_date(today, "--today")
    )
    images = load_collection(evidence_dir, version, source_revision)
    renewals = [
        renew_image(
            repo, evidence_dir, name, digest, source_revision, reviewed_at, evaluation_date
        )
        for name, digest in images
    ]
    pins_path = repo / PINS_PATH
    pins_before = pins_path.read_text(encoding="utf-8")
    pins_after = renew_pins(pins_before, dict(images), source_revision, reviewed_at)

    changed: list[tuple[Path, str]] = []
    for renewal in renewals:
        changes = describe_changes(renewal.before, renewal.after)
        if changes:
            print(f"{renewal.name}: {renewal.path.relative_to(repo)}")
            for change in changes:
                print(f"  {change}")
        else:
            print(f"{renewal.name}: no baseline changes")
        if renewal.path.read_text(encoding="utf-8") != renewal.text:
            changed.append((renewal.path, renewal.text))
        print(
            f"{renewal.name}: rationale is unchanged for "
            f"{len(renewal.after['exceptions'])} exception(s); confirm each still "
            f"describes the {version} evidence"
        )
    if pins_after != pins_before:
        print(f"live test pins: {PINS_PATH} moves to the renewed images")
        changed.append((pins_path, pins_after))
    else:
        print("live test pins: no changes")

    if not write:
        print(f"dry run: {len(changed)} file(s) would change; rerun with --write")
        return
    for path, text in changed:
        path.write_text(text, encoding="utf-8")
    print(f"wrote {len(changed)} file(s)")


def run(
    repo: Path,
    evidence_dir: Path,
    *,
    version: str,
    source_revision: str,
    reviewed_at: str,
    write: bool,
    today: str | None = None,
) -> int:
    try:
        renew(
            repo.resolve(),
            evidence_dir.resolve(),
            version=version,
            source_revision=source_revision,
            reviewed_at=reviewed_at,
            write=write,
            today=today,
        )
    except (OSError, UnicodeError, RenewalError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0
