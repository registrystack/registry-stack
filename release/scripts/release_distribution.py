#!/usr/bin/env python3
"""Select immutable unit releases for a recommended Stack distribution."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import release_candidate  # noqa: E402
import release_units  # noqa: E402
import verify_public_release  # noqa: E402


SELECTION_SCHEMA = "registry-stack.distribution-selection.v1"
LOCK_SCHEMA = "registry-stack.distribution-lock.v1"
SELECTION_FIELDS = {"unit", "version", "policy"}
REPOSITORY = "github.com/registrystack/registry-stack"


class DistributionError(ValueError):
    """A recommended distribution selection is invalid or cannot be trusted."""


def _require_exact_object(
    value: object, label: str, fields: set[str]
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise DistributionError(f"{label} must contain exactly {sorted(fields)!r}")
    return value


def _require_selection(value: object, label: str) -> dict[str, str]:
    selection = _require_exact_object(value, label, SELECTION_FIELDS)
    if any(not isinstance(selection[field], str) for field in SELECTION_FIELDS):
        raise DistributionError(f"{label} fields must be strings")
    unit = selection["unit"]
    try:
        release_units.load_registry().require_pilot(unit)
        release_units.asset_tag(selection["version"])
    except release_units.UnitRegistryError as exc:
        raise DistributionError(str(exc)) from exc
    if selection["policy"] != "exact":
        raise DistributionError(f"{label}.policy must be exact")
    return selection


def load_components(repo: Path, stack_version: str) -> list[dict[str, str]]:
    """Load the optional committed component selection for one Stack version."""

    try:
        release_units.asset_tag(stack_version)
    except release_units.UnitRegistryError as exc:
        raise DistributionError(str(exc)) from exc
    path = repo / "release" / "distributions" / f"v{stack_version}.json"
    if not path.exists() and not path.is_symlink():
        return []
    if path.is_symlink() or not path.is_file():
        raise DistributionError(f"distribution selection must be a regular file: {path}")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DistributionError(f"cannot read distribution selection {path}: {exc}") from exc
    root = _require_exact_object(
        document,
        "distribution selection",
        {"schema_version", "stack_version", "components"},
    )
    if root["schema_version"] != SELECTION_SCHEMA:
        raise DistributionError(f"distribution selection schema must be {SELECTION_SCHEMA}")
    if root["stack_version"] != stack_version:
        raise DistributionError(
            "distribution selection stack_version must match its filename"
        )
    values = root["components"]
    if not isinstance(values, list) or not values:
        raise DistributionError("distribution selection components must be non-empty")
    components = [
        _require_selection(value, f"components[{index}]")
        for index, value in enumerate(values)
    ]
    units = [component["unit"] for component in components]
    if len(set(units)) != len(units):
        raise DistributionError("distribution selection repeats a component unit")
    return components


def validate_selected_version(selection: object, selected_version: str) -> None:
    """Require the resolved release to be the exact committed version."""

    selected = _require_selection(selection, "component selection")
    try:
        release_units.asset_tag(selected_version)
    except release_units.UnitRegistryError as exc:
        raise DistributionError(str(exc)) from exc
    if selected_version != selected["version"]:
        raise DistributionError(
            f"selected release must equal exact version {selected['version']}"
        )


def select_release_tag(selection: object) -> str:
    """Choose the deterministic release tag fixed by one committed selection."""

    selected = _require_selection(selection, "component selection")
    return release_units.release_tag(selected["unit"], selected["version"])


def resolve_components(
    repo: Path,
    stack_version: str,
    *,
    repository: str,
) -> list[dict[str, Any]]:
    """Resolve selections through the complete authenticated public verifier."""

    selections = load_components(repo, stack_version)
    if not selections:
        return []
    components: list[dict[str, Any]] = []
    for selection in selections:
        tag = select_release_tag(selection)
        try:
            closure = verify_public_release.verify_component_closure(
                repo=repo,
                repository=repository,
                tag=tag,
            )
        except verify_public_release.PublicReleaseError as exc:
            raise DistributionError(
                f"selected component release {tag} failed public verification: {exc}"
            ) from exc
        components.append(
            component_from_authenticated_release(
                manifest_bytes=closure["manifest_bytes"],
                manifest_sha256=closure["manifest_sha256"],
                checksums=closure["checksums"],
                selection=selection,
            )
        )
    return components


def component_from_authenticated_release(
    *,
    manifest_bytes: bytes,
    manifest_sha256: str,
    checksums: dict[str, str],
    selection: object,
) -> dict[str, Any]:
    """Lock one manifest from an already authenticated public SHA256SUMS closure.

    The caller must authenticate the supplied checksum map with the public release
    signature and provenance before calling this function. This function binds
    those authenticated hashes to the manifest's exact source, tag, assets, and
    final image digests without changing their release identity.
    """

    selected = _require_selection(selection, "component selection")
    if not isinstance(manifest_bytes, bytes):
        raise DistributionError("manifest_bytes must be bytes")
    try:
        release_candidate.require_sha256(manifest_sha256, "manifest_sha256")
    except release_candidate.CandidateError as exc:
        raise DistributionError(str(exc)) from exc
    actual_manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    if actual_manifest_sha256 != manifest_sha256:
        raise DistributionError("public manifest bytes do not match manifest_sha256")
    if not isinstance(checksums, dict) or any(
        not isinstance(name, str) or not isinstance(digest, str)
        for name, digest in checksums.items()
    ):
        raise DistributionError("authenticated checksums must be a string map")
    try:
        document = json.loads(manifest_bytes)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise DistributionError(f"public component manifest is invalid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise DistributionError("public component manifest must be an object")
    release = document.get("release")
    validity = document.get("validity")
    if not isinstance(release, dict) or not isinstance(validity, dict):
        raise DistributionError("public component manifest lacks release identity")
    unit = release.get("unit")
    version = release.get("version")
    created_at = validity.get("created_at")
    if unit != selected["unit"] or not isinstance(version, str):
        raise DistributionError("public component manifest does not match selection")
    validate_selected_version(selected, version)
    try:
        expected_tag = release_units.release_tag(unit, version)
        manifest_name = release_units.public_manifest_name(unit, version)
        validation_time = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except (release_units.UnitRegistryError, AttributeError, ValueError) as exc:
        raise DistributionError(f"public component release identity is invalid: {exc}") from exc
    if release.get("tag") != expected_tag:
        raise DistributionError("public component release identity was rebound")
    if checksums.get(manifest_name) != manifest_sha256:
        raise DistributionError(
            "authenticated checksum closure does not bind the public manifest"
        )
    try:
        release_candidate.validate_candidate_manifest(
            document,
            expected_unit=unit,
            expected_version=version,
            now=validation_time,
        )
    except release_candidate.CandidateError as exc:
        raise DistributionError(f"public component manifest is invalid: {exc}") from exc
    payloads = document.get("payloads")
    images = document.get("images")
    if not isinstance(payloads, list) or not isinstance(images, list):
        raise DistributionError("public component manifest lacks artifact closure")
    payload_names = {
        payload.get("name") for payload in payloads if isinstance(payload, dict)
    }
    if None in payload_names or set(checksums) != payload_names | {manifest_name}:
        raise DistributionError(
            "authenticated checksum closure differs from component payloads"
        )
    for payload in payloads:
        if checksums.get(payload["name"]) != payload.get("sha256"):
            raise DistributionError(
                f"authenticated checksum rejects component payload {payload['name']!r}"
            )
    locked_images = [
        {
            "name": image.get("name"),
            "final_ref": image.get("final_ref"),
            "digest": image.get("digest"),
        }
        for image in images
        if isinstance(image, dict)
    ]
    if len(locked_images) != len(images):
        raise DistributionError("public component image closure is malformed")
    component = {
        "unit": unit,
        "version": version,
        "release_tag": expected_tag,
        "source_sha": release.get("source_sha"),
        "manifest": {"name": manifest_name, "sha256": manifest_sha256},
        "payloads": [
            {
                field: payload[field]
                for field in ("name", "kind", "size", "sha256")
            }
            for payload in payloads
        ],
        "images": locked_images,
    }
    try:
        release_candidate.validate_release_components([component])
    except release_candidate.CandidateError as exc:
        raise DistributionError(f"component lock is invalid: {exc}") from exc
    return component


def distribution_lock_name(stack_version: str) -> str:
    try:
        tag = release_units.asset_tag(stack_version)
    except release_units.UnitRegistryError as exc:
        raise DistributionError(str(exc)) from exc
    return f"registry-stack-{tag}-distribution.json"


def render_distribution_lock(
    stack_version: str, components: object
) -> bytes:
    """Render the checksum-covered lock payload embedded by a Stack candidate."""

    distribution_lock_name(stack_version)
    try:
        validated = release_candidate.validate_release_components(components)
    except release_candidate.CandidateError as exc:
        raise DistributionError(f"distribution components are invalid: {exc}") from exc
    document = {
        "schema_version": LOCK_SCHEMA,
        "stack_version": stack_version,
        "components": validated,
    }
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()


def load_distribution_lock(path: Path) -> dict[str, Any]:
    """Validate a local lock whose bytes were authenticated by the Stack release.

    This validates structure and recorded component closure. It does not establish
    authenticity for the lock file itself. The caller must first verify the lock's
    hash through the containing Stack release SHA256SUMS signature and provenance.
    """

    if path.is_symlink() or not path.is_file():
        raise DistributionError(
            f"authenticated distribution lock must be a regular file: {path}"
        )
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DistributionError(f"cannot read distribution lock {path}: {exc}") from exc
    lock = _require_exact_object(
        document,
        "distribution lock",
        {"schema_version", "stack_version", "components"},
    )
    if lock["schema_version"] != LOCK_SCHEMA:
        raise DistributionError(f"distribution lock schema must be {LOCK_SCHEMA}")
    try:
        release_units.asset_tag(lock["stack_version"])
        components = release_candidate.validate_release_components(lock["components"])
    except (release_units.UnitRegistryError, release_candidate.CandidateError) as exc:
        raise DistributionError(f"distribution lock is invalid: {exc}") from exc
    return {
        "schema_version": LOCK_SCHEMA,
        "stack_version": lock["stack_version"],
        "components": components,
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(command: list[str], *, environment: dict[str, str] | None = None) -> str:
    try:
        result = subprocess.run(
            command,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        raise DistributionError(f"cannot run {command[0]}: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise DistributionError(f"{command[0]} failed: {detail}")
    return result.stdout.strip()


def install_from_distribution_lock(
    lock_path: Path,
    install_dir: Path,
) -> dict[str, Any]:
    """Install an original Discovery pair selected by an authenticated Stack lock.

    The function downloads original release assets without renaming or repackaging
    them, verifies their lock-recorded size and hash, and runs that release's
    numbered installer against only the verified local assets.
    """

    lock = load_distribution_lock(lock_path)
    discoveries = [
        component
        for component in lock["components"]
        if component["unit"] == "discovery"
    ]
    if len(discoveries) != 1:
        raise DistributionError(
            "distribution lock must contain exactly one Discovery component"
        )
    component = discoveries[0]
    version = component["version"]
    tag = component["release_tag"]
    required_names = {
        f"discovery-v{version}-linux-amd64",
        f"discoveryctl-v{version}-linux-amd64",
        f"discovery-v{version}-install.sh",
    }
    payloads = {payload["name"]: payload for payload in component["payloads"]}
    missing = sorted(required_names - set(payloads))
    if missing:
        raise DistributionError(
            f"Discovery component lock lacks install assets {missing!r}"
        )
    if install_dir.is_symlink() or (install_dir.exists() and not install_dir.is_dir()):
        raise DistributionError(
            f"install directory must be a directory or absent: {install_dir}"
        )
    gh = shutil.which("gh")
    bash = shutil.which("bash")
    if gh is None or bash is None:
        raise DistributionError("distribution install requires gh and bash on PATH")
    with tempfile.TemporaryDirectory(prefix="registry-distribution-install-") as temporary:
        assets = Path(temporary)
        command = [
            gh,
            "release",
            "download",
            tag,
            "--repo",
            REPOSITORY,
            "--dir",
            str(assets),
        ]
        for name in sorted(required_names):
            command.extend(["--pattern", name])
        _run(command)
        downloaded = {
            path.name: path
            for path in assets.iterdir()
            if path.is_file() and not path.is_symlink()
        }
        if set(downloaded) != required_names:
            raise DistributionError(
                "downloaded component install inventory differs from lock: "
                f"missing={sorted(required_names - set(downloaded))!r} "
                f"unexpected={sorted(set(downloaded) - required_names)!r}"
            )
        for name, path in downloaded.items():
            record = payloads[name]
            if path.stat().st_size != record["size"]:
                raise DistributionError(
                    f"downloaded component asset {name!r} has the wrong size"
                )
            if _sha256_file(path) != record["sha256"]:
                raise DistributionError(
                    f"downloaded component asset {name!r} has the wrong digest"
                )
        binary_names = sorted(
            name for name in required_names if name.endswith("-linux-amd64")
        )
        (assets / "SHA256SUMS").write_text(
            "".join(f"{payloads[name]['sha256']}  {name}\n" for name in binary_names),
            encoding="utf-8",
        )
        environment = os.environ.copy()
        environment.pop("DISCOVERY_VERSION", None)
        environment["DISCOVERY_ASSET_DIR"] = str(assets)
        environment["DISCOVERY_INSTALL_DIR"] = str(install_dir)
        installer = assets / f"discovery-v{version}-install.sh"
        _run([bash, str(installer)], environment=environment)

    versions: dict[str, str] = {}
    for binary in ("discovery", "discoveryctl"):
        path = install_dir / binary
        if not path.exists() or not path.is_file():
            raise DistributionError(f"installer did not create {path}")
        observed = _run([str(path), "--version"])
        expected = f"{binary} {version}"
        if observed != expected:
            raise DistributionError(
                f"installed {binary} reports {observed!r}, not {expected!r}"
            )
        versions[binary] = observed
    return {
        "unit": "discovery",
        "version": version,
        "release_tag": tag,
        "source_sha": component["source_sha"],
        "install_dir": str(install_dir),
        "versions": versions,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    resolve = commands.add_parser("resolve")
    resolve.add_argument("--repo", type=Path, required=True)
    resolve.add_argument("--repository", default="registrystack/registry-stack")
    resolve.add_argument("--stack-version", required=True)
    resolve.add_argument("--output", type=Path, required=True)
    install = commands.add_parser(
        "install",
        description=(
            "Install a component from a local distribution lock only after the "
            "lock hash has been authenticated by the containing Stack release."
        ),
    )
    install.add_argument(
        "--lock",
        type=Path,
        required=True,
        help="local lock already authenticated through Stack SHA256SUMS",
    )
    install.add_argument("--install-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "resolve":
            components = resolve_components(
                args.repo,
                args.stack_version,
                repository=args.repository,
            )
            if not components:
                raise DistributionError(
                    "this Stack version has no committed component selection"
                )
            if args.output.exists() or args.output.is_symlink():
                raise DistributionError(f"output already exists: {args.output}")
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(
                render_distribution_lock(args.stack_version, components)
            )
            print(f"resolved authenticated distribution lock {args.output}")
            return 0
        if args.command == "install":
            result = install_from_distribution_lock(args.lock, args.install_dir)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        raise AssertionError(args.command)
    except (DistributionError, OSError, KeyError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
