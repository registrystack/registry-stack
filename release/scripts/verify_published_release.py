#!/usr/bin/env python3
"""Verify the complete public RegistryStack v0.12+ release contract.

The result document is intentionally public-only and covers the release asset
set before the evidence bundle is added.  This avoids recursive
self-attestation: the evidence bundle and closeout files are signed and
provenanced by a later workflow phase.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
from importlib.machinery import SourceFileLoader
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Mapping, Sequence

import yaml


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "registry-stack.verify-published.v1"
CLASSIFICATION = "public"
REPOSITORY = "registrystack/registry-stack"
SOURCE_URL = f"https://github.com/{REPOSITORY}"
SOURCE_URI = f"github.com/{REPOSITORY}"
COSIGN_ISSUER = "https://token.actions.githubusercontent.com"
MINIMUM_VERSION = (0, 12, 0)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
IMAGE_DIGEST_RE = re.compile(r"^([^@]+)@(sha256:[0-9a-f]{64})$")
MAX_JSON_BYTES = 256 * 1024 * 1024

EXPECTED_COUNTS = {
    "payloads": 35,
    "signatures": 35,
    "certificates": 35,
    "provenance": 1,
    "total": 106,
}
EXCLUDED_ROLES = [
    "evidence_bundle",
    "evidence_bundle_signature",
    "evidence_bundle_certificate",
    "evidence_bundle_provenance",
]
CHECK_SPECS = (
    ("release_metadata", "publication", "release", "gh"),
    ("source_identity", "publication", "source", "git"),
    ("asset_inventory", "artifacts", "release-assets", "gh"),
    ("checksums", "artifacts", "SHA256SUMS", "python"),
    ("cosign_signatures", "authenticity", "payloads", "cosign"),
    ("slsa_provenance", "authenticity", "payloads", "slsa-verifier"),
    ("image_lock_bindings", "bindings", "registryctl-image-lock", "python"),
    ("capsule_bindings", "bindings", "release-capsule", "python"),
    ("sbom_bindings", "bindings", "SPDX-subjects", "python"),
    ("grype_bindings", "bindings", "Grype-subjects", "python"),
    ("image_input_bindings", "bindings", "image-inputs", "docker"),
    ("anonymous_image_access", "images", "release-images", "docker"),
    ("oci_labels", "images", "release-images", "docker-buildx"),
    ("non_root_users", "images", "release-images", "docker-buildx"),
    ("service_versions", "images", "release-images", "docker"),
    ("registryctl_authoring_build", "journey", "registryctl", "registryctl"),
    ("archived_docs", "documentation", "archived-docset", "https"),
)
CHECK_IDS = tuple(item[0] for item in CHECK_SPECS)
IMAGE_COMPONENTS = ("registry-notary", "registry-relay")
IMAGE_REPOSITORIES = {
    component: f"ghcr.io/registrystack/{component}" for component in IMAGE_COMPONENTS
}
IMAGE_INPUTS = {
    "registry-notary": ("registry-notary", "registry-notary-cel-worker"),
    "registry-relay": ("registry-relay", "registry-relay-rhai-worker"),
}
OCI_LABELS = {
    "source": "org.opencontainers.image.source",
    "revision": "org.opencontainers.image.revision",
    "version": "org.opencontainers.image.version",
}


class VerificationFailure(RuntimeError):
    """A normalized, public-safe verification failure."""

    def __init__(self, code: str, subject: str) -> None:
        super().__init__(code)
        self.code = code
        self.subject = subject


@dataclass(frozen=True)
class ReleaseIdentity:
    release_id: str
    version: str
    tag: str
    source_ref: str
    repository: str
    manifest_sha256: str


@dataclass(frozen=True)
class AssetContract:
    payloads: tuple[str, ...]
    signatures: tuple[str, ...]
    certificates: tuple[str, ...]
    provenance: str

    @property
    def all_assets(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                (*self.payloads, *self.signatures, *self.certificates, self.provenance)
            )
        )


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: str


class SystemIO:
    """External boundary. Tests replace this object with deterministic fakes."""

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        timeout: int = 120,
    ) -> CommandResult:
        try:
            result = subprocess.run(
                list(argv),
                cwd=cwd,
                env=dict(env) if env is not None else None,
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return CommandResult(127)
        return CommandResult(result.returncode, result.stdout, result.stderr)

    def get(self, url: str, *, timeout: int = 20) -> HttpResponse:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "registry-stack-release-verifier/1"},
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return HttpResponse(
                    response.status, response.read().decode("utf-8", errors="replace")
                )
        except urllib.error.HTTPError as error:
            return HttpResponse(
                error.code, error.read().decode("utf-8", errors="replace")
            )
        except (OSError, UnicodeError):
            return HttpResponse(0, "")

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


def _load_script_module(name: str, path: Path) -> ModuleType:
    loader = SourceFileLoader(name, str(path)) if path.suffix == "" else None
    spec = (
        importlib.util.spec_from_loader(name, loader)
        if loader is not None
        else importlib.util.spec_from_file_location(name, path)
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"unable to load {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


RELEASE_HELPERS = _load_script_module(
    "registry_release_verify_helpers", ROOT / "release/scripts/registry-release"
)
OCI_HELPERS = _load_script_module(
    "registry_release_oci_label_helpers",
    ROOT / "release/scripts/check-release-image-oci-labels.py",
)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_regular_file(path: Path, code: str = "missing_asset") -> Path:
    if path.is_symlink() or not path.is_file():
        raise VerificationFailure(code, path.name)
    return path


def read_json(path: Path) -> Any:
    require_regular_file(path)
    if path.stat().st_size > MAX_JSON_BYTES:
        raise VerificationFailure("json_size_limit_exceeded", path.name)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise VerificationFailure("invalid_json", path.name) from error


def parse_semver(version: str) -> tuple[int, int, int]:
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is None:
        raise VerificationFailure("invalid_release_version", version)
    parsed = tuple(int(part) for part in version.split("."))
    assert len(parsed) == 3
    return parsed  # type: ignore[return-value]


def load_release_identity(manifest_path: Path) -> ReleaseIdentity:
    try:
        data = yaml.safe_load(
            require_regular_file(manifest_path, "manifest_not_found").read_text(
                encoding="utf-8"
            )
        )
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise VerificationFailure("invalid_manifest", manifest_path.name) from error
    if not isinstance(data, dict) or not isinstance(data.get("stack"), dict):
        raise VerificationFailure("invalid_manifest", manifest_path.name)
    stack = data["stack"]
    version = stack.get("version")
    tag = stack.get("source_tag")
    source_ref = stack.get("source_ref")
    release_id = stack.get("release")
    repository = stack.get("source_repo")
    if not all(
        isinstance(value, str)
        for value in (version, tag, source_ref, release_id, repository)
    ):
        raise VerificationFailure("invalid_manifest_identity", manifest_path.name)
    assert (
        isinstance(version, str)
        and isinstance(tag, str)
        and isinstance(source_ref, str)
    )
    assert isinstance(release_id, str) and isinstance(repository, str)
    if parse_semver(version) < MINIMUM_VERSION:
        raise VerificationFailure("unsupported_release_contract", tag)
    if tag != f"v{version}":
        raise VerificationFailure("manifest_tag_version_mismatch", tag)
    if COMMIT_RE.fullmatch(source_ref) is None:
        raise VerificationFailure("invalid_manifest_source_ref", tag)
    if repository != REPOSITORY:
        raise VerificationFailure("unexpected_repository", repository)
    return ReleaseIdentity(
        release_id=release_id,
        version=version,
        tag=tag,
        source_ref=source_ref,
        repository=repository,
        manifest_sha256=file_sha256(manifest_path),
    )


def expected_asset_contract(identity: ReleaseIdentity) -> AssetContract:
    tag = identity.tag
    binaries = (
        f"registry-manifest-{tag}-linux-amd64",
        f"registry-notary-{tag}-linux-amd64",
        f"registry-notary-cel-worker-{tag}-linux-amd64",
        f"registry-relay-{tag}-linux-amd64",
        f"registry-relay-rhai-worker-{tag}-linux-amd64",
        f"registryctl-{tag}-linux-amd64",
        f"registryctl-{tag}-linux-arm64",
        f"registryctl-{tag}-macos-arm64",
    )
    image_lock = f"registryctl-{tag}-image-lock.json"
    release_sboms = tuple(f"{name}.spdx.json" for name in (*binaries, image_lock))
    image_inputs = tuple(
        f"image-input-{name}.spdx.json"
        for name in (
            "registry-notary",
            "registry-notary-cel-worker",
            "registry-relay",
            "registry-relay-rhai-worker",
        )
    )
    image_evidence = tuple(
        f"{component}{suffix}"
        for component in IMAGE_COMPONENTS
        for suffix in (".digest", ".metadata.json", ".spdx.json", ".grype.json")
    )
    capsule_base = f"registry-stack-{tag}-release-capsule"
    payloads = tuple(
        sorted(
            (
                *binaries,
                image_lock,
                "SHA256SUMS",
                *release_sboms,
                "image-binaries.SHA256SUMS",
                "release-builder-image.txt",
                *image_inputs,
                *image_evidence,
                f"{capsule_base}.json",
                f"{capsule_base}.md",
            )
        )
    )
    if len(payloads) != EXPECTED_COUNTS["payloads"]:
        raise AssertionError("release payload contract count changed")
    signatures = tuple(f"{name}.sig" for name in payloads)
    certificates = tuple(f"{name}.pem" for name in payloads)
    provenance = f"registry-stack-{tag}-release-provenance.intoto.jsonl"
    return AssetContract(payloads, signatures, certificates, provenance)


def expected_finalization_assets(identity: ReleaseIdentity) -> dict[str, str]:
    evidence = f"registry-stack-{identity.tag}-release-evidence.json"
    closeout = f"registry-stack-{identity.tag}-release-closeout.md"
    return {
        evidence: "evidence_bundle",
        f"{evidence}.sig": "evidence_bundle_signature",
        f"{evidence}.pem": "evidence_bundle_certificate",
        closeout: "evidence_bundle",
        f"{closeout}.sig": "evidence_bundle_signature",
        f"{closeout}.pem": "evidence_bundle_certificate",
        f"registry-stack-{identity.tag}-release-evidence-provenance.intoto.jsonl": "evidence_bundle_provenance",
    }


def strict_sha256s(path: Path, expected_names: set[str]) -> dict[str, str]:
    require_regular_file(path)
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise VerificationFailure("invalid_checksum_file", path.name) from error
    parsed: dict[str, str] = {}
    pattern = re.compile(r"^([0-9a-f]{64})  (\*?)([^/\x00]+)$")
    for line in lines:
        match = pattern.fullmatch(line)
        if match is None:
            raise VerificationFailure("malformed_checksum_entry", path.name)
        name = match.group(3)
        if name in parsed:
            raise VerificationFailure("duplicate_checksum_entry", name)
        parsed[name] = match.group(1)
    if set(parsed) != expected_names:
        raise VerificationFailure("checksum_inventory_mismatch", path.name)
    return parsed


def verify_checksum_files(asset_dir: Path, identity: ReleaseIdentity) -> None:
    tag = identity.tag
    release_files = {
        f"registry-manifest-{tag}-linux-amd64",
        f"registry-notary-{tag}-linux-amd64",
        f"registry-notary-cel-worker-{tag}-linux-amd64",
        f"registry-relay-{tag}-linux-amd64",
        f"registry-relay-rhai-worker-{tag}-linux-amd64",
        f"registryctl-{tag}-linux-amd64",
        f"registryctl-{tag}-linux-arm64",
        f"registryctl-{tag}-macos-arm64",
        f"registryctl-{tag}-image-lock.json",
    }
    release_sums = strict_sha256s(asset_dir / "SHA256SUMS", release_files)
    for name, expected in release_sums.items():
        if file_sha256(require_regular_file(asset_dir / name)) != expected:
            raise VerificationFailure("checksum_mismatch", name)

    image_inputs = {
        "RELEASE_BUILDER_IMAGE",
        "registry-notary",
        "registry-notary-cel-worker",
        "registry-relay",
        "registry-relay-rhai-worker",
    }
    strict_sha256s(asset_dir / "image-binaries.SHA256SUMS", image_inputs)


def parse_provenance_subjects(path: Path) -> dict[str, str]:
    require_regular_file(path)
    subjects: dict[str, str] = {}
    try:
        lines = [
            line
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, UnicodeError) as error:
        raise VerificationFailure("invalid_provenance", path.name) from error
    if not lines:
        raise VerificationFailure("invalid_provenance", path.name)
    for line in lines:
        try:
            bundle = json.loads(line)
            envelope = bundle["dsseEnvelope"]
            if envelope.get("payloadType") != "application/vnd.in-toto+json":
                raise KeyError("payloadType")
            payload = base64.b64decode(envelope["payload"], validate=True)
            statement = json.loads(payload)
            statement_subjects = statement["subject"]
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise VerificationFailure("invalid_provenance", path.name) from error
        if not isinstance(statement_subjects, list):
            raise VerificationFailure("invalid_provenance", path.name)
        for subject in statement_subjects:
            if not isinstance(subject, dict):
                raise VerificationFailure("invalid_provenance_subject", path.name)
            name = subject.get("name")
            digest = subject.get("digest")
            sha = digest.get("sha256") if isinstance(digest, dict) else None
            if (
                not isinstance(name, str)
                or Path(name).name != name
                or not isinstance(sha, str)
                or SHA256_RE.fullmatch(sha) is None
            ):
                raise VerificationFailure("invalid_provenance_subject", path.name)
            if name in subjects:
                raise VerificationFailure("duplicate_provenance_subject", name)
            subjects[name] = sha
    return subjects


def verify_provenance_subjects(asset_dir: Path, contract: AssetContract) -> None:
    subjects = parse_provenance_subjects(asset_dir / contract.provenance)
    if set(subjects) != set(contract.payloads):
        raise VerificationFailure(
            "provenance_subject_inventory_mismatch", contract.provenance
        )
    for name, expected in subjects.items():
        if file_sha256(require_regular_file(asset_dir / name)) != expected:
            raise VerificationFailure("provenance_subject_digest_mismatch", name)


def _contains_exact_string(value: Any, expected: str) -> bool:
    if value == expected:
        return True
    if isinstance(value, dict):
        return any(_contains_exact_string(item, expected) for item in value.values())
    if isinstance(value, list):
        return any(_contains_exact_string(item, expected) for item in value)
    return False


def verify_image_lock_and_metadata(
    asset_dir: Path,
    identity: ReleaseIdentity,
    tag_target: str,
) -> dict[str, str]:
    lock_name = f"registryctl-{identity.tag}-image-lock.json"
    lock = read_json(asset_dir / lock_name)
    try:
        RELEASE_HELPERS.validate_registryctl_image_lock_document(
            lock,
            version=identity.version,
            release_tag=identity.tag,
            manifest_source_ref=identity.source_ref,
            tag_target=tag_target,
        )
    except ValueError as error:
        raise VerificationFailure("invalid_image_lock_binding", lock_name) from error
    assert isinstance(lock, dict) and isinstance(lock.get("images"), dict)
    locked_images: dict[str, str] = {}
    for component in IMAGE_COMPONENTS:
        digest_ref = lock["images"].get(component)
        if not isinstance(digest_ref, str):
            raise VerificationFailure("invalid_image_lock_binding", component)
        digest_path = asset_dir / f"{component}.digest"
        try:
            body = require_regular_file(digest_path).read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise VerificationFailure(
                "invalid_image_digest_evidence", component
            ) from error
        if body not in {digest_ref, f"{digest_ref}\n"}:
            raise VerificationFailure("image_digest_lock_mismatch", component)
        match = IMAGE_DIGEST_RE.fullmatch(digest_ref)
        if match is None or match.group(1) != IMAGE_REPOSITORIES[component]:
            raise VerificationFailure("invalid_image_digest_evidence", component)
        digest = match.group(2)
        metadata = read_json(asset_dir / f"{component}.metadata.json")
        expected_tag_ref = f"{IMAGE_REPOSITORIES[component]}:{identity.tag}"
        if not isinstance(metadata, dict):
            raise VerificationFailure("invalid_image_metadata", component)
        descriptor = metadata.get("containerimage.descriptor")
        if (
            metadata.get("containerimage.digest") != digest
            or not isinstance(descriptor, dict)
            or descriptor.get("digest") != digest
            or metadata.get("image.name") != expected_tag_ref
            or not _contains_exact_string(
                metadata.get("buildx.build.provenance"), SOURCE_URL
            )
            or not _contains_exact_string(
                metadata.get("buildx.build.provenance"), tag_target
            )
        ):
            raise VerificationFailure("image_metadata_binding_mismatch", component)
        locked_images[component] = digest_ref
    return locked_images


def verify_sbom_bindings(
    asset_dir: Path,
    identity: ReleaseIdentity,
    contract: AssetContract,
    locked_images: Mapping[str, str],
) -> None:
    file_subjects = [
        name
        for name in contract.payloads
        if name.endswith(("-linux-amd64", "-linux-arm64", "-macos-arm64"))
    ]
    file_subjects.append(f"registryctl-{identity.tag}-image-lock.json")
    if len(file_subjects) != 9:
        raise AssertionError("release file SBOM subject count changed")
    for name in file_subjects:
        sbom_name = f"{name}.spdx.json"
        if not RELEASE_HELPERS.spdx_subject_contains_file_digest(
            read_json(asset_dir / sbom_name),
            name,
            file_sha256(require_regular_file(asset_dir / name)),
        ):
            raise VerificationFailure("file_sbom_subject_mismatch", sbom_name)
    for component, digest_ref in locked_images.items():
        digest = digest_ref.rsplit("@", 1)[1]
        if not RELEASE_HELPERS.spdx_subject_contains_digest(
            read_json(asset_dir / f"{component}.spdx.json"), digest_ref, digest
        ):
            raise VerificationFailure("image_sbom_subject_mismatch", component)


def verify_grype_bindings(asset_dir: Path, locked_images: Mapping[str, str]) -> None:
    for component, digest_ref in locked_images.items():
        subject = RELEASE_HELPERS.grype_subject(
            read_json(asset_dir / f"{component}.grype.json")
        )
        digest = digest_ref.rsplit("@", 1)[1]
        if subject not in {digest_ref, digest}:
            raise VerificationFailure("grype_subject_mismatch", component)


def verify_capsule_bindings(
    asset_dir: Path,
    manifest_path: Path,
    manifest_data: Mapping[str, Any],
    identity: ReleaseIdentity,
    tag_target: str,
    contract: AssetContract,
    locked_images: Mapping[str, str],
) -> None:
    name = f"registry-stack-{identity.tag}-release-capsule.json"
    markdown_name = f"registry-stack-{identity.tag}-release-capsule.md"
    capsule = read_json(asset_dir / name)
    if not isinstance(capsule, dict):
        raise VerificationFailure("invalid_capsule", name)
    source = capsule.get("source")
    if (
        capsule.get("release_tag") != identity.tag
        or capsule.get("version") != identity.version
        or capsule.get("repository") != identity.repository
        or capsule.get("warnings") != manifest_data.get("warnings", [])
        or not isinstance(source, dict)
        or source.get("source_tag") != identity.tag
        or source.get("source_ref") != identity.source_ref
        or source.get("manifest_ref") != identity.source_ref
        or source.get("source_commit") != tag_target
    ):
        raise VerificationFailure("capsule_identity_mismatch", name)
    capsule_manifest = capsule.get("manifest")
    if (
        not isinstance(capsule_manifest, dict)
        or capsule_manifest.get("sha256") != identity.manifest_sha256
    ):
        raise VerificationFailure("capsule_manifest_mismatch", name)
    binaries = capsule.get("binaries")
    release_files = capsule.get("release_files")
    images = capsule.get("images")
    if not isinstance(binaries, list) or len(binaries) != 8:
        raise VerificationFailure("capsule_binary_inventory_mismatch", name)
    if not isinstance(release_files, list) or len(release_files) != 1:
        raise VerificationFailure("capsule_release_file_inventory_mismatch", name)
    if not isinstance(images, list) or len(images) != 2:
        raise VerificationFailure("capsule_image_inventory_mismatch", name)

    expected_files = {
        payload
        for payload in contract.payloads
        if payload.endswith(("-linux-amd64", "-linux-arm64", "-macos-arm64"))
    }
    seen_files: set[str] = set()
    for record in [*binaries, *release_files]:
        if not isinstance(record, dict) or not isinstance(record.get("name"), str):
            raise VerificationFailure("invalid_capsule", name)
        file_name = record["name"]
        seen_files.add(file_name)
        sbom = record.get("sbom")
        if (
            record.get("sha256")
            != file_sha256(require_regular_file(asset_dir / file_name))
            or not isinstance(sbom, dict)
            or sbom.get("asset_name") != f"{file_name}.spdx.json"
            or sbom.get("subject") != file_name
            or sbom.get("sha256")
            != file_sha256(require_regular_file(asset_dir / f"{file_name}.spdx.json"))
        ):
            raise VerificationFailure("capsule_file_binding_mismatch", file_name)
    lock_name = f"registryctl-{identity.tag}-image-lock.json"
    if (
        seen_files != expected_files | {lock_name}
        or release_files[0].get("kind") != "registryctl-release-image-lock"
    ):
        raise VerificationFailure("capsule_file_inventory_mismatch", name)

    seen_images: set[str] = set()
    for record in images:
        if not isinstance(record, dict) or record.get("name") not in locked_images:
            raise VerificationFailure("capsule_image_inventory_mismatch", name)
        component = record["name"]
        seen_images.add(component)
        digest_ref = locked_images[component]
        sbom = record.get("sbom")
        scan = record.get("vulnerability_scan")
        if (
            record.get("digest_ref") != digest_ref
            or record.get("digest") != digest_ref.rsplit("@", 1)[1]
            or record.get("tag") != identity.tag
            or record.get("tag_ref")
            != f"{IMAGE_REPOSITORIES[component]}:{identity.tag}"
            or not isinstance(sbom, dict)
            or sbom.get("asset_name") != f"{component}.spdx.json"
            or sbom.get("subject") != digest_ref
            or sbom.get("sha256") != file_sha256(asset_dir / f"{component}.spdx.json")
            or not isinstance(scan, dict)
            or scan.get("asset_name") != f"{component}.grype.json"
            or scan.get("subject") != digest_ref
            or scan.get("sha256") != file_sha256(asset_dir / f"{component}.grype.json")
        ):
            raise VerificationFailure("capsule_image_binding_mismatch", component)
    if seen_images != set(IMAGE_COMPONENTS):
        raise VerificationFailure("capsule_image_inventory_mismatch", name)
    try:
        canonical_markdown = RELEASE_HELPERS.capsule_markdown(capsule)
        actual_markdown = require_regular_file(asset_dir / markdown_name).read_text(
            encoding="utf-8"
        )
    except (KeyError, OSError, UnicodeError) as error:
        raise VerificationFailure("invalid_capsule_markdown", markdown_name) from error
    if actual_markdown != canonical_markdown:
        raise VerificationFailure("capsule_markdown_mismatch", markdown_name)


def initial_report(identity: ReleaseIdentity) -> dict[str, Any]:
    workflow = {
        "name": os.environ.get("GITHUB_WORKFLOW"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "run_url": None,
        "event": os.environ.get("GITHUB_EVENT_NAME"),
        "ref": os.environ.get("GITHUB_REF"),
        "head_sha": os.environ.get("GITHUB_SHA"),
        "started_at": None,
        "completed_at": None,
        "duration_seconds": None,
    }
    if (
        os.environ.get("GITHUB_SERVER_URL")
        and os.environ.get("GITHUB_REPOSITORY")
        and workflow["run_id"]
    ):
        workflow["run_url"] = (
            f"{os.environ['GITHUB_SERVER_URL']}/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{workflow['run_id']}"
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "classification": CLASSIFICATION,
        "status": "incomplete",
        "release": {
            "repository": identity.repository,
            "release_id": identity.release_id,
            "version": identity.version,
            "tag": identity.tag,
            "manifest_sha256": identity.manifest_sha256,
        },
        "lineage": {
            "manifest_source_ref": identity.source_ref,
            "tag_target": None,
            "default_branch": None,
            "default_branch_commit": None,
            "tag_matches_source_tag": False,
            "head_matches_tag_target": False,
            "source_ref_ancestor_or_equal": False,
            "default_branch_reachable": False,
        },
        "workflow": workflow,
        "tools": [],
        "artifact_scope": {
            "name": "pre_evidence_bundle",
            "expected_counts": dict(EXPECTED_COUNTS),
            "observed_counts": {key: 0 for key in EXPECTED_COUNTS},
            "excluded_roles": list(EXCLUDED_ROLES),
        },
        "artifacts": [],
        "images": [],
        "checks": [
            {
                "id": check_id,
                "phase": phase,
                "subject": subject,
                "status": "incomplete",
                "tool": tool,
                "failure_codes": [],
            }
            for check_id, phase, subject, tool in CHECK_SPECS
        ],
        "warnings": [],
    }


def assert_closed_report(report: Mapping[str, Any]) -> None:
    top_keys = {
        "schema_version",
        "classification",
        "status",
        "release",
        "lineage",
        "workflow",
        "tools",
        "artifact_scope",
        "artifacts",
        "images",
        "checks",
        "warnings",
    }
    if set(report) != top_keys:
        raise ValueError("report top-level fields are not closed")
    if (
        report.get("schema_version") != SCHEMA_VERSION
        or report.get("classification") != CLASSIFICATION
    ):
        raise ValueError("report identity is invalid")
    if report.get("status") not in {"passed", "failed", "incomplete"}:
        raise ValueError("report status is invalid")
    closed_fields = {
        "release": {"repository", "release_id", "version", "tag", "manifest_sha256"},
        "lineage": {
            "manifest_source_ref",
            "tag_target",
            "default_branch",
            "default_branch_commit",
            "tag_matches_source_tag",
            "head_matches_tag_target",
            "source_ref_ancestor_or_equal",
            "default_branch_reachable",
        },
        "workflow": {
            "name",
            "run_id",
            "run_attempt",
            "run_url",
            "event",
            "ref",
            "head_sha",
            "started_at",
            "completed_at",
            "duration_seconds",
        },
        "artifact_scope": {
            "name",
            "expected_counts",
            "observed_counts",
            "excluded_roles",
        },
    }
    for field, expected in closed_fields.items():
        value = report.get(field)
        if not isinstance(value, dict) or set(value) != expected:
            raise ValueError(f"report {field} fields are not closed")
    scope = report["artifact_scope"]
    for count_field in ("expected_counts", "observed_counts"):
        counts = scope.get(count_field)
        if not isinstance(counts, dict) or set(counts) != set(EXPECTED_COUNTS):
            raise ValueError("report artifact counts are not closed")
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in counts.values()
        ):
            raise ValueError("report artifact counts are invalid")
    if (
        scope.get("name") != "pre_evidence_bundle"
        or scope.get("excluded_roles") != EXCLUDED_ROLES
    ):
        raise ValueError("report artifact scope is invalid")
    tools = report.get("tools")
    if not isinstance(tools, list):
        raise ValueError("report tools must be an array")
    for observation in tools:
        if not isinstance(observation, dict) or set(observation) != {
            "name",
            "version",
            "source",
        }:
            raise ValueError("report tool fields are not closed")
        if observation.get("source") != "observed" or not all(
            isinstance(observation.get(key), str) for key in ("name", "version")
        ):
            raise ValueError("report tool observation is invalid")
    artifacts = report.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("report artifacts must be an array")
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != {
            "name",
            "role",
            "payload_name",
            "size_bytes",
            "sha256",
            "verification",
        }:
            raise ValueError("report artifact fields are not closed")
        verification = artifact.get("verification")
        if not isinstance(verification, dict) or set(verification) != {
            "checksum",
            "signature",
            "provenance",
        }:
            raise ValueError("report artifact verification fields are not closed")
        if artifact.get("role") not in {
            "payload",
            "signature",
            "certificate",
            "provenance",
        }:
            raise ValueError("report artifact role is invalid")
        if not isinstance(artifact.get("name"), str) or not isinstance(
            artifact.get("size_bytes"), int
        ):
            raise ValueError("report artifact identity is invalid")
        if (
            not isinstance(artifact.get("sha256"), str)
            or SHA256_RE.fullmatch(artifact["sha256"]) is None
        ):
            raise ValueError("report artifact digest is invalid")
        if any(
            value not in {"passed", "failed", "not_applicable"}
            for value in verification.values()
        ):
            raise ValueError("report artifact verification status is invalid")
    images = report.get("images")
    if not isinstance(images, list):
        raise ValueError("report images must be an array")
    image_fields = {
        "component",
        "repository",
        "tag_ref",
        "digest_ref",
        "digest",
        "anonymous_tag_pull",
        "anonymous_digest_pull",
        "config_user",
        "labels",
        "reported_version",
    }
    for image in images:
        if not isinstance(image, dict) or set(image) != image_fields:
            raise ValueError("report image fields are not closed")
        labels = image.get("labels")
        if not isinstance(labels, dict) or set(labels) != {
            "source",
            "revision",
            "version",
        }:
            raise ValueError("report image label fields are not closed")
        if image.get("anonymous_tag_pull") not in {"passed", "failed"} or image.get(
            "anonymous_digest_pull"
        ) not in {"passed", "failed"}:
            raise ValueError("report anonymous image status is invalid")
    checks = report.get("checks")
    if not isinstance(checks, list) or [
        item.get("id") for item in checks if isinstance(item, dict)
    ] != list(CHECK_IDS):
        raise ValueError("report checks are not the fixed contract")
    for check in checks:
        if not isinstance(check, dict) or set(check) != {
            "id",
            "phase",
            "subject",
            "status",
            "tool",
            "failure_codes",
        }:
            raise ValueError("report check fields are not closed")
        if check.get("status") not in {"passed", "failed", "incomplete"}:
            raise ValueError("report check status is invalid")
        if not isinstance(check.get("failure_codes"), list) or not all(
            isinstance(code, str) for code in check["failure_codes"]
        ):
            raise ValueError("report check failure codes are invalid")
    warnings = report.get("warnings")
    if not isinstance(warnings, list):
        raise ValueError("report warnings must be an array")
    for warning in warnings:
        if not isinstance(warning, dict) or set(warning) != {"code", "subject"}:
            raise ValueError("report warning fields are not closed")
        if not all(isinstance(warning.get(key), str) for key in ("code", "subject")):
            raise ValueError("report warning is invalid")
    forbidden = {
        "command",
        "stdout",
        "stderr",
        "environment",
        "env",
        "local_path",
        "path",
        "message",
        "detail",
    }

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            if forbidden & set(value):
                raise ValueError("report contains prohibited diagnostic fields")
            for nested in value.values():
                walk(nested)
        elif isinstance(value, list):
            for nested in value:
                walk(nested)

    walk(report)


class PublishedReleaseVerifier:
    def __init__(
        self,
        manifest_path: Path,
        output_path: Path,
        *,
        repo_root: Path = ROOT,
        assets_dir: Path | None = None,
        io: SystemIO | None = None,
        dry_validate: bool = False,
        docs_attempts: int = 6,
        docs_retry_seconds: float = 10.0,
    ) -> None:
        self.manifest_path = manifest_path.resolve()
        self.output_path = output_path.resolve()
        self.repo_root = repo_root.resolve()
        self.provided_assets_dir = assets_dir.resolve() if assets_dir else None
        self.io = io or SystemIO()
        self.dry_validate = dry_validate
        self.docs_attempts = docs_attempts
        self.docs_retry_seconds = docs_retry_seconds
        self.identity = load_release_identity(self.manifest_path)
        self.contract = expected_asset_contract(self.identity)
        self.report = initial_report(self.identity)
        self.started = datetime.now(UTC)
        self.report["workflow"]["started_at"] = self.started.isoformat().replace(
            "+00:00", "Z"
        )
        self.asset_dir: Path | None = None
        self.temp_root: Path | None = None
        self.release_assets: dict[str, int] = {}
        self.release_metadata_loaded = False
        self.locked_images: dict[str, str] = {}
        self.image_configs: dict[str, dict[str, Any]] = {}

    def _check(self, check_id: str) -> dict[str, Any]:
        return next(item for item in self.report["checks"] if item["id"] == check_id)

    def run_check(self, check_id: str, action: Callable[[], None]) -> None:
        record = self._check(check_id)
        try:
            action()
        except VerificationFailure as error:
            record["status"] = "failed"
            record["subject"] = error.subject
            record["failure_codes"] = [error.code]
        except Exception:
            record["status"] = "failed"
            record["failure_codes"] = ["internal_error"]
        else:
            record["status"] = "passed"

    def command(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        timeout: int = 120,
        code: str,
        subject: str,
    ) -> CommandResult:
        result = self.io.run(argv, cwd=cwd, env=env, timeout=timeout)
        if result.returncode != 0:
            raise VerificationFailure(code, subject)
        return result

    def record_tools(self) -> None:
        tools = (
            ("gh", ("gh", "--version")),
            ("cosign", ("cosign", "version")),
            ("slsa-verifier", ("slsa-verifier", "version")),
            ("docker", ("docker", "version", "--format", "{{.Client.Version}}")),
            ("docker-buildx", ("docker", "buildx", "version")),
        )
        observations = []
        for name, argv in tools:
            result = self.io.run(argv, timeout=20)
            version = "unavailable"
            if result.returncode == 0:
                version_output = (
                    result.stdout if result.stdout.strip() else result.stderr
                )
                candidate = next(
                    (
                        line.strip()
                        for line in version_output.splitlines()
                        if line.strip()
                    ),
                    "",
                )
                if (
                    candidate
                    and len(candidate) <= 200
                    and all(character.isprintable() for character in candidate)
                ):
                    version = candidate
            observations.append(
                {"name": name, "version": version, "source": "observed"}
            )
        self.report["tools"] = observations

    def verify_release_metadata(self) -> None:
        visibility = self.command(
            (
                "gh",
                "repo",
                "view",
                self.identity.repository,
                "--json",
                "visibility",
                "--jq",
                ".visibility",
            ),
            code="repository_visibility_unavailable",
            subject=self.identity.repository,
        ).stdout.strip()
        if visibility.lower() != "public":
            raise VerificationFailure(
                "release_repository_not_public", self.identity.repository
            )
        result = self.command(
            (
                "gh",
                "release",
                "view",
                self.identity.tag,
                "--repo",
                self.identity.repository,
                "--json",
                "assets,isDraft,isPrerelease,tagName",
            ),
            code="release_not_found",
            subject=self.identity.tag,
        )
        try:
            metadata = json.loads(result.stdout)
            assets = metadata["assets"]
        except (KeyError, TypeError, json.JSONDecodeError) as error:
            raise VerificationFailure(
                "invalid_release_metadata", self.identity.tag
            ) from error
        if (
            metadata.get("tagName") != self.identity.tag
            or metadata.get("isDraft") is not False
            or metadata.get("isPrerelease") is not True
        ):
            raise VerificationFailure("release_metadata_mismatch", self.identity.tag)
        if not isinstance(assets, list):
            raise VerificationFailure("invalid_release_metadata", self.identity.tag)
        parsed: dict[str, int] = {}
        for asset in assets:
            if (
                not isinstance(asset, dict)
                or not isinstance(asset.get("name"), str)
                or not isinstance(asset.get("size"), int)
            ):
                raise VerificationFailure("invalid_release_metadata", self.identity.tag)
            if asset["name"] in parsed:
                raise VerificationFailure("duplicate_release_asset", asset["name"])
            parsed[asset["name"]] = asset["size"]
        self.release_assets = parsed
        self.release_metadata_loaded = True

    def verify_source_identity(self) -> None:
        tag_target = self.command(
            ("git", "rev-parse", f"refs/tags/{self.identity.tag}^{{commit}}"),
            cwd=self.repo_root,
            code="tag_target_unavailable",
            subject=self.identity.tag,
        ).stdout.strip()
        head = self.command(
            ("git", "rev-parse", "HEAD"),
            cwd=self.repo_root,
            code="head_unavailable",
            subject=self.identity.tag,
        ).stdout.strip()
        default_branch_result = self.command(
            (
                "gh",
                "repo",
                "view",
                self.identity.repository,
                "--json",
                "defaultBranchRef",
                "--jq",
                ".defaultBranchRef.name",
            ),
            code="default_branch_unavailable",
            subject=self.identity.repository,
        )
        default_branch = default_branch_result.stdout.strip()
        if not default_branch or Path(default_branch).name != default_branch:
            raise VerificationFailure(
                "default_branch_unavailable", self.identity.repository
            )
        default_commit = self.command(
            ("git", "rev-parse", f"origin/{default_branch}"),
            cwd=self.repo_root,
            code="default_branch_unavailable",
            subject=default_branch,
        ).stdout.strip()
        for commit in (tag_target, head, default_commit):
            if COMMIT_RE.fullmatch(commit) is None:
                raise VerificationFailure("invalid_source_commit", self.identity.tag)
        source_to_tag = (
            self.io.run(
                (
                    "git",
                    "merge-base",
                    "--is-ancestor",
                    self.identity.source_ref,
                    tag_target,
                ),
                cwd=self.repo_root,
            ).returncode
            == 0
        )
        tag_to_default = (
            self.io.run(
                (
                    "git",
                    "merge-base",
                    "--is-ancestor",
                    tag_target,
                    default_commit,
                ),
                cwd=self.repo_root,
            ).returncode
            == 0
        )
        lineage = self.report["lineage"]
        lineage.update(
            {
                "tag_target": tag_target,
                "default_branch": default_branch,
                "default_branch_commit": default_commit,
                "tag_matches_source_tag": True,
                "head_matches_tag_target": head == tag_target,
                "source_ref_ancestor_or_equal": source_to_tag,
                "default_branch_reachable": tag_to_default,
            }
        )
        if head != tag_target:
            raise VerificationFailure("head_tag_target_mismatch", self.identity.tag)
        if not source_to_tag:
            raise VerificationFailure(
                "source_ref_not_in_tag_lineage", self.identity.source_ref
            )
        if not tag_to_default:
            raise VerificationFailure(
                "tag_target_not_on_default_branch", self.identity.tag
            )
        workflow = self.report["workflow"]
        if (
            workflow["ref"] is not None
            and workflow["ref"] != f"refs/tags/{self.identity.tag}"
        ):
            raise VerificationFailure("workflow_ref_mismatch", self.identity.tag)
        if workflow["head_sha"] is not None and workflow["head_sha"] != tag_target:
            raise VerificationFailure("workflow_head_mismatch", self.identity.tag)
        if workflow["event"] is not None and workflow["event"] not in {
            "push",
            "workflow_dispatch",
        }:
            raise VerificationFailure("workflow_event_mismatch", self.identity.tag)
        if workflow["run_url"] is not None:
            expected_run_url = f"https://github.com/{self.identity.repository}/actions/runs/{workflow['run_id']}"
            if workflow["run_url"] != expected_run_url:
                raise VerificationFailure(
                    "workflow_run_url_mismatch", self.identity.tag
                )

    def prepare_assets(self) -> None:
        if self.provided_assets_dir is not None:
            self.asset_dir = self.provided_assets_dir
            return
        assert self.temp_root is not None
        self.asset_dir = self.temp_root / "assets"
        self.asset_dir.mkdir()
        command = [
            "gh",
            "release",
            "download",
            self.identity.tag,
            "--repo",
            self.identity.repository,
            "--dir",
            str(self.asset_dir),
        ]
        for name in self.contract.all_assets:
            command.extend(("--pattern", name))
        self.command(
            command,
            code="release_asset_download_failed",
            subject=self.identity.tag,
            timeout=600,
        )

    def verify_inventory(self) -> None:
        self.prepare_assets()
        assert self.asset_dir is not None
        expected = set(self.contract.all_assets)
        finalization = set(expected_finalization_assets(self.identity))
        observed_metadata = (
            set(self.release_assets) if self.release_metadata_loaded else set()
        )
        try:
            observed_local = {
                path.name
                for path in self.asset_dir.iterdir()
                if path.is_file() and not path.is_symlink()
            }
            unsafe = [
                path.name
                for path in self.asset_dir.iterdir()
                if path.is_symlink() or not path.is_file()
            ]
        except OSError as error:
            raise VerificationFailure(
                "asset_directory_unavailable", self.identity.tag
            ) from error
        if unsafe:
            raise VerificationFailure("unsafe_release_asset", sorted(unsafe)[0])
        if (
            not expected.issubset(observed_metadata)
            or not (observed_metadata - expected).issubset(finalization)
            or not expected.issubset(observed_local)
            or not (observed_local - expected).issubset(finalization)
        ):
            raise VerificationFailure(
                "release_asset_inventory_mismatch", self.identity.tag
            )
        finalization_present = observed_metadata - expected
        if not (observed_local - expected).issubset(finalization_present):
            raise VerificationFailure(
                "release_asset_inventory_mismatch", self.identity.tag
            )
        for name in expected:
            if self.release_assets[name] != (self.asset_dir / name).stat().st_size:
                raise VerificationFailure("release_asset_size_mismatch", name)
        artifacts = []
        for name in sorted(expected):
            path = self.asset_dir / name
            if name == self.contract.provenance:
                role, payload_name = "provenance", None
            elif name.endswith(".sig"):
                role, payload_name = "signature", name.removesuffix(".sig")
            elif name.endswith(".pem"):
                role, payload_name = "certificate", name.removesuffix(".pem")
            else:
                role, payload_name = "payload", None
            artifacts.append(
                {
                    "name": name,
                    "role": role,
                    "payload_name": payload_name,
                    "size_bytes": path.stat().st_size,
                    "sha256": file_sha256(path),
                    "verification": {
                        "checksum": "failed" if role == "payload" else "not_applicable",
                        "signature": "failed"
                        if role == "payload"
                        else "not_applicable",
                        "provenance": "failed"
                        if role == "payload"
                        else "not_applicable",
                    },
                }
            )
        self.report["artifacts"] = artifacts
        counts = {
            "payloads": sum(item["role"] == "payload" for item in artifacts),
            "signatures": sum(item["role"] == "signature" for item in artifacts),
            "certificates": sum(item["role"] == "certificate" for item in artifacts),
            "provenance": sum(item["role"] == "provenance" for item in artifacts),
            "total": len(artifacts),
        }
        self.report["artifact_scope"]["observed_counts"] = counts
        if counts != EXPECTED_COUNTS:
            raise VerificationFailure("release_asset_count_mismatch", self.identity.tag)
        if finalization_present:
            warning_code = (
                "final_evidence_assets_excluded"
                if finalization_present == finalization
                else "partial_final_evidence_assets_excluded"
            )
            self.report["warnings"].append(
                {"code": warning_code, "subject": self.identity.tag}
            )

    def _payload_artifact(self, name: str) -> dict[str, Any]:
        return next(
            item
            for item in self.report["artifacts"]
            if item["name"] == name and item["role"] == "payload"
        )

    def verify_checksums(self) -> None:
        assert self.asset_dir is not None
        verify_checksum_files(self.asset_dir, self.identity)

    def _certificate_path(self, encoded_path: Path) -> Path:
        assert self.temp_root is not None
        body = require_regular_file(encoded_path).read_bytes()
        if body.startswith(b"-----BEGIN CERTIFICATE-----"):
            return encoded_path
        try:
            decoded = base64.b64decode(body.strip(), validate=True)
        except ValueError as error:
            raise VerificationFailure(
                "invalid_signing_certificate", encoded_path.name
            ) from error
        if not decoded.startswith(b"-----BEGIN CERTIFICATE-----"):
            raise VerificationFailure("invalid_signing_certificate", encoded_path.name)
        cert_dir = self.temp_root / "certificates"
        cert_dir.mkdir(exist_ok=True)
        target = cert_dir / encoded_path.name
        target.write_bytes(decoded)
        return target

    def verify_cosign(self) -> None:
        assert self.asset_dir is not None
        identity = (
            f"{SOURCE_URL}/.github/workflows/release.yml@refs/tags/{self.identity.tag}"
        )
        for name in self.contract.payloads:
            certificate = self._certificate_path(self.asset_dir / f"{name}.pem")
            self.command(
                (
                    "cosign",
                    "verify-blob",
                    str(self.asset_dir / name),
                    "--signature",
                    str(self.asset_dir / f"{name}.sig"),
                    "--certificate",
                    str(certificate),
                    "--certificate-oidc-issuer",
                    COSIGN_ISSUER,
                    "--certificate-identity",
                    identity,
                ),
                code="cosign_verification_failed",
                subject=name,
                timeout=180,
            )
            self._payload_artifact(name)["verification"]["signature"] = "passed"

    def verify_slsa(self) -> None:
        assert self.asset_dir is not None
        provenance = self.asset_dir / self.contract.provenance
        verify_provenance_subjects(self.asset_dir, self.contract)
        for name in self.contract.payloads:
            self.command(
                (
                    "slsa-verifier",
                    "verify-artifact",
                    str(self.asset_dir / name),
                    "--provenance-path",
                    str(provenance),
                    "--source-uri",
                    SOURCE_URI,
                    "--source-tag",
                    self.identity.tag,
                ),
                code="slsa_verification_failed",
                subject=name,
                timeout=180,
            )
            verification = self._payload_artifact(name)["verification"]
            verification["checksum"] = "passed"
            verification["provenance"] = "passed"

    def verify_image_lock(self) -> None:
        assert self.asset_dir is not None
        tag_target = self.report["lineage"]["tag_target"]
        if not isinstance(tag_target, str):
            raise VerificationFailure("source_identity_unavailable", self.identity.tag)
        self.locked_images = verify_image_lock_and_metadata(
            self.asset_dir, self.identity, tag_target
        )

    def manifest_data(self) -> Mapping[str, Any]:
        try:
            data = yaml.safe_load(self.manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError) as error:
            raise VerificationFailure(
                "invalid_manifest", self.manifest_path.name
            ) from error
        if not isinstance(data, dict):
            raise VerificationFailure("invalid_manifest", self.manifest_path.name)
        return data

    def verify_capsule(self) -> None:
        assert self.asset_dir is not None
        tag_target = self.report["lineage"]["tag_target"]
        if not isinstance(tag_target, str) or not self.locked_images:
            raise VerificationFailure("binding_prerequisite_failed", "release-capsule")
        verify_capsule_bindings(
            self.asset_dir,
            self.manifest_path,
            self.manifest_data(),
            self.identity,
            tag_target,
            self.contract,
            self.locked_images,
        )

    def verify_sboms(self) -> None:
        assert self.asset_dir is not None
        if not self.locked_images:
            raise VerificationFailure("binding_prerequisite_failed", "SPDX-subjects")
        verify_sbom_bindings(
            self.asset_dir, self.identity, self.contract, self.locked_images
        )

    def verify_grype(self) -> None:
        assert self.asset_dir is not None
        if not self.locked_images:
            raise VerificationFailure("binding_prerequisite_failed", "Grype-subjects")
        verify_grype_bindings(self.asset_dir, self.locked_images)

    def anonymous_environment(self) -> tuple[dict[str, str], Path]:
        assert self.temp_root is not None
        docker_config = self.temp_root / "empty-docker-config"
        docker_config.mkdir(exist_ok=True)
        (docker_config / "config.json").write_text("{}\n", encoding="utf-8")
        environment = dict(os.environ)
        for key in tuple(environment):
            if key == "DOCKER_AUTH_CONFIG" or key.startswith("REGISTRY_AUTH"):
                environment.pop(key, None)
        environment["DOCKER_CONFIG"] = str(docker_config)
        return environment, docker_config

    def verify_anonymous_images(self) -> None:
        if not self.locked_images:
            raise VerificationFailure("binding_prerequisite_failed", "release-images")
        environment, docker_config = self.anonymous_environment()
        for component, digest_ref in self.locked_images.items():
            package = self.command(
                ("gh", "api", f"orgs/registrystack/packages/container/{component}"),
                code="package_metadata_unavailable",
                subject=component,
            )
            try:
                package_data = json.loads(package.stdout)
            except json.JSONDecodeError as error:
                raise VerificationFailure(
                    "invalid_package_metadata", component
                ) from error
            if not isinstance(package_data, dict):
                raise VerificationFailure("invalid_package_metadata", component)
            repository = package_data.get("repository")
            if (
                package_data.get("visibility") != "public"
                or not isinstance(repository, dict)
                or repository.get("full_name") != REPOSITORY
            ):
                raise VerificationFailure("package_not_public_or_linked", component)
            tag_ref = f"{IMAGE_REPOSITORIES[component]}:{self.identity.tag}"
            self.command(
                (
                    "docker",
                    "--config",
                    str(docker_config),
                    "pull",
                    "--platform",
                    "linux/amd64",
                    tag_ref,
                ),
                env=environment,
                timeout=600,
                code="anonymous_tag_pull_failed",
                subject=component,
            )
            self.command(
                (
                    "docker",
                    "--config",
                    str(docker_config),
                    "pull",
                    "--platform",
                    "linux/amd64",
                    digest_ref,
                ),
                env=environment,
                timeout=600,
                code="anonymous_digest_pull_failed",
                subject=component,
            )
            manifest_result = self.command(
                (
                    "docker",
                    "buildx",
                    "imagetools",
                    "inspect",
                    "--format",
                    "{{json .Manifest}}",
                    tag_ref,
                ),
                env=environment,
                code="tag_digest_resolution_failed",
                subject=component,
            )
            try:
                manifest = json.loads(manifest_result.stdout)
            except json.JSONDecodeError as error:
                raise VerificationFailure("invalid_tag_manifest", component) from error
            expected_digest = digest_ref.rsplit("@", 1)[1]
            if (
                not isinstance(manifest, dict)
                or manifest.get("digest") != expected_digest
            ):
                raise VerificationFailure("tag_digest_lock_mismatch", component)
        self._ensure_image_records()
        for record in self.report["images"]:
            record["anonymous_tag_pull"] = "passed"
            record["anonymous_digest_pull"] = "passed"

    def _ensure_image_records(self) -> None:
        if self.report["images"] or not self.locked_images:
            return
        self.report["images"] = [
            {
                "component": component,
                "repository": IMAGE_REPOSITORIES[component],
                "tag_ref": f"{IMAGE_REPOSITORIES[component]}:{self.identity.tag}",
                "digest_ref": digest_ref,
                "digest": digest_ref.rsplit("@", 1)[1],
                "anonymous_tag_pull": "failed",
                "anonymous_digest_pull": "failed",
                "config_user": None,
                "labels": {"source": None, "revision": None, "version": None},
                "reported_version": None,
            }
            for component, digest_ref in sorted(self.locked_images.items())
        ]

    def inspect_image_configs(self) -> None:
        if self.image_configs:
            return
        if not self.locked_images:
            raise VerificationFailure("binding_prerequisite_failed", "release-images")
        environment, _ = self.anonymous_environment()
        for component, digest_ref in self.locked_images.items():
            result = self.command(
                (
                    "docker",
                    "buildx",
                    "imagetools",
                    "inspect",
                    "--format",
                    "{{json .Image.Config}}",
                    digest_ref,
                ),
                env=environment,
                code="image_config_inspection_failed",
                subject=component,
            )
            try:
                config = json.loads(result.stdout)
            except json.JSONDecodeError as error:
                raise VerificationFailure("invalid_image_config", component) from error
            if not isinstance(config, dict):
                raise VerificationFailure("invalid_image_config", component)
            self.image_configs[component] = config
        self._ensure_image_records()

    def verify_oci_labels(self) -> None:
        self.inspect_image_configs()
        expected = {
            "source": SOURCE_URL,
            "revision": self.report["lineage"]["tag_target"],
            "version": self.identity.version,
        }
        for component, config in self.image_configs.items():
            try:
                OCI_HELPERS.require_oci_labels(
                    self.locked_images[component], config, expected
                )
            except OCI_HELPERS.CheckError as error:
                raise VerificationFailure("oci_label_mismatch", component) from error
            labels = config["Labels"]
            record = next(
                item for item in self.report["images"] if item["component"] == component
            )
            record["labels"] = {key: labels[label] for key, label in OCI_LABELS.items()}

    def verify_non_root_users(self) -> None:
        self.inspect_image_configs()
        for component, config in self.image_configs.items():
            if config.get("User") != "65532":
                raise VerificationFailure("image_user_mismatch", component)
            record = next(
                item for item in self.report["images"] if item["component"] == component
            )
            record["config_user"] = "65532"

    def verify_service_versions(self) -> None:
        if not self.locked_images:
            raise VerificationFailure("binding_prerequisite_failed", "release-images")
        environment, docker_config = self.anonymous_environment()
        self._ensure_image_records()
        for component, digest_ref in self.locked_images.items():
            result = self.command(
                (
                    "docker",
                    "--config",
                    str(docker_config),
                    "run",
                    "--rm",
                    "--platform",
                    "linux/amd64",
                    digest_ref,
                    "--version",
                ),
                env=environment,
                timeout=120,
                code="service_version_execution_failed",
                subject=component,
            )
            expected = f"{component} {self.identity.version}\n"
            if result.stdout != expected or result.stderr:
                raise VerificationFailure("service_version_mismatch", component)
            record = next(
                item for item in self.report["images"] if item["component"] == component
            )
            record["reported_version"] = result.stdout.strip()

    def verify_image_inputs(self) -> None:
        assert self.asset_dir is not None and self.temp_root is not None
        if not self.locked_images:
            raise VerificationFailure("binding_prerequisite_failed", "image-inputs")
        sums = strict_sha256s(
            self.asset_dir / "image-binaries.SHA256SUMS",
            {
                "RELEASE_BUILDER_IMAGE",
                "registry-notary",
                "registry-notary-cel-worker",
                "registry-relay",
                "registry-relay-rhai-worker",
            },
        )
        try:
            builder_ref = require_regular_file(
                self.asset_dir / "release-builder-image.txt"
            ).read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise VerificationFailure(
                "invalid_builder_image_evidence", "release-builder-image.txt"
            ) from error
        stripped_builder_ref = builder_ref.strip()
        if (
            builder_ref not in {stripped_builder_ref, f"{stripped_builder_ref}\n"}
            or IMAGE_DIGEST_RE.fullmatch(stripped_builder_ref) is None
            or file_sha256(self.asset_dir / "release-builder-image.txt")
            != sums["RELEASE_BUILDER_IMAGE"]
        ):
            raise VerificationFailure(
                "builder_image_checksum_mismatch", "release-builder-image.txt"
            )
        environment, docker_config = self.anonymous_environment()
        extract_dir = self.temp_root / "image-inputs"
        extract_dir.mkdir(exist_ok=True)
        for component, binary_names in IMAGE_INPUTS.items():
            digest_ref = self.locked_images[component]
            created = self.command(
                (
                    "docker",
                    "--config",
                    str(docker_config),
                    "create",
                    "--platform",
                    "linux/amd64",
                    digest_ref,
                    "--version",
                ),
                env=environment,
                code="image_container_create_failed",
                subject=component,
            )
            container_id = created.stdout.strip()
            if re.fullmatch(r"[0-9a-f]{12,64}", container_id) is None:
                raise VerificationFailure("invalid_container_id", component)
            try:
                for binary_name in binary_names:
                    destination = extract_dir / binary_name
                    self.command(
                        (
                            "docker",
                            "--config",
                            str(docker_config),
                            "cp",
                            f"{container_id}:/usr/local/bin/{binary_name}",
                            str(destination),
                        ),
                        env=environment,
                        code="image_binary_extract_failed",
                        subject=binary_name,
                    )
                    actual = file_sha256(
                        require_regular_file(destination, "image_binary_extract_failed")
                    )
                    if actual != sums[binary_name]:
                        raise VerificationFailure(
                            "image_binary_checksum_mismatch", binary_name
                        )
                    sbom_name = f"image-input-{binary_name}.spdx.json"
                    if not RELEASE_HELPERS.spdx_subject_contains_file_digest(
                        read_json(self.asset_dir / sbom_name), binary_name, actual
                    ):
                        raise VerificationFailure(
                            "image_input_sbom_subject_mismatch", binary_name
                        )
            finally:
                self.io.run(
                    (
                        "docker",
                        "--config",
                        str(docker_config),
                        "rm",
                        "-f",
                        container_id,
                    ),
                    env=environment,
                )

    def verify_registryctl_journey(self) -> None:
        assert self.asset_dir is not None and self.temp_root is not None
        binary = require_regular_file(
            self.asset_dir / f"registryctl-{self.identity.tag}-linux-amd64"
        )
        binary.chmod(0o755)
        version = self.command(
            (str(binary), "--version"),
            code="registryctl_version_failed",
            subject="registryctl",
        )
        if version.stdout != f"registryctl {self.identity.version}\n" or version.stderr:
            raise VerificationFailure("registryctl_version_mismatch", "registryctl")
        journey = self.temp_root / "registryctl-journey"
        project = journey / "registry-project"
        journey.mkdir()
        environment = dict(os.environ)
        environment["CI"] = "1"
        commands = (
            (str(binary), "init", "--from", "http", "--project-dir", str(project)),
            (str(binary), "authoring", "editor", "--project-dir", str(project)),
            (str(binary), "test", "--project-dir", str(project)),
            (
                str(binary),
                "check",
                "--project-dir",
                str(project),
                "--environment",
                "local",
                "--explain",
            ),
            (
                str(binary),
                "build",
                "--project-dir",
                str(project),
                "--environment",
                "local",
            ),
        )
        for command in commands:
            self.command(
                command,
                cwd=journey,
                env=environment,
                timeout=180,
                code="registryctl_journey_failed",
                subject="registryctl",
            )
        manifest = read_json(project / ".registry-stack-editor/manifest.json")
        if not _contains_exact_string(manifest, self.identity.version):
            raise VerificationFailure(
                "registryctl_editor_version_mismatch", "registryctl"
            )
        expected_outputs = (
            project / "registry-stack.yaml",
            project / "integrations/person-record/integration.yaml",
            project / "environments/local.yaml",
            project / ".registry-stack/build/local/reviewable/review.json",
            project / ".registry-stack/build/local/private/relay/config/relay.yaml",
            project / ".registry-stack/build/local/private/notary/config/notary.yaml",
        )
        for output in expected_outputs:
            require_regular_file(output, "registryctl_journey_output_missing")

    def verify_archived_docs(self) -> None:
        base = f"https://docs.registrystack.org/v/{self.identity.version}"
        routes = (
            (f"{base}/", (self.identity.version, "noindex,follow")),
            (f"{base}/reference/registryctl/", (self.identity.version, "registryctl")),
            (
                f"{base}/tutorials/author-registry-project/",
                (
                    self.identity.version,
                    "registryctl init --from http",
                    "noindex,follow",
                ),
            ),
            (
                f"{base}/tutorials/author-registry-project.md",
                (self.identity.version, "registryctl init --from http"),
            ),
            (
                f"{base}/reference/apis/registry-relay/",
                (self.identity.version, "noindex,follow"),
            ),
            (
                f"{base}/reference/apis/registry-notary/",
                (self.identity.version, "noindex,follow"),
            ),
        )
        for url, markers in routes:
            matched = False
            for attempt in range(self.docs_attempts):
                response = self.io.get(url)
                if response.status == 200 and all(
                    marker in response.body for marker in markers
                ):
                    matched = True
                    break
                if attempt + 1 < self.docs_attempts:
                    self.io.sleep(self.docs_retry_seconds)
            if not matched:
                raise VerificationFailure("archived_doc_probe_failed", url)

    def finalize(self) -> int:
        completed = datetime.now(UTC)
        self.report["workflow"]["completed_at"] = completed.isoformat().replace(
            "+00:00", "Z"
        )
        self.report["workflow"]["duration_seconds"] = max(
            0, int((completed - self.started).total_seconds())
        )
        statuses = [item["status"] for item in self.report["checks"]]
        if all(status == "passed" for status in statuses):
            self.report["status"] = "passed"
            exit_code = 0
        elif any(status == "failed" for status in statuses):
            self.report["status"] = "failed"
            exit_code = 1
        else:
            self.report["status"] = "incomplete"
            exit_code = 2
        assert_closed_report(self.report)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_path.write_text(
            json.dumps(self.report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return exit_code

    def verify(self) -> int:
        if self.dry_validate:
            self.report["warnings"] = [
                {"code": "dry_validation_only", "subject": self.identity.tag}
            ]
            return self.finalize()
        try:
            with tempfile.TemporaryDirectory(
                prefix="registry-stack-verify-"
            ) as directory:
                self.temp_root = Path(directory)
                self.record_tools()
                self.run_check("release_metadata", self.verify_release_metadata)
                self.run_check("source_identity", self.verify_source_identity)
                self.run_check("asset_inventory", self.verify_inventory)
                if self._check("asset_inventory")["status"] == "passed":
                    self.run_check("checksums", self.verify_checksums)
                    self.run_check("cosign_signatures", self.verify_cosign)
                    self.run_check("slsa_provenance", self.verify_slsa)
                    self.run_check("image_lock_bindings", self.verify_image_lock)
                    self.run_check("capsule_bindings", self.verify_capsule)
                    self.run_check("sbom_bindings", self.verify_sboms)
                    self.run_check("grype_bindings", self.verify_grype)
                    self.run_check("image_input_bindings", self.verify_image_inputs)
                    self.run_check(
                        "anonymous_image_access", self.verify_anonymous_images
                    )
                    self.run_check("oci_labels", self.verify_oci_labels)
                    self.run_check("non_root_users", self.verify_non_root_users)
                    self.run_check("service_versions", self.verify_service_versions)
                    self.run_check(
                        "registryctl_authoring_build", self.verify_registryctl_journey
                    )
                    self.run_check("archived_docs", self.verify_archived_docs)
        except Exception:
            if not any(item["status"] == "failed" for item in self.report["checks"]):
                self._check("release_metadata")["status"] = "failed"
                self._check("release_metadata")["failure_codes"] = ["internal_error"]
        return self.finalize()


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify a published RegistryStack v0.12+ release."
    )
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument(
        "--assets-dir",
        type=Path,
        help="Use an existing exact asset directory instead of downloading assets.",
    )
    parser.add_argument(
        "--dry-validate",
        action="store_true",
        help="Validate the local manifest and closed report contract without publication access; returns incomplete.",
    )
    parser.add_argument("--docs-attempts", type=int, default=6)
    parser.add_argument("--docs-retry-seconds", type=float, default=10.0)
    args = parser.parse_args(argv)
    if args.docs_attempts < 1 or args.docs_retry_seconds < 0:
        parser.error(
            "documentation retry values must be non-negative and attempts must be at least one"
        )
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        verifier = PublishedReleaseVerifier(
            args.manifest,
            args.output_json,
            repo_root=args.repo_root,
            assets_dir=args.assets_dir,
            dry_validate=args.dry_validate,
            docs_attempts=args.docs_attempts,
            docs_retry_seconds=args.docs_retry_seconds,
        )
        return verifier.verify()
    except VerificationFailure as error:
        # Manifest failures happen before the release identity can be trusted.
        # Preserve the closed result shape while representing unknown identity
        # fields as null and exposing only a normalized failure code.
        placeholder = ReleaseIdentity(
            release_id="unknown",
            version="0.0.0",
            tag="unknown",
            source_ref="0" * 40,
            repository=REPOSITORY,
            manifest_sha256="0" * 64,
        )
        fallback = initial_report(placeholder)
        fallback["status"] = "failed"
        fallback["release"].update(
            {
                "release_id": None,
                "version": None,
                "tag": None,
                "manifest_sha256": None,
            }
        )
        fallback["lineage"]["manifest_source_ref"] = None
        failed_check = next(
            item for item in fallback["checks"] if item["id"] == "release_metadata"
        )
        failed_check["status"] = "failed"
        failed_check["subject"] = error.subject
        failed_check["failure_codes"] = [error.code]
        assert_closed_report(fallback)
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        args.output_json.write_text(
            json.dumps(fallback, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
