#!/usr/bin/env python3
"""Generate and assemble the signed RegistryReleaseLockV1 release artifact."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ID = "io.registrystack.registry_release_lock"
SCHEMA_VERSION = "1.0"
REPOSITORY = "registrystack/registry-stack"
WORKFLOW = ".github/workflows/release.yml"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE = re.compile(r"^[^@\s]+@(?P<digest>sha256:[0-9a-f]{64})$")
VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
STARTERS = {
    "http": ROOT / "crates/registryctl/assets/project-starters/bounded-http/registry-stack.yaml",
    "spreadsheet": ROOT
    / "crates/registryctl/assets/project-starters/spreadsheet/registry-stack.yaml",
    "dhis2-tracker": ROOT
    / "crates/registryctl/tests/fixtures/project-authoring/dhis2-tracker/registry-stack.yaml",
    "opencrvs-dci": ROOT
    / "crates/registryctl/tests/fixtures/project-authoring/opencrvs/registry-stack.yaml",
    "fhir-r4": ROOT
    / "crates/registryctl/tests/fixtures/project-authoring/fhir-r4-coverage-active/registry-stack.yaml",
    "snapshot": ROOT
    / "crates/registryctl/tests/fixtures/project-authoring/snapshot-exact/registry-stack.yaml",
}
PLATFORMS = {
    "linux-amd64": "linux-amd64",
    "linux-arm64": "linux-arm64",
    "macos-arm64": "macos-arm64",
}


def reject_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle, object_pairs_hook=reject_duplicate_object)


def write_regular(path: Path, content: bytes) -> None:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError(f"output must be a regular non-symlink file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def canonical_json(value: Any) -> bytes:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if not encoded.isascii():
        raise ValueError("release lock generator accepts only ASCII contract values")
    return encoded


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def image(value: Any, label: str) -> tuple[str, str]:
    if not isinstance(value, str):
        raise ValueError(f"{label} image identity must be text")
    match = IMAGE.fullmatch(value)
    if match is None:
        raise ValueError(f"{label} image identity must be immutable")
    return value, match.group("digest")


def starter_binding(starter_id: str, path: Path, version: str) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    starter = re.search(
        r"(?m)^starter:\n"
        rf"  id: {re.escape(starter_id)}\n"
        r"  release: (?P<release>[^\n]+)\n"
        r"  content_digest: (?P<digest>sha256:[0-9a-f]{64})\n",
        text,
    )
    if starter is None:
        raise ValueError(f"starter {starter_id} has no closed provenance block")
    if starter.group("release") != version:
        raise ValueError(f"starter {starter_id} release does not match {version}")
    return {
        "id": starter_id,
        "release": version,
        "content_digest": starter.group("digest"),
    }


def product_recipe(product: str, lane: str | None = None) -> dict[str, list[str]]:
    prefix = ["product-action"]
    if lane is not None:
        prefix.append(lane)
    return {
        "serve": [*prefix, "serve"],
        "prepare_state_store": [*prefix, "prepare_state_store"],
        "initialize_state": [*prefix, "initialize_state"],
        "verify_state": [*prefix, "verify_state"],
        "health_probe": ["CMD", f"/usr/local/bin/{product}", "healthcheck"],
    }


def create_payload(args: argparse.Namespace) -> int:
    if VERSION.fullmatch(args.version) is None or not args.version.startswith("1."):
        raise ValueError("release lock generation requires a stable 1.x version")
    if HEX40.fullmatch(args.source_sha) is None:
        raise ValueError("source SHA must be 40 lowercase hexadecimal characters")
    tag = f"v{args.version}"
    image_lock = read_json(args.image_lock)
    if not isinstance(image_lock, dict):
        raise ValueError("legacy image lock must be an object")
    if image_lock.get("release_tag") != tag:
        raise ValueError("legacy image lock release tag does not match")
    if image_lock.get("manifest_source_ref") != args.source_sha:
        raise ValueError("legacy image lock source SHA does not match")
    images = image_lock.get("images")
    if not isinstance(images, dict) or set(images) != {
        "registry-relay",
        "registry-notary",
        "postgresql",
    }:
        raise ValueError("legacy image lock image roster is not closed")

    relay, relay_digest = image(images["registry-relay"], "Relay")
    notary, notary_digest = image(images["registry-notary"], "Notary")
    postgresql, postgresql_digest = image(images["postgresql"], "PostgreSQL")

    registryctl_artifacts = []
    for platform, suffix in PLATFORMS.items():
        filename = f"registryctl-{tag}-{suffix}"
        artifact = args.asset_dir / filename
        if not artifact.is_file() or artifact.is_symlink():
            raise ValueError(f"missing regular Registryctl artifact {filename}")
        registryctl_artifacts.append(
            {
                "platform": platform,
                "filename": filename,
                "sha256": sha256_file(artifact),
            }
        )

    def locked_image(identity: str, digest: str) -> dict[str, Any]:
        return {
            "identity": identity,
            "platforms": [
                {"platform": "linux-amd64", "manifest_digest": digest}
            ],
        }

    payload = {
        "schema_id": SCHEMA_ID,
        "schema_version": SCHEMA_VERSION,
        "release": {
            "product_version": args.version,
            "release_tag": tag,
            "source_repository": REPOSITORY,
            "source_workflow": WORKFLOW,
            "source_ref": f"refs/tags/{tag}",
            "source_sha": args.source_sha,
        },
        "registryctl_artifacts": registryctl_artifacts,
        "images": {
            "relay": locked_image(relay, relay_digest),
            "notary": locked_image(notary, notary_digest),
            "postgresql_state_plane": locked_image(postgresql, postgresql_digest),
            # The reviewed PostgreSQL image supplies `sleep` without introducing
            # another mutable or separately trusted supporting image.
            "private_namespace_holder": locked_image(
                postgresql, postgresql_digest
            ),
        },
        "runtime": {
            "relay_public": product_recipe("registry-relay", "relay-public"),
            "relay_consultation": product_recipe(
                "registry-relay", "relay-consultation"
            ),
            "notary": product_recipe("registry-notary"),
            "postgresql_state_plane": {
                "command": ["postgres"],
                "health_probe": ["CMD-SHELL", "pg_isready -U postgres"],
            },
            "private_namespace_holder": {
                "command": ["sleep", "infinity"],
                "health_probe": ["CMD-SHELL", "kill -0 1"],
            },
        },
        "supported_contracts": {
            "config_bundle_schema": "registry.platform.config_bundle.v1",
            "config_signature_schema": (
                "registry.platform.config_bundle_signatures.v1"
            ),
            "trust_anchor_schema": "registry.platform.config_trust_anchor.v1",
            "anchor_transition_schema": "registry.platform.anchor_transition@1.0",
            "relay_config_schema": (
                "https://id.registrystack.org/schemas/"
                "registry-relay/registry-relay.config.schema.json"
            ),
            "notary_config_schema": (
                "https://id.registrystack.org/schemas/"
                "registry-notary/registry-notary.config.schema.json"
            ),
        },
        "embedded_starters": [
            starter_binding(starter_id, STARTERS[starter_id], args.version)
            for starter_id in sorted(STARTERS)
        ],
        "minimum_compose_version": "2.35.0",
        "postgresql_major_version": 17,
    }
    write_regular(args.output, canonical_json(payload))
    return 0


def assemble(args: argparse.Namespace) -> int:
    payload = args.payload.read_bytes()
    decoded = json.loads(payload, object_pairs_hook=reject_duplicate_object)
    if canonical_json(decoded) != payload:
        raise ValueError("signed release-lock payload is not canonical JSON")
    bundle = read_json(args.bundle)
    if not isinstance(bundle, dict) or bundle.get("mediaType") != (
        "application/vnd.dev.sigstore.bundle.v0.3+json"
    ):
        raise ValueError("release lock requires a Cosign v3 Sigstore v0.3 bundle")
    envelope = {
        "schema_id": SCHEMA_ID,
        "schema_version": SCHEMA_VERSION,
        "signed_payload": base64.b64encode(payload).decode("ascii"),
        "sigstore_bundle": bundle,
    }
    write_regular(args.output, json.dumps(envelope, indent=2, sort_keys=True).encode() + b"\n")
    return 0


def check(args: argparse.Namespace) -> int:
    envelope = read_json(args.input)
    if not isinstance(envelope, dict) or set(envelope) != {
        "schema_id",
        "schema_version",
        "signed_payload",
        "sigstore_bundle",
    }:
        raise ValueError("release lock envelope is not closed")
    if envelope["schema_id"] != SCHEMA_ID or envelope["schema_version"] != SCHEMA_VERSION:
        raise ValueError("release lock envelope schema is unsupported")
    payload = base64.b64decode(envelope["signed_payload"], validate=True)
    if canonical_json(
        json.loads(payload, object_pairs_hook=reject_duplicate_object)
    ) != payload:
        raise ValueError("release lock signed payload is not canonical JSON")
    if envelope["sigstore_bundle"].get("mediaType") != (
        "application/vnd.dev.sigstore.bundle.v0.3+json"
    ):
        raise ValueError("release lock does not carry a Sigstore v0.3 bundle")
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    subparsers = result.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create-payload")
    create.add_argument("--version", required=True)
    create.add_argument("--source-sha", required=True)
    create.add_argument("--asset-dir", required=True, type=Path)
    create.add_argument("--image-lock", required=True, type=Path)
    create.add_argument("--output", required=True, type=Path)
    create.set_defaults(handler=create_payload)
    assemble_parser = subparsers.add_parser("assemble")
    assemble_parser.add_argument("--payload", required=True, type=Path)
    assemble_parser.add_argument("--bundle", required=True, type=Path)
    assemble_parser.add_argument("--output", required=True, type=Path)
    assemble_parser.set_defaults(handler=assemble)
    check_parser = subparsers.add_parser("check")
    check_parser.add_argument("--input", required=True, type=Path)
    check_parser.set_defaults(handler=check)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        return args.handler(args)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
