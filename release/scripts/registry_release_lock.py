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
    "spreadsheet": ROOT / "crates/registryctl/assets/project-starters/spreadsheet/registry-stack.yaml",
}
PLATFORMS = {
    "linux-amd64": "linux-amd64",
    "linux-arm64": "linux-arm64",
    "macos-arm64": "macos-arm64",
}
OCI_IMAGE_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
MAX_OCI_INDEX_BYTES = 4 * 1024 * 1024


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


def read_platform_manifest_from_index(
    path: Path,
    label: str,
    expected_index_digest: str,
) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} index must be a regular non-symlink file")
    if path.stat().st_size > MAX_OCI_INDEX_BYTES:
        raise ValueError(f"{label} index exceeds the 4 MiB limit")
    body = path.read_bytes()
    actual_index_digest = f"sha256:{hashlib.sha256(body).hexdigest()}"
    if actual_index_digest != expected_index_digest:
        raise ValueError(f"{label} index bytes do not match the locked image identity")
    index = json.loads(
        body.decode("utf-8"),
        object_pairs_hook=reject_duplicate_object,
    )
    return select_platform_manifest(index, "linux/amd64")


def select_platform_manifest(index: Any, platform: str) -> str:
    if platform != "linux/amd64":
        raise ValueError("release lock supports only the linux/amd64 image platform")
    if not isinstance(index, dict) or not isinstance(index.get("manifests"), list):
        raise ValueError("OCI image index must contain a manifests array")
    matches = []
    for descriptor in index["manifests"]:
        if not isinstance(descriptor, dict):
            raise ValueError("OCI image index manifest descriptors must be objects")
        descriptor_platform = descriptor.get("platform")
        if not isinstance(descriptor_platform, dict):
            continue
        if (
            descriptor_platform.get("os") == "linux"
            and descriptor_platform.get("architecture") == "amd64"
            and descriptor_platform.get("variant") in {None, ""}
        ):
            if descriptor.get("mediaType") != OCI_IMAGE_MANIFEST_MEDIA_TYPE:
                raise ValueError(
                    "linux/amd64 application descriptor has an unsupported media type"
                )
            digest = descriptor.get("digest")
            if not isinstance(digest, str) or DIGEST.fullmatch(digest) is None:
                raise ValueError(
                    "linux/amd64 application descriptor has an invalid digest"
                )
            matches.append(digest)
    if len(matches) != 1:
        raise ValueError(
            "OCI image index must contain exactly one linux/amd64 application manifest"
        )
    return matches[0]


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


def runtime_mount(source: str, target: str, read_only: bool) -> dict[str, Any]:
    return {"source": source, "target": target, "read_only": read_only}


def secret_projection(
    file_id: str, target: str, *, uid: str = "65532"
) -> dict[str, str]:
    return {
        "file_id": file_id,
        "target": target,
        "mode": "0400",
        "uid": uid,
        "gid": uid,
    }


def product_recipe(product: str, lane: str | None = None) -> dict[str, Any]:
    assert lane is not None
    health_port = 8080 if product == "registry-relay" else 8081
    prefix = ["product-action"]
    if product == "registry-relay":
        prefix.append(lane)
    common_mounts = [
        runtime_mount("bundle", "/run/registry/bundle", True),
        runtime_mount("anchor", "/run/registry/anchor", True),
    ]
    audit = runtime_mount("audit", "/var/lib/registry/audit", False)
    state = runtime_mount(
        "anti_rollback_state", "/var/lib/registry/state", False
    )
    state_read_only = runtime_mount(
        "anti_rollback_state", "/var/lib/registry/state", True
    )
    database_ca = secret_projection(
        "postgresql-tls-certificate", "/run/secrets/postgresql-ca.pem"
    )
    serve_secrets: list[dict[str, str]]
    if lane == "relay-public":
        preparation_secrets = []
        initialization_secrets = []
        serve_secrets = [
            secret_projection(
                "relay-public-tls-certificate",
                "/run/secrets/relay-public-tls.crt",
            ),
            secret_projection(
                "relay-public-tls-private-key",
                "/run/secrets/relay-public-tls.key",
            ),
        ]
    elif lane == "relay-consultation":
        preparation_secrets = [database_ca]
        initialization_secrets = [database_ca]
        serve_secrets = [
            database_ca,
            secret_projection(
                "relay-consultation-tls-certificate",
                "/run/secrets/relay-consultation-tls.crt",
            ),
            secret_projection(
                "relay-consultation-tls-private-key",
                "/run/secrets/relay-consultation-tls.key",
            ),
        ]
    else:
        preparation_secrets = [database_ca]
        initialization_secrets = []
        serve_secrets = [
            database_ca,
            secret_projection(
                "relay-consultation-tls-certificate",
                "/run/secrets/relay-consultation-ca.pem",
            ),
            secret_projection(
                "notary-relay-workload-credential",
                "/run/secrets/relay-workload-token",
            ),
            secret_projection(
                "notary-signing-key", "/run/secrets/notary-signing-key.jwk"
            ),
            secret_projection(
                "notary-tls-certificate", "/run/secrets/notary-tls.crt"
            ),
            secret_projection(
                "notary-tls-private-key", "/run/secrets/notary-tls.key"
            ),
        ]
    def action(
        name: str,
        mounts: list[dict[str, Any]],
        secrets: list[dict[str, str]],
        *,
        development: bool = False,
        environment: bool = True,
    ) -> dict[str, Any]:
        command_prefix = ["development-action"] if development else prefix
        if development and product == "registry-relay":
            command_prefix.append(lane)
        return {
            "command": [*command_prefix, name],
            "mounts": mounts,
            "environment_files": [f"{lane}-environment"] if environment else [],
            "secret_files": secrets,
        }

    return {
        "serve": action(
            "serve",
            [*common_mounts, state_read_only, audit],
            serve_secrets,
        ),
        "prepare_state_store": action(
            "prepare_state_store",
            [*common_mounts, audit],
            preparation_secrets,
        ),
        "initialize_state": action(
            "initialize_state",
            [*common_mounts, state, audit],
            initialization_secrets,
        ),
        "verify_state": action(
            "verify_state",
            [*common_mounts, state_read_only],
            [],
            environment=False,
        ),
        "preview_state": action(
            "preview_state",
            [*common_mounts, state_read_only],
            [],
            environment=False,
        ),
        "accept_state": action(
            "accept_state",
            [*common_mounts, state, audit],
            [],
        ),
        "development_prepare_state_store": action(
            "prepare_state_store",
            [*common_mounts, audit],
            preparation_secrets,
            development=True,
        ),
        "development_initialize_state": action(
            "initialize_state",
            [*common_mounts, state, audit],
            preparation_secrets,
            development=True,
        ),
        "development_serve": action(
            "serve",
            [*common_mounts, state_read_only, audit],
            serve_secrets,
            development=True,
        ),
        "health_probe": [
            "CMD",
            f"/usr/local/bin/{product}",
            "healthcheck",
            "--url",
            f"http://127.0.0.1:{health_port}/ready",
        ],
    }


POSTGRESQL_BOOTSTRAP_KEYS = [
    "REGISTRY_RELAY_MIGRATOR_PASSWORD",
    "REGISTRY_RELAY_RUNTIME_PASSWORD",
    "REGISTRY_RELAY_MAINTENANCE_PASSWORD",
    "REGISTRY_RELAY_READER_PASSWORD",
    "REGISTRY_NOTARY_MIGRATOR_PASSWORD",
    "REGISTRY_NOTARY_RUNTIME_PASSWORD",
    "REGISTRY_NOTARY_MAINTENANCE_PASSWORD",
    "REGISTRY_NOTARY_READER_PASSWORD",
]


# Marker creation intentionally has no IF NOT EXISTS. Under psql autocommit,
# its durable table makes every later bootstrap stop before role/database work.
POSTGRESQL_BOOTSTRAP_SCRIPT = r"""export PGPASSWORD="$(cat /run/secrets/postgresql-admin-password)"
psql "host=registry-postgres port=5432 dbname=postgres user=registry_stack_bootstrap sslmode=verify-full sslrootcert=/run/secrets/postgresql-ca.pem" --set=ON_ERROR_STOP=1 <<'SQL'
CREATE TABLE public.registry_stack_bootstrap_marker (
    bootstrap_version integer PRIMARY KEY CHECK (bootstrap_version = 1)
);
INSERT INTO public.registry_stack_bootstrap_marker (bootstrap_version) VALUES (1);
REVOKE ALL ON TABLE public.registry_stack_bootstrap_marker FROM PUBLIC;
\getenv relay_migrator_password REGISTRY_RELAY_MIGRATOR_PASSWORD
\getenv relay_runtime_password REGISTRY_RELAY_RUNTIME_PASSWORD
\getenv relay_maintenance_password REGISTRY_RELAY_MAINTENANCE_PASSWORD
\getenv relay_reader_password REGISTRY_RELAY_READER_PASSWORD
\getenv notary_migrator_password REGISTRY_NOTARY_MIGRATOR_PASSWORD
\getenv notary_runtime_password REGISTRY_NOTARY_RUNTIME_PASSWORD
\getenv notary_maintenance_password REGISTRY_NOTARY_MAINTENANCE_PASSWORD
\getenv notary_reader_password REGISTRY_NOTARY_READER_PASSWORD
SELECT 'CREATE ROLE registry_relay_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS'
WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'registry_relay_owner') \gexec
SELECT format('CREATE ROLE registry_relay_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD %L', :'relay_migrator_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'registry_relay_migrator') \gexec
SELECT format('CREATE ROLE registry_relay_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD %L', :'relay_runtime_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'registry_relay_runtime') \gexec
SELECT format('CREATE ROLE registry_relay_maintenance LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD %L', :'relay_maintenance_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'registry_relay_maintenance') \gexec
SELECT format('CREATE ROLE registry_relay_reader LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD %L', :'relay_reader_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'registry_relay_reader') \gexec
ALTER ROLE registry_relay_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
ALTER ROLE registry_relay_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD :'relay_migrator_password';
ALTER ROLE registry_relay_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD :'relay_runtime_password';
ALTER ROLE registry_relay_maintenance LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD :'relay_maintenance_password';
ALTER ROLE registry_relay_reader LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD :'relay_reader_password';
GRANT registry_relay_owner TO registry_relay_migrator WITH INHERIT FALSE, SET TRUE;
SELECT 'CREATE DATABASE registry_relay OWNER registry_relay_owner'
WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_database WHERE datname = 'registry_relay') \gexec
ALTER DATABASE registry_relay OWNER TO registry_relay_owner;
REVOKE ALL ON DATABASE registry_relay FROM PUBLIC;
GRANT CONNECT ON DATABASE registry_relay TO registry_relay_migrator, registry_relay_runtime, registry_relay_maintenance, registry_relay_reader;
SELECT 'CREATE ROLE registry_notary_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS'
WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'registry_notary_owner') \gexec
SELECT format('CREATE ROLE registry_notary_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD %L', :'notary_migrator_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'registry_notary_migrator') \gexec
SELECT format('CREATE ROLE registry_notary_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD %L', :'notary_runtime_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'registry_notary_runtime') \gexec
SELECT format('CREATE ROLE registry_notary_maintenance LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD %L', :'notary_maintenance_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'registry_notary_maintenance') \gexec
SELECT format('CREATE ROLE registry_notary_reader LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD %L', :'notary_reader_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'registry_notary_reader') \gexec
ALTER ROLE registry_notary_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
ALTER ROLE registry_notary_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD :'notary_migrator_password';
ALTER ROLE registry_notary_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD :'notary_runtime_password';
ALTER ROLE registry_notary_maintenance LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD :'notary_maintenance_password';
ALTER ROLE registry_notary_reader LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD :'notary_reader_password';
GRANT registry_notary_owner TO registry_notary_migrator WITH INHERIT FALSE, SET TRUE;
SELECT 'CREATE DATABASE registry_notary OWNER registry_notary_owner'
WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_database WHERE datname = 'registry_notary') \gexec
ALTER DATABASE registry_notary OWNER TO registry_notary_owner;
REVOKE ALL ON DATABASE registry_notary FROM PUBLIC;
GRANT CONNECT ON DATABASE registry_notary TO registry_notary_migrator, registry_notary_runtime, registry_notary_maintenance, registry_notary_reader;
\connect registry_relay
REVOKE ALL ON SCHEMA public FROM PUBLIC;
\connect registry_notary
REVOKE ALL ON SCHEMA public FROM PUBLIC;
SQL"""


def postgresql_recipe() -> dict[str, Any]:
    return {
        "serve": {
            "command": [
                "postgres",
                "-c",
                "ssl=on",
                "-c",
                "ssl_cert_file=/run/secrets/postgresql-tls.crt",
                "-c",
                "ssl_key_file=/run/secrets/postgresql-tls.key",
                "-c",
                "ssl_min_protocol_version=TLSv1.2",
                "-c",
                "password_encryption=scram-sha-256",
                "-c",
                "listen_addresses=0.0.0.0",
            ],
            "mounts": [
                runtime_mount(
                    "postgresql_data", "/var/lib/postgresql/data", False
                )
            ],
            "environment_files": [],
            "secret_files": [
                secret_projection(
                    "postgresql-admin-password",
                    "/run/secrets/postgresql-admin-password",
                    uid="999",
                ),
                secret_projection(
                    "postgresql-tls-certificate",
                    "/run/secrets/postgresql-tls.crt",
                    uid="999",
                ),
                secret_projection(
                    "postgresql-tls-private-key",
                    "/run/secrets/postgresql-tls.key",
                    uid="999",
                ),
            ],
        },
        "bootstrap": {
            "command": ["/bin/bash", "-ceu", POSTGRESQL_BOOTSTRAP_SCRIPT],
            "mounts": [],
            "environment_files": ["postgresql-bootstrap-environment"],
            "secret_files": [
                secret_projection(
                    "postgresql-admin-password",
                    "/run/secrets/postgresql-admin-password",
                    uid="999",
                ),
                secret_projection(
                    "postgresql-tls-certificate",
                    "/run/secrets/postgresql-ca.pem",
                    uid="999",
                ),
            ],
        },
        "health_probe": [
            "CMD",
            "pg_isready",
            "--host",
            "127.0.0.1",
            "--port",
            "5432",
            "--username",
            "registry_stack_bootstrap",
            "--dbname",
            "postgres",
        ],
        "server_environment": [
            "POSTGRES_USER=registry_stack_bootstrap",
            "POSTGRES_DB=postgres",
            "POSTGRES_PASSWORD_FILE=/run/secrets/postgresql-admin-password",
            "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=trust",
        ],
        "hardening": {
            "user": "999:999",
            "read_only_root_filesystem": True,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "tmpfs": [
                "/tmp",
                "/var/run/postgresql:uid=999,gid=999,mode=0750",
            ],
        },
    }


def operator_files() -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    product_owners = ["root:root", "65532:65532"]
    for lane in ["relay-public", "relay-consultation", "notary"]:
        files.append(
            {
                "id": f"{lane}-environment",
                "format": "dotenv",
                "mode": "0600",
                "allowed_owners": product_owners,
                "required_keys": [],
            }
        )
    for file_id, file_format, owners in [
        (
            "relay-public-tls-certificate",
            "pem_certificate",
            product_owners,
        ),
        ("relay-public-tls-private-key", "pem_private_key", product_owners),
        (
            "relay-consultation-tls-certificate",
            "pem_certificate",
            product_owners,
        ),
        (
            "relay-consultation-tls-private-key",
            "pem_private_key",
            product_owners,
        ),
        ("notary-tls-certificate", "pem_certificate", product_owners),
        ("notary-tls-private-key", "pem_private_key", product_owners),
        ("notary-signing-key", "json_web_key", product_owners),
        ("notary-relay-workload-credential", "compact_jwt", product_owners),
        (
            "postgresql-tls-certificate",
            "pem_certificate",
            ["root:root", "65532:65532", "999:999"],
        ),
        (
            "postgresql-tls-private-key",
            "pem_private_key",
            ["root:root", "999:999"],
        ),
        (
            "postgresql-admin-password",
            "opaque",
            ["root:root", "999:999"],
        ),
    ]:
        files.append(
            {
                "id": file_id,
                "format": file_format,
                "mode": "0600",
                "allowed_owners": owners,
                "required_keys": [],
            }
        )
    files.append(
        {
            "id": "postgresql-bootstrap-environment",
            "format": "dotenv",
            "mode": "0600",
            "allowed_owners": ["root:root", "999:999"],
            "required_keys": POSTGRESQL_BOOTSTRAP_KEYS,
        }
    )
    return sorted(files, key=lambda item: item["id"])


def create_payload(args: argparse.Namespace) -> int:
    if VERSION.fullmatch(args.version) is None or not args.version.startswith("1."):
        raise ValueError("release lock generation requires a stable 1.x version")
    if HEX40.fullmatch(args.manifest_source_ref) is None:
        raise ValueError(
            "manifest source ref must be 40 lowercase hexadecimal characters"
        )
    if HEX40.fullmatch(args.tag_target) is None:
        raise ValueError("tag target must be 40 lowercase hexadecimal characters")
    if args.manifest_source_ref != args.tag_target:
        raise ValueError("manifest source ref and tag target must be identical")
    tag = f"v{args.version}"
    image_lock = read_json(args.image_lock)
    if not isinstance(image_lock, dict):
        raise ValueError("legacy image lock must be an object")
    if image_lock.get("release_tag") != tag:
        raise ValueError("legacy image lock release tag does not match")
    if image_lock.get("manifest_source_ref") != args.manifest_source_ref:
        raise ValueError("legacy image lock manifest source ref does not match")
    if image_lock.get("tag_target") != args.tag_target:
        raise ValueError("legacy image lock tag target does not match")
    images = image_lock.get("images")
    if not isinstance(images, dict) or set(images) != {
        "registry-relay",
        "registry-notary",
        "postgresql",
    }:
        raise ValueError("legacy image lock image roster is not closed")

    relay, relay_index_digest = image(images["registry-relay"], "Relay")
    notary, notary_index_digest = image(images["registry-notary"], "Notary")
    postgresql, postgresql_index_digest = image(
        images["postgresql"], "PostgreSQL"
    )
    relay_manifest_digest = read_platform_manifest_from_index(
        args.relay_image_index,
        "Relay",
        relay_index_digest,
    )
    notary_manifest_digest = read_platform_manifest_from_index(
        args.notary_image_index,
        "Notary",
        notary_index_digest,
    )
    postgresql_manifest_digest = read_platform_manifest_from_index(
        args.postgresql_image_index,
        "PostgreSQL",
        postgresql_index_digest,
    )

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

    def locked_image(identity: str, manifest_digest: str) -> dict[str, Any]:
        return {
            "identity": identity,
            "platforms": [
                {
                    "platform": "linux-amd64",
                    "manifest_digest": manifest_digest,
                }
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
            "manifest_source_ref": args.manifest_source_ref,
            "tag_target": args.tag_target,
        },
        "registryctl_artifacts": registryctl_artifacts,
        "images": {
            "relay": locked_image(relay, relay_manifest_digest),
            "notary": locked_image(notary, notary_manifest_digest),
            "postgresql_state_plane": locked_image(
                postgresql, postgresql_manifest_digest
            ),
        },
        "runtime": {
            "relay_public": product_recipe("registry-relay", "relay-public"),
            "relay_consultation": product_recipe(
                "registry-relay", "relay-consultation"
            ),
            "notary": product_recipe("registry-notary", "notary"),
            "postgresql_state_plane": postgresql_recipe(),
            "operator_files": operator_files(),
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
    create.add_argument("--manifest-source-ref", required=True)
    create.add_argument("--tag-target", required=True)
    create.add_argument("--asset-dir", required=True, type=Path)
    create.add_argument("--image-lock", required=True, type=Path)
    create.add_argument("--relay-image-index", required=True, type=Path)
    create.add_argument("--notary-image-index", required=True, type=Path)
    create.add_argument("--postgresql-image-index", required=True, type=Path)
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
