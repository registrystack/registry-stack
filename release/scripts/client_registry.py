#!/usr/bin/env python3
"""Validate and reconcile historical and unified client packages."""

from __future__ import annotations

import argparse
import base64
import email.parser
import hashlib
import json
import sys
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, NamedTuple


class ClientDefinition(NamedTuple):
    npm_root_package: str
    npm_tarball_stem: str
    native_binary_stems: tuple[str, ...]
    pypi_project: str
    wheel_stem: str


CLIENTS = {
    "discovery": ClientDefinition(
        npm_root_package="@registrystack/discovery-client",
        npm_tarball_stem="registrystack-discovery-client",
        native_binary_stems=("discovery-client",),
        pypi_project="registry-discovery-client",
        wheel_stem="registry_discovery_client",
    ),
    "evidence": ClientDefinition(
        npm_root_package="@registrystack/evidence-client",
        npm_tarball_stem="registrystack-evidence-client",
        native_binary_stems=("evidence-client",),
        pypi_project="registry-evidence-client",
        wheel_stem="registry_evidence_client",
    ),
    "relay": ClientDefinition(
        npm_root_package="@registrystack/relay-client",
        npm_tarball_stem="registrystack-relay-client",
        native_binary_stems=("relay-client",),
        pypi_project="registry-relay-client",
        wheel_stem="registry_relay_client",
    ),
    "stack": ClientDefinition(
        npm_root_package="@registrystack/client",
        npm_tarball_stem="registrystack-client",
        native_binary_stems=(
            "discovery-client",
            "evidence-client",
            "relay-client",
            "breg-client",
        ),
        pypi_project="registry-stack-client",
        wheel_stem="registry_stack_client",
    ),
}
NPM_PLATFORM_NAMES = ("darwin-arm64", "linux-arm64-gnu", "linux-x64-gnu")
WHEEL_PLATFORMS = (
    "manylinux_2_17_x86_64.manylinux2014_x86_64",
    "manylinux_2_17_aarch64.manylinux2014_aarch64",
    "macosx_11_0_arm64",
)
MAXIMUM_ARCHIVE_MEMBERS = 128
MAXIMUM_ARCHIVE_UNCOMPRESSED_BYTES = 128 * 1024 * 1024
MAXIMUM_REGISTRY_METADATA_BYTES = 4 * 1024 * 1024


class ClientRegistryError(RuntimeError):
    """The client package set or public registry state is unsafe."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def npm_integrity(path: Path) -> str:
    digest = hashlib.sha512()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha512-" + base64.b64encode(digest.digest()).decode("ascii")


def client_definition(client: str) -> ClientDefinition:
    try:
        return CLIENTS[client]
    except KeyError as exc:
        raise ClientRegistryError(f"unknown client {client!r}") from exc


def npm_platforms(client: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
    definition = client_definition(client)
    return tuple(
        (
            platform,
            tuple(
                f"{stem}.{platform}.node"
                for stem in definition.native_binary_stems
            ),
        )
        for platform in NPM_PLATFORM_NAMES
    )


def expected_optional_dependencies(client: str, version: str) -> dict[str, str]:
    definition = client_definition(client)
    return {
        f"{definition.npm_root_package}-{platform}": version
        for platform, _binaries in npm_platforms(client)
    }


def bind_optional_dependencies(package_json: Path, version: str, client: str) -> None:
    """Bind a root manifest to its exact platform packages before it is packed.

    The checked-in manifest cannot carry these versions. At preparation time
    they name a release that is not published yet, so npm resolves them to
    placeholder lock entries and `npm ci` stops being satisfiable on the
    default branch from the moment that release publishes. The published root
    package must still bind them exactly, so the binding happens here, against
    the manifest that is about to be packed, and validate_npm_packages proves
    it landed by reading the packed tarball back.
    """
    definition = client_definition(client)
    try:
        metadata = json.loads(package_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ClientRegistryError(
            f"cannot read root manifest {package_json}: {exc}"
        ) from exc
    if not isinstance(metadata, dict):
        raise ClientRegistryError(f"root manifest {package_json} is malformed")
    if (
        metadata.get("name") != definition.npm_root_package
        or metadata.get("version") != version
    ):
        raise ClientRegistryError(
            f"root manifest {package_json} must identify "
            f"{definition.npm_root_package} at version {version}"
        )
    metadata["optionalDependencies"] = expected_optional_dependencies(client, version)
    package_json.write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def npm_tarballs(directory: Path, version: str, client: str) -> list[Path]:
    definition = client_definition(client)
    return [
        *(
            directory / f"{definition.npm_tarball_stem}-{platform}-{version}.tgz"
            for platform, _binaries in npm_platforms(client)
        ),
        directory / f"{definition.npm_tarball_stem}-{version}.tgz",
    ]


def wheel_paths(directory: Path, version: str, client: str) -> list[Path]:
    definition = client_definition(client)
    return [
        directory / f"{definition.wheel_stem}-{version}-cp310-abi3-{platform}.whl"
        for platform in WHEEL_PLATFORMS
    ]


def _safe_archive_name(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ClientRegistryError(f"package archive contains unsafe member {name!r}")
    return path


def npm_package_metadata(path: Path) -> tuple[dict[str, Any], set[str]]:
    if not path.is_file() or path.is_symlink():
        raise ClientRegistryError(f"npm package is missing: {path.name}")
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            members = archive.getmembers()
            if len(members) > MAXIMUM_ARCHIVE_MEMBERS:
                raise ClientRegistryError(
                    f"npm package {path.name} has too many members"
                )
            if sum(member.size for member in members) > MAXIMUM_ARCHIVE_UNCOMPRESSED_BYTES:
                raise ClientRegistryError(
                    f"npm package {path.name} exceeds the unpacked size bound"
                )
            names: set[str] = set()
            for member in members:
                name = str(_safe_archive_name(member.name))
                if member.issym() or member.islnk() or member.isdev():
                    raise ClientRegistryError(
                        f"npm package {path.name} contains a link or device"
                    )
                if name in names:
                    raise ClientRegistryError(
                        f"npm package {path.name} repeats member {name}"
                    )
                names.add(name)
            manifest_members = [
                member for member in members if member.name == "package/package.json"
            ]
            if len(manifest_members) != 1:
                raise ClientRegistryError(
                    f"npm package {path.name} must contain one package.json"
                )
            handle = archive.extractfile(manifest_members[0])
            if handle is None:
                raise ClientRegistryError(
                    f"npm package {path.name} package.json is unreadable"
                )
            metadata = json.load(handle)
    except (OSError, tarfile.TarError, json.JSONDecodeError) as exc:
        raise ClientRegistryError(f"cannot read npm package {path.name}: {exc}") from exc
    if not isinstance(metadata, dict):
        raise ClientRegistryError(f"npm package {path.name} metadata is malformed")
    return metadata, names


def validate_npm_packages(directory: Path, version: str, client: str) -> list[Path]:
    definition = client_definition(client)
    expected_optional = expected_optional_dependencies(client, version)
    paths = npm_tarballs(directory, version, client)
    for path in paths:
        metadata, names = npm_package_metadata(path)
        expected_name = definition.npm_root_package
        expected_binaries = None
        for platform, binaries in npm_platforms(client):
            if path.name == f"{definition.npm_tarball_stem}-{platform}-{version}.tgz":
                expected_name = f"{definition.npm_root_package}-{platform}"
                expected_binaries = binaries
                break
        if metadata.get("name") != expected_name or metadata.get("version") != version:
            raise ClientRegistryError(
                f"npm package {path.name} has the wrong name or version"
            )
        if "package/LICENSE" not in names:
            raise ClientRegistryError(f"npm package {path.name} has no LICENSE")
        native_members = sorted(name for name in names if name.endswith(".node"))
        if expected_binaries is None:
            if native_members:
                raise ClientRegistryError(
                    "root npm package must not contain a native binary"
                )
            if metadata.get("optionalDependencies") != expected_optional:
                raise ClientRegistryError(
                    "root npm package does not bind the exact platform versions"
                )
        elif native_members != sorted(
            f"package/{binary}" for binary in expected_binaries
        ):
            raise ClientRegistryError(
                f"platform npm package {path.name} has the wrong native payload"
            )
    return paths


def validate_wheels(directory: Path, version: str, client: str) -> list[Path]:
    definition = client_definition(client)
    paths = wheel_paths(directory, version, client)
    for path in paths:
        if not path.is_file() or path.is_symlink():
            raise ClientRegistryError(f"Python wheel is missing: {path.name}")
        try:
            with zipfile.ZipFile(path) as archive:
                entries = archive.infolist()
                if len(entries) > MAXIMUM_ARCHIVE_MEMBERS:
                    raise ClientRegistryError(
                        f"Python wheel {path.name} has too many members"
                    )
                if (
                    sum(entry.file_size for entry in entries)
                    > MAXIMUM_ARCHIVE_UNCOMPRESSED_BYTES
                ):
                    raise ClientRegistryError(
                        f"Python wheel {path.name} exceeds the unpacked size bound"
                    )
                names = [str(_safe_archive_name(entry.filename)) for entry in entries]
        except (OSError, zipfile.BadZipFile) as exc:
            raise ClientRegistryError(f"cannot read Python wheel {path.name}: {exc}") from exc
        if len(names) != len(set(names)):
            raise ClientRegistryError(f"Python wheel {path.name} repeats a member")
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(metadata_names) != 1:
            raise ClientRegistryError(
                f"Python wheel {path.name} must contain one METADATA file"
            )
        with zipfile.ZipFile(path) as archive:
            metadata_bytes = archive.read(metadata_names[0])
        if len(metadata_bytes) > 1024 * 1024:
            raise ClientRegistryError(f"Python wheel {path.name} METADATA is too large")
        try:
            metadata = email.parser.BytesParser().parsebytes(metadata_bytes)
        except (TypeError, ValueError) as exc:
            raise ClientRegistryError(
                f"Python wheel {path.name} METADATA is malformed"
            ) from exc
        if (
            metadata.get("Name") != definition.pypi_project
            or metadata.get("Version") != version
        ):
            raise ClientRegistryError(
                f"Python wheel {path.name} has the wrong name or version"
            )
    return paths


def validate_distribution(directory: Path, version: str, client: str) -> None:
    validate_npm_packages(directory, version, client)
    validate_wheels(directory, version, client)


def npm_registry_state(
    tarball: Path,
    metadata: Any | None,
) -> str:
    package, _names = npm_package_metadata(tarball)
    name = package.get("name")
    version = package.get("version")
    if not isinstance(name, str) or not isinstance(version, str):
        raise ClientRegistryError(f"npm package {tarball.name} has invalid identity")
    if metadata is None:
        return "absent"
    if not isinstance(metadata, dict):
        raise ClientRegistryError(f"npm registry metadata for {name} is malformed")
    dist = metadata.get("dist")
    if metadata.get("name") != name or metadata.get("version") != version:
        raise ClientRegistryError(f"npm registry identity differs for {name}@{version}")
    if not isinstance(dist, dict) or dist.get("integrity") != npm_integrity(tarball):
        raise ClientRegistryError(
            f"npm registry bytes differ for immutable {name}@{version}"
        )
    return "present"


def pypi_registry_state(
    wheels: list[Path],
    version: str,
    metadata: Any | None,
    client: str,
) -> str:
    definition = client_definition(client)
    expected = {path.name: sha256_file(path) for path in wheels}
    if metadata is None:
        return "absent"
    if not isinstance(metadata, dict):
        raise ClientRegistryError("PyPI registry metadata is malformed")
    info = metadata.get("info")
    urls = metadata.get("urls")
    if (
        not isinstance(info, dict)
        or info.get("name") != definition.pypi_project
        or info.get("version") != version
        or not isinstance(urls, list)
    ):
        raise ClientRegistryError("PyPI registry identity is malformed")
    observed: dict[str, str] = {}
    for entry in urls:
        if not isinstance(entry, dict):
            raise ClientRegistryError("PyPI release file metadata is malformed")
        name = entry.get("filename")
        digests = entry.get("digests")
        if not isinstance(name, str) or not isinstance(digests, dict):
            raise ClientRegistryError("PyPI release file metadata is malformed")
        digest = digests.get("sha256")
        if name in observed or not isinstance(digest, str):
            raise ClientRegistryError("PyPI release repeats or omits a file digest")
        observed[name] = digest
    unexpected = set(observed) - set(expected)
    if unexpected:
        raise ClientRegistryError(
            f"PyPI release contains unexpected immutable files: {sorted(unexpected)!r}"
        )
    for name, digest in observed.items():
        if expected[name] != digest:
            raise ClientRegistryError(
                f"PyPI registry bytes differ for immutable {name}"
            )
    return "present" if observed == expected else "partial"


def fetch_json(url: str) -> Any | None:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "registry-stack-release"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            if response.status != 200:
                raise ClientRegistryError(
                    f"registry returned unexpected HTTP {response.status}"
                )
            body = response.read(MAXIMUM_REGISTRY_METADATA_BYTES + 1)
            if len(body) > MAXIMUM_REGISTRY_METADATA_BYTES:
                raise ClientRegistryError("registry metadata exceeds the size bound")
            return json.loads(body)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise ClientRegistryError(f"registry request failed with HTTP {exc.code}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ClientRegistryError(f"registry request failed: {exc}") from exc


def npm_metadata(tarball: Path) -> Any | None:
    package, _names = npm_package_metadata(tarball)
    name = package.get("name")
    version = package.get("version")
    if not isinstance(name, str) or not isinstance(version, str):
        raise ClientRegistryError(f"npm package {tarball.name} has invalid identity")
    encoded = urllib.parse.quote(name, safe="")
    return fetch_json(f"https://registry.npmjs.org/{encoded}/{version}")


def pypi_metadata(version: str, client: str) -> Any | None:
    project = client_definition(client).pypi_project
    return fetch_json(f"https://pypi.org/pypi/{project}/{version}/json")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate-dist")
    validate.add_argument("--directory", type=Path, required=True)
    validate.add_argument("--version", required=True)
    validate.add_argument("--client", choices=sorted(CLIENTS), required=True)
    bind = subparsers.add_parser("bind-optional-deps")
    bind.add_argument("--package-json", type=Path, required=True)
    bind.add_argument("--version", required=True)
    bind.add_argument("--client", choices=sorted(CLIENTS), required=True)
    npm = subparsers.add_parser("npm-state")
    npm.add_argument("--tarball", type=Path, required=True)
    pypi = subparsers.add_parser("pypi-state")
    pypi.add_argument("--directory", type=Path, required=True)
    pypi.add_argument("--version", required=True)
    pypi.add_argument("--client", choices=sorted(CLIENTS), required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.command == "validate-dist":
            validate_distribution(args.directory, args.version, args.client)
            print("validated")
        elif args.command == "bind-optional-deps":
            bind_optional_dependencies(args.package_json, args.version, args.client)
            print("bound")
        elif args.command == "npm-state":
            print(npm_registry_state(args.tarball, npm_metadata(args.tarball)))
        elif args.command == "pypi-state":
            wheels = validate_wheels(args.directory, args.version, args.client)
            print(
                pypi_registry_state(
                    wheels,
                    args.version,
                    pypi_metadata(args.version, args.client),
                    args.client,
                )
            )
    except ClientRegistryError as exc:
        print(f"client registry error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
