#!/usr/bin/env python3
"""Smoke an installed Discovery pair through the packaged unified Node SDK."""

from __future__ import annotations

import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import signal
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from typing import NamedTuple, Sequence
import urllib.error
import urllib.request


MEDIA_TYPE = (
    'application/ld+json;profile="https://registrystack.org/discovery/profile/v1alpha1"'
)
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?")
MAX_ARCHIVE_MEMBERS = 4096
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
REQUIREMENT = "urn:example:requirement:adult-status"
JURISDICTION = "https://publications.europa.eu/resource/authority/territory/DEU"
EVIDENCE_TYPE = "urn:example:evidence-type:adult-status"
EVIDENCE_TYPE_LIST = "urn:example:evidence-type-list:adult-status"
EXPECTED_RECORD_ID = (
    "urn:registrystack:discovery:record:sha256:"
    + hashlib.sha256(
        b'{"bindingId":"urn:registrystack:discovery:binding:sha256:2f9ccc4629c7ea2409d986a9c0ee6e3afe6e63326ca7b1be7d9eb8c69082d96c","originId":"evidence-one"}'
    ).hexdigest()
)

CATALOG = b'{"@context":"https://registrystack.org/discovery/context/v1alpha1","@type":"dcat:Catalog","profile":"registry-discovery-v1alpha1","services":[{"@type":"dcat:DataService","bindingId":"urn:registrystack:discovery:binding:sha256:2f9ccc4629c7ea2409d986a9c0ee6e3afe6e63326ca7b1be7d9eb8c69082d96c","serviceId":"urn:example:service:evidence","serviceKind":"evidence","title":"Example Evidence","description":"Public signed evidence assertions","endpointURL":"https://evidence.example.org","publisherId":"urn:example:publisher","jurisdictions":["https://publications.europa.eu/resource/authority/territory/DEU"],"conformsTo":["https://registrystack.org/evidence/profile/v1"],"evidenceTypeIds":["urn:example:evidence-type:adult-status"]}]}'

NODE_JOURNEY = r"""
'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');

const clientRoot = path.resolve(process.argv[2]);
const baseUrl = process.argv[3];
const expectedRecordId = process.argv[4];
const registry = require(clientRoot);
const metadata = require(path.join(clientRoot, 'package.json'));
const {
  DiscoveryClient,
  acceptSelection,
  selectEvidenceAlternative,
  selectEvidenceService,
} = registry.discovery;

assert.throws(
  () => new DiscoveryClient({ baseUrl, authorization: 'Bearer must-be-refused' }),
  (error) => error && error.kind === 'configuration',
);

async function main() {
  const client = new DiscoveryClient({
    baseUrl,
    requestTimeoutMilliseconds: 10000,
    connectTimeoutMilliseconds: 3000,
    maximumResponseBytes: 1048576,
  });
  const resolutionResponse = await client.resolveEvidenceTypes({
    requirementId: 'urn:example:requirement:adult-status',
    jurisdiction: 'https://publications.europa.eu/resource/authority/territory/DEU',
  });
  assert.equal(resolutionResponse.requirementId, 'urn:example:requirement:adult-status');
  assert.equal(resolutionResponse.alternatives.length, 1);
  const resolution = selectEvidenceAlternative(
    resolutionResponse,
    'urn:example:evidence-type-list:adult-status',
  );
  assert.deepEqual(
    resolution.evidenceTypeIds,
    ['urn:example:evidence-type:adult-status'],
  );

  const searchResponse = await client.searchEvidenceServices({
    evidenceTypeId: 'urn:example:evidence-type:adult-status',
    jurisdiction: 'https://publications.europa.eu/resource/authority/territory/DEU',
  });
  assert.equal(searchResponse.items.length, 1);
  const record = searchResponse.items[0];
  assert.equal(record.recordId, expectedRecordId);
  assert.equal(record.serviceId, 'urn:example:service:evidence');
  assert.equal(record.endpointUrl, 'https://evidence.example.org');

  const selection = selectEvidenceService(searchResponse, {
    recordId: record.recordId,
    evidenceTypeId: 'urn:example:evidence-type:adult-status',
    resolution,
  });
  assert.equal(selection.matchedCapability.kind, 'evidence-type');
  assert.throws(
    () => acceptSelection(selection, () => false),
    (error) => error && error.kind === 'local-acceptance-refused',
  );

  const forbidden = new Set([
    'authorization', 'authenticated', 'accepted', 'trusted', 'verified',
  ]);
  function assertNoTrustEscalation(value) {
    if (Array.isArray(value)) {
      value.forEach(assertNoTrustEscalation);
      return;
    }
    if (!value || typeof value !== 'object') return;
    for (const [key, member] of Object.entries(value)) {
      assert.equal(forbidden.has(key.toLowerCase()), false, `unexpected trust field ${key}`);
      assertNoTrustEscalation(member);
    }
  }
  assertNoTrustEscalation(resolutionResponse);
  assertNoTrustEscalation(searchResponse);
  process.stdout.write(JSON.stringify({
    sdkVersion: metadata.version,
    catalogRevision: searchResponse.catalogRevision,
    mappingRevision: resolutionResponse.mappingRevision,
    recordId: record.recordId,
  }) + '\n');
}

main().catch((error) => {
  process.stderr.write(String(error && error.stack ? error.stack : error) + '\n');
  process.exitCode = 1;
});
"""


class ClientDirectory(NamedTuple):
    root: Path
    version: str


class ClientTarballs(NamedTuple):
    root: Path
    native: Path
    version: str


class SmokeError(RuntimeError):
    """A bounded smoke operation failed."""


def parse_args(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Smoke an installed Discovery distribution with the unified Node SDK."
    )
    parser.add_argument(
        "--bin-dir",
        type=Path,
        required=True,
        help="directory containing the installed discovery and discoveryctl pair",
    )
    client = parser.add_mutually_exclusive_group(required=True)
    client.add_argument(
        "--client-dir",
        type=Path,
        help="installed @registrystack/client package root or npm project",
    )
    client.add_argument(
        "--client-tarball",
        type=Path,
        help="unified root .tgz beside its matching native platform .tgz",
    )
    return parser.parse_args(arguments)


def _run_version(binary: Path, expected_name: str) -> str:
    if not binary.exists() or not binary.is_file():
        raise ValueError(f"installed {expected_name} is missing: {binary}")
    if not os.access(binary, os.X_OK):
        raise ValueError(f"installed {expected_name} is not executable: {binary}")
    result = subprocess.run(
        [str(binary), "--version"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    expected = re.fullmatch(
        rf"{re.escape(expected_name)} ({VERSION.pattern})\n?", result.stdout
    )
    if result.returncode != 0 or expected is None or result.stderr:
        raise ValueError(f"installed {expected_name} did not report a valid version")
    return expected.group(1)


def validate_binary_pair(bin_dir: Path) -> tuple[Path, Path, str]:
    directory = bin_dir.expanduser().resolve()
    if not directory.is_dir():
        raise ValueError(f"binary directory is missing: {directory}")
    discovery = directory / "discovery"
    discoveryctl = directory / "discoveryctl"
    version = _run_version(discovery, "discovery")
    ctl_version = _run_version(discoveryctl, "discoveryctl")
    if version != ctl_version:
        raise ValueError(
            "discovery and discoveryctl must report the same product version"
        )
    return discovery, discoveryctl, version


def node_platform() -> str:
    machine = platform.machine().lower()
    system = platform.system()
    if system == "Darwin" and machine in {"arm64", "aarch64"}:
        return "darwin-arm64"
    if system == "Linux" and machine in {"x86_64", "amd64"}:
        return "linux-x64-gnu"
    if system == "Linux" and machine in {"arm64", "aarch64"}:
        return "linux-arm64-gnu"
    raise ValueError(f"the unified Node SDK does not support {system}-{machine}")


def _json_object(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read package metadata: {path}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"package metadata is not an object: {path}")
    return value


def _canonical_package_version(value: object) -> str:
    if not isinstance(value, str) or VERSION.fullmatch(value) is None:
        raise ValueError("client package has a noncanonical version")
    return value


def validate_client_directory(path: Path) -> ClientDirectory:
    supplied = path.expanduser().resolve()
    installed = supplied / "node_modules/@registrystack/client"
    root = installed if installed.is_dir() else supplied
    metadata = _json_object(root / "package.json")
    if metadata.get("name") != "@registrystack/client":
        raise ValueError(
            "client directory is not the unified @registrystack/client package"
        )
    version = _canonical_package_version(metadata.get("version"))
    required = (root / "index.js", root / "native.js", root / "discovery/client.js")
    if any(not member.is_file() or member.is_symlink() for member in required):
        raise ValueError("unified client directory is missing its Discovery facade")
    platform_name = node_platform()
    native_name = f"@registrystack/client-{platform_name}"
    optional = metadata.get("optionalDependencies")
    if not isinstance(optional, dict) or optional.get(native_name) != version:
        raise ValueError(
            "unified client does not bind the exact native package version"
        )
    if root == installed:
        native_root = (
            supplied / "node_modules/@registrystack" / f"client-{platform_name}"
        )
    else:
        native_root = root / "node_modules/@registrystack" / f"client-{platform_name}"
    native_metadata = _json_object(native_root / "package.json")
    if native_metadata.get("name") != native_name:
        raise ValueError("client directory has no matching native package")
    if native_metadata.get("version") != version:
        raise ValueError("native package version does not match the unified client")
    native_binary = native_root / f"discovery-client.{platform_name}.node"
    if not native_binary.is_file() or native_binary.is_symlink():
        raise ValueError("native package is missing the Discovery binding")
    return ClientDirectory(root, version)


def _archive_metadata(path: Path) -> tuple[dict[str, object], set[str]]:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"candidate npm package is missing or is a symlink: {path}")
    try:
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise ValueError(
                    f"candidate npm package has too many members: {path.name}"
                )
            if sum(member.size for member in members) > MAX_ARCHIVE_BYTES:
                raise ValueError(f"candidate npm package is too large: {path.name}")
            names: set[str] = set()
            manifest = None
            for member in members:
                member_path = PurePosixPath(member.name)
                if (
                    member_path.is_absolute()
                    or ".." in member_path.parts
                    or not member_path.parts
                ):
                    raise ValueError(
                        f"candidate npm package has unsafe archive member: {member.name}"
                    )
                if member.issym() or member.islnk() or member.isdev():
                    raise ValueError(
                        f"candidate npm package contains a link or device: {member.name}"
                    )
                if member.name in names:
                    raise ValueError(
                        f"candidate npm package repeats a member: {member.name}"
                    )
                names.add(member.name)
                if member.name == "package/package.json":
                    manifest = member
            if manifest is None:
                raise ValueError(
                    f"candidate npm package has no package.json: {path.name}"
                )
            handle = archive.extractfile(manifest)
            if handle is None:
                raise ValueError(
                    f"candidate npm package metadata is unreadable: {path.name}"
                )
            metadata = json.load(handle)
    except (OSError, tarfile.TarError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read candidate npm package: {path.name}") from exc
    if not isinstance(metadata, dict):
        raise ValueError(f"candidate npm package metadata is malformed: {path.name}")
    return metadata, names


def validate_client_tarballs(path: Path) -> ClientTarballs:
    supplied = path.expanduser()
    if supplied.is_symlink():
        raise ValueError("unified client tarball must not be a symlink")
    root = supplied.resolve()
    metadata, names = _archive_metadata(root)
    if metadata.get("name") != "@registrystack/client":
        raise ValueError(
            "client tarball is not the unified @registrystack/client package"
        )
    version = _canonical_package_version(metadata.get("version"))
    required = {
        "package/package.json",
        "package/index.js",
        "package/native.js",
        "package/discovery/client.js",
    }
    if not required.issubset(names) or any(name.endswith(".node") for name in names):
        raise ValueError(
            "unified client tarball has an invalid Discovery facade or native payload"
        )
    platform_name = node_platform()
    native_package_name = f"@registrystack/client-{platform_name}"
    optional = metadata.get("optionalDependencies")
    if not isinstance(optional, dict) or optional.get(native_package_name) != version:
        raise ValueError(
            "unified client tarball does not bind the exact native package version"
        )
    native = root.parent / f"registrystack-client-{platform_name}-{version}.tgz"
    if not native.is_file():
        raise ValueError(
            "client tarball has no matching native candidate package beside it"
        )
    native_metadata, native_names = _archive_metadata(native)
    if (
        native_metadata.get("name") != native_package_name
        or native_metadata.get("version") != version
    ):
        raise ValueError(
            "native candidate package identity does not match the unified client"
        )
    expected_binary = f"package/discovery-client.{platform_name}.node"
    if expected_binary not in native_names:
        raise ValueError("native candidate package is missing the Discovery binding")
    return ClientTarballs(root, native, version)


def node_environment(source: dict[str, str], scratch: Path) -> dict[str, str]:
    environment = {
        "PATH": source.get("PATH", os.defpath),
        "HOME": str(scratch),
        "TMPDIR": str(scratch),
        "npm_config_cache": str(scratch / "npm-cache"),
        "npm_config_offline": "true",
        "npm_config_audit": "false",
        "npm_config_fund": "false",
        "npm_config_update_notifier": "false",
    }
    for name in ("DYLD_LIBRARY_PATH", "LD_LIBRARY_PATH"):
        if name in source:
            environment[name] = source[name]
    return environment


def install_client_tarballs(packages: ClientTarballs, scratch: Path) -> ClientDirectory:
    install = scratch / "node-client"
    install.mkdir()
    (install / "package.json").write_text(
        '{"name":"discovery-distribution-smoke","private":true}\n',
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            "npm",
            "install",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
            "--offline",
            str(packages.root),
            str(packages.native),
        ],
        cwd=install,
        env=node_environment(os.environ.copy(), scratch),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        raise SmokeError(f"offline npm install failed: {result.stderr.strip()}")
    installed = validate_client_directory(install)
    if installed.version != packages.version:
        raise SmokeError(
            "installed unified client identity changed during npm installation"
        )
    return installed


class _CatalogHandler(BaseHTTPRequestHandler):
    requests_seen = 0
    authorization_seen = False

    def do_GET(self) -> None:  # noqa: N802
        type(self).requests_seen += 1
        if self.headers.get("Authorization") or self.headers.get("Cookie"):
            type(self).authorization_seen = True
        if self.path != "/catalog.jsonld":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", MEDIA_TYPE)
        self.send_header("Content-Length", str(len(CATALOG)))
        self.end_headers()
        self.wfile.write(CATALOG)

    def log_message(self, format: str, *args: object) -> None:
        return


def _run_checked(command: list[str], *, environment: dict[str, str]) -> str:
    result = subprocess.run(
        command,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic"
        raise SmokeError(f"{Path(command[0]).name} failed: {detail}")
    return result.stdout


def _write_project(project: Path, catalog_url: str) -> None:
    (project / "mappings").mkdir(parents=True)
    (project / "origins.yaml").write_text(
        "apiVersion: id.registrystack.org/formats/discovery/origins/v1alpha1\n"
        "kind: DiscoveryOrigins\n"
        "origins:\n"
        "  - originId: evidence-one\n"
        f"    catalogUrl: {catalog_url}\n"
        "    profile: registry-discovery-v1alpha1\n"
        "    enabled: true\n",
        encoding="utf-8",
    )
    (project / "mappings/adult-status.yaml").write_text(
        "apiVersion: id.registrystack.org/formats/discovery/evidence-mapping/v1alpha1\n"
        "kind: DiscoveryEvidenceMapping\n"
        "mappingId: urn:example:mapping:adult-status\n"
        "mappingAuthorityId: urn:example:mapping-authority\n"
        f"requirementId: {REQUIREMENT}\n"
        f"jurisdiction: {JURISDICTION}\n"
        "alternatives:\n"
        f"  - evidenceTypeListId: {EVIDENCE_TYPE_LIST}\n"
        "    evidenceTypeIds:\n"
        f"      - {EVIDENCE_TYPE}\n",
        encoding="utf-8",
    )


def _available_port() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CatalogHandler)
    port = server.server_address[1]
    server.server_close()
    return int(port)


def _write_runtime_config(path: Path, package: Path, port: int) -> None:
    path.write_text(
        "apiVersion: id.registrystack.org/formats/discovery/runtime/v1alpha1\n"
        "kind: DiscoveryRuntimeConfig\n"
        "listener:\n"
        f"  bind: 127.0.0.1:{port}\n"
        "  requestTimeoutMilliseconds: 10000\n"
        "package:\n"
        f"  root: {package.resolve()}\n"
        "limits:\n"
        "  maximumRequestBytes: 65536\n"
        "  maximumResponseBytes: 1048576\n"
        "  maximumResultRecords: 100\n"
        "  maximumResultAlternatives: 100\n"
        "  shutdownGraceMilliseconds: 1000\n"
        "logLevel: info\n",
        encoding="utf-8",
    )


def _wait_until_ready(base_url: str, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 15
    last_failure: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise SmokeError(
                f"discovery exited before readiness with status {process.returncode}"
            )
        try:
            with urllib.request.urlopen(base_url + "ready", timeout=0.5) as response:
                if (
                    response.status == 200
                    and response.read(1024) == b'{"status":"ready"}'
                ):
                    return
        except (urllib.error.URLError, TimeoutError) as error:
            last_failure = error
        time.sleep(0.05)
    raise SmokeError(
        "discovery did not become ready within 15 seconds"
    ) from last_failure


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def run_smoke(args: argparse.Namespace) -> dict[str, object]:
    discovery, discoveryctl, product_version = validate_binary_pair(args.bin_dir)
    tarballs = (
        validate_client_tarballs(args.client_tarball) if args.client_tarball else None
    )
    supplied_client = (
        validate_client_directory(args.client_dir)
        if args.client_dir is not None
        else None
    )
    with tempfile.TemporaryDirectory(prefix="discovery-distribution-smoke-") as name:
        # macOS exposes its temporary root through /var, while Discovery's
        # configuration loader deliberately refuses paths through symlinks.
        scratch = Path(name).resolve()
        client = (
            install_client_tarballs(tarballs, scratch)
            if tarballs is not None
            else supplied_client
        )
        if client is None:
            raise SmokeError("no unified client was selected")
        environment = os.environ.copy()
        _CatalogHandler.requests_seen = 0
        _CatalogHandler.authorization_seen = False
        provider = ThreadingHTTPServer(("127.0.0.1", 0), _CatalogHandler)
        provider_thread = threading.Thread(target=provider.serve_forever, daemon=True)
        provider_thread.start()
        try:
            project = scratch / "project"
            catalog_url = (
                f"http://127.0.0.1:{provider.server_address[1]}/catalog.jsonld"
            )
            _write_project(project, catalog_url)
            package = scratch / "package"
            _run_checked(
                [
                    str(discoveryctl),
                    "check",
                    "--project",
                    str(project),
                    "--allow-loopback",
                    "--deny-warnings",
                    "--format",
                    "json",
                ],
                environment=environment,
            )
            _run_checked(
                [
                    str(discoveryctl),
                    "package",
                    "--project",
                    str(project),
                    "--output",
                    str(package),
                    "--allow-loopback",
                    "--revision",
                    "distribution-smoke",
                ],
                environment=environment,
            )
        finally:
            provider.shutdown()
            provider.server_close()
            provider_thread.join(timeout=5)
        if _CatalogHandler.requests_seen != 1:
            raise SmokeError(
                "discoveryctl did not fetch the synthetic catalog exactly once"
            )
        if _CatalogHandler.authorization_seen:
            raise SmokeError(
                "discoveryctl sent credentials to the unauthenticated catalog"
            )

        _run_checked(
            [
                str(discoveryctl),
                "check",
                "--index",
                str(package / "discovery-index.json"),
                "--format",
                "json",
            ],
            environment=environment,
        )
        port = _available_port()
        runtime_config = scratch / "runtime.yaml"
        _write_runtime_config(runtime_config, package, port)
        _run_checked(
            [
                str(discoveryctl),
                "check",
                "--runtime-config",
                str(runtime_config),
                "--format",
                "json",
            ],
            environment=environment,
        )
        log = scratch / "discovery.log"
        with log.open("wb") as output:
            runtime = subprocess.Popen(
                [str(discovery), "--runtime-config", str(runtime_config)],
                env=environment,
                stdout=output,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        try:
            base_url = f"http://127.0.0.1:{port}/"
            _wait_until_ready(base_url, runtime)
            journey = scratch / "journey.js"
            journey.write_text(NODE_JOURNEY, encoding="utf-8")
            result = subprocess.run(
                [
                    "node",
                    str(journey),
                    str(client.root),
                    base_url,
                    EXPECTED_RECORD_ID,
                ],
                env=node_environment(os.environ.copy(), scratch),
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode != 0:
                raise SmokeError(
                    f"unified Node SDK journey failed: {result.stderr.strip()}"
                )
            try:
                proof = json.loads(result.stdout)
            except json.JSONDecodeError as exc:
                raise SmokeError(
                    "unified Node SDK journey returned malformed proof"
                ) from exc
            if (
                proof.get("sdkVersion") != client.version
                or proof.get("recordId") != EXPECTED_RECORD_ID
            ):
                raise SmokeError(
                    "unified Node SDK journey returned an unexpected identity"
                )
        finally:
            _stop_process(runtime)
        return {
            "ok": True,
            "discoveryVersion": product_version,
            "sdkVersion": client.version,
            "recordId": proof["recordId"],
            "catalogRevision": proof["catalogRevision"],
            "mappingRevision": proof["mappingRevision"],
        }


def main(arguments: Sequence[str] | None = None) -> int:
    try:
        result = run_smoke(parse_args(arguments))
    except (OSError, ValueError, SmokeError, subprocess.SubprocessError) as exc:
        print(f"Discovery distribution smoke failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
