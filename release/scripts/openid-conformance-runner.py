#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run mapped OpenID Foundation conformance-suite slices for Registry Stack."""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime as dt
import hashlib
import hmac
import io
import json
import os
import re
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib
from collections import Counter
from pathlib import Path
from string import Template
from typing import Any

from closed_json_schema import SchemaValidationError, validate_against_schema


REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = REPO_ROOT / "release" / "conformance" / "openid"
PLAN_MAP_PATH = CONFIG_DIR / "plan-map.json"
EVIDENCE_SCHEMA_PATH = CONFIG_DIR / "evidence-summary.schema.json"
COMPOSE_OVERRIDE_PATH = CONFIG_DIR / "docker-compose.override.yaml"
BUILDER_COMPOSE_OVERRIDE_PATH = CONFIG_DIR / "docker-compose-builder.override.yaml"
SUITE_REQUIREMENTS_INPUT_PATH = CONFIG_DIR / "python-requirements.in"
SUITE_REQUIREMENTS_LOCK_PATH = CONFIG_DIR / "python-requirements.txt"
DEFAULT_WORK_ROOT = REPO_ROOT / "target" / "openid-conformance"
DEFAULT_CACHE_DIR = DEFAULT_WORK_ROOT / "cache"
DEFAULT_OUTPUT_ROOT = DEFAULT_WORK_ROOT / "results"
DEFAULT_SUITE_JWKS_PATH = DEFAULT_WORK_ROOT / "conformance-suite-jwks.json"
SCHEMA_VERSION = "registry.release.openid_conformance_plan_map.v1"
EVIDENCE_SCHEMA_VERSION = "registry.release.openid_conformance_evidence.v1"
EVIDENCE_SCENARIO_ID = "notary-oid4vci-issuer-metadata"
EVIDENCE_CLASSIFICATION = "unreviewed-candidate-evidence-summary"
EVIDENCE_ASSOCIATION = "operator-attested-pending-review"
EVIDENCE_UNSUPPORTED_SCENARIOS = (
    ("notary-oid4vci-issuer-full", "blocked-by-suite-profile"),
)
SUITE_JAR = "target/fapi-test-suite.jar"
SUITE_JAR_STAMP = "target/fapi-test-suite.jar.registry-stack-source-ref"
COMPOSE_CONFIG_DIR_ENV = "REGISTRY_OPENID_CONFORMANCE_CONFIG_DIR"
SUITE_CA_CONTAINER_PATH = "/etc/ssl/certs/nginx-selfsigned.crt"
DEFAULT_SUITE_CA_PATH = DEFAULT_WORK_ROOT / "conformance-suite-ca.pem"
MAX_SUITE_EXPORT_BYTES = 64 * 1024 * 1024
MAX_SUITE_EXPORT_ENTRIES = 2
MAX_SUITE_EXPORT_COMPRESSION_RATIO = 100
MAX_SUITE_JWKS_BYTES = 1024 * 1024
MAX_SUITE_SIGNATURE_BYTES = 16 * 1024
SUITE_RESULTS = {"PASSED", "FAILED", "WARNING", "REVIEW", "SKIPPED", "UNKNOWN"}
CONDITION_RESULTS = {"INFO", "SUCCESS", "REVIEW", "WARNING", "FAILURE"}
KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
TEST_ID = re.compile(r"^[A-Za-z0-9]{15}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA256_DIGEST_INFO_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)
FORBIDDEN_PUBLIC_KEYS = {
    "access_token",
    "authorization",
    "credential",
    "credentials",
    "civil_id",
    "date_of_birth",
    "family_name",
    "given_name",
    "id_token",
    "logs",
    "message",
    "messages",
    "msg",
    "national_id",
    "pre-authorized_code",
    "pre_authorized_code",
    "proof",
    "raw",
    "refresh_token",
    "request",
    "response",
    "results",
    "subject_id",
    "static_tx_code",
    "token",
    "transaction_code",
    "tx_code",
}
SENSITIVE_RAW_KEYS = FORBIDDEN_PUBLIC_KEYS - {
    "logs",
    "messages",
    "raw",
    "request",
    "response",
    "results",
}


class RunnerError(RuntimeError):
    """A user-actionable conformance runner failure."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, url):
        return None


def load_plan_map(path: Path = PLAN_MAP_PATH) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        plan_map = json.load(handle)
    if plan_map.get("schema_version") != SCHEMA_VERSION:
        raise RunnerError(f"unsupported plan map schema: {plan_map.get('schema_version')}")
    scenarios = plan_map.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        raise RunnerError("plan map must include at least one scenario")
    ids = [scenario.get("id") for scenario in scenarios]
    if any(not scenario_id for scenario_id in ids):
        raise RunnerError("every plan map scenario must have an id")
    if len(ids) != len(set(ids)):
        raise RunnerError("plan map scenario ids must be unique")
    return plan_map


def find_scenario(plan_map: dict[str, Any], scenario_id: str) -> dict[str, Any]:
    for scenario in plan_map["scenarios"]:
        if scenario.get("id") == scenario_id:
            return scenario
    raise RunnerError(f"unknown OpenID conformance scenario: {scenario_id}")


def scenario_plan_arg(scenario: dict[str, Any]) -> str:
    plan = scenario["suite_plan"]
    variants = scenario.get("variants") or {}
    variant_args = "".join(f"[{key}={value}]" for key, value in variants.items())
    modules = scenario.get("suite_modules") or []
    module_arg = ":" + ",".join(modules) if modules else ""
    return f"{plan}{variant_args}{module_arg}"


def default_params(scenario: dict[str, Any], args: argparse.Namespace) -> dict[str, str]:
    defaults = scenario.get("default_parameters") or {}
    issuer_env = defaults.get(
        "issuer_url_env", "REGISTRY_OPENID_CONFORMANCE_ISSUER_URL"
    )
    issuer_url = args.issuer_url or os.environ.get(issuer_env)
    if not issuer_url:
        raise RunnerError(
            f"issuer URL is required; pass --issuer-url or set {issuer_env}"
        )
    authorization_server = (
        args.authorization_server
        or os.environ.get(defaults.get("authorization_server_env", ""))
        or issuer_url
    )
    credential_configuration_id = (
        args.credential_configuration_id
        or os.environ.get(defaults.get("credential_configuration_id_env", ""))
        or defaults.get("default_credential_configuration_id")
    )
    if not credential_configuration_id:
        raise RunnerError("credential configuration id is required")
    return {
        "issuer_url": issuer_url,
        "authorization_server": authorization_server,
        "credential_configuration_id": credential_configuration_id,
        "static_tx_code": args.static_tx_code,
        "client_id": args.client_id,
        "client2_id": args.client2_id,
    }


def render_config(scenario: dict[str, Any], params: dict[str, str]) -> str:
    template_path = CONFIG_DIR / scenario["config_template"]
    rendered = Template(template_path.read_text(encoding="utf-8")).substitute(params)
    json.loads(rendered)
    return rendered


def write_rendered_config(
    scenario: dict[str, Any], output_dir: Path, params: dict[str, str]
) -> Path:
    path = output_dir / f"{scenario['id']}.config.json"
    return write_new_file(
        path,
        (render_config(scenario, params) + "\n").encode("utf-8"),
    )


def suite_settings(plan_map: dict[str, Any], args: argparse.Namespace) -> dict[str, str]:
    suite = plan_map["suite"]
    return {
        "repo": args.suite_repo or suite["repo"],
        "ref": args.suite_ref or suite["ref"],
        "base_url": args.conformance_server or suite["base_url"],
        "local_base_url": args.conformance_server_local or suite["local_base_url"],
        "mtls_base_url": args.conformance_server_mtls or suite["mtls_base_url"],
    }


def suite_dir(args: argparse.Namespace) -> Path:
    if args.suite_dir:
        return Path(args.suite_dir).expanduser().resolve()
    return Path(args.cache_dir).expanduser().resolve() / "conformance-suite"


def run_checked(
    command: list[str], cwd: Path | None = None, env: dict[str, str] | None = None
) -> None:
    result = subprocess.run(command, cwd=cwd, env=env, text=True, check=False)
    if result.returncode != 0:
        raise RunnerError(f"command failed ({result.returncode}): {' '.join(command)}")


def ensure_suite_checkout(plan_map: dict[str, Any], args: argparse.Namespace) -> Path:
    settings = suite_settings(plan_map, args)
    checkout = suite_dir(args)
    checkout.parent.mkdir(parents=True, exist_ok=True)
    git = shutil.which("git")
    if not git:
        raise RunnerError("git is required to prepare the OpenID conformance suite")
    if checkout.exists():
        status = subprocess.run(
            [git, "status", "--porcelain"],
            cwd=checkout,
            text=True,
            capture_output=True,
            check=False,
        )
        if status.returncode != 0:
            raise RunnerError(status.stderr.strip() or "could not inspect suite checkout")
        if status.stdout.strip():
            raise RunnerError(f"suite checkout has local changes: {checkout}")
        run_checked([git, "fetch", "--tags", "origin"], cwd=checkout)
    else:
        run_checked([git, "clone", settings["repo"], str(checkout)])
        run_checked([git, "fetch", "--tags", "origin"], cwd=checkout)
    run_checked([git, "checkout", "--detach", settings["ref"]], cwd=checkout)
    actual = subprocess.check_output(
        [git, "rev-parse", "HEAD"], cwd=checkout, text=True
    ).strip()
    expected = settings["ref"]
    if len(expected) == 40 and actual != expected:
        raise RunnerError(f"suite checkout is at {actual}, expected {expected}")
    return checkout


def compose_command(
    checkout: Path, args: argparse.Namespace, *compose_args: str
) -> list[str]:
    command = ["docker", "compose", "-f", str(checkout / "docker-compose.yml")]
    if COMPOSE_OVERRIDE_PATH.exists():
        command += ["-f", str(COMPOSE_OVERRIDE_PATH)]
    command += list(compose_args)
    return command


def builder_command(checkout: Path, *compose_args: str) -> list[str]:
    return [
        "docker",
        "compose",
        "-f",
        str(checkout / "builder-compose.yml"),
        "-f",
        str(BUILDER_COMPOSE_OVERRIDE_PATH),
        *compose_args,
    ]


def suite_checkout_ref(checkout: Path) -> str:
    git = shutil.which("git")
    if not git:
        raise RunnerError("git is required to inspect the OpenID conformance suite")
    result = subprocess.run(
        [git, "rev-parse", "HEAD"],
        cwd=checkout,
        text=True,
        capture_output=True,
        check=False,
    )
    actual = result.stdout.strip()
    if result.returncode != 0 or len(actual) != 40:
        raise RunnerError(result.stderr.strip() or "could not resolve suite checkout ref")
    return actual


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def read_owner_only_file(path: Path, *, max_bytes: int, label: str) -> bytes:
    path = path.expanduser()
    nofollow = getattr(os, "O_NOFOLLOW", None)
    cloexec = getattr(os, "O_CLOEXEC", None)
    if nofollow is None or cloexec is None or not hasattr(os, "geteuid"):
        raise RunnerError("secure private result handling is unavailable")
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY | cloexec | nofollow)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_mode & 0o077
            or not 0 < before.st_size <= max_bytes
        ):
            raise RunnerError(f"{label} must be an owner-only, bounded regular file")
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            content = handle.read(max_bytes + 1)
            after = os.fstat(handle.fileno())
    except OSError:
        raise RunnerError(f"{label} could not be opened securely") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if (
        len(content) != before.st_size
        or len(content) > max_bytes
        or (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
    ):
        raise RunnerError(f"{label} changed while it was read")
    return content


def base64url_decode(value: Any, label: str, *, allow_padding: bool) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 16_384:
        raise RunnerError(f"{label} is invalid")
    if allow_padding:
        if re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", value) is None:
            raise RunnerError(f"{label} is invalid")
        unpadded = value.rstrip("=")
        if len(value) - len(unpadded) != (-len(unpadded)) % 4:
            raise RunnerError(f"{label} is invalid")
    else:
        if re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
            raise RunnerError(f"{label} is invalid")
        unpadded = value
    try:
        return base64.urlsafe_b64decode(unpadded + "=" * (-len(unpadded) % 4))
    except (ValueError, binascii.Error):
        raise RunnerError(f"{label} is invalid") from None


def validate_suite_jwks(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"keys"}:
        raise RunnerError("suite JWKS has an unsupported shape")
    keys = value.get("keys")
    if not isinstance(keys, list) or not 0 < len(keys) <= 8:
        raise RunnerError("suite JWKS must contain a bounded key list")
    for key in keys:
        if (
            not isinstance(key, dict)
            or set(key) != {"alg", "e", "kid", "kty", "n", "use"}
            or key.get("alg") != "RS256"
            or key.get("kty") != "RSA"
            or key.get("use") != "sig"
            or not isinstance(key.get("kid"), str)
            or KEY_ID.fullmatch(key["kid"]) is None
        ):
            raise RunnerError("suite JWKS contains an unsupported signing key")
        modulus_bytes = base64url_decode(
            key.get("n"), "suite JWKS RSA modulus", allow_padding=False
        )
        exponent_bytes = base64url_decode(
            key.get("e"), "suite JWKS RSA exponent", allow_padding=False
        )
        if (
            not modulus_bytes
            or modulus_bytes[0] == 0
            or not 2048 <= int.from_bytes(modulus_bytes).bit_length() <= 8192
            or int.from_bytes(modulus_bytes) % 2 == 0
            or not exponent_bytes
            or exponent_bytes[0] == 0
        ):
            raise RunnerError("suite JWKS contains an invalid RSA signing key")
        exponent = int.from_bytes(exponent_bytes)
        if not 3 <= exponent <= 2_147_483_647 or exponent % 2 == 0:
            raise RunnerError("suite JWKS contains an invalid RSA signing key")
    return value


def parse_suite_jwks(content: bytes) -> dict[str, Any]:
    try:
        parsed = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise RunnerError("suite JWKS is not valid JSON") from None
    return validate_suite_jwks(parsed)


def load_suite_jwks(path: Path) -> tuple[dict[str, Any], str]:
    content = read_owner_only_file(
        path,
        max_bytes=MAX_SUITE_JWKS_BYTES,
        label="suite JWKS",
    )
    jwks = parse_suite_jwks(content)
    return jwks, canonical_sha256(jwks)


def rsa_key_verifies(content: bytes, signature: bytes, key: dict[str, Any]) -> bool:
    modulus = int.from_bytes(
        base64url_decode(key["n"], "suite JWKS RSA modulus", allow_padding=False)
    )
    exponent = int.from_bytes(
        base64url_decode(key["e"], "suite JWKS RSA exponent", allow_padding=False)
    )
    encoded_size = (modulus.bit_length() + 7) // 8
    if len(signature) != encoded_size:
        return False
    signature_number = int.from_bytes(signature)
    if signature_number <= 0 or signature_number >= modulus:
        return False
    digest_info = SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(content).digest()
    padding_size = encoded_size - len(digest_info) - 3
    if padding_size < 8:
        return False
    expected = b"\x00\x01" + b"\xff" * padding_size + b"\x00" + digest_info
    recovered = pow(signature_number, exponent, modulus).to_bytes(encoded_size)
    return hmac.compare_digest(recovered, expected)


def verify_suite_export_signature(
    content: bytes, encoded_signature: bytes, jwks: dict[str, Any]
) -> None:
    try:
        signature_text = encoded_signature.decode("ascii")
    except UnicodeDecodeError:
        raise RunnerError("suite export signature is invalid") from None
    signature = base64url_decode(
        signature_text, "suite export signature", allow_padding=True
    )
    matching_keys = [
        key for key in jwks["keys"] if rsa_key_verifies(content, signature, key)
    ]
    if len(matching_keys) != 1:
        raise RunnerError(
            "suite export signature must verify with exactly one trusted suite key"
        )


def load_suite_export(
    path: Path, module_id: str, suite_jwks: dict[str, Any]
) -> dict[str, Any]:
    raw = read_owner_only_file(
        path,
        max_bytes=MAX_SUITE_EXPORT_BYTES,
        label="suite export",
    )
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile:
        raise RunnerError("suite export is not a valid ZIP archive") from None
    try:
        with archive:
            entries = archive.infolist()
            names = [entry.filename for entry in entries]
            if len(entries) != MAX_SUITE_EXPORT_ENTRIES or len(names) != len(
                set(names)
            ):
                raise RunnerError(
                    "suite export must contain one module JSON and one signature"
                )
            json_pattern = re.compile(
                rf"^test-log-{re.escape(module_id)}-([A-Za-z0-9]{{15}})\.json$"
            )
            json_matches = [
                (name, match)
                for name in names
                if (match := json_pattern.fullmatch(name)) is not None
            ]
            if len(json_matches) != 1:
                raise RunnerError("suite export does not contain the expected module")
            json_name, filename_match = json_matches[0]
            filename_test_id = filename_match.group(1)
            signature_name = f"{json_name.removesuffix('.json')}.sig"
            expected_names = {
                json_name,
                signature_name,
            }
            if set(names) != expected_names:
                raise RunnerError("suite export contains unexpected files")

            total_size = 0
            for entry in entries:
                mode = entry.external_attr >> 16
                if (
                    entry.is_dir()
                    or "/" in entry.filename
                    or "\\" in entry.filename
                    or stat.S_ISLNK(mode)
                    or entry.flag_bits & 0x1
                    or entry.compress_type
                    not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                    or entry.file_size <= 0
                    or entry.file_size > MAX_SUITE_EXPORT_BYTES
                    or (
                        entry.filename == signature_name
                        and entry.file_size > MAX_SUITE_SIGNATURE_BYTES
                    )
                ):
                    raise RunnerError("suite export contains an unsafe ZIP entry")
                total_size += entry.file_size
                if total_size > MAX_SUITE_EXPORT_BYTES:
                    raise RunnerError("suite export uncompressed size is too large")
                if entry.file_size > 1024 * 1024 and (
                    entry.compress_size <= 0
                    or entry.file_size
                    > entry.compress_size * MAX_SUITE_EXPORT_COMPRESSION_RATIO
                ):
                    raise RunnerError(
                        "suite export contains a suspicious compression ratio"
                    )

            content: dict[str, bytes] = {}
            for name in expected_names:
                entry = archive.getinfo(name)
                with archive.open(entry) as handle:
                    content[name] = handle.read(entry.file_size + 1)
                if len(content[name]) != entry.file_size:
                    raise RunnerError("suite export ZIP entry has an invalid size")
    except (EOFError, zipfile.BadZipFile, zlib.error):
        raise RunnerError("suite export contains invalid compressed data") from None
    encoded = content[json_name]
    verify_suite_export_signature(encoded, content[signature_name], suite_jwks)
    try:
        exported = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise RunnerError("suite export module is not valid JSON") from None
    if not isinstance(exported, dict):
        raise RunnerError("suite export module must be a JSON object")
    expected_keys = {
        "exportedAt",
        "exportedBy",
        "exportedFrom",
        "exportedVersion",
        "results",
        "testInfo",
    }
    if set(exported) != expected_keys:
        raise RunnerError("suite export module has an unsupported shape")
    results = exported.get("results")
    if (
        not isinstance(results, list)
        or not results
        or len(results) > 20_000
        or any(not isinstance(entry, dict) for entry in results)
    ):
        raise RunnerError("suite export results have an unsupported shape")
    test_info = exported.get("testInfo")
    if (
        not isinstance(test_info, dict)
        or test_info.get("_id") != filename_test_id
        or test_info.get("testId") != filename_test_id
        or not isinstance(test_info.get("planId"), str)
        or not 0 < len(test_info["planId"]) <= 128
    ):
        raise RunnerError("suite export run identifiers do not match")
    return exported


def validate_suite_timestamp(value: Any) -> tuple[str, dt.datetime]:
    if (
        not isinstance(value, str)
        or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
            r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z",
            value,
        )
        is None
    ):
        raise RunnerError("suite run start timestamp is invalid")
    try:
        parsed = dt.datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        raise RunnerError("suite run start timestamp is invalid") from None
    return value, parsed


def completion_timestamp(
    results: list[dict[str, Any]],
    module_id: str,
    suite_result: str,
    started: dt.datetime,
) -> str:
    terminal = [
        entry
        for entry in results
        if entry.get("src") == module_id
        and entry.get("result") == "FINISHED"
        and entry.get("testmodule_result") == suite_result
    ]
    if len(terminal) != 1:
        raise RunnerError(
            "suite export must contain one matching terminal module record"
        )
    epoch_ms = terminal[0].get("time")
    if (
        isinstance(epoch_ms, bool)
        or not isinstance(epoch_ms, int)
        or not 0 < epoch_ms < 32_503_680_000_000
    ):
        raise RunnerError("suite run completion timestamp is invalid")
    completed = dt.datetime.fromtimestamp(epoch_ms / 1000, tz=dt.UTC)
    if completed < started:
        raise RunnerError("suite run completes before it starts")
    return completed.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def validate_considered_log_bindings(
    results: list[dict[str, Any]], module_id: str, test_id: str
) -> None:
    for entry in results:
        considered = entry.get("result") in CONDITION_RESULTS or (
            entry.get("src") == module_id and entry.get("result") == "FINISHED"
        )
        if considered and entry.get("testId") != test_id:
            raise RunnerError("suite export log entry does not match the selected run")


def validate_https_url(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 2048
        or "\\" in value
        or any(
            character.isspace()
            or ord(character) < 0x20
            or ord(character) == 0x7F
            for character in value
        )
    ):
        raise RunnerError(f"suite runtime configuration {label} is invalid")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError:
        raise RunnerError(
            f"suite runtime configuration {label} is invalid"
        ) from None
    hostname = parsed.hostname
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", hostname) is None
            and re.fullmatch(r"[0-9A-Fa-f:.]+", hostname) is None
        )
    ):
        raise RunnerError(f"suite runtime configuration {label} is invalid")
    normalized_host = (
        f"[{hostname.lower()}]" if ":" in hostname else hostname.lower()
    )
    if port is not None:
        normalized_host = f"{normalized_host}:{port}"
    return urllib.parse.urlunsplit(
        ("https", normalized_host, parsed.path, "", "")
    )


def redacted_runtime_configuration_sha256(
    config: Any, template: dict[str, Any], module_id: str
) -> str:
    expected_top_level = {"alias", "description", "vci", "client", "client2"}
    expected_vci = {
        "authorization_server",
        "credential_configuration_id",
        "credential_issuer_url",
        "credential_proof_type_hint",
        "static_tx_code",
    }
    if (
        not isinstance(config, dict)
        or set(config) != expected_top_level
        or not isinstance(config.get("vci"), dict)
        or set(config["vci"]) != expected_vci
        or not isinstance(config.get("client"), dict)
        or set(config["client"]) != {"client_id"}
        or not isinstance(config.get("client2"), dict)
        or set(config["client2"]) != {"client_id"}
        or config.get("alias") != template.get("alias")
        or config.get("description")
        not in {
            template.get("description"),
            f"{template.get('description')} [{module_id}]",
        }
    ):
        raise RunnerError("suite runtime configuration has an unsupported shape")
    validate_https_url(config["vci"].get("credential_issuer_url"), "issuer URL")
    validate_https_url(
        config["vci"].get("authorization_server"), "authorization server"
    )
    string_fields = (
        config["vci"].get("credential_configuration_id"),
        config["vci"].get("credential_proof_type_hint"),
        config["vci"].get("static_tx_code"),
        config["client"].get("client_id"),
        config["client2"].get("client_id"),
    )
    if any(
        not isinstance(value, str) or not value or len(value) > 256
        for value in string_fields
    ):
        raise RunnerError("suite runtime configuration contains an invalid value")
    redacted = json.loads(json.dumps(config))
    redacted["vci"]["static_tx_code"] = "<redacted>"
    return canonical_sha256(redacted)


def condition_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(
        entry.get("result")
        for entry in results
        if entry.get("result") in CONDITION_RESULTS
    )
    return {
        "counts": {
            "info": counts["INFO"],
            "success": counts["SUCCESS"],
            "review": counts["REVIEW"],
            "warning": counts["WARNING"],
            "failure": counts["FAILURE"],
        }
    }


def collect_sensitive_raw_values(value: Any) -> set[str]:
    sensitive: set[str] = set()

    def collect_scalars(item: Any) -> None:
        if isinstance(item, str) and len(item) >= 8:
            sensitive.add(item)
        elif isinstance(item, dict):
            for nested in item.values():
                collect_scalars(nested)
        elif isinstance(item, list):
            for nested in item:
                collect_scalars(nested)

    def visit(item: Any) -> None:
        if isinstance(item, dict):
            for key, nested in item.items():
                if key.lower() in SENSITIVE_RAW_KEYS:
                    collect_scalars(nested)
                else:
                    visit(nested)
        elif isinstance(item, list):
            for nested in item:
                visit(nested)

    visit(value)
    return sensitive


def assert_public_summary_safe(
    summary: dict[str, Any], sensitive_values: set[str]
) -> bytes:
    expected_top_level = {
        "candidate",
        "classification",
        "configuration",
        "contains_sensitive_material",
        "deployment",
        "raw_suite_export_included",
        "review_required",
        "run",
        "scenario",
        "schema_version",
        "suite",
        "unsupported_scenarios",
    }
    if set(summary) != expected_top_level:
        raise RunnerError("evidence summary contains non-allowlisted fields")

    def check_keys(value: Any) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                if key.lower() in FORBIDDEN_PUBLIC_KEYS:
                    raise RunnerError(
                        f"evidence summary contains forbidden field {key}"
                    )
                check_keys(nested)
        elif isinstance(value, list):
            for nested in value:
                check_keys(nested)

    check_keys(summary)
    encoded = (
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    text = encoded.decode("utf-8")
    if any(secret in text for secret in sensitive_values):
        raise RunnerError("evidence summary contains sensitive suite material")
    if "openid-credential-offer://" in text or re.search(
        r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{16,}\."
        r"[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}(?![A-Za-z0-9_-])",
        text,
    ):
        raise RunnerError("evidence summary contains credential or token material")
    return encoded


def candidate_evidence_summary(candidate: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "release_id",
        "version",
        "source_repo",
        "source_ref",
        "source_tag",
        "tag_target",
        "manifest_sha256",
        "image_lock_sha256",
        "release_capsule_sha256",
        "notary_image",
    )
    try:
        selected = {key: candidate[key] for key in keys}
    except KeyError:
        raise RunnerError("authenticated candidate result is incomplete") from None
    selected["release_assets_authenticity_verified"] = True
    return selected


def build_evidence_summary(
    plan_map: dict[str, Any],
    scenario: dict[str, Any],
    exported: dict[str, Any],
    candidate: dict[str, Any],
    suite_jwks_sha256: str,
) -> tuple[dict[str, Any], set[str]]:
    modules = scenario.get("suite_modules")
    if modules != ["oid4vci-1_0-issuer-metadata-test"]:
        raise RunnerError("evidence scenario must select only the metadata module")
    suite_ref = plan_map.get("suite", {}).get("ref")
    if not isinstance(suite_ref, str) or COMMIT.fullmatch(suite_ref) is None:
        raise RunnerError("evidence suite ref must be one pinned commit")
    suite_release_tag = plan_map.get("suite", {}).get("release_tag")
    suite_base_url = plan_map.get("suite", {}).get("base_url")
    release_match = (
        re.fullmatch(r"release-v([0-9]+\.[0-9]+\.[0-9]+)", suite_release_tag)
        if isinstance(suite_release_tag, str)
        else None
    )
    if release_match is None or not isinstance(suite_base_url, str):
        raise RunnerError("evidence suite release identity is invalid")
    suite_version = release_match.group(1)
    if (
        not isinstance(suite_jwks_sha256, str)
        or SHA256.fullmatch(suite_jwks_sha256) is None
    ):
        raise RunnerError("suite JWKS digest is invalid")
    test_info = exported.get("testInfo")
    results = exported["results"]
    if (
        not isinstance(test_info, dict)
        or test_info.get("testName") != modules[0]
        or test_info.get("variant") != scenario.get("variants")
        or test_info.get("status") != "FINISHED"
        or test_info.get("result") not in SUITE_RESULTS
        or test_info.get("version") != suite_version
        or exported.get("exportedVersion") != suite_version
        or exported.get("exportedFrom") != suite_base_url
    ):
        raise RunnerError(
            "suite export identity, version, selection, or terminal status does not match"
        )
    started_at, started = validate_suite_timestamp(test_info.get("started"))
    test_id = test_info["testId"]
    if not isinstance(test_id, str) or TEST_ID.fullmatch(test_id) is None:
        raise RunnerError("suite export run identifier is invalid")
    validate_considered_log_bindings(results, modules[0], test_id)
    completed_at = completion_timestamp(
        results, modules[0], test_info["result"], started
    )
    template_path = CONFIG_DIR / scenario["config_template"]
    try:
        template = json.loads(template_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise RunnerError(
            "checked-in suite configuration template is invalid"
        ) from None
    runtime_config_sha256 = redacted_runtime_configuration_sha256(
        test_info.get("config"), template, modules[0]
    )
    issuer_url = validate_https_url(
        test_info["config"]["vci"]["credential_issuer_url"], "issuer URL"
    )
    unsupported = [
        {
            "scenario_id": item["id"],
            "status": item["status"],
        }
        for item in plan_map["scenarios"]
        if item.get("status") not in {"applicable", "candidate-only"}
    ]
    expected_unsupported = [
        {"scenario_id": scenario_id, "status": status}
        for scenario_id, status in EVIDENCE_UNSUPPORTED_SCENARIOS
    ]
    if unsupported != expected_unsupported:
        raise RunnerError("plan map unsupported scenario contract changed")
    summary = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "classification": EVIDENCE_CLASSIFICATION,
        "review_required": True,
        "contains_sensitive_material": False,
        "raw_suite_export_included": False,
        "candidate": candidate_evidence_summary(candidate),
        "deployment": {
            "issuer_url": issuer_url,
            "candidate_association": EVIDENCE_ASSOCIATION,
        },
        "suite": {
            "repository": plan_map["suite"]["repo"],
            "commit": suite_ref,
            "release_tag": suite_release_tag,
            "reported_version": suite_version,
            "exported_from": suite_base_url,
            "commit_association": EVIDENCE_ASSOCIATION,
            "jwks_sha256": suite_jwks_sha256,
            "export_signature_verified": True,
        },
        "scenario": {
            "scenario_id": scenario["id"],
            "expected_plan": scenario["suite_plan"],
            "plan_association": EVIDENCE_ASSOCIATION,
            "modules": modules,
            "variants": scenario["variants"],
        },
        "configuration": {
            "plan_map_sha256": f"sha256:{file_sha256(PLAN_MAP_PATH)}",
            "template_sha256": f"sha256:{file_sha256(template_path)}",
            "redacted_runtime_configuration_sha256": runtime_config_sha256,
            "redacted_fields": ["vci.static_tx_code"],
        },
        "run": {
            "started_at": started_at,
            "completed_at": completed_at,
            "terminal_status": test_info["status"],
            "result": test_info["result"],
            "conditions": condition_summary(results),
        },
        "unsupported_scenarios": unsupported,
    }
    return summary, collect_sensitive_raw_values(exported)


def expected_suite_artifact_stamp(checkout: Path, jar: Path) -> dict[str, str]:
    return {
        "source_ref": suite_checkout_ref(checkout),
        "builder_override_sha256": file_sha256(BUILDER_COMPOSE_OVERRIDE_PATH),
        "jar_sha256": file_sha256(jar),
    }


def ensure_suite_artifact(checkout: Path, args: argparse.Namespace) -> Path:
    jar = checkout / SUITE_JAR
    stamp = checkout / SUITE_JAR_STAMP
    if jar.exists() and stamp.exists() and not args.rebuild_suite:
        try:
            stamped = json.loads(stamp.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            stamped = None
        if stamped == expected_suite_artifact_stamp(checkout, jar):
            return jar
    if not shutil.which("docker"):
        raise RunnerError("docker is required to build the OpenID conformance suite")
    maven_cache = Path(args.maven_cache_dir).expanduser().resolve()
    maven_cache.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["MAVEN_CACHE"] = str(maven_cache)
    run_checked(
        builder_command(checkout, "run", "--rm", "builder"),
        cwd=checkout,
        env=env,
    )
    if not jar.exists():
        raise RunnerError(f"OpenID conformance suite build did not create {jar}")
    stamp.write_text(
        json.dumps(expected_suite_artifact_stamp(checkout, jar), sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    return jar


def requirements_digest(*requirements_paths: Path) -> str:
    digest = hashlib.sha256()
    for path in requirements_paths:
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def suite_python(args: argparse.Namespace) -> Path:
    digest = requirements_digest(
        SUITE_REQUIREMENTS_INPUT_PATH, SUITE_REQUIREMENTS_LOCK_PATH
    )
    cache_key = f"py{sys.version_info.major}.{sys.version_info.minor}-{digest[:16]}"
    venv_dir = Path(args.python_venv_dir).expanduser().resolve() / cache_key
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def ensure_suite_python(checkout: Path, args: argparse.Namespace) -> Path:
    requirements_path = checkout / "scripts" / "requirements.txt"
    if not requirements_path.exists():
        raise RunnerError(f"missing suite Python requirements: {requirements_path}")
    if requirements_path.read_bytes() != SUITE_REQUIREMENTS_INPUT_PATH.read_bytes():
        raise RunnerError(
            "suite Python requirements differ from the checked-in locked input; "
            "review and regenerate release/conformance/openid/python-requirements.txt"
        )
    python = suite_python(args)
    venv_dir = python.parents[1]
    digest = requirements_digest(
        SUITE_REQUIREMENTS_INPUT_PATH, SUITE_REQUIREMENTS_LOCK_PATH
    )
    stamp = venv_dir / ".requirements.sha256"
    cache_matches = (
        python.exists()
        and stamp.exists()
        and stamp.read_text(encoding="utf-8").strip() == digest
    )
    if venv_dir.exists() and not cache_matches:
        shutil.rmtree(venv_dir)
    if not python.exists():
        run_checked([sys.executable, "-m", "venv", str(venv_dir)])
        run_checked(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--require-hashes",
                "--only-binary=:all:",
                "-r",
                str(SUITE_REQUIREMENTS_LOCK_PATH),
            ]
        )
        stamp.write_text(digest + "\n", encoding="utf-8")
    return python


def wait_for_suite(base_url: str, timeout_seconds: int) -> None:
    url = base_url.rstrip("/") + "/api/runner/available"
    # The pinned suite's local development endpoint uses a self-signed certificate.
    context = ssl._create_unverified_context()
    deadline = time.time() + timeout_seconds
    last_error = ""
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5, context=context) as response:
                if response.status == 200:
                    return
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = str(exc)
        time.sleep(2)
    raise RunnerError(f"conformance suite did not become ready at {url}: {last_error}")


def read_offer(path: Path, issuer_url: str) -> str:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    cloexec = getattr(os, "O_CLOEXEC", None)
    if nofollow is None or cloexec is None or not hasattr(os, "geteuid"):
        raise RunnerError("secure offer input handling is unavailable")
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY | cloexec | nofollow)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
        ):
            raise RunnerError("offer input must be an owner-only regular file")
        if not 0 < info.st_size <= 65_536:
            raise RunnerError("offer input has an invalid size")
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            raw = handle.read(65_537)
    except OSError:
        raise RunnerError("offer input could not be opened securely") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(raw) != info.st_size:
        raise RunnerError("offer input changed while it was read")
    try:
        offer_uri = raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise RunnerError("offer input is not valid UTF-8") from None
    parsed = urllib.parse.urlsplit(offer_uri)
    try:
        query = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
    except ValueError:
        raise RunnerError("offer input has a malformed query") from None
    if (
        parsed.scheme != "openid-credential-offer"
        or parsed.netloc
        or parsed.path
        or parsed.fragment
        or set(query) != {"credential_offer"}
        or len(query["credential_offer"]) != 1
    ):
        raise RunnerError("offer input is not one inline credential offer URI")
    inline = query["credential_offer"][0]
    offer = json.loads(inline)
    grant = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    if (
        not isinstance(offer, dict)
        or offer.get("credential_issuer") != issuer_url.rstrip("/")
        or not isinstance(offer.get("grants"), dict)
        or set(offer["grants"]) != {grant}
        or not isinstance(offer["grants"][grant], dict)
        or not isinstance(offer["grants"][grant].get("pre-authorized_code"), str)
    ):
        raise RunnerError("offer is not the expected Notary pre-authorized offer")
    return inline


def read_suite_ca_certificate(path: Path) -> bytes:
    path = path.expanduser()
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    descriptor: int | None = None
    before: os.stat_result | None = None
    try:
        if not nofollow:
            before = path.lstat()
            if stat.S_ISLNK(before.st_mode):
                raise RunnerError(
                    "suite CA certificate could not be opened securely"
                )
        descriptor = os.open(path, os.O_RDONLY | nofollow | cloexec)
        info = os.fstat(descriptor)
        if before is not None and (
            before.st_dev != info.st_dev or before.st_ino != info.st_ino
        ):
            raise RunnerError("suite CA certificate changed while it was opened")
        if (
            not stat.S_ISREG(info.st_mode)
            or not 0 < info.st_size <= 1024 * 1024
        ):
            raise RunnerError(
                "suite CA certificate must be a bounded regular file"
            )
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            certificate = handle.read(1024 * 1024 + 1)
    except OSError:
        raise RunnerError(
            "suite CA certificate could not be opened securely"
        ) from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(certificate) != info.st_size:
        raise RunnerError("suite CA certificate changed while it was read")
    return certificate


def add_suite_ca(context: ssl.SSLContext, certificate: bytes) -> None:
    try:
        text = certificate.decode("ascii")
    except UnicodeDecodeError:
        cadata: str | bytes = certificate
    else:
        cadata = text if "-----BEGIN CERTIFICATE-----" in text else certificate
    try:
        context.load_verify_locations(cadata=cadata)
    except (OSError, ValueError):
        raise RunnerError("suite CA certificate could not be loaded") from None


def suite_tls_context(ca_certificate: Path | None) -> ssl.SSLContext:
    if ca_certificate is None:
        return ssl.create_default_context()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    add_suite_ca(context, read_suite_ca_certificate(ca_certificate))
    return context


def suite_https_opener(context: ssl.SSLContext):
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        NoRedirect(),
    )


def suite_jwks_url(base_url: str) -> str:
    parsed = urllib.parse.urlsplit(base_url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise RunnerError("conformance server must be one HTTPS origin")
    return urllib.parse.urlunsplit(parsed._replace(path="/jwks"))


def cmd_export_suite_jwks(args: argparse.Namespace) -> int:
    url = suite_jwks_url(args.conformance_server)
    context = suite_tls_context(args.suite_ca_certificate)
    opener = suite_https_opener(context)
    try:
        with opener.open(url, timeout=args.timeout_seconds) as response:
            if not 200 <= response.status < 300:
                raise RunnerError(
                    f"suite JWKS endpoint returned HTTP {response.status}"
                )
            content = response.read(MAX_SUITE_JWKS_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise RunnerError(f"suite JWKS endpoint returned HTTP {exc.code}") from None
    except (OSError, urllib.error.URLError):
        raise RunnerError("suite JWKS fetch failed") from None
    if not 0 < len(content) <= MAX_SUITE_JWKS_BYTES:
        raise RunnerError("suite JWKS response has an invalid size")
    jwks = parse_suite_jwks(content)
    encoded = (
        json.dumps(jwks, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    output = write_new_file(args.output, encoded)
    print(output)
    return 0


def cmd_submit_offer(args: argparse.Namespace) -> int:
    inline = read_offer(args.offer_file, args.issuer_url)
    base = urllib.parse.urlsplit(args.conformance_server)
    endpoint = urllib.parse.urlsplit(args.suite_offer_endpoint)
    if (
        (endpoint.scheme, endpoint.netloc) != (base.scheme, base.netloc)
        or endpoint.scheme != "https"
        or not endpoint.path.endswith("/credential_offer")
        or endpoint.query
        or endpoint.fragment
    ):
        raise RunnerError(
            "suite offer endpoint must use HTTPS on the pinned suite origin"
        )
    url = urllib.parse.urlunsplit(
        endpoint._replace(query=urllib.parse.urlencode({"credential_offer": inline}))
    )
    context = suite_tls_context(args.suite_ca_certificate)
    opener = suite_https_opener(context)
    try:
        with opener.open(url, timeout=args.timeout_seconds) as response:
            if not 200 <= response.status < 300:
                raise RunnerError(f"suite offer endpoint returned HTTP {response.status}")
    except urllib.error.HTTPError as exc:
        raise RunnerError(f"suite offer endpoint returned HTTP {exc.code}") from None
    except (OSError, urllib.error.URLError):
        raise RunnerError("suite offer submission failed") from None
    print("credential offer submitted")
    return 0


def write_new_file(path: Path, content: bytes) -> Path:
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = None
            handle.write(content)
    except OSError:
        raise RunnerError("output could not be created") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return path


def cmd_export_suite_ca(args: argparse.Namespace) -> int:
    checkout = suite_dir(args)
    if not checkout.is_dir():
        raise RunnerError("suite checkout is unavailable; run prepare first")
    output = Path(args.output).expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env[COMPOSE_CONFIG_DIR_ENV] = str(CONFIG_DIR)
    with tempfile.TemporaryDirectory(
        prefix=".openid-suite-ca-", dir=output.parent
    ) as tmp:
        copied = Path(tmp) / "nginx-selfsigned.crt"
        run_checked(
            compose_command(
                checkout,
                args,
                "cp",
                f"nginx:{SUITE_CA_CONTAINER_PATH}",
                str(copied),
            ),
            env=env,
        )
        certificate = read_suite_ca_certificate(copied)
        validation_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        add_suite_ca(validation_context, certificate)
        write_new_file(output, certificate)
    print(output)
    return 0


def output_dir_for(args: argparse.Namespace, scenario_id: str) -> Path:
    if args.output_dir:
        return Path(args.output_dir).expanduser().resolve()
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    return DEFAULT_OUTPUT_ROOT / f"{scenario_id}-{stamp}"


def build_run(
    plan_map: dict[str, Any],
    scenario: dict[str, Any],
    args: argparse.Namespace,
    python_executable: str | None = None,
) -> tuple[Path, dict[str, str], list[str]]:
    settings = suite_settings(plan_map, args)
    checkout = suite_dir(args)
    output_dir = output_dir_for(args, scenario["id"])
    params = default_params(scenario, args)
    config_path = write_rendered_config(scenario, output_dir, params)
    env = os.environ.copy()
    env["CONFORMANCE_SERVER"] = settings["base_url"]
    env["CONFORMANCE_SERVER_LOCAL"] = settings["local_base_url"]
    env["CONFORMANCE_SERVER_MTLS"] = settings["mtls_base_url"]
    if not env.get("CONFORMANCE_TOKEN"):
        env["CONFORMANCE_DEV_MODE"] = "1"
    command = [
        python_executable or sys.executable,
        str(checkout / "scripts" / "run-test-plan.py"),
        "--export-dir",
        str(output_dir),
        scenario_plan_arg(scenario),
        str(config_path),
    ]
    return output_dir, env, command


def cmd_list(args: argparse.Namespace) -> int:
    plan_map = load_plan_map(args.plan_map)
    for scenario in plan_map["scenarios"]:
        print(f"{scenario['id']}\t{scenario['status']}\t{scenario_plan_arg(scenario)}")
    return 0


def cmd_prepare(args: argparse.Namespace) -> int:
    plan_map = load_plan_map(args.plan_map)
    checkout = ensure_suite_checkout(plan_map, args)
    ensure_suite_artifact(checkout, args)
    ensure_suite_python(checkout, args)
    print(checkout)
    return 0


def cmd_up(args: argparse.Namespace) -> int:
    plan_map = load_plan_map(args.plan_map)
    checkout = ensure_suite_checkout(plan_map, args)
    ensure_suite_artifact(checkout, args)
    env = os.environ.copy()
    env[COMPOSE_CONFIG_DIR_ENV] = str(CONFIG_DIR)
    run_checked(compose_command(checkout, args, "up", "-d", "--build"), env=env)
    settings = suite_settings(plan_map, args)
    wait_for_suite(settings["base_url"], args.wait_seconds)
    print(settings["base_url"])
    return 0


def cmd_down(args: argparse.Namespace) -> int:
    checkout = suite_dir(args)
    env = os.environ.copy()
    env[COMPOSE_CONFIG_DIR_ENV] = str(CONFIG_DIR)
    run_checked(compose_command(checkout, args, "down"), env=env)
    return 0


def cmd_render_config(args: argparse.Namespace) -> int:
    plan_map = load_plan_map(args.plan_map)
    scenario = find_scenario(plan_map, args.scenario)
    output_dir = output_dir_for(args, scenario["id"])
    config_path = write_rendered_config(
        scenario, output_dir, default_params(scenario, args)
    )
    print(config_path)
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    plan_map = load_plan_map(args.plan_map)
    scenario = find_scenario(plan_map, args.scenario)
    if scenario.get("status") not in {"applicable", "candidate-only"} and not args.allow_blocked:
        raise RunnerError(
            f"scenario {scenario['id']} is {scenario.get('status')}; "
            "pass --allow-blocked to run it anyway"
        )
    if not args.no_prepare:
        ensure_suite_checkout(plan_map, args)
    checkout = suite_dir(args)
    python = suite_python(args) if args.dry_run else ensure_suite_python(checkout, args)
    output_dir, env, command = build_run(plan_map, scenario, args, str(python))
    if args.dry_run:
        print(json.dumps({"output_dir": str(output_dir), "command": command}, indent=2))
        return 0
    wait_for_suite(env["CONFORMANCE_SERVER"], args.wait_seconds)
    result = subprocess.run(command, cwd=checkout, env=env, text=True, check=False)
    if result.returncode != 0:
        raise RunnerError(
            f"OpenID conformance run failed with status {result.returncode}; "
            f"output: {output_dir}"
        )
    print(output_dir)
    return 0


def cmd_promote_evidence(args: argparse.Namespace) -> int:
    plan_map = load_plan_map()
    scenario = find_scenario(plan_map, EVIDENCE_SCENARIO_ID)
    modules = scenario.get("suite_modules")
    if not isinstance(modules, list) or len(modules) != 1:
        raise RunnerError("evidence scenario must select exactly one suite module")
    suite_jwks, suite_jwks_sha256 = load_suite_jwks(args.suite_jwks)
    exported = load_suite_export(args.suite_export, modules[0], suite_jwks)
    candidate = load_authenticated_candidate(args.release_manifest, args.image_lock)
    try:
        summary, sensitive_values = build_evidence_summary(
            plan_map,
            scenario,
            exported,
            candidate,
            suite_jwks_sha256,
        )
        encoded = assert_public_summary_safe(summary, sensitive_values)
    except RecursionError:
        raise RunnerError("suite export is too deeply nested") from None
    try:
        schema = json.loads(EVIDENCE_SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise RunnerError("checked-in evidence schema is invalid") from None
    if (
        schema.get("properties", {}).get("schema_version", {}).get("const")
        != EVIDENCE_SCHEMA_VERSION
    ):
        raise RunnerError("checked-in evidence schema version is invalid")
    try:
        validate_against_schema(summary, schema, schema, "evidence summary")
    except SchemaValidationError as exc:
        raise RunnerError(f"evidence summary does not match its schema: {exc}") from None
    output = write_new_file(args.output, encoded)
    print(output)
    return 0


def load_authenticated_candidate(
    release_manifest: Path, image_lock: Path
) -> dict[str, Any]:
    try:
        from conformance_candidate import CandidateError, load_candidate
    except ModuleNotFoundError as exc:
        dependency = exc.name or "the candidate validation dependency"
        raise RunnerError(
            f"promote-evidence requires {dependency}; install the release tooling dependencies"
        ) from None
    try:
        return load_candidate(release_manifest, image_lock)
    except CandidateError as exc:
        raise RunnerError(str(exc)) from None


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--plan-map", type=Path, default=PLAN_MAP_PATH)
    parser.add_argument("--cache-dir", default=str(DEFAULT_CACHE_DIR))
    parser.add_argument("--suite-dir")
    parser.add_argument("--suite-repo")
    parser.add_argument("--suite-ref")
    parser.add_argument("--conformance-server")
    parser.add_argument("--conformance-server-local")
    parser.add_argument("--conformance-server-mtls")
    parser.add_argument("--maven-cache-dir", default=str(DEFAULT_CACHE_DIR / "maven"))
    parser.add_argument("--python-venv-dir", default=str(DEFAULT_CACHE_DIR / "python"))
    parser.add_argument("--rebuild-suite", action="store_true")


def add_config_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("scenario")
    parser.add_argument("--issuer-url")
    parser.add_argument("--authorization-server")
    parser.add_argument("--credential-configuration-id")
    parser.add_argument("--static-tx-code", default="0000")
    parser.add_argument("--client-id", default="registry-stack-openid-conformance-client")
    parser.add_argument(
        "--client2-id", default="registry-stack-openid-conformance-client-2"
    )
    parser.add_argument("--output-dir")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list")
    add_common(list_parser)
    list_parser.set_defaults(func=cmd_list)

    prepare_parser = subparsers.add_parser("prepare")
    add_common(prepare_parser)
    prepare_parser.set_defaults(func=cmd_prepare)

    up_parser = subparsers.add_parser("up")
    add_common(up_parser)
    up_parser.add_argument("--wait-seconds", type=int, default=180)
    up_parser.set_defaults(func=cmd_up)

    down_parser = subparsers.add_parser("down")
    add_common(down_parser)
    down_parser.set_defaults(func=cmd_down)

    export_ca_parser = subparsers.add_parser("export-suite-ca")
    export_ca_parser.add_argument("--cache-dir", default=str(DEFAULT_CACHE_DIR))
    export_ca_parser.add_argument("--suite-dir")
    export_ca_parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_SUITE_CA_PATH,
        help="new file that receives the running suite's generated certificate",
    )
    export_ca_parser.set_defaults(func=cmd_export_suite_ca)

    export_jwks_parser = subparsers.add_parser(
        "export-suite-jwks",
        help="capture the suite export-signing keys over authenticated HTTPS",
    )
    export_jwks_parser.add_argument(
        "--conformance-server",
        default=load_plan_map()["suite"]["base_url"],
    )
    export_jwks_parser.add_argument(
        "--suite-ca-certificate",
        type=Path,
        help="PEM or DER trust anchor captured from the local suite",
    )
    export_jwks_parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_SUITE_JWKS_PATH,
        help="new owner-only file that receives the validated suite JWKS",
    )
    export_jwks_parser.add_argument("--timeout-seconds", type=int, default=10)
    export_jwks_parser.set_defaults(func=cmd_export_suite_jwks)

    render_parser = subparsers.add_parser("render-config")
    add_common(render_parser)
    add_config_args(render_parser)
    render_parser.set_defaults(func=cmd_render_config)

    run_parser = subparsers.add_parser("run")
    add_common(run_parser)
    add_config_args(run_parser)
    run_parser.add_argument("--allow-blocked", action="store_true")
    run_parser.add_argument("--dry-run", action="store_true")
    run_parser.add_argument("--no-prepare", action="store_true")
    run_parser.add_argument("--wait-seconds", type=int, default=180)
    run_parser.set_defaults(func=cmd_run)

    offer_parser = subparsers.add_parser("submit-offer")
    offer_parser.add_argument("--offer-file", type=Path, required=True)
    offer_parser.add_argument("--issuer-url", required=True)
    offer_parser.add_argument("--suite-offer-endpoint", required=True)
    offer_parser.add_argument(
        "--conformance-server",
        default=load_plan_map()["suite"]["base_url"],
    )
    offer_parser.add_argument(
        "--suite-ca-certificate",
        type=Path,
        help="PEM or DER trust anchor captured from the local suite",
    )
    offer_parser.add_argument("--timeout-seconds", type=int, default=10)
    offer_parser.set_defaults(func=cmd_submit_offer)

    promote_parser = subparsers.add_parser(
        "promote-evidence",
        help="create a closed candidate-referenced summary from one private suite export",
    )
    promote_parser.add_argument(
        "--suite-export",
        type=Path,
        required=True,
        help="owner-only OIDF plan export ZIP kept outside the repository",
    )
    promote_parser.add_argument(
        "--suite-jwks",
        type=Path,
        required=True,
        help="owner-only JWKS captured from the authenticated suite origin",
    )
    promote_parser.add_argument(
        "--release-manifest",
        type=Path,
        required=True,
        help="checked-in release manifest for the published candidate",
    )
    promote_parser.add_argument(
        "--image-lock",
        type=Path,
        required=True,
        help="downloaded signed registryctl release image lock",
    )
    promote_parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="new JSON file for the allowlisted review summary",
    )
    promote_parser.set_defaults(func=cmd_promote_evidence)

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        return int(args.func(args))
    except (
        OSError,
        json.JSONDecodeError,
        KeyError,
        RunnerError,
    ) as exc:
        print(f"openid-conformance-runner: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
