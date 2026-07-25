#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run mapped OpenID Foundation conformance-suite slices for Registry Stack."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
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
from pathlib import Path
from string import Template
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = REPO_ROOT / "release" / "conformance" / "openid"
PLAN_MAP_PATH = CONFIG_DIR / "plan-map.json"
COMPOSE_OVERRIDE_PATH = CONFIG_DIR / "docker-compose.override.yaml"
BUILDER_COMPOSE_OVERRIDE_PATH = CONFIG_DIR / "docker-compose-builder.override.yaml"
SUITE_REQUIREMENTS_INPUT_PATH = CONFIG_DIR / "python-requirements.in"
SUITE_REQUIREMENTS_LOCK_PATH = CONFIG_DIR / "python-requirements.txt"
DEFAULT_WORK_ROOT = REPO_ROOT / "target" / "openid-conformance"
DEFAULT_CACHE_DIR = DEFAULT_WORK_ROOT / "cache"
DEFAULT_OUTPUT_ROOT = DEFAULT_WORK_ROOT / "results"
SCHEMA_VERSION = "registry.release.openid_conformance_plan_map.v1"
SUITE_JAR = "target/fapi-test-suite.jar"
SUITE_JAR_STAMP = "target/fapi-test-suite.jar.registry-stack-source-ref"
COMPOSE_CONFIG_DIR_ENV = "REGISTRY_OPENID_CONFORMANCE_CONFIG_DIR"
SUITE_CA_CONTAINER_PATH = "/etc/ssl/certs/nginx-selfsigned.crt"
DEFAULT_SUITE_CA_PATH = DEFAULT_WORK_ROOT / "conformance-suite-ca.pem"


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
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{scenario['id']}.config.json"
    path.write_text(render_config(scenario, params) + "\n", encoding="utf-8")
    return path


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
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        NoRedirect(),
    )
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
        raise RunnerError("suite CA output could not be created") from None
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

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        return int(args.func(args))
    except (OSError, json.JSONDecodeError, KeyError, RunnerError) as exc:
        print(f"openid-conformance-runner: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
