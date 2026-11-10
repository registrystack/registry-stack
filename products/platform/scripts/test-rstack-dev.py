#!/usr/bin/env python3
"""Exercise rstack dev with real BReg, Casework and a disposable TLS PostgreSQL."""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import unquote, urlsplit
from urllib.request import ProxyHandler, Request, build_opener

STACK = Path(__file__).resolve().parents[3]
NATIVE_REVIEW = STACK / "products/breg/acceptance/reviewed-evidence-journey"
SPATIAL = STACK / "products/breg/acceptance/spatial-service-sites"
HTTP = build_opener(ProxyHandler({}))


def command(*args, env=None, data=None, cwd=None, timeout=120):
    return subprocess.run(
        args,
        env=env,
        input=data,
        cwd=cwd,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def checked(*args, **kwargs):
    result = command(*args, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{Path(args[0]).name} failed with exit {result.returncode}")
    return result.stdout


def port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def prepare_postgres(root, pg):
    password = secrets.token_urlsafe(32)
    cluster = root / "postgres"
    checked(
        pg / "initdb",
        "-D",
        cluster,
        "-U",
        "devadmin",
        "--pwfile=/dev/stdin",
        "--auth-local=trust",
        "--auth-host=scram-sha-256",
        "--no-locale",
        "-E",
        "UTF8",
        data=f"{password}\n".encode(),
    )
    ca = root / "ca.pem"
    checked(
        "openssl",
        "req",
        "-new",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        "/CN=rstack-dev-test",
        "-days",
        "1",
        "-keyout",
        root / "ca.key",
        "-out",
        ca,
        "-addext",
        "basicConstraints=critical,CA:TRUE",
    )
    checked(
        "openssl",
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        "/CN=127.0.0.1",
        "-keyout",
        cluster / "server.key",
        "-out",
        root / "server.csr",
    )
    (cluster / "server.key").chmod(0o600)
    extensions = root / "server.ext"
    extensions.write_text("subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")
    checked(
        "openssl",
        "x509",
        "-req",
        "-in",
        root / "server.csr",
        "-CA",
        ca,
        "-CAkey",
        root / "ca.key",
        "-CAcreateserial",
        "-days",
        "1",
        "-extfile",
        extensions,
        "-out",
        cluster / "server.crt",
    )
    db_port = port()
    with (cluster / "postgresql.conf").open("a") as config:
        config.write(
            f"\nlisten_addresses = '127.0.0.1'\nport = {db_port}\n"
            "unix_socket_directories = ''\nssl = on\nlog_min_error_statement = panic\n"
        )
    pg_env = {
        **os.environ,
        "PGHOST": "127.0.0.1",
        "PGPORT": str(db_port),
        "PGDATABASE": "postgres",
        "PGUSER": "devadmin",
        "PGPASSWORD": password,
        "PGSSLMODE": "verify-full",
        "PGSSLROOTCERT": str(ca),
    }
    url = f"postgresql://devadmin:{password}@127.0.0.1:{db_port}/postgres"
    return cluster, ca, url, pg_env


def psql(pg, env, query):
    return checked(
        pg / "psql", "-XAtq", "-v", "ON_ERROR_STOP=1", env=env, data=query.encode()
    ).decode()


def inventory(pg, env):
    databases = psql(
        pg, env, "SELECT datname FROM pg_database WHERE datname LIKE 'rstack%';"
    )
    roles = psql(
        pg,
        env,
        "SELECT rolname FROM pg_roles WHERE rolname LIKE 'rstack%' OR rolname LIKE 'breg_bbox_%';",
    )
    return set(databases.splitlines()), set(roles.splitlines())


def administrator_locks(pg, env):
    locks = psql(
        pg,
        env,
        """SELECT classid::text || ':' || objid::text || ':' || objsubid::text
        FROM pg_locks
        WHERE locktype = 'advisory' AND granted
        AND database = (SELECT oid FROM pg_database WHERE datname = current_database());""",
    )
    return set(locks.splitlines())


def files(root):
    return {
        path.relative_to(root): hashlib.sha256(path.read_bytes()).digest()
        for path in root.rglob("*")
        if path.is_file()
    }


def dev(bin_dir, env, cwd, *args, expected=0):
    install_root = Path(env["RSTACK_DEV_STATE_DIR"]).with_name("rstack-install")
    result = command(
        bin_dir / "rstack",
        "--install-root",
        install_root,
        "dev",
        *args,
        "--json",
        env=env,
        cwd=cwd,
        timeout=390,
    )
    try:
        report = json.loads(result.stdout)
    except ValueError:
        raise RuntimeError(
            f"rstack dev {args[0]} did not return JSON (exit {result.returncode})"
        ) from None
    if result.returncode != expected:
        raise RuntimeError(f"rstack dev {args[0]} exited {result.returncode}: {report}")
    if args[0] == "check":
        assert report["kind"] == "BRegCtlReport" and report["command"] == "dev-check"
    else:
        assert report["schema_version"] == "registry.rstack.dev.v1"
    return report


def credential(bin_dir, env, cwd, run, alias):
    report = dev(bin_dir, env, cwd, "token", run, "--as", alias)
    [entry] = report["credentials"]
    header_file = Path(entry["header_file"])
    assert header_file.stat().st_mode & 0o077 == 0
    return dict(line.split(": ", 1) for line in header_file.read_text().splitlines())


def get(url, headers):
    try:
        with HTTP.open(Request(url, headers=headers), timeout=5) as response:
            return response.status
    except HTTPError as error:
        return error.code


def kid(headers):
    jwt_header = headers["Authorization"].split()[1].split(".")[0]
    return json.loads(base64.urlsafe_b64decode(jwt_header + "==="))["kid"]


def wait_for_stop(bin_dir, env, cwd, run):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if dev(bin_dir, env, cwd, "status", run)["status"] == "stopped":
            return
        time.sleep(0.2)
    raise RuntimeError("the run did not finish its TTL cleanup")


def verify_deployment_key(root, bin_dir, env, run_root, headers):
    """Start the real verifier with a separate trust pin and the same issuer."""
    key = root / "deployment-issuer.key"
    checked(
        "openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key
    )
    point = checked("openssl", "pkey", "-in", key, "-pubout", "-outform", "DER")[-65:]
    assert point[0] == 4

    def coordinate(value):
        return base64.urlsafe_b64encode(value).decode().rstrip("=")

    jwks = run_root / "deployment-jwks"
    jwks.touch(mode=0o600)
    jwks.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "kty": "EC",
                        "alg": "ES256",
                        "crv": "P-256",
                        "kid": "deployment-key",
                        "x": coordinate(point[1:33]),
                        "y": coordinate(point[33:]),
                    }
                ]
            }
        )
    )
    config = json.loads((run_root / "breg-runtime.yaml").read_text())
    config["authentication"]["oidc"]["jwksSource"]["documentRef"] = (
        "secret:file/deployment-jwks"
    )
    config["audit"]["path"] = str(root / "deployment-audit" / "audit.jsonl")
    config["listener"]["bind"] = f"127.0.0.1:{port()}"
    runtime_file = root / "deployment-verifier.yaml"
    runtime_file.write_text(json.dumps(config))
    process = subprocess.Popen(
        [bin_dir / "breg", "--runtime-config", runtime_file],
        env={
            key: value for key, value in env.items() if key != "RSTACK_DEV_DATABASE_URL"
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        origin = "http://" + config["listener"]["bind"]
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            assert process.poll() is None, "the independently pinned verifier exited"
            try:
                status = get(origin + "/ready", {})
            except OSError:
                # The verifier may still be opening its listener.
                status = None
            if status == 200:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError("the independently pinned verifier did not become ready")
        assert (
            get(origin + "/v1/records/applications?accessProfile=applicant", headers)
            == 401
        )
    finally:
        process.terminate()
        process.wait(timeout=15)


def exercise(root, bin_dir, pg, project, ca, url, pg_env, spatial):
    checkout = root / "licensing"
    shutil.copytree(project, checkout)
    before = files(checkout)
    state = root / "runs"
    env = {
        **os.environ,
        "RSTACK_DEV_STATE_DIR": str(state),
        "RSTACK_DEV_DATABASE_URL": url,
        "RSTACK_DEV_DATABASE_CA": str(ca),
        "RSTACK_BREGCTL_BIN": str(bin_dir / "bregctl"),
        "RSTACK_BREG_BIN": str(bin_dir / "breg"),
        "RSTACK_CASEWORKCTL_BIN": str(bin_dir / "caseworkctl"),
        "RSTACK_CASEWORK_BIN": str(bin_dir / "casework"),
    }
    try:
        exercise_runs(root, bin_dir, pg, checkout, state, env, pg_env)
        verify_provisioning_deadline(bin_dir, pg, checkout, state, env, pg_env)
        if spatial:
            verify_spatial(root, bin_dir, pg, env, pg_env)
        assert files(checkout) == before
    finally:
        if state.exists():
            for run_root in state.iterdir():
                dev(bin_dir, env, checkout, "stop", run_root.name)


def exercise_runs(root, bin_dir, pg, checkout, state, env, pg_env):
    baseline = inventory(pg, pg_env)
    baseline_locks = administrator_locks(pg, pg_env)
    with concurrent.futures.ThreadPoolExecutor(2) as pool:
        runs = list(
            pool.map(lambda _: dev(bin_dir, env, checkout, "start", "."), range(2))
        )
    a, b = runs
    assert all(run["journey"]["result"] == "passed" for run in runs)
    assert a["run_id"] != b["run_id"]
    assert len(administrator_locks(pg, pg_env) - baseline_locks) == 2
    assert len({url for run in runs for url in run["products"].values()}) == 4
    databases, roles = inventory(pg, pg_env)
    assert all(sum(run["run_id"] in item for item in databases) == 3 for run in runs)
    assert all(sum(run["run_id"] in item for item in roles) == 6 for run in runs)
    for product in ("breg", "casework"):
        own_db = next(
            name
            for name in databases
            if a["run_id"] in name and name.endswith(f"_{product}")
        )
        other_db = next(
            name
            for name in databases
            if b["run_id"] in name and name.endswith(f"_{product}")
        )
        url = urlsplit((state / a["run_id"] / f"{product}-runtime-url").read_text())
        role_env = {
            **pg_env,
            "PGUSER": unquote(url.username),
            "PGPASSWORD": unquote(url.password),
            "PGDATABASE": own_db,
        }
        assert psql(pg, role_env, "SELECT current_database();").strip() == own_db
        refused = command(
            pg / "psql",
            "-XAtq",
            "-v",
            "ON_ERROR_STOP=1",
            env={**role_env, "PGDATABASE": other_db},
            data=b"SELECT 1;",
        )
        assert refused.returncode != 0
    for product, alias, path in [
        ("breg", "applicant", "/v1/records/applications?accessProfile=applicant"),
        ("casework", "intake", "/v1/review-policies/licensing-approval"),
    ]:
        first = credential(bin_dir, env, checkout, a["run_id"], alias)
        second = credential(bin_dir, env, checkout, b["run_id"], alias)
        assert kid(first) != kid(second)
        assert get(a["products"][product] + path, first) == 200
        assert get(b["products"][product] + path, second) == 200
        assert get(a["products"][product] + path, second) == 401
        assert get(b["products"][product] + path, first) == 401
    verify_deployment_key(
        root,
        bin_dir,
        env,
        state / a["run_id"],
        credential(bin_dir, env, checkout, a["run_id"], "applicant"),
    )
    print(
        "Concurrent licensing journeys passed with isolated product tokens, ports, databases and roles"
    )

    for run in runs:
        assert dev(bin_dir, env, checkout, "stop", run["run_id"])["status"] == "stopped"
        assert dev(bin_dir, env, checkout, "stop", run["run_id"])["status"] == "stopped"
        assert not (state / run["run_id"]).exists()
    assert inventory(pg, pg_env) == baseline

    short = dev(bin_dir, env, checkout, "start", ".", "--ttl", "1s")
    wait_for_stop(bin_dir, env, checkout, short["run_id"])
    assert inventory(pg, pg_env) == baseline
    assert list(state.iterdir()) == []

    failure_env = {**env, "RSTACK_CASEWORK_BIN": shutil.which("false")}
    report = dev(bin_dir, failure_env, checkout, "start", ".", expected=1)
    assert "casework exited before readiness" in report["error"], report
    assert inventory(pg, pg_env) == baseline, report
    assert list(state.iterdir()) == [], report
    verify_native_handoff(root, bin_dir, env)
    assert inventory(pg, pg_env) == baseline
    assert administrator_locks(pg, pg_env) == baseline_locks
    assert list(state.iterdir()) == []
    print(
        "Stop, TTL expiry and failed startup cleaned up; authored product files stayed byte-identical"
    )


def verify_provisioning_deadline(bin_dir, pg, checkout, state, env, pg_env):
    baseline = inventory(pg, pg_env)
    baseline_locks = administrator_locks(pg, pg_env)
    lock = subprocess.Popen(
        [pg / "psql", "-XAtq", "-v", "ON_ERROR_STOP=1"],
        env={**pg_env, "PGAPPNAME": "rstack-dev-provisioning-lock"},
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    lock_query = """
        SELECT EXISTS (
            SELECT 1 FROM pg_locks locks JOIN pg_stat_activity sessions USING (pid)
            WHERE sessions.application_name = 'rstack-dev-provisioning-lock'
            AND locks.relation = 'pg_catalog.pg_database'::regclass
            AND locks.mode = 'ShareLock' AND locks.granted
        );
    """
    try:
        # A SHARE lock allows new connections and reads but blocks CREATE DATABASE.
        # The idle deadline releases the lock even if the runner stalls.
        lock.stdin.write(
            "SET lock_timeout = '5s';\n"
            "SET idle_in_transaction_session_timeout = '45s';\n"
            "BEGIN;\n"
            "LOCK TABLE pg_catalog.pg_database IN SHARE MODE;\n"
        )
        lock.stdin.flush()
        deadline = time.monotonic() + 10
        while psql(pg, pg_env, lock_query).strip() != "t":
            assert lock.poll() is None, "the PostgreSQL lock fixture exited"
            assert time.monotonic() < deadline, "the PostgreSQL lock was not acquired"
            time.sleep(0.1)

        report = dev(bin_dir, env, checkout, "start", ".", expected=1)
        error = report["error"]
        assert "cannot create an isolated PostgreSQL database" in error, report
        assert "statement deadline" in error, report
        assert psql(pg, pg_env, lock_query).strip() == "t"
        assert inventory(pg, pg_env) == baseline
        assert administrator_locks(pg, pg_env) == baseline_locks
        assert list(state.iterdir()) == []
    finally:
        lock.stdin.close()
        try:
            lock.wait(timeout=5)
        except subprocess.TimeoutExpired:
            lock.kill()
            lock.wait(timeout=5)
            raise RuntimeError("the PostgreSQL lock fixture did not exit") from None
    print("A blocked PostgreSQL operation timed out and released earlier resources")


def verify_native_handoff(root, bin_dir, env):
    checkout = root / "native-review"
    checkout.mkdir()
    for product in ("registry", "casework"):
        shutil.copytree(NATIVE_REVIEW / product, checkout / product)
    shutil.copyfile(NATIVE_REVIEW / "dev.yaml", checkout / "dev.yaml")
    before = files(checkout)
    report = dev(bin_dir, env, checkout, "start", ".")
    try:
        assert report["journey"]["id"] == "native-review-handoff"
        assert report["journey"]["result"] == "passed"
        assert files(checkout) == before
        print(
            "Native review handoff, reviewer context and separately authorized BReg apply passed"
        )
    finally:
        dev(bin_dir, env, checkout, "stop", report["run_id"])


def verify_spatial(root, bin_dir, pg, env, pg_env):
    checkout = root / "spatial"
    registry = checkout / "registry"
    shutil.copytree(SPATIAL, registry)
    before = files(registry)
    fixture = json.loads((registry / "tests/journeys.yaml").read_text())
    people = {}
    for journey in fixture["journeys"]:
        for step in journey["steps"]:
            profile = step["accessProfile"]
            claims = step["claims"]
            people[profile] = {
                "subject": claims["principal"],
                "client": "spatial-smoke",
                "grants": {
                    "breg": {
                        "profile": profile,
                        "scopes": claims["scopes"],
                        "claims": {
                            **claims.get("directClaims", {}),
                            "registry_actor_kind": claims.get("actorKind", "human"),
                            "registry_purpose": claims["purpose"],
                        },
                    }
                },
            }
    with (registry / "fixtures/seed-service-sites.jsonl").open() as records:
        site = json.loads(next(records))["data"]
    longitude, latitude = site["location"]["coordinates"]
    bbox = (
        f"{longitude - 0.01:.6f},{latitude - 0.01:.6f},"
        f"{longitude + 0.01:.6f},{latitude + 0.01:.6f}"
    )
    plan = {
        "apiVersion": "id.registrystack.org/formats/breg/project-dev/v1alpha1",
        "kind": "BRegProjectDev",
        "issuer": "https://spatial-smoke.example.invalid",
        "products": [{"product": "breg", "project": "registry", "audience": "breg"}],
        "people": people,
        "journey": {
            "id": "spatial-smoke",
            "steps": [
                {
                    "id": "create-site",
                    "product": "breg",
                    "as": "service-site-admin",
                    "method": "POST",
                    "path": "/v1/records/service-sites",
                    "headers": {"Idempotency-Key": "spatial-smoke"},
                    "body": {"data": site},
                    "expect": {"status": 201},
                },
                {
                    "id": "read-bbox",
                    "product": "breg",
                    "as": "map-reader",
                    "method": "GET",
                    "path": f"/v1/records/service-sites?bbox={bbox}",
                    "expect": {
                        "status": 200,
                        "checks": [{"pointer": "/items", "length": 1}],
                    },
                },
            ],
        },
    }
    (checkout / "dev.yaml").write_text(json.dumps(plan))
    baseline = inventory(pg, pg_env)
    report = dev(bin_dir, env, checkout, "start", ".")
    run = report["run_id"]
    try:
        assert report["journey"]["result"] == "passed"
        origin = report["products"]["breg"]
        collection = f"{origin}/v1/gis/collections/service-site.map-reader"
        headers = credential(bin_dir, env, checkout, run, "map-reader")
        with HTTP.open(Request(collection, headers=headers), timeout=5) as response:
            metadata = json.load(response)
        items = next(
            link["href"] for link in metadata["links"] if link["rel"] == "items"
        )
        assert items == f"{collection}/items"
        request = Request(f"{items}?bbox={bbox}&f=json", headers=headers)
        with HTTP.open(request, timeout=5) as response:
            features = json.load(response)
        assert features["type"] == "FeatureCollection"
        assert len(features["features"]) == 1
        owners = set()
        for label in ("breg_test", "breg"):
            prefix = f"rstack_{run}_{label}"
            db_env = {**pg_env, "PGDATABASE": prefix}
            extension = psql(
                pg,
                db_env,
                """SELECT n.nspname
                FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace
                WHERE e.extname = 'postgis';""",
            ).strip()
            assert extension == "registry_spatial_ext"
            owner = psql(
                pg,
                db_env,
                f"""SELECT granted.rolname
                FROM pg_auth_members membership
                JOIN pg_roles grantee ON grantee.oid = membership.member
                JOIN pg_roles granted ON granted.oid = membership.roleid
                WHERE grantee.rolname = '{prefix}_migration'
                AND granted.rolname LIKE 'breg_bbox_%' AND NOT granted.rolcanlogin
                AND membership.set_option AND NOT membership.inherit_option
                AND NOT membership.admin_option
                AND NOT pg_has_role('{prefix}_runtime', granted.oid, 'MEMBER');""",
            ).strip()
            assert owner.startswith("breg_bbox_") and "\n" not in owner
            owners.add(owner)
        assert len(owners) == 2
        assert files(registry) == before
    finally:
        assert dev(bin_dir, env, checkout, "stop", run)["status"] == "stopped"
    assert inventory(pg, pg_env) == baseline
    print("Spatial BReg bbox journey passed with distinct, cleaned-up spatial roles")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--postgres-bin-dir", type=Path, required=True)
    parser.add_argument("--scratch-parent", type=Path)
    parser.add_argument("--spatial", action="store_true", help="also verify PostGIS")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(
        prefix="rstack-dev-", dir=args.scratch_parent
    ) as directory:
        root = Path(directory)
        bin_dir = args.bin_dir.resolve()
        project = STACK / "products/platform/examples/licensing"
        check_env = {
            key: value
            for key, value in os.environ.items()
            if key not in {"RSTACK_DEV_DATABASE_URL", "RSTACK_DEV_DATABASE_CA"}
        }
        check_env["RSTACK_BREGCTL_BIN"] = str(bin_dir / "bregctl")
        check_env["RSTACK_DEV_STATE_DIR"] = str(root / "offline-check-runs")
        report = dev(bin_dir, check_env, project, "check", ".")
        assert (
            report["ok"]
            and report["status"] == "complete"
            and report["diagnostics"] == []
        )
        assert not (root / "offline-check-runs").exists()
        pg = args.postgres_bin_dir.resolve()
        cluster, ca, url, pg_env = prepare_postgres(root, pg)
        checked(
            pg / "pg_ctl", "-D", cluster, "-l", root / "postgres.log", "-w", "start"
        )
        try:
            assert (
                psql(
                    pg,
                    pg_env,
                    "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid();",
                ).strip()
                == "t"
            )
            exercise(
                root,
                bin_dir,
                pg,
                project,
                ca,
                url,
                pg_env,
                args.spatial,
            )
        finally:
            checked(pg / "pg_ctl", "-D", cluster, "-m", "fast", "-w", "stop")


if __name__ == "__main__":
    main()
