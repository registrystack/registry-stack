#!/usr/bin/env python3
"""Exercise rstack dev with real BReg, Casework and a disposable TLS PostgreSQL."""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
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
MINIMAL = STACK / "products/breg/examples/minimal"
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
    return dev_output(bin_dir, env, cwd, *args, expected=expected)[0]


def dev_output(bin_dir, env, cwd, *args, expected=0):
    """Run `rstack dev` and return its report with everything it printed."""
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
    elif report["schema_version"] == "registry.rstack.error.v1":
        assert report["status"] == "refused", report
        assert report["error"]["class"] in ("domain", "usage", "operational"), report
        assert report["error"]["message"], report
    else:
        assert report["schema_version"] == "registry.rstack.dev.v1"
    return report, result.stdout + result.stderr


def credential(bin_dir, env, cwd, run, alias):
    before = time.time()
    report = dev(bin_dir, env, cwd, "token", run, "--as", alias)
    # The report gives the expiry the tokens carry, at most five minutes away.
    assert before < report["expires_at"] <= time.time() + 300, report
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


def live_runs(state):
    """Runs that may still be alive; `failed/` only holds kept logs and a
    `.RUN_ID.removing` directory is a stopped run whose files are being deleted."""
    if not state.exists():
        return []
    return [
        path
        for path in state.iterdir()
        if path.name != "failed" and not path.name.startswith(".")
    ]


def nothing_left_behind(state):
    """Every stopped run's files are eventually deleted."""
    eventually(
        lambda: (
            not state.exists() or all(path.name == "failed" for path in state.iterdir())
        ),
        "a stopped run's files were not deleted",
    )


def kept_logs(state, error):
    """The log directory a failed run's error names, after checking it."""
    marker = "logs kept at "
    assert marker in error, error
    logs = Path(error.rsplit(marker, 1)[1].strip())
    assert logs.name == "logs" and logs.parent.parent == state / "failed", logs
    assert logs.is_dir() and logs.stat().st_mode & 0o777 == 0o700, logs
    assert (logs / "supervisor.log").is_file(), logs
    return logs


def eventually(check, message, timeout=10):
    deadline = time.monotonic() + timeout
    while not check():
        assert time.monotonic() < deadline, message
        time.sleep(0.1)


def accepts_connections(url):
    parts = urlsplit(url)
    with socket.socket() as probe:
        probe.settimeout(2)
        return probe.connect_ex((parts.hostname, parts.port)) == 0


def product_pids(bin_dir):
    """Processes running this build's BReg or Casework (not their ctl tools)."""
    pattern = f"{re.escape(str(bin_dir))}/(breg|casework)( |$)"
    result = command("pgrep", "-f", pattern)
    assert result.returncode in (0, 1), "pgrep failed"
    return result.stdout.split()


def assert_nothing_listening(bin_dir, urls=()):
    """No product URL accepts a connection and no product process remains."""
    for url in urls:
        eventually(
            lambda url=url: not accepts_connections(url), f"{url} is still listening"
        )
    eventually(lambda: not product_pids(bin_dir), "a product process is still alive")


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


def create_owner(pg, pg_env, url):
    """A least-privilege administrator: it can create roles and databases only."""
    password = secrets.token_urlsafe(32)
    psql(
        pg,
        pg_env,
        f"CREATE ROLE devowner LOGIN CREATEROLE CREATEDB PASSWORD '{password}';",
    )
    parts = urlsplit(url)
    owner_url = (
        f"postgresql://devowner:{password}@{parts.hostname}:{parts.port}/postgres"
    )
    return owner_url, {**pg_env, "PGUSER": "devowner", "PGPASSWORD": password}


def exercise(root, bin_dir, pg, project, ca, url, pg_env, spatial):
    checkout = root / "licensing"
    shutil.copytree(project, checkout)
    before = files(checkout)
    state = root / "runs"
    owner_url, owner_env = create_owner(pg, pg_env, url)
    env = {
        **os.environ,
        "RSTACK_DEV_STATE_DIR": str(state),
        "RSTACK_DEV_DATABASE_URL": owner_url,
        "RSTACK_DEV_DATABASE_CA": str(ca),
        "RSTACK_BREGCTL_BIN": str(bin_dir / "bregctl"),
        "RSTACK_BREG_BIN": str(bin_dir / "breg"),
        "RSTACK_CASEWORKCTL_BIN": str(bin_dir / "caseworkctl"),
        "RSTACK_CASEWORK_BIN": str(bin_dir / "casework"),
    }
    try:
        exercise_runs(root, bin_dir, pg, checkout, state, env, pg_env)
        verify_lost_supervisor(bin_dir, pg, checkout, state, env, pg_env, owner_env)
        verify_provisioning_deadline(bin_dir, pg, checkout, state, env, pg_env)
        verify_spatial_refusal(root, bin_dir, pg, state, env, pg_env)
        verify_field_encryption(root, bin_dir, pg, state, env, pg_env)
        if spatial:
            verify_spatial(
                root, bin_dir, pg, {**env, "RSTACK_DEV_DATABASE_URL": url}, pg_env
            )
        assert files(checkout) == before
        nothing_left_behind(state)
    finally:
        for run_root in live_runs(state):
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
    assert_nothing_listening(
        bin_dir, [url for run in runs for url in run["products"].values()]
    )

    short = dev(bin_dir, env, checkout, "start", ".", "--ttl", "1s")
    wait_for_stop(bin_dir, env, checkout, short["run_id"])
    assert inventory(pg, pg_env) == baseline
    assert live_runs(state) == []
    assert_nothing_listening(bin_dir, short["products"].values())

    failing = root / "failing-casework"
    failing.write_text("#!/bin/sh\nprintf 'boom\\n' >&2\nexit 1\n")
    failing.chmod(0o700)
    failure_env = {**env, "RSTACK_CASEWORK_BIN": str(failing)}
    report = dev(bin_dir, failure_env, checkout, "start", ".", expected=1)
    assert "casework exited before readiness" in report["error"]["message"], report
    assert "boom" in report["error"]["message"], report
    logs = kept_logs(state, report["error"]["message"])
    assert any("boom" in log.read_text() for log in logs.glob("casework-*.log")), report
    assert inventory(pg, pg_env) == baseline, report
    assert live_runs(state) == [], report
    assert_nothing_listening(bin_dir)
    verify_native_handoff(root, bin_dir, env)
    assert inventory(pg, pg_env) == baseline
    assert administrator_locks(pg, pg_env) == baseline_locks
    assert live_runs(state) == []
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

        report = dev(bin_dir, env, checkout, "start", ".", expected=3)
        assert report["error"]["class"] == "operational", report
        error = report["error"]["message"]
        assert "cannot create an isolated PostgreSQL database" in error, report
        assert "statement deadline" in error, report
        assert psql(pg, pg_env, lock_query).strip() == "t"
        assert inventory(pg, pg_env) == baseline
        assert administrator_locks(pg, pg_env) == baseline_locks
        assert live_runs(state) == []
        if "logs kept at " in error:
            kept_logs(state, error)
    finally:
        lock.stdin.close()
        try:
            lock.wait(timeout=5)
        except subprocess.TimeoutExpired:
            lock.kill()
            lock.wait(timeout=5)
            raise RuntimeError("the PostgreSQL lock fixture did not exit") from None
    print("A blocked PostgreSQL operation timed out and released earlier resources")


def listener_pids(url):
    result = command(
        "lsof", "-nP", "-Fp", f"-iTCP:{urlsplit(url).port}", "-sTCP:LISTEN"
    )
    return {line[1:] for line in result.stdout.decode().split() if line[0] == "p"}


def recover_lost_supervisor(pg, owner_env, recovery):
    """Release a lost run by hand, from the facts `stop` reports.

    Order: stop each process group (TERM, then KILL), drop every database
    (WITH (FORCE) ends leftover sessions), drop every role, then remove the
    run directory.
    """
    for process in recovery["processes"]:
        group = process["pgid"]
        os.killpg(group, signal.SIGTERM)

        def gone(group=group):
            try:
                os.killpg(group, 0)
            except ProcessLookupError:
                return True
            return False

        try:
            eventually(gone, "a process group ignored SIGTERM", timeout=10)
        except AssertionError:
            os.killpg(group, signal.SIGKILL)
            eventually(gone, "a process group survived SIGKILL", timeout=10)
    objects = recovery["objects"]
    statements = [
        f'DROP DATABASE IF EXISTS "{item["database"]}" WITH (FORCE);'
        for item in objects
    ] + [f'DROP ROLE IF EXISTS "{role}";' for item in objects for role in item["roles"]]
    psql(pg, owner_env, "\n".join(statements) + "\n")
    shutil.rmtree(recovery["run_directory"])


def verify_lost_supervisor(bin_dir, pg, checkout, state, env, pg_env, owner_env):
    baseline = inventory(pg, pg_env)
    baseline_locks = administrator_locks(pg, pg_env)
    report = dev(bin_dir, env, checkout, "start", ".")
    run = report["run_id"]
    worker = command(
        "pgrep", "-f", f"project-dev --worker {re.escape(str(state / run))}"
    )
    [supervisor] = worker.stdout.split()
    os.kill(int(supervisor), signal.SIGKILL)
    status = dev(bin_dir, env, checkout, "status", run, expected=3)
    stopped = dev(bin_dir, env, checkout, "stop", run, expected=3)
    for lost in (status, stopped):
        assert lost["error"]["class"] == "operational", lost
        assert lost["recovery"]["kind"] == "lost-supervisor", lost
        assert lost["run_id"] == run, lost
    recovery = stopped["recovery"]
    assert recovery["run_directory"] == str(state / run), recovery
    processes = recovery["processes"]
    assert sorted(p["product"] for p in processes) == ["breg", "casework"], recovery
    for process in processes:
        os.kill(process["pid"], 0)
        assert os.getpgid(process["pid"]) == process["pgid"], recovery
        listeners = listener_pids(report["products"][process["product"]])
        assert str(process["pid"]) in listeners, recovery
    # The pattern behind assert_nothing_listening sees the live products.
    assert len(product_pids(bin_dir)) == 2, recovery
    databases, roles = inventory(pg, pg_env)
    assert {item["database"] for item in recovery["objects"]} == (
        databases - baseline[0]
    ), recovery
    assert {role for item in recovery["objects"] for role in item["roles"]} == (
        roles - baseline[1]
    ), recovery
    recover_lost_supervisor(pg, owner_env, recovery)
    assert_nothing_listening(bin_dir, report["products"].values())
    assert inventory(pg, pg_env) == baseline
    eventually(
        lambda: administrator_locks(pg, pg_env) == baseline_locks,
        "the lost supervisor's administrator lock was not released",
    )
    assert live_runs(state) == []
    assert dev(bin_dir, env, checkout, "status", run)["status"] == "stopped"
    print("A lost supervisor was recovered by hand from the facts stop reported")
    verify_recover(bin_dir, pg, checkout, state, env, pg_env)


def lose_supervisor(bin_dir, checkout, state, env):
    report = dev(bin_dir, env, checkout, "start", ".")
    run = report["run_id"]
    worker = command(
        "pgrep", "-f", f"project-dev --worker {re.escape(str(state / run))}"
    )
    [supervisor] = worker.stdout.split()
    os.kill(int(supervisor), signal.SIGKILL)
    return report, run


def verify_recover(bin_dir, pg, checkout, state, env, pg_env):
    baseline = inventory(pg, pg_env)
    baseline_locks = administrator_locks(pg, pg_env)

    report, run = lose_supervisor(bin_dir, checkout, state, env)
    recovered = dev(bin_dir, env, checkout, "stop", run, "--recover")
    assert recovered["status"] == "stopped", recovered
    assert len(recovered["recovered"]["stopped_process_groups"]) == 2, recovered
    assert recovered["recovered"]["skipped_process_groups"] == [], recovered
    assert_nothing_listening(bin_dir, report["products"].values())
    assert inventory(pg, pg_env) == baseline
    eventually(
        lambda: administrator_locks(pg, pg_env) == baseline_locks,
        "the recovery's administrator lock was not released",
    )
    assert live_runs(state) == []
    assert dev(bin_dir, env, checkout, "status", run)["status"] == "stopped"
    assert dev(bin_dir, env, checkout, "stop", run, "--recover")["status"] == "stopped"
    print("stop --recover released a lost supervisor's processes, databases and roles")

    # A recorded group whose leader started at another time is not the run's:
    # recovery leaves it running and still releases the rest.
    report, run = lose_supervisor(bin_dir, checkout, state, env)
    processes_file = state / run / "processes.json"
    processes = json.loads(processes_file.read_text())
    [casework] = [p for p in processes if p["product"] == "casework"]
    casework["started"] = "Mon Jan  1 00:00:00 2001"
    processes_file.write_text(json.dumps(processes))
    try:
        recovered = dev(bin_dir, env, checkout, "stop", run, "--recover")
        assert recovered["recovered"]["skipped_process_groups"] == [
            casework["pgid"]
        ], recovered
        os.killpg(casework["pgid"], 0)
        assert inventory(pg, pg_env) == baseline
        assert live_runs(state) == []
    finally:
        try:
            os.killpg(casework["pgid"], signal.SIGKILL)
        except ProcessLookupError:
            pass
    assert_nothing_listening(bin_dir, report["products"].values())

    # Without an administrator URL nothing is signalled or dropped, and the
    # error carries the facts for a hand release.
    report, run = lose_supervisor(bin_dir, checkout, state, env)
    no_url = {k: v for k, v in env.items() if k != "RSTACK_DEV_DATABASE_URL"}
    refused = dev(bin_dir, no_url, checkout, "stop", run, "--recover", expected=3)
    assert "no PostgreSQL administrator URL" in refused["error"]["message"], refused
    assert refused["run_id"] == run, refused
    assert len(refused["recovery"]["processes"]) == 2, refused
    assert len(product_pids(bin_dir)) == 2, refused
    dev(bin_dir, env, checkout, "stop", run, "--recover")
    assert_nothing_listening(bin_dir, report["products"].values())
    assert inventory(pg, pg_env) == baseline
    assert live_runs(state) == []
    print("stop --recover skips a reused process ID and fails with facts when it cannot proceed")


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


def spatial_project(root, name):
    """Copy the spatial registry and write a plan that creates and reads a site."""
    checkout = root / name
    registry = checkout / "registry"
    shutil.copytree(SPATIAL, registry)
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
    return checkout, registry, bbox


def verify_spatial_refusal(root, bin_dir, pg, state, env, pg_env):
    """A spatial start is refused cleanly when the administrator cannot offer PostGIS."""
    checkout, _, _ = spatial_project(root, "spatial-refusal")
    baseline = inventory(pg, pg_env)
    offered = psql(
        pg,
        pg_env,
        "SELECT default_version FROM pg_available_extensions WHERE name = 'postgis';",
    ).strip()
    supported = bool(offered) and tuple(map(int, offered.split(".")[:2])) >= (3, 5)
    report = dev(bin_dir, env, checkout, "start", ".", expected=3)
    assert report["error"]["class"] == "operational", report
    if supported:
        assert "must be allowed to CREATE EXTENSION postgis" in report["error"]["message"], report
    else:
        assert "PostGIS 3.5 or later installed" in report["error"]["message"], report
    assert inventory(pg, pg_env) == baseline, report
    assert live_runs(state) == [], report
    print("A spatial start without PostGIS rights was refused and left nothing behind")


def encrypted_project(root, name):
    """Copy the minimal registry with a note Record type whose body is
    encrypted, and write a plan that creates a note and reads it back.

    The fixture journeys leave notes alone: `bregctl test` runs them without
    field-encryption key state, so a fixture step that wrote an encrypted
    field would be refused there before the run reached its own key."""
    checkout = root / name
    registry = checkout / "registry"
    shutil.copytree(MINIMAL, registry)
    source = (registry / "registry.yaml").read_text()
    for anchor, addition in [
        (
            "\nactions:\n",
            "  - id: note\n"
            "    route: notes\n"
            "    primaryDataset: directory\n"
            "    mutationMode: mutable\n"
            "    classification: restricted\n"
            "    display: {label: Note, description: A note whose body is encrypted.}\n"
            "    fields:\n"
            "      - {id: title, type: string, required: true, minimumLength: 1,"
            " maximumLength: 160, classification: internal}\n"
            "      - {id: body, type: string, required: true, minimumLength: 1,"
            " maximumLength: 2000, classification: restricted, encrypted: true}\n"
            "      - {id: jurisdiction, type: string, required: true, minimumLength: 1,"
            " maximumLength: 40, classification: internal}\n",
        ),
        (
            "      actions:\n        - action: update-contact-email\n",
            "        - recordType: note\n"
            "          operations: [create, get]\n"
            "          readableFields: [title, body, jurisdiction]\n"
            "          writableFields: [title, body, jurisdiction]\n"
            "          rowBoundaries:\n"
            "            - {field: jurisdiction, claim: jurisdiction, operator: equals}\n",
        ),
    ]:
        # Each addition goes in front of its anchor: the note after the
        # contact Record type, and its grant after the contact grant.
        assert source.count(anchor) == 1, anchor
        source = source.replace(anchor, addition + anchor)
    (registry / "registry.yaml").write_text(source)
    # Both fixture principals hold the same grant, so each fixture step names
    # the person whose jurisdiction it expects.
    people = {
        "synthetic-directory-editor": ("editor", "zone-a"),
        "synthetic-foreign-editor": ("foreign-editor", "zone-b"),
    }
    schema_test_people = {}
    steps = 0
    for line in (registry / "tests/journeys.yaml").read_text().splitlines():
        if match := re.fullmatch(r"  - id: (\S+)", line):
            journey = schema_test_people.setdefault(match[1], {})
        elif match := re.fullmatch(r"      - id: (\S+)", line):
            step = match[1]
            steps += 1
        elif match := re.fullmatch(r" +principal: (\S+)", line):
            journey[step] = people[match[1]][0]
    assert steps and sum(map(len, schema_test_people.values())) == steps, (
        schema_test_people
    )
    body = f"encrypted-note-{secrets.token_hex(8)}"
    plan = {
        "apiVersion": "id.registrystack.org/formats/breg/project-dev/v1alpha1",
        "kind": "BRegProjectDev",
        "issuer": "https://directory-smoke.example.invalid",
        "products": [
            {"product": "breg", "project": "registry", "audience": "directory"}
        ],
        "people": {
            alias: {
                "subject": principal,
                "client": "directory-smoke",
                "grants": {
                    "breg": {
                        "profile": "directory-editor",
                        "scopes": ["registry:directory:write"],
                        "claims": {
                            "jurisdiction": jurisdiction,
                            "registry_actor_kind": "human",
                            "registry_purpose": "directory-administration",
                        },
                    }
                },
            }
            for principal, (alias, jurisdiction) in people.items()
        },
        "schemaTestPeople": schema_test_people,
        "journey": {
            "id": "encrypted-note",
            "steps": [
                {
                    "id": "create-note",
                    "product": "breg",
                    "as": "editor",
                    "method": "POST",
                    "path": "/v1/records/notes",
                    "headers": {"Idempotency-Key": "encrypted-note"},
                    "body": {
                        "data": {
                            "title": "Encrypted note",
                            "body": body,
                            "jurisdiction": "zone-a",
                        }
                    },
                    "expect": {"status": 201},
                    "capture": {
                        "note": {
                            "type": "pointer",
                            "pointer": "/data/recordIdentifier",
                        }
                    },
                },
                {
                    "id": "read-note",
                    "product": "breg",
                    "as": "editor",
                    "method": "GET",
                    "path": "/v1/records/notes/{{note}}",
                    "expect": {
                        "status": 200,
                        "json": {"/data/domainData/body": body},
                    },
                },
            ],
        },
    }
    (checkout / "dev.yaml").write_text(json.dumps(plan))
    return checkout, body


def field_key(state, run):
    """The run's key, after checking its custody: an owner-only file in the
    owner-only run directory holding 32 random bytes in base64."""
    key = state / run / "field-key"
    assert key.parent.stat().st_mode & 0o777 == 0o700, key
    assert key.stat().st_mode & 0o777 == 0o600, key
    encoded = key.read_bytes()
    assert len(base64.b64decode(encoded, validate=True)) == 32, key
    return encoded


def tree_bytes(root, skip=()):
    return [
        path.read_bytes()
        for path in root.rglob("*")
        if path.is_file() and path not in skip
    ]


def without_key(encoded, outputs):
    """No output carries the key, as base64 or as raw bytes. The assertion
    names no value so a failure cannot print the key."""
    raw = base64.b64decode(encoded)
    for output in outputs:
        assert encoded not in output and raw not in output, "the field key leaked"


def stored_values(pg, pg_env, run):
    """Every row of the run's BReg database, as text with byte columns hex
    encoded, so plaintext is found whether it sits in text or bytes."""
    dump = checked(
        pg / "pg_dump",
        "--data-only",
        env={**pg_env, "PGDATABASE": f"rstack_{run}_breg"},
    )
    return lambda value: value.encode() in dump or value.encode().hex().encode() in dump


def verify_field_encryption(root, bin_dir, pg, state, env, pg_env):
    """A project with encrypted fields runs on a per-run key that stays in the
    run directory and is removed on every cleanup path."""
    checkout, body = encrypted_project(root, "encrypted")
    before = files(checkout)
    baseline = inventory(pg, pg_env)

    report, printed = dev_output(bin_dir, env, checkout, "start", ".")
    run = report["run_id"]
    try:
        assert report["journey"]["result"] == "passed", report
        key = field_key(state, run)
        credential(bin_dir, env, checkout, run, "editor")
        _, token = dev_output(bin_dir, env, checkout, "token", run, "--as", "editor")
        _, status = dev_output(bin_dir, env, checkout, "status", run)
        without_key(
            key,
            [printed, token, status]
            + tree_bytes(state / run, skip={state / run / "field-key"})
            + tree_bytes(checkout),
        )
        stored = stored_values(pg, pg_env, run)
        assert stored("Encrypted note") and stored("__bregEncryptedV1")
        assert not stored(body), "the encrypted body is stored in plaintext"
    finally:
        stopped, printed = dev_output(bin_dir, env, checkout, "stop", run)
    assert stopped["status"] == "stopped", stopped
    assert not (state / run).exists()
    without_key(key, [printed])
    assert inventory(pg, pg_env) == baseline
    print("An encrypted field round-tripped on an owner-only run key that stop removed")

    short = dev(bin_dir, env, checkout, "start", ".", "--ttl", "5s")
    field_key(state, short["run_id"])
    wait_for_stop(bin_dir, env, checkout, short["run_id"])
    assert not (state / short["run_id"]).exists()
    assert live_runs(state) == []

    # The runtime fixture copies the key it was given so the test can look
    # for it in everything the failed start left behind.
    seen = root / "failed-run-key"
    failing = root / "failing-breg"
    failing.write_text(
        "#!/bin/sh\numask 077\n"
        f"cp \"$(dirname \"$2\")/field-key\" '{seen}'\n"
        "printf 'boom\\n' >&2\nexit 1\n"
    )
    failing.chmod(0o700)
    failure_env = {**env, "RSTACK_BREG_BIN": str(failing)}
    report, printed = dev_output(
        bin_dir, failure_env, checkout, "start", ".", expected=1
    )
    assert "breg exited before readiness" in report["error"]["message"], report
    logs = kept_logs(state, report["error"]["message"])
    key = seen.read_bytes()
    assert len(base64.b64decode(key, validate=True)) == 32
    assert not list(state.rglob("field-key")), "a failed start kept its key"
    without_key(key, [printed] + tree_bytes(logs.parent))
    assert live_runs(state) == []
    assert inventory(pg, pg_env) == baseline

    report, run = lose_supervisor(bin_dir, checkout, state, env)
    lost, printed = dev_output(bin_dir, env, checkout, "stop", run, expected=3)
    key = field_key(state, run)
    assert lost["recovery"]["field_encryption_key"] == str(state / run / "field-key")
    without_key(key, [printed])
    recovered, printed = dev_output(bin_dir, env, checkout, "stop", run, "--recover")
    assert recovered["status"] == "stopped", recovered
    assert not (state / run).exists()
    without_key(key, [printed])
    assert_nothing_listening(bin_dir, report["products"].values())
    assert inventory(pg, pg_env) == baseline
    assert live_runs(state) == []
    assert files(checkout) == before
    print("TTL expiry, a failed start and stop --recover removed the run's key")


def verify_spatial(root, bin_dir, pg, env, pg_env):
    checkout, registry, bbox = spatial_project(root, "spatial")
    before = files(registry)
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


def verify_offline_plan(root, bin_dir, project):
    state = root / "offline-check-runs"
    check_env = {
        key: value
        for key, value in os.environ.items()
        if key
        not in {
            "RSTACK_DEV_DATABASE_URL",
            "RSTACK_DEV_DATABASE_CA",
            "RSTACK_BREG_BIN",
            "RSTACK_CASEWORK_BIN",
        }
    }
    check_env["RSTACK_BREGCTL_BIN"] = str(bin_dir / "bregctl")
    check_env["RSTACK_CASEWORKCTL_BIN"] = str(bin_dir / "caseworkctl")
    check_env["RSTACK_DEV_STATE_DIR"] = str(state)
    report = dev(bin_dir, check_env, project, "check", ".")
    assert report["ok"] and report["status"] == "complete"
    assert report["diagnostics"] == []
    assert not state.exists()

    invalid = root / "offline-invalid"
    shutil.copytree(project, invalid)
    plan = invalid / "dev.yaml"
    authored = plan.read_text()
    profile = "profile: intake"
    unknown = "missing-check-profile"
    assert authored.count(profile) == 1
    plan.write_text(authored.replace(profile, f"profile: {unknown}"))
    refused = dev(bin_dir, check_env, invalid, "check", ".", expected=1)
    [diagnostic] = refused["diagnostics"]
    assert refused["status"] == "domain-refusal"
    assert diagnostic["path"] == "/people/intake/grants/casework/profile"
    assert diagnostic["suggestedAction"]
    assert unknown not in diagnostic["message"] + diagnostic["suggestedAction"]
    assert not state.exists()

    # Casework's own check refuses the context provider binding the run would
    # write, and the refusal lands on the plan field that produced it.
    binding = root / "offline-context-binding"
    binding.mkdir()
    for product in ("registry", "casework"):
        shutil.copytree(NATIVE_REVIEW / product, binding / product)
    authored = (NATIVE_REVIEW / "dev.yaml").read_text()
    audience = 'audience: "urn:journey:breg"'
    assert authored.count(audience) == 1
    (binding / "dev.yaml").write_text(authored.replace(audience, "audience: registry"))
    refused = dev(bin_dir, check_env, binding, "check", ".", expected=1)
    [diagnostic] = refused["diagnostics"]
    assert refused["status"] == "domain-refusal"
    assert diagnostic["path"] == "/products/0/audience"
    assert diagnostic["message"].startswith("Casework refuses"), diagnostic
    assert "contextProviders.registry.resource: " in diagnostic["message"], diagnostic
    assert not state.exists()
    print("Offline checks resolve product profiles with only the authoring tools")


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
        verify_offline_plan(root, bin_dir, project)
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
