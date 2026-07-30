#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import os
import secrets
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("registry_release_lock.py")
SPEC = importlib.util.spec_from_file_location("registry_release_lock", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
release_lock = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_lock)


def run(
    argv: list[str],
    *,
    cwd: Path,
    capture: bool = False,
) -> str:
    completed = subprocess.run(
        argv,
        cwd=cwd,
        check=False,
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        command = " ".join(argv[:4])
        raise AssertionError(
            f"{command} failed without exposing operator values:\n"
            f"{completed.stderr[-4000:]}"
        )
    return completed.stdout if capture else ""


@unittest.skipUnless(
    os.environ.get("REGISTRY_POSTGRESQL_DOCKER_PROOF") == "1",
    "set REGISTRY_POSTGRESQL_DOCKER_PROOF=1 for the sealed Docker proof",
)
class PostgresqlRuntimeRecipeDockerProof(unittest.TestCase):
    def test_empty_volume_tls_roles_databases_and_restart(self) -> None:
        image = os.environ.get(
            "REGISTRY_POSTGRES_IMAGE",
            (
                "postgres@sha256:"
                "0af65001d05296a2ead57ac4a6412433d8913d1bb5d0c88435a7d1e1ee5cb04b"
            ),
        )
        recipe = release_lock.postgresql_recipe()
        project = f"registry-postgresql-proof-{secrets.token_hex(6)}"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            certificate = root / "postgresql-tls.crt"
            private_key = root / "postgresql-tls.key"
            admin_password = root / "postgresql-admin-password"
            bootstrap_environment = root / "postgresql-bootstrap.env"
            server_environment = root / "postgresql-server.env"
            compose_file = root / "compose.json"

            run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-days",
                    "1",
                    "-subj",
                    "/CN=registry-postgres",
                    "-addext",
                    "subjectAltName=DNS:registry-postgres",
                    "-keyout",
                    str(private_key),
                    "-out",
                    str(certificate),
                ],
                cwd=root,
            )
            admin_password.write_text(
                secrets.token_urlsafe(32), encoding="utf-8"
            )
            bootstrap_environment.write_text(
                "\n".join(
                    f"{key}={secrets.token_urlsafe(32)}"
                    for key in release_lock.POSTGRESQL_BOOTSTRAP_KEYS
                )
                + "\n",
                encoding="utf-8",
            )
            server_environment.write_text(
                "\n".join(recipe["server_environment"]) + "\n",
                encoding="utf-8",
            )
            for path in [
                certificate,
                private_key,
                admin_password,
                bootstrap_environment,
                server_environment,
            ]:
                path.chmod(0o600)

            hardening = recipe["hardening"]
            common = {
                "image": image,
                "user": hardening["user"],
                "read_only": hardening["read_only_root_filesystem"],
                "cap_drop": hardening["cap_drop"],
                "security_opt": hardening["security_opt"],
                "tmpfs": hardening["tmpfs"],
            }
            stage_lines = ["umask 077"]
            for stage_id, action in [
                ("postgresql-serve", recipe["serve"]),
                ("postgresql-bootstrap", recipe["bootstrap"]),
            ]:
                for projection in action["secret_files"]:
                    target = Path(projection["target"]).name
                    stage_lines.append(
                        "/usr/bin/install "
                        f"-m {projection['mode']} "
                        f"/run/secrets/{projection['file_id']} "
                        f"/registryctl-stage/output/{stage_id}/{target}"
                    )
                    stage_lines.append(
                        "/usr/bin/chown "
                        f"{projection['uid']}:{projection['gid']} "
                        f"/registryctl-stage/output/{stage_id}/{target}"
                    )
            model = {
                "name": project,
                "services": {
                    "registry-postgres": {
                        **common,
                        "command": recipe["serve"]["command"],
                        "networks": {"registry-private": {}},
                        "depends_on": {
                            "registry-postgresql-stage-secrets": {
                                "condition": "service_completed_successfully",
                                "required": True,
                            },
                        },
                        "env_file": [str(server_environment)],
                        "volumes": [
                            {
                                "type": "volume",
                                "source": "postgresql-data",
                                "target": "/var/lib/postgresql/data",
                                "read_only": False,
                            },
                            {
                                "type": "volume",
                                "source": "postgresql-serve-secrets",
                                "target": "/run/secrets",
                                "read_only": True,
                            },
                        ],
                        "healthcheck": {
                            "test": recipe["health_probe"],
                            "interval": "1s",
                            "timeout": "2s",
                            "retries": 60,
                        },
                    },
                    "registry-postgresql-stage-secrets": {
                        "image": image,
                        "entrypoint": ["/bin/sh", "-ceu"],
                        "command": ["\n".join(stage_lines) + "\n"],
                        "user": "0:0",
                        "read_only": True,
                        "cap_drop": ["ALL"],
                        "cap_add": ["CHOWN"],
                        "security_opt": ["no-new-privileges:true"],
                        "tmpfs": ["/tmp"],
                        "network_mode": "none",
                        "restart": "no",
                        "volumes": [
                            {
                                "type": "volume",
                                "source": "postgresql-serve-secrets",
                                "target": (
                                    "/registryctl-stage/output/"
                                    "postgresql-serve"
                                ),
                            },
                            {
                                "type": "volume",
                                "source": "postgresql-bootstrap-secrets",
                                "target": (
                                    "/registryctl-stage/output/"
                                    "postgresql-bootstrap"
                                ),
                            },
                        ],
                        "secrets": [
                            {
                                "source": "postgresql-admin-password",
                                "target": "postgresql-admin-password",
                            },
                            {
                                "source": "postgresql-tls-certificate",
                                "target": "postgresql-tls-certificate",
                            },
                            {
                                "source": "postgresql-tls-private-key",
                                "target": "postgresql-tls-private-key",
                            },
                        ],
                    },
                    "registry-postgres-bootstrap": {
                        **common,
                        "command": recipe["bootstrap"]["command"],
                        "networks": {"registry-private": {}},
                        "depends_on": {
                            "registry-postgres": {
                                "condition": "service_healthy",
                                "required": True,
                            },
                            "registry-postgresql-stage-secrets": {
                                "condition": "service_completed_successfully",
                                "required": True,
                            },
                        },
                        "env_file": [str(bootstrap_environment)],
                        "volumes": [
                            {
                                "type": "volume",
                                "source": "postgresql-bootstrap-secrets",
                                "target": "/run/secrets",
                                "read_only": True,
                            },
                        ],
                    },
                },
                "networks": {"registry-private": {"internal": True}},
                "volumes": {
                    "postgresql-data": {},
                    "postgresql-serve-secrets": {},
                    "postgresql-bootstrap-secrets": {},
                },
                "secrets": {
                    "postgresql-admin-password": {
                        "file": str(admin_password)
                    },
                    "postgresql-tls-certificate": {
                        "file": str(certificate)
                    },
                    "postgresql-tls-private-key": {
                        "file": str(private_key)
                    },
                },
            }
            compose_file.write_text(
                json.dumps(model, sort_keys=True), encoding="utf-8"
            )
            compose = [
                "docker",
                "compose",
                "--project-name",
                project,
                "--file",
                str(compose_file),
            ]
            try:
                run([*compose, "down", "--volumes", "--remove-orphans"], cwd=root)
                try:
                    run(
                        [
                            *compose,
                            "up",
                            "--detach",
                            "--wait",
                            "--wait-timeout",
                            "120",
                            "registry-postgres",
                        ],
                        cwd=root,
                    )
                except AssertionError as error:
                    stage_logs = run(
                        [
                            *compose,
                            "logs",
                            "--no-color",
                            "registry-postgresql-stage-secrets",
                        ],
                        cwd=root,
                        capture=True,
                    )
                    postgres_logs = run(
                        [
                            *compose,
                            "logs",
                            "--no-color",
                            "registry-postgres",
                        ],
                        cwd=root,
                        capture=True,
                    )
                    raise AssertionError(
                        f"{error}\nstager logs:\n{stage_logs}\n"
                        f"postgres logs:\n{postgres_logs}"
                    ) from error
                inspect = json.loads(
                    run(
                        [
                            "docker",
                            "inspect",
                            f"{project}-registry-postgres-1",
                        ],
                        cwd=root,
                        capture=True,
                    )
                )[0]
                self.assertEqual(inspect["Config"]["User"], "999:999")
                self.assertTrue(inspect["HostConfig"]["ReadonlyRootfs"])
                self.assertIn("ALL", inspect["HostConfig"]["CapDrop"])
                self.assertEqual(inspect["HostConfig"]["PortBindings"], {})
                self.assertTrue(
                    all(
                        bindings is None
                        for bindings in inspect["NetworkSettings"]["Ports"].values()
                    )
                )
                self.assertEqual(
                    inspect["HostConfig"]["NetworkMode"],
                    f"{project}_registry-private",
                )
                self.assertEqual(
                    set(inspect["NetworkSettings"]["Networks"]),
                    {f"{project}_registry-private"},
                )
                stage_inspect = json.loads(
                    run(
                        [
                            "docker",
                            "inspect",
                            (
                                f"{project}-"
                                "registry-postgresql-stage-secrets-1"
                            ),
                        ],
                        cwd=root,
                        capture=True,
                    )
                )[0]
                self.assertEqual(stage_inspect["HostConfig"]["NetworkMode"], "none")
                self.assertEqual(stage_inspect["HostConfig"]["CapAdd"], ["CAP_CHOWN"])
                self.assertNotIn("CAP_CHOWN", inspect["HostConfig"]["CapAdd"] or [])
                secret_mount = next(
                    mount
                    for mount in inspect["Mounts"]
                    if mount["Destination"] == "/run/secrets"
                )
                self.assertEqual(secret_mount["Type"], "volume")
                serve_modes = run(
                    [
                        *compose,
                        "exec",
                        "--no-TTY",
                        "registry-postgres",
                        "stat",
                        "--format",
                        "%u:%g:%a",
                        "/run/secrets/postgresql-admin-password",
                        "/run/secrets/postgresql-tls.crt",
                        "/run/secrets/postgresql-tls.key",
                    ],
                    cwd=root,
                    capture=True,
                )
                self.assertEqual(
                    serve_modes.splitlines(),
                    ["999:999:400", "999:999:400", "999:999:400"],
                )
                bootstrap_modes = run(
                    [
                        *compose,
                        "run",
                        "--rm",
                        "--no-deps",
                        "registry-postgres-bootstrap",
                        "stat",
                        "--format",
                        "%u:%g:%a",
                        "/run/secrets/postgresql-admin-password",
                        "/run/secrets/postgresql-ca.pem",
                    ],
                    cwd=root,
                    capture=True,
                )
                self.assertEqual(
                    bootstrap_modes.splitlines(),
                    ["999:999:400", "999:999:400"],
                )

                run(
                    [*compose, "run", "--rm", "registry-postgres-bootstrap"],
                    cwd=root,
                )
                query_script = (
                    'export PGPASSWORD="$(cat '
                    '/run/secrets/postgresql-admin-password)"; '
                    "psql \"host=registry-postgres port=5432 dbname=postgres "
                    "user=registry_stack_bootstrap sslmode=verify-full "
                    "sslrootcert=/run/secrets/postgresql-ca.pem\" "
                    "--set=ON_ERROR_STOP=1 --tuples-only --no-align "
                    "--command=\"SELECT ssl FROM pg_stat_ssl "
                    "WHERE pid=pg_backend_pid(); "
                    "SELECT datname || ':' || pg_get_userbyid(datdba) "
                    "FROM pg_database WHERE datname IN "
                    "('registry_relay','registry_notary') ORDER BY datname; "
                    "SELECT rolname || ':' || rolcanlogin || ':' || rolsuper "
                    "FROM pg_roles WHERE rolname LIKE 'registry_%' "
                    "ORDER BY rolname;\""
                )
                query = run(
                    [
                        *compose,
                        "run",
                        "--rm",
                        "registry-postgres-bootstrap",
                        "/bin/bash",
                        "-ceu",
                        query_script,
                    ],
                    cwd=root,
                    capture=True,
                )
                lines = {line.strip() for line in query.splitlines() if line.strip()}
                self.assertIn("t", lines)
                self.assertIn("registry_notary:registry_notary_owner", lines)
                self.assertIn("registry_relay:registry_relay_owner", lines)
                expected_roles = {
                    "registry_stack_bootstrap:true:true",
                    "registry_relay_owner:false:false",
                    "registry_relay_migrator:true:false",
                    "registry_relay_runtime:true:false",
                    "registry_relay_maintenance:true:false",
                    "registry_relay_reader:true:false",
                    "registry_notary_owner:false:false",
                    "registry_notary_migrator:true:false",
                    "registry_notary_runtime:true:false",
                    "registry_notary_maintenance:true:false",
                    "registry_notary_reader:true:false",
                }
                self.assertFalse(
                    expected_roles - lines,
                    f"missing role invariants: {sorted(expected_roles - lines)}",
                )

                marker_script = (
                    'export PGPASSWORD="$(cat '
                    '/run/secrets/postgresql-admin-password)"; '
                    "psql \"host=registry-postgres port=5432 "
                    "dbname=registry_relay user=registry_stack_bootstrap "
                    "sslmode=verify-full "
                    "sslrootcert=/run/secrets/postgresql-ca.pem\" "
                    "--set=ON_ERROR_STOP=1 "
                    "--command=\"CREATE TABLE public.runtime_restart_proof "
                    "(value integer PRIMARY KEY); "
                    "INSERT INTO public.runtime_restart_proof VALUES (1);\""
                )
                run(
                    [
                        *compose,
                        "run",
                        "--rm",
                        "registry-postgres-bootstrap",
                        "/bin/bash",
                        "-ceu",
                        marker_script,
                    ],
                    cwd=root,
                )
                run([*compose, "restart", "registry-postgres"], cwd=root)
                run(
                    [
                        *compose,
                        "up",
                        "--detach",
                        "--wait",
                        "--wait-timeout",
                        "120",
                        "registry-postgres",
                    ],
                    cwd=root,
                )
                marker_query = marker_script.replace(
                    '--command="CREATE TABLE public.runtime_restart_proof '
                    "(value integer PRIMARY KEY); "
                    'INSERT INTO public.runtime_restart_proof VALUES (1);"',
                    '--tuples-only --no-align '
                    '--command="SELECT value FROM public.runtime_restart_proof;"',
                )
                restarted = run(
                    [
                        *compose,
                        "run",
                        "--rm",
                        "registry-postgres-bootstrap",
                        "/bin/bash",
                        "-ceu",
                        marker_query,
                    ],
                    cwd=root,
                    capture=True,
                )
                self.assertIn("1", restarted.splitlines())
            finally:
                run([*compose, "down", "--volumes", "--remove-orphans"], cwd=root)


if __name__ == "__main__":
    unittest.main()
