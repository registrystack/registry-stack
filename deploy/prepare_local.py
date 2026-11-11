#!/usr/bin/env python3
"""Prepare PostgreSQL, retained storage and named inputs on one K3s server."""

import argparse
import base64
import json
import os
import re
import shutil
import socket
import sys
import tempfile
from pathlib import Path
from urllib.parse import unquote, urlsplit

from local_volume import prepare_directory, volume_documents
from stack_operator import DNS_LABEL, OperationError, command_output
from state_bundle import BundleError, file_hashes

DEPLOY = Path(__file__).resolve().parent
OWNERSHIP = "registrystack.org/local-installation"
FILE_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


class PrepareError(Exception):
    """An installation prerequisite was refused."""


def database_password(url, role, namespace):
    try:
        parsed = urlsplit(url)
        expected_host = f"registry-postgres.{namespace}.svc.cluster.local"
        password = unquote(parsed.password or "")
        valid = (
            parsed.scheme in {"postgres", "postgresql"} and parsed.hostname == expected_host
            and parsed.port in {None, 5432} and parsed.username == role and parsed.path == "/registry_breg"
            and not parsed.query and not parsed.fragment and bool(password)
            and not any(character in password for character in "\r\n\0")
        )
    except ValueError:
        valid = False
    if not valid:
        raise PrepareError(f"Use the documented PostgreSQL URL for role {role}.")
    return password


def unchanged(existing, desired):
    return all(existing.get(key) == value for key, value in desired.items() if key not in {"apiVersion", "metadata"})


def postgres_manifest(tls_secret):
    if not DNS_LABEL.fullmatch(tls_secret):
        raise PrepareError("Use a valid PostgreSQL TLS Secret name.")
    manifest = (DEPLOY / "postgres/postgres.yaml").read_text()
    default = "secretName: registry-postgres-tls\n"
    if manifest.count(default) != 1:
        raise PrepareError("The PostgreSQL manifest no longer has one reference TLS Secret binding.")
    return manifest.replace(default, f"secretName: {tls_secret}\n")


def input_file(path, private=False):
    if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
        raise PrepareError(f"Supply a nonempty regular file at {path.name}.")
    if private and path.stat().st_mode & 0o077:
        raise PrepareError(f"Make {path.name} readable only by its owner.")
    return path.read_bytes()


def secret_files(directory):
    if directory.is_symlink() or not directory.is_dir():
        raise PrepareError(f"Supply a private input directory named {directory.name}.")
    result = {}
    for path in directory.iterdir():
        if not FILE_KEY.fullmatch(path.name):
            raise PrepareError(f"Invalid Kubernetes Secret key in {directory.name}.")
        result[path.name] = input_file(path, private=True)
    return result


def stage_package(source, destination):
    expected = file_hashes(source)
    if not expected:
        raise PrepareError("Supply the sealed product package directory.")
    if any(destination.iterdir()):
        if file_hashes(destination) != expected:
            raise PrepareError("The existing package differs. Use a separate claim for the new package.")
        return
    with tempfile.TemporaryDirectory(dir=destination.parent) as work:
        staging = Path(work) / "package"
        shutil.copytree(source, staging)
        if file_hashes(staging) != expected:
            raise PrepareError("Package bytes changed while they were being copied.")
        for path in (*staging.rglob("*"), staging):
            os.chown(path, 65532, 65532)
            if path.is_dir():
                path.chmod(0o700)
        os.replace(staging, destination)


def prepare(args):
    root = args.inputs
    postgres_resources = postgres_manifest(args.postgres_tls_secret)
    values = json.loads(input_file(root / "values.json"))
    breg = values["breg"]
    if breg["enabled"] is not True or breg["serve"] is not True:
        raise PrepareError("Enable and serve BReg in values.json for this installation.")
    package_claim = breg["package"]["existingClaim"]
    audit_claim = breg["audit"]["existingClaim"]
    if len({"registry-postgres-data", audit_claim, package_claim}) != 3:
        raise PrepareError("PostgreSQL, BReg audit and package must each have their own claim.")
    runtime = input_file(root / "runtime.yaml").decode()
    runtime_secret = secret_files(root / "breg-runtime")
    migration_secret = secret_files(root / "breg-migration")
    passwords = {
        "registry_runtime": database_password(runtime_secret["runtime-database-url"].decode().strip(), "registry_runtime", args.namespace),
        "registry_migration": database_password(migration_secret["migration-database-url"].decode().strip(), "registry_migration", args.namespace),
    }
    if "migration-database-url" in runtime_secret:
        raise PrepareError("Keep the migration database credential out of the serving Secret.")
    postgres = {
        "tls.crt": input_file(root / "pg-server.crt"),
        "tls.key": input_file(root / "pg-server.key", private=True),
    }
    bootstrap = input_file(root / "pg-bootstrap", private=True)
    ingress = None
    if breg.get("ingress", {}).get("enabled"):
        ingress = {
            "tls.crt": input_file(root / "ingress.crt"),
            "tls.key": input_file(root / "ingress.key", private=True),
        }
    if not file_hashes(root / "package"):
        raise PrepareError("Supply the sealed BReg package directory.")

    def kube(*command, data=None, timeout=60):
        return command_output(
            [args.kubectl_bin, "--context", args.kube_context, "--namespace", args.namespace, *command],
            f"kubectl {command[0]}", data, timeout,
        )

    def existing(kind, name):
        return json.loads(kube("get", kind, name, "--ignore-not-found", "-o", "json") or "null")

    def ensure_object(kind, name, **body):
        desired = {"apiVersion": "v1", "kind": kind, "metadata": {"name": name}, "immutable": True, **body}
        current = existing(kind.lower(), name)
        if current is None:
            kube("create", "-f", "-", data=json.dumps(desired))
        elif not unchanged(current, desired):
            raise PrepareError(f"{kind} {name} already exists with different inputs. Use a new versioned name.")

    def secret(name, files, secret_type="Opaque"):
        data = {key: base64.b64encode(value).decode() for key, value in files.items()}
        ensure_object("Secret", name, data=data, type=secret_type)

    kube("get", "node", args.node, "-o", "name")
    labels = {OWNERSHIP: args.release, "pod-security.kubernetes.io/enforce": "restricted"}
    namespace = existing("namespace", args.namespace)
    if namespace is None:
        kube("create", "-f", "-", data=json.dumps({
            "apiVersion": "v1", "kind": "Namespace", "metadata": {"name": args.namespace, "labels": labels},
        }))
    elif any(namespace["metadata"].get("labels", {}).get(key) != value for key, value in labels.items()):
        raise PrepareError("Use a new namespace or the namespace prepared for this local installation.")

    for claim, owner, size in (
        ("registry-postgres-data", 999, args.postgres_size),
        (audit_claim, 65532, args.audit_size),
        (package_claim, 65532, args.package_size),
    ):
        volume, binding = volume_documents(args.namespace, claim, args.node, size)
        path = Path(volume["spec"]["local"]["path"])
        prepare_directory(path, owner, owner)
        if claim == package_claim:
            stage_package(root / "package", path)
        kube("apply", "-f", "-", data=json.dumps({"apiVersion": "v1", "kind": "List", "items": [volume, binding]}))

    ensure_object("ConfigMap", breg["runtimeConfig"]["configMapName"], data={breg["runtimeConfig"].get("key", "runtime.yaml"): runtime})
    secret(breg["runtimeSecrets"]["secretName"], runtime_secret)
    secret(breg["migrationSecrets"]["secretName"], migration_secret)
    if ingress is not None:
        secret(breg["ingress"]["tls"]["secretName"], ingress, "kubernetes.io/tls")
    secret(args.postgres_tls_secret, postgres, "kubernetes.io/tls")
    secret("registry-postgres-bootstrap", {"password": bootstrap})
    kube("apply", "-f", "-", data=postgres_resources)
    kube("rollout", "status", "statefulset/registry-postgres", "--timeout=240s", timeout=250)

    def postgres_command(*command, data=None):
        return kube("exec", "-i", "registry-postgres-0", "-c", "postgres", "--",
                    "psql", "-XAtq", "-U", "postgres", "-v", "ON_ERROR_STOP=1", *command, data=data)

    prepare_schema = "false" if args.for_restore else "true"
    postgres_command("-v", f"prepare_schema={prepare_schema}", data=(DEPLOY / "postgres/provision-breg.sql").read_text())
    for role, password in passwords.items():
        unset = postgres_command("-c", f"SELECT rolpassword IS NULL FROM pg_authid WHERE rolname = '{role}'").strip()
        if unset == "t":
            postgres_command("-c", f"\\password {role}", data=f"{password}\n{password}\n")
        elif unset != "f":
            raise PrepareError(f"PostgreSQL role {role} was not provisioned.")
    print("Prepared the retained local PostgreSQL and BReg inputs.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--kube-context", required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--release", required=True)
    parser.add_argument("--node", default=socket.gethostname().split(".")[0])
    parser.add_argument("--kubectl-bin", default="kubectl")
    parser.add_argument("--postgres-size", default="20Gi")
    parser.add_argument("--postgres-tls-secret", default="registry-postgres-tls")
    parser.add_argument("--audit-size", default="2Gi")
    parser.add_argument("--package-size", default="1Gi")
    parser.add_argument("--for-restore", action="store_true", help="Prepare an empty database for a verified logical restore.")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0 or args.node != socket.gethostname().split(".")[0]:
        parser.error("Run as root on the local Linux storage node.")
    if not DNS_LABEL.fullmatch(args.namespace) or not DNS_LABEL.fullmatch(args.release) or len(args.release) > 53:
        parser.error("Use a Kubernetes namespace and a valid Helm release name.")
    try:
        prepare(args)
    except (BundleError, PrepareError, OperationError, OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"prepare-local: {error}\n")


if __name__ == "__main__":
    main()
