#!/usr/bin/env python3
"""Capture, archive and recover the reference PostgreSQL installation state."""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


def require_supported_python(version):
    """Stop before work starts on an interpreter older than these tools use.

    stack_operator.py and prepare_local.py import this module, so the check
    covers all three tools. They use hashlib.file_digest and the ISO 8601
    forms that datetime.fromisoformat reads from Python 3.11.
    """
    if tuple(version[:2]) < (3, 11):
        raise SystemExit(
            f"These tools need Python 3.11 or later. This is Python {version[0]}.{version[1]}. "
            "Run them with a newer python3."
        )


require_supported_python(sys.version_info)

DATABASE_NAME = re.compile(r"[a-z][a-z0-9_]{0,62}")
SNAPSHOT_ID = re.compile(r"[0-9a-f]{8,64}")
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
STDERR_LINES = 20
STDERR_CHARACTERS = 2000
# A backup receipt identifies its bundle by these manifest fields and by the
# digest of the manifest bytes.
RECEIPT_FIELDS = ("namespace", "release", "databaseId", "packageDigest", "activationId", "capturedAt")
NOT_INCLUDED = (
    "Persistent volumes are not included: the BReg audit and package claims, and any attachment or object storage. "
    "Copy their files into the --files directory to keep them with this bundle."
)
STOPPED_PHASES = {"Succeeded", "Failed"}
# Status report fields that come from the BReg state row. The query reads that
# row as bregctl status does. BReg does not document this table, so a change to
# it makes psql fail and capture refuse rather than label a bundle wrongly.
BREG_STATE_FIELDS = ("databaseId", "activationId", "activePackageDigest", "maintenanceStatus")
BREG_STATE = (
    "SELECT json_build_object('databaseId', database_id, 'activationId', active_activation_id::text, "
    "'activePackageDigest', active_package_digest, 'maintenanceStatus', maintenance_status) "
    "FROM registry_internal.registry_state WHERE singleton;"
)


class BundleError(Exception):
    """A refused capture, snapshot or restore."""


def stderr_tail(output):
    """Format the end of a command's error output for an operator message.

    Only the command's own error output is used, never the data sent to its
    standard input. Control characters are replaced so a message cannot drive
    the operator's terminal.
    """
    if isinstance(output, bytes):
        output = output.decode(errors="replace")
    lines = (output or "").splitlines()[-STDERR_LINES:]
    text = "\n".join(
        "".join(character if character.isprintable() else " " if character == "\t" else "?" for character in line)
        for line in lines
    )[-STDERR_CHARACTERS:]
    return f"\nLast error output:\n{text}" if text.strip() else ""


def file_hashes(root):
    if not root.is_dir() or root.is_symlink():
        raise BundleError("The payload must be a real directory.")
    hashes = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise BundleError(f"The backup payload contains a symbolic link at {relative}.")
        if path.is_dir():
            continue
        if not path.is_file():
            raise BundleError(f"The backup payload contains a special file at {relative}.")
        with path.open("rb") as data:
            hashes[relative] = hashlib.file_digest(data, "sha256").hexdigest()
    return hashes


def verify_bundle(root, receipt=None):
    """Check the bundle files against its manifest and, when given, the manifest against its receipt."""
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise BundleError("A complete backup needs a regular manifest.json.")
    encoded = manifest_path.read_bytes()
    try:
        manifest = json.loads(encoded)
    except ValueError as error:
        raise BundleError("The backup manifest is unreadable.") from error
    if not isinstance(manifest, dict) or manifest.get("version") != 1 or manifest.get("files") != file_hashes(root / "payload"):
        raise BundleError("The backup files differ from the recorded manifest.")
    if receipt is not None and (
        not isinstance(receipt, dict) or hashlib.sha256(encoded).hexdigest() != receipt.get("manifestSha256")
        or any(manifest.get(field) != receipt.get(field) for field in RECEIPT_FIELDS)
    ):
        raise BundleError("The bundle manifest differs from the backup receipt. Use the receipt written for this bundle.")
    return manifest


def read_receipt(path):
    try:
        return json.loads(path.read_text())
    except ValueError as error:
        raise BundleError("The backup receipt is unreadable.") from error


def checked_run(argv, label, *, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE):
    result = subprocess.run(argv, stdin=stdin, stdout=stdout, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise BundleError(
            f"{label} failed with exit {result.returncode}. Inspect it in the private operator environment."
            f"{stderr_tail(result.stderr)}"
        )
    return result.stdout


def pg_command(args):
    return [
        args.kubectl_bin, "--context", args.kube_context, "--namespace", args.namespace,
        "exec", "-i", args.pod, "-c", args.container, "--",
    ]


def valid_database(name):
    if not DATABASE_NAME.fullmatch(name):
        raise BundleError("Supply a lowercase PostgreSQL database name.")
    return name


def running_release_pods(args):
    """Name the release's Pods that have not finished."""
    pods = json.loads(checked_run([
        args.kubectl_bin, "--context", args.kube_context, "--namespace", args.namespace,
        "get", "pods", "-l", f"app.kubernetes.io/instance={args.release}", "-o", "json",
    ], "List the release Pods"))
    return [
        pod.get("metadata", {}).get("name", "unnamed") for pod in pods.get("items", [])
        if pod.get("status", {}).get("phase") not in STOPPED_PHASES
    ]


def check_status_describes_database(args, status):
    """Refuse a saved status report that another activation or installation wrote."""
    database = args.breg_database
    recorded = checked_run([
        *pg_command(args), "psql", "-XAt", "--no-password", "--username=postgres", f"--dbname={database}",
        "-v", "ON_ERROR_STOP=1", "-c", BREG_STATE,
    ], f"Read the BReg state in {database}")
    if not recorded.strip():
        raise BundleError(f"Database {database} has no BReg state. Name the BReg database with --breg-database.")
    recorded = json.loads(recorded)
    differing = [field for field in BREG_STATE_FIELDS if recorded.get(field) != status.get(field)]
    if differing:
        raise BundleError(
            f"The status file does not describe database {database} (different {', '.join(differing)}). "
            "Run the operator's status command for this release again, save its output as the status file, "
            "then capture again."
        )


def capture(args):
    if not DNS_LABEL.fullmatch(args.release) or len(args.release) > 53:
        raise BundleError("Supply a valid Helm release name.")
    captured_at = datetime.now(timezone.utc).isoformat()
    if len(set(args.database)) != len(args.database):
        raise BundleError("Name each database once.")
    databases = [valid_database(name) for name in args.database]
    if valid_database(args.breg_database) not in databases:
        raise BundleError(
            f"Include the BReg database with --database {args.breg_database}, or name it with --breg-database."
        )
    status = json.loads(args.status_file.read_text())
    status = status.get("database", status)
    digest = status.get("activePackageDigest", "")
    if (
        status.get("ok") is not True or status.get("command") != "status"
        or status.get("roleMode") != "split" or status.get("maintenanceStatus") != "ready"
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
        or not status.get("databaseId") or not status.get("activationId")
    ):
        raise BundleError("Capture requires the current ready BReg status report.")
    if not args.files.is_dir() or args.files.is_symlink():
        raise BundleError("Supply the reviewed installation files in a private directory.")
    if args.output.resolve().is_relative_to(args.files.resolve()):
        raise BundleError("Put the new backup outside the directory being copied.")
    # A dump is consistent with the audit and other copied files only while
    # no release workload can write.
    running = running_release_pods(args)
    if running:
        raise BundleError(
            f"Release {args.release} has {len(running)} Pods that have not finished. "
            "Stop it with stack_operator.py stop, then capture again."
        )
    check_status_describes_database(args, status)
    args.output.mkdir(mode=0o700)
    payload = args.output / "payload"
    dumps = payload / "databases"
    dumps.mkdir(parents=True, mode=0o700)
    shutil.copytree(args.files, payload / "installation", symlinks=True)
    file_hashes(payload / "installation")
    for database in databases:
        path = dumps / f"{database}.dump"
        with path.open("xb") as output:
            checked_run([
                *pg_command(args), "pg_dump", "--format=custom", "--no-password",
                "--username=postgres", f"--dbname={database}",
            ], f"Dump {database}", stdout=output)
        # Read every block of the archive through the path restore-database
        # uses, writing nothing, so an unreadable dump never gets a manifest.
        with path.open("rb") as dump:
            checked_run([*pg_command(args), "pg_restore", "--file=/dev/null"], f"Read back the {database} dump", stdin=dump)
    if running_release_pods(args):
        raise BundleError(
            f"Release {args.release} started Pods during the capture. {args.output} has no manifest and is not a "
            "backup. Stop the release and capture again into a new directory."
        )
    manifest = {
        "version": 1, "namespace": args.namespace, "release": args.release,
        "databaseId": status["databaseId"], "packageDigest": digest, "activationId": status["activationId"],
        "capturedAt": captured_at, "databases": databases, "files": file_hashes(payload),
        "notIncluded": NOT_INCLUDED,
    }
    with (args.output / "manifest.json").open("x") as output:
        json.dump(manifest, output, indent=2)
        output.write("\n")
    print(f"Captured {len(databases)} databases and the reviewed files. {NOT_INCLUDED}")


def snapshot(args):
    # Check the receipt path before Restic writes a snapshot that no receipt would name.
    if os.path.lexists(args.receipt):
        raise BundleError(f"The receipt {args.receipt} already exists. Keep it, and choose a new receipt path.")
    if not args.receipt.parent.is_dir():
        raise BundleError(f"Create the receipt directory {args.receipt.parent}, or choose a receipt path in an existing one.")
    manifest = verify_bundle(args.bundle)
    capture_timestamp(manifest)
    manifest_hash = hashlib.sha256((args.bundle / "manifest.json").read_bytes()).hexdigest()
    result = checked_run([
        args.restic_bin, "backup", "--json", "--tag", "registry-stack", str(args.bundle.resolve()),
    ], "Write the encrypted snapshot")
    summaries = [json.loads(line) for line in result.splitlines()]
    ids = [row.get("snapshot_id", "") for row in summaries if row.get("message_type") == "summary"]
    if len(ids) != 1 or not SNAPSHOT_ID.fullmatch(ids[0]):
        raise BundleError("Restic did not return one snapshot identifier.")
    _, archived = archived_manifest(args.restic_bin, ids[0])
    if hashlib.sha256(archived).hexdigest() != manifest_hash:
        raise BundleError("The archived manifest digest differs from the captured bundle.")
    receipt = {key: manifest[key] for key in RECEIPT_FIELDS}
    receipt.update({"snapshotId": ids[0], "manifestSha256": manifest_hash})
    with args.receipt.open("x") as output:
        json.dump(receipt, output, indent=2)
        output.write("\n")
    print(f"Verified encrypted snapshot {ids[0]}.")


def verify_snapshot_age(metadata, now, maximum_age):
    try:
        created = datetime.fromisoformat(metadata["time"])
    except (KeyError, ValueError, TypeError) as error:
        raise BundleError("Restic did not report a valid snapshot timestamp.") from error
    if created.tzinfo is None:
        raise BundleError("Restic did not report the snapshot time zone.")
    if not timedelta(0) <= now - created <= maximum_age:
        raise BundleError("The encrypted snapshot is outside the configured backup window.")


def capture_timestamp(manifest):
    try:
        captured = datetime.fromisoformat(manifest["capturedAt"])
    except (KeyError, ValueError, TypeError) as error:
        raise BundleError("The bundle needs a recorded capture time.") from error
    if captured.tzinfo is None:
        raise BundleError("The bundle capture time needs a time zone.")
    return captured


def verify_capture_age(manifest, now, maximum_age):
    if not timedelta(0) <= now - capture_timestamp(manifest) <= maximum_age:
        raise BundleError("The database capture is outside the configured backup window.")


def verify_archived_manifest(archived, receipt, now, maximum_age):
    if hashlib.sha256(archived).hexdigest() != receipt.get("manifestSha256"):
        raise BundleError("The archived manifest digest differs from the backup receipt.")
    manifest = json.loads(archived)
    if any(manifest.get(field) != receipt.get(field) for field in RECEIPT_FIELDS):
        raise BundleError("The archived manifest differs from the backup receipt.")
    verify_capture_age(manifest, now, maximum_age)


def archived_manifest(restic, snapshot_id):
    metadata = json.loads(checked_run([restic, "cat", "snapshot", snapshot_id], "Read the encrypted snapshot"))
    paths = metadata.get("paths", [])
    if len(paths) != 1 or not Path(paths[0]).is_absolute():
        raise BundleError("The backup snapshot must identify exactly one bundle path.")
    manifest = checked_run([restic, "dump", snapshot_id, str(Path(paths[0]) / "manifest.json")], "Read the archived manifest")
    return metadata, manifest


def check_snapshot(args):
    receipt = json.loads(args.receipt.read_text())
    snapshot_id = receipt.get("snapshotId", "")
    if not SNAPSHOT_ID.fullmatch(snapshot_id) or args.max_age_hours < 1:
        raise BundleError("Supply a valid snapshot receipt and a positive backup window.")
    metadata, manifest = archived_manifest(args.restic_bin, snapshot_id)
    now = datetime.now(timezone.utc)
    maximum_age = timedelta(hours=args.max_age_hours)
    verify_snapshot_age(metadata, now, maximum_age)
    verify_archived_manifest(manifest, receipt, now, maximum_age)
    print(f"Encrypted snapshot {snapshot_id} is within the backup window.")


def restore_database(args):
    manifest = verify_bundle(args.bundle, read_receipt(args.receipt))
    source = valid_database(args.database)
    target = valid_database(args.target)
    if source not in manifest.get("databases", []):
        raise BundleError("The snapshot has no dump for the requested database.")
    user_object_count = (
        "SELECT (SELECT count(*) FROM pg_namespace WHERE nspname NOT IN "
        "('pg_catalog','pg_toast','public','information_schema') AND nspname NOT LIKE 'pg_temp_%' "
        "AND nspname NOT LIKE 'pg_toast_temp_%') "
        "+ (SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace) "
        "+ (SELECT count(*) FROM pg_extension WHERE extname <> 'plpgsql');"
    )
    user_objects = checked_run([
        *pg_command(args), "psql", "-XAt", "--no-password", "--username=postgres", f"--dbname={target}",
        "-v", "ON_ERROR_STOP=1", "-c", user_object_count,
    ], f"Check clean target {target}")
    if user_objects.strip() != b"0":
        raise BundleError("The restore target must be a clean database. Preserve the original for reconciliation.")
    with (args.bundle / "payload" / "databases" / f"{source}.dump").open("rb") as dump:
        checked_run([
            *pg_command(args), "pg_restore", "--single-transaction", "--exit-on-error",
            "--no-password", "--username=postgres", f"--dbname={target}",
        ], f"Restore {target}", stdin=dump)
    print(f"Restored {source} into clean database {target}.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    capture_command = commands.add_parser("capture", help="Dump PostgreSQL and copy private installation files.")
    restore_command = commands.add_parser("restore-database", help="Restore one verified dump into a clean database.")
    for command in (capture_command, restore_command):
        command.add_argument("--kube-context", required=True)
        command.add_argument("--namespace", required=True)
        command.add_argument("--pod", default="registry-postgres-0")
        command.add_argument("--container", default="postgres")
        command.add_argument("--kubectl-bin", default="kubectl")
    capture_command.add_argument("--release", required=True)
    capture_command.add_argument("--database", action="append", required=True)
    capture_command.add_argument(
        "--breg-database", default="registry_breg", help="The dumped database whose BReg state the status file describes.",
    )
    capture_command.add_argument("--status-file", type=Path, required=True)
    capture_command.add_argument("--files", type=Path, required=True)
    capture_command.add_argument("--output", type=Path, required=True)
    restore_command.add_argument("--bundle", type=Path, required=True)
    restore_command.add_argument("--receipt", type=Path, required=True)
    restore_command.add_argument("--database", required=True)
    restore_command.add_argument("--target", required=True)
    snapshot_command = commands.add_parser("snapshot", help="Archive the bundle to the configured Restic repository.")
    snapshot_command.add_argument("--bundle", type=Path, required=True)
    snapshot_command.add_argument("--receipt", type=Path, required=True)
    snapshot_command.add_argument("--restic-bin", default="restic")
    check_command = commands.add_parser("check-snapshot", help="Check the receipt against the repository and backup window.")
    check_command.add_argument("--receipt", type=Path, required=True)
    check_command.add_argument("--max-age-hours", type=int, required=True)
    check_command.add_argument("--restic-bin", default="restic")
    verify_command = commands.add_parser("verify", help="Verify a retrieved bundle against its manifest and receipt.")
    verify_command.add_argument("--bundle", type=Path, required=True)
    verify_command.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.action == "capture":
            capture(args)
        elif args.action == "snapshot":
            snapshot(args)
        elif args.action == "check-snapshot":
            check_snapshot(args)
        elif args.action == "restore-database":
            restore_database(args)
        else:
            manifest = verify_bundle(args.bundle, read_receipt(args.receipt))
            print(f"Verified {len(manifest['files'])} backup files against the receipt.")
    except (BundleError, OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"state-bundle: {error}\n")


if __name__ == "__main__":
    main()
