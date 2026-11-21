#!/usr/bin/env python3
"""Operate the BReg reference installation on a named Kubernetes context."""

import argparse
import contextlib
import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unicodedata
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from state_bundle import DNS_LABEL, BundleError, file_hashes, stderr_tail, verify_capture_age

CHART = Path(__file__).resolve().parent / "helm" / "registry-stack"
PACKAGE_ANNOTATION = "registrystack.org/package-digest"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
# kubectl prints these when the API server rejected a request without storing
# anything. It reports a failed validation (422) as "The <Kind> "<name>" is
# invalid" or "The request is invalid". Any other failure, such as a server
# timeout or a lost connection, may still have created the object.
REFUSED_REQUEST = re.compile(
    r'^(?:Error from server \((?:BadRequest|Forbidden|Invalid)\)|The \S+ "[^"]*" is invalid|The request is invalid)',
    re.MULTILINE,
)
MODULES = ("breg", "appKit", "casework", "evidence")
# BReg records an operator reference only for package activations. The chart
# accepts up to 256 characters; BReg accepts up to 512 bytes.
ACTIVATION_KINDS = ("apply-initial", "apply-successor")
MAX_OPERATOR_REFERENCE_BYTES = 256
BREG_SUCCESSOR_WARNINGS = (
    "warning: Review authority bindings are absent; affected retained Proposals will require rebase or cancellation after activation.",
    "warning: The retained Review closure could not be verified; affected Proposals will require rebase or cancellation after activation.",
)


class OperationError(Exception):
    """A failed precondition or a refused operation."""


class CommandFailed(OperationError):
    """A command that ran and exited non-zero, with its error output."""

    def __init__(self, message, stderr):
        super().__init__(message)
        self.stderr = stderr or ""


def activation_action(plan, digest, command):
    if (
        plan.get("ok") is not True or plan.get("command") != "plan"
        or plan.get("packageDigest") != digest or plan.get("roleMode") != "split"
    ):
        raise OperationError("The plan did not verify the selected package in split-role mode.")
    if plan.get("resumesActivationId"):
        raise OperationError("An activation was interrupted. Inspect and reconcile it with bregctl before proceeding.")
    if plan.get("requiredBackups"):
        raise OperationError("This migration requires a reviewed backup binding. Use the product migration procedure.")
    activation = plan.get("activation")
    active = plan.get("activePackageDigest")
    if plan.get("pending") is False and activation == "none" and active == digest:
        return None
    if plan.get("pending") is not True:
        raise OperationError("The product returned an inconsistent activation plan.")
    if activation == "initial" and active is None:
        if command == "upgrade":
            raise OperationError("The database has no active package. Use install for a new registry.")
        return "apply-initial"
    if activation == "successor" and isinstance(active, str) and DIGEST.fullmatch(active):
        if command == "install":
            raise OperationError("The database already has an active package. Use upgrade.")
        return "apply-successor"
    raise OperationError(f"Unsupported activation transition {activation!r}. Use the product migration procedure.")


def verify_active(report, digest, database_id):
    if (
        report.get("ok") is not True or report.get("command") != "status"
        or report.get("databaseId") != database_id
        or report.get("activePackageDigest") != digest
        or not report.get("activationId") or report.get("roleMode") != "split"
        or report.get("maintenanceStatus") != "ready" or report.get("maintenanceTargetPackageDigest") is not None
    ):
        raise OperationError("BReg status did not verify the expected ready database, package and split-role activation.")


def successor_job_values(deployed, target):
    inputs = ("runtimeConfig", "runtimeSecrets", "migrationSecrets", "package", "audit", "caBundleKey", "hostAliases")
    breg = {key: deployed[key] for key in inputs if key in deployed}
    breg["operation"] = {
        "candidate": {key: target[key] for key in ("existingClaim", "expectedDigest")},
    }
    return {"breg": breg}


def release_values(target, *, serve):
    values = copy.deepcopy(target)
    for module in ("breg", "casework", "evidence"):
        values.setdefault(module, {}).setdefault("operation", {})["enabled"] = False
    if not serve:
        for module in MODULES:
            values.setdefault(module, {})["serve"] = False
    return values


def require_install_retry(target, deployed):
    if deployed not in (release_values(target, serve=True), release_values(target, serve=False)):
        raise OperationError("Installed inputs differ from the requested values. Use upgrade for changes to an existing release.")


def json_sha256(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def upgrade_inputs_sha256(chart, target):
    if chart.is_dir():
        try:
            chart_contents = file_hashes(chart)
        except BundleError as error:
            raise OperationError("Cannot hash the staged chart directory.") from error
    else:
        with chart.open("rb") as stream:
            chart_contents = hashlib.file_digest(stream, "sha256").hexdigest()
    return json_sha256({"chart": chart_contents, "values": release_values(target, serve=True)})


def verify_backup_receipt(receipt, namespace, release, database_id, digest, activation_id, max_age_hours=26):
    """Check that the receipt names this activation and, unless max_age_hours is None, that it is recent."""
    if (
        receipt.get("namespace") != namespace or receipt.get("release") != release
        or receipt.get("databaseId") != database_id or receipt.get("packageDigest") != digest
        or receipt.get("activationId") != activation_id
        or not re.fullmatch(r"[0-9a-f]{8,64}", receipt.get("snapshotId", ""))
        or not re.fullmatch(r"[0-9a-f]{64}", receipt.get("manifestSha256", ""))
    ):
        raise OperationError("The backup receipt does not identify the current installation and activation.")
    if max_age_hours is None:
        return
    try:
        verify_capture_age(receipt, datetime.now(timezone.utc), timedelta(hours=max_age_hours))
    except BundleError as error:
        raise OperationError(
            f"{error} An upgrade needs a recent backup of the active registry so that a failed activation can be "
            "recovered without losing later changes. Take and check a new backup, or set --max-backup-age-hours "
            "to the recovery point the service owner accepts."
        ) from error


def verify_restored_database(status, receipt, database_id, digest):
    """Check that a restored database is the one --database-id and its backup receipt name, on the staged package."""
    if status.get("databaseId") != database_id:
        raise OperationError(
            "The restored database has another database ID than --database-id. "
            "Restore the bundle into the intended database or correct --database-id."
        )
    if receipt.get("databaseId") != database_id:
        raise OperationError(
            "The backup receipt names another database than --database-id. "
            "Use the receipt of the bundle you restored or correct --database-id."
        )
    if (
        not isinstance(receipt.get("packageDigest"), str) or not receipt.get("activationId")
        or status.get("activePackageDigest") != receipt["packageDigest"]
        or status.get("activationId") != receipt["activationId"]
    ):
        raise OperationError(
            "The restored database does not match the backup receipt. Its package digest or activation differs. "
            "Restore the bundle the receipt names into an empty database."
        )
    if status.get("activePackageDigest") != digest:
        raise OperationError(
            "The restored database runs another package than the values file stages. "
            "Stage the package the backup was taken with."
        )
    verify_active(status, digest, database_id)


def operator_reference(value):
    """Accept the change reference BReg records as a keyed hash with an activation."""
    if (
        not value or len(value.encode()) > MAX_OPERATOR_REFERENCE_BYTES
        or any(unicodedata.category(character) == "Cc" for character in value)
    ):
        raise argparse.ArgumentTypeError(
            f"use a change reference of 1 to {MAX_OPERATOR_REFERENCE_BYTES} bytes with no control characters"
        )
    return value


def previous_activation(status, previous_digest):
    ledger = status["ledger"]
    active = next((entry for entry in ledger if entry["activationId"] == status["activationId"]), None)
    if active is None or active["predecessorPackageDigest"] != previous_digest or active["outcome"] != "applied":
        raise OperationError("The database does not record the candidate as the direct successor of the Helm release.")
    previous = max(
        (entry for entry in ledger if entry["applyOrder"] < active["applyOrder"] and entry["outcome"] == "applied"),
        key=lambda entry: entry["applyOrder"], default=None,
    )
    if previous is None or previous["packageDigest"] != previous_digest:
        raise OperationError("The previous Helm activation is missing from the database ledger.")
    return previous["activationId"]


def command_output(args, label, data=None, timeout=60):
    try:
        result = subprocess.run(
            args, input=data, stdin=subprocess.DEVNULL if data is None else None,
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except FileNotFoundError as error:
        raise OperationError(f"Required command is unavailable: {args[0]}") from error
    except subprocess.TimeoutExpired as error:
        raise OperationError(
            f"{label} timed out. Inspect its state before retrying.{stderr_tail(error.stderr)}"
        ) from error
    if result.returncode:
        raise CommandFailed(
            f"{label} failed with exit {result.returncode}. Inspect the selected resource.{stderr_tail(result.stderr)}",
            result.stderr,
        )
    return result.stdout


def decode_json(output, label):
    try:
        return json.loads(output)
    except ValueError as error:
        raise OperationError(f"{label} did not produce JSON.") from error


def decode_job_report(output, kind, name):
    def unique_members(pairs):
        obj = dict(pairs)
        if len(obj) != len(pairs):
            raise ValueError("Duplicate JSON member")
        return obj

    def reject_constant(_):
        raise ValueError("Invalid JSON numeric token")

    warning = None
    if kind == "apply-successor":
        # kubectl combines stdout and stderr. Accept at most one complete,
        # recognized BReg warning alongside the report.
        lines = output.split("\n")
        warnings = [index for index, line in enumerate(lines) if line in BREG_SUCCESSOR_WARNINGS]
        if len(warnings) == 1:
            warning = lines.pop(warnings[0])
            output = "\n".join(lines)
    try:
        report = json.loads(output, object_pairs_hook=unique_members, parse_constant=reject_constant)
        if not isinstance(report, dict):
            raise ValueError("Expected a JSON object")
    except (ValueError, RecursionError) as error:
        raise OperationError(f"Job {name} did not produce one valid BReg JSON report. Review its logs and product ledger.") from error
    if warning:
        print(warning, file=sys.stderr)
    return report


def rendered_operation(output):
    """Read kubectl's individual JSON objects or List for an operation."""
    documents = []
    decoder = json.JSONDecoder()
    remaining = output.strip()
    try:
        while remaining:
            document, end = decoder.raw_decode(remaining)
            documents.extend(document["items"] if document.get("kind") == "List" else [document])
            remaining = remaining[end:].strip()
    except (ValueError, KeyError, AttributeError) as error:
        raise OperationError("The rendered operation did not produce Kubernetes objects.") from error
    jobs = [resource for resource in documents if resource.get("kind") == "Job"]
    policies = [resource for resource in documents if resource.get("kind") == "NetworkPolicy"]
    if len(jobs) != 1 or len(policies) > 1 or len(jobs) + len(policies) != len(documents):
        raise OperationError("The rendered operation must contain one Job and at most one NetworkPolicy.")
    job = jobs[0]
    digest = job.get("metadata", {}).get("annotations", {}).get(PACKAGE_ANNOTATION)
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        raise OperationError("The rendered Job is missing its selected package digest.")
    return job, policies[0] if policies else None, digest


class Installation:
    def __init__(self, args):
        self.args = args
        self.chart = args.chart
        self.kube = [args.kubectl_bin, "--context", args.kube_context, "--namespace", args.namespace]
        self.helm = [args.helm_bin, "--kube-context", args.kube_context, "--namespace", args.namespace]
        self.selector = f"app.kubernetes.io/instance={args.release}"
        self.upgrade_record_name = f"{args.release}-operator-upgrade"
        self.active_job = None
        self.target = decode_json(args.values.read_text(), "Operator values")

    def require_staged_package(self):
        """Refuse a values file without the BReg package that every BReg operation stages."""
        for path in ("breg.package.expectedDigest", "breg.package.existingClaim"):
            value = self.target
            for key in path.split("."):
                value = value.get(key) if isinstance(value, dict) else None
            if value is None:
                raise OperationError(f"The values file has no {path}. Add it for the staged BReg package.")

    def kubectl(self, *args, data=None, timeout=60):
        return command_output([*self.kube, *args], f"kubectl {args[0]}", data, timeout)

    def releases(self):
        output = command_output(
            [*self.helm, "list", "--filter", f"^{re.escape(self.args.release)}$", "-o", "json"],
            "Read Helm releases",
        )
        return decode_json(output, "helm list")

    def values(self, *, all_values=True):
        output = command_output(
            [*self.helm, "get", "values", self.args.release, "-o", "json", *(["--all"] if all_values else [])],
            "Read current Helm values",
        )
        return decode_json(output, "helm get values")

    @contextlib.contextmanager
    def lock(self):
        name = f"{self.args.release}-operator-lock"
        document = {
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": {"name": name, "namespace": self.args.namespace},
            "spec": {"holderIdentity": str(uuid.uuid4())},
        }
        try:
            lease = decode_json(self.kubectl("create", "-f", "-", "-o", "json", data=json.dumps(document)), "Lease")
        except OperationError as error:
            raise OperationError(f"Cannot acquire Lease {name}. Check for another operation and inspect its Jobs.") from error
        failed = False
        try:
            yield
        except BaseException:
            failed = True
            raise
        finally:
            if self.active_job:
                print(f"Lease {name} retained while Job {self.active_job} has an uncertain outcome.", file=sys.stderr)
            else:
                path = f"/apis/coordination.k8s.io/v1/namespaces/{self.args.namespace}/leases/{name}"
                options = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": lease["metadata"]["uid"]}}
                try:
                    self.kubectl("delete", "--raw", path, "-f", "-", data=json.dumps(options))
                except OperationError as error:
                    # Keep the operation's own failure as the reported error.
                    message = f"Lease {name} was not released. Delete it once no operation is running. {error}"
                    if not failed:
                        raise OperationError(message) from error
                    print(f"registry-stack: {message}", file=sys.stderr)

    def render_job(self, kind, overrides=None):
        name = f"{kind[:12]}-{uuid.uuid4().hex[:8]}"
        override = (overrides or {}).get("breg", {})
        operation = {
            **self.target["breg"].get("operation", {}), **override.get("operation", {}),
            "enabled": True, "name": name, "kind": kind,
        }
        # Only --operator-reference supplies the reference, never a values file.
        operation.pop("operatorReference", None)
        if kind in ACTIVATION_KINDS:
            reference = getattr(self.args, "operator_reference", None)
            if not reference:
                raise OperationError("A package activation needs --operator-reference.")
            operation["operatorReference"] = reference
        # The chart renders an operation Job only while BReg does not serve.
        # Values travel over standard input so the reference is never parsed
        # as a Helm --set expression.
        values = {**self.target, "breg": {**self.target["breg"], **override, "serve": False, "operation": operation}}
        manifest = command_output([
            *self.helm, "template", self.args.release, str(self.chart), "-f", "-",
            "--show-only", "templates/breg-operation-job.yaml",
        ], f"Render the BReg {kind} Job", data=json.dumps(values))
        return rendered_operation(
            self.kubectl("create", "--dry-run=client", "-f", "-", "-o", "json", data=manifest)
        )

    def job(self, kind, expected_digest=None, overrides=None):
        job, policy, digest = self.render_job(kind, overrides)
        if expected_digest and digest != expected_digest:
            raise OperationError("The configured package changed during the operation.")
        name = job["metadata"]["name"]
        if policy:
            self.kubectl("create", "-f", "-", "-o", "name", data=json.dumps(policy))
        # If creation times out, the Job might still exist. Leave the lock for
        # the operator until Kubernetes and the product ledger agree.
        self.active_job = name
        try:
            created = decode_json(self.kubectl("create", "-f", "-", "-o", "json", data=json.dumps(job)), "Job")
        except OperationError as error:
            # A live Job needs its policy. Drop the policy and the lock only
            # when the API server refused the create and Kubernetes confirms
            # the Job is absent. Any other failure stays uncertain, as above.
            if isinstance(error, CommandFailed) and REFUSED_REQUEST.search(error.stderr):
                self.abandon_job(name, policy["metadata"]["name"] if policy else None)
            raise
        if policy:
            reference = {"apiVersion": "batch/v1", "kind": "Job", "name": name, "uid": created["metadata"]["uid"]}
            patch = {"metadata": {"ownerReferences": [reference]}}
            self.kubectl(
                "patch", "networkpolicy", policy["metadata"]["name"], "--type", "merge", "-p", json.dumps(patch)
            )
        deadline = time.monotonic() + self.args.timeout
        terminal = None
        while time.monotonic() < deadline:
            status = decode_json(self.kubectl("get", "job", name, "-o", "json"), "Job status").get("status", {})
            terminal = next((
                condition["type"] for condition in status.get("conditions", [])
                if condition.get("status") == "True" and condition.get("type") in {"Complete", "Failed"}
            ), None)
            if terminal:
                self.active_job = None
                break
            time.sleep(2)
        if terminal is None:
            raise OperationError(
                f"Job {name} timed out. Its Lease and NetworkPolicy remain. "
                "Inspect the Job and product ledger before unlocking."
            )
        if policy:
            self.remove_policy(policy["metadata"]["name"], name)
        output = self.kubectl("logs", f"job/{name}", "--container", "bregctl")
        report = decode_job_report(output, kind, name)
        if terminal != "Complete" or report.get("ok") is not True:
            diagnostic = next(iter(report.get("diagnostics", [])), {})
            code = diagnostic.get("code", "") if isinstance(diagnostic, dict) else ""
            suffix = f" ({code})" if re.fullmatch(r"[a-z0-9.-]{1,100}", str(code)) else ""
            raise OperationError(f"BReg {kind} failed in Job {name}{suffix}. Review the Job and product ledger.")
        return report, digest

    def abandon_job(self, job, policy):
        """Release a Job's policy and lock once Kubernetes confirms it never created the Job."""
        try:
            if self.kubectl("get", "job", job, "--ignore-not-found", "-o", "name").strip():
                return
        except OperationError as error:
            kept = f" Check it before deleting NetworkPolicy {policy}." if policy else ""
            print(f"registry-stack: Cannot confirm whether Job {job} exists.{kept} {error}", file=sys.stderr)
            return
        self.active_job = None
        if policy:
            try:
                self.kubectl("delete", "networkpolicy", policy, "--ignore-not-found")
            except OperationError as error:
                print(f"registry-stack: NetworkPolicy {policy} has no Job and was not removed. Delete it. {error}", file=sys.stderr)

    def remove_policy(self, policy, job):
        """Remove the operation's database egress once its Job has a known outcome."""
        try:
            self.kubectl("delete", "networkpolicy", policy, "--ignore-not-found")
        except OperationError as error:
            print(
                f"registry-stack: NetworkPolicy {policy} was not removed. Kubernetes removes it with Job {job}. {error}",
                file=sys.stderr,
            )

    def stop(self):
        if not self.releases():
            raise OperationError("Helm has no release to stop.")
        # Keep the release's recorded inputs, which name the active package,
        # and record serve=false so any later Helm apply keeps it stopped.
        recorded = self.values(all_values=False) or {}
        stopped = release_values(recorded, serve=False)
        if recorded != stopped:
            self.apply_values(stopped, "Stop the Helm release")
        deadline = time.monotonic() + self.args.timeout
        while time.monotonic() < deadline:
            pods = decode_json(self.kubectl("get", "pods", "-l", self.selector, "-o", "json"), "Pods")
            if all(pod.get("status", {}).get("phase") in {"Succeeded", "Failed"} for pod in pods["items"]):
                return
            time.sleep(2)
        raise OperationError("Serving Pods did not terminate. The release is held in maintenance.")

    def apply_values(self, values, label):
        command_output([
            *self.helm, "upgrade", "--install", self.args.release, str(self.chart),
            "-f", "-", "--wait", f"--timeout={self.args.timeout}s",
        ], label, data=json.dumps(values), timeout=self.args.timeout + 30)

    def apply_release(self, serve):
        self.apply_values(release_values(self.target, serve=serve), "Apply Helm release")

    def verify_ready(self, digest):
        status, _ = self.job("status", digest)
        verify_active(status, digest, self.args.database_id)
        self.job("doctor", digest)
        return status

    def read_receipt(self):
        try:
            receipt = decode_json(self.args.backup_receipt.read_text(), "Backup receipt")
        except (OSError, UnicodeDecodeError) as error:
            raise OperationError("Cannot read the required backup receipt.") from error
        if not isinstance(receipt, dict):
            raise OperationError("Backup receipt is not a JSON object. Use the receipt that capture wrote.")
        return receipt

    def verify_backup(self, digest, activation_id, check_age=True):
        receipt = self.read_receipt()
        verify_backup_receipt(
            receipt, self.args.namespace, self.args.release, self.args.database_id, digest, activation_id,
            self.args.max_backup_age_hours if check_age else None,
        )
        return receipt

    def upgrade_record(self):
        output = self.kubectl("get", "configmap", self.upgrade_record_name, "--ignore-not-found", "-o", "json")
        return decode_json(output, "Upgrade checkpoint") if output.strip() else None

    def create_upgrade_record(self, data):
        record = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": self.upgrade_record_name, "namespace": self.args.namespace},
            "immutable": True,
            "data": data,
        }
        created = decode_json(self.kubectl("create", "-f", "-", "-o", "json", data=json.dumps(record)), "Upgrade checkpoint")
        if created.get("data") != data or created.get("immutable") is not True or not created["metadata"].get("uid"):
            raise OperationError("The upgrade checkpoint did not preserve the accepted inputs.")
        return created

    def remove_upgrade_record(self, record):
        path = f"/api/v1/namespaces/{self.args.namespace}/configmaps/{self.upgrade_record_name}"
        options = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": record["metadata"]["uid"]}}
        try:
            self.kubectl("delete", "--raw", path, "-f", "-", data=json.dumps(options))
        except OperationError:
            if self.upgrade_record() is not None:
                raise

    def require_no_upgrade_record(self):
        if self.upgrade_record() is not None:
            raise OperationError("An upgrade is pending. Use upgrade with the original chart, values and backup receipt.")

    def upgrade(self):
        if not self.releases():
            raise OperationError("Helm has no existing release to upgrade.")
        deployed = self.values()["breg"]
        current = deployed["package"]["expectedDigest"]
        target = self.target["breg"]["package"]
        digest = target["expectedDigest"]
        identity = {
            "version": "1",
            "databaseId": self.args.database_id,
            "candidatePackageDigest": digest,
            "inputsSha256": upgrade_inputs_sha256(self.chart, self.target),
        }
        record = self.upgrade_record()
        previous = current
        if record is not None:
            data = record["data"]
            if any(data.get(key) != value for key, value in identity.items()):
                raise OperationError("An upgrade is pending. Retry with the original chart and values for this database.")
            previous = data["previousPackageDigest"]
            if previous == digest or current not in (previous, digest):
                raise OperationError("Helm does not identify the predecessor or candidate of the pending upgrade.")

        status, _ = self.job("status", digest)
        committed = previous != digest and status.get("activePackageDigest") == digest
        verify_active(status, digest if committed else previous, self.args.database_id)
        activation_id = previous_activation(status, previous) if committed else status["activationId"]
        # A pending upgrade checked the receipt's age when it started, and the
        # recorded digest below binds the retry to that same receipt.
        backup_sha256 = json_sha256(self.verify_backup(previous, activation_id, check_age=record is None))
        if committed and record is None:
            raise OperationError("BReg committed a successor with no recorded upgrade. Use reviewed recovery with the original inputs.")
        if record is not None:
            if record["data"]["previousActivationId"] != activation_id:
                raise OperationError("The recorded upgrade identifies a different predecessor activation.")
            if record["data"].get("backupSha256") != backup_sha256:
                raise OperationError("An upgrade is pending. Retry with the original backup receipt.")

        action = overrides = None
        if not committed:
            if current != previous:
                raise OperationError("Helm records the candidate before its BReg activation. Inspect both before continuing.")
            overrides = successor_job_values(deployed, target) if previous != digest else None
            plan, _ = self.job("plan", digest, overrides)
            action = activation_action(plan, digest, "upgrade")
            if plan.get("activePackageDigest") != previous:
                raise OperationError("The database's active package differs from the serving Helm release.")
            if action and not getattr(self.args, "operator_reference", None):
                raise OperationError(
                    "Activating the successor package needs --operator-reference. "
                    "An upgrade that keeps the active package does not."
                )
            if action == "apply-successor" and record is None:
                record = self.create_upgrade_record({
                    **identity, "previousPackageDigest": previous, "previousActivationId": activation_id,
                    "backupSha256": backup_sha256,
                })

        # A resumed upgrade whose Helm release already serves the committed
        # target needs no maintenance stop before it is verified.
        if not committed or self.values(all_values=False) != release_values(self.target, serve=True):
            self.stop()
        if action:
            self.job(action, digest, overrides)
        status = self.verify_ready(digest)
        self.apply_release(serve=True)
        if record is not None:
            self.remove_upgrade_record(record)
        return status

    def apply(self):
        if self.args.action == "upgrade":
            # Use the same chart bytes for the plan, activation and Helm apply.
            with tempfile.TemporaryDirectory(prefix="registry-stack-chart-") as directory:
                if self.chart.is_dir():
                    staged = Path(directory) / "chart"
                    shutil.copytree(self.chart, staged)
                else:
                    staged = Path(directory) / "chart.tgz"
                    shutil.copyfile(self.chart, staged)
                self.chart = staged
                try:
                    return self.upgrade()
                finally:
                    self.chart = self.args.chart
        self.require_no_upgrade_record()
        existing = bool(self.releases())
        if existing:
            require_install_retry(self.target, self.values(all_values=False))
        digest = self.target["breg"]["package"]["expectedDigest"]
        plan, _ = self.job("plan", digest)
        action = activation_action(plan, digest, "install")
        if not existing and action is None:
            raise OperationError("The database is already active outside this Helm release. Use the recovery procedure.")
        if action and not getattr(self.args, "operator_reference", None):
            raise OperationError(
                "Activating the package needs --operator-reference. Reopening an active installation does not."
            )
        if existing and action:
            self.stop()
        elif not existing:
            self.apply_release(serve=False)
        if action:
            self.job(action, digest)
        status = self.verify_ready(digest)
        self.apply_release(serve=True)
        return status

    def adopt(self):
        receipt = self.read_receipt()
        self.require_no_upgrade_record()
        report, digest = self.job("claim-status")
        claim = report.get("instanceClaim")
        if not isinstance(claim, dict) or not claim.get("claim") or type(claim.get("matches")) is not bool:
            raise OperationError("The target did not show a restored logical copy with a prior instance claim.")
        if self.releases() and (
            not claim["matches"] or self.values()["breg"]["package"]["expectedDigest"] != digest
        ):
            raise OperationError("Use a clean target Helm release for a logical restore.")
        # The status report reads the activation record without the instance claim, so it answers for a copy
        # that has not been adopted. Nothing changes until it matches the receipt.
        restored, _ = self.job("status", digest)
        verify_restored_database(restored, receipt, self.args.database_id, digest)
        if not claim["matches"]:
            self.job("claim-adopt", digest)
        status = self.verify_ready(digest)
        self.apply_release(serve=True)
        return status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kube-context", required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--release", required=True)
    parser.add_argument("--database-id", required=True)
    parser.add_argument("--values", type=Path, required=True, help="Operator Helm values in JSON.")
    parser.add_argument("--chart", type=Path, default=CHART)
    parser.add_argument("--helm-bin", default=os.environ.get("REGISTRY_STACK_HELM", "helm"))
    parser.add_argument("--kubectl-bin", default=os.environ.get("REGISTRY_STACK_KUBECTL", "kubectl"))
    parser.add_argument("--timeout", type=int, default=300)
    commands = parser.add_subparsers(dest="action", required=True)
    install = commands.add_parser("install", help="Activate a new registry or resume the exact installation.")
    commands.add_parser("status", help="Inspect the product ledger and Helm release.")
    commands.add_parser("claim-status", help="Inspect the connected BReg database instance claim.")
    commands.add_parser("stop", help="Record a stopped Helm release for a coordinated backup and wait for its Pods.")
    upgrade = commands.add_parser("upgrade", help="Quiesce and apply a reviewed successor.")
    upgrade.add_argument("--backup-receipt", type=Path, required=True)
    upgrade.add_argument("--max-backup-age-hours", type=int, default=26)
    for command in (install, upgrade):
        command.add_argument(
            "--operator-reference", type=operator_reference,
            help="Change or ticket reference that BReg records, as a keyed hash, with a package activation. "
            "Needed only when the command activates a package.",
        )
    restore = commands.add_parser("adopt-restored", help="Adopt a logical restore after permanently fencing the source.")
    restore.add_argument("--confirm-original-fenced", action="store_true", required=True)
    restore.add_argument(
        "--backup-receipt", type=Path, required=True,
        help="Receipt of the backup bundle that was restored. The restored database must match it.",
    )
    args = parser.parse_args()
    if not DNS_LABEL.fullmatch(args.namespace) or not DNS_LABEL.fullmatch(args.release) or len(args.release) > 53:
        parser.error("Use a Kubernetes namespace and a valid Helm release name.")
    chart_exists = args.chart.is_dir() or (args.chart.is_file() and args.chart.suffix == ".tgz")
    if not args.values.is_file() or not chart_exists or not 1 <= args.timeout <= 3600:
        parser.error("Supply a values file, chart directory or archive, and timeout between 1 and 3600 seconds.")
    if args.action == "upgrade" and args.max_backup_age_hours < 1:
        parser.error("Supply a positive backup window.")

    try:
        installation = Installation(args)
        # stop reads the release's recorded values, so it also serves a release without BReg.
        if args.action != "stop":
            installation.require_staged_package()
        with installation.lock():
            if args.action == "status":
                status, digest = installation.job("status")
                verify_active(status, digest, args.database_id)
                print(json.dumps({"helm": installation.releases(), "database": status}, indent=2))
            elif args.action == "claim-status":
                report, _ = installation.job("claim-status")
                print(json.dumps(report, indent=2))
            elif args.action == "stop":
                installation.stop()
                print("Serving workloads are stopped. Helm keeps the release stopped until install, with the same values, or upgrade reopens it.")
            elif args.action == "adopt-restored":
                print(json.dumps(installation.adopt(), indent=2))
            else:
                print(json.dumps(installation.apply(), indent=2))
    except KeyError as error:
        # Installation checks the values file on load, so a missing key comes
        # from what Helm, Kubernetes, the upgrade record or BReg returned.
        parser.exit(1, (
            f"registry-stack: Missing key {error} in the Helm release values, a Kubernetes object, the upgrade "
            "record or a BReg report. "
            "Inspect them before retrying.\n"
        ))
    except (OperationError, OSError, TypeError, AttributeError) as error:
        parser.exit(1, f"registry-stack: {error}\n")


if __name__ == "__main__":
    main()
