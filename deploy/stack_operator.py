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
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from state_bundle import BundleError, file_hashes, verify_capture_age

CHART = Path(__file__).resolve().parent / "helm" / "registry-stack"
PACKAGE_ANNOTATION = "registrystack.org/package-digest"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
MODULES = ("breg", "appKit", "casework", "evidence")
BREG_SUCCESSOR_WARNINGS = (
    "warning: Review authority bindings are absent; affected retained Proposals will require rebase or cancellation after activation.",
    "warning: The retained Review closure could not be verified; affected Proposals will require rebase or cancellation after activation.",
)


class OperationError(Exception):
    """A failed precondition or a refused operation."""


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
    if (
        receipt.get("namespace") != namespace or receipt.get("release") != release
        or receipt.get("databaseId") != database_id or receipt.get("packageDigest") != digest
        or receipt.get("activationId") != activation_id
        or not re.fullmatch(r"[0-9a-f]{8,64}", receipt.get("snapshotId", ""))
        or not re.fullmatch(r"[0-9a-f]{64}", receipt.get("manifestSha256", ""))
    ):
        raise OperationError("The backup receipt does not identify the current installation and activation.")
    try:
        verify_capture_age(receipt, datetime.now(timezone.utc), timedelta(hours=max_age_hours))
    except BundleError as error:
        raise OperationError(str(error)) from error


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
        raise OperationError(f"{label} timed out. Inspect its state before retrying.") from error
    if result.returncode:
        raise OperationError(f"{label} failed with exit {result.returncode}. Inspect the selected resource.")
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
        try:
            yield
        finally:
            if self.active_job:
                print(f"Lease {name} retained while Job {self.active_job} has an uncertain outcome.", file=sys.stderr)
            else:
                path = f"/apis/coordination.k8s.io/v1/namespaces/{self.args.namespace}/leases/{name}"
                options = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": lease["metadata"]["uid"]}}
                self.kubectl("delete", "--raw", path, "-f", "-", data=json.dumps(options))

    def render_job(self, kind, overrides=None):
        name = f"{kind[:12]}-{uuid.uuid4().hex[:8]}"
        values = self.target if not overrides else {**self.target, "breg": {**self.target["breg"], **overrides["breg"]}}
        manifest = command_output([
            *self.helm, "template", self.args.release, str(self.chart), "-f", "-",
            "--show-only", "templates/breg-operation-job.yaml",
            "--set", "breg.operation.enabled=true",
            "--set-string", f"breg.operation.name={name}",
            "--set-string", f"breg.operation.kind={kind}",
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
        created = decode_json(self.kubectl("create", "-f", "-", "-o", "json", data=json.dumps(job)), "Job")
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
            raise OperationError(f"Job {name} timed out. Inspect the Job and product ledger before unlocking.")
        output = self.kubectl("logs", f"job/{name}", "--container", "bregctl")
        report = decode_job_report(output, kind, name)
        if terminal != "Complete" or report.get("ok") is not True:
            diagnostic = next(iter(report.get("diagnostics", [])), {})
            code = diagnostic.get("code", "") if isinstance(diagnostic, dict) else ""
            suffix = f" ({code})" if re.fullmatch(r"[a-z0-9.-]{1,100}", str(code)) else ""
            raise OperationError(f"BReg {kind} failed in Job {name}{suffix}. Review the Job and product ledger.")
        return report, digest

    def stop(self):
        deployments = self.kubectl("get", "deployments", "-l", self.selector, "-o", "name").splitlines()
        if deployments:
            self.kubectl("scale", *deployments, "--replicas=0")
        deadline = time.monotonic() + self.args.timeout
        while time.monotonic() < deadline:
            pods = decode_json(self.kubectl("get", "pods", "-l", self.selector, "-o", "json"), "Pods")
            if all(pod.get("status", {}).get("phase") in {"Succeeded", "Failed"} for pod in pods["items"]):
                return
            time.sleep(2)
        raise OperationError("Serving Pods did not terminate. The release is held in maintenance.")

    def apply_release(self, serve):
        command_output([
            *self.helm, "upgrade", "--install", self.args.release, str(self.chart),
            "-f", "-", "--wait", f"--timeout={self.args.timeout}s",
        ], "Apply Helm release", data=json.dumps(release_values(self.target, serve=serve)), timeout=self.args.timeout + 30)

    def verify_ready(self, digest):
        status, _ = self.job("status", digest)
        verify_active(status, digest, self.args.database_id)
        self.job("doctor", digest)
        return status

    def verify_backup(self, digest, activation_id):
        try:
            receipt = decode_json(self.args.backup_receipt.read_text(), "Backup receipt")
        except OSError as error:
            raise OperationError("Cannot read the required backup receipt.") from error
        verify_backup_receipt(
            receipt, self.args.namespace, self.args.release, self.args.database_id, digest, activation_id,
            self.args.max_backup_age_hours,
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
        backup_sha256 = json_sha256(self.verify_backup(previous, activation_id))
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
            if action == "apply-successor" and record is None:
                record = self.create_upgrade_record({
                    **identity, "previousPackageDigest": previous, "previousActivationId": activation_id,
                    "backupSha256": backup_sha256,
                })

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
        self.require_no_upgrade_record()
        report, digest = self.job("claim-status")
        claim = report.get("instanceClaim", report.get("status", {}))
        if not claim.get("claim") or type(claim.get("matches")) is not bool:
            raise OperationError("The target did not show a restored logical copy with a prior instance claim.")
        if self.releases() and (
            not claim["matches"] or self.values()["breg"]["package"]["expectedDigest"] != digest
        ):
            raise OperationError("Use a clean target Helm release for a logical restore.")
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
    commands.add_parser("install", help="Activate a new registry or resume the exact installation.")
    commands.add_parser("status", help="Inspect the product ledger and Helm release.")
    commands.add_parser("claim-status", help="Inspect the connected BReg database instance claim.")
    commands.add_parser("stop", help="Quiesce serving workloads for a coordinated backup.")
    upgrade = commands.add_parser("upgrade", help="Quiesce and apply a reviewed successor.")
    upgrade.add_argument("--backup-receipt", type=Path, required=True)
    upgrade.add_argument("--max-backup-age-hours", type=int, default=26)
    restore = commands.add_parser("adopt-restored", help="Adopt a logical restore after permanently fencing the source.")
    restore.add_argument("--confirm-original-fenced", action="store_true", required=True)
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
                print("Serving workloads are stopped.")
            elif args.action == "adopt-restored":
                print(json.dumps(installation.adopt(), indent=2))
            else:
                print(json.dumps(installation.apply(), indent=2))
    except (OperationError, OSError, KeyError, TypeError, AttributeError) as error:
        parser.exit(1, f"registry-stack: {error}\n")


if __name__ == "__main__":
    main()
