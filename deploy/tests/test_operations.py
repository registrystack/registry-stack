"""State transition checks for the Kubernetes operator workflow."""

import argparse
import copy
import io
import itertools
import json
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import stack_operator
from stack_operator import (
    BREG_SUCCESSOR_WARNINGS, Installation, OperationError, activation_action, command_output, operator_reference,
    rendered_operation, require_install_retry, release_values, successor_job_values, verify_active,
    verify_backup_receipt,
)


DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
REPOSITORY = Path(__file__).resolve().parents[2]


def fake_clock():
    """Advance one second per reading so polling loops reach their deadline at once."""
    return SimpleNamespace(monotonic=itertools.count().__next__, sleep=lambda seconds: None)


class ActivationTest(unittest.TestCase):
    def setUp(self):
        self.plan = {
            "ok": True,
            "command": "plan",
            "pending": True,
            "activation": "initial",
            "packageDigest": DIGEST,
            "activePackageDigest": None,
            "roleMode": "split",
            "resumesActivationId": None,
            "requiredBackups": [],
        }
        self.status = {
            "ok": True,
            "command": "status",
            "databaseId": "registry-test-db",
            "activePackageDigest": DIGEST,
            "activationId": "applied-activation",
            "roleMode": "split",
            "maintenanceStatus": "ready",
            "maintenanceTargetPackageDigest": None,
        }

    def test_install_accepts_only_initial_or_exact_noop(self):
        self.assertEqual(activation_action(self.plan, DIGEST, "install"), "apply-initial")
        self.plan.update(activePackageDigest=OTHER_DIGEST, activation="successor")
        with self.assertRaisesRegex(OperationError, "already has an active package"):
            activation_action(self.plan, DIGEST, "install")
        self.plan.update(activePackageDigest=DIGEST, activation="none", pending=False)
        self.assertIsNone(activation_action(self.plan, DIGEST, "install"))

    def test_upgrade_requires_existing_package(self):
        with self.assertRaisesRegex(OperationError, "has no active package"):
            activation_action(self.plan, DIGEST, "upgrade")
        self.plan.update(activePackageDigest=OTHER_DIGEST, activation="successor")
        self.assertEqual(activation_action(self.plan, DIGEST, "upgrade"), "apply-successor")

    def test_refuses_mismatched_plan_roles_and_required_backups(self):
        for update in ({"packageDigest": OTHER_DIGEST}, {"roleMode": "shared"}):
            with self.subTest(update=update), self.assertRaises(OperationError):
                activation_action(dict(self.plan, **update), DIGEST, "install")
        self.plan.update(activePackageDigest=OTHER_DIGEST, activation="successor", requiredBackups=["reviewed-data"])
        with self.assertRaisesRegex(OperationError, "reviewed backup"):
            activation_action(self.plan, DIGEST, "upgrade")

    def test_interrupted_activation_requires_reconciliation(self):
        self.plan.update(activePackageDigest=OTHER_DIGEST, activation="successor", resumesActivationId="unknown")
        with self.assertRaisesRegex(OperationError, "reconcile"):
            activation_action(self.plan, DIGEST, "upgrade")

    def test_ready_requires_exact_database_package_and_role_mode(self):
        verify_active(self.status, DIGEST, "registry-test-db")
        for key, value in {
            "databaseId": "other",
            "activePackageDigest": OTHER_DIGEST,
            "roleMode": "shared",
            "maintenanceStatus": "active",
            "maintenanceTargetPackageDigest": OTHER_DIGEST,
            "activationId": "",
        }.items():
            with self.subTest(key=key), self.assertRaises(OperationError):
                mutated = copy.copy(self.status)
                mutated[key] = value
                verify_active(mutated, DIGEST, "registry-test-db")

    def test_job_and_policy_may_be_returned_as_separate_objects(self):
        job = {"kind": "Job", "metadata": {"annotations": {"registrystack.org/package-digest": DIGEST}}}
        policy = {"kind": "NetworkPolicy"}
        self.assertEqual(rendered_operation(f"{json.dumps(job)}\n{json.dumps(policy)}"), (job, policy, DIGEST))
        self.assertEqual(rendered_operation(json.dumps({"kind": "List", "items": [job]})), (job, None, DIGEST))
        with self.assertRaisesRegex(OperationError, "one Job"):
            rendered_operation(json.dumps({"kind": "List", "items": [job, {"kind": "Secret"}]}))

    def test_successor_mounts_active_config_and_package_separately_from_candidate(self):
        deployed = {
            "runtimeConfig": {"configMapName": "old-config"},
            "runtimeSecrets": {"secretName": "old-runtime"},
            "migrationSecrets": {"secretName": "old-migration"},
            "package": {"existingClaim": "old-package", "expectedDigest": OTHER_DIGEST},
        }
        target = {"existingClaim": "new-package", "expectedDigest": DIGEST}
        overrides = successor_job_values(deployed, target)
        self.assertEqual(overrides["breg"]["runtimeConfig"], deployed["runtimeConfig"])
        self.assertEqual(overrides["breg"]["package"], deployed["package"])
        self.assertEqual(overrides["breg"]["operation"]["candidate"], target)
        self.assertNotIn("image", overrides["breg"])

    def test_backup_receipt_is_bound_to_the_previous_activation(self):
        receipt = {
            "namespace": "pilot", "release": "directory", "databaseId": "registry-test-db",
            "packageDigest": OTHER_DIGEST, "activationId": "previous-activation", "snapshotId": "c" * 64,
            "manifestSha256": "d" * 64,
            "capturedAt": datetime.now(timezone.utc).isoformat(),
        }
        verify_backup_receipt(receipt, "pilot", "directory", "registry-test-db", OTHER_DIGEST, "previous-activation")
        with self.assertRaisesRegex(OperationError, "current installation and activation"):
            verify_backup_receipt(receipt, "pilot", "directory", "registry-test-db", OTHER_DIGEST, "some-other-activation")
        stale = {**receipt, "capturedAt": (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()}
        with self.assertRaisesRegex(OperationError, "capture.*backup window"):
            verify_backup_receipt(stale, "pilot", "directory", "registry-test-db", OTHER_DIGEST, "previous-activation")

    def test_stale_backup_refusal_names_the_window_option_and_its_reason(self):
        receipt = {
            "namespace": "pilot", "release": "directory", "databaseId": "registry-test-db",
            "packageDigest": OTHER_DIGEST, "activationId": "previous-activation", "snapshotId": "c" * 64,
            "manifestSha256": "d" * 64,
            "capturedAt": (datetime.now(timezone.utc) - timedelta(hours=30)).isoformat(),
        }
        with self.assertRaises(OperationError) as raised:
            verify_backup_receipt(receipt, "pilot", "directory", "registry-test-db", OTHER_DIGEST, "previous-activation")
        message = str(raised.exception)
        self.assertIn("--max-backup-age-hours", message)
        self.assertIn("failed activation can be recovered", message)
        verify_backup_receipt(
            receipt, "pilot", "directory", "registry-test-db", OTHER_DIGEST, "previous-activation", max_age_hours=31,
        )

    def test_operator_reference_matches_the_breg_and_chart_limits(self):
        self.assertEqual(operator_reference("CHANGE-42, approved by the service owner"), "CHANGE-42, approved by the service owner")
        self.assertEqual(operator_reference("é" * 128), "é" * 128)
        for invalid in ("", "x" * 257, "é" * 129, "CHANGE-42\nforged", "tab\there", "\x7f"):
            with self.subTest(invalid=invalid), self.assertRaises(argparse.ArgumentTypeError):
                operator_reference(invalid)

    def test_upgrade_requires_an_operator_reference(self):
        common = [
            "stack_operator.py", "--kube-context", "test-only", "--namespace", "pilot", "--release", "directory",
            "--database-id", "registry-test-db", "--values", "values.json",
        ]
        stderr = io.StringIO()
        with (
            patch.object(sys, "argv", [*common, "upgrade", "--backup-receipt", "backup.json"]),
            redirect_stderr(stderr), self.assertRaises(SystemExit),
        ):
            stack_operator.main()
        self.assertIn("--operator-reference", stderr.getvalue())

    def test_install_can_retry_same_inputs_and_resume_a_held_release(self):
        values = {
            "breg": {"enabled": True, "serve": True, "package": {"expectedDigest": DIGEST}},
            "appKit": {"enabled": True, "serve": True, "image": {"digest": OTHER_DIGEST}},
        }
        require_install_retry(values, release_values(values, serve=True))
        require_install_retry(values, release_values(values, serve=False))
        other = copy.deepcopy(values)
        other["appKit"]["image"]["digest"] = DIGEST
        with self.assertRaisesRegex(OperationError, "Use upgrade"):
            require_install_retry(other, release_values(values, serve=True))


class InstallReferenceTest(unittest.TestCase):
    """Install asks for a change reference only when it activates a package."""

    def setUp(self):
        self.target = {"breg": {"enabled": True, "serve": True, "package": {"expectedDigest": DIGEST}}}
        self.status = {
            "ok": True, "command": "status", "databaseId": "registry-test-db",
            "activePackageDigest": DIGEST, "activationId": "applied-activation",
            "roleMode": "split", "maintenanceStatus": "ready", "maintenanceTargetPackageDigest": None,
        }

    def installation(self, deployed, active_digest, reference=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        values = Path(temporary.name) / "values.json"
        values.write_text(json.dumps(self.target))
        args = SimpleNamespace(
            namespace="pilot", release="directory", database_id="registry-test-db",
            kube_context="test-only", kubectl_bin="kubectl", helm_bin="helm", chart=Path("chart"),
            values=values, timeout=5, action="install", operator_reference=reference,
        )
        installation = Installation(args)
        installation.releases = Mock(return_value=[{"revision": "2"}] if deployed is not None else [])
        installation.values = Mock(return_value=deployed)
        installation.require_no_upgrade_record = Mock()
        installation.stop = Mock()
        installation.apply_release = Mock()
        pending = active_digest != DIGEST

        def job(kind, digest, overrides=None):
            if kind == "plan":
                return {
                    "ok": True, "command": "plan", "packageDigest": DIGEST, "roleMode": "split",
                    "activePackageDigest": active_digest, "pending": pending,
                    "activation": "initial" if pending else "none", "resumesActivationId": None,
                    "requiredBackups": [],
                }, digest
            if kind == "status":
                return copy.deepcopy(self.status), digest
            return {"ok": True}, digest

        installation.job = Mock(side_effect=job)
        return installation

    def test_reopening_a_stopped_release_needs_no_reference(self):
        installation = self.installation(release_values(self.target, serve=False), DIGEST)
        self.assertEqual(installation.apply()["activationId"], "applied-activation")
        installation.stop.assert_not_called()
        installation.apply_release.assert_called_once_with(serve=True)
        self.assertNotIn("apply-initial", [call.args[0] for call in installation.job.call_args_list])

    def test_initial_activation_without_a_reference_refuses_before_any_change(self):
        installation = self.installation(None, None)
        with self.assertRaisesRegex(OperationError, "--operator-reference"):
            installation.apply()
        installation.apply_release.assert_not_called()
        installation.stop.assert_not_called()
        self.assertEqual([call.args[0] for call in installation.job.call_args_list], ["plan"])

    def test_initial_activation_with_a_reference_proceeds(self):
        installation = self.installation(None, None, reference="CHANGE-42")
        installation.apply()
        kinds = [call.args[0] for call in installation.job.call_args_list]
        self.assertIn("apply-initial", kinds)
        installation.apply_release.assert_called_with(serve=True)


class JobReportTest(unittest.TestCase):
    WARNINGS = (
        "warning: Review authority bindings are absent; affected retained Proposals will require rebase or cancellation after activation.",
        "warning: The retained Review closure could not be verified; affected Proposals will require rebase or cancellation after activation.",
    )

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        values = root / "values.json"
        values.write_text("{}")
        self.args = SimpleNamespace(
            namespace="pilot", release="directory", kube_context="test-only",
            kubectl_bin="kubectl", helm_bin="helm", chart=root / "chart", values=values, timeout=2,
        )
        self.report = {
            "apiVersion": "id.registrystack.org/formats/breg/ctl-report/v1alpha1",
            "kind": "BRegCtlReport", "ok": True, "command": "apply",
            "packageDigest": DIGEST, "activation": "successor", "activationId": "synthetic-activation",
            "diagnostics": [],
        }
        self.stdout = json.dumps(self.report, indent=2)

    def job_runner(self, output, terminal):
        installation = Installation(self.args)
        installation.render_job = Mock(return_value=({"metadata": {"name": "breg-test-job"}}, None, DIGEST))
        installation.kubectl = Mock(side_effect=[
            json.dumps({"metadata": {"uid": "test-job-uid"}}),
            json.dumps({"status": {"conditions": [{"type": terminal, "status": "True"}]}}),
            output,
        ])
        return installation

    def run_job(self, output, terminal="Complete", kind="apply-successor"):
        self.stderr = io.StringIO()
        with redirect_stderr(self.stderr):
            return self.job_runner(output, terminal).job(kind, DIGEST)

    def test_completed_successor_preserves_an_exact_review_warning(self):
        for warning in self.WARNINGS:
            for position, output in (
                ("before", f"{warning}\n{self.stdout}\n"),
                ("between", self.stdout.replace("{\n", f"{{\n{warning}\n", 1)),
                ("after", f"{self.stdout}\n{warning}\n"),
            ):
                with self.subTest(warning=warning, position=position):
                    self.assertEqual(self.run_job(output), (self.report, DIGEST))
                    self.assertEqual(self.stderr.getvalue(), warning + "\n")

    def test_plain_structured_report_remains_supported(self):
        self.assertEqual(self.run_job(self.stdout), (self.report, DIGEST))
        self.assertEqual(self.stderr.getvalue(), "")

    def test_rejects_malformed_or_ambiguous_job_logs(self):
        warning = self.WARNINGS[0]
        cases = {
            "unknown preamble": f"warning: unknown text\n{self.stdout}",
            "trailing junk": f"{warning}\n{self.stdout}\nother output",
            "two warnings": f"{warning}\n{self.WARNINGS[1]}\n{self.stdout}",
            "two reports": f"{warning}\n{self.stdout}\n{self.stdout}",
            "no report": f"{warning}\n",
            "array": f"[{self.stdout}]",
            "duplicate outcome": self.stdout.replace('"ok": true', '"ok": false, "ok": true'),
            "invalid numeric token": self.stdout.replace('"diagnostics": []', '"diagnostics": NaN'),
        }
        for description, output in cases.items():
            with self.subTest(description=description), self.assertRaises(OperationError):
                self.run_job(output)
        with self.assertRaises(OperationError):
            self.run_job(f"{warning}\n{self.stdout}", kind="status")

    def test_success_report_cannot_override_a_failed_job(self):
        with self.assertRaisesRegex(OperationError, "BReg apply-successor failed"):
            self.run_job(f"{self.WARNINGS[0]}\n{self.stdout}", terminal="Failed")

    def test_completed_job_still_refuses_a_reported_failure(self):
        failure = {**self.report, "ok": False, "diagnostics": [{"code": "apply.synthetic-refusal"}]}
        with self.assertRaisesRegex(OperationError, r"failed .*\(apply\.synthetic-refusal\)"):
            self.run_job(f"{self.WARNINGS[0]}\n{json.dumps(failure)}")
        self.assertEqual(self.stderr.getvalue(), self.WARNINGS[0] + "\n")

    def test_wrong_package_is_refused_before_creating_a_job(self):
        installation = self.job_runner(self.stdout, "Complete")
        with self.assertRaisesRegex(OperationError, "configured package changed"):
            installation.job("apply-successor", OTHER_DIGEST)
        installation.kubectl.assert_not_called()

    def test_accepted_warnings_are_the_ones_bregctl_prints(self):
        source = (REPOSITORY / "crates/registry-bregctl/src/apply_lifecycle.rs").read_text()
        printed = re.findall(r'eprintln!\(\s*"(warning: [^"\\]*)"\s*\);', source)
        self.assertEqual(sorted(printed), sorted(BREG_SUCCESSOR_WARNINGS))
        self.assertEqual(sorted(self.WARNINGS), sorted(BREG_SUCCESSOR_WARNINGS))


class JobLifecycleTest(unittest.TestCase):
    """The operation NetworkPolicy and Lease follow the Job's known or uncertain outcome."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        values = root / "values.json"
        values.write_text("{}")
        self.args = SimpleNamespace(
            namespace="pilot", release="directory", kube_context="test-only",
            kubectl_bin="kubectl", helm_bin="helm", chart=root / "chart", values=values, timeout=2,
        )
        self.report = {"ok": True, "command": "status"}
        self.conditions = [{"type": "Complete", "status": "True"}]
        self.delete_error = None
        self.calls = []

    def kubectl(self, command, *args, data=None, **kwargs):
        self.calls.append((command, *args))
        body = json.loads(data) if data else {}
        if command == "create" and body.get("kind") == "Lease":
            return json.dumps({"metadata": {"uid": "lease-uid"}})
        if command == "create" and body.get("kind") == "NetworkPolicy":
            return "networkpolicy.networking.k8s.io/status-test"
        if command == "create" and body.get("kind") == "Job":
            return json.dumps({"metadata": {"uid": "job-uid"}})
        if command == "patch":
            return ""
        if command == "get":
            return json.dumps({"status": {"conditions": self.conditions}})
        if command == "logs":
            return json.dumps(self.report)
        if command == "delete":
            if self.delete_error and args[0] == self.delete_error[0]:
                raise OperationError(self.delete_error[1])
            return ""
        self.fail(f"Unexpected Kubernetes command {command}")

    def installation(self):
        installation = Installation(self.args)
        job = {"kind": "Job", "metadata": {"name": "status-test"}}
        policy = {"kind": "NetworkPolicy", "metadata": {"name": "status-test"}}
        installation.render_job = Mock(return_value=(job, policy, DIGEST))
        installation.kubectl = Mock(side_effect=self.kubectl)
        return installation

    def test_known_outcome_removes_the_operation_network_policy(self):
        for terminal in ("Complete", "Failed"):
            with self.subTest(terminal=terminal):
                self.calls.clear()
                self.conditions = [{"type": terminal, "status": "True"}]
                installation = self.installation()
                if terminal == "Complete":
                    self.assertEqual(installation.job("status", DIGEST), (self.report, DIGEST))
                else:
                    with self.assertRaisesRegex(OperationError, "BReg status failed"):
                        installation.job("status", DIGEST)
                removal = ("delete", "networkpolicy", "status-test", "--ignore-not-found")
                self.assertIn(removal, self.calls)
                self.assertLess(self.calls.index(("get", "job", "status-test", "-o", "json")), self.calls.index(removal))

    def test_policy_removal_failure_is_reported_without_hiding_the_outcome(self):
        self.delete_error = ("networkpolicy", "synthetic removal failure")
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            self.assertEqual(self.installation().job("status", DIGEST), (self.report, DIGEST))
        self.assertIn("NetworkPolicy status-test", stderr.getvalue())
        self.assertIn("synthetic removal failure", stderr.getvalue())

    def test_job_timeout_keeps_the_lease_and_network_policy(self):
        self.conditions = []
        installation = self.installation()
        stderr = io.StringIO()
        with (
            patch("stack_operator.time", fake_clock()), redirect_stderr(stderr),
            self.assertRaisesRegex(OperationError, "Job status-test timed out"),
        ):
            with installation.lock():
                installation.job("status", DIGEST)
        self.assertIn("Lease directory-operator-lock retained while Job status-test", stderr.getvalue())
        self.assertFalse([entry for entry in self.calls if entry[0] == "delete"])

    def test_lease_release_failure_keeps_the_original_error(self):
        self.delete_error = ("--raw", "synthetic Lease failure")
        installation = self.installation()
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaisesRegex(OperationError, "^Original failure$"):
            with installation.lock():
                raise OperationError("Original failure")
        self.assertIn("Lease directory-operator-lock was not released", stderr.getvalue())
        self.assertIn("synthetic Lease failure", stderr.getvalue())

    def test_lease_release_failure_after_success_is_raised(self):
        self.delete_error = ("--raw", "synthetic Lease failure")
        installation = self.installation()
        with self.assertRaisesRegex(OperationError, "Lease directory-operator-lock was not released.*synthetic Lease failure"):
            with installation.lock():
                pass

    def test_released_lease_names_its_uid_precondition(self):
        installation = self.installation()
        with installation.lock():
            pass
        deletes = [entry for entry in installation.kubectl.call_args_list if entry.args[0] == "delete"]
        self.assertEqual(len(deletes), 1)
        self.assertEqual(json.loads(deletes[0].kwargs["data"])["preconditions"], {"uid": "lease-uid"})


class RenderJobTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.target = {
            "breg": {
                "enabled": True, "serve": True,
                "package": {"existingClaim": "successor", "expectedDigest": DIGEST},
                "operation": {"activeDeadlineSeconds": 900},
            },
            "appKit": {"enabled": True, "serve": True},
        }
        values = root / "values.json"
        values.write_text(json.dumps(self.target))
        self.args = SimpleNamespace(
            namespace="pilot", release="directory", kube_context="test-only", kubectl_bin="kubectl",
            helm_bin="helm", chart=root / "chart", values=values, timeout=2,
            operator_reference="CHANGE-42, approved=service owner",
        )
        self.job = {"kind": "Job", "metadata": {"annotations": {"registrystack.org/package-digest": DIGEST}}}

    def render(self, kind, overrides=None):
        installation = Installation(self.args)
        installation.kubectl = Mock(return_value=json.dumps(self.job))
        with patch("stack_operator.command_output", return_value="rendered") as helm:
            installation.render_job(kind, overrides)
        command = helm.call_args.args[0]
        return command, json.loads(helm.call_args.kwargs["data"])

    def test_operation_jobs_render_with_breg_serving_disabled(self):
        for kind in ("status", "doctor", "plan", "claim-status", "claim-adopt", "apply-initial"):
            with self.subTest(kind=kind):
                command, values = self.render(kind)
                self.assertIs(values["breg"]["serve"], False)
                operation = values["breg"]["operation"]
                self.assertEqual((operation["enabled"], operation["kind"]), (True, kind))
                self.assertRegex(operation["name"], r"^[a-z0-9-]{1,21}$")
                self.assertEqual(operation["activeDeadlineSeconds"], 900)
                self.assertTrue(values["appKit"]["serve"])
                self.assertNotIn("--set", command)
                self.assertNotIn("--set-string", command)

    def test_only_package_activations_carry_the_operator_reference(self):
        candidate = {"existingClaim": "candidate", "expectedDigest": OTHER_DIGEST}
        overrides = {"breg": {"package": {"existingClaim": "previous", "expectedDigest": DIGEST}, "operation": {"candidate": candidate}}}
        for kind, kind_overrides in (("apply-initial", None), ("apply-successor", overrides)):
            with self.subTest(kind=kind):
                command, values = self.render(kind, kind_overrides)
                self.assertEqual(values["breg"]["operation"]["operatorReference"], self.args.operator_reference)
                self.assertNotIn(self.args.operator_reference, " ".join(command))
        _, values = self.render("apply-successor", overrides)
        self.assertEqual(values["breg"]["operation"]["candidate"], candidate)
        self.assertEqual(values["breg"]["operation"]["activeDeadlineSeconds"], 900)
        self.assertEqual(values["breg"]["package"]["existingClaim"], "previous")
        for kind in ("status", "doctor", "plan", "claim-status", "claim-adopt"):
            with self.subTest(kind=kind):
                self.assertNotIn("operatorReference", self.render(kind)[1]["breg"]["operation"])

    def test_package_activation_without_a_reference_is_refused(self):
        del self.args.operator_reference
        with self.assertRaisesRegex(OperationError, "--operator-reference"):
            self.render("apply-initial")

    def test_only_the_command_line_supplies_the_operator_reference(self):
        self.target["breg"]["operation"]["operatorReference"] = "VALUES-FILE-REFERENCE"
        self.args.values.write_text(json.dumps(self.target))
        self.assertNotIn("operatorReference", self.render("plan")[1]["breg"]["operation"])
        operation = self.render("apply-initial")[1]["breg"]["operation"]
        self.assertEqual(operation["operatorReference"], self.args.operator_reference)
        del self.args.operator_reference
        with self.assertRaisesRegex(OperationError, "--operator-reference"):
            self.render("apply-initial")


class StopTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.target = {
            "breg": {"enabled": True, "serve": True, "package": {"existingClaim": "previous", "expectedDigest": OTHER_DIGEST}},
            "appKit": {"enabled": True, "serve": True},
        }
        values = root / "values.json"
        values.write_text(json.dumps(self.target))
        self.args = SimpleNamespace(
            namespace="pilot", release="directory", kube_context="test-only", kubectl_bin="kubectl",
            helm_bin="helm", chart=root / "chart", values=values, timeout=2,
        )
        self.recorded = release_values(self.target, serve=True)
        self.helm_calls = []
        self.pods = [{"status": {"phase": "Succeeded"}}]
        helm = patch("stack_operator.command_output", side_effect=self.helm)
        helm.start()
        self.addCleanup(helm.stop)

    def helm(self, args, label, data=None, timeout=60):
        self.helm_calls.append((args, label))
        self.recorded = json.loads(data)
        return ""

    def kubectl(self, command, *args, **kwargs):
        self.assertEqual((command, *args), ("get", "pods", "-l", "app.kubernetes.io/instance=directory", "-o", "json"))
        return json.dumps({"items": self.pods})

    def installation(self, releases=({"name": "directory"},)):
        installation = Installation(self.args)
        installation.releases = Mock(return_value=list(releases))
        installation.values = Mock(side_effect=self.recorded_values)
        installation.kubectl = Mock(side_effect=self.kubectl)
        return installation

    def recorded_values(self, *, all_values=True):
        self.assertFalse(all_values)
        return copy.deepcopy(self.recorded)

    def test_stop_records_the_stopped_state_in_the_helm_release(self):
        self.installation().stop()
        self.assertEqual(len(self.helm_calls), 1)
        args, _ = self.helm_calls[0]
        self.assertEqual(args[:4], ["helm", "--kube-context", "test-only", "--namespace"])
        self.assertIn("upgrade", args)
        self.assertIn("--install", args)
        self.assertIn("--wait", args)
        self.assertNotIn("--force-conflicts", args)
        self.assertEqual(self.recorded, release_values(self.target, serve=False))
        # An interrupted install or reopen can resume from the stopped release.
        require_install_retry(self.target, self.recorded)

    def test_stop_keeps_the_recorded_inputs_of_the_active_package(self):
        self.recorded = release_values({**self.target, "breg": {**self.target["breg"], "runtimeConfig": {"configMapName": "active"}}}, serve=True)
        self.installation().stop()
        self.assertEqual(self.recorded["breg"]["package"]["expectedDigest"], OTHER_DIGEST)
        self.assertEqual(self.recorded["breg"]["runtimeConfig"], {"configMapName": "active"})
        self.assertFalse(self.recorded["breg"]["serve"])

    def test_stopped_release_is_not_reapplied(self):
        self.recorded = release_values(self.target, serve=False)
        installation = self.installation()
        installation.stop()
        self.assertFalse(self.helm_calls)
        installation.kubectl.assert_called_once()

    def test_stop_timeout_holds_the_release_in_maintenance(self):
        self.pods = [{"status": {"phase": "Running"}}]
        with (
            patch("stack_operator.time", fake_clock()),
            self.assertRaisesRegex(OperationError, "Serving Pods did not terminate"),
        ):
            self.installation().stop()
        self.assertEqual(self.recorded, release_values(self.target, serve=False))

    def test_stop_requires_a_helm_release(self):
        installation = self.installation(releases=())
        with self.assertRaisesRegex(OperationError, "no release to stop"):
            installation.stop()
        self.assertFalse(self.helm_calls)
        installation.kubectl.assert_not_called()


class CommandOutputTest(unittest.TestCase):
    def failure(self, script, data=None):
        with self.assertRaises(OperationError) as raised:
            command_output([sys.executable, "-I", "-c", script], "Synthetic step", data=data)
        return str(raised.exception)

    def test_failure_reports_the_last_error_lines_without_stdin(self):
        message = self.failure(
            "import sys\nsys.stdin.read()\nfor number in range(30):\n    print(f'diagnostic {number}', file=sys.stderr)\nsys.exit(3)",
            data="stdin-only-credential",
        )
        self.assertIn("Synthetic step failed with exit 3", message)
        lines = message.splitlines()
        self.assertIn("diagnostic 29", lines)
        self.assertIn("diagnostic 10", lines)
        self.assertNotIn("diagnostic 9", lines)
        self.assertNotIn("stdin-only-credential", message)

    def test_error_output_is_bounded_and_printable(self):
        message = self.failure("import sys\nprint('\\x1b[2J' + 'x' * 20000, file=sys.stderr)\nsys.exit(1)")
        self.assertLess(len(message), 2500)
        self.assertNotIn("\x1b", message)
        self.assertTrue(message.endswith("x"))

    def test_quiet_failure_keeps_the_short_message(self):
        self.assertEqual(
            self.failure("import sys\nsys.exit(4)"),
            "Synthetic step failed with exit 4. Inspect the selected resource.",
        )

    def test_timeout_reports_the_error_output_so_far(self):
        script = "import sys, time\nprint('waiting for the API server', file=sys.stderr, flush=True)\ntime.sleep(30)"
        with self.assertRaises(OperationError) as raised:
            command_output([sys.executable, "-I", "-c", script], "Synthetic step", timeout=1)
        message = str(raised.exception)
        self.assertIn("Synthetic step timed out", message)
        self.assertIn("waiting for the API server", message.splitlines())


class UpgradeRetryTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.chart = root / "chart.tgz"
        self.chart.write_bytes(b"reviewed chart")
        self.args = SimpleNamespace(
            namespace="pilot", release="directory", database_id="registry-test-db",
            kube_context="test-only", kubectl_bin="kubectl", helm_bin="helm",
            chart=self.chart, values=root / "values.json", backup_receipt=root / "backup.json",
            timeout=5, max_backup_age_hours=26, action="upgrade",
        )
        self.target = {
            "breg": {"package": {"existingClaim": "successor", "expectedDigest": DIGEST}},
            "appKit": {"enabled": True, "image": {"digest": OTHER_DIGEST}},
        }
        self.deployed = {"breg": {"package": {"existingClaim": "previous", "expectedDigest": OTHER_DIGEST}}}
        self.status = {
            "ok": True, "command": "status", "databaseId": self.args.database_id,
            "activePackageDigest": OTHER_DIGEST, "activationId": "previous-activation",
            "roleMode": "split", "maintenanceStatus": "ready", "maintenanceTargetPackageDigest": None,
            "ledger": [{
                "activationId": "previous-activation", "packageDigest": OTHER_DIGEST,
                "predecessorPackageDigest": None, "applyOrder": 1, "outcome": "applied",
            }],
        }
        self.backup_receipt(OTHER_DIGEST, "previous-activation")
        self.record = None
        self.helm_inputs = []
        self.fail_helm = True
        self.record_helm_before_failure = False
        helm = patch("stack_operator.command_output", side_effect=self.helm)
        helm.start()
        self.addCleanup(helm.stop)

    def backup_receipt(self, digest, activation_id, namespace="pilot"):
        self.args.backup_receipt.write_text(json.dumps({
            "namespace": namespace, "release": self.args.release, "databaseId": self.args.database_id,
            "packageDigest": digest, "activationId": activation_id, "snapshotId": "c" * 64,
            "manifestSha256": "d" * 64, "capturedAt": datetime.now(timezone.utc).isoformat(),
        }))

    def installation(self, values=None, action="upgrade"):
        self.args.values.write_text(json.dumps(self.target if values is None else values))
        installation = Installation(SimpleNamespace(**{**vars(self.args), "action": action}))
        installation.releases = Mock(return_value=[{"revision": "1"}])
        installation.values = Mock(side_effect=lambda **kwargs: self.deployed)
        installation.stop = Mock()
        installation.job = Mock(side_effect=self.job)
        installation.kubectl = Mock(side_effect=self.kubectl)
        return installation

    def kubectl(self, command, *args, data=None, **kwargs):
        if command == "get" and args[0] == "configmap":
            return "" if self.record is None else json.dumps(self.record)
        if command == "create":
            self.assertIsNone(self.record)
            self.record = json.loads(data)
            self.assertEqual(self.record["kind"], "ConfigMap")
            self.record["metadata"]["uid"] = "checkpoint-uid"
            return json.dumps(self.record)
        if command == "delete":
            self.assertEqual(json.loads(data)["preconditions"], {"uid": "checkpoint-uid"})
            self.record = None
            return ""
        self.fail(f"Unexpected Kubernetes command {command}")

    def job(self, kind, digest, overrides=None):
        if kind == "status":
            return copy.deepcopy(self.status), digest
        if kind == "plan":
            pending = digest != self.status["activePackageDigest"]
            return {
                "ok": True, "command": "plan", "packageDigest": digest, "roleMode": "split",
                "activePackageDigest": self.status["activePackageDigest"], "pending": pending,
                "activation": "successor" if pending else "none",
            }, digest
        if kind == "apply-successor":
            self.assertEqual(len(self.status["ledger"]), 1)
            self.status.update(activePackageDigest=digest, activationId="successor-activation")
            self.status["ledger"].append({
                "activationId": "successor-activation", "packageDigest": digest,
                "predecessorPackageDigest": OTHER_DIGEST, "applyOrder": 2, "outcome": "applied",
            })
        else:
            self.assertEqual(kind, "doctor")
        return {"ok": True}, digest

    def helm(self, args, label, data=None, timeout=60):
        self.assertEqual(label, "Apply Helm release")
        values = json.loads(data)
        chart = Path(args[args.index("--install") + 2])
        chart_file = chart / "Chart.yaml" if chart.is_dir() else chart
        self.helm_inputs.append((chart_file.read_bytes(), values))
        if self.fail_helm:
            self.fail_helm = False
            if self.record_helm_before_failure:
                self.deployed = values
            raise OperationError("Interrupted before Helm completed")
        self.deployed = values
        return ""

    def interrupt(self):
        with self.assertRaisesRegex(OperationError, "Interrupted before Helm completed"):
            self.installation().apply()
        self.assertEqual(len(self.status["ledger"]), 2)

    def assert_changed_retry_refused(self, values=None):
        retry = self.installation(values)
        with self.assertRaisesRegex(OperationError, "original chart and values"):
            retry.apply()
        retry.job.assert_not_called()
        retry.stop.assert_not_called()
        self.assertEqual(len(self.helm_inputs), 1)

    def test_post_commit_retry_refuses_changed_image(self):
        self.interrupt()
        changed = copy.deepcopy(self.target)
        changed["appKit"]["image"]["digest"] = DIGEST
        self.assert_changed_retry_refused(changed)

    def test_post_commit_retry_refuses_changed_chart(self):
        self.interrupt()
        self.chart.write_bytes(b"different chart")
        self.assert_changed_retry_refused()

    def test_exact_retry_preserves_backup_checks_and_allows_a_later_application_upgrade(self):
        self.interrupt()
        receipt = self.args.backup_receipt.read_bytes()
        self.backup_receipt(OTHER_DIGEST, "previous-activation", namespace="wrong-target")
        with self.assertRaisesRegex(OperationError, "current installation and activation"):
            self.installation().apply()
        self.assertEqual(len(self.helm_inputs), 1)
        self.args.backup_receipt.write_bytes(receipt)
        reordered = dict(reversed(tuple(self.target.items())))
        self.assertEqual(self.installation(reordered).apply()["activationId"], "successor-activation")
        self.assertEqual(self.helm_inputs[0], self.helm_inputs[1])
        self.assertIsNone(self.record)

        changed = copy.deepcopy(self.target)
        changed["appKit"]["image"]["digest"] = DIGEST
        self.backup_receipt(DIGEST, "successor-activation")
        self.assertEqual(self.installation(changed).apply()["activationId"], "successor-activation")
        self.assertEqual(self.helm_inputs[-1][1]["appKit"]["image"]["digest"], DIGEST)
        self.assertEqual(len(self.status["ledger"]), 2)

    def test_retry_refuses_a_different_valid_predecessor_backup(self):
        self.interrupt()
        receipt = json.loads(self.args.backup_receipt.read_bytes())
        receipt["snapshotId"] = "e" * 64
        self.args.backup_receipt.write_text(json.dumps(receipt))
        retry = self.installation()
        with self.assertRaisesRegex(OperationError, "original backup receipt"):
            retry.apply()
        retry.stop.assert_not_called()
        self.assertEqual(len(self.helm_inputs), 1)

    def test_confirmed_checkpoint_removal_recovers_a_lost_delete_response(self):
        self.fail_helm = False
        upgrade = self.installation()

        def lost_response(command, *args, **kwargs):
            result = self.kubectl(command, *args, **kwargs)
            if command == "delete":
                raise OperationError("Kubernetes did not return the delete response")
            return result

        upgrade.kubectl.side_effect = lost_response
        self.assertEqual(upgrade.apply()["activationId"], "successor-activation")
        self.assertIsNone(self.record)
        self.assertEqual(len(self.helm_inputs), 1)

    def test_retry_after_helm_saved_successor_uses_original_predecessor(self):
        self.record_helm_before_failure = True
        self.interrupt()
        with self.assertRaisesRegex(OperationError, "Use upgrade"):
            self.installation(action="install").apply()
        self.assertEqual(self.installation().apply()["activationId"], "successor-activation")
        self.assertEqual(len(self.status["ledger"]), 2)
        self.assertEqual(self.helm_inputs[0], self.helm_inputs[1])

    def test_resume_skips_the_stop_when_helm_already_serves_the_committed_target(self):
        self.record_helm_before_failure = True
        self.interrupt()
        retry = self.installation()
        self.assertEqual(retry.apply()["activationId"], "successor-activation")
        retry.stop.assert_not_called()
        self.assertEqual(self.helm_inputs[0], self.helm_inputs[1])

    def test_resume_stops_while_helm_records_the_predecessor(self):
        self.interrupt()
        retry = self.installation()
        self.assertEqual(retry.apply()["activationId"], "successor-activation")
        retry.stop.assert_called_once_with()
        self.assertEqual(len(self.status["ledger"]), 2)

    def test_failed_checkpoint_creation_leaves_the_predecessor_intact(self):
        upgrade = self.installation()

        def unavailable(command, *args, **kwargs):
            if command == "create":
                raise OperationError("Upgrade checkpoint unavailable")
            return self.kubectl(command, *args, **kwargs)

        upgrade.kubectl.side_effect = unavailable
        with self.assertRaisesRegex(OperationError, "Upgrade checkpoint unavailable"):
            upgrade.apply()
        upgrade.stop.assert_not_called()
        self.assertEqual(len(self.status["ledger"]), 1)
        self.assertFalse(self.helm_inputs)

    def test_post_commit_retry_requires_a_recorded_target(self):
        self.interrupt()
        self.record = None
        retry = self.installation()
        with self.assertRaisesRegex(OperationError, "no recorded upgrade"):
            retry.apply()
        retry.stop.assert_not_called()
        self.assertEqual(len(self.helm_inputs), 1)

    def test_chart_directory_is_staged_before_the_migration(self):
        directory = self.chart.parent / "chart"
        directory.mkdir()
        chart_file = directory / "Chart.yaml"
        chart_file.write_bytes(b"reviewed chart")
        self.args.chart = directory
        upgrade = self.installation()

        def edit_source_after_commit(kind, digest, overrides=None):
            if kind == "apply-successor":
                self.assertTrue(self.record["immutable"])
                self.assertNotIn("appKit", self.record["data"])
                result = self.job(kind, digest, overrides)
                chart_file.write_bytes(b"edited after commit")
                return result
            return self.job(kind, digest, overrides)

        upgrade.job.side_effect = edit_source_after_commit
        with self.assertRaisesRegex(OperationError, "Interrupted before Helm completed"):
            upgrade.apply()
        self.assertEqual(self.helm_inputs[0][0], b"reviewed chart")
        self.assert_changed_retry_refused()


if __name__ == "__main__":
    unittest.main()
