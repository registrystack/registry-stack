"""State transition checks for the Kubernetes operator workflow."""

import copy
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from stack_operator import (
    Installation, OperationError, activation_action, rendered_operation, require_install_retry, release_values,
    successor_job_values, verify_active, verify_backup_receipt,
)


DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64


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
