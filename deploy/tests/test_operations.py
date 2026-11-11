"""State transition checks for the Kubernetes operator workflow."""

import copy
import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from stack_operator import (
    OperationError, activation_action, rendered_operation, require_install_retry, release_values,
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


if __name__ == "__main__":
    unittest.main()
