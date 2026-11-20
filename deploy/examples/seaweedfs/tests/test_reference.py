from __future__ import annotations

import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
IMAGE = (
    "chrislusf/seaweedfs@"
    "sha256:ccad23e18639c8b98cee17e7100b95830a06077b56d8e5b006d6dcf8ec5e94a0"
)
BUCKET = "registry-breg-attachments"


class SeaweedFSReferenceTests(unittest.TestCase):
    def test_upstream_chart_and_image_are_exactly_pinned(self) -> None:
        lock = json.loads((ROOT / "chart-lock.json").read_text())
        self.assertEqual(lock["schema"], "registry.seaweedfs-chart-lock/v1")
        self.assertEqual(lock["chart"]["version"], "4.53.0")
        self.assertEqual(
            lock["chart"]["contentDigest"],
            "sha256:778f079cfbdf026a1a523569d385816d00df51ac049b1383db0cfaf6a094656c",
        )
        self.assertEqual(lock["image"]["reference"], "chrislusf/seaweedfs")
        self.assertEqual(
            lock["image"]["digest"],
            "sha256:ccad23e18639c8b98cee17e7100b95830a06077b56d8e5b006d6dcf8ec5e94a0",
        )
        self.assertEqual(
            lock["source"]["commit"],
            "4ab66fb76da83700739f5839e62fcaf15fb7d02a",
        )

    def test_values_keep_the_profile_small_persistent_and_digest_pinned(self) -> None:
        values = (ROOT / "values.reference.yaml").read_text()
        self.assertEqual(values.count(f'imageOverride: "{IMAGE}"'), 4)
        self.assertIn("createClusterRole: false", values)
        self.assertIn("automountServiceAccountToken: false", values)
        self.assertIn("filerWrite: true", values)
        self.assertEqual(values.count('type: "persistentVolumeClaim"'), 3)
        self.assertIn("resizeHook:\n    enabled: false", values)
        self.assertIn("admin:\n  enabled: false", values)
        self.assertIn("worker:\n  enabled: false", values)
        self.assertIn("cosi:\n  enabled: false", values)
        self.assertIn("allInOne:\n  enabled: false", values)
        self.assertIn("lancePort: 0", values)
        self.assertNotIn("metricsPort: 0", values)
        self.assertEqual(values.count("metricsPort: 9327"), 4)
        self.assertIn("existingConfigSecret: registry-seaweedfs-s3-config", values)
        self.assertIn("name: registry-breg-s3", values)
        self.assertIn("networkPolicy:\n  enabled: true", values)
        self.assertNotIn("extraIngress:", values)
        self.assertNotIn(".svc.cluster.local", values)
        self.assertIn("type: ClusterIP", values)
        self.assertNotIn("accessKey:", values)
        self.assertNotIn("secretKey:", values)

    def test_application_identity_is_bucket_scoped_without_admin_power(self) -> None:
        manifest = (ROOT / "s3-config-secret.yaml").read_text()
        self.assertIn('"name": "registry-breg"', manifest)
        self.assertIn('"accessKey": "${BREG_S3_ACCESS_KEY_ID}"', manifest)
        self.assertIn(
            '"secretKey": "${BREG_S3_SECRET_ACCESS_KEY}"', manifest
        )
        self.assertIn(f'"Read:{BUCKET}"', manifest)
        self.assertIn(f'"Write:{BUCKET}"', manifest)
        for forbidden in ("Admin", "List", "Tagging", "DeleteBucket"):
            self.assertNotIn(f'"{forbidden}', manifest)

    def test_breg_binding_matches_the_v046_attachment_contract(self) -> None:
        snippet = (ROOT / "breg-attachment-storage.tls.yaml").read_text()
        for field in (
            "attachmentStorage:\n  type: s3",
            f"bucket: {BUCKET}",
            "region: us-east-1",
            "accessKeyIdRef: secret:file/s3-access-key-id",
            "secretAccessKeyRef: secret:file/s3-secret-access-key",
            "attemptTimeoutMilliseconds: 10000",
            "https://storage.registry.example.org",
            "caBundleRef: secret:file/s3-ca.pem",
        ):
            self.assertIn(field, snippet)
        self.assertNotIn("http://", snippet)

    def test_local_qualification_uses_the_real_pinned_server_and_sigv4(self) -> None:
        script = (ROOT / "qualify-s3.sh").read_text()
        self.assertTrue(script.startswith("#!/usr/bin/env bash\nset -euo pipefail\n"))
        self.assertIn(IMAGE, script)
        self.assertIn('--aws-sigv4 "aws:amz:us-east-1:s3"', script)
        self.assertIn(f'"Read:{BUCKET}"', script)
        self.assertIn(f'"Write:{BUCKET}"', script)
        self.assertIn("expected the bucket-scoped identity to refuse", script)
        self.assertIn("?versioning", script)
        self.assertIn("OBJECTSTORE_TEST_S3_URL", script)
        self.assertIn("registry-platform-objectstore --lib s3 -- --include-ignored", script)
        self.assertIn("attachment_storage -- --include-ignored", script)
        self.assertNotIn("set -x", script)
        self.assertNotIn("rm -rf", script)

    def test_local_qualification_needs_no_ripgrep_and_fails_when_a_check_cannot_run(self) -> None:
        script = (ROOT / "qualify-s3.sh").read_text()
        self.assertNotRegex(script, r"\brg\b")
        self.assertIn("command -v grep", script)
        self.assertIn("Could not check the versioning response", script)

    def test_runbook_names_no_lab_tooling_and_states_single_server_backup(self) -> None:
        runbook = (ROOT / "README.md").read_text()
        self.assertNotIn("OrbStack", runbook)
        self.assertNotIn("example.gov", runbook)
        self.assertIn("no CSI snapshot class", runbook)
        self.assertIn("Back up the bucket and its objects only", runbook)
        self.assertIn("/usr/local/lib/registry-stack/helm", runbook)
        for line in runbook.splitlines():
            self.assertFalse(line.startswith(("helm ", "kubectl ")), line)

    def test_runbook_separates_bootstrap_runtime_tls_and_recovery(self) -> None:
        runbook = (ROOT / "README.md").read_text()
        for phrase in (
            "short-lived bootstrap identity",
            "Read:registry-breg-attachments",
            "Write:registry-breg-attachments",
            "delete the bootstrap Secret",
            "TLS terminates",
            "caBundleRef",
            "versioning must remain disabled",
            "clean namespace",
            "master PVC",
            "filer PVC",
            "volume PVC",
            "products/breg/scripts/test-attachment-s3.sh",
            "778f079cfbdf026a1a523569d385816d00df51ac049b1383db0cfaf6a094656c",
        ):
            self.assertIn(phrase, runbook)
        self.assertRegex(runbook, r"without\s+a trailing newline")
        for phrase in (
            "one supported BReg binding",
            "DNS:storage.registry.example.org",
            "same exact `attachmentStorage.url`",
            "same exact `region`",
            "databaseId",
            "registryId",
            "openssl verify -CAfile",
            "-verify_hostname storage.registry.example.org",
        ):
            self.assertIn(phrase, runbook)
        self.assertRegex(
            runbook,
            r"namespace or backend may\s+change behind that stable HTTPS identity",
        )
        self.assertNotIn("breg-attachment-storage.cluster-local.yaml", runbook)
        self.assertEqual(runbook.count("breg-attachment-storage.tls.yaml"), 1)
        self.assertNotIn("--set s3.credentials", runbook)


if __name__ == "__main__":
    unittest.main()
