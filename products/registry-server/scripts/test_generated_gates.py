#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


sys.dont_write_bytecode = True
SCRIPT_DIR = Path(__file__).parent
COMPARATOR_PATH = SCRIPT_DIR / "compare-generated-tree.py"
SPEC = importlib.util.spec_from_file_location("registry_server_generated_tree", COMPARATOR_PATH)
assert SPEC is not None and SPEC.loader is not None
COMPARATOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = COMPARATOR
SPEC.loader.exec_module(COMPARATOR)


class GeneratedGateTests(unittest.TestCase):
    def test_comparator_rejects_a_missing_committed_artifact(self) -> None:
        baseline = SCRIPT_DIR.parent / "generated/asset-site-placement"
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "candidate"
            shutil.copytree(baseline, candidate)
            (candidate / COMPARATOR.EXPECTED_PATHS[-1]).unlink()
            errors = COMPARATOR.compare(baseline, candidate)
        self.assertTrue(any("candidate is missing expected artifacts" in error for error in errors), errors)

    def test_generated_gate_script_keeps_a_bounded_database_free_cli_journey(self) -> None:
        generated_gate = (SCRIPT_DIR / "check-generated.sh").read_text(encoding="utf-8")
        self.assertIn("mktemp -d", generated_gate)
        self.assertIn("publicschema-household", generated_gate)
        self.assertIn('export RUSTC_WRAPPER="${RUSTC_WRAPPER-}"', generated_gate)
        self.assertIn("authoring_baseline", generated_gate)
        self.assertIn("--features schema --example authoring-schema", generated_gate)
        self.assertIn("products/registry-server/generated/authoring", generated_gate)
        for selector in ("openapi", "schemas", "manifest", "metadata", "sql"):
            self.assertIn(selector, generated_gate)
        self.assertNotIn(" apply ", generated_gate)
        self.assertNotIn(" serve ", generated_gate)
        self.assertNotIn("REGISTRY_SERVER_TEST_DATABASE_URL", generated_gate)
        self.assertIn("compare-generated-tree.py", generated_gate)

    def test_adopter_workflow_uses_public_binaries_database_and_recovery(self) -> None:
        adopter_gate = (SCRIPT_DIR / "test-adopter-workflow.sh").read_text(encoding="utf-8")
        self.assertIn("mktemp -d", adopter_gate)
        self.assertIn('export RUSTC_WRAPPER="${RUSTC_WRAPPER-}"', adopter_gate)
        self.assertIn('registry_serverctl="$repository_root/target/debug/registry-serverctl"', adopter_gate)
        self.assertIn('registry_server="$repository_root/target/debug/registry-server"', adopter_gate)
        self.assertIn('cargo build --manifest-path "$repository_root/Cargo.toml" --locked', adopter_gate)
        self.assertIn("-p registry-serverctl", adopter_gate)
        self.assertIn("-p registry-server", adopter_gate)
        self.assertIn("server_hash_before", adopter_gate)
        self.assertIn("server_hash_after", adopter_gate)
        self.assertNotIn("cargo run", adopter_gate)
        self.assertNotIn("--signing-key", adopter_gate)

        for marker in (
            "REGISTRY_SERVER_TEST_DATABASE_URL",
            "CREATE ROLE",
            "CREATE DATABASE",
            "adopter_schema_test_v1_database",
            "adopter_schema_test_v2_database",
            "adopter_production_database",
            "derive_admin_database_url",
            "secret:file/schema-test-v1-runtime-url",
            "secret:file/schema-test-v1-migration-url",
            "secret:file/schema-test-v2-runtime-url",
            "secret:file/schema-test-v2-migration-url",
            "secret:file/production-runtime-url",
            "secret:file/production-migration-url",
            "REGISTRY_SERVER_TEST_TLS_CA_PEM_PATH",
            'export SSL_CERT_FILE="$adopter_tls_ca_pem_path"',
            "umask 077",
            "maxTokenLifetimeSeconds: 3600",
            '"exp": now + 3600',
            "jwksSource:",
            "kind: static",
            "documentRef: secret:file/oidc-jwks",
            "write_jwt",
            "--production",
            "compare-generated-tree.py",
            "schemaFingerprint",
            "signing-input.json",
            "--signatures",
            "missing-migration-url",
            "apply.database_configuration.refused",
            "author refusal changed the production database state",
            "apply --runtime-config",
            '"$registry_server" --config',
            "data validate",
            "data import",
            "entity_list_path",
            "http_get_json",
            "authorized public data read",
            "field_added_optional",
            "compatible_additive",
            "LOCK TABLE",
            "pg_terminate_backend",
            "apply.migration.failed",
            "maintenance_status",
            "maintenance_target_revision",
            "restricted successor field was disclosed",
        ):
            self.assertIn(marker, adopter_gate)
        self.assertNotIn('"psql", admin, "-d", database', adopter_gate)
        self.assertNotIn('"scope": "registry:records"', adopter_gate)

    def test_postgres_tls_script_hands_off_public_ca_material_without_retaining_keys(self) -> None:
        tls_gate = (SCRIPT_DIR / "test-postgres-tls.sh").read_text(encoding="utf-8")
        self.assertIn("validate_caller_output_path", tls_gate)
        self.assertIn("REGISTRY_SERVER_TEST_TLS_CA_DER_PATH", tls_gate)
        self.assertIn("REGISTRY_SERVER_TEST_TLS_CA_PEM_PATH", tls_gate)
        self.assertIn("trusted-ca.der", tls_gate)
        self.assertIn("trusted-ca.pem", tls_gate)
        self.assertIn("wrong-ca.der", tls_gate)
        self.assertIn('mktemp "$(dirname -- "$caller_ca_pem_path")/.registry-server-postgres-ca-pem.XXXXXX"', tls_gate)
        self.assertIn('pg_isready -q -d "$database_url"', tls_gate)
        self.assertIn('pg_ctl -D "$postgres_data_directory" reload', tls_gate)
        self.assertIn('rm -rf -- "$tls_dir"', tls_gate)
        self.assertIn('chmod 600 "$tls_dir"/*.key', tls_gate)
        self.assertNotIn("trusted-ca.key\" \"$caller", tls_gate)

    def test_comparator_rejects_a_symbolic_link_without_reading_its_target(self) -> None:
        if os.name == "nt":
            self.skipTest("symbolic-link setup is not portable on Windows")
        baseline = SCRIPT_DIR.parent / "generated/asset-site-placement"
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "candidate"
            shutil.copytree(baseline, candidate)
            target = candidate / COMPARATOR.EXPECTED_PATHS[0]
            target.unlink()
            target.symlink_to("/not/a-generated-artifact")
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                COMPARATOR.compare(baseline, candidate)


if __name__ == "__main__":
    unittest.main()
