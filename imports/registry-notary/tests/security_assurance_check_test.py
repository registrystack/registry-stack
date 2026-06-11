# SPDX-License-Identifier: Apache-2.0
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


def load_module():
    path = Path(__file__).resolve().parents[1] / "scripts" / "check_security_assurance.py"
    spec = importlib.util.spec_from_file_location("check_security_assurance", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SecurityAssuranceCheckTest(unittest.TestCase):
    def setUp(self):
        self.module = load_module()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "security").mkdir()
        (self.root / "crates" / "registry-notary-server" / "src").mkdir(parents=True)
        (self.root / "crates" / "registry-notary-server" / "tests").mkdir(parents=True)
        (self.root / "crates" / "registry-notary-server" / "tests" / "standalone_http.rs").write_text("async fn scope_denied() {}\n")
        (self.root / "crates" / "registry-notary-server" / "src" / "api.rs").write_text(
            'use axum::{routing::get, Router};\n'
            'pub fn router<S>() -> Router<S> { Router::new().route("/x", get(handler)) }\n'
        )
        (self.root / "Dockerfile").write_text("FROM scratch\n")
        (self.root / "Dockerfile.openfn-sidecar").write_text("FROM scratch\n")
        (self.root / "openapi").mkdir()
        (self.root / "openapi" / "registry-notary.openapi.json").write_text(json.dumps({
            "openapi": "3.0.3",
            "paths": {"/x": {"get": {}}},
        }))
        self.old_root = self.module.ROOT
        self.old_security = self.module.SECURITY_DIR
        self.module.ROOT = self.root
        self.module.SECURITY_DIR = self.root / "security"

    def tearDown(self):
        self.module.ROOT = self.old_root
        self.module.SECURITY_DIR = self.old_security
        self.tmp.cleanup()

    def write_contracts(self, manifest_entry):
        (self.root / "security" / "route-inventory.json").write_text(json.dumps({
            "version": 1,
            "service": "registry-notary",
            "routes": [{
                "listener": "public",
                "path": "/x",
                "methods": ["GET"],
                "source": "crates/registry-notary-server/src/api.rs",
            }],
        }))
        (self.root / "security" / "auth-none-allowlist.yml").write_text("allowed:\n")
        (self.root / "security" / "exposure-manifest.json").write_text(json.dumps({
            "version": 1,
            "service": "registry-notary",
            "endpoints": [manifest_entry],
        }))

    def entry(self, **overrides):
        base = {
            "service": "registry-notary",
            "listener": "public",
            "method": "GET",
            "path": "/x",
            "feature": None,
            "audience": "external",
            "auth": "api_key_or_oidc",
            "scopes": ["evidence:metadata"],
            "rate_limit": None,
            "audit": "required",
            "openapi": True,
            "stability": "beta",
            "data_classification": "metadata",
            "notes": "test",
            "source": "manual",
            "enforcement_tests": [
                "crates/registry-notary-server/tests/standalone_http.rs::scope_denied"
            ],
            "waiver": None,
        }
        base.update(overrides)
        return base

    def test_valid_contract_passes(self):
        self.write_contracts(self.entry())
        self.module.validate_manifest()

    def test_posture_exposure_documents_admin_listener_boundary(self):
        manifest = json.loads(
            (Path(__file__).resolve().parents[1] / "security" / "exposure-manifest.json")
            .read_text()
        )
        posture = next(
            endpoint
            for endpoint in manifest["endpoints"]
            if endpoint["method"] == "GET" and endpoint["path"] == "/admin/v1/posture"
        )

        self.assertEqual(posture["listener"], "admin")
        self.assertEqual(posture["audience"], "operator")
        self.assertEqual(posture["scopes"], ["registry_notary:ops_read"])
        self.assertIn("dedicated admin mode", posture["notes"])
        self.assertIn("simple local shared mode", posture["notes"])

    def test_missing_route_manifest_entry_fails(self):
        self.write_contracts(self.entry(path="/other"))
        with self.assertRaises(SystemExit):
            self.module.validate_manifest()

    def test_auth_none_requires_allowlist(self):
        self.write_contracts(self.entry(auth="none", scopes=[], audit="optional", enforcement_tests=[]))
        with self.assertRaises(SystemExit):
            self.module.validate_manifest()

    def test_auth_none_allowlist_rejects_stale_entries(self):
        self.write_contracts(self.entry())
        (self.root / "security" / "auth-none-allowlist.yml").write_text(
            "allowed:\n"
            "  - listener: public\n"
            "    method: GET\n"
            "    path: /x\n"
            "    reason: stale\n"
        )
        with self.assertRaises(SystemExit):
            self.module.validate_manifest()

    def test_auth_none_allowlist_rejects_missing_required_fields(self):
        self.write_contracts(self.entry())
        (self.root / "security" / "auth-none-allowlist.yml").write_text(
            "allowed:\n"
            "  - listener: public\n"
            "    method: GET\n"
        )
        with self.assertRaises(SystemExit):
            self.module.load_allowlist(self.root / "security" / "auth-none-allowlist.yml")

    def test_source_route_missing_from_inventory_fails(self):
        self.write_contracts(self.entry())
        (self.root / "security" / "route-inventory.json").write_text(json.dumps({
            "version": 1,
            "service": "registry-notary",
            "routes": [],
        }))
        with self.assertRaises(SystemExit):
            self.module.validate_manifest()

    def test_stale_manifest_entry_fails(self):
        self.write_contracts(self.entry(path="/stale"))
        (self.root / "security" / "route-inventory.json").write_text(json.dumps({
            "version": 1,
            "service": "registry-notary",
            "routes": [],
        }))
        with self.assertRaises(SystemExit):
            self.module.validate_manifest()

    def test_enforcement_reference_requires_test_symbol(self):
        self.write_contracts(self.entry(enforcement_tests=[
            "crates/registry-notary-server/tests/standalone_http.rs"
        ]))
        with self.assertRaises(SystemExit):
            self.module.validate_manifest()

    def test_openapi_coverage_accepts_catch_all_parameter_shape(self):
        (self.root / "security" / "exposure-manifest.json").write_text(json.dumps({
            "version": 1,
            "service": "registry-notary",
            "endpoints": [
                self.entry(path="/credentials/{*vct_path}", method="GET", openapi=True)
            ],
        }))
        (self.root / "openapi" / "registry-notary.openapi.json").write_text(json.dumps({
            "openapi": "3.0.3",
            "paths": {"/credentials/{vct_path}": {"get": {}, "x-registry-notary-catch-all": True}},
        }))
        self.module.check_openapi_manifest_coverage(self.root / "openapi" / "registry-notary.openapi.json")

    def test_catch_all_inventory_route_without_extension_fails(self):
        """Route inventory has {*vct_path} but spec path item lacks x-registry-notary-catch-all."""
        (self.root / "security" / "exposure-manifest.json").write_text(json.dumps({
            "version": 1,
            "service": "registry-notary",
            "endpoints": [
                self.entry(path="/credentials/{*vct_path}", method="GET", openapi=True)
            ],
        }))
        (self.root / "openapi" / "registry-notary.openapi.json").write_text(json.dumps({
            "openapi": "3.0.3",
            "paths": {"/credentials/{vct_path}": {"get": {}}},
        }))
        with self.assertRaises(SystemExit):
            self.module.check_openapi_manifest_coverage(self.root / "openapi" / "registry-notary.openapi.json")

    def test_single_segment_inventory_route_with_extension_fails(self):
        """Route inventory has a plain {param} but spec path item has x-registry-notary-catch-all."""
        (self.root / "security" / "exposure-manifest.json").write_text(json.dumps({
            "version": 1,
            "service": "registry-notary",
            "endpoints": [
                self.entry(path="/v1/claims/{claim_id}", method="GET", openapi=True)
            ],
        }))
        (self.root / "openapi" / "registry-notary.openapi.json").write_text(json.dumps({
            "openapi": "3.0.3",
            "paths": {"/v1/claims/{claim_id}": {"get": {}, "x-registry-notary-catch-all": True}},
        }))
        with self.assertRaises(SystemExit):
            self.module.check_openapi_manifest_coverage(self.root / "openapi" / "registry-notary.openapi.json")

    def test_openapi_true_missing_operation_fails(self):
        self.write_contracts(self.entry(openapi=True))
        (self.root / "openapi" / "registry-notary.openapi.json").write_text(json.dumps({
            "openapi": "3.0.3",
            "paths": {},
        }))
        with self.assertRaises(SystemExit):
            self.module.check_openapi_manifest_coverage(self.root / "openapi" / "registry-notary.openapi.json")

    def test_openapi_paths_must_be_object(self):
        self.write_contracts(self.entry(openapi=True))
        (self.root / "openapi" / "registry-notary.openapi.json").write_text(json.dumps({
            "openapi": "3.0.3",
            "paths": [],
        }))
        with self.assertRaises(SystemExit):
            self.module.check_openapi_manifest_coverage(self.root / "openapi" / "registry-notary.openapi.json")

    def test_dockerfile_secret_check_covers_add_and_missing_files(self):
        (self.root / "Dockerfile").write_text("ADD private.pem /app/private.pem\n")
        with self.assertRaises(SystemExit):
            self.module.check_dockerfile_secret_patterns()
        (self.root / "Dockerfile").write_text("FROM scratch\n")
        (self.root / "Dockerfile.openfn-sidecar").unlink()
        with self.assertRaises(SystemExit):
            self.module.check_dockerfile_secret_patterns()

    def test_workflow_external_ref_check_rejects_spaced_mutable_platform_ref(self):
        workflow_dir = self.root / ".github" / "workflows"
        workflow_dir.mkdir(parents=True)
        (workflow_dir / "release.yml").write_text("env:\n  REGISTRY_PLATFORM_REF : main\n")

        with self.assertRaises(SystemExit):
            self.module.check_workflow_external_refs()

    def test_extracts_literal_const_format_and_chained_methods(self):
        source = '''
use axum::{routing::{get, post}, Router};
const BASE: &str = "/credentials";
pub fn router<S>() -> Router<S> {
    Router::new()
        .route("/literal", get(a).head(a_head))
        .route(BASE, get(b))
        .route(&format!("{BASE}/{{*vct_path}}"), get(c).post(d))
}

#[cfg(test)]
mod security_tests {
    fn helper() {
        Router::new().route("/test-only", get(test));
    }
}
'''
        self.assertEqual(
            self.module.extract_axum_routes(source),
            {
                ("/literal", "GET"),
                ("/literal", "HEAD"),
                ("/credentials", "GET"),
                ("/credentials/{*vct_path}", "GET"),
                ("/credentials/{*vct_path}", "POST"),
            },
        )


if __name__ == "__main__":
    unittest.main()
