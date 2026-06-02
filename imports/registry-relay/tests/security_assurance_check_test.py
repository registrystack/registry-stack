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
        (self.root / "src" / "api").mkdir(parents=True)
        (self.root / "tests").mkdir()
        (self.root / "tests" / "auth_flow.rs").write_text("scope_denied\n")
        (self.root / "tests" / "auth_flow.rs").write_text("async fn scope_denied() {}\n")
        (self.root / "src" / "api" / "foo.rs").write_text(
            'use axum::{routing::get, Router};\n'
            'pub fn router<S>() -> Router<S> { Router::new().route("/x", get(handler)) }\n'
        )
        (self.root / "Dockerfile").write_text("FROM scratch\n")
        (self.root / "Dockerfile.demo").write_text("FROM scratch\n")
        (self.root / "docs").mkdir()
        (self.root / "docs" / "security-assurance.md").write_text(
            "OpenAPI comparison strategy baseline-vs-baseline generated-vs-curated\n"
        )
        (self.root / "openapi").mkdir()
        (self.root / "openapi" / "registry-relay.openapi.json").write_text(json.dumps({
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
            "service": "registry-relay",
            "routes": [{
                "listener": "public",
                "path": "/x",
                "methods": ["GET"],
                "source": "src/api/foo.rs",
            }],
        }))
        (self.root / "security" / "auth-none-allowlist.yml").write_text("allowed:\n")
        (self.root / "security" / "exposure-manifest.json").write_text(json.dumps({
            "version": 1,
            "service": "registry-relay",
            "endpoints": [manifest_entry],
        }))

    def entry(self, **overrides):
        base = {
            "service": "registry-relay",
            "listener": "public",
            "method": "GET",
            "path": "/x",
            "feature": None,
            "audience": "external",
            "auth": "api_key_or_oidc",
            "scopes": ["configured"],
            "rate_limit": None,
            "audit": "required",
            "openapi": True,
            "stability": "stable",
            "data_classification": "metadata",
            "notes": "test",
            "source": "manual",
            "enforcement_tests": ["tests/auth_flow.rs::scope_denied"],
            "waiver": None,
        }
        base.update(overrides)
        return base

    def test_valid_contract_passes(self):
        self.write_contracts(self.entry())
        self.module.validate_manifest()

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
            "service": "registry-relay",
            "routes": [],
        }))
        with self.assertRaises(SystemExit):
            self.module.validate_manifest()

    def test_stale_manifest_entry_fails(self):
        self.write_contracts(self.entry(path="/stale"))
        (self.root / "security" / "route-inventory.json").write_text(json.dumps({
            "version": 1,
            "service": "registry-relay",
            "routes": [],
        }))
        with self.assertRaises(SystemExit):
            self.module.validate_manifest()

    def test_enforcement_reference_requires_test_symbol(self):
        self.write_contracts(self.entry(enforcement_tests=["tests/auth_flow.rs"]))
        with self.assertRaises(SystemExit):
            self.module.validate_manifest()

    def test_openapi_coverage_accepts_different_parameter_names(self):
        (self.root / "security" / "exposure-manifest.json").write_text(json.dumps({
            "version": 1,
            "service": "registry-relay",
            "endpoints": [self.entry(path="/v1/items/{item_id}", method="GET", openapi=True)],
        }))
        (self.root / "openapi" / "registry-relay.openapi.json").write_text(json.dumps({
            "openapi": "3.0.3",
            "paths": {"/v1/items/{id}": {"get": {}}},
        }))
        self.module.check_openapi_manifest_coverage(self.root / "openapi" / "registry-relay.openapi.json")

    def test_openapi_true_missing_operation_fails(self):
        self.write_contracts(self.entry(openapi=True))
        (self.root / "openapi" / "registry-relay.openapi.json").write_text(json.dumps({
            "openapi": "3.0.3",
            "paths": {},
        }))
        with self.assertRaises(SystemExit):
            self.module.check_openapi_manifest_coverage(self.root / "openapi" / "registry-relay.openapi.json")

    def test_openapi_paths_must_be_object(self):
        self.write_contracts(self.entry(openapi=True))
        (self.root / "openapi" / "registry-relay.openapi.json").write_text(json.dumps({
            "openapi": "3.0.3",
            "paths": [],
        }))
        with self.assertRaises(SystemExit):
            self.module.check_openapi_manifest_coverage(self.root / "openapi" / "registry-relay.openapi.json")

    def test_dockerfile_secret_check_covers_add_and_missing_files(self):
        (self.root / "Dockerfile").write_text("ADD private.pem /app/private.pem\n")
        with self.assertRaises(SystemExit):
            self.module.check_dockerfile_secret_patterns()
        (self.root / "Dockerfile").write_text("FROM scratch\n")
        (self.root / "Dockerfile.demo").unlink()
        with self.assertRaises(SystemExit):
            self.module.check_dockerfile_secret_patterns()

    def test_extracts_literal_const_format_and_chained_methods(self):
        source = '''
use axum::{routing::{get, post}, Router};
const BASE: &str = "/ogc/v1/records";
pub fn router<S>() -> Router<S> {
    Router::new()
        .route("/literal", get(a).head(a_head))
        .route(BASE, get(b))
        .route(&format!("{BASE}/collections/{{collection_id}}/items"), get(c).post(d))
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
                ("/ogc/v1/records", "GET"),
                ("/ogc/v1/records/collections/{collection_id}/items", "GET"),
                ("/ogc/v1/records/collections/{collection_id}/items", "POST"),
            },
        )


if __name__ == "__main__":
    unittest.main()
