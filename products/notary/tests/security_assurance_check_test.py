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
        (self.root / "openapi").mkdir()
        (self.root / "openapi" / "registry-notary.openapi.json").write_text(json.dumps({
            "openapi": "3.0.3",
            "paths": {"/x": {"get": {}}},
        }))
        self.old_root = self.module.ROOT
        self.old_monorepo_root = self.module.MONOREPO_ROOT
        self.old_security = self.module.SECURITY_DIR
        self.module.ROOT = self.root
        self.module.MONOREPO_ROOT = self.root
        self.module.SECURITY_DIR = self.root / "security"

    def tearDown(self):
        self.module.ROOT = self.old_root
        self.module.MONOREPO_ROOT = self.old_monorepo_root
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

    def test_dockerfile_secret_check_covers_add_and_missing_file(self):
        (self.root / "Dockerfile").write_text("ADD private.pem /app/private.pem\n")
        with self.assertRaises(SystemExit):
            self.module.check_dockerfile_secret_patterns()
        (self.root / "Dockerfile").unlink()
        with self.assertRaises(SystemExit):
            self.module.check_dockerfile_secret_patterns()

    def write_route_inventory(self):
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

    def test_route_sources_ignores_path_included_external_test_module(self):
        self.write_route_inventory()
        src = self.root / "crates" / "registry-notary-server" / "src"
        (src / "healthcheck.rs").write_text(
            "pub fn run() {}\n"
            "#[cfg(test)]\n"
            '#[path = "healthcheck/tests.rs"]\n'
            "mod tests;\n"
        )
        (src / "healthcheck").mkdir()
        (src / "healthcheck" / "tests.rs").write_text(
            'fn mock() { Router::new().route("/test-only", get(handler)); }\n'
        )

        self.module.validate_route_sources()

    def test_route_sources_ignores_nested_test_children(self):
        self.write_route_inventory()
        src = self.root / "crates" / "registry-notary-server" / "src"
        (src / "widget.rs").write_text("#[cfg(test)]\nmod tests;\n")
        (src / "widget" / "tests").mkdir(parents=True)
        (src / "widget" / "tests" / "mod.rs").write_text("mod admin;\n")
        (src / "widget" / "tests" / "admin.rs").write_text(
            'fn mock() { Router::new().route("/test-only", get(handler)); }\n'
        )

        self.module.validate_route_sources()

    def test_route_sources_ignores_transitive_include_shards(self):
        self.write_route_inventory()
        src = self.root / "crates" / "registry-notary-server" / "src"
        (src / "runtime.rs").write_text(
            "#[cfg(test)]\n"
            "mod tests {\n"
            '    include!("runtime/tests/first.inc");\n'
            "}\n"
        )
        (src / "runtime" / "tests").mkdir(parents=True)
        (src / "runtime" / "tests" / "first.inc").write_text(
            'include!("second.inc");\n'
        )
        (src / "runtime" / "tests" / "second.inc").write_text(
            'fn mock() { Router::new().route("/test-only", get(handler)); }\n'
        )

        self.module.validate_route_sources()

    def test_route_sources_retains_file_with_production_owner(self):
        self.write_route_inventory()
        src = self.root / "crates" / "registry-notary-server" / "src"
        (src / "owner.rs").write_text(
            "mod shared;\n"
            "#[cfg(test)]\n"
            '#[path = "owner/shared.rs"]\n'
            "mod shared_test;\n"
        )
        (src / "owner").mkdir()
        (src / "owner" / "shared.rs").write_text(
            'fn production() { Router::new().route("/production", get(handler)); }\n'
        )

        with self.assertRaises(SystemExit):
            self.module.validate_route_sources()

    def test_string_literal_cannot_spoof_test_only_ownership(self):
        self.write_route_inventory()
        src = self.root / "crates" / "registry-notary-server" / "src"
        (src / "spoof.rs").write_text(
            'const SPOOF: &str = "#[cfg(test)] mod hidden;";\n'
        )
        (src / "spoof" / "hidden.rs").parent.mkdir()
        (src / "spoof" / "hidden.rs").write_text(
            'fn production() { Router::new().route("/production", get(handler)); }\n'
        )

        with self.assertRaises(SystemExit):
            self.module.validate_route_sources()

    def test_inline_test_module_does_not_hide_later_production_route(self):
        self.write_route_inventory()
        src = self.root / "crates" / "registry-notary-server" / "src"
        (src / "mixed.rs").write_text(
            "#[cfg(test)]\n"
            "mod tests {\n"
            '    fn mock() { Router::new().route("/test-only", get(handler)); }\n'
            "}\n"
            'fn production() { Router::new().route("/production", get(handler)); }\n'
        )

        with self.assertRaises(SystemExit):
            self.module.validate_route_sources()

    def test_route_sources_fail_closed_on_unresolved_test_module(self):
        self.write_route_inventory()
        src = self.root / "crates" / "registry-notary-server" / "src"
        (src / "missing.rs").write_text("#[cfg(test)]\nmod absent;\n")

        with self.assertRaises(SystemExit):
            self.module.validate_route_sources()

    def test_route_sources_reject_path_escape(self):
        self.write_route_inventory()
        src = self.root / "crates" / "registry-notary-server" / "src"
        outside = self.root / "crates" / "outside.rs"
        outside.write_text("fn helper() {}\n")
        (src / "escape.rs").write_text(
            "#[cfg(test)]\n"
            '#[path = "../../outside.rs"]\n'
            "mod tests;\n"
        )

        with self.assertRaises(SystemExit):
            self.module.validate_route_sources()

    def test_route_sources_reject_symlinked_include(self):
        self.write_route_inventory()
        src = self.root / "crates" / "registry-notary-server" / "src"
        outside = self.root / "outside.inc"
        outside.write_text("fn helper() {}\n")
        (src / "linked.inc").symlink_to(outside)
        (src / "symlink.rs").write_text(
            "#[cfg(test)]\n"
            "mod tests {\n"
            '    include!("linked.inc");\n'
            "}\n"
        )

        with self.assertRaises(SystemExit):
            self.module.validate_route_sources()

    def test_route_sources_bounds_test_module_recursion(self):
        self.write_route_inventory()
        src = self.root / "crates" / "registry-notary-server" / "src"
        (src / "bounded.rs").write_text("#[cfg(test)]\nmod tests;\n")
        (src / "bounded" / "tests").mkdir(parents=True)
        (src / "bounded" / "tests" / "mod.rs").write_text("mod child;\n")
        (src / "bounded" / "tests" / "child.rs").write_text("fn helper() {}\n")
        old_depth = self.module.MAX_MODULE_DEPTH
        self.module.MAX_MODULE_DEPTH = 1
        try:
            with self.assertRaises(SystemExit):
                self.module.validate_route_sources()
        finally:
            self.module.MAX_MODULE_DEPTH = old_depth

    def test_cfg_ownership_requires_test_on_every_enabled_branch(self):
        self.assertTrue(self.module.cfg_requires_test("test"))
        self.assertTrue(self.module.cfg_requires_test("all(test, unix)"))
        self.assertTrue(self.module.cfg_requires_test("any(test, all(test, unix))"))
        self.assertFalse(self.module.cfg_requires_test('any(test, feature = "dev")'))
        self.assertFalse(self.module.cfg_requires_test("not(test)"))

    def assert_inert_route_is_ignored(self, inert_source):
        source = (
            f"{inert_source}\n"
            "fn executable_router() {\n"
            '    Router::new().route("/executable", get(handler));\n'
            "}\n"
        )
        self.assertEqual(
            self.module.extract_axum_routes(source), {("/executable", "GET")}
        )

    def test_route_extraction_ignores_raw_string_text(self):
        self.assert_inert_route_is_ignored(
            'const DOC: &str = r#"Router::new().route("/raw", get(handler))"#;'
        )

    def test_route_extraction_ignores_seventeen_hash_raw_string(self):
        hashes = "#" * 17
        self.assert_inert_route_is_ignored(
            f'const DOC: &str = r{hashes}"'
            'Router::new().route("/raw-17", get(handler))'
            f'"{hashes};'
        )

    def test_route_extraction_ignores_large_hash_raw_string(self):
        hashes = "#" * 257
        self.assert_inert_route_is_ignored(
            f'const DOC: &str = r{hashes}"'
            'Router::new().route("/raw-large", get(handler))'
            f'"{hashes};'
        )

    def test_route_extraction_ignores_unterminated_large_hash_raw_string(self):
        hashes = "#" * 257
        source = (
            "fn executable_router() {\n"
            '    Router::new().route("/executable", get(handler));\n'
            "}\n"
            f'const DOC: &str = r{hashes}"'
            'Router::new().route("/unterminated", post(handler));'
        )
        self.assertEqual(
            self.module.extract_axum_routes(source), {("/executable", "GET")}
        )

    def test_route_extraction_ignores_ordinary_string_text(self):
        self.assert_inert_route_is_ignored(
            'const DOC: &str = "Router::new().route(\\"/ordinary\\", get(handler))";'
        )

    def test_route_extraction_ignores_block_comment_text(self):
        self.assert_inert_route_is_ignored(
            '/* Router::new().route("/block-comment", get(handler)); */'
        )

    def test_route_extraction_ignores_standalone_line_comment_text(self):
        self.assert_inert_route_is_ignored(
            '// Router::new().route("/line-comment", get(handler));'
        )

    def test_route_extraction_ignores_trailing_inline_comment_text(self):
        self.assert_inert_route_is_ignored(
            "fn documented_router() {\n"
            "    let _router = Router::new(); "
            '// .route("/trailing-comment", get(handler))\n'
            "}"
        )

    def test_route_extraction_ignores_method_names_inside_strings(self):
        source = '''
fn router() {
    Router::new()
        .route("/post", post(handler).layer(Extension("get(")))
        .route("/get", get(handler).layer(Extension("post(")));
}
'''
        self.assertEqual(
            self.module.extract_axum_routes(source),
            {("/post", "POST"), ("/get", "GET")},
        )

    def test_route_masking_large_input_does_not_match_allocated_suffixes(self):
        hashes = "#" * 257
        source = (
            ("fn filler() {}\n" * 20_000)
            + f'const DOC: &str = r{hashes}"'
            + 'Router::new().route("/inert", get(handler))'
            + f'"{hashes};\n'
            + "fn executable_router() {\n"
            + '    Router::new().route("/executable", post(handler));\n'
            + "}\n"
        )
        original_match = self.module.re.match
        self.module.re.match = lambda *_args, **_kwargs: self.fail(
            "mask_rust must not regex-match allocated source suffixes"
        )
        try:
            self.assertEqual(
                self.module.extract_axum_routes(source), {("/executable", "POST")}
            )
        finally:
            self.module.re.match = original_match

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

    def test_route_source_scan_ignores_test_only_router_modules(self):
        self.write_contracts(self.entry())
        (
            self.root
            / "crates"
            / "registry-notary-server"
            / "src"
            / "relay_client.rs"
        ).write_text("#[cfg(test)]\nmod tests;\n")
        test_module = (
            self.root
            / "crates"
            / "registry-notary-server"
            / "src"
            / "relay_client"
            / "tests.rs"
        )
        test_module.parent.mkdir(parents=True)
        test_module.write_text(
            'use axum::{routing::post, Router};\n'
            'fn fake_upstream() -> Router { '
            'Router::new().route("/relay-only", post(handler)) }\n'
        )

        self.module.validate_route_sources()


if __name__ == "__main__":
    unittest.main()
