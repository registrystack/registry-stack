#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "products" / "platform" / "scripts" / "check-no-cross-origin.sh"

CLEAN_SOURCE = "pub fn serve() {}\n"
CLEAN_MANIFEST = (
    '[package]\nname = "sample"\n\n[dependencies]\n'
    'tower-http = { version = "0.7", features = ["limit", "trace"] }\n'
)


def run(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(SCRIPT), str(root)],
        check=False,
        capture_output=True,
        text=True,
    )


class CheckNoCrossOrigin(unittest.TestCase):
    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.root = Path(self._directory.name)
        self.write("crates/sample/src/lib.rs", CLEAN_SOURCE)
        self.write("crates/sample/Cargo.toml", CLEAN_MANIFEST)
        self.write("Cargo.toml", CLEAN_MANIFEST)

    def write(self, relative: str, content: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def assert_refused(self, name: str) -> None:
        result = run(self.root)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(name, result.stdout)

    def test_clean_tree_passes(self) -> None:
        result = run(self.root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ok", result.stdout)

    def test_missing_crates_directory_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as empty:
            result = run(Path(empty))
        self.assertEqual(result.returncode, 2)

    def test_planted_cors_layer_fails(self) -> None:
        self.write(
            "crates/sample/src/server.rs",
            "use tower_http::cors::CorsLayer;\nfn layer() -> CorsLayer { CorsLayer::new() }\n",
        )
        self.assert_refused("crates/sample/src/server.rs")

    def test_planted_allow_origin_header_fails_in_any_case(self) -> None:
        self.write(
            "crates/sample/src/headers.rs",
            'const H: &str = "access-control-allow-origin";\n',
        )
        self.assert_refused("crates/sample/src/headers.rs")

    def test_planted_cors_feature_inline_fails(self) -> None:
        self.write(
            "crates/sample/Cargo.toml",
            '[dependencies]\ntower-http = { version = "0.7", features = ["cors"] }\n',
        )
        self.assert_refused("crates/sample/Cargo.toml")

    def test_planted_cors_feature_across_lines_fails(self) -> None:
        self.write(
            "Cargo.toml",
            '[workspace.dependencies]\ntower-http = { version = "0.7", features = [\n'
            '  "limit",\n  "cors",\n] }\nserde = "1"\n',
        )
        self.assert_refused("Cargo.toml")

    def test_planted_cors_feature_in_dependency_table_fails(self) -> None:
        self.write(
            "crates/sample/Cargo.toml",
            '[dependencies.tower-http]\nversion = "0.7"\nfeatures = ["cors"]\n',
        )
        self.assert_refused("crates/sample/Cargo.toml")

    def test_cors_feature_of_another_dependency_is_not_flagged(self) -> None:
        self.write(
            "crates/sample/Cargo.toml",
            '[dependencies]\ntower-http = "0.7"\nother = { version = "1", features = ["cors"] }\n',
        )
        result = run(self.root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_test_code_is_exempt(self) -> None:
        planted = "use tower_http::cors::CorsLayer;\n"
        self.write("crates/sample/tests/cors.rs", planted)
        self.write("crates/sample/src/server_tests.rs", planted)
        self.write("crates/sample/src/tests.rs", planted)
        self.write(
            "crates/sample/src/lib.rs",
            CLEAN_SOURCE + "#[cfg(test)]\nmod tests {\n    use tower_http::cors::CorsLayer;\n}\n",
        )
        result = run(self.root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_production_code_before_a_test_module_is_still_checked(self) -> None:
        self.write(
            "crates/sample/src/lib.rs",
            "use tower_http::cors::CorsLayer;\n#[cfg(test)]\nmod tests {}\n",
        )
        self.assert_refused("crates/sample/src/lib.rs")

    # The one allowlisted CORS site, and the two places that only name the header.

    EVIDENCE_SERVER = "crates/registry-evidence/src/server.rs"
    PUBLIC_CHECK_CORS = (
        "use tower_http::cors::{Any, CorsLayer};\n"
        "fn mount(router: Router) -> Router {\n"
        "    router.layer(public_check_cors())\n"
        "}\n"
        "fn public_check_cors() -> CorsLayer {\n"
        "    CorsLayer::new()\n"
        "        .allow_origin(Any)\n"
        "        .allow_headers([CONTENT_TYPE, HeaderName::from_static(\"registry-client\")])\n"
        "}\n"
    )

    def test_the_public_check_cors_function_is_allowed(self) -> None:
        self.write(self.EVIDENCE_SERVER, self.PUBLIC_CHECK_CORS)
        result = run(self.root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_a_third_allowed_header_on_the_public_check_fails(self) -> None:
        pair = 'CONTENT_TYPE, HeaderName::from_static("registry-client")'
        for list_ in (
            pair + ", AUTHORIZATION",
            pair + ', HeaderName::from_static("x-other")',
            "CONTENT_TYPE",
        ):
            self.write(
                self.EVIDENCE_SERVER,
                self.PUBLIC_CHECK_CORS.replace(pair, list_),
            )
            result = run(self.root)
            self.assertEqual(result.returncode, 1, list_ + result.stdout + result.stderr)
            self.assertIn("exactly Content-Type and Registry-Client", result.stdout)

    def test_the_exact_pair_passes_however_it_is_formatted(self) -> None:
        self.write(
            self.EVIDENCE_SERVER,
            self.PUBLIC_CHECK_CORS.replace(
                '[CONTENT_TYPE, HeaderName::from_static("registry-client")]',
                '[\n            CONTENT_TYPE,\n            HeaderName::from_static("registry-client"),\n        ]',
            ),
        )
        result = run(self.root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_a_public_check_without_an_allowed_header_list_fails(self) -> None:
        self.write(
            self.EVIDENCE_SERVER,
            "fn public_check_cors() -> CorsLayer {\n    CorsLayer::new().allow_origin(Any)\n}\n",
        )
        self.assert_refused(self.EVIDENCE_SERVER)

    def test_widening_the_layer_at_its_call_site_fails(self) -> None:
        mount = "    router.layer(public_check_cors())\n"
        for call in (
            ".allow_headers(Any)",
            ".allow_origin(AllowOrigin::mirror_request()).expose_headers(Any)",
            ".allow_methods(Any)",
            ".allow_private_network(true)",
        ):
            with self.subTest(call=call):
                self.write(
                    self.EVIDENCE_SERVER,
                    self.PUBLIC_CHECK_CORS.replace(
                        mount, mount.replace("())", "()" + call + ")")
                    ),
                )
                result = run(self.root)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn(":3:", result.stdout)

    def test_a_second_cfg_gated_public_check_function_fails(self) -> None:
        self.write(
            self.EVIDENCE_SERVER,
            self.PUBLIC_CHECK_CORS
            + "#[cfg(feature = \"wide\")]\n"
            + "fn public_check_cors() -> CorsLayer {\n"
            + "    CorsLayer::new().allow_headers(Any)\n}\n",
        )
        result = run(self.root)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("exactly one fn public_check_cors", result.stdout)

    def test_a_very_permissive_layer_fails_even_with_the_pinned_headers(self) -> None:
        for constructor in ("very_permissive", "permissive"):
            with self.subTest(constructor=constructor):
                self.write(
                    self.EVIDENCE_SERVER,
                    self.PUBLIC_CHECK_CORS.replace(
                        "CorsLayer::new()", f"CorsLayer::{constructor}()"
                    ),
                )
                result = run(self.root)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn(":6:", result.stdout)

    def test_a_second_allowed_header_call_fails_when_the_last_is_the_pair(self) -> None:
        self.write(
            self.EVIDENCE_SERVER,
            self.PUBLIC_CHECK_CORS.replace(
                "        .allow_headers(",
                "        .allow_headers(Any)\n        .allow_headers(",
            ),
        )
        result = run(self.root)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("exactly Content-Type and Registry-Client", result.stdout)

    def test_a_second_cors_layer_in_the_same_file_fails(self) -> None:
        self.write(
            self.EVIDENCE_SERVER,
            self.PUBLIC_CHECK_CORS
            + "fn another() -> CorsLayer {\n    CorsLayer::new()\n}\n",
        )
        result = run(self.root)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(":10:", result.stdout)
        self.assertNotIn(":7:", result.stdout)

    def test_a_cors_layer_after_the_allowed_function_outside_any_function_fails(
        self,
    ) -> None:
        self.write(
            self.EVIDENCE_SERVER,
            self.PUBLIC_CHECK_CORS + "static LAYER: Option<CorsLayer> = None;\n",
        )
        self.assert_refused(self.EVIDENCE_SERVER)

    def test_the_allowed_function_name_in_another_file_fails(self) -> None:
        self.write("crates/sample/src/server.rs", self.PUBLIC_CHECK_CORS)
        self.assert_refused("crates/sample/src/server.rs")

    def test_a_cors_policy_type_fails(self) -> None:
        self.write(
            "crates/sample/src/policy.rs",
            "pub struct CorsPolicy { pub origins: Vec<String> }\n",
        )
        self.assert_refused("crates/sample/src/policy.rs")

    def test_the_allow_origin_header_constant_fails(self) -> None:
        self.write(
            "crates/sample/src/headers.rs",
            "use axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN;\n",
        )
        self.assert_refused("crates/sample/src/headers.rs")

    def test_the_contract_and_corp_helpers_may_name_the_origin_header(self) -> None:
        self.write(
            "crates/registry-evidence/src/contracts.rs",
            'fn public_check_response_headers() {\n    let n = "Access-Control-Allow-Origin";\n}\n',
        )
        self.write(
            "crates/registry-platform-httpsec/src/server.rs",
            "pub fn apply_conditional_corp() {\n"
            '    let n = "access-control-allow-origin";\n}\n',
        )
        result = run(self.root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_the_allowed_header_helpers_cannot_move_to_another_function(self) -> None:
        self.write(
            "crates/registry-evidence/src/contracts.rs",
            'fn other_headers() {\n    let n = "Access-Control-Allow-Origin";\n}\n',
        )
        self.assert_refused("crates/registry-evidence/src/contracts.rs")

    # Credentials are never allowed, even where CORS is.

    def test_a_credentials_header_fails_in_any_case(self) -> None:
        for spelling in (
            "Access-Control-Allow-Credentials",
            "access-control-allow-credentials",
            "ACCESS_CONTROL_ALLOW_CREDENTIALS",
        ):
            with self.subTest(spelling=spelling):
                self.write(
                    "crates/sample/src/headers.rs",
                    f'const H: &str = "{spelling}";\n',
                )
                self.assert_refused("crates/sample/src/headers.rs")

    def test_a_credentials_header_fails_inside_the_allowed_function(self) -> None:
        self.write(
            self.EVIDENCE_SERVER,
            self.PUBLIC_CHECK_CORS.replace(
                "CorsLayer::new()\n",
                "CorsLayer::new().allow_credentials(true)\n",
            ),
        )
        self.assert_refused(self.EVIDENCE_SERVER)

    def test_a_credentials_header_fails_in_the_allowed_contract_function(self) -> None:
        self.write(
            "crates/registry-evidence/src/contracts.rs",
            "fn public_check_response_headers() {\n"
            '    let n = "Access-Control-Allow-Credentials";\n}\n',
        )
        self.assert_refused("crates/registry-evidence/src/contracts.rs")

    # The tower-http `cors` feature is allowed in Evidence's manifest only.

    EVIDENCE_MANIFEST = (
        '[dependencies]\ntower-http = { workspace = true, features = ["cors"] }\n'
    )

    def test_the_cors_feature_is_allowed_in_the_evidence_manifest(self) -> None:
        self.write("crates/registry-evidence/Cargo.toml", self.EVIDENCE_MANIFEST)
        result = run(self.root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_the_cors_feature_in_another_manifest_fails(self) -> None:
        self.write("crates/sample/Cargo.toml", self.EVIDENCE_MANIFEST)
        self.assert_refused("crates/sample/Cargo.toml")


if __name__ == "__main__":
    unittest.main()
