#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import base64
import importlib.util
import json
import sys
import tempfile
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch


SCRIPT_DIR = Path(__file__).resolve().parent
RUNNER_PATH = SCRIPT_DIR / "relay-oidc-smoke.py"
HELPER_PATH = SCRIPT_DIR.parent / "conformance" / "relay-oidc" / "zitadel-helper.py"


def load_runner():
    spec = importlib.util.spec_from_file_location("relay_oidc_smoke", RUNNER_PATH)
    if not spec or not spec.loader:
        raise RuntimeError(f"could not load {RUNNER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_helper():
    spec = importlib.util.spec_from_file_location(
        "relay_oidc_zitadel_helper", HELPER_PATH
    )
    if not spec or not spec.loader:
        raise RuntimeError(f"could not load {HELPER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PlainTextResponse:
    status = 200
    headers: dict[str, str] = {}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit: int) -> bytes:
        return b"ok"


def encode_json(value: dict[str, object]) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def fake_token(
    *,
    role_claim: object | None = None,
    claim_name: str = "urn:zitadel:iam:org:project:roles",
) -> str:
    header = encode_json({"alg": "RS256", "typ": "JWT", "kid": "key-1"})
    payload: dict[str, object] = {
        "iss": "http://localhost:8080",
        "aud": ["project-1"],
        "azp": "client-1",
    }
    if role_claim is not None:
        payload[claim_name] = role_claim
    signature = base64.urlsafe_b64encode(b"synthetic-signature").rstrip(b"=").decode()
    return f"{header}.{encode_json(payload)}.{signature}"


class RelayOidcSmokeTest(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = load_runner()
        cls.helper = load_helper()

    def topology(self) -> dict[str, str]:
        return {
            "client_id": "client-1",
            "project_id": "project-1",
            "role_key": "registry-smoke-reader",
            "service_account_org_id": "org-1",
        }

    def test_assets_are_candidate_neutral_and_digest_pinned(self) -> None:
        assets = self.runner.validate_assets()
        compose = self.runner.COMPOSE_PATH.read_text(encoding="utf-8")

        self.assertNotIn("build:", compose)
        self.assertEqual(3, len(assets["support_images"]))
        self.assertEqual(
            len(assets["support_images"]), len(set(assets["support_images"]))
        )
        for image in assets["support_images"]:
            self.assertRegex(image, self.runner.DIGEST_IMAGE_RE)
        self.assertNotIn("ghcr.io/registrystack/registry-relay@sha256:", compose)

    def test_relay_image_requires_exact_repository_and_lowercase_digest(self) -> None:
        valid = "ghcr.io/registrystack/registry-relay@sha256:" + "a" * 64
        self.assertEqual(valid, self.runner.validate_relay_image(valid))

        invalid = (
            "ghcr.io/registrystack/registry-relay:1.0.0",
            "ghcr.io/registrystack/registry-relay:1.0.0@sha256:" + "a" * 64,
            "example.test/registry-relay@sha256:" + "a" * 64,
            "ghcr.io/registrystack/registry-relay@sha256:" + "A" * 64,
        )
        for image in invalid:
            with self.subTest(image=image):
                with self.assertRaises(self.runner.SmokeError):
                    self.runner.validate_relay_image(image)

    def test_plan_is_offline_and_does_not_claim_live_evidence(self) -> None:
        plan = self.runner.plan_document(
            "ghcr.io/registrystack/registry-relay@sha256:" + "a" * 64,
            "b" * 40,
            "1.0.0-rc.1",
        )

        self.assertFalse(plan["plan_network_required"])
        self.assertTrue(plan["live_run_requires_docker"])
        self.assertTrue(plan["live_run_network_required"])
        self.assertFalse(plan["live_evidence"])
        self.assertEqual(list(self.runner.REQUIRED_CHECKS), plan["checks"])
        self.assertEqual("candidate-neutral-harness-plan", plan["classification"])

    def test_candidate_identifiers_are_bounded(self) -> None:
        self.assertEqual("a" * 40, self.runner.validate_source_ref("a" * 40))
        self.assertEqual("1.0.0-rc.1", self.runner.validate_release_id("1.0.0-rc.1"))
        for source_ref in ("a" * 39, "A" * 40, "main"):
            with self.assertRaises(self.runner.SmokeError):
                self.runner.validate_source_ref(source_ref)
        for release_id in ("", "contains space", "a" * 65):
            with self.assertRaises(self.runner.SmokeError):
                self.runner.validate_release_id(release_id)

    def test_native_zitadel_role_claim_drives_scope_profile(self) -> None:
        token = fake_token(role_claim={"registry-smoke-reader": {"org-1": "active"}})
        profile = self.runner.inspect_token(token, self.topology())

        self.assertEqual("client-1", profile["allowed_client"])
        self.assertEqual("project-1", profile["audience"])
        self.assertEqual("org-1", profile["required_org"])
        self.assertEqual("urn:zitadel:iam:org:project:roles", profile["scope_claim"])
        rendered = self.runner.render_relay_config(profile, host_port=19191)
        self.assertIn("mode: oidc", rendered)
        self.assertIn('scope_claim: "urn:zitadel:iam:org:project:roles"', rendered)
        self.assertIn('"registry-smoke-reader": "smoke_registry:metadata"', rendered)
        self.assertIn('- "org-1"', rendered)
        self.assertNotIn("$", rendered)

    def test_project_specific_native_role_claim_is_preferred(self) -> None:
        claim_name = "urn:zitadel:iam:org:project:project-1:roles"
        token = fake_token(
            claim_name=claim_name,
            role_claim={"registry-smoke-reader": {"org-1": "active"}},
        )
        profile = self.runner.inspect_token(token, self.topology())
        rendered = self.runner.render_relay_config(profile, host_port=19191)

        self.assertEqual(claim_name, profile["scope_claim"])
        self.assertIn(f'scope_claim: "{claim_name}"', rendered)

    def test_role_claim_requires_the_service_account_organization(self) -> None:
        wrong_org = fake_token(
            role_claim={"registry-smoke-reader": {"org-other": "active"}}
        )
        with self.assertRaisesRegex(self.runner.SmokeError, "not active"):
            self.runner.inspect_token(wrong_org, self.topology())
        with self.assertRaisesRegex(self.runner.SmokeError, "omitted"):
            self.runner.inspect_token(fake_token(), self.topology())

    def test_signature_tamper_changes_decoded_signature_bytes(self) -> None:
        token = fake_token(role_claim={})
        tampered = self.runner.tamper_signature(token)
        original_segment = token.split(".")[2]
        tampered_segment = tampered.split(".")[2]

        def decode(value: str) -> bytes:
            return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

        self.assertEqual(token.split(".")[:2], tampered.split(".")[:2])
        self.assertNotEqual(decode(original_segment), decode(tampered_segment))

    def test_sensitive_guard_redacts_and_rejects_leaks(self) -> None:
        guard = self.runner.SensitiveGuard("secret-canary-value")
        self.assertEqual("token=<redacted>", guard.redact("token=secret-canary-value"))
        with self.assertRaisesRegex(self.runner.SmokeError, "canary detected"):
            guard.assert_clean_bytes(b"prefix secret-canary-value suffix", "test")

    def test_relay_wait_retries_connection_level_os_errors(self) -> None:
        class HealthyResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        guard = self.runner.SensitiveGuard("secret-canary-value")
        with patch.object(
            self.runner.urllib.request,
            "urlopen",
            side_effect=[ConnectionResetError("restart"), HealthyResponse()],
        ):
            with patch.object(self.runner.time, "sleep"):
                self.runner.wait_for_relay(
                    "http://127.0.0.1:19191", {}, "project", guard
                )

    def test_safe_report_allowlist_and_canary_scan(self) -> None:
        guard = self.runner.SensitiveGuard("secret-canary-value")
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            with self.assertRaisesRegex(self.runner.SmokeError, "non-allowlisted"):
                self.runner.safe_report({"raw_token": "value"}, output, guard)
            with self.assertRaisesRegex(self.runner.SmokeError, "canary detected"):
                self.runner.safe_report(
                    {"diagnostic": "secret-canary-value"}, output, guard
                )
            path = self.runner.safe_report(
                {
                    "schema_version": self.runner.SCHEMA_VERSION,
                    "classification": "unreviewed-live-candidate-output",
                    "review_required": True,
                    "contains_sensitive_material": False,
                    "result": "pass",
                    "checks": [],
                },
                output,
                guard,
            )
            self.assertEqual(0o644, path.stat().st_mode & 0o777)
            report = json.loads(path.read_text(encoding="utf-8"))
            self.assertTrue(report["review_required"])
            self.assertFalse(report["contains_sensitive_material"])

    def test_output_directory_must_be_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            output.mkdir()
            (output / "existing").write_text("preserve", encoding="utf-8")
            with self.assertRaisesRegex(self.runner.SmokeError, "must be empty"):
                self.runner.ensure_empty_output(output)
            self.assertEqual("preserve", (output / "existing").read_text())

    def test_run_requires_all_candidate_binding_arguments(self) -> None:
        with patch.object(sys, "stderr"):
            with self.assertRaises(SystemExit):
                self.runner.parse_args(["run", "--release-id", "1.0.0-rc.1"])

    def test_helper_never_logs_secret_response_fields(self) -> None:
        helper = self.runner.HELPER_PATH.read_text(encoding="utf-8")
        self.assertNotIn("print(client_secret", helper)
        self.assertNotIn("print(token", helper)
        self.assertIn("unexpected internal failure", helper)
        self.assertIn("0o600", helper)
        self.assertIn("parse_json=False", helper)
        self.assertIn('f"{MANAGEMENT_URL}/projects/_search"', helper)
        self.assertNotIn('"Host":', helper)

    def test_helper_accepts_plain_text_health_response_only_when_requested(
        self,
    ) -> None:
        with patch.object(
            self.helper.urllib.request, "urlopen", return_value=PlainTextResponse()
        ):
            self.assertEqual(
                {},
                self.helper.request(
                    "GET", "http://localhost:8080/debug/healthz", parse_json=False
                ),
            )
            with self.assertRaisesRegex(self.helper.HelperError, "malformed JSON"):
                self.helper.request("GET", "http://localhost:8080/management/v1")

    def test_helper_writes_runtime_secrets_for_the_invoking_host_user(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "secret"
            env = {
                "REGISTRY_RELAY_OIDC_SMOKE_RUNTIME_UID": str(self.runner.os.getuid()),
                "REGISTRY_RELAY_OIDC_SMOKE_RUNTIME_GID": str(self.runner.os.getgid()),
            }
            with patch.dict(self.helper.os.environ, env, clear=False):
                self.helper.atomic_secret(path, "synthetic-secret")

            self.assertEqual(0o600, path.stat().st_mode & 0o777)
            self.assertEqual(self.runner.os.getuid(), path.stat().st_uid)
            self.assertEqual(self.runner.os.getgid(), path.stat().st_gid)

    def test_helper_rejects_invalid_runtime_ownership(self) -> None:
        env = {
            "REGISTRY_RELAY_OIDC_SMOKE_RUNTIME_UID": "not-a-uid",
            "REGISTRY_RELAY_OIDC_SMOKE_RUNTIME_GID": "123",
        }
        with patch.dict(self.helper.os.environ, env, clear=False):
            with self.assertRaisesRegex(self.helper.HelperError, "decimal integers"):
                self.helper.runtime_owner()


if __name__ == "__main__":
    main()
