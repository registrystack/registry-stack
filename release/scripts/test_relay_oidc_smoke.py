#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib.util
import json
import sys
import tempfile
import threading
from argparse import Namespace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch


SCRIPT_DIR = Path(__file__).resolve().parent
RUNNER_PATH = SCRIPT_DIR / "relay-oidc-smoke.py"
HELPER_PATH = SCRIPT_DIR.parent / "conformance" / "relay-oidc" / "zitadel-helper.py"
sys.path.insert(0, str(SCRIPT_DIR))


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


class RecordingHttpServer(ThreadingHTTPServer):
    redirect_target: str | None = None
    authorization_headers: list[str | None]


class RecordingHandler(BaseHTTPRequestHandler):
    server: RecordingHttpServer

    def record_and_respond(self) -> None:
        self.server.authorization_headers.append(self.headers.get("Authorization"))
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length:
            self.rfile.read(content_length)
        if self.server.redirect_target:
            self.send_response(302)
            self.send_header("Location", self.server.redirect_target)
        else:
            self.send_response(204)
        self.end_headers()

    def do_GET(self) -> None:
        self.record_and_respond()

    def do_POST(self) -> None:
        self.record_and_respond()

    def log_message(self, _format: str, *_args) -> None:
        return


@contextlib.contextmanager
def cross_origin_redirect():
    target = RecordingHttpServer(("127.0.0.1", 0), RecordingHandler)
    target.authorization_headers = []
    source = RecordingHttpServer(("127.0.0.1", 0), RecordingHandler)
    source.authorization_headers = []
    source.redirect_target = f"http://127.0.0.1:{target.server_port}/redirect-target"
    source_url = f"http://127.0.0.1:{source.server_port}/start"
    threads = [
        threading.Thread(target=server.serve_forever, daemon=True)
        for server in (target, source)
    ]
    for thread in threads:
        thread.start()
    try:
        yield source_url, source, target
    finally:
        source.shutdown()
        target.shutdown()
        source.server_close()
        target.server_close()
        for thread in threads:
            thread.join(timeout=2)


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

    def write_candidate_evidence(
        self, image_lock: Path, lock: dict[str, object]
    ) -> None:
        lock_bytes = json.dumps(lock).encode("utf-8")
        image_lock.write_bytes(lock_bytes)
        lock_sha256 = hashlib.sha256(lock_bytes).hexdigest()
        tag = str(lock["release_tag"])
        capsule_name = f"registry-stack-{tag}-release-capsule.json"
        images = lock["images"]
        if not isinstance(images, dict):
            raise AssertionError("test image lock images must be an object")
        capsule = {
            "release_tag": tag,
            "version": tag.removeprefix("v"),
            "repository": "registrystack/registry-stack",
            "source": {
                "source_tag": tag,
                "source_ref": lock["manifest_source_ref"],
                "source_commit": lock["tag_target"],
                "lineage": {
                    "tag_matches_source_tag": True,
                    "head_matches_tag_target": True,
                    "source_ref_ancestor_or_equal": True,
                    "default_branch_reachable": True,
                },
            },
            "release_files": [
                {
                    "name": image_lock.name,
                    "kind": "registryctl-release-image-lock",
                    "sha256": lock_sha256,
                }
            ],
            "images": [
                {"name": name, "digest_ref": digest_ref}
                for name, digest_ref in images.items()
            ],
        }
        capsule_path = image_lock.parent / capsule_name
        capsule_path.write_text(json.dumps(capsule), encoding="utf-8")
        (image_lock.parent / "SHA256SUMS").write_text(
            f"{lock_sha256}  {image_lock.name}\n", encoding="utf-8"
        )
        provenance = (
            image_lock.parent
            / f"registry-stack-{tag}-release-provenance.intoto.jsonl"
        )
        provenance.write_text("{}\n", encoding="utf-8")
        for subject in (image_lock, capsule_path):
            subject.with_name(f"{subject.name}.sig").write_text(
                "signature", encoding="utf-8"
            )
            subject.with_name(f"{subject.name}.pem").write_text(
                "certificate", encoding="utf-8"
            )

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

    def test_plan_declares_authenticity_network_and_no_live_evidence(self) -> None:
        candidate = {"release_id": "beta-17", "source_ref": "a" * 40}
        plan = self.runner.plan_document(candidate)

        self.assertTrue(plan["plan_network_required"])
        self.assertTrue(plan["live_run_requires_docker"])
        self.assertTrue(plan["live_run_network_required"])
        self.assertFalse(plan["live_evidence"])
        self.assertEqual(list(self.runner.REQUIRED_CHECKS), plan["checks"])
        self.assertEqual("candidate-neutral-harness-plan", plan["classification"])
        self.assertEqual(candidate, plan["candidate"])

    def test_candidate_binding_rejects_manifest_lock_and_image_mismatches(self) -> None:
        candidate_module = sys.modules["conformance_candidate"]
        with tempfile.TemporaryDirectory() as tmp:
            manifest = (
                self.runner.REPO_ROOT / "release/manifests/registry-stack-beta-15.yaml"
            )
            image_lock = Path(tmp) / "registryctl-v0.12.1-image-lock.json"
            lock = {
                "schema_version": "registryctl.release_image_lock.v1",
                "release_tag": "v0.12.1",
                "manifest_source_ref": "a6f409259158f44c9fdbe99242ec0f9ac10d9373",
                "tag_target": "567fb93704d25855238e11fd43c7cb9bf8a2f28e",
                "platform": "linux/amd64",
                "images": {
                    "registry-notary": (
                        "ghcr.io/registrystack/registry-notary@sha256:" + "c" * 64
                    ),
                    "registry-relay": (
                        "ghcr.io/registrystack/registry-relay@sha256:" + "d" * 64
                    ),
                },
            }
            self.write_candidate_evidence(image_lock, lock)
            args = Namespace(
                release_manifest=manifest,
                image_lock=image_lock,
                topology="release-owned",
                solmara_source_ref=None,
            )
            with patch.object(
                candidate_module, "verify_release_authenticity"
            ) as authenticate:
                candidate = self.runner.candidate_from_args(args)
            self.assertEqual("beta-15", candidate["release_id"])
            self.assertEqual(lock["images"]["registry-relay"], candidate["relay_image"])
            authenticate.assert_called_once()

            lock["manifest_source_ref"] = "e" * 40
            image_lock.write_text(json.dumps(lock), encoding="utf-8")
            with self.assertRaisesRegex(
                candidate_module.CandidateError, "does not match"
            ):
                self.runner.candidate_from_args(args)

            lock["manifest_source_ref"] = "a6f409259158f44c9fdbe99242ec0f9ac10d9373"
            lock["images"]["registry-relay"] = "registry-relay:mutable"
            image_lock.write_text(json.dumps(lock), encoding="utf-8")
            with self.assertRaisesRegex(candidate_module.CandidateError, "not pinned"):
                self.runner.candidate_from_args(args)

            lock["images"]["registry-relay"] = (
                "ghcr.io/registrystack/registry-relay@sha256:" + "d" * 64
            )
            lock["tag_target"] = "b" * 40
            image_lock.write_text(json.dumps(lock), encoding="utf-8")
            with self.assertRaisesRegex(candidate_module.CandidateError, "Git binding"):
                self.runner.candidate_from_args(args)

    def test_candidate_binding_rejects_locally_replaced_release_assets(self) -> None:
        candidate_module = sys.modules["conformance_candidate"]
        with tempfile.TemporaryDirectory() as tmp:
            manifest = (
                self.runner.REPO_ROOT / "release/manifests/registry-stack-beta-15.yaml"
            )
            image_lock = Path(tmp) / "registryctl-v0.12.1-image-lock.json"
            lock = {
                "schema_version": "registryctl.release_image_lock.v1",
                "release_tag": "v0.12.1",
                "manifest_source_ref": "a6f409259158f44c9fdbe99242ec0f9ac10d9373",
                "tag_target": "567fb93704d25855238e11fd43c7cb9bf8a2f28e",
                "platform": "linux/amd64",
                "images": {
                    "registry-notary": (
                        "ghcr.io/registrystack/registry-notary@sha256:" + "c" * 64
                    ),
                    "registry-relay": (
                        "ghcr.io/registrystack/registry-relay@sha256:" + "d" * 64
                    ),
                },
            }
            self.write_candidate_evidence(image_lock, lock)
            args = Namespace(
                release_manifest=manifest,
                image_lock=image_lock,
                topology="release-owned",
                solmara_source_ref=None,
            )

            lock["images"]["registry-relay"] = (
                "ghcr.io/registrystack/registry-relay@sha256:" + "e" * 64
            )
            image_lock.write_text(json.dumps(lock), encoding="utf-8")
            with patch.object(
                candidate_module, "verify_release_authenticity"
            ) as authenticate:
                with self.assertRaisesRegex(
                    candidate_module.CandidateError, "SHA256SUMS"
                ):
                    self.runner.candidate_from_args(args)
            authenticate.assert_not_called()

            tampered_sha256 = hashlib.sha256(image_lock.read_bytes()).hexdigest()
            (image_lock.parent / "SHA256SUMS").write_text(
                f"{tampered_sha256}  {image_lock.name}\n", encoding="utf-8"
            )
            with patch.object(
                candidate_module, "verify_release_authenticity"
            ) as authenticate:
                with self.assertRaisesRegex(
                    candidate_module.CandidateError, "classification or hash"
                ):
                    self.runner.candidate_from_args(args)
            authenticate.assert_not_called()

            self.write_candidate_evidence(image_lock, lock)
            with patch.object(
                candidate_module,
                "verify_release_authenticity",
                side_effect=candidate_module.CandidateError(
                    "candidate authenticity rejected"
                ),
            ):
                with self.assertRaisesRegex(
                    candidate_module.CandidateError, "authenticity rejected"
                ):
                    self.runner.candidate_from_args(args)

    def test_candidate_authenticity_is_pinned_to_the_tagged_release_workflow(
        self,
    ) -> None:
        candidate_module = sys.modules["conformance_candidate"]
        with tempfile.TemporaryDirectory() as tmp:
            asset_dir = Path(tmp)
            tag = "v0.12.1"
            subjects = (
                f"registryctl-{tag}-image-lock.json",
                f"registry-stack-{tag}-release-capsule.json",
            )
            for name in subjects:
                (asset_dir / name).write_text("subject", encoding="utf-8")
                (asset_dir / f"{name}.sig").write_text(
                    "signature", encoding="utf-8"
                )
                (asset_dir / f"{name}.pem").write_text(
                    "certificate", encoding="utf-8"
                )
            (
                asset_dir
                / f"registry-stack-{tag}-release-provenance.intoto.jsonl"
            ).write_text("{}\n", encoding="utf-8")
            commands: list[list[str]] = []
            tool_paths = {
                "cosign": "/tools/cosign",
                "slsa-verifier": "/tools/slsa-verifier",
            }
            with patch.object(
                candidate_module.shutil,
                "which",
                side_effect=lambda name: tool_paths.get(name),
            ):
                candidate_module.verify_release_authenticity(
                    asset_dir, tag, subjects, command_runner=commands.append
                )

        self.assertEqual(4, len(commands))
        identity = candidate_module.RELEASE_WORKFLOW.format(tag=tag)
        for command in commands[::2]:
            self.assertEqual("/tools/cosign", command[0])
            self.assertIn(identity, command)
        for command in commands[1::2]:
            self.assertEqual("/tools/slsa-verifier", command[0])
            self.assertEqual(tag, command[command.index("--source-tag") + 1])
            self.assertEqual(
                candidate_module.SLSA_SOURCE_URI,
                command[command.index("--source-uri") + 1],
            )

    def test_candidate_binding_accepts_only_the_manifest_closeout_transition(
        self,
    ) -> None:
        candidate_module = sys.modules["conformance_candidate"]
        with tempfile.TemporaryDirectory() as tmp:
            image_lock = Path(tmp) / "registryctl-v0.12.2-image-lock.json"
            lock = {
                "schema_version": "registryctl.release_image_lock.v1",
                "release_tag": "v0.12.2",
                "manifest_source_ref": (
                    "0e76f5ea61f78bbc15d91fcb6e9dfcaa956c3df8"
                ),
                "tag_target": "e25f081ce800ade13e892503cc19b96588e081ef",
                "platform": "linux/amd64",
                "images": {
                    "registry-notary": (
                        "ghcr.io/registrystack/registry-notary@sha256:"
                        + "c" * 64
                    ),
                    "registry-relay": (
                        "ghcr.io/registrystack/registry-relay@sha256:"
                        + "d" * 64
                    ),
                },
            }
            self.write_candidate_evidence(image_lock, lock)
            manifest = (
                self.runner.REPO_ROOT
                / "release/manifests/registry-stack-beta-16.yaml"
            )
            args = Namespace(
                release_manifest=manifest,
                image_lock=image_lock,
                topology="release-owned",
                solmara_source_ref=None,
            )
            with patch.object(
                candidate_module, "verify_release_authenticity"
            ) as authenticate:
                candidate = self.runner.candidate_from_args(args)

            self.assertEqual("beta-16", candidate["release_id"])
            authenticate.assert_called_once()

            tagged = candidate_module.git_output(
                [
                    "show",
                    (
                        "e25f081ce800ade13e892503cc19b96588e081ef:"
                        "release/manifests/registry-stack-beta-16.yaml"
                    ),
                ],
                1024 * 1024,
            )
            released = manifest.read_bytes()
            candidate_module.verify_closeout_manifest_transition(
                {"status": "released"}, released, tagged
            )
            with self.assertRaisesRegex(
                candidate_module.CandidateError, "Git binding"
            ):
                candidate_module.verify_closeout_manifest_transition(
                    {"status": "released"},
                    released
                    + (
                        b"# Any post-tag change beyond the exact status closeout "
                        b"is rejected.\n"
                    ),
                    tagged,
                )

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
            self.runner.NO_REDIRECT_OPENER,
            "open",
            side_effect=[ConnectionResetError("restart"), HealthyResponse()],
        ):
            with patch.object(self.runner.time, "sleep"):
                self.runner.wait_for_relay(
                    "http://127.0.0.1:19191", {}, "project", guard
                )

    def test_relay_bearer_is_not_forwarded_across_redirect(self) -> None:
        bearer = "synthetic-bearer-secret"
        guard = self.runner.SensitiveGuard(bearer)
        with cross_origin_redirect() as (source_url, source, target):
            with self.assertRaisesRegex(self.runner.SmokeError, "returned a redirect"):
                self.runner.http_json(source_url, bearer, guard)

        self.assertEqual([f"Bearer {bearer}"], source.authorization_headers)
        self.assertEqual([], target.authorization_headers)

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
                self.runner.parse_args(
                    ["run", "--release-manifest", "release/manifests/example.yaml"]
                )

    def test_helper_never_logs_secret_response_fields(self) -> None:
        helper = self.runner.HELPER_PATH.read_text(encoding="utf-8")
        self.assertNotIn("print(client_secret", helper)
        self.assertNotIn("print(token", helper)
        self.assertIn("unexpected internal failure", helper)
        self.assertIn("0o600", helper)
        self.assertIn("parse_json=False", helper)
        self.assertIn('f"{MANAGEMENT_URL}/projects/_search"', helper)
        self.assertNotIn('"Host":', helper)

    def test_readme_states_binding_and_ephemeral_secret_boundaries(self) -> None:
        readme = (self.runner.CONFIG_DIR / "README.md").read_text(encoding="utf-8")
        self.assertIn("release-tag, product-version, or image-digest mismatch", readme)
        self.assertIn("container environment metadata", readme)
        self.assertIn("container command metadata", readme)
        self.assertIn("never follow redirects", readme)

    def test_helper_accepts_plain_text_health_response_only_when_requested(
        self,
    ) -> None:
        with patch.object(
            self.helper.NO_REDIRECT_OPENER, "open", return_value=PlainTextResponse()
        ):
            self.assertEqual(
                {},
                self.helper.request(
                    "GET", "http://localhost:8080/debug/healthz", parse_json=False
                ),
            )
            with self.assertRaisesRegex(self.helper.HelperError, "malformed JSON"):
                self.helper.request("GET", "http://localhost:8080/management/v1")

    def test_helper_bootstrap_pat_is_not_forwarded_across_redirect(self) -> None:
        pat = "synthetic-bootstrap-pat"
        with cross_origin_redirect() as (source_url, source, target):
            with self.assertRaisesRegex(self.helper.HelperError, "redirect refused"):
                self.helper.request("GET", source_url, bearer=pat)

        self.assertEqual([f"Bearer {pat}"], source.authorization_headers)
        self.assertEqual([], target.authorization_headers)

    def test_helper_client_credentials_are_not_forwarded_across_redirect(self) -> None:
        client_id = "synthetic-client"
        client_secret = "synthetic-client-secret"
        encoded = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        with cross_origin_redirect() as (source_url, source, target):
            with self.assertRaisesRegex(self.helper.HelperError, "redirect refused"):
                self.helper.request(
                    "POST",
                    source_url,
                    form_body={"grant_type": "client_credentials"},
                    basic_auth=(client_id, client_secret),
                )

        self.assertEqual([f"Basic {encoded}"], source.authorization_headers)
        self.assertEqual([], target.authorization_headers)

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

    def test_helper_writes_all_runtime_json_owner_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "topology.json"
            env = {
                "REGISTRY_RELAY_OIDC_SMOKE_RUNTIME_UID": str(self.runner.os.getuid()),
                "REGISTRY_RELAY_OIDC_SMOKE_RUNTIME_GID": str(self.runner.os.getgid()),
            }
            with patch.dict(self.helper.os.environ, env, clear=False):
                self.helper.atomic_json(path, {"client_id": "synthetic-client"})

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
