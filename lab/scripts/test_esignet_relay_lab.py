#!/usr/bin/env python3
"""Regression checks for the Relay-backed eSignet lab wiring."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parent


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def repo_text(path: str) -> str:
    return (REPO_ROOT / path).read_text(encoding="utf-8")


class EsignetRelayLabTest(unittest.TestCase):
    def test_local_compose_uses_relay_authenticator_without_mock_ida(self) -> None:
        compose = text("compose.esignet-live.yaml")

        self.assertNotIn("mock-identity-system:", compose)
        self.assertNotIn("MOSIP_ESIGNET_MOCK_DOMAIN_URL", compose)
        self.assertIn("MOSIP_ESIGNET_INTEGRATION_AUTHENTICATOR: RelayAuthenticationService", compose)
        self.assertIn("REGISTRY_RELAY_BASE_URL", compose)
        self.assertIn("REGISTRY_RELAY_ATTRIBUTE_RELEASE_PROFILE_ID: esignet-civil-userinfo", compose)
        self.assertIn("POPULATION_ESIGNET_IDENTITY_RELEASE_RAW", compose)
        self.assertIn("REGISTRY_ESIGNET_USER_INFO_ISSUER", compose)
        self.assertIn("REGISTRY_ESIGNET_KYC_SIGNING_KEYSTORE_PATH", compose)

    def test_seed_script_does_not_seed_mock_identities(self) -> None:
        seed = text("scripts/seed-esignet-live.py")

        for forbidden in (
            "DEMO_USERS",
            "DEMO_PIN",
            "seed_mock_identities",
            "mockidentitysystem",
            "mosip_mockidentitysystem",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, seed)

    def test_hosted_compose_requires_digest_pinned_esignet_images(self) -> None:
        hosted = text("compose.esignet-hosted.yaml")

        self.assertIn("REGISTRY_LAB_ESIGNET_RELAY_IMAGE:?", hosted)
        self.assertIn("REGISTRY_LAB_ESIGNET_SEED_IMAGE:?", hosted)
        self.assertNotIn("mock-identity-system:", hosted)
        self.assertIn("RelayAuthenticationService", hosted)
        self.assertIn("REGISTRY_ESIGNET_USER_INFO_ISSUER", hosted)

    def test_user_facing_login_text_no_longer_mentions_static_pin(self) -> None:
        checked_paths = [
            "README.md",
            "docs/citizen-self-attestation-esignet-use-case.md",
            "scripts/lab_homepage_static/homepage.js",
            "config/lab-homepage/public-demo-credentials.json",
        ]
        for path in checked_paths:
            value = text(path)
            with self.subTest(path=path):
                self.assertNotIn("545411", value)
                self.assertNotIn("if eSignet asks", value)

    def test_plugin_submodule_is_declared(self) -> None:
        modules = repo_text(".gitmodules")

        self.assertIn("[submodule \"lab/vendor/esignet-relay-authenticator\"]", modules)
        self.assertIn("path = lab/vendor/esignet-relay-authenticator", modules)
        self.assertIn("url = git@github.com:jeremi/esignet-relay-authenticator.git", modules)

    def test_esignet_relay_image_rebuilds_plugin_classes_from_source(self) -> None:
        dockerfile = text("Dockerfile.esignet-relay")
        justfile = text("justfile")

        self.assertIn("mvn -B -DskipTests clean package", dockerfile)
        self.assertIn('default_esignet_relay_authenticator_src := "./vendor/esignet-relay-authenticator"', justfile)
        self.assertIn(
            'docker buildx build --load --no-cache --build-context esignet_relay_authenticator_src="${ESIGNET_RELAY_AUTHENTICATOR_SOURCE_DIR}"',
            justfile,
        )
        self.assertIn("docker compose -f compose.esignet-live.yaml up -d --no-build", justfile)

    def test_token_replay_recipe_forwards_citizen_tokens(self) -> None:
        justfile = text("justfile")
        recipe_start = justfile.index("citizen-self-attestation-esignet-token:")
        recipe_end = justfile.index("# Show the latest citizen self-attestation evidence report.", recipe_start)
        recipe = justfile[recipe_start:recipe_end]

        self.assertIn('ESIGNET_CITIZEN_ACCESS_TOKEN="${ESIGNET_CITIZEN_ACCESS_TOKEN}"', recipe)
        self.assertIn('ESIGNET_CITIZEN_ID_TOKEN="${ESIGNET_CITIZEN_ID_TOKEN}"', recipe)

    def test_esignet_entrypoint_repairs_stale_kyc_keystore(self) -> None:
        start_script = text("scripts/start-esignet-relay.sh")

        self.assertIn("keytool -list", start_script)
        self.assertIn('-storepass "$keystore_password"', start_script)
        self.assertIn('-alias "$key_alias"', start_script)
        self.assertIn('rm -f "$keystore_path"', start_script)
        self.assertIn("keytool -genkeypair", start_script)

    def test_self_attestation_is_source_free_and_uses_application_purpose(self) -> None:
        smoke = text("scripts/smoke-citizen-self-attestation.sh")
        hosted = text("config/notary/self-attested-notary.yaml")
        purpose = "application-processing"

        self.assertIn(f"ESIGNET_SELF_ATTESTATION_PURPOSE:-{purpose}", smoke)
        self.assertIn("purpose: {json.dumps(self_attestation_purpose)}", smoke)
        self.assertIn("- {json.dumps(self_attestation_purpose)}", smoke)
        self.assertIn("type: self_attested", hosted)
        self.assertIn(f"purpose: {purpose}", hosted)
        self.assertNotIn("consultations:", hosted)

    def test_smoke_does_not_start_relay_for_source_free_claim(self) -> None:
        smoke = text("scripts/smoke-citizen-self-attestation.sh")

        self.assertNotIn('up -d --force-recreate civil-registry-relay', smoke)
        self.assertNotIn("source_connections", smoke)
        self.assertNotIn("source_bindings", smoke)

    def test_smoke_runs_citizen_notary_with_cel_feature(self) -> None:
        smoke = text("scripts/smoke-citizen-self-attestation.sh")

        self.assertIn("cargo run -p registry-notary --features registry-notary-cel", smoke)

    def test_smoke_waits_for_notary_health_before_authenticated_discovery(self) -> None:
        smoke = text("scripts/smoke-citizen-self-attestation.sh")
        health_wait = 'wait_http "citizen civil notary health" "http://127.0.0.1:${port}/healthz"'
        discovery_step = 'step 7 "Call Notary discovery"'

        self.assertIn(health_wait, smoke)
        self.assertLess(smoke.index(health_wait), smoke.index(discovery_step))
        self.assertNotIn(
            'wait_http "citizen civil notary discovery" "http://127.0.0.1:${port}/.well-known/evidence-service"',
            smoke,
        )

    def test_smoke_accepts_current_notary_provenance_source_count(self) -> None:
        smoke = text("scripts/smoke-citizen-self-attestation.sh")

        self.assertIn('(provenance.get("used") or {}).get("source_count")', smoke)

    def test_smoke_declares_jq_prerequisite(self) -> None:
        smoke = text("scripts/smoke-citizen-self-attestation.sh")

        self.assertIn("need jq", smoke)

    def test_docs_match_default_other_subject_control(self) -> None:
        smoke = text("scripts/smoke-citizen-self-attestation.sh")
        readme = text("README.md")
        use_case = text("docs/citizen-self-attestation-esignet-use-case.md")

        self.assertIn('other_subject="${ESIGNET_OTHER_SUBJECT:-NID-1001}"', smoke)
        self.assertIn("proves `NID-1001` is denied", readme)
        self.assertIn("such as `NID-1001`", use_case)
        self.assertIn("denied evaluation for `NID-1001`", use_case)

    def test_civil_person_dataset_policy_allows_esignet_purpose(self) -> None:
        relay = text("config/relay/civil-registry-relay.yaml")
        civil_person_start = relay.index("      - name: civil_person\n")
        civil_person_end = relay.index("      - name: civil_person_detail\n", civil_person_start)
        civil_person = relay[civil_person_start:civil_person_end]

        for path in (
            "config/relay/civil-registry-relay.metadata.yaml",
            "config/coolify/relay/civil-registry-relay.metadata.yaml",
        ):
            metadata = text(path)
            self.assertIn("civil-row-purpose", metadata)
            self.assertIn("https://demo.example.gov/purpose/decentralized-evidence-demo", metadata)
            self.assertIn("https://demo.example.gov/purpose/civil-certificate-evidence", metadata)
            self.assertIn("https://demo.example.gov/purpose/esignet-identity-verification", metadata)
        self.assertIn("require_purpose_header: true", civil_person)
        self.assertNotIn("governed_policy:", civil_person)

    def test_hosted_esignet_identity_release_uses_fingerprint_reference(self) -> None:
        hosted = text("config/coolify/relay/civil-registry-relay.yaml")
        start = hosted.index("    - id: esignet_identity_release\n")
        end = hosted.index("    - id:", start + 1)
        block = hosted[start:end]

        self.assertIn("name: CIVIL_ESIGNET_IDENTITY_RELEASE_HASH", block)
        self.assertNotIn("commitment:", block)

    def test_hosted_esignet_compose_declares_required_env(self) -> None:
        hosted = text("compose.esignet-hosted.yaml")

        for key in (
            "CIVIL_ESIGNET_IDENTITY_RELEASE_RAW",
            "REGISTRY_ESIGNET_KYC_KEYSTORE_PASSWORD",
            "REGISTRY_ESIGNET_KYC_TOKEN_SECRET",
            "REGISTRY_ESIGNET_PSUT_SECRET",
            "REGISTRY_LAB_ESIGNET_RELAY_IMAGE",
            "REGISTRY_LAB_ESIGNET_SEED_IMAGE",
        ):
            with self.subTest(key=key):
                self.assertIn(f"  - {key}", hosted)


if __name__ == "__main__":
    unittest.main()
