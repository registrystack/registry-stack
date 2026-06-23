#!/usr/bin/env python3
"""Focused tests for hosted Coolify deploy artifact validation."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import sys
import tempfile
import unittest
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
VALIDATOR_PATH = SCRIPT_DIR / "validate-hosted-deploy.py"
WORKFLOW_PATH = SCRIPT_DIR.parent / ".github" / "workflows" / "hosted-lab.yml"
IMAGE_PIN_WORKFLOW_PATH = SCRIPT_DIR.parent / ".github" / "workflows" / "coolify-image-pin.yml"


def load_validator():
    spec = importlib.util.spec_from_file_location("validate_hosted_deploy", VALIDATOR_PATH)
    if not spec or not spec.loader:
        raise RuntimeError(f"could not load {VALIDATOR_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class HostedDeployValidationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.validator = load_validator()

    def test_valid_hosted_artifacts_pass(self) -> None:
        issues = self._validate(self._valid_registry_lab(), self._valid_esignet())
        self.assertEqual([], issues)

    def test_rejects_host_ports(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["citizen-civil-notary"]["ports"] = ["4321:8080"]
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "host-ports")

    def test_rejects_build_and_additional_contexts(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["civil-registry-relay"]["build"] = {
            "context": ".",
            "additional_contexts": {"registry_relay_src": "./vendor/registry-relay"},
        }
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "host-build")
        self.assertIssue(issues, "additional-contexts")

    def test_rejects_latest_image_tags(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["civil-registry-relay"]["image"] = "ghcr.io/registrystack/registry-relay:latest"
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "latest-image-tag")

    def test_rejects_floating_product_image_tags(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["civil-registry-relay"]["image"] = "ghcr.io/jeremi/registry-relay:main"
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "floating-product-image-tag")

    def test_rejects_floating_citizen_portal_image_tags(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["citizen-portal"]["image"] = "ghcr.io/jeremi/registry-lab-citizen-portal:main"
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "floating-product-image-tag")

    def test_rejects_hardcoded_product_image_digests(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["civil-registry-relay"][
            "image"
        ] = "ghcr.io/jeremi/registry-relay@sha256:abc"
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "product-image-env-var")

    def test_rejects_hardcoded_citizen_portal_image_digests(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["citizen-portal"]["image"] = "ghcr.io/jeremi/registry-lab-citizen-portal@sha256:abc"
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "product-image-env-var")

    def test_allows_interim_local_hosted_product_tags(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["citizen-portal"]["image"] = "registry-lab-citizen-portal:hosted"
        compose["services"]["civil-registry-relay"]["image"] = "registry-relay:hosted"
        compose["services"]["citizen-civil-notary"]["image"] = "registry-notary:hosted"
        compose["services"]["openfn-dhis2-sidecar"][
            "image"
        ] = "registry-notary-source-adapter-sidecar:hosted"
        issues = self._validate(compose, self._valid_esignet())
        self.assertEqual([], issues)

    def test_strict_mode_rejects_interim_local_hosted_product_tags(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["citizen-portal"]["image"] = "registry-lab-citizen-portal:hosted"
        compose["services"]["civil-registry-relay"]["image"] = "registry-relay:hosted"
        compose["services"]["citizen-civil-notary"]["image"] = "registry-notary:hosted"
        compose["services"]["openfn-dhis2-sidecar"][
            "image"
        ] = "registry-notary-source-adapter-sidecar:hosted"

        issues = self.validator.validate_artifacts(
            {
                "registry-lab": compose,
                "esignet": self._valid_esignet(),
            },
            reject_interim_product_images=True,
        )

        self.assertIssue(issues, "interim-product-image-tag")

    def test_strict_mode_env_flag_accepts_common_truthy_values(self) -> None:
        self.assertTrue(self.validator.truthy_env("1"))
        self.assertTrue(self.validator.truthy_env("true"))
        self.assertTrue(self.validator.truthy_env("TRUE"))
        self.assertFalse(self.validator.truthy_env(""))
        self.assertFalse(self.validator.truthy_env(None))

    def test_docker_compose_fallback_ignores_default_dotenv(self) -> None:
        captured_envs: list[dict[str, str]] = []
        original_run = self.validator.subprocess.run

        class Result:
            stdout = "{}"
            stderr = ""

        def fake_run(*_args, **kwargs):
            captured_envs.append(dict(kwargs["env"]))
            return Result()

        try:
            self.validator.subprocess.run = fake_run
            self.assertEqual({}, self.validator.render_compose_json(Path("compose.yaml")))
        finally:
            self.validator.subprocess.run = original_run

        self.assertEqual("1", captured_envs[0]["COMPOSE_DISABLE_ENV_FILE"])

    def test_allows_env_overridable_digest_pinned_product_images(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["civil-registry-relay"][
            "image"
        ] = "${REGISTRY_RELAY_IMAGE:-ghcr.io/jeremi/registry-relay@sha256:abc}"
        compose["services"]["citizen-civil-notary"][
            "image"
        ] = "${REGISTRY_NOTARY_IMAGE:-ghcr.io/jeremi/registry-notary@sha256:abc}"
        compose["services"]["openfn-dhis2-sidecar"][
            "image"
        ] = "${REGISTRY_NOTARY_OPENFN_SIDECAR_IMAGE:-ghcr.io/jeremi/registry-notary-source-adapter-sidecar@sha256:abc}"

        issues = self._validate(compose, self._valid_esignet())
        self.assertEqual([], issues)

    def test_rejects_floating_config_loader_ref(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["config-loader"]["environment"]["CONFIG_REPO_REF"] = "${CONFIG_REPO_REF:-main}"
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "stale-config-repo-ref")

    def test_rejects_stale_config_loader_ref_across_hosted_apps(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["config-loader"] = {
            "image": "alpine:3.20",
            "environment": {
                "CONFIG_REPO_REF": "registry-stack-technical-preview-2026-06-04"
            },
        }
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "stale-config-repo-ref")

        esignet = self._valid_esignet()
        esignet["services"]["config-loader"]["environment"][
            "CONFIG_REPO_REF"
        ] = "registry-stack-technical-preview-2026-06-04"
        issues = self._validate(self._valid_registry_lab(), esignet)
        self.assertIssue(issues, "stale-config-repo-ref")

        walt = self._valid_walt()
        walt["services"]["config-loader"]["environment"][
            "CONFIG_REPO_REF"
        ] = "registry-stack-technical-preview-2026-06-04"
        issues = self._validate_walt(walt)
        self.assertIssue(issues, "stale-config-repo-ref")

    def test_rejects_static_metadata_publisher_with_remote_image(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["static-metadata-publisher"][
            "image"
        ] = "ghcr.io/jeremi/registry-lab-static-metadata:main"
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "static-metadata-image-name")

    def test_rejects_static_metadata_publisher_without_generator_build(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["static-metadata-publisher"].pop("build")
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "static-metadata-build")

    def test_rejects_static_metadata_publisher_volume_content(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["static-metadata-publisher"]["volumes"] = [
            "static-content:/srv/static:ro"
        ]
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "static-metadata-volume-mount")

    def test_rejects_static_metadata_healthcheck_without_manifest_probe(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["static-metadata-publisher"]["healthcheck"] = {
            "test": ["CMD-SHELL", "python -c 'import urllib.request; urllib.request.urlopen(\"http://127.0.0.1:8080/\").read()'"]
        }
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "static-metadata-healthcheck")

    def test_rejects_config_loader_that_does_not_prepare_relay_cache_volumes(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["config-loader"]["command"] = [
            command.replace("chown -R 65532:65532", "chown -R 1000:1000")
            for command in compose["services"]["config-loader"]["command"]
        ]
        compose["services"]["config-loader"]["volumes"] = [
            volume
            for volume in compose["services"]["config-loader"]["volumes"]
            if not volume.startswith("social-protection-registry-cache:")
        ]
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "runtime-state-not-chowned")

    def test_rejects_config_loader_that_does_not_prepare_openfn_state_volumes(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["config-loader"]["command"] = [
            command.replace(
                "chown -R 1000:1000",
                "chown -R 65532:65532",
            )
            for command in compose["services"]["config-loader"]["command"]
        ]
        compose["services"]["config-loader"]["volumes"] = [
            volume
            for volume in compose["services"]["config-loader"]["volumes"]
            if not volume.startswith("openfn-sidecar-tuf-state:")
            and not volume.startswith("openfn-sidecar-config-state:")
            and not volume.startswith("openfn-sidecar-audit-state:")
        ]
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "runtime-state-not-chowned")

    def test_rejects_config_loader_that_does_not_copy_lab_homepage_scenarios(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["config-loader"]["command"] = [
            command.replace(
                "cp -a /tmp/repo/scripts/lab_homepage_scenarios /out/static-scripts/",
                "",
            )
            for command in compose["services"]["config-loader"]["command"]
        ]
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "lab-homepage-scenarios-not-copied")

    def test_rejects_config_loader_that_does_not_copy_lab_homepage_explorer(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["config-loader"]["command"] = [
            command.replace(
                "cp -a /tmp/repo/scripts/lab_homepage_explorer /out/static-scripts/",
                "",
            )
            for command in compose["services"]["config-loader"]["command"]
        ]
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "lab-homepage-explorer-not-copied")

    def test_rejects_config_loader_that_does_not_copy_lab_homepage_static(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["config-loader"]["command"] = [
            command.replace(
                "cp -a /tmp/repo/scripts/lab_homepage_static /out/static-scripts/",
                "",
            )
            for command in compose["services"]["config-loader"]["command"]
        ]
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "lab-homepage-static-not-copied")

    def test_rejects_config_loader_that_does_not_copy_civil_notary_config(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["config-loader"]["command"] = [
            command.replace(
                "cp -a /tmp/repo/config/coolify/notary/civil-notary.yaml /out/notary/",
                "",
            )
            for command in compose["services"]["config-loader"]["command"]
        ]
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "civil-notary-config-not-copied")

    def test_rejects_config_loader_that_does_not_copy_mounted_product_config(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["extra-notary"] = {
            "image": "${REGISTRY_NOTARY_IMAGE:-ghcr.io/registrystack/registry-notary@sha256:abc}",
            "command": ["--config", "/etc/registry-notary/extra-notary.yaml"],
        }

        issues = self.validator.validate_config_loader_hosted_outputs(
            "registry-lab",
            compose["services"],
        )

        self.assertIssue(issues, "hosted-config-not-copied")

    def test_rejects_duplicate_hosted_yaml_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_dir = root / "config" / "coolify" / "notary"
            config_dir.mkdir(parents=True)
            (config_dir / "duplicate.yaml").write_text(
                "server:\n  bind: 0.0.0.0:8080\n  bind: 127.0.0.1:8080\n",
                encoding="utf-8",
            )

            issues = self.validator.validate_hosted_yaml_files("registry-lab", root)

        self.assertIssue(issues, "duplicate-yaml-key")

    def test_rejects_missing_dhis2_programme_profile_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_dir = root / "config" / "coolify" / "notary"
            config_dir.mkdir(parents=True)
            (config_dir / "dhis2-health-notary.yaml").write_text(
                """
evidence:
  max_credential_validity_seconds: 600
  credential_profiles: {}
  claims: []
""",
                encoding="utf-8",
            )

            issues = self.validator.validate_dhis2_programme_vc_contract("registry-lab", root)

        self.assertIssue(issues, "dhis2-programme-validity-ceiling")
        self.assertIssue(issues, "missing-dhis2-programme-profile")

    def test_rejects_dhis2_programme_profile_missing_reconciliation_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_dir = root / "config" / "coolify" / "notary"
            config_dir.mkdir(parents=True)
            (config_dir / "dhis2-health-notary.yaml").write_text(
                """
evidence:
  max_credential_validity_seconds: 31536000
  credential_profiles:
    dhis2_programme_participation_sd_jwt:
      validity_seconds: 31536000
      allowed_claims:
        - dhis2-tracked-entity-first-name
        - dhis2-tracked-entity-last-name
        - dhis2-child-age-band
        - dhis2-programme-code
        - dhis2-child-program-active
      holder_binding:
        mode: did
        proof_of_possession: required
        allowed_did_methods:
          - did:jwk
  claims:
    - id: dhis2-child-program-active
      credential_profiles:
        - dhis2_programme_participation_sd_jwt
""",
                encoding="utf-8",
            )

            issues = self.validator.validate_dhis2_programme_vc_contract("registry-lab", root)

        self.assertIssue(issues, "dhis2-programme-claims-missing")

    def test_rejects_notary_credential_commitment_mismatch_in_strict_env(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_dir = root / "config" / "coolify" / "notary"
            config_dir.mkdir(parents=True)
            (config_dir / "notary.yaml").write_text(
                """
auth:
  mode: api_key
  bearer_tokens:
    - id: hosted_civil_evidence_client
      fingerprint:
        provider: env
        name: CIVIL_EVIDENCE_CLIENT_BEARER_HASH
        commitment: sha256:0000000000000000000000000000000000000000000000000000000000000000
""",
                encoding="utf-8",
            )

            issues = self.validator.validate_credential_commitments(
                "registry-lab",
                root,
                {
                    "CIVIL_EVIDENCE_CLIENT_BEARER_HASH": (
                        "sha256:f6091e63acf60468a49a94982b1143f5c88802ab35747bb5cd22839fc21620a5"
                    )
                },
            )

        self.assertIssue(issues, "credential-commitment-mismatch")

    def test_rejects_relay_credential_commitment_mismatch_in_strict_env(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_dir = root / "config" / "coolify" / "relay"
            config_dir.mkdir(parents=True)
            (config_dir / "relay.yaml").write_text(
                """
auth:
  mode: api_key
  api_keys:
    - id: metadata_client
      fingerprint:
        provider: env
        name: CIVIL_METADATA_CLIENT_HASH
        commitment: sha256:0000000000000000000000000000000000000000000000000000000000000000
""",
                encoding="utf-8",
            )

            issues = self.validator.validate_credential_commitments(
                "registry-lab",
                root,
                {
                    "CIVIL_METADATA_CLIENT_HASH": (
                        "sha256:54e6c08b6ce02c56d258b4f40313d8ec7a2cf9a222fdfa88789d720cb923c254"
                    )
                },
            )

        self.assertIssue(issues, "credential-commitment-mismatch")

    @staticmethod
    def _stub_manifest_oracle(root: Path) -> list[str]:
        """A stand-in for registry-manifest-cli: digest = sha256 of file bytes."""
        stub = root / "stub-manifest-oracle.py"
        stub.write_text(
            """
import hashlib
import sys

path = sys.argv[2]
data = open(path, "rb").read()
if b"INVALID" in data:
    sys.stderr.write("metadata manifest failed validation\\n")
    raise SystemExit(1)
print(f"metadata manifest valid: {path}")
print("source_manifest_digest: sha256:" + hashlib.sha256(data).hexdigest())
""",
            encoding="utf-8",
        )
        return [sys.executable, str(stub)]

    @staticmethod
    def _write_pinned_relay_config(root: Path, manifest_text: str, digest: str) -> Path:
        config_dir = root / "config" / "coolify" / "relay"
        config_dir.mkdir(parents=True)
        (config_dir / "civil.metadata.yaml").write_text(manifest_text, encoding="utf-8")
        config_path = config_dir / "civil.yaml"
        config_path.write_text(
            f"""
metadata:
  source:
    path: civil.metadata.yaml
    digest: {digest}
""",
            encoding="utf-8",
        )
        return config_path

    def test_metadata_digest_pins_pass_with_matching_oracle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_text = "title: Civil Registry Metadata\n"
            digest = "sha256:" + hashlib.sha256(manifest_text.encode("utf-8")).hexdigest()
            self._write_pinned_relay_config(root, manifest_text, digest)

            issues = self.validator.validate_metadata_digest_pins(
                "registry-lab", root, {}, manifest_cli=self._stub_manifest_oracle(root)
            )

        self.assertEqual([], issues)

    def test_rejects_metadata_digest_pin_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stale = "sha256:" + "0" * 64
            self._write_pinned_relay_config(root, "title: Civil Registry Metadata\n", stale)

            issues = self.validator.validate_metadata_digest_pins(
                "registry-lab", root, {}, manifest_cli=self._stub_manifest_oracle(root)
            )

        self.assertIssue(issues, "metadata-digest-mismatch")

    def test_rejects_missing_metadata_manifest_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_pinned_relay_config(root, "title: x\n", "sha256:" + "0" * 64)
            (root / "config" / "coolify" / "relay" / "civil.metadata.yaml").unlink()

            issues = self.validator.validate_metadata_digest_pins(
                "registry-lab", root, {}, manifest_cli=self._stub_manifest_oracle(root)
            )

        self.assertIssue(issues, "metadata-manifest-missing")

    def test_rejects_invalid_metadata_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_pinned_relay_config(root, "INVALID\n", "sha256:" + "0" * 64)

            issues = self.validator.validate_metadata_digest_pins(
                "registry-lab", root, {}, manifest_cli=self._stub_manifest_oracle(root)
            )

        self.assertIssue(issues, "metadata-manifest-invalid")
        self.assertNoIssue(issues, "metadata-digest-mismatch")

    def test_metadata_digest_check_fails_without_oracle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_pinned_relay_config(root, "title: x\n", "sha256:" + "0" * 64)

            issues = self.validator.validate_metadata_digest_pins("registry-lab", root, {})

        self.assertIssue(issues, "metadata-digest-oracle-missing")

    def test_metadata_digest_check_resolves_oracle_from_env(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_text = "title: Civil Registry Metadata\n"
            digest = "sha256:" + hashlib.sha256(manifest_text.encode("utf-8")).hexdigest()
            self._write_pinned_relay_config(root, manifest_text, digest)
            oracle = " ".join(self._stub_manifest_oracle(root))

            issues = self.validator.validate_metadata_digest_pins(
                "registry-lab", root, {"REGISTRY_MANIFEST_CLI": oracle}
            )

        self.assertEqual([], issues)

    def test_metadata_digest_check_honors_skip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_pinned_relay_config(root, "title: x\n", "sha256:" + "0" * 64)

            issues = self.validator.validate_metadata_digest_pins(
                "registry-lab", root, {}, skip=True
            )

        self.assertEqual([], issues)

    def test_metadata_digest_check_ignores_configs_without_pins(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_dir = root / "config" / "coolify" / "relay"
            config_dir.mkdir(parents=True)
            (config_dir / "civil.yaml").write_text("server:\n  bind: 0.0.0.0:8080\n", encoding="utf-8")

            issues = self.validator.validate_metadata_digest_pins("registry-lab", root, {})

        self.assertEqual([], issues)

    def test_repo_relay_configs_pin_metadata_digests(self) -> None:
        relay_dir = SCRIPT_DIR.parent / "config" / "coolify" / "relay"
        configs = [
            path
            for path in sorted(relay_dir.glob("*.yaml"))
            if not path.name.endswith(".metadata.yaml")
        ]
        self.assertTrue(configs, f"no relay configs found in {relay_dir}")
        for path in configs:
            with self.subTest(path=path.name):
                config = self.validator.load_yaml_mapping_strict(path)
                source = config.get("metadata", {}).get("source", {})
                self.assertRegex(source.get("digest", ""), r"^sha256:[0-9a-f]{64}$")
                self.assertTrue((path.parent / source["path"]).is_file())

    def test_repo_relay_configs_expose_refreshed_attestation_source_surfaces(self) -> None:
        expected = {
            "civil-registry-relay.yaml": {
                "tables": {
                    "civil_person_details_table",
                    "civil_identifiers_table",
                    "birth_events_table",
                    "death_events_table",
                    "civil_status_records_table",
                    "certificates_table",
                    "relationships_table",
                },
                "entities": {
                    "civil_person_detail",
                    "civil_identifier",
                    "birth_event",
                    "death_event",
                    "civil_status_record",
                    "certificate",
                    "relationship",
                },
            },
            "social-protection-registry-relay.yaml": {
                "tables": {
                    "group_memberships_table",
                    "socio_economic_profiles_table",
                    "scoring_events_table",
                    "programs_table",
                    "entitlements_table",
                    "payment_events_table",
                    "functioning_profiles_table",
                    "disability_determinations_table",
                },
                "entities": {
                    "household_membership",
                    "socio_economic_profile",
                    "scoring_event",
                    "program",
                    "entitlement",
                    "payment_event",
                    "functioning_profile",
                    "disability_determination",
                },
            },
        }
        for config_dir in (SCRIPT_DIR.parent / "config" / "relay", SCRIPT_DIR.parent / "config" / "coolify" / "relay"):
            for filename, contract in expected.items():
                with self.subTest(config_dir=config_dir.relative_to(SCRIPT_DIR.parent), filename=filename):
                    config = self.validator.load_yaml_mapping_strict(config_dir / filename)
                    dataset = config["datasets"][0]
                    table_ids = {table["id"] for table in dataset.get("tables", [])}
                    entity_names = {entity["name"] for entity in dataset.get("entities", [])}
                    self.assertTrue(contract["tables"].issubset(table_ids), sorted(contract["tables"] - table_ids))
                    self.assertTrue(contract["entities"].issubset(entity_names), sorted(contract["entities"] - entity_names))

    def test_repo_relay_table_sources_exist_in_generated_fixture_data(self) -> None:
        repo = SCRIPT_DIR.parent
        for config_dir in (repo / "config" / "relay", repo / "config" / "coolify" / "relay"):
            for path in sorted(config_dir.glob("*-registry-relay.yaml")):
                config = self.validator.load_yaml_mapping_strict(path)
                for dataset in config.get("datasets", []):
                    for table in dataset.get("tables", []):
                        with self.subTest(config=path.relative_to(repo), table=table.get("id")):
                            source = table.get("source", {})
                            source_path = self._fixture_path(repo, source.get("path", ""))
                            self.assertTrue(source_path.is_file(), source_path)
                            fmt = source.get("format", {})
                            if "xlsx" in fmt:
                                self.assertIn(fmt["xlsx"]["sheet"], self._xlsx_sheet_names(source_path))

    @staticmethod
    def _non_empty_list(value: object) -> bool:
        return isinstance(value, list) and bool(value)

    @staticmethod
    def _non_empty_mapping(value: object) -> bool:
        return isinstance(value, dict) and bool(value)

    def _source_bound_notary_purpose_constraint_issues(
        self,
        *,
        repo: Path,
        path: Path,
        config: dict,
    ) -> list[str]:
        issues = []
        evidence = config.get("evidence", {})
        if not isinstance(evidence, dict) or not evidence.get("enabled"):
            return issues

        global_purposes = evidence.get("allowed_purposes", [])
        claims = evidence.get("claims", [])
        if not isinstance(claims, list):
            return [f"{path.relative_to(repo)} evidence.claims must be a list"]

        for claim in claims:
            if not isinstance(claim, dict):
                issues.append(f"{path.relative_to(repo)} claim must be a mapping")
                continue
            source_bindings = claim.get("source_bindings", {})
            if source_bindings is None:
                continue
            if not isinstance(source_bindings, dict):
                issues.append(
                    f"{path.relative_to(repo)} claim={claim.get('id')} source_bindings must be a mapping"
                )
                continue
            if not source_bindings:
                continue
            claim_purpose = claim.get("purpose")
            for binding_id, binding in source_bindings.items():
                if not isinstance(binding, dict):
                    issues.append(
                        f"{path.relative_to(repo)} claim={claim.get('id')} binding={binding_id} must be a mapping"
                    )
                    continue
                matching = binding.get("matching", {})
                if not isinstance(matching, dict):
                    issues.append(
                        f"{path.relative_to(repo)} claim={claim.get('id')} binding={binding_id} matching must be a mapping"
                    )
                    continue
                has_purpose_constraint = any(
                    (
                        self._non_empty_list(global_purposes),
                        isinstance(claim_purpose, str) and bool(claim_purpose),
                        self._non_empty_list(matching.get("allowed_purposes", [])),
                        self._non_empty_mapping(matching.get("relationship_purpose_scopes", {})),
                    )
                )
                if not has_purpose_constraint:
                    issues.append(
                        f"{path.relative_to(repo)} claim={claim.get('id')} binding={binding_id}"
                    )

        return issues

    def test_repo_source_bound_notary_claims_have_purpose_constraints(self) -> None:
        repo = SCRIPT_DIR.parent
        issues = []
        for config_dir in (repo / "config" / "notary", repo / "config" / "coolify" / "notary"):
            for path in sorted(config_dir.glob("*.yaml")):
                config = self.validator.load_yaml_mapping_strict(path)
                issues.extend(
                    self._source_bound_notary_purpose_constraint_issues(
                        repo=repo,
                        path=path,
                        config=config,
                    )
                )

        self.assertEqual([], issues)

    def test_source_bound_notary_purpose_constraint_check_handles_malformed_yaml(self) -> None:
        repo = SCRIPT_DIR.parent
        path = repo / "config" / "notary" / "malformed-notary.yaml"
        issues = self._source_bound_notary_purpose_constraint_issues(
            repo=repo,
            path=path,
            config={
                "evidence": {
                    "enabled": True,
                    "allowed_purposes": None,
                    "claims": [
                        None,
                        {"id": "claim-with-null-bindings", "source_bindings": None},
                        {"id": "claim-with-list-bindings", "source_bindings": []},
                        {"id": "claim-with-null-binding", "source_bindings": {"birth": None}},
                        {"id": "claim-with-bad-matching", "source_bindings": {"birth": {"matching": []}}},
                        {"id": "claim-without-purpose", "source_bindings": {"birth": {"matching": {}}}},
                    ],
                }
            },
        )

        self.assertIn("config/notary/malformed-notary.yaml claim must be a mapping", issues)
        self.assertIn(
            "config/notary/malformed-notary.yaml claim=claim-with-list-bindings source_bindings must be a mapping",
            issues,
        )
        self.assertIn(
            "config/notary/malformed-notary.yaml claim=claim-with-null-binding binding=birth must be a mapping",
            issues,
        )
        self.assertIn(
            "config/notary/malformed-notary.yaml claim=claim-with-bad-matching binding=birth matching must be a mapping",
            issues,
        )
        self.assertIn(
            "config/notary/malformed-notary.yaml claim=claim-without-purpose binding=birth",
            issues,
        )

    def test_repo_relay_runtime_entities_and_fields_exist_in_metadata_manifests(self) -> None:
        repo = SCRIPT_DIR.parent
        for config_dir in (repo / "config" / "relay", repo / "config" / "coolify" / "relay"):
            for path in sorted(config_dir.glob("*-registry-relay.yaml")):
                config = self.validator.load_yaml_mapping_strict(path)
                metadata_source = config.get("metadata", {}).get("source", {})
                metadata_path = path.parent / metadata_source.get("path", "")
                metadata = self.validator.load_yaml_mapping_strict(metadata_path)
                metadata_datasets = {
                    dataset.get("id"): dataset
                    for dataset in metadata.get("datasets", [])
                    if isinstance(dataset, dict)
                }
                for dataset in config.get("datasets", []):
                    with self.subTest(config=path.relative_to(repo), dataset=dataset.get("id")):
                        runtime_entities = {entity["name"] for entity in dataset.get("entities", [])}
                        manifest_entities_by_name = {
                            entity["name"]: entity
                            for entity in metadata_datasets[dataset["id"]].get("entities", [])
                        }
                        manifest_entities = set(manifest_entities_by_name)
                        self.assertTrue(runtime_entities.issubset(manifest_entities), sorted(runtime_entities - manifest_entities))
                    for entity in dataset.get("entities", []):
                        runtime_fields = {field["name"] for field in entity.get("fields", [])}
                        manifest_fields = {
                            field["name"]
                            for field in manifest_entities_by_name[entity["name"]].get("fields", [])
                        }
                        with self.subTest(
                            config=path.relative_to(repo),
                            dataset=dataset.get("id"),
                            entity=entity.get("name"),
                        ):
                            self.assertTrue(runtime_fields.issubset(manifest_fields), sorted(runtime_fields - manifest_fields))

    def test_hosted_workflow_does_not_skip_metadata_digest_pins(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertNotIn("--skip-metadata-digest-pins", workflow)

    def test_parse_args_supports_metadata_digest_flags(self) -> None:
        args = self.validator.parse_args(["--skip-metadata-digest-pins"])
        self.assertTrue(args.skip_metadata_digest_pins)
        args = self.validator.parse_args(["--manifest-cli", "/tmp/registry-manifest"])
        self.assertEqual(Path("/tmp/registry-manifest"), args.manifest_cli)

    def test_repo_static_metadata_uses_public_attestation_labels(self) -> None:
        issues = self.validator.validate_attestation_metadata_contract(
            "registry-lab",
            SCRIPT_DIR.parent,
        )
        self.assertEqual([], issues, [str(issue) for issue in issues])

    def test_rejects_static_metadata_without_public_attestation_label(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata_dir = root / "config" / "static-metadata"
            metadata_dir.mkdir(parents=True)
            (metadata_dir / "metadata.yaml").write_text(
                """
datasets:
  - id: civil_registry
    evidence_offerings:
      - id: civil_child_status_evidence_service
        title: Civil vital status evidence service
        attestation_id: vital-status-attestation
        compatibility_claim_ids:
          - person-is-alive
""",
                encoding="utf-8",
            )

            issues = self.validator.validate_attestation_metadata_contract(
                "registry-lab",
                root,
            )

        self.assertIssue(issues, "attestation-public-label")
        self.assertIssue(issues, "attestation-raw-claim-ids-public")

    def test_rejects_static_metadata_with_public_raw_claim_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata_dir = root / "config" / "static-metadata"
            metadata_dir.mkdir(parents=True)
            (metadata_dir / "metadata.yaml").write_text(
                """
datasets:
  - id: civil_registry
    evidence_offerings:
      - id: civil_child_status_evidence_service
        title: Vital Status Attestation
        attestation_id: vital-status-attestation
        compatibility_claim_ids:
          - person-is-alive
""",
                encoding="utf-8",
            )

            issues = self.validator.validate_attestation_metadata_contract(
                "registry-lab",
                root,
            )

        self.assertIssue(issues, "attestation-raw-claim-ids-public")

    def test_rejects_localhost_public_urls(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["citizen-civil-notary"]["environment"][
            "CITIZEN_OID4VCI_CREDENTIAL_ISSUER"
        ] = "http://localhost:4321"
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "public-local-url")

    def test_rejects_loopback_public_urls(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["citizen-civil-notary"]["environment"][
            "ESIGNET_DISCOVERY_URL"
        ] = "http://127.0.0.1:8088/v1/esignet/oidc/.well-known/openid-configuration"
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "public-local-url")

    def test_rejects_stale_http_public_urls(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["citizen-civil-notary"]["environment"][
            "CITIZEN_OID4VCI_CREDENTIAL_ENDPOINT"
        ] = "http://citizen-notary.lab.registrystack.org/oid4vci/credential"
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "public-http-url")

    def test_rejects_demo_example_public_urls(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["dhis2-health-notary"]["environment"][
            "REGISTRY_NOTARY_PUBLIC_API_BASE_URL"
        ] = "https://demo.example.gov/dhis2"
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "stale-demo-url")

    def test_rejects_missing_required_lab_domain(self) -> None:
        compose = self._valid_registry_lab()
        del compose["x-hosted-domains"]["civil-registry-relay"]
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "missing-domain")

    def test_rejects_seed_output_under_repo_output(self) -> None:
        esignet = self._valid_esignet()
        esignet["services"]["esignet-seed"] = {
            "image": "python:3.12-alpine",
            "volumes": ["./output/esignet-live:/output"],
        }
        issues = self._validate(self._valid_registry_lab(), esignet)
        self.assertIssue(issues, "repo-output-bind")

    def test_rejects_missing_required_services(self) -> None:
        compose = self._valid_registry_lab()
        del compose["services"]["citizen-civil-notary"]
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "missing-service")

    def test_rejects_missing_required_esignet_bootstrap_services(self) -> None:
        for service in ("config-loader", "esignet-seed"):
            with self.subTest(service=service):
                esignet = self._valid_esignet()
                del esignet["services"][service]
                issues = self._validate(self._valid_registry_lab(), esignet)
                self.assertIssue(issues, "missing-service")

    def test_rejects_missing_civil_alive_notary_wiring(self) -> None:
        compose = self._valid_registry_lab()
        del compose["services"]["lab-homepage"]["environment"]["CIVIL_EVIDENCE_URL"]
        del compose["services"]["lab-homepage"]["environment"]["CIVIL_EVIDENCE_CLIENT_BEARER"]
        del compose["services"]["civil-notary"]["environment"]["CIVIL_EVIDENCE_CLIENT_BEARER_HASH"]

        issues = self._validate(compose, self._valid_esignet())

        self.assertIssue(issues, "missing-civil-alive-notary-url")
        self.assertIssue(issues, "missing-civil-alive-notary-bearer")
        self.assertIssue(issues, "missing-civil-notary-bearer-hash")

    def test_rejects_missing_hosted_social_combined_wiring(self) -> None:
        compose = self._valid_registry_lab()
        del compose["services"]["lab-homepage"]["environment"]["SOCIAL_RELAY_URL"]
        del compose["services"]["lab-homepage"]["environment"]["SHARED_EVIDENCE_URL"]
        del compose["services"]["lab-homepage"]["environment"]["SHARED_EVIDENCE_CLIENT_BEARER"]
        del compose["services"]["shared-eligibility-notary"]["environment"]["SHARED_EVIDENCE_CLIENT_BEARER_HASH"]
        del compose["services"]["shared-eligibility-notary"]["environment"]["SHARED_SOCIAL_EVIDENCE_SOURCE_RAW"]

        issues = self._validate(compose, self._valid_esignet())

        self.assertIssue(issues, "missing-hosted-scenario-url")
        self.assertIssue(issues, "missing-combined-support-bearer")
        self.assertIssue(issues, "missing-shared-notary-client-hash")
        self.assertIssue(issues, "missing-shared-notary-source-token")

    def test_rejects_lab_homepage_without_config_repo_ref(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["lab-homepage"]["environment"].pop("CONFIG_REPO_REF", None)
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "lab-homepage-missing-config-ref")

    def test_accepts_lab_homepage_config_repo_ref_placeholder(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["lab-homepage"]["environment"][
            "CONFIG_REPO_REF"
        ] = "hosted-validation-placeholder"
        issues = self._validate(compose, self._valid_esignet())
        self.assertNoIssue(issues, "lab-homepage-missing-config-ref")

    def test_rejects_shared_notary_config_with_wrong_public_url(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_dir = root / "config/coolify/notary"
            config_dir.mkdir(parents=True)
            (config_dir / "shared-eligibility-notary.yaml").write_text(
                """
evidence:
  api_base_url: http://shared-eligibility-notary:8080
  source_connections:
    civil:
      base_url: https://civil-relay.lab.registrystack.org
      token_env: SHARED_CIVIL_EVIDENCE_SOURCE_RAW
    social_protection:
      base_url: http://social-protection-registry-relay:8080
      token_env: SHARED_SOCIAL_EVIDENCE_SOURCE_RAW
    health:
      base_url: https://health-relay.lab.registrystack.org
      token_env: SHARED_HEALTH_EVIDENCE_SOURCE_RAW
  credential_profiles:
    combined_support_sd_jwt:
      issuer: did:web:shared-notary.lab.registrystack.org
""",
                encoding="utf-8",
            )
            issues = self.validator.validate_shared_notary_hosted_config(root)
        self.assertIssue(issues, "shared-notary-public-url-mismatch")

    def test_rejects_shared_notary_metadata_with_local_only_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata_dir = root / "config/coolify/relay"
            metadata_dir.mkdir(parents=True)
            (metadata_dir / "health-registry-relay.metadata.yaml").write_text(
                "discovery_url: https://metadata.lab.registrystack.org/local-only/shared-eligibility-notary/.well-known/evidence-service\n",
                encoding="utf-8",
            )
            issues = self.validator.validate_shared_notary_hosted_metadata(root)
        self.assertIssue(issues, "shared-notary-metadata-url-mismatch")

    def test_rejects_missing_civil_notary_config(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["civil-notary"]["command"] = [
            "--config",
            "/etc/registry-notary/citizen-civil-notary.yaml",
        ]

        issues = self._validate(compose, self._valid_esignet())

        self.assertIssue(issues, "missing-civil-notary-config")

    def test_rejects_localhost_urls_in_mounted_hosted_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "citizen-civil-notary.yaml").write_text(
                "oid4vci:\n  credential_issuer: http://localhost:4321\n",
                encoding="utf-8",
            )
            compose = self._valid_registry_lab()
            compose["services"]["citizen-civil-notary"]["volumes"] = [
                "./citizen-civil-notary.yaml:/etc/registry-notary/citizen-civil-notary.yaml:ro"
            ]
            issues = self.validator.validate_artifacts(
                {
                    "registry-lab": compose,
                    "esignet": self._valid_esignet(),
                },
                {"registry-lab": root, "esignet": root},
            )
        self.assertIssue(issues, "public-local-url")

    def test_rejects_stale_urls_in_directory_binds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_dir = root / "relay"
            config_dir.mkdir()
            (config_dir / "civil-registry-relay.yaml").write_text(
                "catalog:\n  participant_id: did:web:civil-registry.demo.example.gov\n",
                encoding="utf-8",
            )
            compose = self._valid_registry_lab()
            compose["services"]["civil-registry-relay"]["volumes"] = [
                "./relay:/etc/registry-relay:ro"
            ]
            issues = self.validator.validate_artifacts(
                {
                    "registry-lab": compose,
                    "esignet": self._valid_esignet(),
                },
                {"registry-lab": root, "esignet": root},
            )
        self.assertIssue(issues, "stale-demo-url")

    def test_rejects_missing_required_hosted_variable_reference(self) -> None:
        compose = self._valid_registry_lab()
        del compose["services"]["postgres"]["environment"]["DHIS2_EVIDENCE_CLIENT_TOKEN_HASH"]
        del compose["services"]["dhis2-health-notary"]["environment"][
            "DHIS2_EVIDENCE_CLIENT_TOKEN_HASH"
        ]
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "missing-required-variable")

    def test_strict_mode_rejects_missing_secret_values(self) -> None:
        issues = self.validator.validate_artifacts(
            {
                "registry-lab": self._valid_registry_lab(),
                "esignet": self._valid_esignet(),
            },
            require_secret_values=True,
            env={},
        )
        self.assertIssue(issues, "missing-required-secret-value")

    def test_hosted_workflow_declares_minimal_permissions(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertRegex(workflow, r"(?m)^permissions:\n\s+contents: read$")
        self.assertRegex(
            workflow,
            r"(?m)^  deploy-coolify:\n(?:.*\n)*?    permissions:\n      contents: read$",
        )

    def test_hosted_workflow_deploys_all_coolify_apps_by_api(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn("COOLIFY_API_TOKEN", workflow)
        self.assertIn("::error::COOLIFY_API_TOKEN is not configured.", workflow)
        self.assertNotIn("hosted deploy trigger skipped", workflow)
        self.assertIn("scripts/check-coolify-required-env.py", workflow)
        self.assertIn("scripts/sync-coolify-compose-domains.py", workflow)
        self.assertIn("citizen-portal=https://portal.lab.registrystack.org:3000", workflow)
        self.assertIn("--compose compose.coolify.yaml", workflow)
        self.assertIn("--compose compose.esignet-hosted.yaml", workflow)
        self.assertIn("--attempts 6", workflow)
        self.assertIn("monolith-domain-sync", workflow)
        self.assertIn(
            '"${api_base}/deploy?uuid=${COOLIFY_REGISTRY_LAB_APP_UUID}&force=false"',
            workflow,
        )
        self.assertNotIn(
            '"${api_base}/deploy?uuid=${COOLIFY_REGISTRY_LAB_APP_UUID}&force=true"',
            workflow,
        )
        self.assertIn("https://portal.lab.registrystack.org|24", workflow)
        compose = self.validator.load_yaml_mapping(SCRIPT_DIR.parent / "compose.coolify.yaml")
        hosted_domains = compose["x-hosted-domains"]
        for service, domain in self.validator.REQUIRED_DOMAINS["registry-lab"].items():
            with self.subTest(service=service):
                self.assertEqual(domain, hosted_domains[service])
        initial_deploy_done = workflow.index('done < "$deployments_file"')
        domain_sync = workflow.rindex("python3 scripts/sync-coolify-compose-domains.py")
        portal_route_probe = workflow.index('"citizen-portal|https://portal.lab.registrystack.org|24"')
        self.assertLess(initial_deploy_done, domain_sync)
        self.assertLess(domain_sync, portal_route_probe)
        self.assertNotIn("COOLIFY_DEPLOY_WEBHOOK_URL", workflow)
        self.assertIn("${{ vars.COOLIFY_REGISTRY_LAB_APP_UUID }}", workflow)
        self.assertIn("${{ vars.COOLIFY_HOSTED_ESIGNET_APP_UUID }}", workflow)
        self.assertIn("${{ vars.COOLIFY_HOSTED_WALT_APP_UUID }}", workflow)
        self.assertIn("${{ vars.COOLIFY_HOSTED_SOCIAL_APP_UUID }}", workflow)
        self.assertIn("${{ vars.COOLIFY_HOSTED_AGRI_APP_UUID }}", workflow)
        self.assertIn("/applications/${app}/envs", workflow)
        self.assertIn('"key": "CONFIG_REPO_REF"', workflow)
        self.assertIn('os.environ["GITHUB_SHA"]', workflow)
        self.assertIn("/deployments/${deployment_uuid}", workflow)
        self.assertIn("python3 scripts/hosted-smoke.py", workflow)
        self.assertNotIn("klhnsuoye8lwuamp0bko387t", workflow)
        self.assertNotIn("cewwn93kknzsfzicen9nul6v", workflow)
        self.assertNotIn("uvqfk8gwqdbdse4v871xfv56", workflow)

    def test_hosted_workflow_rejects_interim_product_images(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn("--reject-interim-product-images", workflow)

    def test_image_pin_workflow_validates_digest_inputs_and_smokes(self) -> None:
        workflow = IMAGE_PIN_WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn("validate_image REGISTRY_RELAY_IMAGE", workflow)
        self.assertIn("validate_image REGISTRY_LAB_ESIGNET_RELAY_IMAGE", workflow)
        self.assertIn("validate_image REGISTRY_LAB_ESIGNET_SEED_IMAGE", workflow)
        self.assertIn("@sha256:[0-9a-f]{64}", workflow)
        self.assertIn("COOLIFY_HOSTED_ESIGNET_APP_UUID", workflow)
        self.assertIn("COOLIFY_HOSTED_SOCIAL_APP_UUID", workflow)
        self.assertIn("COOLIFY_HOSTED_AGRI_APP_UUID", workflow)
        self.assertIn('patch_env "${COOLIFY_HOSTED_ESIGNET_APP_UUID}" esignet REGISTRY_LAB_ESIGNET_RELAY_IMAGE', workflow)
        self.assertIn('patch_env "${COOLIFY_HOSTED_ESIGNET_APP_UUID}" esignet REGISTRY_LAB_ESIGNET_SEED_IMAGE', workflow)
        self.assertIn('patch_product_images "${COOLIFY_HOSTED_SOCIAL_APP_UUID}" social', workflow)
        self.assertIn('patch_product_images "${COOLIFY_HOSTED_AGRI_APP_UUID}" agri', workflow)
        self.assertIn("/deployments/${deployment_uuid}", workflow)
        self.assertIn("python3 scripts/hosted-smoke.py", workflow)

    def test_build_images_workflow_publishes_esignet_images(self) -> None:
        workflow = (SCRIPT_DIR.parent / ".github" / "workflows" / "build-images.yml").read_text(encoding="utf-8")
        self.assertIn("Dockerfile.esignet-relay", workflow)
        self.assertIn("Dockerfile.esignet-seed", workflow)
        self.assertIn("esignet_relay_authenticator_src=vendor/esignet-relay-authenticator", workflow)
        self.assertIn("REGISTRY_LAB_ESIGNET_RELAY_IMAGE=ghcr.io/${owner}/registry-lab-esignet-relay@", workflow)
        self.assertIn("REGISTRY_LAB_ESIGNET_SEED_IMAGE=ghcr.io/${owner}/registry-lab-esignet-seed@", workflow)

    def test_hosted_workflow_paths_cover_deployment_automation(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        for path in (
            "scripts/credential-commitment.py",
            "scripts/test_credential_commitment.py",
            "scripts/test_dhis2_programme_vc_config.py",
            "scripts/generate-holder-proof.js",
            "scripts/summarize-dhis2-programme-vc.py",
            "scripts/hosted-smoke.py",
            "scripts/test_hosted_smoke.py",
            "scripts/sync-coolify-compose-domains.py",
            "scripts/test_sync_coolify_compose_domains.py",
        ):
            self.assertIn(path, workflow)

    def test_hosted_config_loaders_fetch_exact_config_ref(self) -> None:
        for path in (
            SCRIPT_DIR.parent / "compose.coolify.yaml",
            SCRIPT_DIR.parent / "compose.esignet-hosted.yaml",
            SCRIPT_DIR.parent / "compose.social-hosted.yaml",
            SCRIPT_DIR.parent / "compose.agri-hosted.yaml",
            SCRIPT_DIR.parent / "compose.walt-hosted.yaml",
        ):
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIn(
                    "CONFIG_REPO_REF: ${CONFIG_REPO_REF:?set CONFIG_REPO_REF to the deployed registry-lab git ref}",
                    text,
                )
                self.assertNotIn('--branch "$$CONFIG_REPO_REF"', text)
                self.assertIn(
                    'git -C /tmp/repo fetch --depth 1 origin "$$CONFIG_REPO_REF"',
                    text,
                )
                self.assertRegex(text, r"git -C /tmp/repo .*checkout .*FETCH_HEAD")

    def test_hosted_relays_recreate_when_deployed_config_ref_changes(self) -> None:
        compose = self.validator.load_yaml_mapping(SCRIPT_DIR.parent / "compose.coolify.yaml")
        for service in (
            "civil-registry-relay",
            "health-registry-relay",
        ):
            with self.subTest(service=service):
                env = self.validator.normalize_environment(
                    compose["services"][service]["environment"]
                )
                self.assertEqual(
                    "${CONFIG_REPO_REF:?set CONFIG_REPO_REF to the deployed registry-lab git ref}",
                    env.get("CONFIG_REPO_REF"),
                )

    def test_rejects_esignet_issuer_mismatch(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["citizen-civil-notary"]["environment"][
            "ESIGNET_ISSUER"
        ] = "https://esignet.lab.registrystack.org/v1/esignet"
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "esignet-issuer-mismatch")

    def test_rejects_missing_oid4vci_configuration_assertions(self) -> None:
        compose = self._valid_registry_lab()
        del compose["services"]["citizen-civil-notary"]["command"]
        compose["services"]["citizen-civil-notary"]["environment"][
            "CITIZEN_OID4VCI_CREDENTIAL_CONFIGURATION_ID"
        ] = "citizen_civil_status_sd_jwt"
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "missing-credential-configuration")

        compose = self._valid_registry_lab()
        del compose["services"]["citizen-civil-notary"]["command"]
        compose["services"]["citizen-civil-notary"]["environment"][
            "CITIZEN_OID4VCI_FORMAT"
        ] = "jwt_vc_json"
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "missing-oid4vci-format")

    def test_reads_named_volume_notary_config_for_oid4vci_assertions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_dir = root / "config" / "coolify" / "notary"
            config_dir.mkdir(parents=True)
            (config_dir / "citizen-civil-notary.yaml").write_text(
                """
oid4vci:
  credential_configurations:
    person_is_alive_sd_jwt:
      format: dc+sd-jwt
    crvs_birth_certificate_sd_jwt:
      format: dc+sd-jwt
""",
                encoding="utf-8",
            )
            compose = self._valid_registry_lab()
            env = compose["services"]["citizen-civil-notary"]["environment"]
            del env["CITIZEN_OID4VCI_CREDENTIAL_CONFIGURATION_ID"]
            del env["CITIZEN_OID4VCI_FORMAT"]
            compose["services"]["citizen-civil-notary"]["command"] = [
                "--config",
                "/etc/registry-notary/citizen-civil-notary.yaml",
            ]
            compose["services"]["citizen-civil-notary"]["volumes"] = [
                "cfg-notary:/etc/registry-notary:ro"
            ]
            issues = self.validator.validate_artifacts(
                {
                    "registry-lab": compose,
                    "esignet": self._valid_esignet(),
                },
                {"registry-lab": root, "esignet": root},
            )

        self.assertNoIssue(issues, "missing-credential-configuration")
        self.assertNoIssue(issues, "missing-oid4vci-format")

    def test_rejects_unsupported_hosted_notary_dci_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_dir = root / "config" / "coolify" / "notary"
            config_dir.mkdir(parents=True)
            (config_dir / "citizen-civil-notary.yaml").write_text(
                """
evidence:
  source_connections:
    civil:
      dci:
        search_path: /dci/crvs/registry/sync/search
        version: "1.0.0"
""",
                encoding="utf-8",
            )
            issues = self.validator.validate_artifacts(
                {
                    "registry-lab": self._valid_registry_lab(),
                    "esignet": self._valid_esignet(),
                },
                {"registry-lab": root, "esignet": root},
            )

        self.assertIssue(issues, "unsupported-notary-dci-field")

    def test_rejects_unsupported_hosted_notary_source_connectors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_dir = root / "config" / "coolify" / "notary"
            config_dir.mkdir(parents=True)
            (config_dir / "dhis2-health-notary.yaml").write_text(
                """
evidence:
  source_connections:
    dhis2_openfn:
      base_url: http://openfn-dhis2-sidecar:8080
  claims:
    - id: dhis2-tracked-entity-first-name
      source_bindings:
        dhis2:
          connector: openfn_sidecar
""",
                encoding="utf-8",
            )
            issues = self.validator.validate_artifacts(
                {
                    "registry-lab": self._valid_registry_lab(),
                    "esignet": self._valid_esignet(),
                },
                {"registry-lab": root, "esignet": root},
            )

        self.assertIssue(issues, "unsupported-notary-source-connector")

    def test_rejects_self_attestation_claim_purpose_outside_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_dir = root / "config" / "coolify" / "notary"
            config_dir.mkdir(parents=True)
            (config_dir / "citizen-civil-notary.yaml").write_text(
                """
evidence:
  source_connections:
    civil:
      base_url: http://civil-registry-relay:8080
  claims:
    - id: birth.certificate_summary
      purpose: citizen_self_attestation
self_attestation:
  allowed_purposes:
    - https://demo.example.gov/purpose/civil-certificate-evidence
  allowed_claims:
    - birth.certificate_summary
""",
                encoding="utf-8",
            )
            issues = self.validator.validate_artifacts(
                {
                    "registry-lab": self._valid_registry_lab(),
                    "esignet": self._valid_esignet(),
                },
                {"registry-lab": root, "esignet": root},
            )

        self.assertIssue(issues, "self-attestation-claim-purpose-unallowed")

    def test_rejects_overlong_bearer_offer_ttl(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_dir = root / "config" / "coolify" / "notary"
            config_dir.mkdir(parents=True)
            config_path = config_dir / "citizen-civil-notary.yaml"
            config_path.write_text(
                """
oid4vci:
  pre_authorized_code:
    enabled: true
    pre_authorized_code_ttl_seconds: 301
    tx_code:
      required: false
""",
                encoding="utf-8",
            )
            compose = self._valid_registry_lab()
            compose["services"]["citizen-civil-notary"]["command"] = [
                "--config",
                "/etc/registry-notary/citizen-civil-notary.yaml",
            ]
            issues = self.validator.validate_artifacts(
                {
                    "registry-lab": compose,
                    "esignet": self._valid_esignet(),
                },
                {"registry-lab": root, "esignet": root},
            )
            self.assertIssue(issues, "bearer-offer-ttl-too-long")

            config_path.write_text(
                """
oid4vci:
  pre_authorized_code:
    enabled: true
    pre_authorized_code_ttl_seconds: 300
    tx_code:
      required: false
""",
                encoding="utf-8",
            )
            issues = self.validator.validate_artifacts(
                {
                    "registry-lab": compose,
                    "esignet": self._valid_esignet(),
                },
                {"registry-lab": root, "esignet": root},
            )
            self.assertNoIssue(issues, "bearer-offer-ttl-too-long")

    def test_rejects_hosted_configs_that_require_openapi_auth(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            relay_dir = root / "config" / "coolify" / "relay"
            notary_dir = root / "config" / "coolify" / "notary"
            relay_dir.mkdir(parents=True)
            notary_dir.mkdir(parents=True)
            (relay_dir / "civil-registry-relay.yaml").write_text(
                "server:\n  bind: 0.0.0.0:8080\n",
                encoding="utf-8",
            )
            (notary_dir / "citizen-civil-notary.yaml").write_text(
                "server:\n  bind: 0.0.0.0:8080\n  openapi_requires_auth: false\n",
                encoding="utf-8",
            )
            compose = self._valid_registry_lab()
            compose["services"]["civil-registry-relay"]["command"] = [
                "--config",
                "/etc/registry-relay/civil-registry-relay.yaml",
            ]
            compose["services"]["citizen-civil-notary"]["command"] = [
                "--config",
                "/etc/registry-notary/citizen-civil-notary.yaml",
            ]
            issues = self.validator.validate_artifacts(
                {
                    "registry-lab": compose,
                    "esignet": self._valid_esignet(),
                },
                {"registry-lab": root, "esignet": root},
            )

        self.assertIssue(issues, "openapi-auth-required")

    def test_rejects_relay_coolify_config_without_public_openapi(self) -> None:
        # Scan-based check: relay config file in HOSTED_CONFIG_DIRS must have
        # openapi_requires_auth: false even if no compose service references it.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            relay_dir = root / "config" / "coolify" / "relay"
            relay_dir.mkdir(parents=True)
            (relay_dir / "civil-registry-relay.yaml").write_text(
                "server:\n  bind: 0.0.0.0:8080\n",
                encoding="utf-8",
            )
            issues = self.validator.validate_hosted_openapi_policy(
                "registry-lab",
                {},
                root,
            )
        self.assertIssue(issues, "openapi-auth-required")

    def test_rejects_notary_coolify_config_without_public_openapi(self) -> None:
        # Scan-based check: notary config file in HOSTED_CONFIG_DIRS must have
        # openapi_requires_auth: false even if no compose service references it.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            notary_dir = root / "config" / "coolify" / "notary"
            notary_dir.mkdir(parents=True)
            (notary_dir / "citizen-civil-notary.yaml").write_text(
                "server:\n  bind: 0.0.0.0:8080\n  openapi_requires_auth: true\n",
                encoding="utf-8",
            )
            issues = self.validator.validate_hosted_openapi_policy(
                "registry-lab",
                {},
                root,
            )
        self.assertIssue(issues, "openapi-auth-required")

    def test_hosted_openapi_policy_allows_public_coolify_configs(self) -> None:
        # Positive case: all configs in HOSTED_CONFIG_DIRS with the flag set pass.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            relay_dir = root / "config" / "coolify" / "relay"
            notary_dir = root / "config" / "coolify" / "notary"
            relay_dir.mkdir(parents=True)
            notary_dir.mkdir(parents=True)
            (relay_dir / "civil-registry-relay.yaml").write_text(
                "server:\n  bind: 0.0.0.0:8080\n  openapi_requires_auth: false\n",
                encoding="utf-8",
            )
            (notary_dir / "citizen-civil-notary.yaml").write_text(
                "server:\n  bind: 0.0.0.0:8080\n  openapi_requires_auth: false\n",
                encoding="utf-8",
            )
            issues = self.validator.validate_hosted_openapi_policy(
                "registry-lab",
                {},
                root,
            )
        self.assertNoIssue(issues, "openapi-auth-required")

    def test_hosted_openapi_policy_ignores_nested_server_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            relay_dir = root / "config" / "coolify" / "relay"
            relay_dir.mkdir(parents=True)
            (relay_dir / "metadata.yaml").write_text(
                "metadata:\n  server:\n    openapi_requires_auth: true\n",
                encoding="utf-8",
            )
            issues = self.validator.validate_hosted_openapi_policy(
                "registry-lab",
                {},
                root,
            )
        self.assertNoIssue(issues, "openapi-auth-required")

    def test_rejects_relay_healthcheck_that_calls_notary_binary(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["civil-registry-relay"]["healthcheck"] = {
            "test": ["CMD", "registry-notary", "healthcheck"]
        }
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "unsupported-relay-healthcheck")

    def test_allows_relay_command_that_mentions_notary_outside_healthcheck(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["civil-registry-relay"]["command"] = [
            "--config",
            "/etc/registry-relay/config.yaml",
            "--note",
            "registry-notary",
        ]
        issues = self._validate(compose, self._valid_esignet())
        self.assertNoIssue(issues, "unsupported-relay-healthcheck")

    def test_rejects_relay_healthcheck_that_requires_curl(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["civil-registry-relay"]["healthcheck"] = {
            "test": ["CMD", "curl", "-fsS", "http://127.0.0.1:8080/healthz"]
        }
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "unsupported-relay-healthcheck")

    def test_rejects_notary_healthcheck_that_requires_curl(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["citizen-civil-notary"]["healthcheck"] = {
            "test": ["CMD", "curl", "-fsS", "http://127.0.0.1:8080/healthz"]
        }
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "unsupported-notary-healthcheck")

    def test_rejects_shell_entrypoint_for_notary_image(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["opencrvs-dci-notary"]["entrypoint"] = ["/bin/sh", "-eu", "-c"]
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "unsupported-notary-entrypoint")

    def test_rejects_missing_openfn_config_trust_mount(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["openfn-dhis2-sidecar"]["volumes"] = [
            "cfg-openfn-tmpl:/etc/registry-notary-openfn:ro",
            "openfn-sidecar-tuf-state:/var/lib/registry-notary-openfn-sidecar/tuf",
        ]
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "missing-openfn-governed-mount")

    def test_rejects_missing_openfn_audit_mount(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["openfn-dhis2-sidecar"]["volumes"] = [
            volume
            for volume in compose["services"]["openfn-dhis2-sidecar"]["volumes"]
            if not volume.startswith("openfn-sidecar-audit-state:")
        ]
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "missing-openfn-governed-mount")

    def test_rejects_hosted_openfn_unsigned_dev_config(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["openfn-dhis2-sidecar"]["command"] = [
            "--config",
            "/tmp/openfn-dhis2-sidecar.yaml",
            "--allow-unsigned-dev-config",
        ]
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "hosted-openfn-unsigned-dev-config")
        self.assertIssue(issues, "missing-openfn-governed-bootstrap")

    def test_rejects_hosted_openfn_missing_audit_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            notary_dir = root / "config" / "coolify" / "notary"
            openfn_dir = root / "config" / "coolify" / "openfn"
            governed_dir = openfn_dir / "governed"
            notary_dir.mkdir(parents=True)
            governed_dir.mkdir(parents=True)
            (openfn_dir / "openfn-dhis2-sidecar.bootstrap.yaml").write_text(
                """
config_trust:
  product: registry-notary-openfn-sidecar
  instance_id: hosted-dhis2-openfn-sidecar
  environment: hosted-lab
  stream_id: dhis2-openfn-sidecar-runtime
  accepted_roots:
    - root_id: demo
""",
                encoding="utf-8",
            )
            (governed_dir / "openfn-dhis2-sidecar-runtime.report.json").write_text(
                '{"config_hash":"sha256:1111111111111111111111111111111111111111111111111111111111111111"}',
                encoding="utf-8",
            )
            (notary_dir / "dhis2-health-notary.yaml").write_text(
                """
evidence:
  source_connections:
    dhis2_openfn:
      expected_sidecar:
        product: registry-notary-openfn-sidecar
        instance_id: hosted-dhis2-openfn-sidecar
        environment: hosted-lab
        stream_id: dhis2-openfn-sidecar-runtime
        config_hash: sha256:1111111111111111111111111111111111111111111111111111111111111111
        require_expression_hashes_verified: true
        require_runtime_verified: true
        require_smoke_verified: true
""",
                encoding="utf-8",
            )
            issues = self.validator.validate_artifacts(
                {
                    "registry-lab": self._valid_registry_lab(),
                    "esignet": self._valid_esignet(),
                },
                {"registry-lab": root, "esignet": root},
            )
        self.assertIssue(issues, "missing-openfn-audit-config")

    def test_rejects_hosted_openfn_expected_sidecar_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            notary_dir = root / "config" / "coolify" / "notary"
            openfn_dir = root / "config" / "coolify" / "openfn"
            governed_dir = openfn_dir / "governed"
            notary_dir.mkdir(parents=True)
            governed_dir.mkdir(parents=True)
            (openfn_dir / "openfn-dhis2-sidecar.bootstrap.yaml").write_text(
                """
config_trust:
  product: registry-notary-openfn-sidecar
  instance_id: hosted-dhis2-openfn-sidecar
  environment: hosted-lab
  stream_id: dhis2-openfn-sidecar-runtime
  accepted_roots:
    - root_id: demo
""",
                encoding="utf-8",
            )
            (governed_dir / "openfn-dhis2-sidecar-runtime.report.json").write_text(
                '{"config_hash":"sha256:1111111111111111111111111111111111111111111111111111111111111111"}',
                encoding="utf-8",
            )
            (notary_dir / "dhis2-health-notary.yaml").write_text(
                """
evidence:
  source_connections:
    dhis2_openfn:
      expected_sidecar:
        product: registry-notary-openfn-sidecar
        instance_id: hosted-dhis2-openfn-sidecar
        environment: hosted-lab
        stream_id: dhis2-openfn-sidecar-runtime
        config_hash: sha256:2222222222222222222222222222222222222222222222222222222222222222
        require_expression_hashes_verified: true
        require_runtime_verified: true
        require_smoke_verified: true
""",
                encoding="utf-8",
            )
            issues = self.validator.validate_artifacts(
                {
                    "registry-lab": self._valid_registry_lab(),
                    "esignet": self._valid_esignet(),
                },
                {"registry-lab": root, "esignet": root},
            )
        self.assertIssue(issues, "openfn-sidecar-hash-mismatch")

    def test_valid_walt_artifact_passes(self) -> None:
        issues = self._validate_walt(self._valid_walt())
        self.assertEqual(issues, [], [str(issue) for issue in issues])

    def test_rejects_missing_walt_service(self) -> None:
        walt = self._valid_walt()
        del walt["services"]["wallet-api"]
        issues = self._validate_walt(walt)
        self.assertIssue(issues, "missing-service")

    def test_rejects_missing_walt_domain(self) -> None:
        walt = self._valid_walt()
        walt["x-hosted-domains"] = {}
        issues = self._validate_walt(walt)
        self.assertIssue(issues, "missing-domain")

    def test_rejects_missing_walt_auth_secret_reference(self) -> None:
        walt = self._valid_walt()
        del walt["services"]["wallet-api"]["environment"]["WALT_AUTH_SIGN_KEY"]
        issues = self._validate_walt(walt)
        self.assertIssue(issues, "missing-required-variable")

    def test_rejects_missing_walt_ktor_secret_reference(self) -> None:
        walt = self._valid_walt()
        del walt["services"]["wallet-api"]["environment"]["WALT_KTOR_SIGNING_KEY"]
        issues = self._validate_walt(walt)
        self.assertIssue(issues, "missing-required-variable")

    def test_rejects_walt_host_ports(self) -> None:
        walt = self._valid_walt()
        walt["services"]["caddy"]["ports"] = ["7101:7101"]
        issues = self._validate_walt(walt)
        self.assertIssue(issues, "host-ports")

    def assertIssue(self, issues, code: str) -> None:
        codes = [issue.code for issue in issues]
        self.assertIn(code, codes, [str(issue) for issue in issues])

    def assertNoIssue(self, issues, code: str) -> None:
        codes = [issue.code for issue in issues]
        self.assertNotIn(code, codes, [str(issue) for issue in issues])

    def _validate(self, registry_lab: dict, esignet: dict):
        return self.validator.validate_artifacts(
            {
                "registry-lab": copy.deepcopy(registry_lab),
                "esignet": copy.deepcopy(esignet),
            }
        )

    def _validate_walt(self, walt: dict):
        return self.validator.validate_artifacts({"walt": copy.deepcopy(walt)})

    @staticmethod
    def _fixture_path(repo: Path, source_path: str) -> Path:
        if source_path.startswith("/demo/"):
            return repo / source_path.removeprefix("/demo/")
        return repo / source_path

    @staticmethod
    def _xlsx_sheet_names(path: Path) -> set[str]:
        ns = {"main": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
        with zipfile.ZipFile(path) as archive:
            workbook = ET.fromstring(archive.read("xl/workbook.xml"))
        return {
            item.attrib["name"]
            for item in workbook.findall("main:sheets/main:sheet", ns)
            if "name" in item.attrib
        }

    @staticmethod
    def _valid_registry_lab() -> dict:
        lab = "lab.registrystack.org"
        required_env = {
            "AGRI_AGGREGATE_READER_RAW": "${AGRI_AGGREGATE_READER_RAW:-}",
            "AGRI_EVIDENCE_CLIENT_BEARER": "${AGRI_EVIDENCE_CLIENT_BEARER:-}",
            "AGRI_EVIDENCE_ONLY_RAW": "${AGRI_EVIDENCE_ONLY_RAW:-}",
            "AGRI_METADATA_CLIENT_RAW": "${AGRI_METADATA_CLIENT_RAW:-}",
            "AGRI_ROW_READER_RAW": "${AGRI_ROW_READER_RAW:-}",
            "REGISTRY_LAB_POSTGRES_PASSWORD": "${REGISTRY_LAB_POSTGRES_PASSWORD:-}",
            "CONFIG_REPO_REF": "${CONFIG_REPO_REF:?set CONFIG_REPO_REF}",
            "ZITADEL_MASTERKEY": "${ZITADEL_MASTERKEY:-}",
            "REGISTRY_NOTARY_AUDIT_HASH_SECRET": "${REGISTRY_NOTARY_AUDIT_HASH_SECRET:-}",
            "REGISTRY_NOTARY_ISSUER_JWK": "${REGISTRY_NOTARY_ISSUER_JWK:-}",
            "REGISTRY_NOTARY_ACCESS_TOKEN_JWK": "${REGISTRY_NOTARY_ACCESS_TOKEN_JWK:-}",
            "REGISTRY_NOTARY_ESIGNET_RP_JWK": "${REGISTRY_NOTARY_ESIGNET_RP_JWK:-}",
            "CIVIL_EVIDENCE_CLIENT_BEARER": "${CIVIL_EVIDENCE_CLIENT_BEARER:-}",
            "CIVIL_EVIDENCE_CLIENT_BEARER_HASH": "${CIVIL_EVIDENCE_CLIENT_BEARER_HASH:-}",
            "CIVIL_EVIDENCE_SOURCE_RAW": "${CIVIL_EVIDENCE_SOURCE_RAW:-}",
            "CIVIL_ESIGNET_IDENTITY_RELEASE_RAW": "${CIVIL_ESIGNET_IDENTITY_RELEASE_RAW:-}",
            "CIVIL_METADATA_CLIENT_RAW": "${CIVIL_METADATA_CLIENT_RAW:-}",
            "CIVIL_EVIDENCE_ONLY_RAW": "${CIVIL_EVIDENCE_ONLY_RAW:-}",
            "CIVIL_ROW_READER_RAW": "${CIVIL_ROW_READER_RAW:-}",
            "SOCIAL_METADATA_CLIENT_RAW": "${SOCIAL_METADATA_CLIENT_RAW:-}",
            "SOCIAL_EVIDENCE_ONLY_RAW": "${SOCIAL_EVIDENCE_ONLY_RAW:-}",
            "SOCIAL_EVIDENCE_CLIENT_BEARER": "${SOCIAL_EVIDENCE_CLIENT_BEARER:-}",
            "SOCIAL_EVIDENCE_CLIENT_BEARER_HASH": "${SOCIAL_EVIDENCE_CLIENT_BEARER_HASH:-}",
            "SOCIAL_EVIDENCE_CLIENT_TOKEN": "${SOCIAL_EVIDENCE_CLIENT_TOKEN:-}",
            "SOCIAL_EVIDENCE_CLIENT_TOKEN_HASH": "${SOCIAL_EVIDENCE_CLIENT_TOKEN_HASH:-}",
            "SOCIAL_EVIDENCE_SOURCE_RAW": "${SOCIAL_EVIDENCE_SOURCE_RAW:-}",
            "SOCIAL_ROW_READER_RAW": "${SOCIAL_ROW_READER_RAW:-}",
            "SOCIAL_AGGREGATE_READER_RAW": "${SOCIAL_AGGREGATE_READER_RAW:-}",
            "SOCIAL_FEDERATION_PAIRWISE_SUBJECT_HASH_SECRET": "${SOCIAL_FEDERATION_PAIRWISE_SUBJECT_HASH_SECRET:-}",
            "SOCIAL_FEDERATION_RESPONSE_JWK": "${SOCIAL_FEDERATION_RESPONSE_JWK:-}",
            "HEALTH_METADATA_CLIENT_RAW": "${HEALTH_METADATA_CLIENT_RAW:-}",
            "HEALTH_EVIDENCE_ONLY_RAW": "${HEALTH_EVIDENCE_ONLY_RAW:-}",
            "HEALTH_ROW_READER_RAW": "${HEALTH_ROW_READER_RAW:-}",
            "DHIS2_EVIDENCE_CLIENT_TOKEN": "${DHIS2_EVIDENCE_CLIENT_TOKEN:-}",
            "DHIS2_EVIDENCE_CLIENT_BEARER": "${DHIS2_EVIDENCE_CLIENT_BEARER:-}",
            "OPENCRVS_EVIDENCE_CLIENT_TOKEN": "${OPENCRVS_EVIDENCE_CLIENT_TOKEN:-}",
            "OPENFN_SIDECAR_TOKEN_HASH": "${OPENFN_SIDECAR_TOKEN_HASH:-}",
            "OPENFN_SIDECAR_TOKEN_RAW": "${OPENFN_SIDECAR_TOKEN_RAW:-}",
            "OPENFN_DHIS2_USERNAME": "${OPENFN_DHIS2_USERNAME:-}",
            "OPENFN_DHIS2_PASSWORD": "${OPENFN_DHIS2_PASSWORD:-}",
            "DHIS2_EVIDENCE_CLIENT_TOKEN_HASH": "${DHIS2_EVIDENCE_CLIENT_TOKEN_HASH:-}",
            "DHIS2_EVIDENCE_CLIENT_BEARER_HASH": "${DHIS2_EVIDENCE_CLIENT_BEARER_HASH:-}",
            "OPENCRVS_EVIDENCE_CLIENT_TOKEN_HASH": "${OPENCRVS_EVIDENCE_CLIENT_TOKEN_HASH:-}",
            "OPENCRVS_DCI_BASE_URL": "${OPENCRVS_DCI_BASE_URL:-}",
            "OPENCRVS_DCI_CLIENT_ID": "${OPENCRVS_DCI_CLIENT_ID:-}",
            "OPENCRVS_DCI_CLIENT_SECRET": "${OPENCRVS_DCI_CLIENT_SECRET:-}",
            "OPENCRVS_DCI_SHA_SECRET": "${OPENCRVS_DCI_SHA_SECRET:-}",
            "REGISTRY_RELAY_AUDIT_HASH_SECRET": "${REGISTRY_RELAY_AUDIT_HASH_SECRET:-}",
            "CIVIL_METADATA_CLIENT_HASH": "${CIVIL_METADATA_CLIENT_HASH:-}",
            "CIVIL_EVIDENCE_SOURCE_HASH": "${CIVIL_EVIDENCE_SOURCE_HASH:-}",
            "CIVIL_ESIGNET_IDENTITY_RELEASE_HASH": "${CIVIL_ESIGNET_IDENTITY_RELEASE_HASH:-}",
            "CIVIL_EVIDENCE_ONLY_HASH": "${CIVIL_EVIDENCE_ONLY_HASH:-}",
            "CIVIL_ROW_READER_HASH": "${CIVIL_ROW_READER_HASH:-}",
            "SHARED_CIVIL_EVIDENCE_SOURCE_HASH": "${SHARED_CIVIL_EVIDENCE_SOURCE_HASH:-}",
            "SHARED_CIVIL_EVIDENCE_SOURCE_RAW": "${SHARED_CIVIL_EVIDENCE_SOURCE_RAW:-}",
            "SHARED_EVIDENCE_CLIENT_BEARER": "${SHARED_EVIDENCE_CLIENT_BEARER:-}",
            "SHARED_EVIDENCE_CLIENT_BEARER_HASH": "${SHARED_EVIDENCE_CLIENT_BEARER_HASH:-}",
            "SHARED_EVIDENCE_CLIENT_TOKEN_HASH": "${SHARED_EVIDENCE_CLIENT_TOKEN_HASH:-}",
            "SOCIAL_METADATA_CLIENT_HASH": "${SOCIAL_METADATA_CLIENT_HASH:-}",
            "SOCIAL_EVIDENCE_SOURCE_HASH": "${SOCIAL_EVIDENCE_SOURCE_HASH:-}",
            "SOCIAL_EVIDENCE_ONLY_HASH": "${SOCIAL_EVIDENCE_ONLY_HASH:-}",
            "SOCIAL_ROW_READER_HASH": "${SOCIAL_ROW_READER_HASH:-}",
            "SOCIAL_AGGREGATE_READER_HASH": "${SOCIAL_AGGREGATE_READER_HASH:-}",
            "SHARED_SOCIAL_EVIDENCE_SOURCE_HASH": "${SHARED_SOCIAL_EVIDENCE_SOURCE_HASH:-}",
            "SHARED_SOCIAL_EVIDENCE_SOURCE_RAW": "${SHARED_SOCIAL_EVIDENCE_SOURCE_RAW:-}",
            "HEALTH_METADATA_CLIENT_HASH": "${HEALTH_METADATA_CLIENT_HASH:-}",
            "HEALTH_EVIDENCE_SOURCE_HASH": "${HEALTH_EVIDENCE_SOURCE_HASH:-}",
            "HEALTH_EVIDENCE_ONLY_HASH": "${HEALTH_EVIDENCE_ONLY_HASH:-}",
            "HEALTH_ROW_READER_HASH": "${HEALTH_ROW_READER_HASH:-}",
            "SHARED_HEALTH_EVIDENCE_SOURCE_HASH": "${SHARED_HEALTH_EVIDENCE_SOURCE_HASH:-}",
            "SHARED_HEALTH_EVIDENCE_SOURCE_RAW": "${SHARED_HEALTH_EVIDENCE_SOURCE_RAW:-}",
        }
        return {
            "services": {
                "config-loader": {
                    "image": "alpine:3.20",
                    "environment": {
                        "CONFIG_REPO_REF": "${CONFIG_REPO_REF:?set CONFIG_REPO_REF to the deployed registry-lab git ref}",
                    },
                    "command": [
                        """
for d in civil-cache health-cache; do
  mkdir -p "/out/$d"
  chown -R 65532:65532 "/out/$d"
done
for d in openfn-tuf-state openfn-config-state openfn-audit-state; do
  mkdir -p "/out/$d"
  chown -R 1000:1000 "/out/$d"
done
openfn_antirollback=/out/openfn-config-state/dhis2-openfn-sidecar-antirollback.json
if [ ! -s "$openfn_antirollback" ]; then
  printf '%s\n' '{"key":{"product":"registry-notary-openfn-sidecar","instance_id":"hosted-dhis2-openfn-sidecar","environment":"hosted-lab","stream_id":"dhis2-openfn-sidecar-runtime"},"last_sequence":0,"last_config_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","root_version":1,"break_glass":{"accepted":[]},"local_approvals":{"accepted":[]}}' > "$openfn_antirollback"
fi
cp -a /tmp/repo/config/coolify/notary/civil-notary.yaml /out/notary/
cp -a /tmp/repo/config/coolify/notary/citizen-civil-notary.yaml /out/notary/
cp -a /tmp/repo/config/coolify/notary/social-protection-notary.yaml /out/notary/
cp -a /tmp/repo/config/coolify/notary/shared-eligibility-notary.yaml /out/notary/
cp -a /tmp/repo/scripts/lab_homepage_explorer /out/static-scripts/
cp -a /tmp/repo/scripts/lab_homepage_scenarios /out/static-scripts/
cp -a /tmp/repo/scripts/lab_homepage_static /out/static-scripts/
"""
                    ],
                    "volumes": [
                        "civil-registry-cache:/out/civil-cache",
                        "social-protection-registry-cache:/out/social-cache",
                        "health-registry-cache:/out/health-cache",
                        "openfn-sidecar-tuf-state:/out/openfn-tuf-state",
                        "openfn-sidecar-config-state:/out/openfn-config-state",
                        "openfn-sidecar-audit-state:/out/openfn-audit-state",
                    ],
                },
                "postgres": {"image": "postgres:16-alpine", "environment": required_env},
                "redis": {"image": "redis:7.4-alpine"},
                "civil-notary": {
                    "image": "${REGISTRY_NOTARY_IMAGE:-ghcr.io/registrystack/registry-notary@sha256:abc}",
                    "command": [
                        "--config",
                        "/etc/registry-notary/civil-notary.yaml",
                    ],
                    "expose": ["8080"],
                    "environment": {
                        "CIVIL_EVIDENCE_CLIENT_BEARER_HASH": "${CIVIL_EVIDENCE_CLIENT_BEARER_HASH:-}",
                    },
                    "volumes": ["cfg-notary:/etc/registry-notary:ro"],
                    "healthcheck": {
                        "test": ["CMD", "registry-notary", "healthcheck"]
                    },
                },
                "social-protection-notary": {
                    "image": "${REGISTRY_NOTARY_IMAGE:-ghcr.io/registrystack/registry-notary@sha256:abc}",
                    "command": [
                        "--config",
                        "/etc/registry-notary/social-protection-notary.yaml",
                    ],
                    "expose": ["8080"],
                    "environment": {
                        "SOCIAL_EVIDENCE_CLIENT_TOKEN_HASH": "${SOCIAL_EVIDENCE_CLIENT_TOKEN_HASH:-}",
                        "SOCIAL_EVIDENCE_CLIENT_BEARER_HASH": "${SOCIAL_EVIDENCE_CLIENT_BEARER_HASH:-}",
                        "SOCIAL_EVIDENCE_SOURCE_RAW": "${SOCIAL_EVIDENCE_SOURCE_RAW:-}",
                        "SOCIAL_FEDERATION_PAIRWISE_SUBJECT_HASH_SECRET": "${SOCIAL_FEDERATION_PAIRWISE_SUBJECT_HASH_SECRET:-}",
                        "SOCIAL_FEDERATION_RESPONSE_JWK": "${SOCIAL_FEDERATION_RESPONSE_JWK:-}",
                    },
                    "volumes": ["cfg-notary:/etc/registry-notary:ro"],
                    "healthcheck": {
                        "test": ["CMD", "registry-notary", "healthcheck"]
                    },
                },
                "citizen-civil-notary": {
                    "image": "${REGISTRY_NOTARY_IMAGE:-ghcr.io/registrystack/registry-notary@sha256:abc}",
                    "command": [
                        "--config",
                        "/etc/registry-notary/citizen-civil-notary.yaml",
                    ],
                    "expose": ["8080"],
                    "environment": {
                        "CITIZEN_OID4VCI_CREDENTIAL_ISSUER": f"https://citizen-notary.{lab}",
                        "CITIZEN_OID4VCI_CREDENTIAL_ENDPOINT": f"https://citizen-notary.{lab}/oid4vci/credential",
                        "CITIZEN_OID4VCI_OFFER_ENDPOINT": f"https://citizen-notary.{lab}/oid4vci/credential-offer",
                        "CITIZEN_OID4VCI_NONCE_ENDPOINT": f"https://citizen-notary.{lab}/oid4vci/nonce",
                        "ESIGNET_ISSUER": f"https://esignet.{lab}",
                        "ESIGNET_DISCOVERY_URL": f"https://esignet.{lab}/v1/esignet/oidc/.well-known/openid-configuration",
                        "ESIGNET_AUTHORIZATION_URL": f"https://esignet-ui.{lab}/authorize",
                        "ESIGNET_JWKS_URI": f"https://esignet.{lab}/v1/esignet/oauth/.well-known/jwks.json",
                        "ESIGNET_TOKEN_ENDPOINT": f"https://esignet.{lab}/v1/esignet/oauth/v2/token",
                        "ESIGNET_USERINFO_ENDPOINT": f"https://esignet.{lab}/v1/esignet/oidc/userinfo",
                        "CITIZEN_OID4VCI_CREDENTIAL_CONFIGURATION_ID": "person_is_alive_sd_jwt",
                        "CITIZEN_OID4VCI_FORMAT": "dc+sd-jwt",
                    },
                    "volumes": ["cfg-notary:/etc/registry-notary:ro"],
                    "healthcheck": {
                        "test": ["CMD", "registry-notary", "healthcheck"]
                    },
                },
                "civil-registry-relay": {
                    "image": "${REGISTRY_RELAY_IMAGE:-ghcr.io/registrystack/registry-relay@sha256:abc}",
                    "expose": ["8080"],
                    "healthcheck": {
                        "test": ["CMD", "/usr/local/bin/registry-relay", "healthcheck"]
                    },
                },
                "social-protection-registry-relay": {
                    "image": "${REGISTRY_RELAY_IMAGE:-ghcr.io/registrystack/registry-relay@sha256:abc}",
                    "expose": ["8080"],
                },
                "health-registry-relay": {
                    "image": "${REGISTRY_RELAY_IMAGE:-ghcr.io/registrystack/registry-relay@sha256:abc}",
                    "expose": ["8080"],
                },
                "static-metadata-publisher": {
                    "image": "registry-lab-static-metadata:hosted",
                    "build": {
                        "context": ".",
                        "dockerfile": "Dockerfile.static-metadata",
                    },
                    "expose": ["8080"],
                    "healthcheck": {
                        "test": [
                            "CMD-SHELL",
                            "python -c 'import urllib.request; urllib.request.urlopen(\"http://127.0.0.1:8080/.well-known/registry-manifest.json\", timeout=2).read()'",
                        ]
                    },
                },
                "lab-homepage": {
                    "image": "python:3.12.3-slim-bookworm",
                    "expose": ["8080"],
                    "environment": {
                        "CONFIG_REPO_REF": "${CONFIG_REPO_REF:?set CONFIG_REPO_REF to the deployed registry-lab git ref}",
                        "CIVIL_EVIDENCE_URL": "http://civil-notary:8080",
                        "CIVIL_EVIDENCE_CLIENT_BEARER": "${CIVIL_EVIDENCE_CLIENT_BEARER:-}",
                        "SOCIAL_RELAY_URL": "https://social-relay.lab.registrystack.org",
                        "SHARED_EVIDENCE_URL": "https://shared-notary.lab.registrystack.org",
                        "SHARED_EVIDENCE_CLIENT_BEARER": "${SHARED_EVIDENCE_CLIENT_BEARER:-}",
                        "AGRI_EVIDENCE_URL": "https://agriculture-notary.lab.registrystack.org",
                        "AGRI_EVIDENCE_CLIENT_BEARER": "${AGRI_EVIDENCE_CLIENT_BEARER:-}",
                        "AGRI_METADATA_CLIENT_RAW": "${AGRI_METADATA_CLIENT_RAW:-}",
                        "AGRI_EVIDENCE_ONLY_RAW": "${AGRI_EVIDENCE_ONLY_RAW:-}",
                        "AGRI_ROW_READER_RAW": "${AGRI_ROW_READER_RAW:-}",
                        "AGRI_AGGREGATE_READER_RAW": "${AGRI_AGGREGATE_READER_RAW:-}",
                    },
                },
                "citizen-portal": {
                    "image": "${REGISTRY_LAB_CITIZEN_PORTAL_IMAGE:-ghcr.io/jeremi/registry-lab-citizen-portal@sha256:abc}",
                    "expose": ["3000"],
                    "environment": {
                        "ORIGIN": f"https://portal.{lab}",
                        "PORT": "3000",
                        "HOST": "0.0.0.0",
                        "PORTAL_PROVIDER": "mock",
                        "PORTAL_SECURE_COOKIES": "true",
                        "PROTOCOL_HEADER": "x-forwarded-proto",
                        "HOST_HEADER": "x-forwarded-host",
                        "PORT_HEADER": "x-forwarded-port",
                    },
                    "healthcheck": {
                        "test": [
                            "CMD-SHELL",
                            "node -e 'fetch(\"http://127.0.0.1:3000/\").then((r) => { if (!r.ok) process.exit(1); }).catch(() => process.exit(1));'",
                        ]
                    },
                },
                "shared-eligibility-notary": {
                    "image": "${REGISTRY_NOTARY_IMAGE:-ghcr.io/registrystack/registry-notary@sha256:abc}",
                    "command": [
                        "--config",
                        "/etc/registry-notary/shared-eligibility-notary.yaml",
                    ],
                    "expose": ["8080"],
                    "environment": {
                        "SHARED_EVIDENCE_CLIENT_TOKEN_HASH": "${SHARED_EVIDENCE_CLIENT_TOKEN_HASH:-}",
                        "SHARED_EVIDENCE_CLIENT_BEARER_HASH": "${SHARED_EVIDENCE_CLIENT_BEARER_HASH:-}",
                        "SHARED_CIVIL_EVIDENCE_SOURCE_RAW": "${SHARED_CIVIL_EVIDENCE_SOURCE_RAW:-}",
                        "SHARED_SOCIAL_EVIDENCE_SOURCE_RAW": "${SHARED_SOCIAL_EVIDENCE_SOURCE_RAW:-}",
                        "SHARED_HEALTH_EVIDENCE_SOURCE_RAW": "${SHARED_HEALTH_EVIDENCE_SOURCE_RAW:-}",
                    },
                    "volumes": ["cfg-notary:/etc/registry-notary:ro"],
                    "healthcheck": {
                        "test": ["CMD", "registry-notary", "healthcheck"]
                    },
                },
                "zitadel": {
                    "image": "ghcr.io/zitadel/zitadel:v2.66.4",
                    "expose": ["8080"],
                    "environment": {
                        "ZITADEL_EXTERNALDOMAIN": f"zitadel.{lab}",
                        "ZITADEL_EXTERNALPORT": "443",
                        "ZITADEL_EXTERNALSECURE": "true",
                    },
                },
                "openfn-dhis2-sidecar": {
                    "image": "${REGISTRY_NOTARY_OPENFN_SIDECAR_IMAGE:-ghcr.io/registrystack/registry-notary-source-adapter-sidecar@sha256:abc}",
                    "command": [
                        "--config",
                        "/etc/registry-notary-openfn/openfn-dhis2-sidecar.bootstrap.yaml",
                    ],
                    "environment": {
                        "OPENFN_DHIS2_USERNAME": "${OPENFN_DHIS2_USERNAME:-}",
                        "OPENFN_DHIS2_PASSWORD": "${OPENFN_DHIS2_PASSWORD:-}",
                    },
                    "volumes": [
                        "cfg-openfn-tmpl:/etc/registry-notary-openfn:ro",
                        "openfn-sidecar-tuf-state:/var/lib/registry-notary-openfn-sidecar/tuf",
                        "openfn-sidecar-config-state:/var/lib/registry-notary-openfn-sidecar/config-trust",
                        "openfn-sidecar-audit-state:/var/lib/registry-notary-openfn-sidecar/audit",
                    ],
                },
                "dhis2-health-notary": {
                    "image": "${REGISTRY_NOTARY_IMAGE:-ghcr.io/registrystack/registry-notary@sha256:abc}",
                    "expose": ["8080"],
                    "environment": {
                        "REGISTRY_NOTARY_PUBLIC_API_BASE_URL": f"https://dhis2-notary.{lab}",
                        "DHIS2_EVIDENCE_CLIENT_TOKEN_HASH": "${DHIS2_EVIDENCE_CLIENT_TOKEN_HASH:-}",
                        "DHIS2_EVIDENCE_CLIENT_BEARER_HASH": "${DHIS2_EVIDENCE_CLIENT_BEARER_HASH:-}",
                    },
                    "healthcheck": {
                        "test": ["CMD", "registry-notary", "healthcheck"]
                    },
                },
                "opencrvs-dci-notary": {
                    "image": "${REGISTRY_NOTARY_IMAGE:-ghcr.io/registrystack/registry-notary@sha256:abc}",
                    "expose": ["8080"],
                    "environment": {
                        "REGISTRY_NOTARY_PUBLIC_API_BASE_URL": f"https://opencrvs-notary.{lab}"
                    },
                    "healthcheck": {
                        "test": ["CMD", "registry-notary", "healthcheck"]
                    },
                },
            },
            "x-hosted-domains": {
                "citizen-portal": f"portal.{lab}",
                "citizen-civil-notary": f"citizen-notary.{lab}",
                "social-protection-notary": f"social-notary.{lab}",
                "civil-registry-relay": f"civil-relay.{lab}",
                "social-protection-registry-relay": f"social-relay.{lab}",
                "health-registry-relay": f"health-relay.{lab}",
                "static-metadata-publisher": f"metadata.{lab}",
                "lab-homepage": lab,
                "zitadel": f"zitadel.{lab}",
                "shared-eligibility-notary": f"shared-notary.{lab}",
                "dhis2-health-notary": f"dhis2-notary.{lab}",
                "opencrvs-dci-notary": f"opencrvs-notary.{lab}",
            },
        }

    @staticmethod
    def _valid_esignet() -> dict:
        lab = "lab.registrystack.org"
        return {
            "services": {
                "config-loader": {
                    "image": "alpine:3.20",
                    "environment": {
                        "CONFIG_REPO_REF": "${CONFIG_REPO_REF:?set CONFIG_REPO_REF to the deployed registry-lab git ref}",
                    },
                },
                "database": {
                    "image": "postgres:bookworm",
                    "environment": {
                        "REGISTRY_LAB_ESIGNET_POSTGRES_PASSWORD": "${REGISTRY_LAB_ESIGNET_POSTGRES_PASSWORD:-}",
                    },
                },
                "redis": {"image": "redis:6.0"},
                "esignet": {
                    "image": "${REGISTRY_LAB_ESIGNET_RELAY_IMAGE:-ghcr.io/jeremi/registry-lab-esignet-relay@sha256:" + ("1" * 64) + "}",
                    "expose": ["8088"],
                    "environment": {
                        "MOSIP_ESIGNET_PUBLIC_URL": f"https://esignet.{lab}",
                        "MOSIP_ESIGNET_UI_PUBLIC_URL": f"https://esignet-ui.{lab}",
                        "MOSIP_ESIGNET_DISCOVERY_ISSUER_ID": f"https://esignet.{lab}",
                        "MOSIP_ESIGNET_DISCOVERY_KEY_VALUES": "{'issuer':'https://esignet.lab.registrystack.org'}",
                        "MOSIP_ESIGNET_INTEGRATION_AUTHENTICATOR": "RelayAuthenticationService",
                        "MOSIP_ESIGNET_INTEGRATION_SCAN_BASE_PACKAGE": "io.mosip.esignet.mock.integration,io.registry.esignet.relay",
                        "REGISTRY_RELAY_BASE_URL": f"https://civil-relay.{lab}",
                        "REGISTRY_RELAY_AUTH_BEARER_TOKEN": "${CIVIL_ESIGNET_IDENTITY_RELEASE_RAW:-replace-in-coolify}",
                        "REGISTRY_ESIGNET_KYC_TOKEN_HMAC_SECRET": "${REGISTRY_ESIGNET_KYC_TOKEN_SECRET:-replace-in-coolify-kyc-token-secret-32}",
                        "REGISTRY_ESIGNET_PSUT_HMAC_SECRET": "${REGISTRY_ESIGNET_PSUT_SECRET:-replace-in-coolify-psut-secret-32chars}",
                        "REGISTRY_ESIGNET_USER_INFO_ISSUER": f"https://esignet.{lab}",
                        "REGISTRY_ESIGNET_KYC_SIGNING_KEYSTORE_PASSWORD": "${REGISTRY_ESIGNET_KYC_KEYSTORE_PASSWORD:-replace-in-coolify}",
                        "REGISTRY_ESIGNET_KYC_SIGNING_KEY_PASSWORD": "${REGISTRY_ESIGNET_KYC_KEYSTORE_PASSWORD:-replace-in-coolify}",
                    },
                    "healthcheck": {
                        "test": [
                            "CMD",
                            "curl",
                            "-fsS",
                            "http://127.0.0.1:8088/v1/esignet/oidc/.well-known/openid-configuration",
                        ]
                    },
                },
                "esignet-ui": {
                    "image": "mosipid/oidc-ui:1.8.0",
                    "expose": ["3000"],
                    "environment": {
                        "ESIGNET_UI_PUBLIC_URL": f"https://esignet-ui.{lab}"
                    },
                },
                "esignet-seed": {
                    "image": "${REGISTRY_LAB_ESIGNET_SEED_IMAGE:-ghcr.io/jeremi/registry-lab-esignet-seed@sha256:" + ("2" * 64) + "}",
                    "environment": {
                        "REGISTRY_LAB_ESIGNET_CLIENT_REDIRECT_URIS_JSON": "${REGISTRY_LAB_ESIGNET_CLIENT_REDIRECT_URIS_JSON:-}",
                    },
                },
            },
            "x-hosted-domains": {
                "esignet": f"esignet.{lab}",
                "esignet-ui": f"esignet-ui.{lab}",
            },
        }

    @staticmethod
    def _valid_walt() -> dict:
        lab = "lab.registrystack.org"
        return {
            "services": {
                "config-loader": {
                    "image": "alpine:3.20",
                    "environment": {
                        "CONFIG_REPO_REF": "${CONFIG_REPO_REF:?set CONFIG_REPO_REF to the deployed registry-lab git ref}",
                    },
                },
                "walt-postgres": {
                    "image": "postgres:16-alpine",
                    "environment": {
                        "POSTGRES_PASSWORD": "${WALT_DB_PASSWORD:-replace-in-coolify}",
                    },
                },
                "wallet-api": {
                    "image": "docker.io/waltid/wallet-api:0.20.2",
                    "expose": ["7001"],
                    "environment": {
                        "SERVICE_HOST": f"wallet.{lab}",
                        "DB_PASSWORD": "${WALT_DB_PASSWORD:-replace-in-coolify}",
                        "WALT_AUTH_ENCRYPTION_KEY": "${WALT_AUTH_ENCRYPTION_KEY:?set it}",
                        "WALT_AUTH_SIGN_KEY": "${WALT_AUTH_SIGN_KEY:?set it}",
                        "WALT_AUTH_TOKEN_KEY": "${WALT_AUTH_TOKEN_KEY:?set it}",
                        "WALT_KTOR_SIGNING_KEY": "${WALT_KTOR_SIGNING_KEY:?set it}",
                        "WALT_KTOR_VERIFICATION_KEY": "${WALT_KTOR_VERIFICATION_KEY:?set it}",
                    },
                },
                "waltid-demo-wallet": {
                    "image": "docker.io/waltid/waltid-demo-wallet:0.20.2",
                    "expose": ["7101"],
                    "environment": {
                        "NUXT_PUBLIC_ISSUER_CALLBACK_URL": f"https://wallet.{lab}",
                    },
                },
                "caddy": {
                    "image": "docker.io/caddy:2",
                    "expose": ["7101"],
                },
            },
            "x-hosted-domains": {
                "caddy": f"wallet.{lab}",
            },
        }


if __name__ == "__main__":
    unittest.main()
