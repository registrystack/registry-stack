#!/usr/bin/env python3
"""Focused tests for hosted Coolify deploy artifact validation."""

from __future__ import annotations

import copy
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
VALIDATOR_PATH = SCRIPT_DIR / "validate-hosted-deploy.py"
WORKFLOW_PATH = SCRIPT_DIR.parent / ".github" / "workflows" / "hosted-lab.yml"


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

    def test_rejects_hardcoded_product_image_digests(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["civil-registry-relay"][
            "image"
        ] = "ghcr.io/jeremi/registry-relay@sha256:abc"
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "product-image-env-var")

    def test_allows_interim_local_hosted_product_tags(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["civil-registry-relay"]["image"] = "registry-relay:hosted"
        compose["services"]["citizen-civil-notary"]["image"] = "registry-notary:hosted"
        compose["services"]["openfn-dhis2-sidecar"][
            "image"
        ] = "registry-notary-openfn-sidecar:hosted"
        issues = self._validate(compose, self._valid_esignet())
        self.assertEqual([], issues)

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
        ] = "${REGISTRY_NOTARY_OPENFN_SIDECAR_IMAGE:-ghcr.io/jeremi/registry-notary-openfn-sidecar@sha256:abc}"

        issues = self._validate(compose, self._valid_esignet())
        self.assertEqual([], issues)

    def test_rejects_stale_config_loader_ref(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["config-loader"] = {
            "image": "alpine:3.20",
            "environment": {
                "CONFIG_REPO_REF": "registry-stack-technical-preview-2026-06-04"
            },
        }
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "stale-config-repo-ref")

    def test_rejects_config_loader_that_does_not_seed_static_content(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["config-loader"]["command"] = ["echo no static metadata"]
        compose["services"]["config-loader"]["volumes"] = [
            volume
            for volume in compose["services"]["config-loader"]["volumes"]
            if not volume.startswith("static-content:")
        ]
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "missing-static-content-seed")

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
        self.assertIssue(issues, "relay-cache-not-chowned")

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
        self.assertRegex(workflow, r"(?m)^  deploy-coolify:\n(?:.*\n)*?    permissions: \{\}$")

    def test_hosted_workflow_deploys_all_coolify_apps_by_api(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn("COOLIFY_API_TOKEN", workflow)
        self.assertNotIn("COOLIFY_DEPLOY_WEBHOOK_URL", workflow)
        self.assertIn("klhnsuoye8lwuamp0bko387t", workflow)
        self.assertIn("cewwn93kknzsfzicen9nul6v", workflow)
        self.assertIn("uvqfk8gwqdbdse4v871xfv56", workflow)

    def test_rejects_esignet_issuer_mismatch(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["citizen-civil-notary"]["environment"][
            "ESIGNET_ISSUER"
        ] = "https://esignet.lab.registrystack.org/v1/esignet"
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "esignet-issuer-mismatch")

    def test_rejects_missing_oid4vci_configuration_assertions(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["citizen-civil-notary"]["environment"][
            "CITIZEN_OID4VCI_CREDENTIAL_CONFIGURATION_ID"
        ] = "citizen_civil_status_sd_jwt"
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "missing-credential-configuration")

        compose = self._valid_registry_lab()
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

    def test_rejects_missing_openfn_job_mount(self) -> None:
        compose = self._valid_registry_lab()
        compose["services"]["openfn-dhis2-sidecar"]["volumes"] = [
            "./config/coolify/openfn/openfn-dhis2-sidecar.yaml.template:/etc/registry-notary-openfn/openfn-dhis2-sidecar.yaml.template:ro"
        ]
        issues = self._validate(compose, self._valid_esignet())
        self.assertIssue(issues, "missing-openfn-job-mount")

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
    def _valid_registry_lab() -> dict:
        lab = "lab.registrystack.org"
        required_env = {
            "REGISTRY_LAB_POSTGRES_PASSWORD": "${REGISTRY_LAB_POSTGRES_PASSWORD:-}",
            "ZITADEL_MASTERKEY": "${ZITADEL_MASTERKEY:-}",
            "REGISTRY_NOTARY_AUDIT_HASH_SECRET": "${REGISTRY_NOTARY_AUDIT_HASH_SECRET:-}",
            "REGISTRY_NOTARY_ISSUER_JWK": "${REGISTRY_NOTARY_ISSUER_JWK:-}",
            "REGISTRY_NOTARY_ACCESS_TOKEN_JWK": "${REGISTRY_NOTARY_ACCESS_TOKEN_JWK:-}",
            "REGISTRY_NOTARY_ESIGNET_RP_JWK": "${REGISTRY_NOTARY_ESIGNET_RP_JWK:-}",
            "CIVIL_EVIDENCE_SOURCE_RAW": "${CIVIL_EVIDENCE_SOURCE_RAW:-}",
            "CIVIL_METADATA_CLIENT_RAW": "${CIVIL_METADATA_CLIENT_RAW:-}",
            "CIVIL_EVIDENCE_ONLY_RAW": "${CIVIL_EVIDENCE_ONLY_RAW:-}",
            "CIVIL_ROW_READER_RAW": "${CIVIL_ROW_READER_RAW:-}",
            "SOCIAL_METADATA_CLIENT_RAW": "${SOCIAL_METADATA_CLIENT_RAW:-}",
            "SOCIAL_EVIDENCE_ONLY_RAW": "${SOCIAL_EVIDENCE_ONLY_RAW:-}",
            "SOCIAL_ROW_READER_RAW": "${SOCIAL_ROW_READER_RAW:-}",
            "SOCIAL_AGGREGATE_READER_RAW": "${SOCIAL_AGGREGATE_READER_RAW:-}",
            "HEALTH_METADATA_CLIENT_RAW": "${HEALTH_METADATA_CLIENT_RAW:-}",
            "HEALTH_EVIDENCE_ONLY_RAW": "${HEALTH_EVIDENCE_ONLY_RAW:-}",
            "HEALTH_ROW_READER_RAW": "${HEALTH_ROW_READER_RAW:-}",
            "DHIS2_EVIDENCE_CLIENT_TOKEN": "${DHIS2_EVIDENCE_CLIENT_TOKEN:-}",
            "DHIS2_EVIDENCE_CLIENT_BEARER": "${DHIS2_EVIDENCE_CLIENT_BEARER:-}",
            "OPENCRVS_EVIDENCE_CLIENT_TOKEN": "${OPENCRVS_EVIDENCE_CLIENT_TOKEN:-}",
            "OPENFN_SIDECAR_TOKEN_HASH": "${OPENFN_SIDECAR_TOKEN_HASH:-}",
            "OPENFN_SIDECAR_TOKEN_RAW": "${OPENFN_SIDECAR_TOKEN_RAW:-}",
            "OPENFN_DHIS2_HOST_URL": "${OPENFN_DHIS2_HOST_URL:-}",
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
            "CIVIL_EVIDENCE_ONLY_HASH": "${CIVIL_EVIDENCE_ONLY_HASH:-}",
            "CIVIL_ROW_READER_HASH": "${CIVIL_ROW_READER_HASH:-}",
            "SHARED_CIVIL_EVIDENCE_SOURCE_HASH": "${SHARED_CIVIL_EVIDENCE_SOURCE_HASH:-}",
            "SOCIAL_METADATA_CLIENT_HASH": "${SOCIAL_METADATA_CLIENT_HASH:-}",
            "SOCIAL_EVIDENCE_SOURCE_HASH": "${SOCIAL_EVIDENCE_SOURCE_HASH:-}",
            "SOCIAL_EVIDENCE_ONLY_HASH": "${SOCIAL_EVIDENCE_ONLY_HASH:-}",
            "SOCIAL_ROW_READER_HASH": "${SOCIAL_ROW_READER_HASH:-}",
            "SOCIAL_AGGREGATE_READER_HASH": "${SOCIAL_AGGREGATE_READER_HASH:-}",
            "SHARED_SOCIAL_EVIDENCE_SOURCE_HASH": "${SHARED_SOCIAL_EVIDENCE_SOURCE_HASH:-}",
            "HEALTH_METADATA_CLIENT_HASH": "${HEALTH_METADATA_CLIENT_HASH:-}",
            "HEALTH_EVIDENCE_SOURCE_HASH": "${HEALTH_EVIDENCE_SOURCE_HASH:-}",
            "HEALTH_EVIDENCE_ONLY_HASH": "${HEALTH_EVIDENCE_ONLY_HASH:-}",
            "HEALTH_ROW_READER_HASH": "${HEALTH_ROW_READER_HASH:-}",
            "SHARED_HEALTH_EVIDENCE_SOURCE_HASH": "${SHARED_HEALTH_EVIDENCE_SOURCE_HASH:-}",
        }
        return {
            "services": {
                "config-loader": {
                    "image": "alpine:3.20",
                    "environment": {"CONFIG_REPO_REF": "${CONFIG_REPO_REF:-main}"},
                    "command": [
                        """
cp -a /tmp/repo/static-metadata/. /out/static-content/
cat > /out/static-content/.well-known/api-catalog
cat > /out/static-content/.well-known/registry-manifest.json
cat > /out/static-content/metadata/index.json
cat > /out/static-content/metadata/evidence-offerings.json
cat > /out/static-content/metadata/policies.jsonld
cat > /out/static-content/metadata/cpsv-ap.jsonld
cat > /out/static-content/metadata/dcat/bregdcat-ap
cat > /out/static-content/metadata/forms/health_linked_child_support_form/schema.json
for d in civil-cache social-cache health-cache; do
  mkdir -p "/out/$d"
  chown -R 65532:65532 "/out/$d"
done
"""
                    ],
                    "volumes": [
                        "static-content:/out/static-content",
                        "civil-registry-cache:/out/civil-cache",
                        "social-protection-registry-cache:/out/social-cache",
                        "health-registry-cache:/out/health-cache",
                    ],
                },
                "postgres": {"image": "postgres:16-alpine", "environment": required_env},
                "redis": {"image": "redis:7.4-alpine"},
                "citizen-civil-notary": {
                    "image": "${REGISTRY_NOTARY_IMAGE:-ghcr.io/registrystack/registry-notary@sha256:abc}",
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
                    "image": "python:3.12.3-slim-bookworm",
                    "expose": ["8080"],
                },
                "lab-homepage": {
                    "image": "python:3.12.3-slim-bookworm",
                    "expose": ["8080"],
                    "environment": required_env,
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
                    "image": "${REGISTRY_NOTARY_OPENFN_SIDECAR_IMAGE:-ghcr.io/registrystack/registry-notary-openfn-sidecar@sha256:abc}",
                    "environment": {
                        "OPENFN_DHIS2_HOST_URL": "https://play.im.dhis2.org/stable-2-43-0"
                    },
                    "volumes": [
                        "./config/coolify/openfn/openfn-dhis2-sidecar.yaml.template:/etc/registry-notary-openfn/openfn-dhis2-sidecar.yaml.template:ro",
                        "./config/openfn/jobs:/opt/openfn/jobs:ro",
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
                "citizen-civil-notary": f"citizen-notary.{lab}",
                "civil-registry-relay": f"civil-relay.{lab}",
                "social-protection-registry-relay": f"social-relay.{lab}",
                "health-registry-relay": f"health-relay.{lab}",
                "static-metadata-publisher": f"metadata.{lab}",
                "lab-homepage": lab,
                "zitadel": f"zitadel.{lab}",
                "dhis2-health-notary": f"dhis2-notary.{lab}",
                "opencrvs-dci-notary": f"opencrvs-notary.{lab}",
            },
        }

    @staticmethod
    def _valid_esignet() -> dict:
        lab = "lab.registrystack.org"
        return {
            "services": {
                "database": {
                    "image": "postgres:bookworm",
                    "environment": {
                        "REGISTRY_LAB_ESIGNET_POSTGRES_PASSWORD": "${REGISTRY_LAB_ESIGNET_POSTGRES_PASSWORD:-}",
                    },
                },
                "redis": {"image": "redis:6.0"},
                "mock-identity-system": {
                    "image": "mosipid/mock-identity-system:0.13.0",
                    "environment": {"MOSIP_ESIGNET_HOST": f"esignet.{lab}"},
                },
                "esignet": {
                    "image": "mosipid/esignet-with-plugins:1.8.0",
                    "expose": ["8088"],
                    "environment": {
                        "MOSIP_ESIGNET_PUBLIC_URL": f"https://esignet.{lab}",
                        "MOSIP_ESIGNET_UI_PUBLIC_URL": f"https://esignet-ui.{lab}",
                        "MOSIP_ESIGNET_DISCOVERY_ISSUER_ID": f"https://esignet.{lab}",
                        "MOSIP_ESIGNET_DISCOVERY_KEY_VALUES": "{'issuer':'https://esignet.lab.registrystack.org'}",
                        "MOSIP_ESIGNET_MOCK_DOMAIN_URL": "http://mock-identity-system:8082",
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
                    "image": "python:3.12-alpine",
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
