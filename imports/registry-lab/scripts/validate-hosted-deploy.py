#!/usr/bin/env python3
"""Validate hosted Coolify deployment artifacts before deployment."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


LAB_DOMAIN = "lab.registrystack.org"

REQUIRED_SERVICES = {
    "registry-lab": {
        "config-loader",
        "postgres",
        "redis",
        "civil-notary",
        "citizen-civil-notary",
        "civil-registry-relay",
        "social-protection-registry-relay",
        "health-registry-relay",
        "static-metadata-publisher",
        "lab-homepage",
        "zitadel",
        "openfn-dhis2-sidecar",
        "dhis2-health-notary",
        "opencrvs-dci-notary",
    },
    "esignet": {
        "database",
        "redis",
        "mock-identity-system",
        "esignet",
        "esignet-ui",
    },
    "walt": {
        "walt-postgres",
        "wallet-api",
        "waltid-demo-wallet",
        "caddy",
    },
}

REQUIRED_DOMAINS = {
    "registry-lab": {
        "citizen-civil-notary": f"citizen-notary.{LAB_DOMAIN}",
        "civil-registry-relay": f"civil-relay.{LAB_DOMAIN}",
        "social-protection-registry-relay": f"social-relay.{LAB_DOMAIN}",
        "health-registry-relay": f"health-relay.{LAB_DOMAIN}",
        "static-metadata-publisher": f"metadata.{LAB_DOMAIN}",
        "lab-homepage": LAB_DOMAIN,
        "zitadel": f"zitadel.{LAB_DOMAIN}",
        "dhis2-health-notary": f"dhis2-notary.{LAB_DOMAIN}",
        "opencrvs-dci-notary": f"opencrvs-notary.{LAB_DOMAIN}",
    },
    "esignet": {
        "esignet": f"esignet.{LAB_DOMAIN}",
        "esignet-ui": f"esignet-ui.{LAB_DOMAIN}",
    },
    "walt": {
        "caddy": f"wallet.{LAB_DOMAIN}",
    },
}

REQUIRED_HOSTED_VARIABLES = {
    "registry-lab": {
        "REGISTRY_LAB_POSTGRES_PASSWORD",
        "CONFIG_REPO_REF",
        "ZITADEL_MASTERKEY",
        "REGISTRY_NOTARY_AUDIT_HASH_SECRET",
        "REGISTRY_NOTARY_ISSUER_JWK",
        "REGISTRY_NOTARY_ACCESS_TOKEN_JWK",
        "REGISTRY_NOTARY_ESIGNET_RP_JWK",
        "CIVIL_EVIDENCE_CLIENT_BEARER",
        "CIVIL_EVIDENCE_CLIENT_BEARER_HASH",
        "CIVIL_EVIDENCE_SOURCE_RAW",
        "CIVIL_METADATA_CLIENT_RAW",
        "CIVIL_EVIDENCE_ONLY_RAW",
        "CIVIL_ROW_READER_RAW",
        "SOCIAL_METADATA_CLIENT_RAW",
        "SOCIAL_EVIDENCE_ONLY_RAW",
        "SOCIAL_ROW_READER_RAW",
        "SOCIAL_AGGREGATE_READER_RAW",
        "HEALTH_METADATA_CLIENT_RAW",
        "HEALTH_EVIDENCE_ONLY_RAW",
        "HEALTH_ROW_READER_RAW",
        "DHIS2_EVIDENCE_CLIENT_TOKEN",
        "DHIS2_EVIDENCE_CLIENT_BEARER",
        "OPENCRVS_EVIDENCE_CLIENT_TOKEN",
        "OPENFN_SIDECAR_TOKEN_HASH",
        "OPENFN_SIDECAR_TOKEN_RAW",
        "OPENFN_DHIS2_USERNAME",
        "OPENFN_DHIS2_PASSWORD",
        "DHIS2_EVIDENCE_CLIENT_TOKEN_HASH",
        "DHIS2_EVIDENCE_CLIENT_BEARER_HASH",
        "OPENCRVS_EVIDENCE_CLIENT_TOKEN_HASH",
        "OPENCRVS_DCI_BASE_URL",
        "OPENCRVS_DCI_CLIENT_ID",
        "OPENCRVS_DCI_CLIENT_SECRET",
        "OPENCRVS_DCI_SHA_SECRET",
        "REGISTRY_RELAY_AUDIT_HASH_SECRET",
        "CIVIL_METADATA_CLIENT_HASH",
        "CIVIL_EVIDENCE_SOURCE_HASH",
        "CIVIL_EVIDENCE_ONLY_HASH",
        "CIVIL_ROW_READER_HASH",
        "SHARED_CIVIL_EVIDENCE_SOURCE_HASH",
        "SOCIAL_METADATA_CLIENT_HASH",
        "SOCIAL_EVIDENCE_SOURCE_HASH",
        "SOCIAL_EVIDENCE_ONLY_HASH",
        "SOCIAL_ROW_READER_HASH",
        "SOCIAL_AGGREGATE_READER_HASH",
        "SHARED_SOCIAL_EVIDENCE_SOURCE_HASH",
        "HEALTH_METADATA_CLIENT_HASH",
        "HEALTH_EVIDENCE_SOURCE_HASH",
        "HEALTH_EVIDENCE_ONLY_HASH",
        "HEALTH_ROW_READER_HASH",
        "SHARED_HEALTH_EVIDENCE_SOURCE_HASH",
    },
    "esignet": {
        "REGISTRY_LAB_ESIGNET_POSTGRES_PASSWORD",
        "REGISTRY_LAB_ESIGNET_CLIENT_REDIRECT_URIS_JSON",
    },
    "walt": {
        "WALT_DB_PASSWORD",
        "WALT_AUTH_ENCRYPTION_KEY",
        "WALT_AUTH_SIGN_KEY",
        "WALT_AUTH_TOKEN_KEY",
        "WALT_KTOR_SIGNING_KEY",
        "WALT_KTOR_VERIFICATION_KEY",
    },
}

ALLOWED_INTERIM_PRODUCT_IMAGES = {
    "registry-relay:hosted",
    "registry-notary:hosted",
    "registry-notary-openfn-sidecar:hosted",
}

PRODUCT_IMAGE_NAMES = (
    "registry-notary-openfn-sidecar",
    "registry-relay",
    "registry-notary",
)
PRODUCT_IMAGE_ENV_BY_NAME = {
    "registry-relay": "REGISTRY_RELAY_IMAGE",
    "registry-notary": "REGISTRY_NOTARY_IMAGE",
    "registry-notary-openfn-sidecar": "REGISTRY_NOTARY_OPENFN_SIDECAR_IMAGE",
}

PUBLIC_KEYWORDS = (
    "API_BASE_URL",
    "AUTHORIZATION",
    "BASE_URL",
    "CALLBACK",
    "CREDENTIAL_ENDPOINT",
    "CREDENTIAL_ISSUER",
    "DISCOVERY",
    "DOMAIN",
    "ENDPOINT",
    "EXTERNALDOMAIN",
    "HOST",
    "ISSUER",
    "JWKS",
    "ORIGIN",
    "PUBLIC_URL",
    "REDIRECT",
    "TOKEN_ENDPOINT",
    "UI_PUBLIC_URL",
    "URI",
    "URL",
    "USERINFO",
)
PUBLIC_SERVICE_KEYS = {
    "domain",
    "domains",
    "labels",
    "x-coolify-domain",
    "x-coolify-domains",
    "x-hosted-domain",
    "x-hosted-domains",
}
URL_RE = re.compile(r"https?://[^\s'\"<>),]+")
HOST_RULE_RE = re.compile(r"Host\(([^)]*)\)")
LOOPBACK_RE = re.compile(r"(^|[^a-z0-9_.-])(localhost|127(?:\.\d{1,3}){3})(?=$|[^a-z0-9_.-])", re.I)
REQUIRED_VAR_RE = re.compile(r"required variable ([A-Za-z_][A-Za-z0-9_]*) is missing")
SCANNED_FILE_SUFFIXES = {
    ".conf",
    ".env",
    ".json",
    ".template",
    ".toml",
    ".yaml",
    ".yml",
}
HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
HOSTED_CONFIG_DIRS = (
    Path("config/coolify/notary"),
    Path("config/coolify/relay"),
)
DHIS2_PROGRAMME_PROFILE = "dhis2_programme_participation_sd_jwt"
DHIS2_PROGRAMME_CLAIMS = {
    "dhis2-tracked-entity-first-name",
    "dhis2-tracked-entity-last-name",
    "dhis2-child-age-band",
    "dhis2-programme-code",
    "dhis2-child-program-active",
    "dhis2-reconciliation-ref",
}


@dataclass(frozen=True)
class Issue:
    code: str
    artifact: str
    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.artifact}:{self.path}: [{self.code}] {self.message}"


class DuplicateYamlKeyError(ValueError):
    pass


def validate_artifacts(
    artifacts: dict[str, dict[str, Any]],
    artifact_roots: dict[str, Path] | None = None,
    artifact_texts: dict[str, str] | None = None,
    *,
    require_secret_values: bool = False,
    env: dict[str, str] | None = None,
) -> list[Issue]:
    issues: list[Issue] = []
    artifact_roots = artifact_roots or {}
    artifact_texts = artifact_texts or {}
    env = dict(os.environ if env is None else env)
    for artifact, compose in artifacts.items():
        root = artifact_roots.get(artifact, Path("."))
        services = compose.get("services")
        if not isinstance(services, dict):
            issues.append(
                Issue(
                    "missing-services-section",
                    artifact,
                    "services",
                    "compose artifact must define a services map",
                )
            )
            services = {}

        issues.extend(validate_required_services(artifact, services))
        issues.extend(validate_required_domains(artifact, compose, services, root))
        issues.extend(
            validate_required_variables(
                artifact,
                compose,
                artifact_texts.get(artifact, ""),
                require_secret_values,
                env,
            )
        )
        issues.extend(validate_service_ports(artifact, services))
        issues.extend(validate_build_inputs(artifact, compose))
        issues.extend(
            validate_image_refs(artifact, services, artifact_texts.get(artifact, ""))
        )
        issues.extend(validate_runtime_commands(artifact, services))
        issues.extend(validate_openfn_sidecar_governance(artifact, services, root))
        issues.extend(validate_repo_output_binds(artifact, services))
        issues.extend(validate_public_urls(artifact, compose, root))
        issues.extend(validate_hosted_openapi_policy(artifact, services, root))
        issues.extend(
            validate_civil_alive_scenario_contract(
                artifact,
                compose,
                services,
                root,
                artifact_texts.get(artifact, ""),
            )
        )
        issues.extend(validate_config_loader_ref(artifact, services))
        issues.extend(validate_config_loader_hosted_outputs(artifact, services))
        issues.extend(validate_hosted_yaml_files(artifact, root))
        issues.extend(validate_dhis2_programme_vc_contract(artifact, root))
        if require_secret_values:
            issues.extend(validate_credential_commitments(artifact, root, env))
        issues.extend(
            validate_static_metadata_publisher(
                artifact,
                services,
            )
        )

    issues.extend(validate_cross_artifact_contracts(artifacts, artifact_roots))
    return sorted(dedupe_issues(issues), key=lambda issue: (issue.artifact, issue.path, issue.code))


def validate_required_services(artifact: str, services: dict[str, Any]) -> list[Issue]:
    issues = []
    for service in sorted(REQUIRED_SERVICES.get(artifact, set())):
        if service not in services:
            issues.append(
                Issue(
                    "missing-service",
                    artifact,
                    f"services.{service}",
                    f"required hosted service {service!r} is missing",
                )
            )
    return issues


def validate_required_domains(
    artifact: str,
    compose: dict[str, Any],
    services: dict[str, Any],
    root: Path,
) -> list[Issue]:
    issues = []
    for service, domain in sorted(REQUIRED_DOMAINS.get(artifact, {}).items()):
        if service not in services:
            continue
        domains = collect_domains_for_service(compose, service, root)
        if domain not in domains:
            found = ", ".join(sorted(domains)) or "none"
            issues.append(
                Issue(
                    "missing-domain",
                    artifact,
                    f"services.{service}",
                    f"required hosted domain {domain!r} is missing; found {found}",
                )
            )
    return issues


def validate_required_variables(
    artifact: str,
    compose: dict[str, Any],
    raw_text: str,
    require_secret_values: bool,
    env: dict[str, str],
) -> list[Issue]:
    issues = []
    for variable in sorted(REQUIRED_HOSTED_VARIABLES.get(artifact, set())):
        if not compose_references_variable(compose, variable, raw_text):
            issues.append(
                Issue(
                    "missing-required-variable",
                    artifact,
                    variable,
                    f"required hosted variable {variable!r} is not referenced by the compose artifact",
                )
            )
        if require_secret_values and not usable_secret_value(env.get(variable)):
            issues.append(
                Issue(
                    "missing-required-secret-value",
                    artifact,
                    variable,
                    f"required hosted variable {variable!r} has no non-placeholder value in the environment",
                )
            )
    return issues


def validate_service_ports(artifact: str, services: dict[str, Any]) -> list[Issue]:
    issues = []
    for service, config in services.items():
        if isinstance(config, dict) and config.get("ports"):
            issues.append(
                Issue(
                    "host-ports",
                    artifact,
                    f"services.{service}.ports",
                    "hosted Coolify compose must not publish host ports",
                )
            )
    return issues


def validate_build_inputs(artifact: str, compose: dict[str, Any]) -> list[Issue]:
    issues = []
    services = compose.get("services")
    if isinstance(services, dict):
        for service, config in services.items():
            if not isinstance(config, dict) or not config.get("build"):
                continue
            if (
                artifact == "registry-lab"
                and service == "static-metadata-publisher"
                and static_metadata_build_uses_generator(config.get("build"))
            ):
                continue
            if isinstance(config, dict) and config.get("build"):
                issues.append(
                    Issue(
                        "host-build",
                        artifact,
                        f"services.{service}.build",
                        "hosted compose must consume pre-built images, not build on the host",
                    )
                )

    for path, value in walk(compose):
        if path and path[-1] == "additional_contexts" and value:
            issues.append(
                Issue(
                    "additional-contexts",
                    artifact,
                    format_path(path),
                    "hosted compose must not reference local additional_contexts",
                )
            )
    return issues


def validate_image_refs(
    artifact: str, services: dict[str, Any], artifact_text: str = ""
) -> list[Issue]:
    issues = []
    for service, config in services.items():
        if not isinstance(config, dict):
            continue
        image = config.get("image")
        if not isinstance(image, str):
            continue
        if image_uses_latest_tag(image):
            issues.append(
                Issue(
                    "latest-image-tag",
                    artifact,
                    f"services.{service}.image",
                    "hosted compose must not deploy images tagged latest",
                )
            )
        if image_uses_floating_product_tag(image):
            issues.append(
                Issue(
                    "floating-product-image-tag",
                    artifact,
                    f"services.{service}.image",
                    "canonical product images must be digest-pinned; use only local :hosted tags as interim",
                )
            )
        if artifact == "registry-lab":
            product_name = product_image_name(image)
            if product_name is not None and not artifact_uses_product_env_fallback(
                artifact_text, image, PRODUCT_IMAGE_ENV_BY_NAME[product_name]
            ):
                issues.append(
                    Issue(
                        "product-image-env-var",
                        artifact,
                        f"services.{service}.image",
                        "hosted product image must use "
                        f"{PRODUCT_IMAGE_ENV_BY_NAME[product_name]} "
                        "with a digest-pinned fallback",
                    )
                )
    return issues


def validate_runtime_commands(artifact: str, services: dict[str, Any]) -> list[Issue]:
    issues = []
    if artifact != "registry-lab":
        return issues
    for service, config in services.items():
        if not isinstance(config, dict):
            continue
        image = str(config.get("image", ""))
        if is_registry_relay_service(service, image):
            healthcheck_text = json.dumps(config.get("healthcheck"), sort_keys=True)
            if "registry-notary" in healthcheck_text:
                issues.append(
                    Issue(
                        "unsupported-relay-healthcheck",
                        artifact,
                        f"services.{service}.healthcheck",
                        "relay healthchecks must use tools available in the relay image, not registry-notary",
                    )
                )
            if "curl" in healthcheck_text:
                issues.append(
                    Issue(
                        "unsupported-relay-healthcheck",
                        artifact,
                        f"services.{service}.healthcheck",
                        "distroless relay healthchecks must use registry-relay healthcheck, not curl",
                    )
                )
        if is_registry_notary_service(service, image):
            healthcheck_text = json.dumps(config.get("healthcheck"), sort_keys=True)
            if "curl" in healthcheck_text:
                issues.append(
                    Issue(
                        "unsupported-notary-healthcheck",
                        artifact,
                        f"services.{service}.healthcheck",
                        "notary healthchecks must use registry-notary healthcheck, not curl",
                    )
                )
            entrypoint_text = json.dumps(config.get("entrypoint"), sort_keys=True)
            if "/bin/sh" in entrypoint_text or '"sh"' in entrypoint_text:
                issues.append(
                    Issue(
                        "unsupported-notary-entrypoint",
                        artifact,
                        f"services.{service}.entrypoint",
                        "distroless notary images must not require a shell entrypoint",
                    )
                )
    return issues


def validate_openfn_sidecar_governance(
    artifact: str,
    services: dict[str, Any],
    root: Path,
) -> list[Issue]:
    if artifact != "registry-lab":
        return []
    openfn = services.get("openfn-dhis2-sidecar")
    if not isinstance(openfn, dict):
        return []

    issues: list[Issue] = []
    command_text = shell_command_text(openfn.get("command"))
    if "--allow-unsigned-dev-config" in command_text:
        issues.append(
            Issue(
                "hosted-openfn-unsigned-dev-config",
                artifact,
                "services.openfn-dhis2-sidecar.command",
                "hosted OpenFn sidecar must start from governed config_trust, not unsigned dev config",
            )
        )
    if "openfn-dhis2-sidecar.bootstrap.yaml" not in command_text:
        issues.append(
            Issue(
                "missing-openfn-governed-bootstrap",
                artifact,
                "services.openfn-dhis2-sidecar.command",
                "hosted OpenFn sidecar must use the governed bootstrap config",
            )
        )
    required_mounts = {
        "/etc/registry-notary-openfn",
        "/tmp/registry-lab-openfn-jobs",
        "/var/lib/registry-notary-openfn-sidecar/tuf",
        "/var/lib/registry-notary-openfn-sidecar/config-trust",
    }
    for target in sorted(required_mounts):
        if not service_mounts_target(openfn, target):
            issues.append(
                Issue(
                    "missing-openfn-governed-mount",
                    artifact,
                    "services.openfn-dhis2-sidecar.volumes",
                    f"hosted OpenFn sidecar must mount {target}",
                )
            )

    bootstrap = root / "config/coolify/openfn/openfn-dhis2-sidecar.bootstrap.yaml"
    notary = root / "config/coolify/notary/dhis2-health-notary.yaml"
    report = root / "config/coolify/openfn/governed/openfn-dhis2-sidecar-runtime.report.json"
    try:
        bootstrap_config = load_yaml_mapping(bootstrap)
        notary_config = load_yaml_mapping(notary)
        report_config = load_json_mapping(report)
    except Exception as exc:
        issues.append(
            Issue(
                "unreadable-openfn-governed-artifact",
                artifact,
                "config/coolify/openfn/governed",
                f"could not read governed OpenFn sidecar artifacts: {exc}",
            )
        )
        return issues

    config_trust = extract_openfn_config_trust_scalars(bootstrap_config)
    accepted_roots = nested_get(bootstrap_config, ("config_trust", "accepted_roots"))
    if not config_trust or not isinstance(accepted_roots, list) or not accepted_roots:
        issues.append(
            Issue(
                "missing-openfn-config-trust",
                artifact,
                "config/coolify/openfn/openfn-dhis2-sidecar.bootstrap.yaml",
                "hosted OpenFn sidecar bootstrap must include config_trust.accepted_roots",
            )
        )

    expected = extract_openfn_expected_sidecar_scalars(notary_config)
    if not expected:
        issues.append(
            Issue(
                "missing-openfn-expected-sidecar",
                artifact,
                "config/coolify/notary/dhis2-health-notary.yaml",
                "hosted DHIS2 Notary must pin expected_sidecar for the OpenFn sidecar",
            )
        )
        return issues

    expected_hash = report_config.get("config_hash")
    if expected.get("config_hash") != expected_hash:
        issues.append(
            Issue(
                "openfn-sidecar-hash-mismatch",
                artifact,
                "config/coolify/notary/dhis2-health-notary.yaml",
                "hosted DHIS2 Notary expected_sidecar.config_hash must match the generated sidecar report",
            )
        )
    for key in (
        "require_expression_hashes_verified",
        "require_runtime_verified",
        "require_smoke_verified",
    ):
        if expected.get(key) not in (True, "true"):
            issues.append(
                Issue(
                    "openfn-sidecar-assurance-not-required",
                    artifact,
                    f"config/coolify/notary/dhis2-health-notary.yaml:{key}",
                    "hosted DHIS2 Notary must require expression, runtime, and smoke assurance",
                )
            )
    for key in ("product", "instance_id", "environment", "stream_id"):
        if expected.get(key) != config_trust.get(key):
            issues.append(
                Issue(
                    "openfn-sidecar-identity-mismatch",
                    artifact,
                    f"config/coolify/notary/dhis2-health-notary.yaml:{key}",
                    "hosted DHIS2 Notary expected_sidecar identity must match sidecar config_trust",
                )
            )
    return issues


def extract_openfn_config_trust_scalars(config: dict[str, Any]) -> dict[str, Any]:
    trust = config.get("config_trust")
    if not isinstance(trust, dict):
        return {}
    return {
        key: trust.get(key)
        for key in ("product", "instance_id", "environment", "stream_id")
        if trust.get(key) is not None
    }


def extract_openfn_expected_sidecar_scalars(config: dict[str, Any]) -> dict[str, Any]:
    expected = nested_get(
        config,
        ("evidence", "source_connections", "dhis2_openfn", "expected_sidecar"),
    )
    if not isinstance(expected, dict):
        return {}
    return expected


def validate_repo_output_binds(artifact: str, services: dict[str, Any]) -> list[Issue]:
    issues = []
    for service, config in services.items():
        if not isinstance(config, dict):
            continue
        volumes = config.get("volumes") or []
        if not isinstance(volumes, list):
            continue
        for index, volume in enumerate(volumes):
            source = volume_source(volume)
            if source and is_repo_output_source(source):
                issues.append(
                    Issue(
                        "repo-output-bind",
                        artifact,
                        f"services.{service}.volumes[{index}]",
                        "hosted seed or secret material must not bind-mount repo ./output",
                    )
                )
    return issues


def validate_public_urls(artifact: str, compose: dict[str, Any], root: Path) -> list[Issue]:
    issues = []
    for path, key, value in iter_public_settings(compose):
        issues.extend(validate_public_text(artifact, format_path(path), key, str(value)))

    services = compose.get("services") or {}
    if isinstance(services, dict):
        for service, config in services.items():
            if not isinstance(config, dict):
                continue
            for file_path, text in iter_referenced_file_texts(root, config):
                issues.extend(
                    validate_public_text(
                        artifact,
                        f"services.{service}.volumes:{file_path}",
                        str(file_path),
                        text,
                    )
                )
    return issues


def validate_hosted_openapi_policy(
    artifact: str,
    services: dict[str, Any],
    root: Path,
) -> list[Issue]:
    issues = []
    if artifact != "registry-lab":
        return issues
    for service, config in services.items():
        if not isinstance(config, dict):
            continue
        config_path = hosted_product_config_path(root, config)
        if config_path is None or not config_path.exists():
            continue
        try:
            config_text = config_path.read_text(encoding="utf-8")
        except Exception as exc:
            issues.append(
                Issue(
                    "unreadable-product-config",
                    artifact,
                    f"services.{service}.command",
                    f"could not read hosted product config {config_path}: {exc}",
                )
            )
            continue
        if not hosted_openapi_requires_auth_is_false(config_text):
            issues.append(
                Issue(
                    "openapi-auth-required",
                    artifact,
                    f"services.{service}.server.openapi_requires_auth",
                    "hosted lab Relay and Notary OpenAPI endpoints must be public for demos",
                )
            )
    return issues


def validate_civil_alive_scenario_contract(
    artifact: str,
    compose: dict[str, Any],
    services: dict[str, Any],
    root: Path,
    raw_text: str = "",
) -> list[Issue]:
    if artifact != "registry-lab":
        return []

    issues: list[Issue] = []
    lab_homepage = services.get("lab-homepage")
    civil_notary = services.get("civil-notary")

    if isinstance(lab_homepage, dict):
        env = normalize_environment(lab_homepage.get("environment"))
        if env.get("CIVIL_EVIDENCE_URL") != "http://civil-notary:8080":
            issues.append(
                Issue(
                    "missing-civil-alive-notary-url",
                    artifact,
                    "services.lab-homepage.environment.CIVIL_EVIDENCE_URL",
                    "alive-proof Step 2 must call the internal civil-notary evidence API",
                )
            )
        if not environment_uses_rendered_or_referenced_secret(
            raw_text,
            "lab-homepage",
            env,
            "CIVIL_EVIDENCE_CLIENT_BEARER",
        ):
            issues.append(
                Issue(
                    "missing-civil-alive-notary-bearer",
                    artifact,
                    "services.lab-homepage.environment.CIVIL_EVIDENCE_CLIENT_BEARER",
                    "alive-proof Step 2 must receive the hosted civil Notary bearer token",
                )
            )
    if isinstance(civil_notary, dict):
        env = normalize_environment(civil_notary.get("environment"))
        if not environment_uses_rendered_or_referenced_secret(
            raw_text,
            "civil-notary",
            env,
            "CIVIL_EVIDENCE_CLIENT_BEARER_HASH",
            required_prefix="sha256:",
        ):
            issues.append(
                Issue(
                    "missing-civil-notary-bearer-hash",
                    artifact,
                    "services.civil-notary.environment.CIVIL_EVIDENCE_CLIENT_BEARER_HASH",
                    "hosted civil-notary must verify the bearer token used by alive-proof Step 2",
                )
            )
        if hosted_notary_config_path(root, civil_notary) != root / "config/coolify/notary/civil-notary.yaml":
            issues.append(
                Issue(
                    "missing-civil-notary-config",
                    artifact,
                    "services.civil-notary.command",
                    "hosted civil-notary must start with config/coolify/notary/civil-notary.yaml",
                )
            )
    return issues


def environment_uses_rendered_or_referenced_secret(
    raw_text: str,
    service: str,
    env: dict[str, str],
    variable: str,
    *,
    required_prefix: str | None = None,
) -> bool:
    value = env.get(variable)
    if value == "${" + variable + ":-}":
        return True
    if value and usable_secret_value(value):
        if required_prefix is None or value.startswith(required_prefix):
            return True
    return service_block_references_variable(raw_text, service, variable)


def service_block_references_variable(raw_text: str, service: str, variable: str) -> bool:
    if not raw_text:
        return False
    service_re = re.compile(
        rf"(?ms)^  {re.escape(service)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_.-]+:|\Z)"
    )
    match = service_re.search(raw_text)
    if not match:
        return False
    variable_ref_re = r"\$\{" + re.escape(variable) + r"(?::[-?][^}]*)?\}"
    return re.search(variable_ref_re, match.group("body")) is not None


def validate_config_loader_ref(artifact: str, services: dict[str, Any]) -> list[Issue]:
    if artifact not in {"registry-lab", "esignet", "walt"}:
        return []
    config_loader = services.get("config-loader")
    if not isinstance(config_loader, dict):
        return []
    env = normalize_environment(config_loader.get("environment"))
    config_ref = env.get("CONFIG_REPO_REF")
    if config_ref in {
        "${CONFIG_REPO_REF:?set CONFIG_REPO_REF to the deployed registry-lab git ref}",
        "hosted-validation-placeholder",
    } or (isinstance(config_ref, str) and bool(re.fullmatch(r"[0-9a-f]{40}", config_ref))):
        return []
    return [
        Issue(
            "stale-config-repo-ref",
            artifact,
            "services.config-loader.environment.CONFIG_REPO_REF",
            "hosted config-loader must require a deployed git ref, not a floating or stale branch",
        )
    ]


def validate_config_loader_hosted_outputs(
    artifact: str,
    services: dict[str, Any],
) -> list[Issue]:
    if artifact != "registry-lab":
        return []
    config_loader = services.get("config-loader")
    if not isinstance(config_loader, dict):
        return []

    command_text = shell_command_text(config_loader.get("command"))
    volumes = config_loader.get("volumes") or []
    issues = []
    if not all(
        has_service_volume(volumes, source, target)
        for source, target in (
            ("civil-registry-cache", "/out/civil-cache"),
            ("social-protection-registry-cache", "/out/social-cache"),
            ("health-registry-cache", "/out/health-cache"),
            ("openfn-sidecar-tuf-state", "/out/openfn-tuf-state"),
            ("openfn-sidecar-config-state", "/out/openfn-config-state"),
        )
    ) or not all(
        token in command_text
        for token in (
            "chown -R 65532:65532",
            "civil-cache social-cache health-cache",
            "chown -R 1000:1000",
            "openfn-tuf-state openfn-config-state",
            "dhis2-openfn-sidecar-antirollback.json",
            "last_sequence\":0",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        )
    ):
        issues.append(
            Issue(
                "runtime-state-not-chowned",
                artifact,
                "services.config-loader",
                "hosted Relay and OpenFn runtime state volumes must be writable by their runtime users",
            )
        )
    if "cp -a /tmp/repo/scripts/lab_homepage_scenarios /out/static-scripts/" not in command_text:
        issues.append(
            Issue(
                "lab-homepage-scenarios-not-copied",
                artifact,
                "services.config-loader.command",
                "hosted config-loader must copy the lab_homepage_scenarios package used by lab-homepage-server.py",
            )
        )
    if "cp -a /tmp/repo/config/coolify/notary/civil-notary.yaml /out/notary/" not in command_text:
        issues.append(
            Issue(
                "civil-notary-config-not-copied",
                artifact,
                "services.config-loader.command",
                "hosted config-loader must copy the internal civil Notary config",
            )
        )
    for target, config_path in hosted_service_config_copies(services):
        expected = f"cp -a /tmp/repo/{config_path} {target}"
        directory = Path(config_path).parent
        directory_copy = f"cp -a /tmp/repo/{directory}/. {target}"
        if expected not in command_text and directory_copy not in command_text:
            issues.append(
                Issue(
                    "hosted-config-not-copied",
                    artifact,
                    "services.config-loader.command",
                    f"hosted config-loader must copy {config_path}",
                )
            )
    return issues


def hosted_service_config_copies(services: dict[str, Any]) -> set[tuple[str, str]]:
    copies: set[tuple[str, str]] = set()
    for service, config in services.items():
        if not isinstance(config, dict):
            continue
        command = config.get("command")
        if not isinstance(command, list):
            continue
        for index, value in enumerate(command[:-1]):
            if value != "--config":
                continue
            mounted_path = Path(str(command[index + 1]))
            name = mounted_path.name
            if not name:
                continue
            mounted_text = str(mounted_path)
            if "/registry-notary/" in mounted_text:
                source = f"config/coolify/notary/{name}"
                target = "/out/notary/"
            elif "/registry-relay/" in mounted_text:
                source = f"config/coolify/relay/{name}"
                target = "/out/relay/"
            else:
                continue
            copies.add((target, source))
    return copies


def validate_hosted_yaml_files(artifact: str, root: Path) -> list[Issue]:
    if artifact != "registry-lab":
        return []
    issues: list[Issue] = []
    for relative_dir in HOSTED_CONFIG_DIRS:
        directory = root / relative_dir
        if not directory.exists():
            continue
        for path in sorted(directory.glob("*.yaml")):
            try:
                load_yaml_mapping_strict(path)
            except DuplicateYamlKeyError as exc:
                issues.append(
                    Issue(
                        "duplicate-yaml-key",
                        artifact,
                        str(path.relative_to(root)),
                        str(exc),
                    )
                )
            except Exception as exc:
                issues.append(
                    Issue(
                        "unreadable-hosted-yaml",
                        artifact,
                        str(path.relative_to(root)),
                        f"could not parse hosted YAML config: {exc}",
                    )
                )
    return issues


def validate_dhis2_programme_vc_contract(artifact: str, root: Path) -> list[Issue]:
    if artifact != "registry-lab":
        return []
    path = root / "config/coolify/notary/dhis2-health-notary.yaml"
    try:
        config = load_yaml_mapping_strict(path)
    except Exception as exc:
        return [
            Issue(
                "unreadable-dhis2-notary-config",
                artifact,
                "config/coolify/notary/dhis2-health-notary.yaml",
                f"could not read hosted DHIS2 Notary config: {exc}",
            )
        ]

    issues: list[Issue] = []
    evidence = config.get("evidence") if isinstance(config.get("evidence"), dict) else {}
    if evidence.get("max_credential_validity_seconds") != 31_536_000:
        issues.append(
            Issue(
                "dhis2-programme-validity-ceiling",
                artifact,
                "config/coolify/notary/dhis2-health-notary.yaml:evidence.max_credential_validity_seconds",
                "hosted DHIS2 Notary must allow one-year programme participation credentials",
            )
        )
    profiles = evidence.get("credential_profiles") if isinstance(evidence, dict) else None
    profile = profiles.get(DHIS2_PROGRAMME_PROFILE) if isinstance(profiles, dict) else None
    if not isinstance(profile, dict):
        issues.append(
            Issue(
                "missing-dhis2-programme-profile",
                artifact,
                "config/coolify/notary/dhis2-health-notary.yaml:evidence.credential_profiles",
                f"hosted DHIS2 Notary must define {DHIS2_PROGRAMME_PROFILE}",
            )
        )
        return issues
    if profile.get("validity_seconds") != 31_536_000:
        issues.append(
            Issue(
                "dhis2-programme-profile-validity",
                artifact,
                f"config/coolify/notary/dhis2-health-notary.yaml:{DHIS2_PROGRAMME_PROFILE}.validity_seconds",
                "DHIS2 programme participation VC must be valid for one year",
            )
        )
    allowed_claims = set(profile.get("allowed_claims") or [])
    missing_claims = sorted(DHIS2_PROGRAMME_CLAIMS - allowed_claims)
    if missing_claims:
        issues.append(
            Issue(
                "dhis2-programme-claims-missing",
                artifact,
                f"config/coolify/notary/dhis2-health-notary.yaml:{DHIS2_PROGRAMME_PROFILE}.allowed_claims",
                "DHIS2 programme participation VC is missing claims: " + ", ".join(missing_claims),
            )
        )
    holder = profile.get("holder_binding") if isinstance(profile.get("holder_binding"), dict) else {}
    if (
        holder.get("mode") != "did"
        or holder.get("proof_of_possession") != "required"
        or "did:jwk" not in (holder.get("allowed_did_methods") or [])
    ):
        issues.append(
            Issue(
                "dhis2-programme-holder-binding",
                artifact,
                f"config/coolify/notary/dhis2-health-notary.yaml:{DHIS2_PROGRAMME_PROFILE}.holder_binding",
                "DHIS2 programme participation VC must require did:jwk proof of possession",
            )
        )
    configured_claims = {
        claim.get("id"): claim
        for claim in evidence.get("claims", [])
        if isinstance(claim, dict) and isinstance(claim.get("id"), str)
    }
    for claim_id in sorted(DHIS2_PROGRAMME_CLAIMS):
        claim = configured_claims.get(claim_id)
        if not isinstance(claim, dict):
            issues.append(
                Issue(
                    "dhis2-programme-claim-not-configured",
                    artifact,
                    "config/coolify/notary/dhis2-health-notary.yaml:evidence.claims",
                    f"DHIS2 programme claim {claim_id!r} must be configured",
                )
            )
            continue
        if DHIS2_PROGRAMME_PROFILE not in (claim.get("credential_profiles") or []):
            issues.append(
                Issue(
                    "dhis2-programme-claim-profile-missing",
                    artifact,
                    f"config/coolify/notary/dhis2-health-notary.yaml:evidence.claims.{claim_id}",
                    f"claim {claim_id!r} must allow {DHIS2_PROGRAMME_PROFILE}",
                )
            )
    return issues


def validate_credential_commitments(
    artifact: str,
    root: Path,
    env: dict[str, str],
) -> list[Issue]:
    if artifact != "registry-lab":
        return []
    issues: list[Issue] = []
    for product, relative_dir in (
        ("registry-notary", Path("config/coolify/notary")),
        ("registry-relay", Path("config/coolify/relay")),
    ):
        directory = root / relative_dir
        if not directory.exists():
            continue
        for path in sorted(directory.glob("*.yaml")):
            try:
                config = load_yaml_mapping_strict(path)
            except Exception:
                continue
            for credential_type, entry in iter_credential_entries(product, config):
                fingerprint = entry.get("fingerprint") if isinstance(entry, dict) else None
                if not isinstance(fingerprint, dict):
                    continue
                env_name = fingerprint.get("name")
                commitment = fingerprint.get("commitment")
                credential_id = entry.get("id")
                if not all(isinstance(value, str) for value in (env_name, commitment, credential_id)):
                    continue
                supplied_fingerprint = env.get(str(env_name))
                if not supplied_fingerprint:
                    continue
                if not HASH_RE.match(supplied_fingerprint):
                    issues.append(
                        Issue(
                            "credential-fingerprint-invalid",
                            artifact,
                            f"{path.relative_to(root)}:{credential_id}",
                            f"{env_name} must contain a sha256 fingerprint",
                        )
                    )
                    continue
                expected = credential_commitment(
                    product,
                    credential_type,
                    str(credential_id),
                    supplied_fingerprint,
                )
                if commitment != expected:
                    issues.append(
                        Issue(
                            "credential-commitment-mismatch",
                            artifact,
                            f"{path.relative_to(root)}:{credential_id}",
                            f"{env_name} commitment does not match the supplied fingerprint",
                        )
                    )
    return issues


def iter_credential_entries(product: str, config: dict[str, Any]):
    auth = config.get("auth")
    if not isinstance(auth, dict):
        return
    if product == "registry-notary":
        for key, credential_type in (("api_keys", "api_key"), ("bearer_tokens", "bearer_token")):
            for entry in auth.get(key) or []:
                if isinstance(entry, dict):
                    yield credential_type, entry
    elif product == "registry-relay":
        for entry in auth.get("api_keys") or []:
            if isinstance(entry, dict):
                yield "api_key", entry


def credential_commitment(
    product: str,
    credential_type: str,
    credential_id: str,
    fingerprint: str,
) -> str:
    payload = {
        "product": product,
        "credential_type": credential_type,
        "credential_id": credential_id,
        "fingerprint": fingerprint,
    }
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def validate_static_metadata_publisher(
    artifact: str,
    services: dict[str, Any],
) -> list[Issue]:
    if artifact != "registry-lab":
        return []
    service = services.get("static-metadata-publisher")
    if not isinstance(service, dict):
        return []
    issues = []
    image = str(service.get("image", ""))
    if image != "registry-lab-static-metadata:hosted":
        issues.append(
            Issue(
                "static-metadata-image-name",
                artifact,
                "services.static-metadata-publisher.image",
                "hosted static metadata must use the local image built from Dockerfile.static-metadata",
            )
        )
    if not static_metadata_build_uses_generator(service.get("build")):
        issues.append(
            Issue(
                "static-metadata-build",
                artifact,
                "services.static-metadata-publisher.build",
                "hosted static metadata must be generated by Dockerfile.static-metadata",
            )
        )
    if service_mounts_target(service, "/srv/static"):
        issues.append(
            Issue(
                "static-metadata-volume-mount",
                artifact,
                "services.static-metadata-publisher.volumes",
                "hosted static metadata content must come from the generated image, not a Coolify volume",
            )
        )
    healthcheck_text = json.dumps(service.get("healthcheck"), sort_keys=True)
    if "/.well-known/registry-manifest.json" not in healthcheck_text:
        issues.append(
            Issue(
                "static-metadata-healthcheck",
                artifact,
                "services.static-metadata-publisher.healthcheck",
                "static metadata healthcheck must require the generated registry manifest",
            )
        )
    return issues


def static_metadata_build_uses_generator(build: Any) -> bool:
    if isinstance(build, str):
        return False
    if not isinstance(build, dict):
        return False
    return build.get("dockerfile") == "Dockerfile.static-metadata"


def has_service_volume(volumes: Any, source: str, target: str) -> bool:
    for volume in volumes or []:
        if isinstance(volume, str):
            parts = volume.split(":")
            if len(parts) >= 2 and parts[0] == source and parts[1] == target:
                return True
        elif isinstance(volume, dict):
            if volume.get("source") == source and volume.get("target") == target:
                return True
    return False


def shell_command_text(command: Any) -> str:
    if command is None:
        return ""
    if isinstance(command, str):
        return command
    if isinstance(command, list):
        return "\n".join(str(item) for item in command)
    return str(command)


def hosted_openapi_requires_auth_is_false(text: str) -> bool:
    in_server = False
    server_indent = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if stripped == "server:":
            in_server = True
            server_indent = indent
            continue
        if not in_server:
            continue
        if indent <= server_indent:
            in_server = False
            continue
        if re.match(r"openapi_requires_auth\s*:\s*false\b", stripped, flags=re.IGNORECASE):
            return True
    return False


def validate_cross_artifact_contracts(
    artifacts: dict[str, dict[str, Any]],
    artifact_roots: dict[str, Path],
) -> list[Issue]:
    issues = []
    registry_lab = artifacts.get("registry-lab")
    esignet = artifacts.get("esignet")
    if not registry_lab or not esignet:
        return issues

    registry_root = artifact_roots.get("registry-lab", Path("."))
    esignet_root = artifact_roots.get("esignet", Path("."))
    citizen_issuer = extract_citizen_esignet_issuer(registry_lab, registry_root)
    esignet_issuer = extract_esignet_discovery_issuer(esignet, esignet_root)
    if citizen_issuer and esignet_issuer and citizen_issuer != esignet_issuer:
        issues.append(
            Issue(
                "esignet-issuer-mismatch",
                "registry-lab",
                "services.citizen-civil-notary.auth.oidc.issuer",
                f"citizen notary issuer {citizen_issuer!r} must match hosted eSignet issuer {esignet_issuer!r}",
            )
        )

    text = collect_service_contract_text(registry_lab, registry_root, "citizen-civil-notary")
    if text:
        if "person_is_alive_sd_jwt" not in text:
            issues.append(
                Issue(
                    "missing-credential-configuration",
                    "registry-lab",
                    "services.citizen-civil-notary.oid4vci",
                    "citizen OID4VCI contract must advertise person_is_alive_sd_jwt",
                )
            )
        if "dc+sd-jwt" not in text:
            issues.append(
                Issue(
                    "missing-oid4vci-format",
                    "registry-lab",
                    "services.citizen-civil-notary.oid4vci",
                    "citizen OID4VCI contract must advertise dc+sd-jwt",
                )
            )
    return issues


def validate_public_text(artifact: str, issue_path: str, key: str, text: str) -> list[Issue]:
    issues = []
    if "demo.example.gov" in text:
        issues.append(
            Issue(
                "stale-demo-url",
                artifact,
                issue_path,
                "hosted public settings must not advertise demo.example.gov",
            )
        )

    if LOOPBACK_RE.search(text):
        issues.append(
            Issue(
                "public-local-url",
                artifact,
                issue_path,
                f"public hosted setting {key!r} must not reference localhost or loopback",
            )
        )

    for url in extract_urls(text):
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme == "http" and is_public_http_host(host):
            issues.append(
                Issue(
                    "public-http-url",
                    artifact,
                    issue_path,
                    f"public hosted URL must use https, not {url!r}",
                )
            )
    return issues


def collect_domains_for_service(compose: dict[str, Any], service: str, root: Path) -> set[str]:
    domains: set[str] = set()
    top_domains = compose.get("x-hosted-domains")
    if isinstance(top_domains, dict) and service in top_domains:
        domains.update(extract_domains(top_domains[service]))

    service_config = compose.get("services", {}).get(service)
    if isinstance(service_config, dict):
        for key, value in service_config.items():
            if key in PUBLIC_SERVICE_KEYS or public_key_name(str(key)):
                domains.update(extract_domains(value))
        domains.update(extract_label_domains(service_config.get("labels")))
        for _path, key, value in iter_environment_settings(service_config, ("services", service)):
            if public_key_name(key):
                domains.update(extract_domains(value))
        for _file_path, text in iter_referenced_file_texts(root, service_config):
            domains.update(extract_domains(text))

    return domains


def iter_public_settings(compose: dict[str, Any]):
    top_domains = compose.get("x-hosted-domains")
    if top_domains is not None:
        yield ("x-hosted-domains",), "x-hosted-domains", top_domains

    services = compose.get("services") or {}
    if not isinstance(services, dict):
        return

    for service, config in services.items():
        if not isinstance(config, dict):
            continue
        base = ("services", str(service))
        yield from iter_environment_settings(config, base)
        labels = config.get("labels")
        if labels is not None:
            yield base + ("labels",), "labels", labels
        for key in PUBLIC_SERVICE_KEYS:
            if key in config:
                yield base + (key,), key, config[key]
        for path, value in walk(config, base):
            if not path:
                continue
            leaf = path[-1]
            if str(leaf) in {"healthcheck", "test"} or "healthcheck" in path:
                continue
            if public_key_name(str(leaf)):
                yield path, str(leaf), value


def iter_environment_settings(config: dict[str, Any], base: tuple[str, ...]):
    env = config.get("environment")
    if isinstance(env, dict):
        for key, value in env.items():
            if public_key_name(str(key)):
                yield base + ("environment", str(key)), str(key), value
    elif isinstance(env, list):
        for index, entry in enumerate(env):
            if not isinstance(entry, str):
                continue
            key = entry.split("=", 1)[0]
            if public_key_name(key):
                yield base + ("environment", str(index)), key, entry


def extract_urls(text: str) -> list[str]:
    return [match.group(0).rstrip(".,;]") for match in URL_RE.finditer(text)]


def extract_domains(value: Any) -> set[str]:
    domains: set[str] = set()
    for _path, leaf in walk(value):
        if not isinstance(leaf, str):
            continue
        text = leaf.strip()
        domains.update(extract_label_domains(text))
        for url in extract_urls(text):
            host = urlsplit(url).hostname
            if host:
                domains.add(host.lower())
        if looks_like_domain(text):
            domains.add(text.lower().removeprefix("https://").removeprefix("http://").split("/", 1)[0])
    return domains


def extract_label_domains(labels: Any) -> set[str]:
    domains: set[str] = set()
    values: list[str] = []
    if isinstance(labels, str):
        values.append(labels)
    elif isinstance(labels, list):
        values.extend(item for item in labels if isinstance(item, str))
    elif isinstance(labels, dict):
        values.extend(str(item) for item in labels.values())

    for value in values:
        for match in HOST_RULE_RE.finditer(value):
            raw_hosts = re.findall(r"`([^`]+)`|'([^']+)'|\"([^\"]+)\"", match.group(1))
            for host_parts in raw_hosts:
                host = next(part for part in host_parts if part)
                if looks_like_domain(host):
                    domains.add(host.lower())
    return domains


def public_key_name(key: str) -> bool:
    normalized = re.sub(r"[^A-Z0-9]+", "_", key.upper())
    return any(keyword in normalized for keyword in PUBLIC_KEYWORDS)


def is_public_http_host(host: str) -> bool:
    if not host:
        return False
    if host == "localhost" or host.startswith("127."):
        return True
    if host.endswith(f".{LAB_DOMAIN}") or host == LAB_DOMAIN:
        return True
    if host == "demo.example.gov" or host.endswith(".example.gov"):
        return True
    return "." in host


def image_uses_latest_tag(image: str) -> bool:
    if "@sha256:" in image:
        return False
    last_segment = image.rsplit("/", 1)[-1]
    return ":" not in last_segment or last_segment.endswith(":latest")


def image_uses_floating_product_tag(image: str) -> bool:
    if "@sha256:" in image or image in ALLOWED_INTERIM_PRODUCT_IMAGES:
        return False
    image_ref = image.split("@", 1)[0]
    name = image_ref.rsplit("/", 1)[-1].split(":", 1)[0]
    return name in PRODUCT_IMAGE_NAMES


def product_image_name(image: str) -> str | None:
    if image in ALLOWED_INTERIM_PRODUCT_IMAGES:
        return None
    for name in PRODUCT_IMAGE_NAMES:
        if name in image:
            return name
    return None


def image_uses_product_env_fallback(image: str, env_var: str) -> bool:
    prefix = "${" + env_var + ":-"
    return image.startswith(prefix) and image.endswith("}") and "@sha256:" in image


def artifact_uses_product_env_fallback(artifact_text: str, image: str, env_var: str) -> bool:
    if image_uses_product_env_fallback(image, env_var):
        return True
    if not artifact_text:
        return False
    return image_uses_product_env_fallback_marker(artifact_text, env_var)


def image_uses_product_env_fallback_marker(text: str, env_var: str) -> bool:
    marker = "${" + env_var + ":-"
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("image:") and marker in stripped and "@sha256:" in stripped:
            return True
    return False


def is_registry_relay_service(service: str, image: str) -> bool:
    return "relay" in service and "registry-relay" in image


def is_registry_notary_service(service: str, image: str) -> bool:
    return "notary" in service and "registry-notary" in image and "openfn-sidecar" not in image


def service_mounts_target(service_config: dict[str, Any], target: str) -> bool:
    for volume in service_config.get("volumes") or []:
        if isinstance(volume, str):
            parts = volume.split(":")
            if len(parts) >= 2 and parts[1] == target:
                return True
        elif isinstance(volume, dict) and volume.get("target") == target:
            return True
    return False


def compose_references_variable(compose: dict[str, Any], variable: str, raw_text: str = "") -> bool:
    variable_ref_re = r"\$\{" + re.escape(variable) + r"(?::[-?][^}]*)?\}"
    if raw_text and re.search(variable_ref_re, raw_text):
        return True
    serialized = json.dumps(compose, sort_keys=True)
    if re.search(variable_ref_re, serialized):
        return True
    return f'"{variable}"' in serialized


def usable_secret_value(value: str | None) -> bool:
    if value is None:
        return False
    stripped = value.strip()
    if not stripped:
        return False
    return stripped not in {"replace-in-coolify", "hosted-validation-placeholder"}


def looks_like_domain(value: str) -> bool:
    text = value.strip().lower()
    if "://" in text:
        parsed = urlsplit(text)
        text = parsed.hostname or ""
    if "/" in text or ":" in text or not text:
        return False
    return "." in text and not text.startswith(".") and not text.endswith(".")


def volume_source(volume: Any) -> str | None:
    if isinstance(volume, str):
        if ":" not in volume:
            return None
        return volume.split(":", 1)[0]
    if isinstance(volume, dict):
        source = volume.get("source")
        return str(source) if source else None
    return None


def iter_referenced_file_texts(root: Path, service_config: dict[str, Any]):
    for path in iter_referenced_file_paths(root, service_config):
        try:
            if path.stat().st_size > 1_000_000:
                continue
            yield path, path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue


def iter_referenced_file_paths(root: Path, service_config: dict[str, Any]):
    volumes = service_config.get("volumes") or []
    if not isinstance(volumes, list):
        return
    for volume in volumes:
        source = volume_source(volume)
        if not source:
            continue
        path = resolve_volume_source(root, source)
        if not path:
            continue
        if path.is_file() and path.suffix in SCANNED_FILE_SUFFIXES:
            yield path
        elif path.is_dir() and should_scan_directory_mount(path):
            for child in sorted(path.rglob("*")):
                if child.is_file() and child.suffix in SCANNED_FILE_SUFFIXES:
                    yield child


def resolve_volume_source(root: Path, source: str) -> Path | None:
    if source.startswith("${") or source.startswith("$"):
        return None
    source_path = Path(source)
    if not source_path.is_absolute() and not source.startswith("."):
        return None
    path = source_path if source_path.is_absolute() else root / source_path
    try:
        return path.resolve()
    except OSError:
        return None


def is_repo_output_source(source: str) -> bool:
    normalized = source.replace("\\", "/").strip()
    if normalized in {"./output", "output"}:
        return True
    return normalized.startswith("./output/") or normalized.startswith("output/")


def should_scan_directory_mount(path: Path) -> bool:
    return path.name not in {"data", "static-metadata"}


def walk(value: Any, path: tuple[str, ...] = ()):
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from walk(child, path + (str(key),))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk(child, path + (str(index),))


def format_path(path: tuple[str, ...]) -> str:
    if not path:
        return "."
    formatted = path[0]
    for part in path[1:]:
        if part.isdigit():
            formatted += f"[{part}]"
        else:
            formatted += f".{part}"
    return formatted


def dedupe_issues(issues: list[Issue]) -> list[Issue]:
    seen: set[tuple[str, str, str, str]] = set()
    unique = []
    for issue in issues:
        key = (issue.code, issue.artifact, issue.path, issue.message)
        if key in seen:
            continue
        seen.add(key)
        unique.append(issue)
    return unique


def collect_service_contract_text(compose: dict[str, Any], root: Path, service: str) -> str:
    service_config = compose.get("services", {}).get(service)
    chunks: list[str] = []
    if isinstance(service_config, dict):
        chunks.append(json.dumps(service_config, sort_keys=True))
        for _path, text in iter_referenced_file_texts(root, service_config):
            chunks.append(text)
        config_path = hosted_notary_config_path(root, service_config)
        if config_path and config_path.exists():
            chunks.append(config_path.read_text(encoding="utf-8"))
    return "\n".join(chunks)


def hosted_notary_config_path(root: Path, service_config: dict[str, Any]) -> Path | None:
    return hosted_product_config_path(root, service_config, product="notary")


def hosted_product_config_path(
    root: Path,
    service_config: dict[str, Any],
    *,
    product: str | None = None,
) -> Path | None:
    command = service_config.get("command")
    if not isinstance(command, list):
        return None
    product_dirs = [product] if product else ["relay", "notary"]
    for index, value in enumerate(command[:-1]):
        if value != "--config":
            continue
        config_path = str(command[index + 1])
        name = Path(config_path).name
        if not name:
            continue
        for product_dir in product_dirs:
            path = root / "config" / "coolify" / product_dir / name
            if path.exists():
                return path
    return None


def extract_citizen_esignet_issuer(compose: dict[str, Any], root: Path) -> str | None:
    service_config = compose.get("services", {}).get("citizen-civil-notary")
    if not isinstance(service_config, dict):
        return None

    env = normalize_environment(service_config.get("environment"))
    if isinstance(env.get("ESIGNET_ISSUER"), str):
        return env["ESIGNET_ISSUER"]

    for path in iter_referenced_file_paths(root, service_config):
        if path.suffix not in {".yaml", ".yml"}:
            continue
        try:
            loaded = load_yaml_mapping(path)
        except Exception:
            continue
        issuer = nested_get(loaded, ("auth", "oidc", "issuer"))
        if isinstance(issuer, str):
            return issuer
    return None


def extract_esignet_discovery_issuer(compose: dict[str, Any], root: Path) -> str | None:
    del root
    service_config = compose.get("services", {}).get("esignet")
    if not isinstance(service_config, dict):
        return None
    env = normalize_environment(service_config.get("environment"))
    issuer = env.get("MOSIP_ESIGNET_DISCOVERY_ISSUER_ID")
    if isinstance(issuer, str):
        return issuer
    key_values = env.get("MOSIP_ESIGNET_DISCOVERY_KEY_VALUES")
    if not isinstance(key_values, str):
        return None
    try:
        loaded = ast.literal_eval(key_values)
    except (SyntaxError, ValueError):
        match = re.search(r"['\"]issuer['\"]\s*:\s*['\"]([^'\"]+)['\"]", key_values)
        return match.group(1) if match else None
    if isinstance(loaded, dict) and isinstance(loaded.get("issuer"), str):
        return loaded["issuer"]
    return None


def normalize_environment(env: Any) -> dict[str, str]:
    if isinstance(env, dict):
        return {str(key): str(value) for key, value in env.items()}
    if isinstance(env, list):
        values: dict[str, str] = {}
        for entry in env:
            if not isinstance(entry, str):
                continue
            key, _, value = entry.partition("=")
            values[key] = value
        return values
    return {}


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    try:
        import yaml  # type: ignore[import-not-found]
    except ModuleNotFoundError:
        return load_yaml_mapping_with_ruby(path)

    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    return loaded if isinstance(loaded, dict) else {}


def load_yaml_mapping_strict(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    assert_no_duplicate_yaml_keys_text(text)
    try:
        import yaml  # type: ignore[import-not-found]
    except ModuleNotFoundError:
        return load_yaml_mapping_with_ruby(path)

    assert_unique_yaml_keys(yaml.compose(text), yaml)
    loaded = yaml.safe_load(text)
    return loaded if isinstance(loaded, dict) else {}


def assert_no_duplicate_yaml_keys_text(text: str) -> None:
    scopes: list[tuple[int, set[str]]] = []
    key_re = re.compile(r"^(?P<indent>\s*)(?P<dash>-\s+)?(?P<key>[A-Za-z0-9_.-]+)\s*:")
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = key_re.match(raw_line)
        if not match:
            continue
        indent = len(match.group("indent"))
        if match.group("dash"):
            indent += 2
            scopes = [(level, keys) for level, keys in scopes if level < indent]
        else:
            scopes = [(level, keys) for level, keys in scopes if level <= indent]
        if not scopes or scopes[-1][0] != indent:
            scopes.append((indent, set()))
        keys = scopes[-1][1]
        key = match.group("key")
        if key in keys:
            raise DuplicateYamlKeyError(f"duplicate YAML key {key!r} at line {lineno}")
        keys.add(key)


def assert_unique_yaml_keys(node: Any, yaml_module: Any) -> None:
    if node is None:
        return
    if isinstance(node, yaml_module.MappingNode):
        seen: set[str] = set()
        for key_node, value_node in node.value:
            key = str(key_node.value)
            if key in seen:
                mark = getattr(key_node, "start_mark", None)
                location = f"line {mark.line + 1}" if mark is not None else "unknown line"
                raise DuplicateYamlKeyError(f"duplicate YAML key {key!r} at {location}")
            seen.add(key)
            assert_unique_yaml_keys(value_node, yaml_module)
    elif isinstance(node, yaml_module.SequenceNode):
        for child in node.value:
            assert_unique_yaml_keys(child, yaml_module)


def load_yaml_mapping_with_ruby(path: Path) -> dict[str, Any]:
    script = r'''
require "json"
require "yaml"

data = YAML.load_file(ARGV.fetch(0))
data = {} unless data.is_a?(Hash)
puts JSON.generate(data)
'''
    result = subprocess.run(
        ["ruby", "-e", script, str(path)],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    loaded = json.loads(result.stdout)
    return loaded if isinstance(loaded, dict) else {}


def load_json_mapping(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    return loaded if isinstance(loaded, dict) else {}


def nested_get(value: dict[str, Any], path: tuple[str, ...]) -> Any:
    current: Any = value
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def load_compose(path: Path) -> dict[str, Any]:
    if path.suffix == ".json":
        return json.loads(path.read_text(encoding="utf-8"))

    try:
        import yaml  # type: ignore[import-not-found]
    except ModuleNotFoundError:
        return render_compose_json(path)

    with path.open(encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle)
    if not isinstance(loaded, dict):
        raise ValueError(f"{path} did not load as a mapping")
    return loaded


def render_compose_json(path: Path) -> dict[str, Any]:
    env = os.environ.copy()
    missing_vars: set[str] = set()
    for _attempt in range(20):
        try:
            result = subprocess.run(
                ["docker", "compose", "-f", str(path), "config", "--format", "json"],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
            return json.loads(result.stdout)
        except FileNotFoundError as exc:
            raise RuntimeError(
                "install PyYAML or Docker Compose so hosted compose YAML can be rendered"
            ) from exc
        except subprocess.CalledProcessError as exc:
            match = REQUIRED_VAR_RE.search(exc.stderr)
            if match and match.group(1) not in missing_vars:
                missing_vars.add(match.group(1))
                env[match.group(1)] = "hosted-validation-placeholder"
                continue
            raise RuntimeError(exc.stderr.strip() or str(exc)) from exc

    raise RuntimeError(
        "could not render compose after adding placeholders for required variables: "
        + ", ".join(sorted(missing_vars))
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--registry-lab-compose",
        type=Path,
        default=Path("compose.coolify.yaml"),
        help="hosted Registry Lab compose file",
    )
    parser.add_argument(
        "--esignet-compose",
        type=Path,
        default=Path("compose.esignet-hosted.yaml"),
        help="hosted eSignet compose file",
    )
    parser.add_argument(
        "--walt-compose",
        type=Path,
        default=Path("compose.walt-hosted.yaml"),
        help="hosted walt.id wallet compose file",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print validation issues as JSON",
    )
    parser.add_argument(
        "--require-secret-values",
        action="store_true",
        help="also require every hosted secret variable to have a non-placeholder environment value",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    artifacts: dict[str, dict[str, Any]] = {}
    artifact_roots: dict[str, Path] = {}
    artifact_texts: dict[str, str] = {}
    issues: list[Issue] = []

    for artifact, path in (
        ("registry-lab", args.registry_lab_compose),
        ("esignet", args.esignet_compose),
        ("walt", args.walt_compose),
    ):
        if not path.exists():
            issues.append(
                Issue(
                    "missing-artifact",
                    artifact,
                    str(path),
                    f"required hosted compose artifact {path} is missing",
                )
            )
            continue
        try:
            artifact_texts[artifact] = path.read_text(encoding="utf-8")
            artifacts[artifact] = load_compose(path)
            artifact_roots[artifact] = path.parent
        except Exception as exc:
            issues.append(
                Issue(
                    "unreadable-artifact",
                    artifact,
                    str(path),
                    f"could not load hosted compose artifact: {exc}",
                )
            )

    issues.extend(
        validate_artifacts(
            artifacts,
            artifact_roots,
            artifact_texts,
            require_secret_values=args.require_secret_values,
        )
    )
    issues = sorted(dedupe_issues(issues), key=lambda issue: (issue.artifact, issue.path, issue.code))

    if args.json:
        print(json.dumps([issue.__dict__ for issue in issues], indent=2, sort_keys=True))
    elif issues:
        for issue in issues:
            print(issue, file=sys.stderr)
    else:
        print("hosted deploy artifacts passed validation")

    return 1 if issues else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
