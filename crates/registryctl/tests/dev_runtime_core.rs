// SPDX-License-Identifier: Apache-2.0

#[allow(dead_code)]
mod release_lock {
    use std::path::Path;

    pub struct VerifiedReleaseLockV1;
    pub struct Images;
    pub struct ProductRuntime;
    pub struct PostgresqlRuntime;
    pub struct Runtime;
    #[derive(Clone)]
    pub struct LockedRuntimeActionV1 {
        pub command: Vec<String>,
        pub mounts: Vec<LockedRuntimeMountV1>,
        pub environment_files: Vec<String>,
        pub secret_files: Vec<LockedSecretProjectionV1>,
    }
    #[derive(Clone, Copy)]
    pub enum LockedMountSourceV1 {
        Bundle,
        Anchor,
        AntiRollbackState,
        Audit,
        PostgresqlData,
    }
    #[derive(Clone)]
    pub struct LockedRuntimeMountV1 {
        pub source: LockedMountSourceV1,
    }
    #[derive(Clone)]
    pub struct LockedSecretProjectionV1 {
        pub file_id: String,
        pub target: String,
        pub mode: String,
        pub uid: String,
        pub gid: String,
    }
    #[derive(Clone)]
    pub struct LockedServiceHardeningV1 {
        pub user: String,
        pub read_only_root_filesystem: bool,
        pub cap_drop: Vec<String>,
        pub security_opt: Vec<String>,
        pub tmpfs: Vec<String>,
    }
    #[derive(Clone)]
    pub struct LockedOperatorFileV1 {
        pub id: String,
        pub mode: String,
        pub allowed_owners: Vec<String>,
        pub required_keys: Vec<String>,
    }

    impl VerifiedReleaseLockV1 {
        pub fn managed_images(&self) -> Images {
            unreachable!()
        }
        pub fn runtime_mapping(&self) -> Runtime {
            unreachable!()
        }
        pub fn signed_payload_sha256(&self) -> &str {
            unreachable!()
        }
        pub fn release_tag(&self) -> &str {
            unreachable!()
        }
        pub fn minimum_compose_version(&self) -> &str {
            unreachable!()
        }
    }

    pub fn verify_installed_release_lock(_path: &Path) -> anyhow::Result<VerifiedReleaseLockV1> {
        unreachable!()
    }
    impl Images {
        pub fn relay(&self) -> &str {
            unreachable!()
        }
        pub fn notary(&self) -> &str {
            unreachable!()
        }
        pub fn postgresql_state_plane(&self) -> &str {
            unreachable!()
        }
    }
    impl ProductRuntime {
        pub fn prepare_state_store(&self) -> &[String] {
            unreachable!()
        }
        pub fn initialize_state(&self) -> &[String] {
            unreachable!()
        }
        pub fn serve(&self) -> &[String] {
            unreachable!()
        }
        pub fn serve_action(&self) -> &LockedRuntimeActionV1 {
            unreachable!()
        }
        pub fn prepare_state_store_action(&self) -> &LockedRuntimeActionV1 {
            unreachable!()
        }
        pub fn initialize_state_action(&self) -> &LockedRuntimeActionV1 {
            unreachable!()
        }
        pub fn development_prepare_state_store_action(&self) -> &LockedRuntimeActionV1 {
            unreachable!()
        }
        pub fn development_initialize_state_action(&self) -> &LockedRuntimeActionV1 {
            unreachable!()
        }
        pub fn development_serve_action(&self) -> &LockedRuntimeActionV1 {
            unreachable!()
        }
        pub fn health_probe(&self) -> &[String] {
            unreachable!()
        }
    }
    impl PostgresqlRuntime {
        pub fn serve(&self) -> &LockedRuntimeActionV1 {
            unreachable!()
        }
        pub fn bootstrap(&self) -> &LockedRuntimeActionV1 {
            unreachable!()
        }
        pub fn health_probe(&self) -> &[String] {
            unreachable!()
        }
        pub fn server_environment(&self) -> &[String] {
            unreachable!()
        }
        pub fn hardening(&self) -> &LockedServiceHardeningV1 {
            unreachable!()
        }
    }
    impl Runtime {
        pub fn relay_public(&self) -> &ProductRuntime {
            unreachable!()
        }
        pub fn relay_consultation(&self) -> &ProductRuntime {
            unreachable!()
        }
        pub fn notary(&self) -> &ProductRuntime {
            unreachable!()
        }
        pub fn postgresql_state_plane(&self) -> &PostgresqlRuntime {
            unreachable!()
        }
        pub fn operator_files(&self) -> &[LockedOperatorFileV1] {
            unreachable!()
        }
    }
}

#[allow(dead_code)]
mod dev_credentials {
    use std::fs;
    use std::path::{Path, PathBuf};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum DevOAuthCredentialProfile {
        Oauth2Bearer,
        Oauth2BearerNoExpiry,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum DevSourceCredentialProjection {
        OperatorBound,
        SyntheticUnauthenticated {
            control_token_file: String,
            tls_certificate_file: String,
            tls_private_key_file: String,
        },
        SyntheticStaticBearer {
            relay_token_env: String,
            source_token_file: String,
            control_token_file: String,
            tls_certificate_file: String,
            tls_private_key_file: String,
        },
        SyntheticOAuthClientCredentials {
            profile: DevOAuthCredentialProfile,
            relay_client_id_env: String,
            relay_client_secret_env: String,
            source_client_id_file: String,
            source_client_secret_file: String,
            control_token_file: String,
            tls_certificate_file: String,
            tls_private_key_file: String,
        },
    }

    pub struct DevCredentialPublicProjection {
        pub source: DevSourceCredentialProjection,
    }

    #[derive(Clone)]
    pub struct DevCredentialRequirements;

    pub struct PreparedDevCredentialClosure {
        projection: DevCredentialPublicProjection,
        relay_api_keys: bool,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct PreparedDevActionCredentialFile {
        pub host_path: PathBuf,
        pub container_path: String,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct PreparedDevSourceCredentialFiles {
        pub control_token: PathBuf,
        pub tls_certificate: PathBuf,
        pub tls_private_key: PathBuf,
        pub static_bearer: Option<PathBuf>,
        pub oauth_client_id: Option<PathBuf>,
        pub oauth_client_secret: Option<PathBuf>,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct PreparedDevCredentialFiles {
        pub root: PathBuf,
        pub caller_token: PathBuf,
        pub relay_match_token: Option<PathBuf>,
        pub relay_no_match_token: Option<PathBuf>,
        pub workload_token: PathBuf,
        pub workload_public_jwk: PathBuf,
        pub workload_jwks: PathBuf,
        pub relay_public_prepare: PreparedDevActionCredentialFile,
        pub relay_public_initialize: PreparedDevActionCredentialFile,
        pub relay_public_serve: PreparedDevActionCredentialFile,
        pub relay_consultation_prepare: PreparedDevActionCredentialFile,
        pub relay_consultation_initialize: PreparedDevActionCredentialFile,
        pub relay_consultation_serve: PreparedDevActionCredentialFile,
        pub notary_prepare: PreparedDevActionCredentialFile,
        pub notary_initialize: PreparedDevActionCredentialFile,
        pub notary_serve: PreparedDevActionCredentialFile,
        pub postgres_bootstrap: PreparedDevActionCredentialFile,
        pub postgres_admin_password: PathBuf,
        pub notary_signing_key: PathBuf,
        pub postgres_tls_certificate: PathBuf,
        pub postgres_tls_private_key: PathBuf,
        pub source: Option<PreparedDevSourceCredentialFiles>,
        pub issuance_public_jwk: Option<PathBuf>,
        pub lane_public_jwks: [PathBuf; 3],
    }

    impl PreparedDevCredentialClosure {
        pub fn generate(_requirements: DevCredentialRequirements) -> anyhow::Result<Self> {
            unreachable!()
        }

        pub fn operator_bound() -> Self {
            Self {
                projection: DevCredentialPublicProjection {
                    source: DevSourceCredentialProjection::OperatorBound,
                },
                relay_api_keys: false,
            }
        }

        pub fn synthetic(profile: Option<DevOAuthCredentialProfile>, static_bearer: bool) -> Self {
            let common = || {
                (
                    "/run/registry/synthetic-source-secrets/control-token".to_string(),
                    "/run/registry/synthetic-source-secrets/tls.crt".to_string(),
                    "/run/registry/synthetic-source-secrets/tls.key".to_string(),
                )
            };
            let source = if static_bearer {
                let (control, cert, key) = common();
                DevSourceCredentialProjection::SyntheticStaticBearer {
                    relay_token_env: "SOURCE_TOKEN".to_string(),
                    source_token_file: "/run/registry/synthetic-source-secrets/static-bearer"
                        .to_string(),
                    control_token_file: control,
                    tls_certificate_file: cert,
                    tls_private_key_file: key,
                }
            } else if let Some(profile) = profile {
                let (control, cert, key) = common();
                DevSourceCredentialProjection::SyntheticOAuthClientCredentials {
                    profile,
                    relay_client_id_env: "SOURCE_CLIENT_ID".to_string(),
                    relay_client_secret_env: "SOURCE_CLIENT_SECRET".to_string(),
                    source_client_id_file: "/run/registry/synthetic-source-secrets/oauth-client-id"
                        .to_string(),
                    source_client_secret_file:
                        "/run/registry/synthetic-source-secrets/oauth-client-secret".to_string(),
                    control_token_file: control,
                    tls_certificate_file: cert,
                    tls_private_key_file: key,
                }
            } else {
                let (control, cert, key) = common();
                DevSourceCredentialProjection::SyntheticUnauthenticated {
                    control_token_file: control,
                    tls_certificate_file: cert,
                    tls_private_key_file: key,
                }
            };
            Self {
                projection: DevCredentialPublicProjection { source },
                relay_api_keys: false,
            }
        }

        pub fn synthetic_records() -> Self {
            let mut closure = Self::synthetic(None, false);
            closure.relay_api_keys = true;
            closure
        }

        pub fn public_projection(&self) -> &DevCredentialPublicProjection {
            &self.projection
        }

        pub fn planned_files(&self, root: &Path) -> PreparedDevCredentialFiles {
            let action = |name: &str| PreparedDevActionCredentialFile {
                host_path: root.join(name),
                container_path: format!("/run/registry/dev-secrets/{name}"),
            };
            let synthetic = !matches!(
                self.projection.source,
                DevSourceCredentialProjection::OperatorBound
            );
            let source = synthetic.then(|| PreparedDevSourceCredentialFiles {
                control_token: root.join("control-token"),
                tls_certificate: root.join("tls.crt"),
                tls_private_key: root.join("tls.key"),
                static_bearer: matches!(
                    self.projection.source,
                    DevSourceCredentialProjection::SyntheticStaticBearer { .. }
                )
                .then(|| root.join("static-bearer")),
                oauth_client_id: matches!(
                    self.projection.source,
                    DevSourceCredentialProjection::SyntheticOAuthClientCredentials { .. }
                )
                .then(|| root.join("oauth-client-id")),
                oauth_client_secret: matches!(
                    self.projection.source,
                    DevSourceCredentialProjection::SyntheticOAuthClientCredentials { .. }
                )
                .then(|| root.join("oauth-client-secret")),
            });
            PreparedDevCredentialFiles {
                root: root.to_path_buf(),
                caller_token: root.join("caller-token"),
                relay_match_token: self.relay_api_keys.then(|| root.join("relay-match-token")),
                relay_no_match_token: self
                    .relay_api_keys
                    .then(|| root.join("relay-no-match-token")),
                workload_token: root.join("notary-relay-token"),
                workload_public_jwk: root.join("notary-workload-public.jwk"),
                workload_jwks: root.join("notary-workload-jwks.json"),
                relay_public_prepare: action("relay-public-prepare.env"),
                relay_public_initialize: action("relay-public-initialize.env"),
                relay_public_serve: action("relay-public-serve.env"),
                relay_consultation_prepare: action("relay-consultation-prepare.env"),
                relay_consultation_initialize: action("relay-consultation-initialize.env"),
                relay_consultation_serve: action("relay-consultation-serve.env"),
                notary_prepare: action("notary-prepare.env"),
                notary_initialize: action("notary-initialize.env"),
                notary_serve: action("notary-serve.env"),
                postgres_bootstrap: action("postgres-bootstrap.env"),
                postgres_admin_password: root.join("postgres-admin-password"),
                notary_signing_key: root.join("notary-signing-key.jwk"),
                postgres_tls_certificate: root.join("postgres-tls.crt"),
                postgres_tls_private_key: root.join("postgres-tls.key"),
                source,
                issuance_public_jwk: None,
                lane_public_jwks: [
                    root.join("relay-public-lane.jwk"),
                    root.join("relay-consultation-lane.jwk"),
                    root.join("notary-lane.jwk"),
                ],
            }
        }

        pub fn materialize_owner_only(
            &self,
            root: &Path,
        ) -> anyhow::Result<PreparedDevCredentialFiles> {
            let files = self.planned_files(root);
            fs::create_dir(root)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
            }
            let mut paths = vec![
                (&files.caller_token, "test-caller-token"),
                (&files.workload_token, "test-workload-token"),
                (&files.workload_public_jwk, "{}"),
                (&files.workload_jwks, "{\"keys\":[]}"),
                (&files.relay_public_prepare.host_path, "A=1\n"),
                (&files.relay_public_initialize.host_path, "A=1\n"),
                (&files.relay_public_serve.host_path, "A=1\n"),
                (&files.relay_consultation_prepare.host_path, "A=1\n"),
                (&files.relay_consultation_initialize.host_path, "A=1\n"),
                (&files.relay_consultation_serve.host_path, "A=1\n"),
                (&files.notary_prepare.host_path, "A=1\n"),
                (&files.notary_initialize.host_path, "A=1\n"),
                (&files.notary_serve.host_path, "A=1\n"),
                (&files.postgres_bootstrap.host_path, "A=1\n"),
                (&files.postgres_admin_password, "postgres-admin-password"),
                (&files.notary_signing_key, "{}"),
                (&files.postgres_tls_certificate, "certificate"),
                (&files.postgres_tls_private_key, "private-key"),
                (&files.lane_public_jwks[0], "{}"),
                (&files.lane_public_jwks[1], "{}"),
                (&files.lane_public_jwks[2], "{}"),
            ];
            if let Some(path) = &files.relay_match_token {
                paths.push((path, "test-relay-match-token"));
            }
            if let Some(path) = &files.relay_no_match_token {
                paths.push((path, "test-relay-no-match-token"));
            }
            if let Some(source) = &files.source {
                paths.extend([
                    (&source.control_token, "control"),
                    (&source.tls_certificate, "certificate"),
                    (&source.tls_private_key, "private-key"),
                ]);
                if let Some(path) = &source.static_bearer {
                    paths.push((path, "bearer"));
                }
                if let Some(path) = &source.oauth_client_id {
                    paths.push((path, "client-id"));
                }
                if let Some(path) = &source.oauth_client_secret {
                    paths.push((path, "client-secret"));
                }
            }
            for (path, value) in paths {
                fs::write(path, value)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
                }
            }
            Ok(files)
        }
    }
}

#[allow(dead_code)]
mod project_authoring {
    use std::path::{Path, PathBuf};

    use crate::dev_credentials::{DevCredentialRequirements, PreparedDevCredentialClosure};
    use crate::dev_runtime::{AuthoredDevScenario, AuthoredDevelopment, DevEnvironmentProfile};

    pub struct DevAuthoringProjection {
        pub project_id: String,
        pub environment_id: String,
        pub environment_profile: DevEnvironmentProfile,
        pub development: AuthoredDevelopment,
        pub scenarios: Vec<AuthoredDevScenario>,
        pub records_request: Option<AuthoredRecordsRequest>,
        pub local_snapshot: Option<crate::dev_runtime::AuthoredLocalSnapshot>,
        pub operator_source_secret_env: Vec<String>,
    }

    pub struct AuthoredRecordsRequest {
        pub dataset_id: String,
        pub entity_id: String,
        pub record_id: String,
        pub purpose: String,
    }

    impl DevAuthoringProjection {
        pub fn credential_requirements(&self) -> DevCredentialRequirements {
            DevCredentialRequirements
        }
    }

    #[derive(Clone)]
    pub struct CompiledSignedDevLanes {
        pub relay_public_bundle: PathBuf,
        pub relay_public_anchor: PathBuf,
        pub relay_consultation_bundle: PathBuf,
        pub relay_consultation_anchor: PathBuf,
        pub notary_bundle: PathBuf,
        pub notary_anchor: PathBuf,
        pub lane_config_digests: [String; 3],
    }

    pub struct ProjectBuildOptions {
        pub project_directory: PathBuf,
        pub environment: String,
        pub against: Option<PathBuf>,
        pub anchor: Option<PathBuf>,
    }

    pub struct Text(String);
    impl Text {
        pub fn as_str(&self) -> &str {
            &self.0
        }
    }

    pub struct ArtifactManifest {
        pub path: Text,
        pub digest: Text,
    }

    pub struct ProjectCommandReport {
        pub artifact_manifest: Option<ArtifactManifest>,
    }

    pub fn build_registry_project(
        _options: &ProjectBuildOptions,
    ) -> anyhow::Result<ProjectCommandReport> {
        unreachable!()
    }

    pub fn compile_dev_runtime_authoring(
        _project_directory: &Path,
        _environment_id: &str,
    ) -> anyhow::Result<DevAuthoringProjection> {
        unreachable!()
    }

    pub fn compile_and_sign_dev_lanes(
        _project_directory: &Path,
        _environment_id: &str,
        _credentials: &PreparedDevCredentialClosure,
        _output_root: &Path,
    ) -> anyhow::Result<CompiledSignedDevLanes> {
        unreachable!()
    }
}

#[allow(dead_code)]
#[path = "../src/dev_runtime.rs"]
mod dev_runtime;

use std::collections::BTreeSet;
use std::fs;
use std::net::TcpListener;
use std::path::Path;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use dev_credentials::{DevOAuthCredentialProfile, PreparedDevCredentialClosure};
use dev_runtime::*;
use registry_platform_config::{
    ConfigBundleFile, ConfigBundleManifest, ConfigBundleSignature, ConfigBundleSignatureEnvelope,
    ConfigTrustAnchor, ConfigTrustAnchorSigner, ProductAcceptanceIdentityV1,
    ProductAcceptanceLaneV1, ProductAcceptanceProductV1, ProductTrustDomainV1,
};
use registry_platform_crypto::{canonicalize_json, sign, PrivateJwk};

const RESPONSE_CANARY: &str = "fixture-response-canary-value";
const REQUEST_CANARY: &str = "fixture-request-canary-value";
const TEST_PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"registryctl-test-private-key"}"#;

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn verified_release() -> VerifiedDevReleaseProjection {
    VerifiedDevReleaseProjection::test_only(
        "release-v1.0.0".to_string(),
        "v1.0.0".to_string(),
        format!(
            "ghcr.io/registrystack/registry-relay@sha256:{}",
            "a".repeat(64)
        ),
        format!(
            "ghcr.io/registrystack/registry-notary@sha256:{}",
            "b".repeat(64)
        ),
        format!("docker.io/library/postgres@sha256:{}", "c".repeat(64)),
        "2.24.0".to_string(),
    )
    .unwrap()
}

fn create_artifacts_generation(root: &Path, generation: &str) -> DevRuntimeArtifactInputs {
    let build = root.join(".registry-stack/build/local");
    fs::create_dir_all(&build).unwrap();
    let binding = DevProjectBindingV1 {
        project: "citizen-registry".to_string(),
        environment: "local".to_string(),
        project_root_digest: registry_platform_config::sha256_uri(
            fs::canonicalize(root).unwrap().to_string_lossy().as_bytes(),
        ),
    };
    let generated = root
        .join(".registry-stack/dev-artifacts/local")
        .join(stable_runtime_id(&binding).unwrap())
        .join(generation);
    let bundles = generated.join("bundles");
    let anchors = generated.join("anchors");
    fs::create_dir_all(&bundles).unwrap();
    fs::create_dir_all(&anchors).unwrap();
    let compose_file = generated.join("compose.yaml");
    fs::write(&compose_file, "services: {}\n").unwrap();
    let relay_public_bundle = bundles.join("relay-public");
    let relay_consultation_bundle = bundles.join("relay-consultation");
    let notary_bundle = bundles.join("notary");
    for path in [
        &relay_public_bundle,
        &relay_consultation_bundle,
        &notary_bundle,
    ] {
        fs::create_dir(path).unwrap();
    }
    let relay_public_anchor = anchors.join("relay-public.json");
    let relay_consultation_anchor = anchors.join("relay-consultation.json");
    let notary_anchor = anchors.join("notary.json");
    for path in [
        &relay_public_anchor,
        &relay_consultation_anchor,
        &notary_anchor,
    ] {
        assert!(!path.exists());
    }
    write_development_trust_material(
        &relay_public_bundle,
        &relay_public_anchor,
        ProductAcceptanceLaneV1::RelayPublic,
        ProductAcceptanceProductV1::RegistryRelay,
        "relay-public",
    );
    write_development_trust_material(
        &relay_consultation_bundle,
        &relay_consultation_anchor,
        ProductAcceptanceLaneV1::RelayConsultation,
        ProductAcceptanceProductV1::RegistryRelay,
        "relay-consultation",
    );
    write_development_trust_material(
        &notary_bundle,
        &notary_anchor,
        ProductAcceptanceLaneV1::Notary,
        ProductAcceptanceProductV1::RegistryNotary,
        "notary",
    );
    DevRuntimeArtifactInputs {
        compose_file,
        relay_public_bundle,
        relay_public_anchor,
        relay_consultation_bundle,
        relay_consultation_anchor,
        notary_bundle,
        notary_anchor,
    }
}

fn write_development_trust_material(
    bundle: &Path,
    anchor_path: &Path,
    lane: ProductAcceptanceLaneV1,
    product: ProductAcceptanceProductV1,
    instance: &str,
) {
    let identity = ProductAcceptanceIdentityV1 {
        trust_domain: ProductTrustDomainV1::Development,
        project: "citizen-registry".to_string(),
        environment: "local".to_string(),
        lane,
        product,
        stream: "citizen-registry".to_string(),
        instance: instance.to_string(),
    };
    let config_path = bundle.join("config/runtime.yaml");
    fs::create_dir_all(config_path.parent().unwrap()).unwrap();
    let config = b"runtime: synthetic\n";
    fs::write(&config_path, config).unwrap();
    let config_digest = registry_platform_config::sha256_uri(config);
    let manifest = ConfigBundleManifest {
        schema: "registry.platform.config_bundle.v1".to_string(),
        acceptance_identity: identity.clone(),
        bundle_id: format!("dev-{instance}"),
        sequence: 1,
        previous_config_hash: None,
        config_hash: config_digest.clone(),
        files: vec![ConfigBundleFile {
            path: "config/runtime.yaml".to_string(),
            sha256: config_digest,
        }],
        created_at: "2026-07-30T00:00:00Z".to_string(),
    };
    let private = PrivateJwk::parse(TEST_PRIVATE_JWK).unwrap();
    let jwk = private.public();
    let kid = jwk.jkt().unwrap();
    let signer = ConfigTrustAnchorSigner {
        kid: kid.clone(),
        jwk,
    };
    let manifest_value = serde_json::to_value(&manifest).unwrap();
    let canonical_manifest = canonicalize_json(&manifest_value).unwrap();
    let signature = sign(&canonical_manifest, &private).unwrap();
    fs::write(
        bundle.join("manifest.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    fs::write(
        bundle.join("manifest.sig.json"),
        serde_json::to_vec(&ConfigBundleSignatureEnvelope {
            schema: "registry.platform.config_bundle_signatures.v1".to_string(),
            signatures: vec![ConfigBundleSignature {
                kid,
                alg: "EdDSA".to_string(),
                sig: URL_SAFE_NO_PAD.encode(signature),
            }],
        })
        .unwrap(),
    )
    .unwrap();
    let anchor = ConfigTrustAnchor {
        schema: "registry.platform.config_trust_anchor.v1".to_string(),
        acceptance_identity: identity,
        version: 1,
        threshold: 1,
        enabled_signers: vec![signer],
    };
    fs::write(anchor_path, serde_json::to_vec(&anchor).unwrap()).unwrap();
}

fn scenario(provider: DevSourceProvider, oauth_profile: DevOAuthProfile) -> AuthoredDevScenario {
    let expected_claim_results_sha256 =
        dev_claim_results_commitment(vec![DevClaimResultExpectation {
            claim_id: "eligibility".to_string(),
            value: serde_json::json!(true),
            satisfied: Some(true),
            disclosure: "predicate".to_string(),
        }])
        .unwrap();
    AuthoredDevScenario {
        integration_id: "citizen-source".to_string(),
        fixture_id: "passing-default".to_string(),
        synthetic: true,
        source_provider: provider,
        request_encoding: if provider == DevSourceProvider::Rhai {
            SyntheticRequestEncoding::Form
        } else {
            SyntheticRequestEncoding::Json
        },
        oauth_profile,
        denial_scenario_id: "default-denied".to_string(),
        authorized_scenario_id: "default-authorized".to_string(),
        minimized_claim_ids: vec!["eligibility".to_string()],
        expected_claim_results_sha256,
        synthetic_source: Some(AuthoredSyntheticSourcePlan {
            scenario: SyntheticSourceScenario::AuthoredResponse,
            source_request: AuthoredSyntheticSourceRequest {
                method: SyntheticRequestMethod::Get,
                path: "/people/example-person".to_string(),
                query: [("expand".to_string(), "eligibility".to_string())]
                    .into_iter()
                    .collect(),
                headers: [("accept".to_string(), "application/json".to_string())]
                    .into_iter()
                    .collect(),
                body: None,
            },
            source_auth: None,
            oauth_response_case: (oauth_profile != DevOAuthProfile::None)
                .then_some(SyntheticOAuthResponseCase::Valid),
            oauth_request: (oauth_profile != DevOAuthProfile::None).then(|| {
                AuthoredSyntheticOauthRequest {
                    audience: Some("registry-notary".to_string()),
                    scope: Some("registry.read".to_string()),
                    resource: Some("registry-source".to_string()),
                }
            }),
            response_body: Some(format!(r#"{{"result":"{RESPONSE_CANARY}"}}"#).into_bytes()),
        }),
        request_json: format!(r#"{{"subject":"{REQUEST_CANARY}"}}"#).into_bytes(),
    }
}

fn authorized_claim_result() -> serde_json::Value {
    serde_json::json!({
        "evaluation_id": "evaluation-1",
        "claim_id": "eligibility",
        "claim_version": "1",
        "subject_type": "Person",
        "target_ref": {
            "type": "Person",
            "handle": "rnref:v1:test",
            "identifier_schemes": []
        },
        "value": true,
        "satisfied": true,
        "disclosure": "predicate",
        "format": "application/vnd.registry-notary.claim-result+json",
        "issued_at": "2026-07-31T00:00:00Z",
        "expires_at": null,
        "provenance": {
            "schema_version": "registry-notary-claim-provenance/v2",
            "generated_by": {
                "type": "claim_evaluation",
                "service_id": "registry-notary",
                "evaluation_id": "evaluation-1",
                "claim_id": "eligibility",
                "claim_version": "1"
            },
            "used": {"relay_consultation_count": 1},
            "derived_from": []
        }
    })
}

#[test]
fn authorized_evaluation_requires_the_committed_claim_outcome() {
    let temporary = tempfile::tempdir().unwrap();
    let mut plan = DevRuntimePlan::derive(plan_input(
        temporary.path(),
        DevSourceProvider::Http,
        DevOAuthProfile::None,
    ))
    .unwrap();
    let valid = serde_json::json!({"results": [authorized_claim_result()]});
    let valid_bytes = serde_json::to_vec(&valid).unwrap();
    assert_eq!(
        validate_authorized_evaluation_response(&plan, &valid_bytes).unwrap(),
        ["eligibility"]
    );

    for (field, unexpected) in [
        ("value", serde_json::json!(false)),
        ("satisfied", serde_json::json!(false)),
        ("disclosure", serde_json::json!("value")),
    ] {
        let mut changed = valid.clone();
        changed["results"][0][field] = unexpected;
        assert!(
            validate_authorized_evaluation_response(&plan, &serde_json::to_vec(&changed).unwrap())
                .is_err(),
            "{field} mismatch must fail smoke"
        );
    }

    let mut missing = valid.clone();
    missing["results"][0]
        .as_object_mut()
        .unwrap()
        .remove("satisfied");
    assert!(
        validate_authorized_evaluation_response(&plan, &serde_json::to_vec(&missing).unwrap())
            .is_err()
    );

    let duplicate = serde_json::json!({
        "results": [authorized_claim_result(), authorized_claim_result()]
    });
    assert!(validate_authorized_evaluation_response(
        &plan,
        &serde_json::to_vec(&duplicate).unwrap()
    )
    .is_err());

    plan.scenario.expected_claim_results_sha256 =
        dev_claim_results_commitment(vec![DevClaimResultExpectation {
            claim_id: "eligibility".to_string(),
            value: serde_json::Value::Null,
            satisfied: None,
            disclosure: "redacted".to_string(),
        }])
        .unwrap();
    let mut redacted = valid;
    redacted["results"][0]["value"] = serde_json::Value::Null;
    redacted["results"][0]["satisfied"] = serde_json::Value::Null;
    redacted["results"][0]["disclosure"] = serde_json::json!("redacted");
    assert!(validate_authorized_evaluation_response(
        &plan,
        &serde_json::to_vec(&redacted).unwrap()
    )
    .is_ok());
    for field in ["value", "satisfied"] {
        let mut missing = redacted.clone();
        missing["results"][0].as_object_mut().unwrap().remove(field);
        assert!(
            validate_authorized_evaluation_response(&plan, &serde_json::to_vec(&missing).unwrap())
                .is_err(),
            "nullable {field} must still be present"
        );
    }
}

fn plan_input(
    root: &Path,
    provider: DevSourceProvider,
    oauth_profile: DevOAuthProfile,
) -> DevRuntimePlanInput {
    plan_input_generation(root, provider, oauth_profile, "0000000000000001")
}

fn plan_input_generation(
    root: &Path,
    provider: DevSourceProvider,
    oauth_profile: DevOAuthProfile,
    generation: &str,
) -> DevRuntimePlanInput {
    let root = fs::canonicalize(root).unwrap();
    let artifacts = create_artifacts_generation(&root, generation);
    let build_manifest_path = root.join(".registry-stack/build/local/artifact-manifest.json");
    let build_manifest_bytes = b"{\"schema_version\":\"registry.project.artifact_manifest.v1\"}\n";
    fs::write(&build_manifest_path, build_manifest_bytes).unwrap();
    let relay_port = free_port();
    let mut notary_port = free_port();
    while notary_port == relay_port {
        notary_port = free_port();
    }
    DevRuntimePlanInput {
        project_root: root,
        project_id: "citizen-registry".to_string(),
        environment_id: "local".to_string(),
        environment_profile: DevEnvironmentProfile::Local,
        build_manifest: DevBuildManifestBinding {
            path: build_manifest_path,
            digest: registry_platform_config::sha256_uri(build_manifest_bytes),
            project: "citizen-registry".to_string(),
            environment: "local".to_string(),
        },
        release: verified_release(),
        development: AuthoredDevelopment {
            source_mode: DevSourceMode::Synthetic,
            default_integration: "citizen-source".to_string(),
            default_fixture: "passing-default".to_string(),
            operator_source_binding_present: false,
            relay_port: Some(relay_port),
            notary_port: Some(notary_port),
        },
        scenarios: vec![scenario(provider, oauth_profile)],
        records_request: None,
        local_snapshot: None,
        artifacts,
        credentials: PreparedDevCredentialClosure::synthetic(
            match oauth_profile {
                DevOAuthProfile::None => None,
                DevOAuthProfile::Oauth2Bearer => Some(DevOAuthCredentialProfile::Oauth2Bearer),
                DevOAuthProfile::Oauth2BearerNoExpiry => {
                    Some(DevOAuthCredentialProfile::Oauth2BearerNoExpiry)
                }
            },
            false,
        ),
        operator_source_secret_env: Vec::new(),
    }
}

fn local_snapshot_plan_input(root: &Path) -> DevRuntimePlanInput {
    let workbook = root.join("data.xlsx");
    fs::write(&workbook, b"bounded workbook fixture").unwrap();
    let mut input = plan_input(root, DevSourceProvider::Spreadsheet, DevOAuthProfile::None);
    input.development.source_mode = DevSourceMode::LocalSnapshot;
    input.scenarios[0].synthetic_source = None;
    input.credentials = PreparedDevCredentialClosure::operator_bound();
    input.local_snapshot = Some(AuthoredLocalSnapshot {
        host_path: fs::canonicalize(&workbook).unwrap(),
        container_path: "/var/lib/registry/data.xlsx".to_string(),
        digest: registry_platform_config::sha256_uri(b"bounded workbook fixture"),
    });
    input
}

#[test]
fn generic_plan_uses_locked_images_loopback_development_identity_and_exact_source_command() {
    for provider in [
        DevSourceProvider::Http,
        DevSourceProvider::Spreadsheet,
        DevSourceProvider::Rhai,
    ] {
        let temp = tempfile::tempdir().unwrap();
        let plan = DevRuntimePlan::derive(plan_input(temp.path(), provider, DevOAuthProfile::None))
            .unwrap();
        assert_eq!(plan.scenario.source_provider, provider);
        assert!(plan
            .workloads
            .iter()
            .all(|workload| workload.image.contains("@sha256:")));
        assert!(plan
            .public_endpoints()
            .iter()
            .all(|endpoint| endpoint.ip().is_loopback()));
        assert!(plan
            .workloads
            .iter()
            .filter_map(|workload| workload.acceptance_identity.as_ref())
            .all(|identity| {
                identity.trust_domain == registry_platform_config::ProductTrustDomainV1::Development
            }));
        let source = plan
            .workloads
            .iter()
            .find(|workload| workload.id == DevWorkloadId::SyntheticSource)
            .unwrap();
        assert_eq!(
            source.command,
            [
                "registry-relay",
                "synthetic-source",
                "--plan",
                "/run/registry/synthetic-source-plan.json"
            ]
        );
        assert!(source.host_endpoint.is_none());
        assert!(source.mounts.iter().all(|mount| mount.read_only));
        assert!(source
            .mounts
            .iter()
            .any(|mount| mount.container_path == "/run/registry/synthetic-source-plan.json"));
        for workload in plan
            .workloads
            .iter()
            .filter(|workload| workload.acceptance_identity.is_some())
        {
            assert_eq!(
                workload
                    .prepare_state_store
                    .as_ref()
                    .unwrap()
                    .command
                    .last(),
                Some(&"prepare_state_store".to_string())
            );
            assert_eq!(
                workload.initialize_state.as_ref().unwrap().command.last(),
                Some(&"initialize_state".to_string())
            );
            assert_ne!(
                workload
                    .prepare_state_store
                    .as_ref()
                    .unwrap()
                    .compose_service,
                workload.id.compose_service()
            );
            assert_ne!(
                workload.initialize_state.as_ref().unwrap().compose_service,
                workload.id.compose_service()
            );
            assert_eq!(workload.command.last(), Some(&"serve".to_string()));
            assert!(workload.command.contains(&"development-action".to_string()));
            assert!(workload.mounts.iter().any(|mount| {
                !mount.read_only && mount.container_path == "/var/lib/registry/state"
            }));
        }
        assert!(!format!("{plan:?}").contains(RESPONSE_CANARY));
        assert!(!format!("{plan:?}").contains(REQUEST_CANARY));
        let report_json = serde_json::to_string(&plan).unwrap();
        assert!(!report_json.contains(RESPONSE_CANARY));
        assert!(!report_json.contains(REQUEST_CANARY));
    }
}

#[test]
fn credential_mount_inventory_is_lane_and_action_specific() {
    let temp = tempfile::tempdir().unwrap();
    let plan = DevRuntimePlan::derive(plan_input(
        temp.path(),
        DevSourceProvider::Http,
        DevOAuthProfile::Oauth2Bearer,
    ))
    .unwrap();
    let notary = plan
        .workloads
        .iter()
        .find(|workload| workload.id == DevWorkloadId::Notary)
        .unwrap();
    assert!(notary
        .mounts
        .iter()
        .any(|mount| mount.container_path == "/run/secrets/relay-workload-token"));
    let relay_consultation = plan
        .workloads
        .iter()
        .find(|workload| workload.id == DevWorkloadId::RelayConsultation)
        .unwrap();
    assert!(!relay_consultation
        .mounts
        .iter()
        .any(|mount| mount.container_path == "/run/secrets/relay-workload-token"));
    let secret_targets = |action: &DevProductActionPlan| {
        action
            .mounts
            .iter()
            .filter(|mount| mount.container_path.starts_with("/run/secrets/"))
            .map(|mount| mount.container_path.clone())
            .collect::<BTreeSet<_>>()
    };
    let environment_inputs = |mounts: &[DevWorkloadMount]| {
        mounts
            .iter()
            .filter(|mount| {
                mount
                    .host_path
                    .extension()
                    .is_some_and(|extension| extension == "env")
            })
            .map(|mount| {
                mount
                    .host_path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<BTreeSet<_>>()
    };
    let public = plan
        .workloads
        .iter()
        .find(|workload| workload.id == DevWorkloadId::RelayPublic)
        .unwrap();
    assert_eq!(
        environment_inputs(&public.prepare_state_store.as_ref().unwrap().mounts),
        BTreeSet::from(["relay-public-prepare.env".to_string()])
    );
    assert_eq!(
        environment_inputs(&public.initialize_state.as_ref().unwrap().mounts),
        BTreeSet::from(["relay-public-initialize.env".to_string()])
    );
    assert_eq!(
        environment_inputs(&public.mounts),
        BTreeSet::from(["relay-public-serve.env".to_string()])
    );
    assert_eq!(
        environment_inputs(
            &relay_consultation
                .prepare_state_store
                .as_ref()
                .unwrap()
                .mounts
        ),
        BTreeSet::from(["relay-consultation-prepare.env".to_string()])
    );
    assert_eq!(
        environment_inputs(&relay_consultation.initialize_state.as_ref().unwrap().mounts),
        BTreeSet::from(["relay-consultation-initialize.env".to_string()])
    );
    assert_eq!(
        environment_inputs(&relay_consultation.mounts),
        BTreeSet::from(["relay-consultation-serve.env".to_string()])
    );
    assert_eq!(
        environment_inputs(&notary.prepare_state_store.as_ref().unwrap().mounts),
        BTreeSet::from(["notary-prepare.env".to_string()])
    );
    assert_eq!(
        environment_inputs(&notary.initialize_state.as_ref().unwrap().mounts),
        BTreeSet::from(["notary-initialize.env".to_string()])
    );
    assert_eq!(
        environment_inputs(&notary.mounts),
        BTreeSet::from(["notary-serve.env".to_string()])
    );
    assert!(secret_targets(public.prepare_state_store.as_ref().unwrap()).is_empty());
    assert!(secret_targets(public.initialize_state.as_ref().unwrap()).is_empty());
    let database_ca = BTreeSet::from(["/run/secrets/postgresql-ca.pem".to_string()]);
    assert_eq!(
        secret_targets(relay_consultation.prepare_state_store.as_ref().unwrap()),
        database_ca
    );
    assert_eq!(
        secret_targets(relay_consultation.initialize_state.as_ref().unwrap()),
        database_ca
    );
    assert_eq!(
        secret_targets(notary.prepare_state_store.as_ref().unwrap()),
        database_ca
    );
    assert_eq!(
        secret_targets(notary.initialize_state.as_ref().unwrap()),
        database_ca
    );
    assert_eq!(
        notary
            .mounts
            .iter()
            .filter(|mount| mount.container_path.starts_with("/run/secrets/"))
            .map(|mount| mount.container_path.clone())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "/run/secrets/notary-signing-key.jwk".to_string(),
            "/run/secrets/postgresql-ca.pem".to_string(),
            "/run/secrets/relay-workload-token".to_string(),
        ])
    );
    assert!(relay_consultation.mounts.iter().any(|mount| {
        mount.container_path == "/run/registry/dev-public/notary-workload-jwks.json"
            && mount.read_only
            && mount.kind == DevWorkloadMountKind::Bind
    }));
    for workload in plan
        .workloads
        .iter()
        .filter(|workload| workload.id != DevWorkloadId::RelayConsultation)
    {
        assert!(workload.mounts.iter().all(|mount| {
            mount.container_path != "/run/registry/dev-public/notary-workload-jwks.json"
        }));
    }
    for action in plan
        .workloads
        .iter()
        .flat_map(|workload| {
            [
                workload.prepare_state_store.as_ref(),
                workload.initialize_state.as_ref(),
            ]
        })
        .flatten()
    {
        assert!(action.mounts.iter().any(|mount| mount
            .host_path
            .extension()
            .is_some_and(|value| value == "env")));
        assert!(!action.mounts.iter().any(|mount| {
            mount
                .container_path
                .starts_with("/run/registry/synthetic-source-secrets")
        }));
    }
}

#[test]
fn local_snapshot_mounts_one_bounded_workbook_only_into_relay_serve_workloads() {
    let temporary = tempfile::tempdir().unwrap();
    let plan = DevRuntimePlan::derive(local_snapshot_plan_input(temporary.path())).unwrap();

    assert_eq!(plan.source_mode, DevSourceMode::LocalSnapshot);
    assert!(!plan
        .workloads
        .iter()
        .any(|workload| workload.id == DevWorkloadId::SyntheticSource));
    let project_mounts = plan
        .workloads
        .iter()
        .flat_map(|workload| {
            workload
                .mounts
                .iter()
                .filter(|mount| mount.kind == DevWorkloadMountKind::ProjectFile)
                .map(move |mount| (workload.id, mount))
        })
        .collect::<Vec<_>>();
    assert_eq!(project_mounts.len(), 2);
    assert_eq!(project_mounts[0].0, DevWorkloadId::RelayPublic);
    assert_eq!(project_mounts[1].0, DevWorkloadId::RelayConsultation);
    assert_eq!(project_mounts[0].1, project_mounts[1].1);
    assert!(project_mounts.iter().all(|(_, mount)| mount.read_only));
    assert!(plan.workloads.iter().all(|workload| workload
        .mounts
        .iter()
        .all(|mount| { !mount.container_path.contains("synthetic-source") })));
    assert!(plan.workloads.iter().all(|workload| [
        workload.prepare_state_store.as_ref(),
        workload.initialize_state.as_ref(),
    ]
    .into_iter()
    .flatten()
    .flat_map(|action| &action.mounts)
    .all(|mount| mount.kind != DevWorkloadMountKind::ProjectFile)));

    let compose = temporary.path().join("local-snapshot-compose.json");
    render_closed_compose(&compose, &plan.workloads, DevSourceMode::LocalSnapshot).unwrap();
    let compose: serde_json::Value = serde_json::from_slice(&fs::read(compose).unwrap()).unwrap();
    assert!(compose["networks"].get("registry_egress").is_none());
    assert!(compose["services"]
        .get("registry-synthetic-source")
        .is_none());
    for service in ["registry-relay-public", "registry-relay-consultation"] {
        assert!(compose["services"][service]["volumes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|mount| {
                mount["target"] == "/var/lib/registry/data.xlsx" && mount["read_only"] == true
            }));
    }
    let debug = format!("{plan:?}");
    assert!(!debug.contains(&temporary.path().join("data.xlsx").display().to_string()));
    validate_local_snapshot(&plan).unwrap();
}

#[test]
fn local_snapshot_cannot_shadow_runtime_owned_mounts() {
    let temporary = tempfile::tempdir().unwrap();
    let mut input = local_snapshot_plan_input(temporary.path());
    input.local_snapshot.as_mut().unwrap().container_path =
        "/run/registry/dev-public/notary-workload-jwks.json".to_string();

    assert!(DevRuntimePlan::derive(input).is_err());
}

#[test]
fn local_snapshot_rejects_changed_extra_escaped_and_oversized_project_files() {
    let changed = tempfile::tempdir().unwrap();
    let changed_plan = DevRuntimePlan::derive(local_snapshot_plan_input(changed.path())).unwrap();
    let mut changed_controller = DevRuntimeController::new(FakeBackend::default());
    changed_controller.start(&changed_plan, true).unwrap();
    fs::write(changed.path().join("data.xlsx"), b"changed workbook").unwrap();
    assert!(validate_local_snapshot(&changed_plan).is_err());
    assert_eq!(
        changed_controller
            .status(&changed_plan)
            .unwrap_err()
            .category,
        DevFailureCategory::ProjectBinding
    );
    changed_controller.down(&changed_plan).unwrap();

    let extra = tempfile::tempdir().unwrap();
    let mut extra_plan = DevRuntimePlan::derive(local_snapshot_plan_input(extra.path())).unwrap();
    let mount = extra_plan
        .workloads
        .iter()
        .find(|workload| workload.id == DevWorkloadId::RelayPublic)
        .unwrap()
        .mounts
        .iter()
        .find(|mount| mount.kind == DevWorkloadMountKind::ProjectFile)
        .unwrap()
        .clone();
    extra_plan
        .workloads
        .iter_mut()
        .find(|workload| workload.id == DevWorkloadId::Notary)
        .unwrap()
        .mounts
        .push(mount);
    assert!(validate_local_snapshot(&extra_plan).is_err());

    let escaped = tempfile::tempdir().unwrap();
    let external = tempfile::NamedTempFile::new().unwrap();
    let mut escaped_input = local_snapshot_plan_input(escaped.path());
    escaped_input.local_snapshot.as_mut().unwrap().host_path =
        fs::canonicalize(external.path()).unwrap();
    escaped_input.local_snapshot.as_mut().unwrap().digest =
        registry_platform_config::sha256_uri(&fs::read(external.path()).unwrap());
    assert!(DevRuntimePlan::derive(escaped_input).is_err());

    let oversized = tempfile::tempdir().unwrap();
    let mut oversized_input = local_snapshot_plan_input(oversized.path());
    std::fs::OpenOptions::new()
        .write(true)
        .open(oversized.path().join("data.xlsx"))
        .unwrap()
        .set_len(MAX_LOCAL_SNAPSHOT_BYTES + 1)
        .unwrap();
    oversized_input.local_snapshot.as_mut().unwrap().digest =
        registry_platform_config::sha256_uri(b"");
    assert!(DevRuntimePlan::derive(oversized_input).is_err());
}

#[cfg(unix)]
#[test]
fn local_snapshot_rejects_a_symlink_swap_after_planning() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().unwrap();
    let plan = DevRuntimePlan::derive(local_snapshot_plan_input(temporary.path())).unwrap();
    let external = tempfile::NamedTempFile::new().unwrap();
    fs::remove_file(temporary.path().join("data.xlsx")).unwrap();
    symlink(external.path(), temporary.path().join("data.xlsx")).unwrap();
    assert!(validate_local_snapshot(&plan).is_err());
}

#[test]
fn compose_networks_close_synthetic_mode_and_scope_operator_egress_and_secrets() {
    let synthetic_temp = tempfile::tempdir().unwrap();
    let synthetic = DevRuntimePlan::derive(plan_input(
        synthetic_temp.path(),
        DevSourceProvider::Http,
        DevOAuthProfile::None,
    ))
    .unwrap();
    let synthetic_compose = synthetic_temp
        .path()
        .join(".registry-stack/build/local/dev/synthetic-compose.json");
    render_closed_compose(
        &synthetic_compose,
        &synthetic.workloads,
        DevSourceMode::Synthetic,
    )
    .unwrap();
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(synthetic_compose).unwrap()).unwrap();
    assert!(value["networks"].get("registry_egress").is_none());
    assert_eq!(
        value["networks"]["registry_private"]["ipam"]["config"][0]["subnet"],
        "10.89.0.0/24"
    );
    assert_eq!(
        value["services"]["registry-synthetic-source"]["networks"]["registry_private"]
            ["ipv4_address"],
        "10.89.0.3"
    );
    assert_eq!(
        value["services"]["registry-relay-consultation"]["networks"]["registry_private"]
            ["ipv4_address"],
        "10.89.0.4"
    );
    let consultation_mounts = value["services"]["registry-relay-consultation"]["volumes"]
        .as_array()
        .unwrap();
    assert!(consultation_mounts.iter().any(|mount| {
        mount["target"] == "/run/registry/dev-public/synthetic-source-tls.crt"
            && mount["read_only"] == true
    }));
    assert!(consultation_mounts.iter().any(|mount| {
        mount["target"] == "/run/registry/dev-public/notary-workload-jwks.json"
            && mount["read_only"] == true
    }));
    let notary_mounts = value["services"]["registry-notary"]["volumes"]
        .as_array()
        .unwrap();
    assert!(notary_mounts.iter().all(|mount| {
        mount["target"] != "/run/secrets/relay-consultation-ca.pem"
            && mount["target"] != "/run/registry/dev-public/notary-workload-jwks.json"
    }));
    #[cfg(unix)]
    {
        let expected_user = format!(
            "{}:{}",
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw()
        );
        for (service, document) in value["services"].as_object().unwrap() {
            match service.as_str() {
                "registry-postgres" | "registry-postgres-bootstrap" => {
                    assert_eq!(document["user"], "999:999");
                }
                "registry-postgres-stage-secrets" => {
                    assert_eq!(document["user"], "0:0");
                    assert_eq!(document["network_mode"], "none");
                    assert_eq!(
                        document["cap_add"],
                        serde_json::json!(["CHOWN", "DAC_READ_SEARCH"])
                    );
                }
                _ => {
                    assert_eq!(document["user"], expected_user);
                    assert_ne!(document["user"], "0:0");
                }
            }
        }
    }
    let postgres = &value["services"]["registry-postgres"];
    assert_eq!(postgres["read_only"], true);
    assert_eq!(postgres["cap_drop"], serde_json::json!(["ALL"]));
    assert_eq!(
        postgres["environment"],
        serde_json::json!([
            "POSTGRES_USER=registry_stack_bootstrap",
            "POSTGRES_DB=postgres",
            "POSTGRES_PASSWORD_FILE=/run/secrets/postgresql-admin-password",
            "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=peer"
        ])
    );
    let stage_command = value["services"]["registry-postgres-stage-secrets"]["command"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(stage_command.contains("/usr/bin/install -m 0400"));
    assert!(stage_command.contains("/usr/bin/chown 999:999"));
    assert!(!stage_command.contains("postgres-admin-password"));
    assert_eq!(
        value["services"]["registry-postgres-bootstrap"]["networks"]["registry_private"],
        serde_json::json!({})
    );

    let operator_temp = tempfile::tempdir().unwrap();
    let mut input = plan_input(
        operator_temp.path(),
        DevSourceProvider::Http,
        DevOAuthProfile::None,
    );
    input.development.source_mode = DevSourceMode::OperatorBound;
    input.development.operator_source_binding_present = true;
    input.scenarios[0].synthetic_source = None;
    input.credentials = PreparedDevCredentialClosure::operator_bound();
    input.operator_source_secret_env = vec!["FICTIONAL_REGISTRY_TOKEN".to_string()];
    let operator = DevRuntimePlan::derive(input).unwrap();
    let operator_compose = operator_temp
        .path()
        .join(".registry-stack/build/local/dev/operator-compose.json");
    render_closed_compose(
        &operator_compose,
        &operator.workloads,
        DevSourceMode::OperatorBound,
    )
    .unwrap();
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(operator_compose).unwrap()).unwrap();
    assert!(value["networks"].get("registry_egress").is_some());
    for (service, document) in value["services"].as_object().unwrap() {
        if document.get("network_mode").is_some() {
            assert_eq!(service, "registry-postgres-stage-secrets");
            assert_eq!(document["network_mode"], "none");
            continue;
        }
        let networks = document["networks"].as_object().unwrap();
        let has_egress = networks.contains_key("registry_egress");
        assert_eq!(has_egress, service == "registry-relay-consultation");
        if service == "registry-relay-consultation" {
            assert_eq!(
                document["environment"],
                serde_json::json!(["FICTIONAL_REGISTRY_TOKEN"])
            );
        } else if service != "registry-postgres" {
            assert!(document.get("environment").is_none());
        }
    }
}

#[test]
fn supporting_services_wait_for_health_before_product_actions() {
    assert_eq!(
        supporting_up_operation(vec!["registry-postgres".to_string()]),
        [
            "up",
            "--detach",
            "--wait",
            "--wait-timeout",
            "60",
            "registry-postgres"
        ]
    );
}

#[test]
fn compose_health_requires_the_exact_complete_healthy_workload_set() {
    let expected = ["registry-postgres", "registry-relay-public"];
    let healthy = br#"[
      {"Service":"registry-postgres","State":"running","Health":"healthy"},
      {"Service":"registry-relay-public","State":"running","Health":"healthy"}
    ]"#;
    assert_eq!(
        classify_compose_ps_health(healthy, &expected).unwrap(),
        DevRuntimeHealth::Running
    );

    for degraded in [
        br#"[{"Service":"registry-postgres","State":"running","Health":"healthy"}]"#.as_slice(),
        br#"[{"Service":"registry-postgres","State":"exited","Health":""}]"#.as_slice(),
        br#"[
          {"Service":"registry-postgres","State":"running","Health":"healthy"},
          {"Service":"registry-relay-public","State":"running","Health":"unhealthy"}
        ]"#
        .as_slice(),
        br#"[
          {"Service":"registry-postgres","State":"running","Health":"healthy"},
          {"Service":"registry-relay-public","State":"restarting","Health":""}
        ]"#
        .as_slice(),
    ] {
        assert_eq!(
            classify_compose_ps_health(degraded, &expected).unwrap(),
            DevRuntimeHealth::Degraded
        );
    }
    assert_eq!(
        classify_compose_ps_health(b"[]", &expected).unwrap(),
        DevRuntimeHealth::Stopped
    );
}

#[test]
fn operator_bound_smoke_reports_unobserved_source_counters() {
    let temp = tempfile::tempdir().unwrap();
    let mut input = plan_input(temp.path(), DevSourceProvider::Http, DevOAuthProfile::None);
    input.development.source_mode = DevSourceMode::OperatorBound;
    input.development.operator_source_binding_present = true;
    input.scenarios[0].synthetic_source = None;
    input.credentials = PreparedDevCredentialClosure::operator_bound();
    input.operator_source_secret_env = vec!["FICTIONAL_REGISTRY_TOKEN".to_string()];
    let plan = DevRuntimePlan::derive(input).unwrap();
    let mut controller = DevRuntimeController::new(FakeBackend::default());
    controller.start(&plan, true).unwrap();
    let report = controller.smoke(&plan).unwrap();
    assert!(report.results.iter().all(|result| {
        result.token_counter_delta.is_none() && result.source_counter_delta.is_none()
    }));
}

#[test]
fn lifecycle_refuses_compose_content_changed_after_plan_derivation() {
    let temp = tempfile::tempdir().unwrap();
    let plan = DevRuntimePlan::derive(plan_input(
        temp.path(),
        DevSourceProvider::Http,
        DevOAuthProfile::None,
    ))
    .unwrap();
    fs::write(&plan.lifecycle.compose_file, "services:\n  replaced: {}\n").unwrap();
    let error = DevRuntimeController::new(FakeBackend::default())
        .start(&plan, true)
        .unwrap_err();
    assert_eq!(error.category, DevFailureCategory::ProjectBinding);
    assert!(!plan.paths.root.exists());
}

#[test]
fn attached_flow_returns_report_before_wait_and_cleans_up_normally() {
    let temp = tempfile::tempdir().unwrap();
    let plan = DevRuntimePlan::derive(plan_input(
        temp.path(),
        DevSourceProvider::Http,
        DevOAuthProfile::None,
    ))
    .unwrap();
    let mut controller = DevRuntimeController::new(FakeBackend::default());
    let report = controller.start(&plan, false).unwrap();
    assert!(report
        .evidence_request_command
        .starts_with("curl --config "));
    assert!(plan.paths.state_file.exists());
    controller.attach(&plan).unwrap();
    let backend = controller.into_backend();
    let start = backend
        .calls
        .iter()
        .position(|call| call == "start:true")
        .unwrap();
    let attach = backend
        .calls
        .iter()
        .position(|call| call == "attach")
        .unwrap();
    let down = backend
        .calls
        .iter()
        .position(|call| call == "down")
        .unwrap();
    assert!(start < attach && attach < down);
    assert!(!plan.paths.root.exists());
}

#[test]
fn default_scenario_is_authored_exactly_and_production_or_evidence_is_refused() {
    let temp = tempfile::tempdir().unwrap();
    let mut input = plan_input(temp.path(), DevSourceProvider::Http, DevOAuthProfile::None);
    input.development.default_fixture = "not-authored".to_string();
    input.scenarios.push(AuthoredDevScenario {
        fixture_id: "available-second".to_string(),
        ..scenario(DevSourceProvider::Http, DevOAuthProfile::None)
    });
    let error = DevRuntimePlan::derive(input).unwrap_err();
    assert_eq!(error.category, DevFailureCategory::MissingDefaultScenario);
    assert!(error.summary.contains("citizen-source.passing-default"));
    assert!(error.summary.contains("citizen-source.available-second"));

    for profile in [
        DevEnvironmentProfile::Production,
        DevEnvironmentProfile::EvidenceGrade,
    ] {
        let temp = tempfile::tempdir().unwrap();
        let mut input = plan_input(temp.path(), DevSourceProvider::Http, DevOAuthProfile::None);
        input.environment_profile = profile;
        let error = DevRuntimePlan::derive(input).unwrap_err();
        assert_eq!(error.category, DevFailureCategory::UnsafeEnvironment);
    }
}

#[test]
fn synthetic_and_operator_bound_sources_cannot_be_confused() {
    let temp = tempfile::tempdir().unwrap();
    let mut synthetic = plan_input(temp.path(), DevSourceProvider::Http, DevOAuthProfile::None);
    synthetic.development.operator_source_binding_present = true;
    let error = DevRuntimePlan::derive(synthetic).unwrap_err();
    assert_eq!(error.category, DevFailureCategory::InvalidPlan);

    let temp = tempfile::tempdir().unwrap();
    let mut operator = plan_input(temp.path(), DevSourceProvider::Http, DevOAuthProfile::None);
    operator.development.source_mode = DevSourceMode::OperatorBound;
    operator.development.operator_source_binding_present = true;
    let error = DevRuntimePlan::derive(operator).unwrap_err();
    assert!(error
        .summary
        .contains("cannot carry a synthetic source plan"));

    let temp = tempfile::tempdir().unwrap();
    let mut operator = plan_input(temp.path(), DevSourceProvider::Http, DevOAuthProfile::None);
    operator.development.source_mode = DevSourceMode::OperatorBound;
    operator.development.operator_source_binding_present = true;
    operator.scenarios[0].synthetic_source = None;
    operator.credentials = PreparedDevCredentialClosure::operator_bound();
    operator.operator_source_secret_env = vec!["FICTIONAL_REGISTRY_TOKEN".to_string()];
    let plan = DevRuntimePlan::derive(operator).unwrap();
    assert!(!plan
        .workloads
        .iter()
        .any(|workload| workload.id == DevWorkloadId::SyntheticSource));
    assert!(!plan
        .workloads
        .iter()
        .flat_map(|workload| &workload.mounts)
        .any(|mount| mount.container_path.contains("synthetic-oauth")));
}

#[test]
fn governed_trust_material_is_refused_by_development_planning() {
    let temp = tempfile::tempdir().unwrap();
    let input = plan_input(temp.path(), DevSourceProvider::Http, DevOAuthProfile::None);
    let manifest_path = input.artifacts.relay_public_bundle.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    manifest["acceptance_identity"]["trust_domain"] = serde_json::json!("governed");
    fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let error = DevRuntimePlan::derive(input).unwrap_err();
    assert_eq!(error.category, DevFailureCategory::InvalidPlan);
    assert!(error.summary.contains("disposable development identity"));
}

#[test]
fn unsigned_or_tampered_development_bundle_is_refused() {
    let temp = tempfile::tempdir().unwrap();
    let input = plan_input(temp.path(), DevSourceProvider::Http, DevOAuthProfile::None);
    let signature_path = input
        .artifacts
        .relay_consultation_bundle
        .join("manifest.sig.json");
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(&signature_path).unwrap()).unwrap();
    envelope["signatures"][0]["sig"] = serde_json::json!("AAAA");
    fs::write(&signature_path, serde_json::to_vec(&envelope).unwrap()).unwrap();
    let error = DevRuntimePlan::derive(input).unwrap_err();
    assert_eq!(error.category, DevFailureCategory::InvalidPlan);
    assert!(error.summary.contains("disposable development identity"));
}

#[test]
fn release_projection_and_oauth_profiles_fail_closed() {
    assert_eq!(
        VerifiedDevReleaseProjection::test_only(
            "release-v1.0.0".to_string(),
            "v1.0.0".to_string(),
            "ghcr.io/registrystack/registry-relay:v1.0.0".to_string(),
            format!(
                "ghcr.io/registrystack/registry-notary@sha256:{}",
                "b".repeat(64)
            ),
            format!("docker.io/library/postgres@sha256:{}", "c".repeat(64)),
            "2.24.0".to_string(),
        )
        .unwrap_err()
        .category,
        DevFailureCategory::InvalidImageLock
    );

    let temp = tempfile::tempdir().unwrap();
    let mut no_oauth = plan_input(temp.path(), DevSourceProvider::Rhai, DevOAuthProfile::None);
    no_oauth.scenarios[0]
        .synthetic_source
        .as_mut()
        .unwrap()
        .oauth_response_case = Some(SyntheticOAuthResponseCase::Valid);
    let error = DevRuntimePlan::derive(no_oauth).unwrap_err();
    assert!(error.summary.contains("non-OAuth source"));

    let temp = tempfile::tempdir().unwrap();
    let mut forbidden_body =
        plan_input(temp.path(), DevSourceProvider::Http, DevOAuthProfile::None);
    forbidden_body.scenarios[0]
        .synthetic_source
        .as_mut()
        .unwrap()
        .scenario = SyntheticSourceScenario::SourceTimeout;
    let error = DevRuntimePlan::derive(forbidden_body).unwrap_err();
    assert!(error.summary.contains("response_body presence"));

    let temp = tempfile::tempdir().unwrap();
    let mut reserved_request =
        plan_input(temp.path(), DevSourceProvider::Http, DevOAuthProfile::None);
    reserved_request.scenarios[0]
        .synthetic_source
        .as_mut()
        .unwrap()
        .source_request
        .path = "/oauth/token".to_string();
    let error = DevRuntimePlan::derive(reserved_request).unwrap_err();
    assert!(error.summary.contains("closed authored operation"));
}

#[derive(Default)]
struct FakeBackend {
    calls: Vec<String>,
    absent_images: BTreeSet<String>,
    running: bool,
    health: Option<DevRuntimeHealth>,
    down_calls: usize,
    fail_down: bool,
    fail_start: bool,
    doctor_report: Option<DevDoctorReport>,
}

impl DevRuntimeBackend for FakeBackend {
    fn doctor(&mut self, _plan: &DevRuntimePlan) -> DevRuntimeResult<DevDoctorReport> {
        self.calls.push("doctor".to_string());
        Ok(self.doctor_report.clone().unwrap_or(DevDoctorReport {
            docker_installed: true,
            daemon_available: true,
            compose_supported: true,
        }))
    }

    fn image_availability(&mut self, image: &str) -> DevRuntimeResult<DevImageAvailability> {
        self.calls.push(format!("inspect:{image}"));
        Ok(if self.absent_images.contains(image) {
            DevImageAvailability::Absent
        } else {
            DevImageAvailability::Local
        })
    }

    fn pull_image(&mut self, image: &str) -> DevRuntimeResult<()> {
        self.calls.push(format!("pull:{image}"));
        Ok(())
    }

    fn health(&mut self, _state: &DevRuntimeStateV1) -> DevRuntimeResult<DevRuntimeHealth> {
        Ok(self.health.unwrap_or(if self.running {
            DevRuntimeHealth::Running
        } else {
            DevRuntimeHealth::Stopped
        }))
    }

    fn start(
        &mut self,
        _plan: &DevRuntimePlan,
        _state: &DevRuntimeStateV1,
        detach: bool,
    ) -> DevRuntimeResult<()> {
        self.calls.push(format!("start:{detach}"));
        if self.fail_start {
            return Err(DevRuntimeError::new(
                DevFailureCategory::Startup,
                "injected startup failure",
                "retry",
            ));
        }
        self.running = true;
        Ok(())
    }

    fn attach(
        &mut self,
        _plan: &DevRuntimePlan,
        _state: &DevRuntimeStateV1,
    ) -> DevRuntimeResult<()> {
        self.calls.push("attach".to_string());
        Ok(())
    }

    fn status(
        &mut self,
        plan: &DevRuntimePlan,
        _state: &DevRuntimeStateV1,
    ) -> DevRuntimeResult<Vec<DevWorkloadStatus>> {
        Ok(plan
            .lifecycle
            .status_services
            .iter()
            .map(|workload| DevWorkloadStatus {
                workload: *workload,
                state: DevRuntimeHealthWire::Running,
            })
            .collect())
    }

    fn logs(
        &mut self,
        plan: &DevRuntimePlan,
        _state: &DevRuntimeStateV1,
    ) -> DevRuntimeResult<Vec<DevProductLogSummary>> {
        Ok(plan
            .lifecycle
            .log_services
            .iter()
            .map(|workload| DevProductLogSummary {
                workload: *workload,
                available: true,
            })
            .collect())
    }

    fn smoke(
        &mut self,
        plan: &DevRuntimePlan,
        _state: &DevRuntimeStateV1,
    ) -> DevRuntimeResult<DevSmokeReportV1> {
        let token_delta = if plan.scenario.oauth_profile == DevOAuthProfile::None {
            0
        } else {
            1
        };
        let observed = plan.source_mode == DevSourceMode::Synthetic;
        Ok(DevSmokeReportV1 {
            schema_version: DEV_SMOKE_REPORT_SCHEMA_V1.to_string(),
            project: plan.binding.project.clone(),
            environment: plan.binding.environment.clone(),
            results: vec![
                DevSmokeScenarioResult {
                    scenario_id: plan.scenario.denial_scenario_id.clone(),
                    status: DevSmokeStatus::Denied,
                    token_counter_delta: observed.then_some(0),
                    source_counter_delta: observed.then_some(0),
                    minimized_claim_ids: Vec::new(),
                    passed: true,
                },
                DevSmokeScenarioResult {
                    scenario_id: plan.scenario.authorized_scenario_id.clone(),
                    status: DevSmokeStatus::Authorized,
                    token_counter_delta: observed.then_some(token_delta),
                    source_counter_delta: observed.then_some(1),
                    minimized_claim_ids: plan.scenario.minimized_claim_ids.clone(),
                    passed: true,
                },
            ],
            passed: true,
        })
    }

    fn down(&mut self, _state: &DevRuntimeStateV1, timeout_seconds: u16) -> DevRuntimeResult<()> {
        assert_eq!(timeout_seconds, 15);
        if self.fail_down {
            return Err(DevRuntimeError::new(
                DevFailureCategory::DockerUnavailable,
                "injected down failure",
                "retry",
            ));
        }
        self.calls.push("down".to_string());
        self.down_calls += 1;
        self.running = false;
        Ok(())
    }
}

#[test]
fn lifecycle_is_project_bound_bounded_owner_only_and_value_free() {
    let temp = tempfile::tempdir().unwrap();
    let plan = DevRuntimePlan::derive(plan_input(
        temp.path(),
        DevSourceProvider::Rhai,
        DevOAuthProfile::Oauth2BearerNoExpiry,
    ))
    .unwrap();
    let generated_artifacts = plan.artifacts.compose_file.parent().unwrap().to_path_buf();
    let mut backend = FakeBackend::default();
    backend
        .absent_images
        .insert(plan.workloads[0].image.clone());
    let mut controller = DevRuntimeController::new(backend);
    let startup = controller.start(&plan, true).unwrap();
    assert_eq!(startup.source_mode, DevSourceMode::Synthetic);
    assert!(startup.disposable_notice.contains("not production inputs"));
    assert!(startup.evidence_request_command.contains("curl --config"));
    assert!(!format!("{startup:?}").contains(RESPONSE_CANARY));
    assert!(!format!("{startup:?}").contains(REQUEST_CANARY));

    let request_config = fs::read_to_string(&plan.paths.request_config).unwrap();
    assert!(request_config.contains("/v1/evaluations"));
    assert!(request_config.contains("url = \"http://127.0.0.1:"));
    assert!(!request_config.contains("url = \"https://"));
    assert!(!request_config.contains("cacert = "));
    assert!(startup.relay_api_url.starts_with("http://127.0.0.1:"));
    assert!(startup.evidence_api_url.starts_with("http://127.0.0.1:"));
    for obsolete_listener_credential in [
        "relay-public-tls.crt",
        "relay-public-tls.key",
        "relay-consultation-tls.crt",
        "relay-consultation-tls.key",
        "notary-tls.crt",
        "notary-tls.key",
    ] {
        assert!(!plan
            .paths
            .credentials
            .join(obsolete_listener_credential)
            .exists());
    }
    let caller_token = fs::read_to_string(plan.paths.credentials.join("caller-token")).unwrap();
    assert!(request_config.contains(&caller_token));
    assert!(!startup.evidence_request_command.contains(&caller_token));
    assert!(fs::read_to_string(&plan.paths.synthetic_source_plan)
        .unwrap()
        .contains(RESPONSE_CANARY));
    let source_plan: serde_json::Value =
        serde_json::from_slice(&fs::read(&plan.paths.synthetic_source_plan).unwrap()).unwrap();
    assert_eq!(
        source_plan["version"],
        "registry.relay.synthetic-source-plan.v1"
    );
    assert_eq!(source_plan["scenario"], "authored_response");
    assert_eq!(source_plan["source_request"]["method"], "get");
    assert_eq!(
        source_plan["source_request"]["path"],
        "/people/example-person"
    );
    assert_eq!(
        source_plan["source_request"]["query"]["expand"],
        "eligibility"
    );
    assert!(source_plan.get("routes").is_none());
    assert!(source_plan.get("path").is_none());
    assert_eq!(
        source_plan["oauth"]["response_profile"],
        "oauth2_bearer_no_expiry"
    );
    assert_eq!(source_plan["request_encoding"], "form");
    assert_eq!(
        source_plan["oauth"]["request"]["audience"],
        "registry-notary"
    );
    assert_eq!(source_plan["oauth"]["request"]["scope"], "registry.read");
    assert_eq!(
        source_plan["oauth"]["request"]["resource"],
        "registry-source"
    );
    assert_eq!(
        source_plan["secrets"]["control_token"]["file"],
        "control-token"
    );
    assert_eq!(source_plan["secrets"]["control_token"]["generation"], 1);
    let same_runtime = controller.start(&plan, true).unwrap();
    assert_eq!(
        same_runtime.evidence_request_command,
        startup.evidence_request_command
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for path in [
            &plan.paths.state_file,
            &plan.paths.request_config,
            &plan.paths.request_body,
            &plan.paths.synthetic_source_plan,
        ] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(
            fs::metadata(&plan.paths.credentials)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    let status = controller.status(&plan).unwrap();
    assert_eq!(status.schema_version, DEV_STATUS_REPORT_SCHEMA_V1);
    assert_eq!(
        status.evidence_request_command,
        startup.evidence_request_command
    );
    assert_eq!(status.workloads.len(), plan.lifecycle.status_services.len());
    let status_json = serde_json::to_value(&status).unwrap();
    assert_eq!(status_json["schema_version"], DEV_STATUS_REPORT_SCHEMA_V1);
    assert_eq!(status_json.as_object().unwrap().len(), 9);
    let serialized_status = serde_json::to_string(&status).unwrap();
    assert!(!serialized_status.contains(&caller_token));
    assert!(!serialized_status.contains(RESPONSE_CANARY));
    let logs = controller.logs(&plan).unwrap();
    assert_eq!(logs.schema_version, DEV_LOGS_REPORT_SCHEMA_V1);
    assert_eq!(logs.products.len(), plan.lifecycle.log_services.len());
    let logs_json = serde_json::to_value(&logs).unwrap();
    assert_eq!(logs_json["schema_version"], DEV_LOGS_REPORT_SCHEMA_V1);
    assert_eq!(logs_json.as_object().unwrap().len(), 3);
    let serialized_logs = serde_json::to_string(&logs).unwrap();
    assert!(!serialized_logs.contains(&caller_token));
    assert!(!serialized_logs.contains(RESPONSE_CANARY));
    let smoke = controller.smoke(&plan).unwrap();
    assert!(smoke.passed);
    assert_eq!(smoke.results[0].token_counter_delta, Some(0));
    assert_eq!(smoke.results[0].source_counter_delta, Some(0));
    assert_eq!(smoke.results[1].token_counter_delta, Some(1));
    assert_eq!(smoke.results[1].source_counter_delta, Some(1));

    controller.down(&plan).unwrap();
    assert!(!plan.paths.root.exists());
    assert!(!generated_artifacts.exists());
    let backend = controller.into_backend();
    assert_eq!(backend.down_calls, 1);
    assert_eq!(
        backend
            .calls
            .iter()
            .filter(|call| call.starts_with("start:"))
            .count(),
        1
    );
    assert_eq!(backend.calls.first().unwrap(), "doctor");
    assert!(backend.calls.iter().any(|call| call.starts_with("pull:")));
}

#[test]
fn records_requests_are_owner_only_minimal_and_credential_separated() {
    let temp = tempfile::tempdir().unwrap();
    let mut input = plan_input(
        temp.path(),
        DevSourceProvider::Spreadsheet,
        DevOAuthProfile::None,
    );
    input.records_request = Some(project_authoring::AuthoredRecordsRequest {
        dataset_id: "projects".to_string(),
        entity_id: "projects".to_string(),
        record_id: "pw_001".to_string(),
        purpose: "public-works-case-management".to_string(),
    });
    input.credentials = PreparedDevCredentialClosure::synthetic_records();
    let plan = DevRuntimePlan::derive(input).unwrap();
    let mut controller = DevRuntimeController::new(FakeBackend::default());
    let startup = controller.start(&plan, true).unwrap();

    assert!(startup.relay_api_url.starts_with("http://127.0.0.1:"));
    assert!(startup
        .records_denied_command
        .as_ref()
        .unwrap()
        .contains("records-denied.curl"));
    assert!(startup
        .records_request_command
        .as_ref()
        .unwrap()
        .contains("records-request.curl"));
    assert!(!startup.evidence_request_command.contains("records"));

    let authorized = fs::read_to_string(&plan.paths.records_request_config).unwrap();
    let denied = fs::read_to_string(&plan.paths.records_denied_config).unwrap();
    let match_token = fs::read_to_string(plan.paths.credentials.join("relay-match-token")).unwrap();
    let no_match_token =
        fs::read_to_string(plan.paths.credentials.join("relay-no-match-token")).unwrap();
    let caller_token = fs::read_to_string(plan.paths.credentials.join("caller-token")).unwrap();
    assert!(authorized.contains("/v1/datasets/projects/entities/projects/records/pw_001"));
    assert!(authorized.contains("url = \"http://127.0.0.1:"));
    assert!(!authorized.contains("cacert = "));
    assert!(authorized.contains("header = \"Data-Purpose: public-works-case-management\""));
    assert!(authorized.contains(&match_token));
    assert!(authorized.contains("fail\n"));
    assert!(!authorized.contains(&no_match_token));
    assert!(!authorized.contains(&caller_token));
    assert!(denied.contains("include\n"));
    assert!(denied.contains("silent\n"));
    assert!(denied.contains("show-error\n"));
    assert!(!denied.contains("Authorization"));
    assert!(!denied.contains("fail\n"));
    for token in [&match_token, &no_match_token, &caller_token] {
        assert!(!denied.contains(token));
        assert!(!startup
            .records_request_command
            .as_ref()
            .unwrap()
            .contains(token));
    }
    let status = controller.status(&plan).unwrap();
    let status_json = serde_json::to_string(&status).unwrap();
    for token in [&match_token, &no_match_token, &caller_token] {
        assert!(!status_json.contains(token));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for path in [
            &plan.paths.records_request_config,
            &plan.paths.records_denied_config,
        ] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}

#[test]
fn records_request_percent_encodes_each_path_segment_without_encoding_separators() {
    let temp = tempfile::tempdir().unwrap();
    let mut input = plan_input(
        temp.path(),
        DevSourceProvider::Spreadsheet,
        DevOAuthProfile::None,
    );
    input.records_request = Some(project_authoring::AuthoredRecordsRequest {
        dataset_id: "pro/jects".to_string(),
        entity_id: "entity?x#y".to_string(),
        record_id: "PW/%?#café".to_string(),
        purpose: "public-works-case-management".to_string(),
    });
    input.credentials = PreparedDevCredentialClosure::synthetic_records();
    let plan = DevRuntimePlan::derive(input).unwrap();
    DevRuntimeController::new(FakeBackend::default())
        .start(&plan, true)
        .unwrap();

    let request = fs::read_to_string(&plan.paths.records_request_config).unwrap();
    assert!(request.contains(
        "/v1/datasets/pro%2Fjects/entities/entity%3Fx%23y/records/PW%2F%25%3F%23caf%C3%A9"
    ));
    assert!(!request.contains("/datasets/pro/jects/"));
}

#[test]
fn healthy_unchanged_start_rebinds_candidate_attach_to_retained_runtime() {
    let temp = tempfile::tempdir().unwrap();
    let plan = DevRuntimePlan::derive(plan_input(
        temp.path(),
        DevSourceProvider::Http,
        DevOAuthProfile::None,
    ))
    .unwrap();
    let old_artifacts = plan.artifacts.compose_file.parent().unwrap().to_path_buf();
    let relay_port = plan
        .workloads
        .iter()
        .find(|workload| workload.id == DevWorkloadId::RelayPublic)
        .and_then(|workload| workload.host_endpoint)
        .unwrap()
        .port();
    let notary_port = plan
        .workloads
        .iter()
        .find(|workload| workload.id == DevWorkloadId::Notary)
        .and_then(|workload| workload.host_endpoint)
        .unwrap()
        .port();
    let mut controller = DevRuntimeController::new(FakeBackend::default());
    controller.start(&plan, true).unwrap();

    let mut input = plan_input_generation(
        temp.path(),
        DevSourceProvider::Http,
        DevOAuthProfile::None,
        "0000000000000002",
    );
    input.development.relay_port = Some(relay_port);
    input.development.notary_port = Some(notary_port);
    let candidate = DevRuntimePlan::derive(input).unwrap();
    let candidate_artifacts = candidate
        .artifacts
        .compose_file
        .parent()
        .unwrap()
        .to_path_buf();
    controller.start(&candidate, true).unwrap();

    assert!(plan.paths.root.exists());
    assert!(old_artifacts.exists());
    assert!(!candidate_artifacts.exists());
    controller.attach(&candidate).unwrap();
    assert!(!plan.paths.root.exists());
    assert!(!old_artifacts.exists());
    let backend = controller.into_backend();
    assert_eq!(backend.down_calls, 1);
    assert_eq!(
        backend
            .calls
            .iter()
            .filter(|call| call.starts_with("start:"))
            .count(),
        1
    );
    assert!(backend.calls.iter().any(|call| call == "attach"));
}

#[test]
fn stopped_degraded_and_changed_running_starts_replace_without_orphan_generations() {
    for (health, changed) in [
        (DevRuntimeHealth::Stopped, false),
        (DevRuntimeHealth::Degraded, false),
        (DevRuntimeHealth::Running, true),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let plan = DevRuntimePlan::derive(plan_input(
            temp.path(),
            DevSourceProvider::Http,
            DevOAuthProfile::None,
        ))
        .unwrap();
        let old_artifacts = plan.artifacts.compose_file.parent().unwrap().to_path_buf();
        let mut controller = DevRuntimeController::new(FakeBackend::default());
        controller.start(&plan, true).unwrap();
        let mut backend = controller.into_backend();
        backend.health = Some(health);
        let mut input = plan_input_generation(
            temp.path(),
            DevSourceProvider::Http,
            DevOAuthProfile::None,
            "0000000000000002",
        );
        if changed {
            input.scenarios[0].request_json = br#"{"subject":"changed"}"#.to_vec();
        }
        let replacement = DevRuntimePlan::derive(input).unwrap();
        let replacement_artifacts = replacement
            .artifacts
            .compose_file
            .parent()
            .unwrap()
            .to_path_buf();
        let mut controller = DevRuntimeController::new(backend);
        controller.start(&replacement, true).unwrap();

        assert!(!old_artifacts.exists());
        assert!(replacement_artifacts.exists());
        assert!(replacement.paths.root.exists());
        let backend = controller.into_backend();
        assert_eq!(backend.down_calls, 1);
        assert_eq!(
            backend
                .calls
                .iter()
                .filter(|call| call.starts_with("start:"))
                .count(),
            2
        );
    }
}

#[test]
fn failed_replacement_down_retains_owned_runtime_and_removes_candidate() {
    let temp = tempfile::tempdir().unwrap();
    let plan = DevRuntimePlan::derive(plan_input(
        temp.path(),
        DevSourceProvider::Http,
        DevOAuthProfile::None,
    ))
    .unwrap();
    let old_artifacts = plan.artifacts.compose_file.parent().unwrap().to_path_buf();
    let mut controller = DevRuntimeController::new(FakeBackend::default());
    controller.start(&plan, true).unwrap();
    let mut backend = controller.into_backend();
    backend.health = Some(DevRuntimeHealth::Stopped);
    backend.fail_down = true;
    let replacement = DevRuntimePlan::derive(plan_input_generation(
        temp.path(),
        DevSourceProvider::Http,
        DevOAuthProfile::None,
        "0000000000000002",
    ))
    .unwrap();
    let candidate_artifacts = replacement
        .artifacts
        .compose_file
        .parent()
        .unwrap()
        .to_path_buf();
    let error = DevRuntimeController::new(backend)
        .start(&replacement, true)
        .unwrap_err();
    assert_eq!(error.category, DevFailureCategory::DockerUnavailable);
    assert!(plan.paths.root.exists());
    assert!(old_artifacts.exists());
    assert!(!candidate_artifacts.exists());
}

#[test]
fn terminal_errors_include_stable_public_category_code() {
    let error = DevRuntimeError::new(
        DevFailureCategory::PortCollision,
        "port is occupied",
        "select another port",
    );
    assert_eq!(
        error.to_string(),
        "[registryctl.dev.port_collision] port is occupied; remediation: select another port"
    );
}

#[test]
fn bound_plan_loader_is_read_only_and_rebinds_exact_request_body() {
    fn snapshot(root: &Path) -> BTreeSet<(String, Vec<u8>)> {
        fn collect(root: &Path, directory: &Path, out: &mut BTreeSet<(String, Vec<u8>)>) {
            for entry in fs::read_dir(directory).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                if entry.file_type().unwrap().is_dir() {
                    collect(root, &path, out);
                } else {
                    out.insert((
                        path.strip_prefix(root)
                            .unwrap()
                            .to_string_lossy()
                            .into_owned(),
                        fs::read(path).unwrap(),
                    ));
                }
            }
        }
        let mut files = BTreeSet::new();
        collect(root, root, &mut files);
        files
    }

    let temp = tempfile::tempdir().unwrap();
    let plan = DevRuntimePlan::derive(plan_input(
        temp.path(),
        DevSourceProvider::Http,
        DevOAuthProfile::None,
    ))
    .unwrap();
    let mut controller = DevRuntimeController::new(FakeBackend::default());
    controller.start(&plan, true).unwrap();
    let before = snapshot(&plan.paths.root);

    let loaded = load_bound_dev_runtime_plan(temp.path(), "local").unwrap();
    assert_eq!(loaded.request_digest, plan.request_digest);
    assert_eq!(
        loaded.evidence_request_command(),
        plan.evidence_request_command()
    );
    assert_eq!(snapshot(&plan.paths.root), before);

    fs::write(&plan.paths.request_body, br#"{"subject":"tampered"}"#).unwrap();
    let error = load_bound_dev_runtime_plan(temp.path(), "local").unwrap_err();
    assert_eq!(error.category, DevFailureCategory::ProjectBinding);
}

#[test]
fn doctor_distinguishes_missing_docker_from_an_unavailable_daemon() {
    for (report, expected) in [
        (
            DevDoctorReport {
                docker_installed: false,
                daemon_available: false,
                compose_supported: false,
            },
            DevFailureCategory::DockerMissing,
        ),
        (
            DevDoctorReport {
                docker_installed: true,
                daemon_available: false,
                compose_supported: false,
            },
            DevFailureCategory::DockerUnavailable,
        ),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let plan = DevRuntimePlan::derive(plan_input(
            temp.path(),
            DevSourceProvider::Http,
            DevOAuthProfile::None,
        ))
        .unwrap();
        let backend = FakeBackend {
            doctor_report: Some(report),
            ..FakeBackend::default()
        };
        let error = DevRuntimeController::new(backend)
            .start(&plan, true)
            .unwrap_err();
        assert_eq!(error.category, expected);
        assert!(!plan.paths.root.exists());
        assert!(!plan.artifacts.compose_file.parent().unwrap().exists());
    }
}

#[test]
fn static_bearer_source_auth_uses_one_owner_only_locator_and_no_oauth_block() {
    let temp = tempfile::tempdir().unwrap();
    let mut input = plan_input(temp.path(), DevSourceProvider::Http, DevOAuthProfile::None);
    input.scenarios[0]
        .synthetic_source
        .as_mut()
        .unwrap()
        .source_auth = Some(SyntheticSourceAuth::StaticBearer);
    input.credentials = PreparedDevCredentialClosure::synthetic(None, true);
    let plan = DevRuntimePlan::derive(input).unwrap();
    let source = plan
        .workloads
        .iter()
        .find(|workload| workload.id == DevWorkloadId::SyntheticSource)
        .unwrap();
    assert!(source.mounts.iter().any(|mount| {
        mount.container_path == "/run/registry/synthetic-source-secrets/static-bearer"
    }));
    let mut controller = DevRuntimeController::new(FakeBackend::default());
    controller.start(&plan, true).unwrap();
    let source_plan: serde_json::Value =
        serde_json::from_slice(&fs::read(&plan.paths.synthetic_source_plan).unwrap()).unwrap();
    assert_eq!(source_plan["source_auth"]["type"], "static_bearer");
    assert_eq!(
        source_plan["source_auth"]["secret"]["file"],
        "static-bearer"
    );
    assert!(source_plan.get("oauth").is_none());
}

#[test]
fn down_refuses_tampered_project_binding_before_backend_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let plan = DevRuntimePlan::derive(plan_input(
        temp.path(),
        DevSourceProvider::Http,
        DevOAuthProfile::None,
    ))
    .unwrap();
    let mut controller = DevRuntimeController::new(FakeBackend::default());
    controller.start(&plan, true).unwrap();

    let mut state: serde_json::Value =
        serde_json::from_slice(&fs::read(&plan.paths.state_file).unwrap()).unwrap();
    state["binding"]["project"] = serde_json::json!("different-project");
    fs::write(&plan.paths.state_file, serde_json::to_vec(&state).unwrap()).unwrap();
    let error = controller.down(&plan).unwrap_err();
    assert_eq!(error.category, DevFailureCategory::ProjectBinding);
    let backend = controller.into_backend();
    assert_eq!(backend.down_calls, 0);
    assert!(plan.paths.root.exists());
}

#[test]
fn down_refuses_tampered_generated_root_before_backend_or_filesystem_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let plan = DevRuntimePlan::derive(plan_input(
        temp.path(),
        DevSourceProvider::Http,
        DevOAuthProfile::None,
    ))
    .unwrap();
    let mut controller = DevRuntimeController::new(FakeBackend::default());
    controller.start(&plan, true).unwrap();
    let unrelated = fs::canonicalize(temp.path())
        .unwrap()
        .join(".registry-stack/build");
    assert!(unrelated.exists());
    let mut state: serde_json::Value =
        serde_json::from_slice(&fs::read(&plan.paths.state_file).unwrap()).unwrap();
    state["generated_artifact_root"] = serde_json::json!(unrelated);
    fs::write(&plan.paths.state_file, serde_json::to_vec(&state).unwrap()).unwrap();

    let error = controller.down(&plan).unwrap_err();
    assert_eq!(error.category, DevFailureCategory::ProjectBinding);
    assert_eq!(controller.into_backend().down_calls, 0);
    assert!(plan.paths.root.exists());
    assert!(unrelated.exists());
    assert!(plan.artifacts.compose_file.parent().unwrap().exists());
}

#[test]
fn lifecycle_requires_exact_plan_for_use_but_down_remains_available_by_binding_identity() {
    for (field, value) in [
        (
            "plan_digest",
            serde_json::json!(format!("sha256:{}", "0".repeat(64))),
        ),
        ("source_mode", serde_json::json!("operator_bound")),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let plan = DevRuntimePlan::derive(plan_input(
            temp.path(),
            DevSourceProvider::Http,
            DevOAuthProfile::None,
        ))
        .unwrap();
        let mut controller = DevRuntimeController::new(FakeBackend::default());
        controller.start(&plan, true).unwrap();
        let mut state: serde_json::Value =
            serde_json::from_slice(&fs::read(&plan.paths.state_file).unwrap()).unwrap();
        state[field] = value;
        fs::write(&plan.paths.state_file, serde_json::to_vec(&state).unwrap()).unwrap();
        let error = controller.status(&plan).unwrap_err();
        assert_eq!(error.category, DevFailureCategory::ProjectBinding);
        controller.down(&plan).unwrap();
        assert_eq!(controller.into_backend().down_calls, 1);
        assert!(!plan.paths.root.exists());
    }
}

#[cfg(unix)]
#[test]
fn lifecycle_refuses_runtime_state_with_group_or_other_permissions() {
    use std::os::unix::fs::PermissionsExt as _;

    let temp = tempfile::tempdir().unwrap();
    let plan = DevRuntimePlan::derive(plan_input(
        temp.path(),
        DevSourceProvider::Http,
        DevOAuthProfile::None,
    ))
    .unwrap();
    let mut controller = DevRuntimeController::new(FakeBackend::default());
    controller.start(&plan, true).unwrap();
    fs::set_permissions(&plan.paths.state_file, fs::Permissions::from_mode(0o640)).unwrap();
    let error = controller.status(&plan).unwrap_err();
    assert_eq!(error.category, DevFailureCategory::ProjectBinding);
}

#[cfg(unix)]
#[test]
fn planning_refuses_a_symlinked_runtime_ancestor() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let input = plan_input(temp.path(), DevSourceProvider::Http, DevOAuthProfile::None);
    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path(), temp.path().join(".registry-stack/dev")).unwrap();
    let error = DevRuntimePlan::derive(input).unwrap_err();
    assert_eq!(error.category, DevFailureCategory::ProjectBinding);
}
