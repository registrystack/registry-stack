// SPDX-License-Identifier: Apache-2.0
//! Disposable credentials for the closed local-development runtime.
//!
//! The authoring compiler consumes only [`DevCredentialPublicProjection`].
//! Secret values stay in [`PreparedDevCredentialClosure`] until a lane-scoped
//! signing callback or owner-only materialization explicitly consumes them.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer as _, SigningKey};
use registry_platform_authcommon::{fingerprint_api_key, validate_api_key_entropy};
use registry_platform_config::ProductAcceptanceLaneV1;
use registry_platform_crypto::PublicJwk;
use zeroize::Zeroizing;

const DEV_SECRET_ROOT: &str = "/run/registry/dev-secrets";
const DEV_PUBLIC_ROOT: &str = "/run/registry/dev-public";
const SYNTHETIC_SECRET_ROOT: &str = "/run/registry/synthetic-source-secrets";
const DEV_WORKLOAD_ISSUER: &str = "http://registry-notary:8081";
const DEV_WORKLOAD_JWKS_URL: &str = "http://registry-notary:8081/.well-known/evidence/jwks.json";
const DEV_WORKLOAD_KID: &str = "registryctl-local-workload";
const DEV_WORKLOAD_CLIENT: &str = "registryctl-local-notary";
const DEV_WORKLOAD_AUDIENCE: &str = "registry-relay";
const DEV_WORKLOAD_SCOPE: &str = "registry:consult:public-works-verification";
const DEV_WORKLOAD_LIFETIME_SECONDS: u64 = 10 * 365 * 24 * 60 * 60;

const RELAY_PUBLIC_AUDIT_ENV: &str = "REGISTRY_RELAY_AUDIT_HASH_SECRET";
const RELAY_CONSULTATION_AUDIT_ENV: &str = "REGISTRY_RELAY_AUDIT_HASH_SECRET";
const RELAY_PSEUDONYM_ENV: &str = "REGISTRY_RELAY_AUDIT_PSEUDONYM_EPOCH_1";
const RELAY_DATABASE_ENV: &str = "REGISTRY_RELAY_CONSULTATION_DATABASE_URL";
const RELAY_MIGRATION_DATABASE_ENV: &str = "REGISTRY_RELAY_CONSULTATION_MIGRATION_DATABASE_URL";
const RELAY_MAINTENANCE_DATABASE_ENV: &str = "REGISTRY_RELAY_CONSULTATION_MAINTENANCE_DATABASE_URL";
const RELAY_READER_DATABASE_ENV: &str = "REGISTRY_RELAY_CONSULTATION_READER_DATABASE_URL";
const NOTARY_AUDIT_ENV: &str = "REGISTRY_NOTARY_AUDIT_HASH_SECRET";
const NOTARY_MIGRATION_DATABASE_ENV: &str = "REGISTRY_NOTARY_POSTGRES_MIGRATOR_URL";
const NOTARY_DATABASE_ENV: &str = "REGISTRY_NOTARY_POSTGRES_RUNTIME_URL";
const NOTARY_MAINTENANCE_DATABASE_ENV: &str = "REGISTRY_NOTARY_POSTGRES_MAINTENANCE_URL";
const NOTARY_READER_DATABASE_ENV: &str = "REGISTRY_NOTARY_POSTGRES_READER_URL";
const NOTARY_WORKLOAD_PUBLIC_JWK_ENV: &str = "REGISTRY_NOTARY_WORKLOAD_PUBLIC_JWK";

const POSTGRES_HOST: &str = "registry-postgres";
const POSTGRES_PORT: u16 = 5432;
const POSTGRES_ADMIN_ROLE: &str = "registry_stack_bootstrap";
const RELAY_DATABASE: &str = "registry_relay";
const RELAY_OWNER_ROLE: &str = "registry_relay_owner";
const RELAY_MIGRATOR_ROLE: &str = "registry_relay_migrator";
const RELAY_RUNTIME_ROLE: &str = "registry_relay_runtime";
const RELAY_MAINTENANCE_ROLE: &str = "registry_relay_maintenance";
const RELAY_READER_ROLE: &str = "registry_relay_reader";
const NOTARY_DATABASE: &str = "registry_notary";
const NOTARY_OWNER_ROLE: &str = "registry_notary_owner";
const NOTARY_MIGRATOR_ROLE: &str = "registry_notary_migrator";
const NOTARY_RUNTIME_ROLE: &str = "registry_notary_runtime";
const NOTARY_MAINTENANCE_ROLE: &str = "registry_notary_maintenance";
const NOTARY_READER_ROLE: &str = "registry_notary_reader";

const CALLER_TOKEN_FILE: &str = "caller-token";
const WORKLOAD_TOKEN_FILE: &str = "notary-relay-token";
const WORKLOAD_PUBLIC_JWK_FILE: &str = "notary-workload-public.jwk";
const WORKLOAD_JWKS_FILE: &str = "notary-workload-jwks.json";
const POSTGRES_TLS_CERTIFICATE_FILE: &str = "postgres-tls.crt";
const POSTGRES_TLS_PRIVATE_KEY_FILE: &str = "postgres-tls.key";
const RELAY_PUBLIC_TLS_CERTIFICATE_FILE: &str = "relay-public-tls.crt";
const RELAY_PUBLIC_TLS_PRIVATE_KEY_FILE: &str = "relay-public-tls.key";
const RELAY_CONSULTATION_TLS_CERTIFICATE_FILE: &str = "relay-consultation-tls.crt";
const RELAY_CONSULTATION_TLS_PRIVATE_KEY_FILE: &str = "relay-consultation-tls.key";
const NOTARY_TLS_CERTIFICATE_FILE: &str = "notary-tls.crt";
const NOTARY_TLS_PRIVATE_KEY_FILE: &str = "notary-tls.key";
const SYNTHETIC_CONTROL_TOKEN_FILE: &str = "control-token";
const SYNTHETIC_TLS_CERTIFICATE_FILE: &str = "tls.crt";
const SYNTHETIC_TLS_PRIVATE_KEY_FILE: &str = "tls.key";
const SYNTHETIC_STATIC_BEARER_FILE: &str = "static-bearer";
const SYNTHETIC_OAUTH_CLIENT_ID_FILE: &str = "oauth-client-id";
const SYNTHETIC_OAUTH_CLIENT_SECRET_FILE: &str = "oauth-client-secret";

const RELAY_PUBLIC_PREPARE_ENV_FILE: &str = "relay-public-prepare.env";
const RELAY_PUBLIC_INITIALIZE_ENV_FILE: &str = "relay-public-initialize.env";
const RELAY_PUBLIC_SERVE_ENV_FILE: &str = "relay-public-serve.env";
const RELAY_CONSULTATION_PREPARE_ENV_FILE: &str = "relay-consultation-prepare.env";
const RELAY_CONSULTATION_INITIALIZE_ENV_FILE: &str = "relay-consultation-initialize.env";
const RELAY_CONSULTATION_SERVE_ENV_FILE: &str = "relay-consultation-serve.env";
const NOTARY_PREPARE_ENV_FILE: &str = "notary-prepare.env";
const NOTARY_INITIALIZE_ENV_FILE: &str = "notary-initialize.env";
const NOTARY_SERVE_ENV_FILE: &str = "notary-serve.env";
const POSTGRES_BOOTSTRAP_ENV_FILE: &str = "postgres-bootstrap.env";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DevOAuthCredentialProfile {
    Oauth2Bearer,
    Oauth2BearerNoExpiry,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) enum DevSourceCredentialProfile {
    OperatorBound,
    SyntheticUnauthenticated,
    SyntheticStaticBearer {
        relay_token_env: String,
    },
    SyntheticOAuthClientCredentials {
        profile: DevOAuthCredentialProfile,
        relay_client_id_env: String,
        relay_client_secret_env: String,
    },
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DevIssuanceCredentialRequirement {
    pub(crate) issuer: String,
    pub(crate) signing_kid: String,
    pub(crate) private_jwk_env: String,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DevCredentialRequirements {
    pub(crate) project_id: String,
    pub(crate) environment_id: String,
    pub(crate) caller_id: String,
    pub(crate) caller_fingerprint_env: String,
    pub(crate) source: DevSourceCredentialProfile,
    pub(crate) issuance: Option<DevIssuanceCredentialRequirement>,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DevCallerCredentialProjection {
    pub(crate) id: String,
    pub(crate) fingerprint_env: String,
    pub(crate) token_file: String,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DevRelayOidcProjection {
    pub(crate) issuer: String,
    pub(crate) jwks_url: String,
    pub(crate) jwks_file: String,
    pub(crate) public_jwk: String,
    pub(crate) audience: String,
    pub(crate) client_id: String,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DevNotaryRelayProjection {
    pub(crate) base_url: String,
    pub(crate) workload_client_id: String,
    pub(crate) token_file: String,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DevDatabaseCredentialProjection {
    pub(crate) root_certificate_path: String,
    pub(crate) postgres_admin_role: &'static str,
    pub(crate) relay_owner_role: &'static str,
    pub(crate) relay_migrator_role: &'static str,
    pub(crate) relay_runtime_role: &'static str,
    pub(crate) relay_maintenance_role: &'static str,
    pub(crate) relay_reader_role: &'static str,
    pub(crate) notary_owner_role: &'static str,
    pub(crate) notary_migrator_role: &'static str,
    pub(crate) notary_runtime_role: &'static str,
    pub(crate) notary_maintenance_role: &'static str,
    pub(crate) notary_reader_role: &'static str,
    pub(crate) relay_database_env: &'static str,
    pub(crate) relay_migration_database_env: &'static str,
    pub(crate) relay_maintenance_database_env: &'static str,
    pub(crate) relay_reader_database_env: &'static str,
    pub(crate) notary_database_env: &'static str,
    pub(crate) notary_migration_database_env: &'static str,
    pub(crate) notary_maintenance_database_env: &'static str,
    pub(crate) notary_reader_database_env: &'static str,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) enum DevSourceCredentialProjection {
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

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DevIssuanceCredentialProjection {
    pub(crate) issuer: String,
    pub(crate) signing_kid: String,
    pub(crate) private_jwk_env: String,
    pub(crate) public_jwk: String,
    pub(crate) public_jwk_file: String,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DevLaneSignerProjection {
    pub(crate) lane: ProductAcceptanceLaneV1,
    pub(crate) signer_id: String,
    pub(crate) kid: String,
    pub(crate) public_jwk: String,
    pub(crate) public_jwk_file: String,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DevActionCredentialLocator {
    pub(crate) container_env_file: String,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DevActionCredentialProjection {
    pub(crate) relay_public_prepare: DevActionCredentialLocator,
    pub(crate) relay_public_initialize: DevActionCredentialLocator,
    pub(crate) relay_public_serve: DevActionCredentialLocator,
    pub(crate) relay_consultation_prepare: DevActionCredentialLocator,
    pub(crate) relay_consultation_initialize: DevActionCredentialLocator,
    pub(crate) relay_consultation_serve: DevActionCredentialLocator,
    pub(crate) notary_prepare: DevActionCredentialLocator,
    pub(crate) notary_initialize: DevActionCredentialLocator,
    pub(crate) notary_serve: DevActionCredentialLocator,
    pub(crate) postgres_bootstrap: DevActionCredentialLocator,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DevCredentialPublicProjection {
    pub(crate) caller: DevCallerCredentialProjection,
    pub(crate) relay_oidc: DevRelayOidcProjection,
    pub(crate) notary_relay: DevNotaryRelayProjection,
    pub(crate) databases: DevDatabaseCredentialProjection,
    pub(crate) source: DevSourceCredentialProjection,
    pub(crate) issuance: Option<DevIssuanceCredentialProjection>,
    pub(crate) lane_signers: [DevLaneSignerProjection; 3],
    pub(crate) actions: DevActionCredentialProjection,
}

struct LaneSigningCredential {
    projection: DevLaneSignerProjection,
    private_jwk: Zeroizing<String>,
    public_jwk: String,
}

struct IssuanceCredential {
    projection: DevIssuanceCredentialProjection,
    private_jwk: Zeroizing<String>,
    public_jwk: String,
}

struct DatabaseCredentialSet {
    postgres_admin: Zeroizing<String>,
    relay_owner: Zeroizing<String>,
    relay_migrator: Zeroizing<String>,
    relay_runtime: Zeroizing<String>,
    relay_maintenance: Zeroizing<String>,
    relay_reader: Zeroizing<String>,
    notary_owner: Zeroizing<String>,
    notary_migrator: Zeroizing<String>,
    notary_runtime: Zeroizing<String>,
    notary_maintenance: Zeroizing<String>,
    notary_reader: Zeroizing<String>,
}

struct TlsCredential {
    certificate: String,
    private_key: Zeroizing<String>,
}

struct ProductTlsCredentialSet {
    relay_public: TlsCredential,
    relay_consultation: TlsCredential,
    notary: TlsCredential,
    postgres: TlsCredential,
}

enum SourceCredential {
    OperatorBound,
    SyntheticUnauthenticated {
        control_token: Zeroizing<String>,
        tls: TlsCredential,
    },
    SyntheticStaticBearer {
        bearer: Zeroizing<String>,
        control_token: Zeroizing<String>,
        tls: TlsCredential,
    },
    SyntheticOAuthClientCredentials {
        client_id: Zeroizing<String>,
        client_secret: Zeroizing<String>,
        control_token: Zeroizing<String>,
        tls: TlsCredential,
    },
}

/// A prepared disposable credential closure.
///
/// Deliberately does not implement `Debug`, `Clone`, `Serialize`, or
/// `Deserialize`. Moving the value transfers the only general owner of its
/// private material.
pub(crate) struct PreparedDevCredentialClosure {
    projection: DevCredentialPublicProjection,
    caller_token: Zeroizing<String>,
    workload_private_jwk: Zeroizing<String>,
    workload_public_jwk: String,
    workload_jwks: String,
    workload_token: Zeroizing<String>,
    relay_public_audit: Zeroizing<String>,
    relay_consultation_audit: Zeroizing<String>,
    notary_audit: Zeroizing<String>,
    relay_pseudonym: Zeroizing<String>,
    databases: DatabaseCredentialSet,
    product_tls: ProductTlsCredentialSet,
    source: SourceCredential,
    issuance: Option<IssuanceCredential>,
    lane_signers: [LaneSigningCredential; 3],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreparedDevActionCredentialFile {
    pub(crate) host_path: PathBuf,
    pub(crate) container_path: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreparedDevSourceCredentialFiles {
    pub(crate) control_token: PathBuf,
    pub(crate) tls_certificate: PathBuf,
    pub(crate) tls_private_key: PathBuf,
    pub(crate) static_bearer: Option<PathBuf>,
    pub(crate) oauth_client_id: Option<PathBuf>,
    pub(crate) oauth_client_secret: Option<PathBuf>,
}

/// Materialized paths only. This descriptor never contains credential values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreparedDevCredentialFiles {
    pub(crate) root: PathBuf,
    pub(crate) caller_token: PathBuf,
    pub(crate) workload_token: PathBuf,
    pub(crate) workload_public_jwk: PathBuf,
    pub(crate) workload_jwks: PathBuf,
    pub(crate) relay_public_prepare: PreparedDevActionCredentialFile,
    pub(crate) relay_public_initialize: PreparedDevActionCredentialFile,
    pub(crate) relay_public_serve: PreparedDevActionCredentialFile,
    pub(crate) relay_consultation_prepare: PreparedDevActionCredentialFile,
    pub(crate) relay_consultation_initialize: PreparedDevActionCredentialFile,
    pub(crate) relay_consultation_serve: PreparedDevActionCredentialFile,
    pub(crate) notary_prepare: PreparedDevActionCredentialFile,
    pub(crate) notary_initialize: PreparedDevActionCredentialFile,
    pub(crate) notary_serve: PreparedDevActionCredentialFile,
    pub(crate) postgres_bootstrap: PreparedDevActionCredentialFile,
    pub(crate) postgres_tls_certificate: PathBuf,
    pub(crate) postgres_tls_private_key: PathBuf,
    pub(crate) relay_public_tls_certificate: PathBuf,
    pub(crate) relay_public_tls_private_key: PathBuf,
    pub(crate) relay_consultation_tls_certificate: PathBuf,
    pub(crate) relay_consultation_tls_private_key: PathBuf,
    pub(crate) notary_tls_certificate: PathBuf,
    pub(crate) notary_tls_private_key: PathBuf,
    pub(crate) source: Option<PreparedDevSourceCredentialFiles>,
    pub(crate) issuance_public_jwk: Option<PathBuf>,
    pub(crate) lane_public_jwks: [PathBuf; 3],
}

impl PreparedDevCredentialClosure {
    pub(crate) fn generate(requirements: DevCredentialRequirements) -> Result<Self> {
        validate_requirements(&requirements)?;
        let caller_token = secret_token(32)?;
        validate_api_key_entropy(&caller_token)
            .map_err(|_| anyhow!("generated development caller credential failed validation"))?;
        let caller_fingerprint = fingerprint_api_key(&caller_token);

        let (workload_private_jwk, workload_public_jwk) = generate_ed25519_jwk(DEV_WORKLOAD_KID)
            .context("failed to generate the development workload identity")?;
        let workload_jwks = workload_jwks_from_private(&workload_private_jwk)
            .context("failed to project the development workload identity")?;
        let workload_token = sign_dev_workload_jwt(&workload_private_jwk)?;

        let lane_signers = [
            generate_lane_signer(
                ProductAcceptanceLaneV1::RelayPublic,
                &requirements.project_id,
                &requirements.environment_id,
            )?,
            generate_lane_signer(
                ProductAcceptanceLaneV1::RelayConsultation,
                &requirements.project_id,
                &requirements.environment_id,
            )?,
            generate_lane_signer(
                ProductAcceptanceLaneV1::Notary,
                &requirements.project_id,
                &requirements.environment_id,
            )?,
        ];
        let issuance = requirements
            .issuance
            .as_ref()
            .map(generate_issuance_credential)
            .transpose()?;
        let source = generate_source_credential(&requirements.source)?;
        let product_tls = ProductTlsCredentialSet {
            relay_public: generate_tls_credential("registry-relay-public")?,
            relay_consultation: generate_tls_credential("registry-relay-consultation")?,
            notary: generate_tls_credential("registry-notary")?,
            postgres: generate_tls_credential(POSTGRES_HOST)?,
        };
        let databases = DatabaseCredentialSet::generate()?;
        let relay_public_audit = secret_token(48)?;
        let relay_consultation_audit = secret_token(48)?;
        let notary_audit = secret_token(48)?;
        let relay_pseudonym = secret_token(48)?;

        let source_projection = source_projection(&requirements.source);
        let projection = DevCredentialPublicProjection {
            caller: DevCallerCredentialProjection {
                id: requirements.caller_id,
                fingerprint_env: requirements.caller_fingerprint_env,
                token_file: secret_container_path(CALLER_TOKEN_FILE),
            },
            relay_oidc: DevRelayOidcProjection {
                issuer: DEV_WORKLOAD_ISSUER.to_string(),
                jwks_url: DEV_WORKLOAD_JWKS_URL.to_string(),
                jwks_file: public_container_path(WORKLOAD_JWKS_FILE),
                public_jwk: workload_public_jwk.clone(),
                audience: DEV_WORKLOAD_AUDIENCE.to_string(),
                client_id: DEV_WORKLOAD_CLIENT.to_string(),
            },
            notary_relay: DevNotaryRelayProjection {
                base_url: "http://registry-relay-consultation:8080".to_string(),
                workload_client_id: DEV_WORKLOAD_CLIENT.to_string(),
                token_file: secret_container_path(WORKLOAD_TOKEN_FILE),
            },
            databases: DevDatabaseCredentialProjection {
                root_certificate_path: secret_container_path(POSTGRES_TLS_CERTIFICATE_FILE),
                postgres_admin_role: POSTGRES_ADMIN_ROLE,
                relay_owner_role: RELAY_OWNER_ROLE,
                relay_migrator_role: RELAY_MIGRATOR_ROLE,
                relay_runtime_role: RELAY_RUNTIME_ROLE,
                relay_maintenance_role: RELAY_MAINTENANCE_ROLE,
                relay_reader_role: RELAY_READER_ROLE,
                notary_owner_role: NOTARY_OWNER_ROLE,
                notary_migrator_role: NOTARY_MIGRATOR_ROLE,
                notary_runtime_role: NOTARY_RUNTIME_ROLE,
                notary_maintenance_role: NOTARY_MAINTENANCE_ROLE,
                notary_reader_role: NOTARY_READER_ROLE,
                relay_database_env: RELAY_DATABASE_ENV,
                relay_migration_database_env: RELAY_MIGRATION_DATABASE_ENV,
                relay_maintenance_database_env: RELAY_MAINTENANCE_DATABASE_ENV,
                relay_reader_database_env: RELAY_READER_DATABASE_ENV,
                notary_database_env: NOTARY_DATABASE_ENV,
                notary_migration_database_env: NOTARY_MIGRATION_DATABASE_ENV,
                notary_maintenance_database_env: NOTARY_MAINTENANCE_DATABASE_ENV,
                notary_reader_database_env: NOTARY_READER_DATABASE_ENV,
            },
            source: source_projection,
            issuance: issuance
                .as_ref()
                .map(|credential| credential.projection.clone()),
            lane_signers: lane_signers
                .each_ref()
                .map(|credential| credential.projection.clone()),
            actions: action_projection(),
        };
        let closure = Self {
            projection,
            caller_token,
            workload_private_jwk: Zeroizing::new(workload_private_jwk),
            workload_public_jwk,
            workload_jwks,
            workload_token: Zeroizing::new(workload_token),
            relay_public_audit,
            relay_consultation_audit,
            notary_audit,
            relay_pseudonym,
            databases,
            product_tls,
            source,
            issuance,
            lane_signers,
        };
        closure.validate_distinct_secrets(&caller_fingerprint)?;
        Ok(closure)
    }

    pub(crate) fn public_projection(&self) -> &DevCredentialPublicProjection {
        &self.projection
    }

    pub(crate) fn with_lane_private_jwk<T>(
        &self,
        lane: ProductAcceptanceLaneV1,
        consume: impl FnOnce(&str) -> Result<T>,
    ) -> Result<T> {
        let credential = self
            .lane_signers
            .iter()
            .find(|credential| credential.projection.lane == lane)
            .ok_or_else(|| anyhow!("development signing lane is not in the closed lane set"))?;
        consume(&credential.private_jwk)
    }

    pub(crate) fn planned_files(&self, root: &Path) -> PreparedDevCredentialFiles {
        PreparedDevCredentialFiles::for_root(root, &self.projection)
    }

    pub(crate) fn materialize_owner_only(&self, root: &Path) -> Result<PreparedDevCredentialFiles> {
        create_new_owner_only_root(root)?;
        self.materialize_into(root)
    }

    fn materialize_into(&self, root: &Path) -> Result<PreparedDevCredentialFiles> {
        let files = PreparedDevCredentialFiles::for_root(root, &self.projection);
        write_new_owner_only(&files.caller_token, self.caller_token.as_bytes())?;
        write_new_owner_only(&files.workload_token, self.workload_token.as_bytes())?;
        write_new_owner_only(
            &files.workload_public_jwk,
            self.workload_public_jwk.as_bytes(),
        )?;
        write_new_owner_only(&files.workload_jwks, self.workload_jwks.as_bytes())?;

        write_new_owner_only(
            &files.relay_public_prepare.host_path,
            env_file(&[(RELAY_PUBLIC_AUDIT_ENV, &self.relay_public_audit)]).as_bytes(),
        )?;
        write_new_owner_only(
            &files.relay_public_initialize.host_path,
            env_file(&[(RELAY_PUBLIC_AUDIT_ENV, &self.relay_public_audit)]).as_bytes(),
        )?;
        let caller_fingerprint = fingerprint_api_key(&self.caller_token);
        write_new_owner_only(
            &files.relay_public_serve.host_path,
            env_file(&[
                (RELAY_PUBLIC_AUDIT_ENV, &self.relay_public_audit),
                (&self.projection.caller.fingerprint_env, &caller_fingerprint),
            ])
            .as_bytes(),
        )?;

        let relay_owner_url = database_url(
            RELAY_OWNER_ROLE,
            &self.databases.relay_owner,
            RELAY_DATABASE,
        );
        let relay_migration_url = database_url(
            RELAY_MIGRATOR_ROLE,
            &self.databases.relay_migrator,
            RELAY_DATABASE,
        );
        let relay_runtime_url = database_url(
            RELAY_RUNTIME_ROLE,
            &self.databases.relay_runtime,
            RELAY_DATABASE,
        );
        let relay_maintenance_url = database_url(
            RELAY_MAINTENANCE_ROLE,
            &self.databases.relay_maintenance,
            RELAY_DATABASE,
        );
        let relay_reader_url = database_url(
            RELAY_READER_ROLE,
            &self.databases.relay_reader,
            RELAY_DATABASE,
        );
        write_new_owner_only(
            &files.relay_consultation_prepare.host_path,
            env_file(&[
                (RELAY_CONSULTATION_AUDIT_ENV, &self.relay_consultation_audit),
                (RELAY_DATABASE_ENV, &relay_owner_url),
                (RELAY_MIGRATION_DATABASE_ENV, &relay_migration_url),
            ])
            .as_bytes(),
        )?;
        write_new_owner_only(
            &files.relay_consultation_initialize.host_path,
            env_file(&[
                (RELAY_CONSULTATION_AUDIT_ENV, &self.relay_consultation_audit),
                (RELAY_DATABASE_ENV, &relay_runtime_url),
            ])
            .as_bytes(),
        )?;
        let mut relay_serve = vec![
            (
                RELAY_CONSULTATION_AUDIT_ENV,
                self.relay_consultation_audit.as_str(),
            ),
            (RELAY_PSEUDONYM_ENV, self.relay_pseudonym.as_str()),
            (RELAY_DATABASE_ENV, relay_runtime_url.as_str()),
            (
                RELAY_MAINTENANCE_DATABASE_ENV,
                relay_maintenance_url.as_str(),
            ),
            (RELAY_READER_DATABASE_ENV, relay_reader_url.as_str()),
        ];
        add_relay_source_env(&mut relay_serve, &self.projection.source, &self.source);
        write_new_owner_only(
            &files.relay_consultation_serve.host_path,
            env_file(&relay_serve).as_bytes(),
        )?;

        let notary_migration_url = database_url(
            NOTARY_MIGRATOR_ROLE,
            &self.databases.notary_migrator,
            NOTARY_DATABASE,
        );
        let notary_runtime_url = database_url(
            NOTARY_RUNTIME_ROLE,
            &self.databases.notary_runtime,
            NOTARY_DATABASE,
        );
        let notary_maintenance_url = database_url(
            NOTARY_MAINTENANCE_ROLE,
            &self.databases.notary_maintenance,
            NOTARY_DATABASE,
        );
        let notary_reader_url = database_url(
            NOTARY_READER_ROLE,
            &self.databases.notary_reader,
            NOTARY_DATABASE,
        );
        write_new_owner_only(
            &files.notary_prepare.host_path,
            env_file(&[
                (NOTARY_AUDIT_ENV, &self.notary_audit),
                (NOTARY_MIGRATION_DATABASE_ENV, &notary_migration_url),
            ])
            .as_bytes(),
        )?;
        write_new_owner_only(
            &files.notary_initialize.host_path,
            env_file(&[
                (NOTARY_AUDIT_ENV, &self.notary_audit),
                (NOTARY_DATABASE_ENV, &notary_runtime_url),
            ])
            .as_bytes(),
        )?;
        let mut notary_serve = vec![
            (NOTARY_AUDIT_ENV, self.notary_audit.as_str()),
            (NOTARY_DATABASE_ENV, notary_runtime_url.as_str()),
            (
                NOTARY_MAINTENANCE_DATABASE_ENV,
                notary_maintenance_url.as_str(),
            ),
            (NOTARY_READER_DATABASE_ENV, notary_reader_url.as_str()),
            (
                NOTARY_WORKLOAD_PUBLIC_JWK_ENV,
                self.workload_public_jwk.as_str(),
            ),
        ];
        if let Some(issuance) = &self.issuance {
            notary_serve.push((
                issuance.projection.private_jwk_env.as_str(),
                issuance.private_jwk.as_str(),
            ));
        }
        write_new_owner_only(
            &files.notary_serve.host_path,
            env_file(&notary_serve).as_bytes(),
        )?;

        let postgres_bootstrap = [
            ("POSTGRES_USER", POSTGRES_ADMIN_ROLE),
            ("POSTGRES_PASSWORD", self.databases.postgres_admin.as_str()),
            (
                "REGISTRY_RELAY_OWNER_PASSWORD",
                self.databases.relay_owner.as_str(),
            ),
            (
                "REGISTRY_RELAY_MIGRATOR_PASSWORD",
                self.databases.relay_migrator.as_str(),
            ),
            (
                "REGISTRY_RELAY_RUNTIME_PASSWORD",
                self.databases.relay_runtime.as_str(),
            ),
            (
                "REGISTRY_RELAY_MAINTENANCE_PASSWORD",
                self.databases.relay_maintenance.as_str(),
            ),
            (
                "REGISTRY_RELAY_READER_PASSWORD",
                self.databases.relay_reader.as_str(),
            ),
            (
                "REGISTRY_NOTARY_OWNER_PASSWORD",
                self.databases.notary_owner.as_str(),
            ),
            (
                "REGISTRY_NOTARY_MIGRATOR_PASSWORD",
                self.databases.notary_migrator.as_str(),
            ),
            (
                "REGISTRY_NOTARY_RUNTIME_PASSWORD",
                self.databases.notary_runtime.as_str(),
            ),
            (
                "REGISTRY_NOTARY_MAINTENANCE_PASSWORD",
                self.databases.notary_maintenance.as_str(),
            ),
            (
                "REGISTRY_NOTARY_READER_PASSWORD",
                self.databases.notary_reader.as_str(),
            ),
        ];
        write_new_owner_only(
            &files.postgres_bootstrap.host_path,
            env_file(&postgres_bootstrap).as_bytes(),
        )?;

        write_tls_files(
            &files.relay_public_tls_certificate,
            &files.relay_public_tls_private_key,
            &self.product_tls.relay_public,
        )?;
        write_tls_files(
            &files.relay_consultation_tls_certificate,
            &files.relay_consultation_tls_private_key,
            &self.product_tls.relay_consultation,
        )?;
        write_tls_files(
            &files.notary_tls_certificate,
            &files.notary_tls_private_key,
            &self.product_tls.notary,
        )?;
        write_tls_files(
            &files.postgres_tls_certificate,
            &files.postgres_tls_private_key,
            &self.product_tls.postgres,
        )?;

        if let Some(source_files) = &files.source {
            materialize_source(source_files, &self.source)?;
        }
        if let (Some(path), Some(issuance)) = (&files.issuance_public_jwk, &self.issuance) {
            write_new_owner_only(path, issuance.public_jwk.as_bytes())?;
        }
        for (path, signer) in files.lane_public_jwks.iter().zip(&self.lane_signers) {
            write_new_owner_only(path, signer.public_jwk.as_bytes())?;
        }
        Ok(files)
    }

    fn validate_distinct_secrets(&self, caller_fingerprint: &str) -> Result<()> {
        let mut values = Vec::new();
        values.extend([
            self.caller_token.as_str(),
            self.workload_private_jwk.as_str(),
            self.workload_token.as_str(),
            self.relay_public_audit.as_str(),
            self.relay_consultation_audit.as_str(),
            self.notary_audit.as_str(),
            self.relay_pseudonym.as_str(),
            self.product_tls.relay_public.private_key.as_str(),
            self.product_tls.relay_consultation.private_key.as_str(),
            self.product_tls.notary.private_key.as_str(),
            self.product_tls.postgres.private_key.as_str(),
        ]);
        values.extend(self.databases.values());
        values.extend(
            self.lane_signers
                .iter()
                .map(|credential| credential.private_jwk.as_str()),
        );
        if let Some(issuance) = &self.issuance {
            values.push(issuance.private_jwk.as_str());
        }
        match &self.source {
            SourceCredential::OperatorBound => {}
            SourceCredential::SyntheticUnauthenticated { control_token, tls } => {
                values.extend([control_token.as_str(), tls.private_key.as_str()]);
            }
            SourceCredential::SyntheticStaticBearer {
                bearer,
                control_token,
                tls,
            } => values.extend([
                bearer.as_str(),
                control_token.as_str(),
                tls.private_key.as_str(),
            ]),
            SourceCredential::SyntheticOAuthClientCredentials {
                client_id,
                client_secret,
                control_token,
                tls,
            } => values.extend([
                client_id.as_str(),
                client_secret.as_str(),
                control_token.as_str(),
                tls.private_key.as_str(),
            ]),
        }
        if values.iter().any(|value| value.is_empty())
            || values.contains(&caller_fingerprint)
            || values.iter().copied().collect::<BTreeSet<_>>().len() != values.len()
        {
            bail!("generated development credentials violated the closed separation invariant");
        }
        Ok(())
    }
}

impl DatabaseCredentialSet {
    fn generate() -> Result<Self> {
        Ok(Self {
            postgres_admin: secret_token(32)?,
            relay_owner: secret_token(32)?,
            relay_migrator: secret_token(32)?,
            relay_runtime: secret_token(32)?,
            relay_maintenance: secret_token(32)?,
            relay_reader: secret_token(32)?,
            notary_owner: secret_token(32)?,
            notary_migrator: secret_token(32)?,
            notary_runtime: secret_token(32)?,
            notary_maintenance: secret_token(32)?,
            notary_reader: secret_token(32)?,
        })
    }

    fn values(&self) -> [&str; 11] {
        [
            &self.postgres_admin,
            &self.relay_owner,
            &self.relay_migrator,
            &self.relay_runtime,
            &self.relay_maintenance,
            &self.relay_reader,
            &self.notary_owner,
            &self.notary_migrator,
            &self.notary_runtime,
            &self.notary_maintenance,
            &self.notary_reader,
        ]
    }
}

impl PreparedDevCredentialFiles {
    fn for_root(root: &Path, projection: &DevCredentialPublicProjection) -> Self {
        let action = |file: &'static str, locator: &DevActionCredentialLocator| {
            PreparedDevActionCredentialFile {
                host_path: root.join(file),
                container_path: locator.container_env_file.clone(),
            }
        };
        let source = (!matches!(
            projection.source,
            DevSourceCredentialProjection::OperatorBound
        ))
        .then(|| PreparedDevSourceCredentialFiles {
            control_token: root.join(SYNTHETIC_CONTROL_TOKEN_FILE),
            tls_certificate: root.join(SYNTHETIC_TLS_CERTIFICATE_FILE),
            tls_private_key: root.join(SYNTHETIC_TLS_PRIVATE_KEY_FILE),
            static_bearer: matches!(
                projection.source,
                DevSourceCredentialProjection::SyntheticStaticBearer { .. }
            )
            .then(|| root.join(SYNTHETIC_STATIC_BEARER_FILE)),
            oauth_client_id: matches!(
                projection.source,
                DevSourceCredentialProjection::SyntheticOAuthClientCredentials { .. }
            )
            .then(|| root.join(SYNTHETIC_OAUTH_CLIENT_ID_FILE)),
            oauth_client_secret: matches!(
                projection.source,
                DevSourceCredentialProjection::SyntheticOAuthClientCredentials { .. }
            )
            .then(|| root.join(SYNTHETIC_OAUTH_CLIENT_SECRET_FILE)),
        });
        Self {
            root: root.to_path_buf(),
            caller_token: root.join(CALLER_TOKEN_FILE),
            workload_token: root.join(WORKLOAD_TOKEN_FILE),
            workload_public_jwk: root.join(WORKLOAD_PUBLIC_JWK_FILE),
            workload_jwks: root.join(WORKLOAD_JWKS_FILE),
            relay_public_prepare: action(
                RELAY_PUBLIC_PREPARE_ENV_FILE,
                &projection.actions.relay_public_prepare,
            ),
            relay_public_initialize: action(
                RELAY_PUBLIC_INITIALIZE_ENV_FILE,
                &projection.actions.relay_public_initialize,
            ),
            relay_public_serve: action(
                RELAY_PUBLIC_SERVE_ENV_FILE,
                &projection.actions.relay_public_serve,
            ),
            relay_consultation_prepare: action(
                RELAY_CONSULTATION_PREPARE_ENV_FILE,
                &projection.actions.relay_consultation_prepare,
            ),
            relay_consultation_initialize: action(
                RELAY_CONSULTATION_INITIALIZE_ENV_FILE,
                &projection.actions.relay_consultation_initialize,
            ),
            relay_consultation_serve: action(
                RELAY_CONSULTATION_SERVE_ENV_FILE,
                &projection.actions.relay_consultation_serve,
            ),
            notary_prepare: action(NOTARY_PREPARE_ENV_FILE, &projection.actions.notary_prepare),
            notary_initialize: action(
                NOTARY_INITIALIZE_ENV_FILE,
                &projection.actions.notary_initialize,
            ),
            notary_serve: action(NOTARY_SERVE_ENV_FILE, &projection.actions.notary_serve),
            postgres_bootstrap: action(
                POSTGRES_BOOTSTRAP_ENV_FILE,
                &projection.actions.postgres_bootstrap,
            ),
            postgres_tls_certificate: root.join(POSTGRES_TLS_CERTIFICATE_FILE),
            postgres_tls_private_key: root.join(POSTGRES_TLS_PRIVATE_KEY_FILE),
            relay_public_tls_certificate: root.join(RELAY_PUBLIC_TLS_CERTIFICATE_FILE),
            relay_public_tls_private_key: root.join(RELAY_PUBLIC_TLS_PRIVATE_KEY_FILE),
            relay_consultation_tls_certificate: root.join(RELAY_CONSULTATION_TLS_CERTIFICATE_FILE),
            relay_consultation_tls_private_key: root.join(RELAY_CONSULTATION_TLS_PRIVATE_KEY_FILE),
            notary_tls_certificate: root.join(NOTARY_TLS_CERTIFICATE_FILE),
            notary_tls_private_key: root.join(NOTARY_TLS_PRIVATE_KEY_FILE),
            source,
            issuance_public_jwk: projection
                .issuance
                .as_ref()
                .map(|_| root.join("issuance-public.jwk")),
            lane_public_jwks: [
                root.join("relay-public-signing-public.jwk"),
                root.join("relay-consultation-signing-public.jwk"),
                root.join("notary-signing-public.jwk"),
            ],
        }
    }
}

fn validate_requirements(requirements: &DevCredentialRequirements) -> Result<()> {
    for (name, value) in [
        ("project id", requirements.project_id.as_str()),
        ("environment id", requirements.environment_id.as_str()),
        ("caller id", requirements.caller_id.as_str()),
    ] {
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            bail!("development credential {name} is outside the closed identifier grammar");
        }
    }
    validate_env_name(&requirements.caller_fingerprint_env)?;
    match &requirements.source {
        DevSourceCredentialProfile::OperatorBound
        | DevSourceCredentialProfile::SyntheticUnauthenticated => {}
        DevSourceCredentialProfile::SyntheticStaticBearer { relay_token_env } => {
            validate_env_name(relay_token_env)?;
        }
        DevSourceCredentialProfile::SyntheticOAuthClientCredentials {
            relay_client_id_env,
            relay_client_secret_env,
            ..
        } => {
            validate_env_name(relay_client_id_env)?;
            validate_env_name(relay_client_secret_env)?;
            if relay_client_id_env == relay_client_secret_env {
                bail!("development OAuth client locators must be distinct");
            }
        }
    }
    if let Some(issuance) = &requirements.issuance {
        validate_env_name(&issuance.private_jwk_env)?;
        if issuance.issuer.is_empty()
            || issuance.issuer.len() > 2048
            || issuance.issuer.chars().any(char::is_control)
        {
            bail!("development issuance issuer is outside the closed locator grammar");
        }
        if issuance.signing_kid.is_empty() || issuance.signing_kid.len() > 128 {
            bail!("development issuance signing kid is outside the closed identifier grammar");
        }
    }
    Ok(())
}

fn validate_env_name(name: &str) -> Result<()> {
    let mut bytes = name.bytes();
    if name.len() > 128
        || !bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_uppercase() || byte == b'_')
        || !bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        bail!("development credential environment locator is invalid");
    }
    Ok(())
}

fn generate_lane_signer(
    lane: ProductAcceptanceLaneV1,
    project: &str,
    environment: &str,
) -> Result<LaneSigningCredential> {
    let lane_name = lane_name(lane);
    let kid = format!("registryctl-dev-{project}-{environment}-{lane_name}");
    let (private_jwk, public_jwk) = generate_ed25519_jwk(&kid)
        .context("failed to generate a disposable development lane signer")?;
    let trust_kid = PublicJwk::parse(&public_jwk)
        .and_then(|jwk| jwk.jkt())
        .context("failed to identify a disposable development lane signer")?;
    Ok(LaneSigningCredential {
        projection: DevLaneSignerProjection {
            lane,
            signer_id: format!("development:{project}:{environment}:{lane_name}"),
            kid: trust_kid,
            public_jwk: public_jwk.clone(),
            public_jwk_file: public_container_path(match lane {
                ProductAcceptanceLaneV1::RelayPublic => "relay-public-signing-public.jwk",
                ProductAcceptanceLaneV1::RelayConsultation => {
                    "relay-consultation-signing-public.jwk"
                }
                ProductAcceptanceLaneV1::Notary => "notary-signing-public.jwk",
            }),
        },
        private_jwk: Zeroizing::new(private_jwk),
        public_jwk,
    })
}

fn generate_issuance_credential(
    requirement: &DevIssuanceCredentialRequirement,
) -> Result<IssuanceCredential> {
    let (private_jwk, public_jwk) = generate_ed25519_jwk(&requirement.signing_kid)
        .context("failed to generate disposable development issuance material")?;
    Ok(IssuanceCredential {
        projection: DevIssuanceCredentialProjection {
            issuer: requirement.issuer.clone(),
            signing_kid: requirement.signing_kid.clone(),
            private_jwk_env: requirement.private_jwk_env.clone(),
            public_jwk: public_jwk.clone(),
            public_jwk_file: public_container_path("issuance-public.jwk"),
        },
        private_jwk: Zeroizing::new(private_jwk),
        public_jwk,
    })
}

fn generate_source_credential(profile: &DevSourceCredentialProfile) -> Result<SourceCredential> {
    Ok(match profile {
        DevSourceCredentialProfile::OperatorBound => SourceCredential::OperatorBound,
        DevSourceCredentialProfile::SyntheticUnauthenticated => {
            SourceCredential::SyntheticUnauthenticated {
                control_token: secret_token(32)?,
                tls: generate_tls_credential("registry-synthetic-source")?,
            }
        }
        DevSourceCredentialProfile::SyntheticStaticBearer { .. } => {
            SourceCredential::SyntheticStaticBearer {
                bearer: secret_token(32)?,
                control_token: secret_token(32)?,
                tls: generate_tls_credential("registry-synthetic-source")?,
            }
        }
        DevSourceCredentialProfile::SyntheticOAuthClientCredentials { .. } => {
            SourceCredential::SyntheticOAuthClientCredentials {
                client_id: secret_token(24)?,
                client_secret: secret_token(32)?,
                control_token: secret_token(32)?,
                tls: generate_tls_credential("registry-synthetic-source")?,
            }
        }
    })
}

fn source_projection(profile: &DevSourceCredentialProfile) -> DevSourceCredentialProjection {
    let common = || {
        (
            synthetic_container_path(SYNTHETIC_CONTROL_TOKEN_FILE),
            synthetic_container_path(SYNTHETIC_TLS_CERTIFICATE_FILE),
            synthetic_container_path(SYNTHETIC_TLS_PRIVATE_KEY_FILE),
        )
    };
    match profile {
        DevSourceCredentialProfile::OperatorBound => DevSourceCredentialProjection::OperatorBound,
        DevSourceCredentialProfile::SyntheticUnauthenticated => {
            let (control_token_file, tls_certificate_file, tls_private_key_file) = common();
            DevSourceCredentialProjection::SyntheticUnauthenticated {
                control_token_file,
                tls_certificate_file,
                tls_private_key_file,
            }
        }
        DevSourceCredentialProfile::SyntheticStaticBearer { relay_token_env } => {
            let (control_token_file, tls_certificate_file, tls_private_key_file) = common();
            DevSourceCredentialProjection::SyntheticStaticBearer {
                relay_token_env: relay_token_env.clone(),
                source_token_file: synthetic_container_path(SYNTHETIC_STATIC_BEARER_FILE),
                control_token_file,
                tls_certificate_file,
                tls_private_key_file,
            }
        }
        DevSourceCredentialProfile::SyntheticOAuthClientCredentials {
            profile,
            relay_client_id_env,
            relay_client_secret_env,
        } => {
            let (control_token_file, tls_certificate_file, tls_private_key_file) = common();
            DevSourceCredentialProjection::SyntheticOAuthClientCredentials {
                profile: *profile,
                relay_client_id_env: relay_client_id_env.clone(),
                relay_client_secret_env: relay_client_secret_env.clone(),
                source_client_id_file: synthetic_container_path(SYNTHETIC_OAUTH_CLIENT_ID_FILE),
                source_client_secret_file: synthetic_container_path(
                    SYNTHETIC_OAUTH_CLIENT_SECRET_FILE,
                ),
                control_token_file,
                tls_certificate_file,
                tls_private_key_file,
            }
        }
    }
}

fn add_relay_source_env<'a>(
    values: &mut Vec<(&'a str, &'a str)>,
    projection: &'a DevSourceCredentialProjection,
    source: &'a SourceCredential,
) {
    match (projection, source) {
        (
            DevSourceCredentialProjection::SyntheticStaticBearer {
                relay_token_env, ..
            },
            SourceCredential::SyntheticStaticBearer { bearer, .. },
        ) => values.push((relay_token_env, bearer)),
        (
            DevSourceCredentialProjection::SyntheticOAuthClientCredentials {
                relay_client_id_env,
                relay_client_secret_env,
                ..
            },
            SourceCredential::SyntheticOAuthClientCredentials {
                client_id,
                client_secret,
                ..
            },
        ) => {
            values.push((relay_client_id_env, client_id));
            values.push((relay_client_secret_env, client_secret));
        }
        _ => {}
    }
}

fn materialize_source(
    files: &PreparedDevSourceCredentialFiles,
    source: &SourceCredential,
) -> Result<()> {
    let (control_token, tls) = match source {
        SourceCredential::OperatorBound => {
            bail!("operator-bound source cannot materialize development credentials")
        }
        SourceCredential::SyntheticUnauthenticated { control_token, tls }
        | SourceCredential::SyntheticStaticBearer {
            control_token, tls, ..
        }
        | SourceCredential::SyntheticOAuthClientCredentials {
            control_token, tls, ..
        } => (control_token, tls),
    };
    write_new_owner_only(&files.control_token, control_token.as_bytes())?;
    write_tls_files(&files.tls_certificate, &files.tls_private_key, tls)?;
    if let (Some(path), SourceCredential::SyntheticStaticBearer { bearer, .. }) =
        (&files.static_bearer, source)
    {
        write_new_owner_only(path, bearer.as_bytes())?;
    }
    if let (
        Some(client_id_path),
        Some(client_secret_path),
        SourceCredential::SyntheticOAuthClientCredentials {
            client_id,
            client_secret,
            ..
        },
    ) = (&files.oauth_client_id, &files.oauth_client_secret, source)
    {
        write_new_owner_only(client_id_path, client_id.as_bytes())?;
        write_new_owner_only(client_secret_path, client_secret.as_bytes())?;
    }
    Ok(())
}

fn action_projection() -> DevActionCredentialProjection {
    let locator = |file| DevActionCredentialLocator {
        container_env_file: secret_container_path(file),
    };
    DevActionCredentialProjection {
        relay_public_prepare: locator(RELAY_PUBLIC_PREPARE_ENV_FILE),
        relay_public_initialize: locator(RELAY_PUBLIC_INITIALIZE_ENV_FILE),
        relay_public_serve: locator(RELAY_PUBLIC_SERVE_ENV_FILE),
        relay_consultation_prepare: locator(RELAY_CONSULTATION_PREPARE_ENV_FILE),
        relay_consultation_initialize: locator(RELAY_CONSULTATION_INITIALIZE_ENV_FILE),
        relay_consultation_serve: locator(RELAY_CONSULTATION_SERVE_ENV_FILE),
        notary_prepare: locator(NOTARY_PREPARE_ENV_FILE),
        notary_initialize: locator(NOTARY_INITIALIZE_ENV_FILE),
        notary_serve: locator(NOTARY_SERVE_ENV_FILE),
        postgres_bootstrap: locator(POSTGRES_BOOTSTRAP_ENV_FILE),
    }
}

fn secret_token(bytes: usize) -> Result<Zeroizing<String>> {
    random_token(bytes)
        .map(Zeroizing::new)
        .map_err(|_| anyhow!("failed to generate a disposable development credential"))
}

fn random_token(bytes: usize) -> Result<String> {
    let mut random = Zeroizing::new(vec![0_u8; bytes]);
    getrandom::fill(random.as_mut_slice()).map_err(|_| anyhow!("random generation failed"))?;
    Ok(URL_SAFE_NO_PAD.encode(random.as_slice()))
}

fn generate_ed25519_jwk(kid: &str) -> Result<(String, String)> {
    let mut secret = Zeroizing::new([0_u8; 32]);
    getrandom::fill(secret.as_mut_slice()).map_err(|_| anyhow!("random generation failed"))?;
    let signing_key = SigningKey::from_bytes(&secret);
    let x = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().as_bytes());
    let d = URL_SAFE_NO_PAD.encode(secret.as_slice());
    let private = serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "d": d,
        "x": x.clone(),
        "alg": "EdDSA",
        "kid": kid,
    });
    let public = serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": x,
        "alg": "EdDSA",
        "kid": kid,
        "use": "sig",
    });
    Ok((
        serde_json::to_string(&private).context("failed to render private signing JWK")?,
        serde_json::to_string(&public).context("failed to render public signing JWK")?,
    ))
}

fn workload_jwks_from_private(private_jwk: &str) -> Result<String> {
    let private: serde_json::Value =
        serde_json::from_str(private_jwk).context("failed to parse workload private JWK")?;
    let x = private["x"]
        .as_str()
        .ok_or_else(|| anyhow!("workload private JWK is missing its public member"))?;
    serde_json::to_string_pretty(&serde_json::json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x,
            "alg": "EdDSA",
            "kid": DEV_WORKLOAD_KID,
            "use": "sig",
        }]
    }))
    .context("failed to render workload JWKS")
}

fn sign_ed25519_compact_jwt(
    private_jwk: &str,
    header: &serde_json::Value,
    claims: &serde_json::Value,
) -> Result<String> {
    let private: serde_json::Value =
        serde_json::from_str(private_jwk).context("failed to parse private signing JWK")?;
    let encoded_secret = private["d"]
        .as_str()
        .ok_or_else(|| anyhow!("private signing JWK is missing its private member"))?;
    let secret = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(encoded_secret)
            .context("private signing JWK contains an invalid private member")?,
    );
    let secret: [u8; 32] = secret
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("private signing JWK has the wrong private member length"))?;
    let secret = Zeroizing::new(secret);
    let signing_key = SigningKey::from_bytes(&secret);
    let header =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).context("failed to render JWT header")?);
    let claims =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).context("failed to render JWT claims")?);
    let signing_input = format!("{header}.{claims}");
    let signature = signing_key.sign(signing_input.as_bytes());
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

fn generate_self_signed_tls_identity(subject_alt_names: Vec<String>) -> Result<(String, String)> {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(subject_alt_names)
            .context("failed to generate the local TLS identity")?;
    Ok((
        pem_block("CERTIFICATE", cert.der().as_ref()),
        pem_block("PRIVATE KEY", &key_pair.serialize_der()),
    ))
}

fn pem_block(label: &str, der: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;

    let encoded = STANDARD.encode(der);
    let body = encoded
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).expect("base64 is ASCII"))
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
}

fn sign_dev_workload_jwt(private_jwk: &str) -> Result<String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow!("system clock cannot issue a development workload credential"))?
        .as_secs();
    let header = serde_json::json!({
        "alg": "EdDSA",
        "kid": DEV_WORKLOAD_KID,
        "typ": "at+jwt",
    });
    let claims = serde_json::json!({
        "iss": DEV_WORKLOAD_ISSUER,
        "sub": DEV_WORKLOAD_CLIENT,
        "aud": DEV_WORKLOAD_AUDIENCE,
        "client_id": DEV_WORKLOAD_CLIENT,
        "azp": DEV_WORKLOAD_CLIENT,
        "scope": DEV_WORKLOAD_SCOPE,
        "iat": now,
        "nbf": now.saturating_sub(1),
        "exp": now + DEV_WORKLOAD_LIFETIME_SECONDS,
        "jti": secret_token(16)?.as_str(),
    });
    sign_ed25519_compact_jwt(private_jwk, &header, &claims)
        .context("failed to issue the development workload credential")
}

fn generate_tls_credential(service_name: &str) -> Result<TlsCredential> {
    let (certificate, private_key) =
        generate_self_signed_tls_identity(vec![service_name.to_string()])
            .context("failed to generate a disposable development TLS identity")?;
    Ok(TlsCredential {
        certificate,
        private_key: Zeroizing::new(private_key),
    })
}

fn database_url(role: &str, password: &str, database: &str) -> Zeroizing<String> {
    Zeroizing::new(format!(
        "postgresql://{role}:{password}@{POSTGRES_HOST}:{POSTGRES_PORT}/{database}?sslmode=verify-full"
    ))
}

fn env_file(values: &[(&str, &str)]) -> Zeroizing<String> {
    let mut rendered = Zeroizing::new(String::new());
    for (name, value) in values {
        rendered.push_str(name);
        rendered.push('=');
        rendered.push_str(value);
        rendered.push('\n');
    }
    rendered
}

fn write_tls_files(certificate: &Path, private_key: &Path, tls: &TlsCredential) -> Result<()> {
    write_new_owner_only(certificate, tls.certificate.as_bytes())?;
    write_new_owner_only(private_key, tls.private_key.as_bytes())
}

fn create_new_owner_only_root(root: &Path) -> Result<()> {
    let parent = root
        .parent()
        .ok_or_else(|| anyhow!("development credential root requires a parent directory"))?;
    let parent_metadata = fs::symlink_metadata(parent)
        .context("failed to inspect the development credential root parent")?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        bail!("development credential root parent must be a real directory");
    }
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(root)
        .context("failed to create a fresh development credential root")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))
            .context("failed to protect the development credential root")?;
    }
    Ok(())
}

fn write_new_owner_only(path: &Path, contents: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    }
    let mut file = options
        .open(path)
        .context("failed to create a development credential file")?;
    file.write_all(contents)
        .context("failed to materialize a development credential file")?;
    file.sync_all()
        .context("failed to persist a development credential file")?;
    set_owner_only(&file)
}

fn set_owner_only(file: &File) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .context("failed to protect a development credential file")?;
    }
    Ok(())
}

fn secret_container_path(file: &str) -> String {
    format!("{DEV_SECRET_ROOT}/{file}")
}

fn public_container_path(file: &str) -> String {
    format!("{DEV_PUBLIC_ROOT}/{file}")
}

fn synthetic_container_path(file: &str) -> String {
    format!("{SYNTHETIC_SECRET_ROOT}/{file}")
}

fn lane_name(lane: ProductAcceptanceLaneV1) -> &'static str {
    match lane {
        ProductAcceptanceLaneV1::RelayPublic => "relay-public",
        ProductAcceptanceLaneV1::RelayConsultation => "relay-consultation",
        ProductAcceptanceLaneV1::Notary => "notary",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
    use registry_platform_crypto::{PrivateJwk, PublicJwk};
    use serde_json::Value;
    use tempfile::tempdir;

    use super::*;

    fn requirements(source: DevSourceCredentialProfile) -> DevCredentialRequirements {
        DevCredentialRequirements {
            project_id: "example-project".to_string(),
            environment_id: "local".to_string(),
            caller_id: "local-developer".to_string(),
            caller_fingerprint_env: "REGISTRY_DEV_CALLER_FINGERPRINT".to_string(),
            source,
            issuance: Some(DevIssuanceCredentialRequirement {
                issuer: "http://127.0.0.1:4243".to_string(),
                signing_kid: "registry-dev-issuer".to_string(),
                private_jwk_env: "REGISTRY_NOTARY_ISSUER_JWK".to_string(),
            }),
        }
    }

    fn oauth_profile(profile: DevOAuthCredentialProfile) -> DevSourceCredentialProfile {
        DevSourceCredentialProfile::SyntheticOAuthClientCredentials {
            profile,
            relay_client_id_env: "REGISTRY_SOURCE_OAUTH_CLIENT_ID".to_string(),
            relay_client_secret_env: "REGISTRY_SOURCE_OAUTH_CLIENT_SECRET".to_string(),
        }
    }

    #[test]
    fn materialization_is_owner_only_and_projection_locators_match() {
        let parent = tempdir().unwrap();
        let closure = PreparedDevCredentialClosure::generate(requirements(oauth_profile(
            DevOAuthCredentialProfile::Oauth2Bearer,
        )))
        .unwrap();
        let projection = closure.public_projection().clone();
        let root = parent.path().join("credentials");
        let planned = closure.planned_files(&root);
        let files = closure.materialize_owner_only(&root).unwrap();
        assert_eq!(files, planned);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&root).unwrap().permissions().mode() & 0o777,
                0o700
            );
            for entry in fs::read_dir(&root).unwrap() {
                let entry = entry.unwrap();
                assert_eq!(
                    entry.metadata().unwrap().permissions().mode() & 0o777,
                    0o600,
                    "{}",
                    entry.path().display()
                );
            }
        }
        assert_eq!(
            projection.caller.token_file,
            secret_container_path(files.caller_token.file_name().unwrap().to_str().unwrap())
        );
        assert_eq!(
            projection.relay_oidc.jwks_file,
            public_container_path(files.workload_jwks.file_name().unwrap().to_str().unwrap())
        );
        assert_eq!(
            projection.notary_relay.token_file,
            secret_container_path(files.workload_token.file_name().unwrap().to_str().unwrap())
        );
        assert_eq!(
            projection
                .actions
                .relay_consultation_serve
                .container_env_file,
            files.relay_consultation_serve.container_path
        );
        let projected_actions = [
            &projection.actions.relay_public_prepare,
            &projection.actions.relay_public_initialize,
            &projection.actions.relay_public_serve,
            &projection.actions.relay_consultation_prepare,
            &projection.actions.relay_consultation_initialize,
            &projection.actions.relay_consultation_serve,
            &projection.actions.notary_prepare,
            &projection.actions.notary_initialize,
            &projection.actions.notary_serve,
            &projection.actions.postgres_bootstrap,
        ];
        let prepared_actions = [
            &files.relay_public_prepare,
            &files.relay_public_initialize,
            &files.relay_public_serve,
            &files.relay_consultation_prepare,
            &files.relay_consultation_initialize,
            &files.relay_consultation_serve,
            &files.notary_prepare,
            &files.notary_initialize,
            &files.notary_serve,
            &files.postgres_bootstrap,
        ];
        for (projected, prepared) in projected_actions.into_iter().zip(prepared_actions) {
            assert_eq!(projected.container_env_file, prepared.container_path);
            assert_eq!(
                projected.container_env_file,
                secret_container_path(prepared.host_path.file_name().unwrap().to_str().unwrap())
            );
        }
        assert_eq!(
            projection.databases.root_certificate_path,
            secret_container_path(
                files
                    .postgres_tls_certificate
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
            )
        );
        for (projected, prepared) in projection.lane_signers.iter().zip(&files.lane_public_jwks) {
            assert_eq!(
                projected.public_jwk_file,
                public_container_path(prepared.file_name().unwrap().to_str().unwrap())
            );
        }
        assert_eq!(
            projection.issuance.as_ref().unwrap().public_jwk_file,
            public_container_path(
                files
                    .issuance_public_jwk
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
            )
        );
        let DevSourceCredentialProjection::SyntheticOAuthClientCredentials {
            source_client_id_file,
            source_client_secret_file,
            control_token_file,
            tls_certificate_file,
            tls_private_key_file,
            ..
        } = projection.source
        else {
            panic!("OAuth projection");
        };
        let source_files = files.source.unwrap();
        assert_eq!(
            control_token_file,
            synthetic_container_path(
                source_files
                    .control_token
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
            )
        );
        assert_eq!(
            tls_certificate_file,
            synthetic_container_path(
                source_files
                    .tls_certificate
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
            )
        );
        assert_eq!(
            tls_private_key_file,
            synthetic_container_path(
                source_files
                    .tls_private_key
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
            )
        );
        assert_eq!(
            source_client_id_file,
            synthetic_container_path(
                source_files
                    .oauth_client_id
                    .unwrap()
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
            )
        );
        assert_eq!(
            source_client_secret_file,
            synthetic_container_path(
                source_files
                    .oauth_client_secret
                    .unwrap()
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
            )
        );
    }

    #[test]
    fn materialization_never_overwrites_or_follows_a_symlink() {
        let parent = tempdir().unwrap();
        let closure = PreparedDevCredentialClosure::generate(requirements(
            DevSourceCredentialProfile::OperatorBound,
        ))
        .unwrap();
        let existing = parent.path().join("existing");
        fs::create_dir(&existing).unwrap();
        fs::write(existing.join("keep"), "unchanged").unwrap();
        assert!(closure.materialize_owner_only(&existing).is_err());
        assert_eq!(
            fs::read_to_string(existing.join("keep")).unwrap(),
            "unchanged"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let target = parent.path().join("target");
            fs::create_dir(&target).unwrap();
            let link = parent.path().join("link");
            symlink(&target, &link).unwrap();
            assert!(closure.materialize_owner_only(&link).is_err());
            assert!(fs::read_dir(target).unwrap().next().is_none());

            let nested_target = parent.path().join("nested-target");
            fs::create_dir(&nested_target).unwrap();
            let nested_link = parent.path().join("nested-link");
            symlink(&nested_target, &nested_link).unwrap();
            assert!(closure
                .materialize_owner_only(&nested_link.join("credentials"))
                .is_err());
            assert!(fs::read_dir(nested_target).unwrap().next().is_none());
        }
    }

    #[test]
    fn caller_workload_and_jwks_are_internally_consistent() {
        let closure = PreparedDevCredentialClosure::generate(requirements(
            DevSourceCredentialProfile::SyntheticUnauthenticated,
        ))
        .unwrap();
        let parent = tempdir().unwrap();
        let files = closure
            .materialize_owner_only(&parent.path().join("credentials"))
            .unwrap();
        let serve_env = fs::read_to_string(files.relay_public_serve.host_path).unwrap();
        assert!(serve_env.contains(&format!(
            "{}={}",
            closure.projection.caller.fingerprint_env,
            fingerprint_api_key(&closure.caller_token)
        )));
        let public: Value = serde_json::from_str(&closure.workload_public_jwk).unwrap();
        let jwks: Value = serde_json::from_str(&closure.workload_jwks).unwrap();
        assert_eq!(jwks["keys"][0], public);

        let segments = closure.workload_token.split('.').collect::<Vec<_>>();
        assert_eq!(segments.len(), 3);
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[0]).unwrap()).unwrap();
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[1]).unwrap()).unwrap();
        assert_eq!(header["kid"], DEV_WORKLOAD_KID);
        assert_eq!(claims["iss"], closure.projection.relay_oidc.issuer);
        assert_eq!(claims["aud"], closure.projection.relay_oidc.audience);
        assert_eq!(claims["azp"], closure.projection.relay_oidc.client_id);

        let x: [u8; 32] = URL_SAFE_NO_PAD
            .decode(public["x"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let signature =
            Signature::from_slice(&URL_SAFE_NO_PAD.decode(segments[2]).unwrap()).unwrap();
        VerifyingKey::from_bytes(&x)
            .unwrap()
            .verify(
                format!("{}.{}", segments[0], segments[1]).as_bytes(),
                &signature,
            )
            .unwrap();
    }

    #[test]
    fn source_profiles_are_closed_and_operator_bound_gets_no_source_secret() {
        let profiles = [
            DevSourceCredentialProfile::OperatorBound,
            DevSourceCredentialProfile::SyntheticUnauthenticated,
            DevSourceCredentialProfile::SyntheticStaticBearer {
                relay_token_env: "REGISTRY_SOURCE_TOKEN".to_string(),
            },
            oauth_profile(DevOAuthCredentialProfile::Oauth2Bearer),
            oauth_profile(DevOAuthCredentialProfile::Oauth2BearerNoExpiry),
        ];
        for profile in profiles {
            let closure =
                PreparedDevCredentialClosure::generate(requirements(profile.clone())).unwrap();
            let parent = tempdir().unwrap();
            let files = closure
                .materialize_owner_only(&parent.path().join("credentials"))
                .unwrap();
            match profile {
                DevSourceCredentialProfile::OperatorBound => {
                    assert!(matches!(
                        closure.projection.source,
                        DevSourceCredentialProjection::OperatorBound
                    ));
                    assert!(files.source.is_none());
                }
                DevSourceCredentialProfile::SyntheticUnauthenticated => {
                    let files = files.source.unwrap();
                    assert!(files.static_bearer.is_none());
                    assert!(files.oauth_client_id.is_none());
                }
                DevSourceCredentialProfile::SyntheticStaticBearer { .. } => {
                    let files = files.source.unwrap();
                    assert!(files.static_bearer.unwrap().is_file());
                    assert!(files.oauth_client_id.is_none());
                }
                DevSourceCredentialProfile::SyntheticOAuthClientCredentials { .. } => {
                    let files = files.source.unwrap();
                    assert!(files.static_bearer.is_none());
                    assert!(files.oauth_client_id.unwrap().is_file());
                    assert!(files.oauth_client_secret.unwrap().is_file());
                }
            }
        }
    }

    #[test]
    fn action_files_hold_only_action_specific_authority() {
        let parent = tempdir().unwrap();
        let closure = PreparedDevCredentialClosure::generate(requirements(oauth_profile(
            DevOAuthCredentialProfile::Oauth2Bearer,
        )))
        .unwrap();
        let files = closure
            .materialize_owner_only(&parent.path().join("credentials"))
            .unwrap();
        let parse = |path: &Path| -> BTreeMap<String, String> {
            fs::read_to_string(path)
                .unwrap()
                .lines()
                .map(|line| {
                    let (name, value) = line.split_once('=').unwrap();
                    (name.to_string(), value.to_string())
                })
                .collect()
        };
        let relay_prepare = parse(&files.relay_consultation_prepare.host_path);
        let relay_initialize = parse(&files.relay_consultation_initialize.host_path);
        let relay_serve = parse(&files.relay_consultation_serve.host_path);
        assert!(relay_prepare.contains_key(RELAY_MIGRATION_DATABASE_ENV));
        assert!(!relay_prepare.contains_key(RELAY_MAINTENANCE_DATABASE_ENV));
        assert!(!relay_prepare.contains_key("REGISTRY_SOURCE_OAUTH_CLIENT_SECRET"));
        assert!(!relay_initialize.contains_key(RELAY_MIGRATION_DATABASE_ENV));
        assert!(!relay_initialize.contains_key(RELAY_MAINTENANCE_DATABASE_ENV));
        assert!(relay_serve.contains_key(RELAY_MAINTENANCE_DATABASE_ENV));
        assert!(relay_serve.contains_key("REGISTRY_SOURCE_OAUTH_CLIENT_SECRET"));

        let notary_prepare = parse(&files.notary_prepare.host_path);
        let notary_initialize = parse(&files.notary_initialize.host_path);
        let notary_serve = parse(&files.notary_serve.host_path);
        assert!(notary_prepare.contains_key(NOTARY_MIGRATION_DATABASE_ENV));
        assert!(!notary_prepare.contains_key("REGISTRY_NOTARY_ISSUER_JWK"));
        assert!(!notary_initialize.contains_key(NOTARY_MIGRATION_DATABASE_ENV));
        assert!(!notary_initialize.contains_key("REGISTRY_NOTARY_ISSUER_JWK"));
        assert!(notary_serve.contains_key("REGISTRY_NOTARY_ISSUER_JWK"));
    }

    #[test]
    fn signing_lanes_are_distinct_and_private_material_is_callback_scoped() {
        let closure = PreparedDevCredentialClosure::generate(requirements(
            DevSourceCredentialProfile::OperatorBound,
        ))
        .unwrap();
        let mut public_thumbprints = BTreeSet::new();
        let mut private_values = BTreeSet::new();
        for lane in [
            ProductAcceptanceLaneV1::RelayPublic,
            ProductAcceptanceLaneV1::RelayConsultation,
            ProductAcceptanceLaneV1::Notary,
        ] {
            closure
                .with_lane_private_jwk(lane, |text| {
                    let private = PrivateJwk::parse(text)?;
                    let public = private.public();
                    private_values.insert(text.to_string());
                    public_thumbprints.insert(public.jkt()?);
                    Ok(())
                })
                .unwrap();
        }
        assert_eq!(private_values.len(), 3);
        assert_eq!(public_thumbprints.len(), 3);
        assert_eq!(
            closure
                .projection
                .lane_signers
                .iter()
                .map(|signer| signer.kid.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            3
        );
        for signer in &closure.projection.lane_signers {
            assert_eq!(
                signer.kid,
                PublicJwk::parse(&signer.public_jwk).unwrap().jkt().unwrap()
            );
        }
    }

    #[test]
    fn all_generated_secret_values_are_distinct() {
        let closure = PreparedDevCredentialClosure::generate(requirements(oauth_profile(
            DevOAuthCredentialProfile::Oauth2Bearer,
        )))
        .unwrap();
        let fingerprint = fingerprint_api_key(&closure.caller_token);
        closure.validate_distinct_secrets(&fingerprint).unwrap();
    }

    #[test]
    fn descriptors_and_errors_are_value_free() {
        let parent = tempdir().unwrap();
        let closure = PreparedDevCredentialClosure::generate(requirements(
            DevSourceCredentialProfile::SyntheticStaticBearer {
                relay_token_env: "REGISTRY_SOURCE_TOKEN".to_string(),
            },
        ))
        .unwrap();
        let sentinel = closure.caller_token.to_string();
        let files = closure
            .materialize_owner_only(&parent.path().join("credentials"))
            .unwrap();
        let debug = format!("{files:?}");
        assert!(!debug.contains(&sentinel));
        let error = closure
            .materialize_owner_only(&files.root)
            .unwrap_err()
            .to_string();
        assert!(!error.contains(&sentinel));
    }

    #[test]
    fn public_jwk_files_never_contain_private_members() {
        let parent = tempdir().unwrap();
        let closure = PreparedDevCredentialClosure::generate(requirements(
            DevSourceCredentialProfile::OperatorBound,
        ))
        .unwrap();
        let files = closure
            .materialize_owner_only(&parent.path().join("credentials"))
            .unwrap();
        for path in files
            .lane_public_jwks
            .iter()
            .chain(files.issuance_public_jwk.iter())
            .chain([&files.workload_public_jwk])
        {
            PublicJwk::parse(&fs::read_to_string(path).unwrap()).unwrap();
            assert!(!fs::read_to_string(path).unwrap().contains("\"d\""));
        }
    }
}
