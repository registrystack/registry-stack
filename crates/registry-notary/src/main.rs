// SPDX-License-Identifier: Apache-2.0
//! Registry Notary process entrypoint.

mod boot;
mod commands;
mod config_loader;
mod doctor;
mod env_file;
mod explain_config;
mod logging;
mod serve;

use boot::*;
use commands::*;
use config_loader::*;
use doctor::*;
use env_file::*;
use explain_config::*;
use logging::*;

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::extract::MatchedPath;
use axum::http::Request;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use clap::{Args as ClapArgs, Parser, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use registry_config_report::{
    ConfigValueClassification, LiveApplyClass, ReportStatus, RequiredEnvStatus, TrustedValueSource,
    PLATFORM_CONTEXT_CONSTRAINTS_CONTRACT_V1,
    PLATFORM_CONTEXT_CONSTRAINTS_HASH_MATERIAL_CONTRACT_V1,
};
use registry_notary_core::deployment::{
    evaluate_gates, gate_severity_for_profile, DeploymentFindingStatus, DeploymentProfile,
    EvaluatedFinding, FINDING_SOURCE_BINDING_NO_MATCHING_POLICY,
};
use registry_notary_core::{
    deprecated_config_fields, ConfigAuditEvent, ConfigTrustConfig, EvidenceAuthMode,
    Oauth2ClientCredentialsSourceAuthConfig, RegistryNotaryAdminListenerMode,
    SigningKeyProviderConfig, SourceAuthConfig, SourceConnectorKind,
    StandaloneRegistryNotaryConfig,
};
use registry_notary_server::{
    compile_notary_runtime_with_provenance, notary_router_from_runtime,
    notary_routers_from_runtime, openapi_document, EvidenceIssuerRegistry,
};
use registry_platform_config::{
    expand_config_env_vars, reject_deprecated_config_fields, verify_config_bundle,
    ConfigBundleError, VerifiedConfigBundle,
};
use registry_platform_crypto::{LocalJwkSigner, PrivateJwk, PublicJwk};
use registry_platform_httputil::{url as httputil_url, FetchUrlPolicy};
use registry_platform_ops::{
    antirollback_key_from_verified_bundle, audit_shipping_target, bundle_verify_rejection_result,
    evaluate_ack_health, load_unsigned_break_glass_or_pin,
    persist_bundle_acceptance as persist_config_bundle_acceptance,
    posture_safe_runtime_config_hash, resolve_bundle_state_action, verify_bundle_state_read_only,
    AuditSinkKind, BundleStateAction, BundleStateRequest, ConfigBootError, ConfigOverrideMode,
    ConfigProvenance, ConfigSource, PendingBundleAcceptance, UnsignedConfigSelection,
};
use serde_json::{json, Value};
use serve::{serve_listener, ServeLimits};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;
use ulid::Ulid;

const DEFAULT_LOG_FILTER: &str = "info";
const NOTARY_CONFIG_SCHEMA_VERSION: &str = "registry.notary.config.v1";

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

#[derive(Debug, Parser)]
#[command(author, version, about = "Run the standalone Registry Notary")]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
    /// YAML config path.
    #[arg(short, long, env = "REGISTRY_NOTARY_CONFIG", global = true)]
    config: Option<PathBuf>,
    /// Dotenv-style file to load before config validation resolves env vars.
    #[arg(long, env = "REGISTRY_NOTARY_ENV_FILE", global = true)]
    env_file: Option<PathBuf>,
    /// Override already-set process env vars with values from --env-file.
    #[arg(long, global = true)]
    env_file_override: bool,
    /// Override server.bind after config load.
    #[arg(long, env = "REGISTRY_NOTARY_BIND", global = true)]
    bind: Option<SocketAddr>,
    /// Initialize signed config anti-rollback state on first boot.
    #[arg(long, global = true)]
    initialize_state: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the Registry Notary OpenAPI document as JSON.
    Openapi,
    /// Validate config, env-backed secrets, source auth, and VC wiring.
    Doctor {
        /// Fetch OAuth source tokens and run live reachability checks.
        #[arg(long)]
        live: bool,
        /// Target id for record-level live probes. Output is redacted.
        #[arg(long)]
        target_id: Option<String>,
        /// Override the lookup field used by DCI idtype-value probes.
        #[arg(long)]
        target_id_type: Option<String>,
        /// Validate local VC issuing setup. This does not print credentials.
        #[arg(long)]
        issue_demo_vc: bool,
        /// Print resolved config with no secret values in text output.
        /// For JSON output, use `explain-config --format json`.
        #[arg(long)]
        show_expanded_config: bool,
        /// Review-only deployment profile override for JSON doctor findings.
        #[arg(
            long,
            value_parser = ["local", "hosted_lab", "production", "evidence_grade"]
        )]
        profile: Option<String>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = DoctorOutputFormat::Text)]
        format: DoctorOutputFormat,
    },
    /// Print resolved config and required env vars.
    ExplainConfig {
        /// Output format.
        #[arg(long, value_enum, default_value_t = ExplainConfigOutputFormat::Json)]
        format: ExplainConfigOutputFormat,
    },
    /// Verify governed runtime configuration bundles without applying them.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Generate starter files.
    Init {
        #[command(subcommand)]
        template: InitCommand,
    },
    /// Generate or hash a Registry Notary API key.
    HashApiKey {
        /// Read the API key from stdin.
        #[arg(long)]
        stdin: bool,
        /// Print only sha256:<hex>, useful for automation.
        #[arg(long)]
        hash_only: bool,
        /// Also print the plaintext key when generating one.
        #[arg(long)]
        print_secret: bool,
        /// API key to hash. If omitted, a random key is generated.
        api_key: Option<String>,
    },
    /// Generate a demo Ed25519 issuer JWK for local VC smoke tests.
    DemoIssuerKey {
        /// Key id to embed in the generated JWK.
        #[arg(long, default_value = "did:web:localhost#registry-notary-demo")]
        kid: String,
    },
    /// Probe the local HTTP health endpoint and exit non-zero when unhealthy.
    Healthcheck {
        /// Health endpoint URL.
        #[arg(
            long,
            env = "REGISTRY_NOTARY_HEALTHCHECK_URL",
            default_value = "http://127.0.0.1:8080/healthz"
        )]
        url: String,
        /// Request timeout in milliseconds.
        #[arg(
            long,
            env = "REGISTRY_NOTARY_HEALTHCHECK_TIMEOUT_MS",
            default_value_t = 5000,
            value_parser = clap::value_parser!(u64).range(1..)
        )]
        timeout_ms: u64,
    },
    /// Run the internal CEL worker line protocol.
    #[cfg(feature = "registry-notary-cel")]
    #[command(hide = true)]
    CelWorker,
    /// Print machine-readable build metadata and compiled capabilities.
    BuildInfo,
    /// Print a lightweight JSON schema for top-level config discovery.
    Schema,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Verify a Registry Config Bundle directory against local trust and state.
    VerifyBundle(ConfigVerifyBundleArgs),
}

#[derive(Debug, Clone, ClapArgs)]
struct ConfigVerifyBundleArgs {
    /// Bundle directory containing manifest.json, manifest.sig.json, and config files.
    #[arg(long)]
    bundle_dir: PathBuf,
    /// Trust anchor JSON path.
    #[arg(long)]
    anchor_path: PathBuf,
    /// Anti-rollback state JSON path.
    #[arg(long)]
    state_path: PathBuf,
}

#[derive(Debug, Subcommand)]
enum InitCommand {
    /// Generate a generic DCI source starter skeleton.
    Dci {
        /// Output directory for generated files.
        #[arg(long, default_value = ".")]
        output: PathBuf,
        /// DCI upstream base URL.
        #[arg(long, default_value = "https://dci.example.test")]
        base_url: String,
        /// DCI OAuth token URL.
        #[arg(long, default_value = "https://dci.example.test/oauth2/client/token")]
        token_url: String,
        /// DCI lookup field used by idtype-value queries.
        #[arg(long, default_value = "SUBJECT_ID")]
        lookup_field: String,
        /// Claim id to generate.
        #[arg(long, default_value = "dci-record-exists")]
        claim_id: String,
        /// Human-readable claim title.
        #[arg(long, default_value = "DCI record exists")]
        claim_title: String,
        /// Include local VC issuer wiring and a generated issuer key.
        #[arg(long)]
        demo_issuer: bool,
        /// Create .env.local with generated local secrets.
        #[arg(long, alias = "write-local-secrets")]
        with_env_file: bool,
        /// Overwrite generated files if they already exist.
        #[arg(long)]
        force: bool,
        /// Print generated local secrets to stdout.
        #[arg(long)]
        print_secrets: bool,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Args::parse()).await {
        Ok(code) => code,
        Err(err) => {
            eprintln!("ERROR {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let env_report = load_env_file_arg(args.env_file.as_deref(), args.env_file_override)?;
    match args.command {
        None => {
            let config_path = required_config_path(args.config.as_deref())?;
            run_server(config_path, args.bind, args.initialize_state).await?;
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Openapi) => {
            println!("{}", serde_json::to_string_pretty(&openapi_document())?);
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Doctor {
            live,
            target_id,
            target_id_type,
            issue_demo_vc,
            show_expanded_config,
            profile,
            format,
        }) => {
            let config_path = required_config_path(args.config.as_deref())?;
            let ok = doctor(
                config_path,
                &env_report,
                args.bind,
                DoctorOptions {
                    live,
                    target_id,
                    target_id_type,
                    issue_demo_vc,
                    show_expanded_config,
                    profile_override: profile,
                    format,
                },
            )
            .await?;
            Ok(if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
        Some(Command::ExplainConfig { format }) => {
            let config_path = required_config_path(args.config.as_deref())?;
            explain_config(config_path, &env_report, args.bind, format)?;
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Config {
            command: ConfigCommand::VerifyBundle(verify_args),
        }) => {
            config_verify_bundle(verify_args).await?;
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Init { template }) => {
            match template {
                InitCommand::Dci {
                    output,
                    base_url,
                    token_url,
                    lookup_field,
                    claim_id,
                    claim_title,
                    demo_issuer,
                    with_env_file,
                    force,
                    print_secrets,
                } => init_dci(
                    &output,
                    InitDciOptions {
                        base_url,
                        token_url,
                        lookup_field,
                        claim_id,
                        claim_title,
                        demo_issuer,
                        with_env_file,
                        force,
                        print_secrets,
                    },
                )?,
            }
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::HashApiKey {
            stdin,
            hash_only,
            print_secret,
            api_key,
        }) => {
            hash_api_key(stdin, hash_only, print_secret, api_key)?;
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::DemoIssuerKey { kid }) => {
            println!("{}", demo_issuer_jwk(&kid)?);
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Healthcheck { url, timeout_ms }) => {
            run_healthcheck(&url, Duration::from_millis(timeout_ms)).await?;
            println!("registry-notary healthcheck ok");
            Ok(ExitCode::SUCCESS)
        }
        #[cfg(feature = "registry-notary-cel")]
        Some(Command::CelWorker) => {
            registry_notary_server::cel_worker::run_stdio_worker();
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::BuildInfo) => {
            println!("{}", serde_json::to_string_pretty(&build_info())?);
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Schema) => {
            println!("{}", serde_json::to_string_pretty(&lightweight_schema())?);
            Ok(ExitCode::SUCCESS)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use axum_test::TestServer;
    use registry_platform_config::{
        sha256_uri, ConfigBundleFile, ConfigBundleManifest, ConfigBundleSignature,
        ConfigBundleSignatureEnvelope, ConfigTrustAnchor, ConfigTrustAnchorSigner,
    };
    use registry_platform_crypto::{canonicalize_json, sign, PrivateJwk};

    static ENV_LOCK: Mutex<()> = Mutex::new(());
    const CONFIG_BUNDLE_PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;

    #[derive(Clone, Default)]
    struct DoctorLiveState {
        token_called: Arc<AtomicBool>,
        dci_called: Arc<AtomicBool>,
    }

    struct SignedBundleFixture {
        bundle_dir: PathBuf,
        anchor_path: PathBuf,
        state_path: PathBuf,
        config_hash: String,
    }

    fn write_signed_notary_bundle(tmp: &tempfile::TempDir) -> SignedBundleFixture {
        let bundle_dir = tmp.path().join("bundle");
        let config_dir = bundle_dir.join("config");
        std::fs::create_dir_all(&config_dir).expect("bundle config dir");
        let config = notary_bundle_runtime_config();
        std::fs::write(config_dir.join("notary.yaml"), config.as_bytes()).expect("config writes");
        let config_hash = sha256_uri(config.as_bytes());
        let private = PrivateJwk::parse(CONFIG_BUNDLE_PRIVATE_JWK).expect("private jwk");
        let public = private.public();
        let kid = public.jkt().expect("thumbprint");
        let manifest = ConfigBundleManifest {
            schema: "registry.platform.config_bundle.v1".to_string(),
            product: "registry-notary".to_string(),
            environment: "development".to_string(),
            stream_id: "notary-loader-test".to_string(),
            instance_id: None,
            bundle_id: "notary-loader-bundle".to_string(),
            sequence: 1,
            previous_config_hash: None,
            config_hash: config_hash.clone(),
            files: vec![ConfigBundleFile {
                path: "config/notary.yaml".to_string(),
                sha256: config_hash.clone(),
            }],
            created_at: "2026-07-07T10:00:00Z".to_string(),
        };
        write_manifest_and_signature(&bundle_dir, &manifest, &private, &kid);
        let anchor = ConfigTrustAnchor {
            schema: "registry.platform.config_trust_anchor.v1".to_string(),
            product: "registry-notary".to_string(),
            environment: "development".to_string(),
            stream_id: "notary-loader-test".to_string(),
            instance_id: "notary-loader".to_string(),
            signers: vec![ConfigTrustAnchorSigner {
                kid,
                jwk: public,
                enabled: true,
            }],
        };
        let anchor_path = tmp.path().join("trust_anchor.json");
        std::fs::write(
            &anchor_path,
            serde_json::to_vec_pretty(&anchor).expect("anchor serializes"),
        )
        .expect("anchor writes");
        SignedBundleFixture {
            bundle_dir,
            anchor_path,
            state_path: tmp.path().join("antirollback.json"),
            config_hash,
        }
    }

    fn write_manifest_and_signature(
        bundle_dir: &Path,
        manifest: &ConfigBundleManifest,
        private: &PrivateJwk,
        kid: &str,
    ) {
        let manifest_value = serde_json::to_value(manifest).expect("manifest value");
        let canonical = canonicalize_json(&manifest_value).expect("canonical manifest");
        let signature = sign(&canonical, private).expect("manifest signs");
        let envelope = ConfigBundleSignatureEnvelope {
            schema: "registry.platform.config_bundle_signatures.v1".to_string(),
            signatures: vec![ConfigBundleSignature {
                kid: kid.to_string(),
                alg: "EdDSA".to_string(),
                sig: URL_SAFE_NO_PAD.encode(signature),
            }],
        };
        std::fs::write(
            bundle_dir.join("manifest.json"),
            serde_json::to_vec_pretty(manifest).expect("manifest serializes"),
        )
        .expect("manifest writes");
        std::fs::write(
            bundle_dir.join("manifest.sig.json"),
            serde_json::to_vec_pretty(&envelope).expect("signature serializes"),
        )
        .expect("signature writes");
    }

    fn notary_bundle_runtime_config() -> String {
        r#"
deployment:
  profile: local
server:
  bind: 127.0.0.1:4255
  admin_listener:
    mode: dedicated
    bind: 127.0.0.1:4256
auth:
  mode: api_key
  api_keys:
    - id: local
      fingerprint:
        provider: env
        name: TEST_NOTARY_LOADER_API_HASH
      scopes: [registry_notary:credential_issue]
audit:
  sink: stdout
  hash_secret_env: TEST_NOTARY_LOADER_AUDIT_HASH_SECRET
evidence:
  enabled: true
  signing_keys:
    issuer:
      provider: local_jwk_env
      private_jwk_env: TEST_NOTARY_LOADER_ISSUER_JWK
      alg: EdDSA
      kid: did:web:issuer.example#key-1
      status: active
"#
        .to_string()
    }

    fn notary_bootstrap_config(fixture: &SignedBundleFixture) -> String {
        format!(
            r#"{}
config_trust:
  trust_anchor_path: {}
  bundle_path: {}
  antirollback_state_path: {}
"#,
            notary_bundle_runtime_config(),
            fixture.anchor_path.display(),
            fixture.bundle_dir.display(),
            fixture.state_path.display()
        )
    }

    async fn test_oauth_token(
        State(state): State<DoctorLiveState>,
        Json(body): Json<Value>,
    ) -> Response {
        state.token_called.store(true, Ordering::SeqCst);
        if body["grant_type"] != json!("client_credentials")
            || body["client_id"] != json!("doctor-client")
            || body["client_secret"] != json!("doctor-secret")
        {
            return StatusCode::BAD_REQUEST.into_response();
        }
        Json(json!({
            "access_token": "doctor-live-token",
            "expires_in": 300,
        }))
        .into_response()
    }

    async fn test_dci_search(
        State(state): State<DoctorLiveState>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Response {
        state.dci_called.store(true, Ordering::SeqCst);
        if headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            != Some("Bearer doctor-live-token")
        {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        if headers
            .get("data-purpose")
            .and_then(|value| value.to_str().ok())
            != Some("https://registry-notary.local/purpose/doctor")
        {
            return StatusCode::BAD_REQUEST.into_response();
        }
        let query = &body["message"]["search_request"][0]["search_criteria"]["query"];
        if query["type"] != json!("SUBJECT_ID") || query["value"] != json!("secret-subject-123") {
            return StatusCode::BAD_REQUEST.into_response();
        }
        Json(json!({
            "message": {
                "search_response": [{
                    "data": {
                        "reg_records": [{
                            "id": "record-1"
                        }]
                    }
                }]
            }
        }))
        .into_response()
    }

    #[test]
    fn env_file_parses_quotes_export_and_comments() {
        let parsed = parse_env_file(
            r#"
# comment
export API_HASH=sha256:abc # inline
CLIENT_ID="client value"
CLIENT_SECRET='secret value'
"#,
        )
        .expect("env file parses");
        assert_eq!(
            parsed,
            vec![
                ("API_HASH".to_string(), "sha256:abc".to_string()),
                ("CLIENT_ID".to_string(), "client value".to_string()),
                ("CLIENT_SECRET".to_string(), "secret value".to_string()),
            ]
        );
    }

    #[test]
    fn config_env_expansion_replaces_required_and_default_values() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        std::env::set_var("RN_CONFIG_EXPAND_REQUIRED", "https://upstream.example");
        std::env::remove_var("RN_CONFIG_EXPAND_DEFAULT");

        let expanded = expand_config_env_vars(
            "base_url: ${RN_CONFIG_EXPAND_REQUIRED:?missing upstream}\noptional: ${RN_CONFIG_EXPAND_DEFAULT:-fallback}\n",
        )
        .expect("config expands");

        assert!(expanded.contains("base_url: \"https://upstream.example\""));
        assert!(expanded.contains("optional: \"fallback\""));
        std::env::remove_var("RN_CONFIG_EXPAND_REQUIRED");
    }

    #[test]
    fn config_env_expansion_rejects_missing_required_values() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        std::env::remove_var("RN_CONFIG_EXPAND_MISSING");

        let err = expand_config_env_vars("${RN_CONFIG_EXPAND_MISSING:?missing configured URL}")
            .expect_err("missing env var fails");

        assert!(err.to_string().contains("missing configured URL"));
    }

    #[test]
    fn config_env_expansion_rejects_invalid_variable_names() {
        let err =
            expand_config_env_vars("${NOT-A-VALID-NAME:-fallback}").expect_err("invalid var fails");

        assert!(err.to_string().contains("invalid env var name"));
    }

    #[test]
    fn signed_bundle_server_config_loads_with_pending_acceptance() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let fixture = write_signed_notary_bundle(&tmp);
        let config_path = tmp.path().join("bootstrap.yaml");
        std::fs::write(&config_path, notary_bootstrap_config(&fixture)).expect("bootstrap writes");

        let loaded = load_server_config(&config_path, true).expect("signed bundle config loads");

        assert_eq!(loaded.config_source, ConfigSource::SignedBundleFile);
        let provenance = loaded.config_provenance.expect("provenance");
        assert_eq!(provenance.source, ConfigSource::SignedBundleFile);
        assert_eq!(provenance.internal_config_hash, fixture.config_hash);
        let acceptance = loaded
            .pending_bundle_acceptance
            .expect("pending acceptance");
        assert_eq!(acceptance.source, ConfigSource::SignedBundleFile);
        assert_eq!(
            acceptance.bundle_id.as_deref(),
            Some("notary-loader-bundle")
        );
        assert_eq!(acceptance.sequence, Some(1));
        assert_eq!(acceptance.config_hash, fixture.config_hash);
        assert!(matches!(
            acceptance.state_action,
            BundleStateAction::Initialize
        ));
    }

    #[test]
    fn boot_bundle_acceptance_audit_failure_aborts_before_antirollback_persist() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let state_path = tmp.path().join("antirollback.json");
        let acceptance = PendingBundleAcceptance {
            state_path: state_path.clone(),
            key: registry_platform_ops::AntiRollbackKey {
                product: "registry-notary".to_string(),
                instance_id: "notary-loader".to_string(),
                environment: "development".to_string(),
                stream_id: "notary-loader-test".to_string(),
            },
            source: ConfigSource::SignedBundleFile,
            bundle_id: Some("notary-loader-bundle".to_string()),
            bundle_manifest_hash: Some(
                "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                    .to_string(),
            ),
            sequence: Some(1),
            config_hash: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                .to_string(),
            previous_config_hash: None,
            previous_hash_matched: None,
            signer_kids: vec!["kid-1".to_string()],
            break_glass: false,
            state_action: BundleStateAction::Initialize,
            override_pin: None,
            override_path: None,
        };
        let audit_result: Result<(), Box<dyn std::error::Error>> =
            Err(Box::new(std::io::Error::other("boot audit write failed")));

        let result = persist_after_successful_boot_audit(&acceptance, audit_result);

        assert!(result.is_err());
        let err = registry_platform_ops::FileAntiRollbackStore::new(&state_path)
            .load(&acceptance.key)
            .expect_err("state remains absent");
        assert_eq!(
            err,
            registry_platform_ops::AntiRollbackStoreError::MissingState
        );
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn boot_listener_bind_failure_aborts_before_antirollback_persist() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        std::env::set_var("TEST_NOTARY_LOADER_API_HASH", sha256_hash("api-token"));
        std::env::set_var(
            "TEST_NOTARY_LOADER_AUDIT_HASH_SECRET",
            "registry-notary-loader-audit-secret-32-bytes",
        );
        std::env::set_var(
            "TEST_NOTARY_LOADER_ISSUER_JWK",
            demo_issuer_jwk("did:web:issuer.example#key-1").expect("issuer key generates"),
        );
        let tmp = tempfile::tempdir().expect("tempdir");
        let fixture = write_signed_notary_bundle(&tmp);
        let config_path = tmp.path().join("bootstrap.yaml");
        std::fs::write(&config_path, notary_bootstrap_config(&fixture)).expect("bootstrap writes");
        let held_listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("test listener binds");
        let held_addr = held_listener
            .local_addr()
            .expect("test listener exposes local addr");

        let error = run_server(&config_path, Some(held_addr), true)
            .await
            .expect_err("occupied listener rejects startup");

        assert!(
            error.to_string().contains("Address already in use"),
            "unexpected error: {error}"
        );
        let key = registry_platform_ops::AntiRollbackKey {
            product: "registry-notary".to_string(),
            instance_id: String::new(),
            environment: "development".to_string(),
            stream_id: "notary-loader-test".to_string(),
        };
        let err = registry_platform_ops::FileAntiRollbackStore::new(&fixture.state_path)
            .load(&key)
            .expect_err("state remains absent");
        assert_eq!(
            err,
            registry_platform_ops::AntiRollbackStoreError::MissingState
        );

        drop(held_listener);
        std::env::remove_var("TEST_NOTARY_LOADER_API_HASH");
        std::env::remove_var("TEST_NOTARY_LOADER_AUDIT_HASH_SECRET");
        std::env::remove_var("TEST_NOTARY_LOADER_ISSUER_JWK");
    }

    #[test]
    fn default_log_filter_is_plain_info() {
        assert_eq!(default_log_filter(), "info");
        assert!(!default_log_filter().contains("debug"));
    }

    #[test]
    fn log_format_env_accepts_text_and_json() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        std::env::remove_var("REGISTRY_NOTARY_LOG_FORMAT");
        assert_eq!(
            log_format_from_env().expect("default is text"),
            LogFormat::Text
        );

        std::env::set_var("REGISTRY_NOTARY_LOG_FORMAT", "json");
        assert_eq!(
            log_format_from_env().expect("json is accepted"),
            LogFormat::Json
        );

        std::env::set_var("REGISTRY_NOTARY_LOG_FORMAT", "text");
        assert_eq!(
            log_format_from_env().expect("text is accepted"),
            LogFormat::Text
        );

        std::env::set_var("REGISTRY_NOTARY_LOG_FORMAT", "pretty");
        let err = log_format_from_env().expect_err("unknown format fails");
        assert!(err.contains("text"));
        assert!(err.contains("json"));

        std::env::remove_var("REGISTRY_NOTARY_LOG_FORMAT");
    }

    #[test]
    fn scalar_admin_listener_shape_names_accepted_modes() {
        let value = parse_config_value(
            r#"
server:
  admin_listener: shared_with_public
"#,
        )
        .expect("config shape parses");
        let err = validate_admin_listener_shape(&value)
            .expect_err("legacy scalar admin listener shape is rejected");

        let message = err.to_string();
        assert!(message.contains("server.admin_listener.mode"));
        assert!(message.contains("disabled"));
        assert!(message.contains("dedicated"));
        assert!(message.contains("shared_with_public"));
    }

    #[test]
    fn deprecated_config_fields_name_replacements_and_removed_cors_credentials() {
        for (raw, expected) in [
            (
                "auth:\n  oidc:\n    jwks_uri: https://id.example.gov/keys\n",
                "auth.oidc.jwks_url",
            ),
            (
                "auth:\n  oidc:\n    leeway_seconds: 60\n",
                "auth.oidc.leeway",
            ),
            (
                "auth:\n  oidc:\n    allowed_typ:\n      - JWT\n",
                "auth.oidc.allowed_token_types",
            ),
            (
                "server:\n  cors:\n    allow_credentials: true\n",
                "always disables credentialed CORS",
            ),
            ("audit:\n  max_size_bytes: 10485760\n", "audit.max_size_mb"),
        ] {
            let value = parse_config_value(raw).expect("deprecated-field fixture parses");
            let err = reject_deprecated_config_fields(&value, &deprecated_config_fields())
                .expect_err("deprecated field is rejected before deserialization");

            assert!(err.to_string().contains(expected), "unexpected: {err}");
        }
    }

    #[test]
    fn absent_admin_listener_block_requests_restore_key_warning() {
        let config: StandaloneRegistryNotaryConfig = serde_norway::from_str(
            r#"
server:
  bind: 127.0.0.1:0
auth:
  mode: api_key
  api_keys:
    - id: local
      fingerprint:
        provider: env
        name: TEST_ADMIN_WARNING_API_HASH
      scopes: [registry_notary:credential_issue]
audit:
  sink: stdout
evidence:
  enabled: true
  signing_keys:
    issuer:
      provider: local_jwk_env
      private_jwk_env: TEST_ADMIN_WARNING_ISSUER_JWK
      alg: EdDSA
      kid: did:web:issuer.example#key-1
      status: active
  credential_profiles:
    civil-status:
      format: application/dc+sd-jwt
      issuer: did:web:issuer.example
      signing_key: issuer
      vct: https://issuer.example/credentials/civil-status
"#,
        )
        .expect("config parses");

        assert!(admin_listener_default_warning_needed(&config, false));
        assert!(!admin_listener_default_warning_needed(&config, true));
    }

    #[test]
    fn env_file_ignores_quotes_inside_trailing_comments() {
        let parsed = parse_env_file(
            r#"
DOUBLE="client value" # comment with "quote"
SINGLE='secret value' # comment with 'quote'
ESCAPED="client \"quoted\" value" # comment with "quote"
"#,
        )
        .expect("env file parses");
        assert_eq!(
            parsed,
            vec![
                ("DOUBLE".to_string(), "client value".to_string()),
                ("SINGLE".to_string(), "secret value".to_string()),
                ("ESCAPED".to_string(), "client \"quoted\" value".to_string()),
            ]
        );
    }

    #[test]
    fn env_file_rejects_malformed_line_with_line_number() {
        let err = parse_env_file("GOOD=value\nnot valid\n").expect_err("line 2 fails");
        assert_eq!(err.line, 2);
        assert!(err.to_string().contains("line 2"));
    }

    #[test]
    fn env_file_does_not_overwrite_by_default() {
        std::env::set_var("RN_ENV_FILE_NO_OVERWRITE_TEST", "process");
        let report = apply_env_file("RN_ENV_FILE_NO_OVERWRITE_TEST=file\n", false)
            .expect("env file applies");
        assert_eq!(
            std::env::var("RN_ENV_FILE_NO_OVERWRITE_TEST").expect("env var exists"),
            "process"
        );
        assert!(report
            .skipped_existing
            .contains("RN_ENV_FILE_NO_OVERWRITE_TEST"));
        std::env::remove_var("RN_ENV_FILE_NO_OVERWRITE_TEST");
    }

    #[test]
    fn env_file_override_replaces_existing_process_value() {
        std::env::set_var("RN_ENV_FILE_OVERRIDE_TEST", "process");
        let report =
            apply_env_file("RN_ENV_FILE_OVERRIDE_TEST=file\n", true).expect("env file applies");
        assert_eq!(
            std::env::var("RN_ENV_FILE_OVERRIDE_TEST").expect("env var exists"),
            "file"
        );
        assert!(report.loaded.contains("RN_ENV_FILE_OVERRIDE_TEST"));
        std::env::remove_var("RN_ENV_FILE_OVERRIDE_TEST");
    }

    #[test]
    fn hash_api_key_uses_runtime_sha256_shape() {
        assert_eq!(
            sha256_hash("api-token"),
            "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51"
        );
    }

    #[test]
    fn healthcheck_cli_defaults_to_container_health_endpoint() {
        let args = Args::try_parse_from(["registry-notary", "healthcheck"]).expect("args parse");
        let Some(Command::Healthcheck { url, timeout_ms }) = args.command else {
            panic!("expected healthcheck command");
        };

        assert_eq!(url, "http://127.0.0.1:8080/healthz");
        assert_eq!(timeout_ms, 5000);
    }

    #[test]
    fn healthcheck_cli_accepts_url_and_timeout_overrides() {
        let args = Args::try_parse_from([
            "registry-notary",
            "healthcheck",
            "--url",
            "http://127.0.0.1:9000/ready",
            "--timeout-ms",
            "250",
        ])
        .expect("args parse");
        let Some(Command::Healthcheck { url, timeout_ms }) = args.command else {
            panic!("expected healthcheck command");
        };

        assert_eq!(url, "http://127.0.0.1:9000/ready");
        assert_eq!(timeout_ms, 250);
    }

    #[test]
    fn healthcheck_cli_rejects_zero_timeout() {
        let err = Args::try_parse_from(["registry-notary", "healthcheck", "--timeout-ms", "0"])
            .expect_err("zero timeout is rejected");

        assert!(err.to_string().contains("invalid value"));
    }

    #[test]
    fn doctor_cli_defaults_to_text_format() {
        let args = Args::try_parse_from(["registry-notary", "doctor"]).expect("args parse");
        let Some(Command::Doctor { format, .. }) = args.command else {
            panic!("expected doctor command");
        };

        assert_eq!(format, DoctorOutputFormat::Text);
    }

    #[test]
    fn doctor_cli_accepts_json_format() {
        let args = Args::try_parse_from(["registry-notary", "doctor", "--format", "json"])
            .expect("args parse");
        let Some(Command::Doctor { format, .. }) = args.command else {
            panic!("expected doctor command");
        };

        assert_eq!(format, DoctorOutputFormat::Json);
    }

    #[test]
    fn doctor_cli_accepts_profile_override() {
        let args = Args::try_parse_from(["registry-notary", "doctor", "--profile", "production"])
            .expect("args parse");
        let Some(Command::Doctor { profile, .. }) = args.command else {
            panic!("expected doctor command");
        };

        assert_eq!(profile.as_deref(), Some("production"));
    }

    #[test]
    fn doctor_cli_rejects_unknown_format() {
        let err = Args::try_parse_from(["registry-notary", "doctor", "--format", "pretty"])
            .expect_err("unknown doctor format is rejected");

        assert!(err.to_string().contains("text"));
        assert!(err.to_string().contains("json"));
    }

    #[test]
    fn build_info_cli_parses() {
        let args = Args::try_parse_from(["registry-notary", "build-info"]).expect("args parse");
        assert!(matches!(args.command, Some(Command::BuildInfo)));
    }

    #[test]
    fn config_verify_bundle_cli_accepts_bundle_flags() {
        let args = Args::try_parse_from([
            "registry-notary",
            "config",
            "verify-bundle",
            "--bundle-dir",
            "/etc/registry-notary/bundle",
            "--anchor-path",
            "/etc/registry-notary/trust_anchor.json",
            "--state-path",
            "/var/lib/registry-notary/config-state/antirollback.json",
        ])
        .expect("args parse");

        let Some(Command::Config {
            command: ConfigCommand::VerifyBundle(command),
        }) = args.command
        else {
            panic!("expected config verify-bundle command");
        };
        assert_eq!(
            command.bundle_dir,
            PathBuf::from("/etc/registry-notary/bundle")
        );
        assert_eq!(
            command.anchor_path,
            PathBuf::from("/etc/registry-notary/trust_anchor.json")
        );
        assert_eq!(
            command.state_path,
            PathBuf::from("/var/lib/registry-notary/config-state/antirollback.json")
        );
    }

    #[test]
    fn config_verify_bundle_cli_requires_state_path() {
        let err = Args::try_parse_from([
            "registry-notary",
            "config",
            "verify-bundle",
            "--bundle-dir",
            "/etc/registry-notary/bundle",
            "--anchor-path",
            "/etc/registry-notary/trust_anchor.json",
        ])
        .expect_err("missing state-path is rejected");

        assert!(err.to_string().contains("--state-path"));
    }

    #[test]
    fn config_apply_bundle_cli_is_removed() {
        let err = Args::try_parse_from(["registry-notary", "config", "apply-bundle"])
            .expect_err("apply-bundle is no longer a supported config subcommand");

        assert!(
            err.to_string().contains("unrecognized subcommand"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn build_info_reports_compiled_pkcs11_capability() {
        let info = build_info();
        assert_eq!(info["package"], "registry-notary");
        assert_eq!(
            info["capabilities"]["signing_providers"]["pkcs11"],
            json!(cfg!(feature = "pkcs11"))
        );
        let features = info["build_features"]
            .as_array()
            .expect("build_features is an array");
        assert_eq!(
            features.iter().any(|feature| feature == "pkcs11"),
            cfg!(feature = "pkcs11")
        );
    }

    #[tokio::test]
    async fn healthcheck_succeeds_for_success_status() {
        let upstream = TestServer::builder()
            .http_transport()
            .build(Router::new().route("/healthz", get(|| async { StatusCode::OK })));
        let base_url = upstream.server_address().expect("upstream address");
        let url = format!("{}/healthz", base_url.as_str().trim_end_matches('/'));

        run_healthcheck(&url, Duration::from_secs(1))
            .await
            .expect("healthcheck succeeds");
    }

    #[tokio::test]
    async fn healthcheck_fails_for_non_success_status() {
        let upstream = TestServer::builder()
            .http_transport()
            .build(Router::new().route(
                "/healthz",
                get(|| async { StatusCode::SERVICE_UNAVAILABLE }),
            ));
        let base_url = upstream.server_address().expect("upstream address");
        let url = format!("{}/healthz", base_url.as_str().trim_end_matches('/'));

        let err = run_healthcheck(&url, Duration::from_secs(1))
            .await
            .expect_err("healthcheck fails");
        assert!(err.to_string().contains("HTTP 503"));
    }

    #[test]
    fn generated_demo_issuer_key_is_parseable() {
        let jwk = demo_issuer_jwk("did:web:localhost#demo").expect("jwk generated");
        PrivateJwk::parse(&jwk).expect("generated JWK parses");
        assert!(!format!("{jwk:?}").contains("[redacted]"));
    }

    #[test]
    fn bind_override_replaces_config_bind() {
        let mut config = doctor_live_test_config("http://127.0.0.1:1");
        config.server.bind = "127.0.0.1:8081".parse().expect("socket addr parses");

        apply_bind_override(
            &mut config,
            Some("0.0.0.0:8080".parse().expect("socket addr parses")),
        );

        assert_eq!(
            config.server.bind,
            "0.0.0.0:8080"
                .parse::<SocketAddr>()
                .expect("socket addr parses")
        );
    }

    #[tokio::test]
    async fn run_server_compiles_runtime_before_binding_listener() {
        let held_listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("test listener binds");
        let held_addr = held_listener
            .local_addr()
            .expect("test listener exposes local addr");
        let config_path = std::env::temp_dir().join(format!(
            "registry-notary-invalid-startup-{}.yaml",
            Ulid::new()
        ));
        let config = doctor_live_test_config("http://127.0.0.1:1");
        fs::write(
            &config_path,
            serde_norway::to_string(&config).expect("startup config serializes"),
        )
        .expect("invalid startup config writes");

        let error = run_server(&config_path, Some(held_addr), false)
            .await
            .expect_err("invalid runtime config fails before serving");
        let message = error.to_string();

        assert!(
            message.contains("TEST_DOCTOR_OAUTH_CLIENT_ID")
                || message.contains("TEST_DOCTOR_OAUTH_CLIENT_SECRET")
                || message.contains("audit.hash_secret_env"),
            "unexpected error: {message}"
        );
        assert!(
            !message.contains("Address already in use"),
            "server bound before compile failure: {message}"
        );

        let _ = fs::remove_file(config_path);
        drop(held_listener);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn run_server_fails_fast_when_active_signing_key_env_is_missing() {
        let _guard = ENV_LOCK.lock().expect("env lock is not poisoned");
        std::env::set_var(
            "TEST_STARTUP_API_HASH",
            "sha256:31f2999a69fa6301763a9f61eea44388a13318ce8b80a16a115a9efdb62b883b",
        );
        std::env::set_var(
            "TEST_STARTUP_AUDIT_HASH_SECRET",
            "registry-notary-startup-audit-secret-32-bytes",
        );
        std::env::remove_var("TEST_STARTUP_ISSUER_JWK");

        let held_listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("test listener binds");
        let held_addr = held_listener
            .local_addr()
            .expect("test listener exposes local addr");
        let config_path = std::env::temp_dir().join(format!(
            "registry-notary-missing-signing-env-{}.yaml",
            Ulid::new()
        ));
        fs::write(
            &config_path,
            r#"
deployment:
  profile: local
server:
  bind: 127.0.0.1:0
auth:
  mode: api_key
  api_keys:
    - id: local
      fingerprint:
        provider: env
        name: TEST_STARTUP_API_HASH
      scopes: [registry_notary:credential_issue]
audit:
  sink: stdout
  hash_secret_env: TEST_STARTUP_AUDIT_HASH_SECRET
evidence:
  enabled: true
  signing_keys:
    issuer:
      provider: local_jwk_env
      private_jwk_env: TEST_STARTUP_ISSUER_JWK
      alg: EdDSA
      kid: did:web:issuer.example#key-1
      status: active
"#,
        )
        .expect("startup config writes");

        let error = run_server(&config_path, Some(held_addr), false)
            .await
            .expect_err("missing signing key env fails before serving");
        let message = error.to_string();

        assert!(
            message.contains("signing key 'issuer' is invalid")
                && message.contains("private_jwk_env is missing or empty"),
            "unexpected error: {message}"
        );
        assert!(
            !message.contains("Address already in use"),
            "server bound before signing key validation failed: {message}"
        );

        let _ = fs::remove_file(config_path);
        drop(held_listener);
        std::env::remove_var("TEST_STARTUP_API_HASH");
        std::env::remove_var("TEST_STARTUP_AUDIT_HASH_SECRET");
    }

    #[test]
    fn bind_cli_override_wins_over_env() {
        let _guard = ENV_LOCK.lock().expect("env lock is not poisoned");
        std::env::set_var("REGISTRY_NOTARY_BIND", "0.0.0.0:8080");
        let args = Args::try_parse_from([
            "registry-notary",
            "--bind",
            "127.0.0.1:9000",
            "explain-config",
        ])
        .expect("args parse");
        std::env::remove_var("REGISTRY_NOTARY_BIND");

        assert_eq!(
            args.bind,
            Some("127.0.0.1:9000".parse().expect("socket addr parses"))
        );
    }

    #[test]
    fn env_bind_override_is_loaded_by_cli() {
        let _guard = ENV_LOCK.lock().expect("env lock is not poisoned");
        std::env::set_var("REGISTRY_NOTARY_BIND", "0.0.0.0:8080");
        let args = Args::try_parse_from(["registry-notary", "explain-config"]).expect("args parse");
        std::env::remove_var("REGISTRY_NOTARY_BIND");

        assert_eq!(
            args.bind,
            Some("0.0.0.0:8080".parse().expect("socket addr parses"))
        );
    }

    #[test]
    fn redaction_covers_pin_key_and_credential_names() {
        let mut value = json!({
            "pin": "1234",
            "password_env": "PKCS12_PASSWORD_ENV_NAME",
            "key": "plain-key",
            "credential": "raw-credential",
            "credential_env": "SOURCE_CREDENTIAL",
            "api_keys": [{
                "id": "api-key-id",
                "scopes": ["claims:read"]
            }],
            "signing_keys": {
                "active": {
                    "status": "active",
                    "public_key_id": "public-key-id"
                }
            },
            "nested": {
                "public_key": "public-material",
                "source_credential": "source-secret",
                "safe": "visible"
            }
        });

        redact_value(&mut value);

        assert_eq!(value["pin"], json!("[redacted]"));
        assert_eq!(value["password_env"], json!("[redacted]"));
        assert_eq!(value["key"], json!("[redacted]"));
        assert_eq!(value["credential"], json!("[redacted]"));
        assert_eq!(value["credential_env"], json!("[redacted]"));
        assert_eq!(value["nested"]["public_key"], json!("[redacted]"));
        assert_eq!(value["nested"]["source_credential"], json!("[redacted]"));
        assert_eq!(value["nested"]["safe"], json!("visible"));
        assert_eq!(value["api_keys"][0]["id"], json!("api-key-id"));
        assert_eq!(value["api_keys"][0]["scopes"][0], json!("claims:read"));
        assert_eq!(value["signing_keys"]["active"]["status"], json!("active"));
        assert_eq!(
            value["signing_keys"]["active"]["public_key_id"],
            json!("[redacted]")
        );
    }

    #[test]
    fn local_file_audit_sink_emits_beta_tamper_evidence_warning() {
        let mut config = doctor_live_test_config("http://127.0.0.1:1");
        config.audit.sink = "jsonl".to_string();

        let diagnostics = local_env_diagnostics(&config, &EnvFileReport::default());

        let warning = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.label.contains("local-chain-only"))
            .expect("audit file warning exists");
        assert!(warning.ok);
        assert!(warning.warning);
        assert!(warning
            .action
            .as_deref()
            .expect("warning has next action")
            .contains("off-host"));
    }

    #[test]
    fn attested_local_file_audit_sink_suppresses_beta_tamper_evidence_warning() {
        let mut config = doctor_live_test_config("http://127.0.0.1:1");
        config.audit.sink = "jsonl".to_string();
        config.deployment.evidence.audit_offhost_shipping = true;

        let diagnostics = local_env_diagnostics(&config, &EnvFileReport::default());

        assert!(
            !diagnostics
                .iter()
                .any(|diagnostic| diagnostic.label.contains("local-chain-only")),
            "declaring off-host shipping must silence the local-chain-only warning"
        );
    }

    #[test]
    fn notary_audit_shipping_reports_stdout_sink_as_shipped() {
        let mut config = doctor_live_test_config("http://127.0.0.1:1");
        config.audit.sink = "stdout".to_string();

        let shipping = notary_audit_shipping(&config);

        assert_eq!(shipping["sink_type"], "stdout");
        assert_eq!(shipping["shipping_target_configured"], true);
        assert_eq!(shipping["shipping_target"], "stdout");
        // A shipping target is declared but no ack cursor is configured.
        assert_eq!(shipping["shipping_health"], "unverified");
        assert_eq!(shipping["shipping_observed_at"], Value::Null);
    }

    #[test]
    fn notary_audit_shipping_reports_local_file_sink_without_attestation_as_unshipped() {
        let mut config = doctor_live_test_config("http://127.0.0.1:1");
        config.audit.sink = "jsonl".to_string();
        config.deployment.evidence.audit_offhost_shipping = false;

        let shipping = notary_audit_shipping(&config);

        assert_eq!(shipping["sink_type"], "file");
        assert_eq!(shipping["shipping_target_configured"], false);
        assert_eq!(shipping["shipping_target"], "none");
        // No shipping target is configured, so health is null.
        assert_eq!(shipping["shipping_health"], Value::Null);
        assert_eq!(shipping["shipping_observed_at"], Value::Null);
    }

    #[test]
    fn notary_audit_shipping_reports_attested_local_file_sink_as_declared_external() {
        let mut config = doctor_live_test_config("http://127.0.0.1:1");
        config.audit.sink = "file".to_string();
        config.deployment.evidence.audit_offhost_shipping = true;

        let shipping = notary_audit_shipping(&config);

        assert_eq!(shipping["sink_type"], "file");
        assert_eq!(shipping["shipping_target_configured"], true);
        assert_eq!(shipping["shipping_target"], "declared_external");
        // declared_external with no ack cursor: shipping is declared but unobserved.
        assert_eq!(shipping["shipping_health"], "unverified");
        assert_eq!(shipping["shipping_observed_at"], Value::Null);
    }

    #[test]
    fn notary_audit_shipping_maps_unrecognized_sink_to_unknown() {
        let mut config = doctor_live_test_config("http://127.0.0.1:1");
        config.audit.sink = "s3".to_string();

        let shipping = notary_audit_shipping(&config);

        assert_eq!(shipping["sink_type"], "unknown");
        assert_eq!(shipping["shipping_target_configured"], false);
        assert_eq!(shipping["shipping_target"], "unknown");
        assert_eq!(shipping["shipping_health"], Value::Null);
        assert_eq!(shipping["shipping_observed_at"], Value::Null);
    }

    /// Write a `registry.audit.ack_cursor.v1` cursor with `acked_at` and return
    /// its path, so doctor shipping-health tests can drive each observation.
    fn write_doctor_ack_cursor(tmp: &tempfile::TempDir, acked_at: &str) -> std::path::PathBuf {
        let path = tmp.path().join("ack-cursor.json");
        let body = format!(
            r#"{{"schema":"registry.audit.ack_cursor.v1","acked_at":"{acked_at}","last_acked_hash":"sha256:4444444444444444444444444444444444444444444444444444444444444444","writer":"test-shipper"}}"#
        );
        std::fs::write(&path, body).expect("ack cursor writes");
        path
    }

    #[test]
    fn notary_audit_shipping_reports_unverified_for_fresh_offline_cursor() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let acked_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .expect("now formats");
        let cursor = write_doctor_ack_cursor(&tmp, &acked_at);
        let mut config = doctor_live_test_config("http://127.0.0.1:1");
        config.audit.sink = "stdout".to_string();
        config.deployment.evidence.audit_ack_cursor_path = Some(cursor);

        let shipping = notary_audit_shipping(&config);

        assert_eq!(shipping["shipping_health"], "unverified");
        assert_eq!(shipping["shipping_observed_at"], acked_at);
    }

    #[test]
    fn notary_audit_shipping_reports_stale_for_old_cursor() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        // Far past the default 900s window relative to any plausible test clock.
        let cursor = write_doctor_ack_cursor(&tmp, "2026-06-04T09:59:00Z");
        let mut config = doctor_live_test_config("http://127.0.0.1:1");
        config.audit.sink = "stdout".to_string();
        config.deployment.evidence.audit_ack_cursor_path = Some(cursor);

        let shipping = notary_audit_shipping(&config);

        assert_eq!(shipping["shipping_health"], "stale");
        assert_eq!(shipping["shipping_observed_at"], "2026-06-04T09:59:00Z");
    }

    #[test]
    fn notary_audit_shipping_reports_missing_for_absent_cursor_file() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let cursor = tmp.path().join("does-not-exist.json");
        let mut config = doctor_live_test_config("http://127.0.0.1:1");
        config.audit.sink = "stdout".to_string();
        config.deployment.evidence.audit_ack_cursor_path = Some(cursor);

        let shipping = notary_audit_shipping(&config);

        assert_eq!(shipping["shipping_health"], "missing");
        assert_eq!(shipping["shipping_observed_at"], Value::Null);
    }

    #[test]
    fn notary_audit_shipping_reports_invalid_for_malformed_cursor_file() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let cursor = tmp.path().join("ack-cursor.json");
        std::fs::write(&cursor, "{ not valid json").expect("cursor writes");
        let mut config = doctor_live_test_config("http://127.0.0.1:1");
        config.audit.sink = "stdout".to_string();
        config.deployment.evidence.audit_ack_cursor_path = Some(cursor);

        let shipping = notary_audit_shipping(&config);

        assert_eq!(shipping["shipping_health"], "invalid");
        assert_eq!(shipping["shipping_observed_at"], Value::Null);
    }

    #[test]
    fn doctor_pkcs11_preflight_attempts_module_loading() {
        let _guard = ENV_LOCK.lock().expect("env lock is not poisoned");
        std::env::set_var(
            "TEST_DOCTOR_PKCS11_PUBLIC_JWK",
            r#"{"kty":"OKP","crv":"Ed25519","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:issuer.example#hsm"}"#,
        );
        std::env::set_var("TEST_DOCTOR_PKCS11_PIN", "1234");
        let mut config = doctor_live_test_config("http://127.0.0.1:1");
        config.evidence.signing_keys.insert(
            "hsm-key".to_string(),
            registry_notary_core::SigningKeyConfig {
                provider: SigningKeyProviderConfig::Pkcs11,
                alg: "EdDSA".to_string(),
                kid: "did:web:issuer.example#hsm".to_string(),
                status: registry_notary_core::SigningKeyStatus::Active,
                publish_until_unix_seconds: None,
                private_jwk_env: String::new(),
                public_jwk_env: "TEST_DOCTOR_PKCS11_PUBLIC_JWK".to_string(),
                module_path: "/definitely/missing/pkcs11.so".to_string(),
                token_label: "registry-notary".to_string(),
                pin_env: "TEST_DOCTOR_PKCS11_PIN".to_string(),
                key_label: "issuer-signing-key".to_string(),
                key_id_hex: "01ab23cd".to_string(),
                path: String::new(),
                password_env: String::new(),
            },
        );

        let diagnostic =
            pkcs11_preflight_diagnostic(&config).expect("active PKCS#11 key triggers preflight");

        assert!(!diagnostic.ok);
        assert!(diagnostic
            .label
            .contains("PKCS#11 signing preflight failed"));
        assert!(
            diagnostic.label.contains("could not load PKCS#11 module")
                || diagnostic
                    .label
                    .contains("provider 'pkcs11' is not enabled"),
            "unexpected diagnostic: {}",
            diagnostic.label
        );
        std::env::remove_var("TEST_DOCTOR_PKCS11_PUBLIC_JWK");
        std::env::remove_var("TEST_DOCTOR_PKCS11_PIN");
    }

    #[test]
    fn dci_diagnostics_skip_registry_data_api_bindings() {
        let mut config = doctor_live_test_config("http://127.0.0.1:1");
        let binding = config.evidence.claims[0]
            .source_bindings
            .get_mut("record")
            .expect("source binding exists");
        binding.connector = registry_notary_core::SourceConnectorKind::RegistryDataApi;

        let diagnostics = dci_diagnostics(&config, None);

        assert!(diagnostics.is_empty());
    }

    fn test_dci_options(demo_issuer: bool) -> InitDciOptions {
        InitDciOptions {
            base_url: "https://dci.example.test".to_string(),
            token_url: "https://dci.example.test/oauth2/client/token".to_string(),
            lookup_field: "SUBJECT_ID".to_string(),
            claim_id: "dci-record-exists".to_string(),
            claim_title: "DCI record exists".to_string(),
            demo_issuer,
            with_env_file: false,
            force: false,
            print_secrets: false,
        }
    }

    #[test]
    fn generated_dci_config_uses_explicit_dci_and_generic_oauth() {
        let yaml = dci_config_yaml(&test_dci_options(true));
        assert!(!yaml.contains("preset:"));
        assert!(yaml.contains("type: oauth2_client_credentials"));
        assert!(yaml.contains("client_id_env: DCI_CLIENT_ID"));
        assert!(yaml.contains("field: 'SUBJECT_ID'"));
        let config: StandaloneRegistryNotaryConfig =
            serde_norway::from_str(&yaml).expect("generated config parses");
        config.validate().expect("generated config validates");
        let profile = config
            .evidence
            .credential_profiles
            .get("dci_record_sd_jwt")
            .expect("demo DCI credential profile exists");
        assert_eq!(profile.holder_binding.mode, "none");
        assert!(profile.holder_binding.proof_of_possession.is_none());
    }

    #[test]
    fn lightweight_schema_exposes_top_level_config_sections() {
        let schema = lightweight_schema();
        assert_eq!(schema["additionalProperties"], json!(false));
        assert!(schema["properties"]["evidence"].is_object());
        assert!(schema["properties"]["auth"].is_object());
    }

    #[test]
    fn dci_probe_body_uses_binding_lookup_field_for_idtype_value_queries_by_default() {
        let config: StandaloneRegistryNotaryConfig =
            serde_norway::from_str(&dci_config_yaml(&test_dci_options(false)))
                .expect("generated config parses");
        let connection = config
            .evidence
            .source_connections
            .get("dci_registry")
            .expect("connection exists");
        let binding =
            first_dci_binding_for_connection(&config, "dci_registry").expect("dci binding exists");
        let body = dci_probe_body(
            &connection.effective_dci().expect("effective dci"),
            binding,
            "secret-subject-123",
            None,
        )
        .expect("body builds");
        assert_eq!(
            body["message"]["search_request"][0]["search_criteria"]["query"],
            json!({
                "type": "SUBJECT_ID",
                "value": "secret-subject-123"
            })
        );
    }

    #[test]
    fn dci_probe_body_allows_subject_id_type_override_for_idtype_value_queries() {
        let config: StandaloneRegistryNotaryConfig =
            serde_norway::from_str(&dci_config_yaml(&test_dci_options(false)))
                .expect("generated config parses");
        let connection = config
            .evidence
            .source_connections
            .get("dci_registry")
            .expect("connection exists");
        let binding =
            first_dci_binding_for_connection(&config, "dci_registry").expect("dci binding exists");
        let body = dci_probe_body(
            &connection.effective_dci().expect("effective dci"),
            binding,
            "secret-subject-123",
            Some("NATIONAL_ID"),
        )
        .expect("body builds");
        assert_eq!(
            body["message"]["search_request"][0]["search_criteria"]["query"],
            json!({
                "type": "NATIONAL_ID",
                "value": "secret-subject-123"
            })
        );
    }

    #[test]
    fn doctor_source_url_preserves_base_path_prefix() {
        let url = source_url_for_cli("https://dci.example.test/api/v1", "/registry/sync/search")
            .expect("relative DCI path builds");

        assert_eq!(
            url.as_str(),
            "https://dci.example.test/api/v1/registry/sync/search"
        );
    }

    #[test]
    fn doctor_source_url_ignores_empty_relative_path_segments() {
        let url = source_url_for_cli("https://dci.example.test/api/v1/", "registry//sync/search")
            .expect("relative DCI path builds");

        assert_eq!(
            url.as_str(),
            "https://dci.example.test/api/v1/registry/sync/search"
        );
    }

    #[test]
    fn public_jwk_diagnostic_rejects_mismatched_kid() {
        let env = format!("TEST_REGISTRY_NOTARY_PUBLIC_JWK_{}", Ulid::new());
        unsafe {
            std::env::set_var(
                &env,
                json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "11qYAYdkdABYXknkTDYUs_NflZt9-QJxBWpukhfQq8Q",
                    "alg": "EdDSA",
                    "kid": "did:web:issuer.example#wrong"
                })
                .to_string(),
            );
        }

        let diagnostic = check_public_jwk_env(
            &env,
            "hsm-key",
            "did:web:issuer.example#expected",
            "EdDSA",
            &EnvFileReport::default(),
        );
        unsafe {
            std::env::remove_var(&env);
        }

        assert!(!diagnostic.ok);
        assert!(diagnostic.label.contains("kid mismatch"));
    }

    #[test]
    fn public_jwk_diagnostic_rejects_missing_alg() {
        let env = format!("TEST_REGISTRY_NOTARY_PUBLIC_JWK_{}", Ulid::new());
        unsafe {
            std::env::set_var(
                &env,
                json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "11qYAYdkdABYXknkTDYUs_NflZt9-QJxBWpukhfQq8Q",
                    "kid": "did:web:issuer.example#key-1"
                })
                .to_string(),
            );
        }

        let diagnostic = check_public_jwk_env(
            &env,
            "hsm-key",
            "did:web:issuer.example#key-1",
            "EdDSA",
            &EnvFileReport::default(),
        );
        unsafe {
            std::env::remove_var(&env);
        }

        assert!(!diagnostic.ok);
        assert!(diagnostic.label.contains("alg mismatch"));
    }

    #[test]
    fn local_jwk_diagnostic_rejects_mismatched_alg() {
        let env = format!("TEST_REGISTRY_NOTARY_PRIVATE_JWK_{}", Ulid::new());
        unsafe {
            std::env::set_var(
                &env,
                json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "d": "2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw",
                    "x": "1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc",
                    "alg": "RS256",
                    "kid": "did:web:issuer.example#key-1"
                })
                .to_string(),
            );
        }

        let diagnostic = check_local_jwk_env(
            &env,
            "issuer-key",
            "did:web:issuer.example#key-1",
            "EdDSA",
            &EnvFileReport::default(),
        );
        unsafe {
            std::env::remove_var(&env);
        }

        assert!(!diagnostic.ok);
        assert!(
            diagnostic.label.contains("alg mismatch")
                || diagnostic.label.contains("usable local JWK")
        );
    }

    #[cfg(unix)]
    #[test]
    fn generated_secret_file_overwrite_forces_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "registry-notary-secret-permissions-{}",
            Ulid::new()
        ));
        std::fs::write(&path, "old").expect("test file is written");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("test file permissions are set");

        write_generated_file(&path, "secret", true, true).expect("secret file is overwritten");

        let mode = std::fs::metadata(&path)
            .expect("test file metadata")
            .permissions()
            .mode()
            & 0o777;
        std::fs::remove_file(&path).expect("test file is removed");
        assert_eq!(mode, 0o600);
    }

    #[tokio::test]
    async fn doctor_live_fetches_oauth_runs_dci_probe_and_redacts_subject_and_token() {
        std::env::set_var("TEST_DOCTOR_OAUTH_CLIENT_ID", "doctor-client");
        std::env::set_var("TEST_DOCTOR_OAUTH_CLIENT_SECRET", "doctor-secret");
        let state = DoctorLiveState::default();
        let upstream = TestServer::builder().http_transport().build(
            Router::new()
                .route("/oauth/token", post(test_oauth_token))
                .route("/registry/sync/search", post(test_dci_search))
                .with_state(state.clone()),
        );
        let base_url = upstream
            .server_address()
            .expect("upstream address")
            .to_string();
        let config = doctor_live_test_config(base_url.trim_end_matches('/'));
        let diagnostics = live_diagnostics(&config, Some("secret-subject-123"), None).await;

        assert!(
            state.token_called.load(Ordering::SeqCst),
            "doctor should call OAuth token endpoint"
        );
        assert!(
            state.dci_called.load(Ordering::SeqCst),
            "doctor should run DCI record probe"
        );
        assert!(
            diagnostics.iter().all(|diagnostic| diagnostic.ok),
            "expected all diagnostics ok: {diagnostics:?}"
        );
        let output = diagnostics
            .iter()
            .map(|diagnostic| {
                format!(
                    "{} {}",
                    diagnostic.label,
                    diagnostic.action.as_deref().unwrap_or_default()
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!output.contains("secret-subject-123"));
        assert!(!output.contains("doctor-live-token"));

        std::env::remove_var("TEST_DOCTOR_OAUTH_CLIENT_ID");
        std::env::remove_var("TEST_DOCTOR_OAUTH_CLIENT_SECRET");
    }

    fn doctor_live_test_config(base_url: &str) -> StandaloneRegistryNotaryConfig {
        let raw = format!(
            r#"
deployment:
  profile: local
server:
  bind: 127.0.0.1:0
auth:
  mode: api_key
  api_keys:
    - id: local
      fingerprint:
        provider: env
        name: TEST_DOCTOR_API_HASH
      scopes: [dci:evidence_verification]
audit:
  sink: stdout
evidence:
  enabled: true
  service_id: doctor-live-test
  source_connections:
    dci_registry:
      base_url: "{base_url}"
      allow_insecure_localhost: true
      source_auth:
        type: oauth2_client_credentials
        token_url: "{base_url}/oauth/token"
        client_id_env: TEST_DOCTOR_OAUTH_CLIENT_ID
        client_secret_env: TEST_DOCTOR_OAUTH_CLIENT_SECRET
        request_format: json
      dci:
        search_path: /registry/sync/search
        sender_id: registry-notary
        query_type: idtype-value
        records_path: /message/search_response/0/data/reg_records
  claims:
    - id: dci-record-exists
      title: DCI record exists
      version: 2026-05
      subject_type: person
      value:
        type: boolean
      source_bindings:
        record:
          connector: dci
          connection: dci_registry
          required_scope: dci:evidence_verification
          dataset: registry_records
          entity: record
          lookup:
            input: target.id
            field: SUBJECT_ID
            op: eq
            cardinality: one
          fields:
            id:
              field: id
              type: string
              required: false
      rule:
        type: exists
        source: record
      disclosure:
        default: value
        allowed: [value, redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
"#
        );
        serde_norway::from_str::<StandaloneRegistryNotaryConfig>(&raw).expect("config parses")
    }

    #[test]
    fn doctor_parse_expanded_config_surfaces_disclosure_default_violation() {
        // GH#170 / RS-DM-CLAIM Section 10: `registry-notary doctor` calls
        // parse_expanded_config (see the `doctor` function above), which now
        // rejects a disclosure default that isn't a member of the claim's
        // allowed set (REQ-DM-CLAIM-008) at load instead of loading cleanly
        // and surfacing the inconsistency only when a result is rendered.
        let raw = r#"
deployment:
  profile: local
server:
  bind: 127.0.0.1:0
auth:
  mode: api_key
  api_keys:
    - id: local
      fingerprint:
        provider: env
        name: TEST_DOCTOR_API_HASH
      scopes: [dci:evidence_verification]
audit:
  sink: stdout
evidence:
  enabled: true
  service_id: doctor-disclosure-test
  source_connections:
    dci_registry:
      base_url: "https://dci.example.test"
      source_auth:
        type: oauth2_client_credentials
        token_url: "https://dci.example.test/oauth/token"
        client_id_env: TEST_DOCTOR_OAUTH_CLIENT_ID
        client_secret_env: TEST_DOCTOR_OAUTH_CLIENT_SECRET
        request_format: json
      dci:
        search_path: /registry/sync/search
        sender_id: registry-notary
        query_type: idtype-value
        records_path: /message/search_response/0/data/reg_records
  claims:
    - id: dci-record-exists
      title: DCI record exists
      version: 2026-05
      subject_type: person
      value:
        type: boolean
      source_bindings:
        record:
          connector: dci
          connection: dci_registry
          required_scope: dci:evidence_verification
          dataset: registry_records
          entity: record
          lookup:
            input: target.id
            field: SUBJECT_ID
            op: eq
            cardinality: one
          fields:
            id:
              field: id
              type: string
              required: false
      rule:
        type: exists
        source: record
      disclosure:
        default: value
        allowed: [redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
"#;

        let err = parse_expanded_config(raw)
            .expect_err("disclosure default outside allowed must fail at the doctor entrypoint");
        let message = err.to_string();
        assert!(
            message.contains("dci-record-exists") && message.contains("disclosure"),
            "doctor-facing error must name the offending claim id and field: {message}"
        );
    }
}
