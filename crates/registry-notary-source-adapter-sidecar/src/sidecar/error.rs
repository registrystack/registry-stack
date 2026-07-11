use super::*;

#[derive(Debug, Error)]
pub enum SidecarError {
    #[error("sidecar config error: {0}")]
    Config(String),
    #[error("failed to bind or serve sidecar: {0}")]
    Io(#[from] std::io::Error),
    #[error("credential env {env} for source {source_id} is missing")]
    MissingCredential { source_id: String, env: String },
    #[error("credential env {env} for source {source_id} is not valid JSON: {source}")]
    CredentialJson {
        source_id: String,
        env: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("credential env {env} for source {source_id} has disallowed or missing baseUrl for allowed_base_urls")]
    CredentialBaseUrl { source_id: String, env: String },
    #[error("auth token hash env {env} for bearer token {token_id} is missing")]
    MissingTokenHashEnv { token_id: String, env: String },
    #[error("auth token hash env {env} for bearer token {token_id} is invalid")]
    InvalidTokenHashEnv { token_id: String, env: String },
    #[error("startup check failed: {0}")]
    StartupCheck(String),
    #[error("smoke lookup for source {source_id} failed: {reason}")]
    SmokeLookup { source_id: String, reason: String },
    #[error("audit setup or write failed: {0}")]
    Audit(#[from] registry_platform_audit::AuditError),
}
