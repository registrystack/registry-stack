//! The canonical JSON Schema of the shared runtime configuration blocks.

use serde_json::{Map, Value};

use crate::blocks::{
    AuditKeyConfig, DatabaseConfig, JwksSource, ListenerConfig, OidcIssuerConfig, PackageConfig,
    PrivateListenerConfig, SecretProvidersConfig,
};

/// File name the shared-blocks generator writes.
pub const SHARED_BLOCKS_SCHEMA_FILE: &str = "runtime-config-blocks.schema.json";

/// Every shared block as a definition, keyed by the name a runtime schema
/// derived with schemars gives it.
#[derive(schemars::JsonSchema)]
#[allow(dead_code)]
struct SharedBlocks {
    secret_providers: SecretProvidersConfig,
    database: DatabaseConfig,
    jwks_source: JwksSource,
    package: PackageConfig,
    listener: ListenerConfig,
    private_listener: PrivateListenerConfig,
    audit_key: AuditKeyConfig,
    oidc_issuer: OidcIssuerConfig,
}

/// The pretty-printed shared-blocks document, newline terminated.
pub fn shared_blocks_document() -> Result<String, serde_json::Error> {
    let derived = serde_json::to_value(schemars::schema_for!(SharedBlocks))?;
    let definitions = derived.get("$defs").cloned().unwrap_or_default();
    let mut document = Map::new();
    document.insert(
        "$schema".to_owned(),
        Value::String("https://json-schema.org/draft/2020-12/schema".to_owned()),
    );
    document.insert(
        "title".to_owned(),
        Value::String("Registry Stack shared runtime configuration blocks".to_owned()),
    );
    document.insert("$defs".to_owned(), definitions);
    let mut rendered = serde_json::to_string_pretty(&Value::Object(document))?;
    rendered.push('\n');
    Ok(rendered)
}
