// SPDX-License-Identifier: Apache-2.0
//! Deployment-bound S3 content storage. PostgreSQL owns references, locking,
//! pending writes and durable deletion retries; this adapter owns only bytes.
//!
//! The transport is `registry-platform-objectstore`; this module binds it to
//! the Registry namespace: key prefix `breg`, binding domain
//! `breg-attachment-s3-v1`, and the attachment size bound.

use std::{fmt, sync::Arc};

use registry_platform_config::{ObjectStorageConfig, SecretResolver};
use registry_platform_objectstore::{ObjectNamespace, S3Settings};
use serde::Deserialize;

pub use registry_platform_objectstore::{
    ObjectStoreError as AttachmentStorageError, S3ObjectStore as S3AttachmentStore,
};

/// The longest one object-store request may run, body included.
pub(crate) const MAXIMUM_TIMEOUT_MILLISECONDS: u64 =
    registry_platform_config::MAX_ATTEMPT_TIMEOUT_MILLISECONDS;

/// The Registry's place in a shared bucket. Changing any member moves every
/// retained object and changes the binding digest recorded beside it.
const NAMESPACE: ObjectNamespace = ObjectNamespace {
    key_prefix: "breg",
    binding_domain: "breg-attachment-s3-v1",
    max_object_bytes: crate::contract::MAX_ATTACHMENT_BYTES as u64,
};

type Result<T> = std::result::Result<T, AttachmentStorageError>;

/// Omitted configuration selects transactional PostgreSQL content storage.
#[derive(Clone, Default)]
pub enum AttachmentStorage {
    #[default]
    Database,
    S3(Arc<S3AttachmentStore>),
}

impl AttachmentStorage {
    /// Persist beside retained content; a changed binding cannot read/delete it.
    pub fn binding_digest(&self) -> String {
        match self {
            Self::Database => "database".to_string(),
            Self::S3(store) => store.binding_digest().to_string(),
        }
    }
}

impl fmt::Debug for AttachmentStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Database => "AttachmentStorage::Database",
            Self::S3(_) => "AttachmentStorage::S3(<redacted>)",
        })
    }
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Clone, Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
// Read once from `runtime.yaml` at startup and converted at once, so the size
// of the S3 variant costs nothing worth an indirection.
#[allow(clippy::large_enum_variant)]
pub(crate) enum RawAttachmentStorageConfig {
    Database {},
    S3(ObjectStorageConfig),
}
registry_platform_yaml::tagged_union!(RawAttachmentStorageConfig);

#[cfg(feature = "schema")]
impl serde::Serialize for RawAttachmentStorageConfig {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        crate::contract::serialize_tagged_union(
            Self::serialize(self, serde_json::value::Serializer),
            "type",
            serializer,
        )
    }
}

impl Default for RawAttachmentStorageConfig {
    fn default() -> Self {
        Self::Database {}
    }
}

/// Validated deployment settings. Debug never reveals deployment values.
#[derive(Clone, Default)]
pub(crate) struct AttachmentStorageConfig(Option<S3Settings>);

impl AttachmentStorageConfig {
    pub(crate) fn from_raw(raw: RawAttachmentStorageConfig) -> Result<Self> {
        match raw {
            RawAttachmentStorageConfig::Database {} => Ok(Self::default()),
            RawAttachmentStorageConfig::S3(config) => {
                S3Settings::from_config(&config).map(|settings| Self(Some(settings)))
            }
        }
    }

    /// `registry_id` is the scope input: separate databases and registries
    /// never share an object key or a last-reference deletion namespace.
    pub(crate) async fn activate(
        &self,
        registry_id: &str,
        resolver: &SecretResolver,
    ) -> Result<AttachmentStorage> {
        let Some(settings) = &self.0 else {
            return Ok(AttachmentStorage::Database);
        };
        let store = settings.activate(NAMESPACE, registry_id, resolver).await?;
        Ok(AttachmentStorage::S3(Arc::new(store)))
    }
}

impl fmt::Debug for AttachmentStorageConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.0.is_some() {
            "AttachmentStorageConfig::S3(<redacted>)"
        } else {
            "AttachmentStorageConfig::Database"
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_platform_config::SecretProvider;
    use serde_json::json;
    use sha2::{Digest, Sha256};

    struct SecretFiles(tempfile::TempDir);
    impl SecretFiles {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            for (name, value) in [
                ("access", "breg960test"),
                ("secret", "breg960-test-only-secret"),
            ] {
                let path = root.path().join(name);
                std::fs::write(&path, value).unwrap();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
                }
            }
            Self(root)
        }
        fn resolver(&self) -> SecretResolver {
            SecretResolver::new([SecretProvider::File], self.0.path()).unwrap()
        }
    }

    fn raw(url: &str) -> serde_json::Value {
        json!({"type":"s3", "url":url, "bucket":"breg-960-test", "region":"us-east-1", "accessKeyIdRef":"secret:file/access", "secretAccessKeyRef":"secret:file/secret"})
    }

    fn config(input: serde_json::Value) -> Result<AttachmentStorageConfig> {
        AttachmentStorageConfig::from_raw(serde_json::from_value(input).unwrap())
    }

    #[test]
    fn strict_storage_configuration_and_debug_are_value_free() {
        for url in [
            "http://storage.example",
            "https://storage.example/path",
            "https://storage.example?canary",
            "https://storage.example#canary",
        ] {
            assert_eq!(
                config(raw(url)).unwrap_err(),
                AttachmentStorageError::InvalidConfiguration
            );
        }
        // A URL with userinfo or another scheme is refused at decode.
        for url in ["https://user:canary@storage.example", "file:///canary"] {
            assert!(serde_json::from_value::<RawAttachmentStorageConfig>(raw(url)).is_err());
        }
        for (key, value) in [
            ("bucket", json!("../canary")),
            ("bucket", json!("127.0.0.1")),
            ("region", json!("us/east")),
        ] {
            let mut input = raw("https://storage.example");
            input[key] = value;
            assert!(config(input).is_err());
        }
        // The timeout is bounded at decode.
        let mut input = raw("https://storage.example");
        input["attemptTimeoutMilliseconds"] = json!(0);
        assert!(serde_json::from_value::<RawAttachmentStorageConfig>(input).is_err());
        let mut input = raw("https://storage.example");
        input["accessKeyIdRef"] = json!("inline-secret-canary");
        let error = serde_json::from_value::<RawAttachmentStorageConfig>(input)
            .err()
            .expect("an inline credential is not a secret reference");
        assert!(!error.to_string().contains("inline-secret-canary"));
        assert!(serde_json::from_value::<RawAttachmentStorageConfig>(
            json!({"type":"database", "url":"https://ignored.example"})
        )
        .is_err());
        let mut input = raw("https://storage.example");
        input["secretAccessKey"] = json!("inline-canary");
        assert!(serde_json::from_value::<RawAttachmentStorageConfig>(input).is_err());
        // The destination key is `url`; the earlier `endpoint` is unknown.
        let mut input = raw("https://storage.example");
        input["endpoint"] = input["url"].take();
        input.as_object_mut().unwrap().remove("url");
        assert!(serde_json::from_value::<RawAttachmentStorageConfig>(input).is_err());
        let config = config(raw("https://storage.example")).unwrap();
        assert_eq!(
            format!("{config:?}"),
            "AttachmentStorageConfig::S3(<redacted>)"
        );
        let mut input = raw("http://127.0.0.1:1234");
        input["pathStyle"] = json!(false);
        assert!(self::config(input).is_err());
    }

    #[test]
    #[cfg(feature = "schema")]
    fn storage_schema_refuses_inline_credentials_and_database_extras() {
        let schema = crate::runtime_config::runtime_config_schema().unwrap();
        let mut storage_schema = schema
            .pointer("/$defs/RawAttachmentStorageConfig")
            .unwrap()
            .clone();
        storage_schema["$defs"] = schema["$defs"].clone();
        let validator = jsonschema::JSONSchema::compile(&storage_schema).unwrap();
        let mut input = raw("https://storage.example");
        assert!(validator.is_valid(&input));
        input["accessKeyIdRef"] = json!("inline-credential-canary");
        assert!(!validator.is_valid(&input));
        let mut input = raw("https://storage.example");
        input["endpoint"] = json!("https://storage.example");
        assert!(!validator.is_valid(&input));
        assert!(validator.is_valid(&json!({"type":"database"})));
        assert!(!validator.is_valid(&json!({"type":"database", "url":"https://ignored.example"})));
    }

    #[tokio::test]
    async fn database_default_needs_no_storage_service() {
        let files = SecretFiles::new();
        let config = config(json!({"type":"database"})).unwrap();
        assert!(matches!(
            config
                .activate("registry", &files.resolver())
                .await
                .unwrap(),
            AttachmentStorage::Database
        ));
        assert!(matches!(
            AttachmentStorageConfig::default()
                .activate("registry", &files.resolver())
                .await
                .unwrap(),
            AttachmentStorage::Database
        ));
    }

    /// A storage service that answers the versioning probe and records every
    /// request path, accepting writes and serving back `content`.
    async fn recording_service() -> (
        String,
        Arc<std::sync::Mutex<Vec<String>>>,
        tokio::task::JoinHandle<()>,
    ) {
        use axum::{extract::Request, http::StatusCode, routing::any, Router};
        let paths = Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = paths.clone();
        let app = Router::new().fallback(any(move |request: Request| {
            let log = log.clone();
            async move {
                log.lock().unwrap().push(request.uri().to_string());
                if request.uri().query() == Some("versioning=") {
                    (StatusCode::OK, "<VersioningConfiguration/>")
                } else {
                    (StatusCode::OK, "content")
                }
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (url, paths, server)
    }

    #[tokio::test]
    async fn the_registry_namespace_keeps_its_key_prefix_and_binding_digest() {
        let (url, paths, server) = recording_service().await;
        let files = SecretFiles::new();
        let scope = r#"["database-one","registry"]"#;
        let storage = config(raw(&url))
            .unwrap()
            .activate(scope, &files.resolver())
            .await
            .unwrap();
        let scope_digest = hex::encode(Sha256::digest(scope));
        let bucket_url = format!("{url}/breg-960-test");
        // The binding digest is the SHA-256 of the JSON array
        // [domain, bucket URL, region, hex SHA-256 of the scope], so every
        // retained attachment row still matches after the transport moved.
        let identity = serde_json::to_vec(&(
            "breg-attachment-s3-v1",
            bucket_url.as_str(),
            "us-east-1",
            scope_digest.as_str(),
        ))
        .unwrap();
        assert_eq!(
            storage.binding_digest(),
            hex::encode(Sha256::digest(identity))
        );
        let AttachmentStorage::S3(store) = storage else {
            panic!("S3 storage expected");
        };
        let digest = hex::encode(Sha256::digest(b"content"));
        store.put(&digest, b"content".to_vec()).await.unwrap();
        let recorded = paths.lock().unwrap().clone();
        let object = format!("/breg-960-test/breg/{scope_digest}/{digest}");
        assert_eq!(recorded[0], "/breg-960-test?versioning=");
        assert!(recorded.contains(&object), "{recorded:?}");
        assert!(
            recorded
                .iter()
                .all(|path| path == &object || path == "/breg-960-test?versioning="),
            "{recorded:?}"
        );
        server.abort();
    }

    #[tokio::test]
    async fn storage_binding_identity_tracks_namespace_but_allows_timeout_changes() {
        let (url, _, server) = recording_service().await;
        let files = SecretFiles::new();
        let config = self::config(raw(&url)).unwrap();
        let first = config
            .activate("database-one/registry", &files.resolver())
            .await
            .unwrap();
        let second = config
            .activate("database-two/registry", &files.resolver())
            .await
            .unwrap();
        assert_ne!(first.binding_digest(), second.binding_digest());
        let mut input = raw(&url);
        input["attemptTimeoutMilliseconds"] = json!(5000);
        assert_eq!(
            first.binding_digest(),
            self::config(input.clone())
                .unwrap()
                .activate("database-one/registry", &files.resolver())
                .await
                .unwrap()
                .binding_digest()
        );
        input["bucket"] = json!("different-bucket");
        assert_ne!(
            first.binding_digest(),
            self::config(input)
                .unwrap()
                .activate("database-one/registry", &files.resolver())
                .await
                .unwrap()
                .binding_digest()
        );
        server.abort();
    }
}
