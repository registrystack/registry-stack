//! Closed operator connection file and owner-only final header output for CLIs.
//! There are no task-policy fields here: the UUID selects an existing approval.
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use registry_platform_config::SecretError;
use registry_platform_yaml::{
    Diagnostic, Document, Report, Severity, Source, MAXIMUM_DOCUMENT_BYTES,
};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::grant::{acquire, GrantConnection};
use crate::task_connection::{client_pointer, valid_client_id, TaskClient, TaskConnection, KIND};
use crate::ToolingError;

/// Non-secret CLI output. Header contents are never returned or printed.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantOutput {
    pub header_file: PathBuf,
    pub grant_expires_at: u64,
}
fn refuse(reason: &'static str) -> ToolingError {
    ToolingError::GrantAcquisition { reason }
}
fn metadata_valid(metadata: &fs::Metadata, directory: bool) -> bool {
    metadata.uid() == rustix::process::geteuid().as_raw()
        && metadata.permissions().mode() & 0o077 == 0
        && if directory {
            metadata.is_dir()
        } else {
            metadata.is_file() && metadata.nlink() == 1
        }
}
/// The task connection refused as a whole, before or without a position.
fn file_refusal(file: &str, code: &str, message: &str, action: &str) -> ToolingError {
    let mut diagnostic = Diagnostic::error(code, "", message, action);
    diagnostic.artifact = Some(KIND.to_owned());
    diagnostic.source = Some(Source {
        file: file.to_owned(),
        line: None,
        column: None,
    });
    refused_report(Report::new(vec![diagnostic]))
}

fn refused_report(mut report: Report) -> ToolingError {
    report.set_files_checked(1);
    ToolingError::FileRefused {
        what: "the task connection",
        fix: "correct each finding below, then run the command again",
        report: Box::new(report),
    }
}

/// The connection file names no secret, so others may read it; it steers
/// where a client's signed assertion is sent, so only its owner may write
/// it. Opened without following a link, then checked on the open file.
fn read_connection(path: &Path, file: &str) -> Result<Vec<u8>, ToolingError> {
    let mut opened = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|_| {
            file_refusal(
                file,
                "platform.task-connection.unreadable",
                "the task connection file cannot be opened",
                "Pass the path of an existing task connection file that is not a symbolic link.",
            )
        })?;
    let safe = opened.metadata().is_ok_and(|metadata| {
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.permissions().mode() & 0o022 == 0
    });
    if !safe {
        return Err(file_refusal(
            file,
            "platform.task-connection.unsafe-file",
            "the task connection file is not a regular single-link file that only its owner, the current user, may write",
            "Make it a regular file you own with a single link, writable by you alone (for example mode 0644 or 0600).",
        ));
    }
    let mut bytes = Vec::new();
    (&mut opened)
        .take(MAXIMUM_DOCUMENT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            file_refusal(
                file,
                "platform.task-connection.unreadable",
                "the task connection file cannot be read",
                "Check that the task connection file is readable, then retry.",
            )
        })?;
    Ok(bytes)
}

/// Resolve the client's private assertion key through the file's secret
/// providers. A refusal is placed at the client's `assertionKeyRef` and
/// names neither the reference nor the value (CFG-SEC-3).
fn assertion_key(
    document: &Document,
    connection: &TaskConnection,
    client_id: &str,
    client: &TaskClient,
) -> Result<registry_platform_crypto::PrivateJwk, ToolingError> {
    let pointer = client_pointer(client_id, "assertionKeyRef");
    let refusal = |code: &str, message: &str, action: &str| {
        refused_report(Report::new(vec![document.diagnostic_at_value(
            Severity::Error,
            code,
            &pointer,
            message,
            action,
        )]))
    };
    let unresolved = |error: SecretError| {
        let (message, action) = match error {
            SecretError::Unavailable => (
                "no secret of the referenced name exists under its provider",
                "Create the key file under secretProviders.file.root, or set the environment variable the reference names.",
            ),
            SecretError::UnsafeFile => (
                "the referenced key file is not a regular file you own with mode 0400 or 0600 and a single link",
                "Make the key file a regular file you own, with mode 0400 or 0600 and a single link.",
            ),
            SecretError::InvalidValue => (
                "the referenced secret is empty, holds a NUL byte, or is larger than 64 KiB",
                "Store the client's private assertion key as one JWK under this reference.",
            ),
            SecretError::Read => (
                "the referenced secret could not be read",
                "Check that the key file is readable, then retry.",
            ),
            _ => (
                "the reference cannot be resolved by the declared secret providers",
                "Declare the provider the reference names under secretProviders.",
            ),
        };
        refusal(
            "platform.task-connection.unresolved-secret",
            message,
            action,
        )
    };
    let secret = connection
        .secret_providers
        .resolver()
        .map_err(&unresolved)?
        .resolve_reference(&client.assertion_key_ref)
        .map_err(&unresolved)?;
    std::str::from_utf8(secret.expose_secret())
        .ok()
        .and_then(|text| registry_platform_crypto::PrivateJwk::parse(text).ok())
        .ok_or_else(|| {
            refusal(
                "platform.task-connection.invalid-assertion-key",
                "the referenced secret is not one private JWK",
                "Store the client's private assertion key as one JWK under this reference.",
            )
        })
}

fn directory(path: &Path) -> Result<(), ToolingError> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(_) => {
            return Err(refuse(
                "the private grant output directory cannot be created",
            ))
        }
    }
    if !fs::symlink_metadata(path).is_ok_and(|metadata| metadata_valid(&metadata, true)) {
        return Err(refuse(
            "grant output directories must be ordinary owner-only directories",
        ));
    }
    Ok(())
}

/// Use an explicit retained operator connection. `private_root` is the owning
/// product's private directory, beneath an already canonical project directory.
/// The command neither starts services nor changes their configured trust.
pub async fn acquire_to_header(
    connection_file: &Path,
    private_root: &Path,
    client_id: &str,
    grant_id: &str,
) -> Result<GrantOutput, ToolingError> {
    if !valid_client_id(client_id) || !crate::description::valid_uuid(grant_id) {
        return Err(refuse(
            "a bounded registered client ID and approved grant UUID are required",
        ));
    }
    let file = connection_file.display().to_string();
    let bytes = read_connection(connection_file, &file)?;
    let read = crate::task_connection::read(&file, &bytes).map_err(refused_report)?;
    let (document, connections) = (read.document, read.value);
    let client = connections
        .clients
        .iter()
        .find(|(id, _)| id.as_str() == client_id)
        .map(|(_, client)| client)
        .ok_or_else(|| {
            refuse("the client is not registered in this connection file; pass a client id the file lists under clients")
        })?;
    let connection = GrantConnection {
        casework_url: connections.casework_url.to_string(),
        token_endpoint: connections.token_endpoint.to_string(),
        client_assertion_audience: connections.client_assertion_audience.to_string(),
        bootstrap_resource: connections.bootstrap_resource.to_string(),
        resource: client.resource.to_string(),
        scopes: client.scopes.iter().map(ToString::to_string).collect(),
    };
    connection.validate()?;
    let key = assertion_key(&document, &connections, client_id, client)?;
    directory(private_root)?;
    let output_root = private_root.join("grants");
    directory(&output_root)?;
    let credential = acquire(&connection, client_id, key, grant_id).await?;
    let header = credential.token.authorization_header_value();
    let mut bytes = Zeroizing::new(b"Authorization: ".to_vec());
    bytes.extend_from_slice(header.as_bytes());
    bytes.push(b'\n');
    let path = output_root.join(format!("{client_id}-{grant_id}.header"));
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        if !metadata_valid(&metadata, false) {
            return Err(refuse(
                "the existing grant header is not an ordinary owner-only file",
            ));
        }
    }
    let temporary = output_root.join(format!(
        ".grant-{}",
        crate::container::random_urlsafe(16)
            .map_err(|_| refuse("the private grant output nonce is unavailable"))?
    ));
    let write = || -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, &path)?;
        File::open(&output_root)?.sync_all()
    };
    if write().is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(refuse("the private grant header could not be stored"));
    }
    Ok(GrantOutput {
        header_file: path,
        grant_expires_at: credential.grant_expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn the_connection_file_is_read_only_when_only_its_owner_may_write_it() {
        let root = std::env::temp_dir().join(format!(
            "task-connection-{}",
            crate::container::random_urlsafe(16).unwrap()
        ));
        directory(&root).unwrap();
        let path = root.join("connection");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(b"synthetic").unwrap();
        let code = |result: Result<Vec<u8>, ToolingError>| match result {
            Ok(_) => "accepted".to_owned(),
            Err(error) => error.report().expect("a placed refusal").diagnostics()[0]
                .code
                .clone(),
        };
        assert_eq!(code(read_connection(&path, "connection")), "accepted");
        std::fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(code(read_connection(&path, "connection")), "accepted");
        let alias = root.join("alias");
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        assert_eq!(
            code(read_connection(&alias, "alias")),
            "platform.task-connection.unreadable"
        );
        std::fs::remove_file(&alias).unwrap();
        std::fs::hard_link(&path, &alias).unwrap();
        assert_eq!(
            code(read_connection(&path, "connection")),
            "platform.task-connection.unsafe-file"
        );
        std::fs::remove_file(&alias).unwrap();
        for mode in [0o664, 0o646] {
            std::fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                code(read_connection(&path, "connection")),
                "platform.task-connection.unsafe-file"
            );
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    const GRANT: &str = "01970000-0000-7000-8000-000000000001";

    fn write_private(path: &Path, bytes: &[u8], mode: u32) {
        let _ = std::fs::remove_file(path);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
    }

    #[tokio::test]
    async fn the_assertion_key_resolves_through_the_declared_providers() {
        let root = std::env::temp_dir().join(format!(
            "task-connection-{}",
            crate::container::random_urlsafe(16).unwrap()
        ));
        let keys = root.join("keys");
        directory(&root).unwrap();
        directory(&keys).unwrap();
        let connection = root.join("task-connection.yaml");
        write_private(
            &connection,
            format!(
                "apiVersion: id.registrystack.org/formats/platform/task-connection/v1alpha1
kind: PlatformTaskConnection
caseworkUrl: http://127.0.0.1:9
tokenEndpoint: http://127.0.0.1:9/oauth2/token
clientAssertionAudience: http://127.0.0.1:9/oauth2/token
bootstrapResource: urn:registry:casework
secretProviders:
  file:
    root: {}
clients:
  task-agent:
    assertionKeyRef: secret:file/task-agent.jwk
    resource: urn:registry:breg
    scopes:
      - records:get
",
                keys.display()
            )
            .as_bytes(),
            0o644,
        );
        let private = root.join("private");
        let acquire = |client: &'static str| {
            let (connection, private) = (connection.clone(), private.clone());
            async move { acquire_to_header(&connection, &private, client, GRANT).await }
        };
        let placed = |error: ToolingError| {
            let report = error.report().expect("a placed refusal").clone();
            let rendered = report.render_human();
            assert!(!rendered.contains("task-agent.jwk"), "{rendered}");
            let diagnostic = &report.diagnostics()[0];
            assert_eq!(diagnostic.path, "/clients/task-agent/assertionKeyRef");
            assert!(diagnostic
                .source
                .as_ref()
                .is_some_and(|source| source.line.is_some()));
            diagnostic.code.clone()
        };

        let unregistered = acquire("other-agent").await.unwrap_err();
        assert!(matches!(
            unregistered,
            ToolingError::GrantAcquisition { .. }
        ));

        let missing = acquire("task-agent").await.unwrap_err();
        assert_eq!(
            placed(missing),
            "platform.task-connection.unresolved-secret"
        );

        let key_file = keys.join("task-agent.jwk");
        let key = registry_platform_crypto::generate_private_jwk(
            registry_platform_crypto::GeneratedKeyAlgorithm::Es384,
        )
        .unwrap();
        let jwk = serde_json::to_vec(&serde_json::json!({
            "kty": key.kty, "alg": key.alg, "kid": "task-agent",
            "crv": key.crv, "x": key.x, "y": key.y, "d": key.d,
        }))
        .unwrap();
        write_private(&key_file, &jwk, 0o644);
        let exposed = acquire("task-agent").await.unwrap_err();
        assert_eq!(
            placed(exposed),
            "platform.task-connection.unresolved-secret"
        );

        write_private(&key_file, b"not a key", 0o600);
        let invalid = acquire("task-agent").await.unwrap_err();
        assert_eq!(
            placed(invalid),
            "platform.task-connection.invalid-assertion-key"
        );

        write_private(&key_file, &jwk, 0o600);
        let unreachable = acquire("task-agent").await.unwrap_err();
        assert!(unreachable.report().is_none(), "{unreachable}");
        std::fs::remove_dir_all(&root).unwrap();
    }
}
