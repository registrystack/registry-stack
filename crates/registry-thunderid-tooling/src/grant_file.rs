//! Closed operator connection file and owner-only final header output for CLIs.
//! There are no task-policy fields here: the UUID selects an existing approval.
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::grant::{acquire, GrantConnection};
use crate::ToolingError;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Connections {
    version: u8,
    casework_url: String,
    token_endpoint: String,
    client_assertion_audience: String,
    bootstrap_resource: String,
    clients: BTreeMap<String, Client>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Client {
    assertion_key_file: PathBuf,
    resource: String,
    scopes: Vec<String>,
}

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
fn identifier(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
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
fn read_private(path: &Path, maximum: usize) -> Result<Zeroizing<Vec<u8>>, ToolingError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|_| refuse("the connection or credential file cannot be opened"))?;
    if !file
        .metadata()
        .is_ok_and(|metadata| metadata_valid(&metadata, false))
    {
        return Err(refuse(
            "connection and credential files must be ordinary owner-only single-link files",
        ));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    (&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| refuse("the connection or credential file cannot be read"))?;
    if bytes.len() > maximum {
        return Err(refuse(
            "the connection or credential file exceeds its bound",
        ));
    }
    Ok(bytes)
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
    if !identifier(client_id) || !crate::description::valid_uuid(grant_id) {
        return Err(refuse(
            "a bounded registered client ID and approved grant UUID are required",
        ));
    }
    let bytes = read_private(connection_file, 64 * 1024)?;
    let connections: Connections = serde_norway::from_slice(&bytes).map_err(|_| {
        refuse("the connection file must match the closed task connection v1 format")
    })?;
    if connections.version != 1
        || connections.clients.is_empty()
        || connections.clients.len() > 32
        || connections.clients.keys().any(|id| !identifier(id))
    {
        return Err(refuse(
            "task connection v1 requires 1..32 bounded registered clients",
        ));
    }
    let client = connections
        .clients
        .get(client_id)
        .ok_or_else(|| refuse("the client is not registered in this connection file"))?;
    if !client.assertion_key_file.is_absolute() {
        return Err(refuse("the registered assertion key file must be absolute"));
    }
    let connection = GrantConnection {
        casework_url: connections.casework_url,
        token_endpoint: connections.token_endpoint,
        client_assertion_audience: connections.client_assertion_audience,
        bootstrap_resource: connections.bootstrap_resource,
        resource: client.resource.clone(),
        scopes: client.scopes.clone(),
    };
    connection.validate()?;
    let key_bytes = read_private(&client.assertion_key_file, 64 * 1024)?;
    let key = registry_platform_crypto::PrivateJwk::parse(
        std::str::from_utf8(&key_bytes)
            .map_err(|_| refuse("the registered assertion key is invalid"))?,
    )
    .map_err(|_| refuse("the registered assertion key is invalid"))?;
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
    fn credential_boundary_refuses_public_symlink_and_hardlinked_files() {
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
        assert!(read_private(&path, 64).is_ok());
        assert!(read_private(&path, 2).is_err());
        let alias = root.join("alias");
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        assert!(read_private(&alias, 64).is_err());
        std::fs::remove_file(&alias).unwrap();
        std::fs::hard_link(&path, &alias).unwrap();
        assert!(read_private(&path, 64).is_err());
        std::fs::remove_file(&alias).unwrap();
        std::fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private(&path, 64).is_err());
        std::fs::remove_dir_all(&root).unwrap();
    }
}
